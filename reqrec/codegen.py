"""Plan -> standalone Python script source.  Contract: DESIGN.md §8.

``generate(plan, opts)`` renders a :class:`~reqrec.model.Plan` as a self-contained, readable
Python 3.8+ script built on ``requests`` + ``BeautifulSoup``: one function per step, a ``main()``
that threads extracted values between steps through a ``ctx`` dict, and a handful of small
runtime helpers (``_charset`` / ``_text`` for response encoding, ``_soup``, ``_check``, ``_regex``,
``_json_path``, ``_select`` / ``_attr`` / ``_elem_text``).

Phase 2 (DESIGN.md §13)
-----------------------
* ``main()`` runs every step but prints the result of the step named by ``Plan.final_step_index``
  (``final_resp`` / ``final_results``; the last step when unset).
* ``Plan.auth`` becomes ``session.auth`` (Basic tuple, ``HTTPDigestAuth``, or the
  ``requests_negotiate_sspi`` -> ``requests_ntlm`` fallback for NTLM / Negotiate); recorded
  ``Authorization`` headers of that scheme are never emitted.
* ``VERIFY_TLS`` is always emitted and applied (``session.verify``); ``GenOptions.legacy_tls`` adds
  ``_LegacyTLSAdapter`` (TLS 1.0+, ``@SECLEVEL=1``) mounted on ``https://``.
* Responses are decoded from bytes: ``_soup`` parses ``resp.content`` and ``_text(resp)`` sniffs the
  charset (header -> ``<meta>`` / ``<?xml`` -> JSON = UTF-8 -> ``apparent_encoding``), so Shift_JIS
  pages served without a charset do not become mojibake.
* A ``raw`` body that carries ``Step.form`` (a form recorded percent-encoded in a legacy charset) is
  rebuilt with ``urlencode`` from the form pairs, so fresh ``__VIEWSTATE``-style values reach the server.
* Downloads (DESIGN.md §13.13): right after its own request, every step's response is saved as a
  file when it is binary or ``Content-Disposition`` names an attachment (any response kind, loop
  iterations included; ``_save_download`` / ``_save_if_attachment``, unique names per run); the final
  print block only prints.  ``main()`` first checks the required secret *constants* (recorded
  non-empty secrets and the Basic / Digest password) and exits with a plain message.

Security boundary
-----------------
Everything in a ``Plan`` that came from the recording (URLs, header names and values, parameter
names and values, form fields, JSON bodies, cookie values, regex patterns, CSS selectors,
constants, sample values, free-text comments) is attacker-controlled.  It only ever reaches the
generated source through :func:`_lit` (``repr()``), :func:`_json_lit` (JSON bodies rendered as
Python literals leaf by leaf), :func:`_docstring_lines` (a ``repr``-equivalent escaper for
triple-quoted strings) or :func:`_comment_text` (line breaks and control characters removed so a
comment can never continue onto a new line).  Identifiers (``Ref.var``, extractor variables,
constant and function names, loop variables) are validated with ``str.isidentifier`` and
``Ref.expr`` sources must parse as a single Python expression without comments or line breaks;
anything else raises :class:`CodegenError` instead of being written into the script.
"""

from __future__ import annotations

import ast
import contextlib
import io
import keyword
import math
import re
import tokenize
from typing import Any, Iterable, Iterator, Optional, Sequence
from urllib.parse import quote_from_bytes

from . import util
from .model import Constant, Extractor, GenOptions, Plan, Ref, Step

try:  # the package version is stamped into the generated module docstring
    from . import __version__ as _VERSION
except ImportError:  # pragma: no cover - defensive
    _VERSION = "0.0.0"

#: Bodies larger than this are not embedded in the script (``b""`` + TODO + warning instead).
MAX_INLINE_BODY = 64 * 1024

#: Longest recorded sample value quoted in a comment.
_SAMPLE_LEN = 48

#: Longest inline container (``{...}`` on one line) before switching to one item per line.
_INLINE_WIDTH = 72

_INDENT = "    "

#: HTTP methods that have a ``session.<method>()`` shortcut with sane defaults
#: (``head`` is excluded because its shortcut disables redirects).
_METHOD_SHORTCUTS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

_LINEBREAK_RE = re.compile("[\r\n\x0b\x0c\x1c\x1d\x1e\x85  ]+")

#: ``Authorization`` schemes that ``session.auth`` covers for an ``AuthInfo.kind`` (DESIGN.md §13.2).
#: A recorded ``Authorization`` header of a covered scheme is dropped from the emitted steps.
_AUTH_FAMILIES: dict[str, frozenset[str]] = {
    "ntlm": frozenset({"ntlm", "negotiate"}),
    "negotiate": frozenset({"ntlm", "negotiate"}),
    "basic": frozenset({"basic"}),
    "digest": frozenset({"digest"}),
}
_AUTH_LABELS = {"ntlm": "NTLM", "negotiate": "Negotiate", "basic": "Basic", "digest": "Digest"}

#: Default for ``REQREC_NTLM_USER`` when the recording did not reveal the user (emitted verbatim;
#: it is our own text, not recorded content).
_NTLM_USER_PLACEHOLDER = 'r"DOMAIN\\user"'

_FORM_MIME = "application/x-www-form-urlencoded"
_AUTH_EXPR_SCHEME_RE = re.compile(r"""^\s*(?:[bru]*)(["'])([A-Za-z][A-Za-z0-9._-]*)\s""")

_Block = list  # list[str]: a rendered value; line 0 is placed after a prefix, the rest are relative


class CodegenError(ValueError):
    """The plan contains something that cannot be rendered safely (bad identifier / expression)."""


# =========================================================================== literal rendering

def _lit(value: Any) -> str:
    """The *only* way recorded text enters the script: ``repr()`` of a str (or bytes).

    ``repr`` escapes quotes, backslashes, control characters, non-printable unicode and lone
    surrogates, so the result is always a single-line, valid Python literal.
    """
    if isinstance(value, (bytes, bytearray)):
        return repr(bytes(value))
    if value is None:
        return "''"
    return repr(str(value))


def _bytes_lit(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return repr(bytes(value))
    return repr(str(value).encode("utf-8", "surrogateescape"))


def _oneline(text: Any) -> str:
    """Collapse every line-break character the tokenizer or ``str.splitlines`` knows into a space."""
    return _LINEBREAK_RE.sub(" ", str(text))


def _escape_unprintable(ch: str) -> str:
    n = ord(ch)
    if n < 0x100:
        return f"\\x{n:02x}"
    if n < 0x10000:
        return f"\\u{n:04x}"
    return f"\\U{n:08x}"


def _comment_text(text: Any) -> str:
    """Recorded text made safe for a ``#`` comment: one line, printable characters only."""
    out = []
    for ch in _oneline(text):
        if ch == " " or ch == "\t" or ch.isprintable():
            out.append(ch)
        else:
            out.append(_escape_unprintable(ch))
    return "".join(out).rstrip()


def _docstring_lines(lines: Iterable[Any]) -> list[str]:
    """Render text lines as the lines of a ``\"\"\"...\"\"\"`` literal.

    This is ``repr`` adapted to a multi-line, double-quoted context: backslashes and double quotes
    are escaped, every line-break character inside a line becomes a space and any other
    non-printable character is written as a ``\\xNN`` / ``\\uNNNN`` escape.  The content can
    therefore never terminate the literal.
    """
    out: list[str] = []
    for raw in lines:
        buf = []
        for ch in _oneline(raw):
            if ch == "\\":
                buf.append("\\\\")
            elif ch == '"':
                buf.append('\\"')
            elif ch == " " or ch == "\t" or ch.isprintable():
                buf.append(ch)
            else:
                buf.append(_escape_unprintable(ch))
        out.append("".join(buf).rstrip())
    while out and not out[-1]:
        out.pop()
    if not out:
        return ['""""""']
    if len(out) == 1:
        return ['"""' + out[0] + '"""']
    return ['"""' + out[0]] + out[1:] + ['"""']


def _css_string(value: Any) -> str:
    """A CSS string literal (double-quoted) for attribute selectors such as ``input[name="X"]``."""
    buf = []
    for ch in str(value):
        if ch in '\\"':
            buf.append("\\" + ch)
        elif ch == "\x00":
            buf.append("\\fffd ")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            buf.append(f"\\{ord(ch):x} ")
        else:
            buf.append(ch)
    return '"' + "".join(buf) + '"'


def _num_lit(value: Any) -> str:
    """Python literal for an int/float, including the JSON extremes ``NaN`` / ``Infinity``."""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, float):
        if math.isnan(value):
            return "float('nan')"
        if math.isinf(value):
            return "float('inf')" if value > 0 else "float('-inf')"
    return repr(value)


# =========================================================================== identifier / expression validation

def _check_identifier(name: Any, what: str) -> str:
    name = str(name)
    if not name.isidentifier() or keyword.iskeyword(name):
        raise CodegenError(f"{what} is not a valid Python identifier: {name!r}")
    return name


def _check_expr(src: Any) -> str:
    """Validate a ``Ref.expr`` source: one expression, no line breaks, no comment."""
    src = str(src).strip()
    if not src or _LINEBREAK_RE.search(src):
        raise CodegenError(f"Ref.expr must be a single-line expression: {src!r}")
    try:
        ast.parse(src, mode="eval")
    except SyntaxError as exc:
        raise CodegenError(f"Ref.expr is not a valid expression: {src!r} ({exc.msg})") from None
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                raise CodegenError(f"Ref.expr must not contain a comment: {src!r}")
    except tokenize.TokenError as exc:  # pragma: no cover - ast.parse already succeeded
        raise CodegenError(f"Ref.expr cannot be tokenized: {src!r} ({exc})") from None
    return src


def _expr_names(src: str) -> list[str]:
    """Names referenced by a validated expression, in source order (deduplicated)."""
    tree = ast.parse(src, mode="eval")
    found = sorted(
        ((n.lineno, n.col_offset, n.id) for n in ast.walk(tree) if isinstance(n, ast.Name)),
    )
    out: list[str] = []
    for _, _, name in found:
        if name not in out:
            out.append(name)
    return out


def _expr_is_str_call(src: str) -> bool:
    try:
        node = ast.parse(src, mode="eval").body
    except SyntaxError:  # pragma: no cover - validated earlier
        return False
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "str"


# =========================================================================== block helpers

def _join_first(prefix: str, block: Sequence[str], suffix: str = "") -> list[str]:
    out = list(block)
    out[0] = prefix + out[0]
    out[-1] = out[-1] + suffix
    return out


def _indent_block(block: Sequence[str], levels: int = 1) -> list[str]:
    return [(_INDENT * levels + line) if line else line for line in block]


def _container(open_: str, close: str, items: Sequence[tuple[list, Optional[str]]], *,
               inline_ok: bool = True, trailing_comma_single: bool = False) -> list[str]:
    """Render a dict/list/tuple literal from ``(block, inline_comment)`` items.

    Everything goes on one line when every item is single-line, has no comment and the result
    is short; otherwise one item per line with trailing commas.
    """
    if not items:
        return [open_ + close]
    if inline_ok and all(len(b) == 1 and not c for b, c in items):
        body = ", ".join(b[0] for b, _ in items)
        if trailing_comma_single and len(items) == 1:
            body += ","
        line = open_ + body + close
        if len(line) <= _INLINE_WIDTH:
            return [line]
    out = [open_]
    for block, comment in items:
        lines = _join_first("", block, ",")
        if comment:
            lines[-1] += "  # " + comment
        out.extend(_indent_block(lines))
    out.append(close)
    return out


class _Writer:
    """Accumulates indented source lines."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.level = 0

    def line(self, text: str = "") -> None:
        self.lines.append((_INDENT * self.level + text) if text else "")

    def block(self, lines: Iterable[str], prefix: str = "", suffix: str = "") -> None:
        lines = _join_first(prefix, list(lines), suffix)
        for ln in lines:
            self.line(ln)

    def blank(self, n: int = 1) -> None:
        self.lines.extend([""] * n)

    @contextlib.contextmanager
    def indent(self) -> Iterator[None]:
        self.level += 1
        try:
            yield
        finally:
            self.level -= 1

    def text(self) -> str:
        out: list[str] = []
        blanks = 0
        for ln in self.lines:
            ln = ln.rstrip()
            if not ln:
                blanks += 1
                if blanks > 2:
                    continue
            else:
                blanks = 0
            out.append(ln)
        while out and not out[-1]:
            out.pop()
        return "\n".join(out) + "\n"


# =========================================================================== the generator

class _Generator:
    def __init__(self, plan: Plan, opts: GenOptions) -> None:
        self.plan = plan
        self.opts = opts
        self.w = _Writer()
        self.warnings: list[str] = []  # codegen-time notes merged into the docstring (and plan.warnings)
        self.constant_names: set[str] = set()
        self.producer: dict[str, str] = {}  # extractor var -> func_name of the step that extracts it
        self.producer_kind: dict[str, str] = {}
        self.loop_vars: set[str] = set()
        self.func_names: list[str] = []
        self.helpers_needed: set[str] = set()
        self.final_step: Optional[Step] = None  # the step whose result main() prints
        self.auth_user_const: Optional[str] = None
        self.auth_pw_const: Optional[str] = None
        self.extra_constants: list[Constant] = []  # auth constants synthesised when the plan lacks them
        self.needs_urlencode = False
        self._prepare()

    # ------------------------------------------------------------------ preparation

    def _prepare(self) -> None:
        taken: set[str] = set()
        for const in self.plan.constants:
            name = _check_identifier(const.name, "constant name")
            self.constant_names.add(name)
            taken.add(name)
        for step in self.plan.steps:
            for ext in step.extractors:
                var = _check_identifier(ext.var, "extractor variable")
                if var in self.constant_names:
                    raise CodegenError(f"extractor variable {var!r} collides with a constant")
            if step.loop is not None:
                var = _check_identifier(step.loop.var, "loop variable")
                if var in self.constant_names:  # main() reads constants (required secrets) before the loop
                    raise CodegenError(f"loop variable {var!r} collides with a constant")
                self.loop_vars.add(var)
        self._prepare_auth()
        # unique function names (the plan should already guarantee this; be safe)
        reserved = set(self.constant_names) | {
            "main", "session", "resp", "soup", "data", "ctx", "results", "out", "requests", "re", "json",
            "os", "sys", "time", "ssl", "warnings", "unquote", "urlencode", "urljoin", "BeautifulSoup",
            "TIMEOUT", "DELAY", "VERIFY_TLS", "BASE_HEADERS", "INITIAL_COOKIES",
            "_soup", "_check", "_regex", "_json_path", "_select", "_attr", "_elem_text", "_text", "_charset",
            "_normalise_charset", "final_resp", "final_results", "final_saved", "_LegacyTLSAdapter",
            "HttpNegotiateAuth", "HttpNtlmAuth",
        } | _DOWNLOAD_HELPER_NAMES
        for step in self.plan.steps:
            base = _check_identifier(step.func_name or f"step_{step.index:02d}", "step function name")
            self.func_names.append(util.unique_name(base, reserved))
        for step, fname in zip(self.plan.steps, self.func_names):
            for ext in step.extractors:
                self.producer.setdefault(ext.var, fname)
                self.producer_kind.setdefault(ext.var, ext.kind)
                self.helpers_needed.update(_helpers_for_extractor(ext))
            if self._raw_form(step) is not None:
                self.needs_urlencode = True
        self.final_step = self._resolve_final_step()
        if self.final_step is not None and self.opts.print_final and self.final_step.response_kind == "html":
            self.helpers_needed.add("_soup")
        if self.plan.steps:
            # DESIGN.md §13.13 download rule: every step's response may turn out to be a file (binary
            # bodies always; any kind, HTML included, when Content-Disposition says attachment)
            self.helpers_needed.add("_save_download")

    def _required_secrets(self) -> list[tuple[str, str]]:
        """``(env_var, constant_name)`` pairs main() insists on before the first request.

        Secrets recorded with a non-empty value (an empty password field stays optional), plus the
        HTTP Basic / Digest password constant whatever was recorded: a Digest password never
        appears on the wire and a synthesised ``AUTH_PASSWORD`` has no recorded value, yet both are
        needed.  NTLM / Negotiate need none (SSPI uses the logged-in user).  The check tests the
        *constant*, so a value typed into the constant block works as well as the variable.
        Sending an empty password silently would only end in a confusing failure later."""
        out: list[tuple[str, str]] = []
        for const in self._all_constants():
            if not const.secret:
                continue
            name = _check_identifier(const.name, "constant name")
            if str(const.value or "") == "" and name != self.auth_pw_const:
                continue
            pair = (_env_name(const), name)
            if pair not in out:
                out.append(pair)
        return out

    def _resolve_final_step(self) -> Optional[Step]:
        """The step whose result ``main()`` prints: ``Plan.final_step_index`` or the last step."""
        steps = self.plan.steps
        if not steps:
            return None
        wanted = self.plan.final_step_index
        if wanted is None:
            return steps[-1]
        for st in steps:
            if st.index == wanted:
                return st
        self._note(f"結果に指定したステップ {wanted} が見つからないため、最後のステップの結果を表示します")
        return steps[-1]

    def _prepare_auth(self) -> None:
        """Resolve the constants ``session.auth`` needs for Basic / Digest.

        ``plan.py`` provides ``AUTH_USERNAME`` / ``AUTH_PASSWORD`` (``AuthInfo.username_const`` /
        ``password_const``); should they be missing, codegen synthesises them (the password as a
        secret read from ``REQREC_AUTH_PASSWORD``) rather than emitting an undefined name.
        """
        auth = self.plan.auth
        if auth is None:
            return
        kind = str(auth.kind or "").lower()
        if kind not in ("basic", "digest"):
            return
        label = _AUTH_LABELS[kind]
        self.auth_user_const = self._auth_constant(
            auth.username_const, "AUTH_USERNAME",
            Constant(name="AUTH_USERNAME", value=str(auth.username or ""), comment=f"HTTP {label} 認証のユーザー名"),
        )
        self.auth_pw_const = self._auth_constant(
            auth.password_const, "AUTH_PASSWORD",
            Constant(name="AUTH_PASSWORD", value="", secret=True, env_var="REQREC_AUTH_PASSWORD",
                     comment=f"HTTP {label} 認証のパスワード（環境変数 REQREC_AUTH_PASSWORD で指定）"),
        )

    def _auth_constant(self, declared: Optional[str], default_name: str, fallback: Constant) -> str:
        if declared and str(declared) in self.constant_names:
            return _check_identifier(declared, "auth constant name")
        taken = set(self.constant_names) | self.loop_vars
        for step in self.plan.steps:
            taken.update(str(ext.var) for ext in step.extractors)
        name = util.unique_name(default_name, taken)
        fallback.name = name
        if fallback.secret:
            fallback.env_var = f"REQREC_{name}"
        self.extra_constants.append(fallback)
        self.constant_names.add(name)
        self._note(f"認証用の定数 {name} が解析結果に無かったため、生成コードで補いました")
        return name

    def _all_constants(self) -> list[Constant]:
        return list(self.plan.constants) + list(self.extra_constants)

    def _comment(self, text: str) -> Optional[str]:
        """Sanitised comment text, or None when comments are disabled."""
        if not self.opts.comments:
            return None
        return _comment_text(text)

    def _c(self, text: str) -> None:
        """Emit a full-line comment (no-op when comments are disabled)."""
        c = self._comment(text)
        if c:
            self.w.line("# " + c)

    def _cl(self, code: str, comment: str) -> None:
        """Emit a code line with a trailing comment (the comment is dropped when disabled)."""
        c = self._comment(comment)
        self.w.line(code + (f"  # {c}" if c else ""))

    def _note(self, text: str) -> None:
        if text not in self.warnings:
            self.warnings.append(text)

    # ------------------------------------------------------------------ Ref rendering

    def _ref(self, ref: Ref, *, header: bool = False) -> str:
        """Python source for a Ref: literal -> repr, var -> identifier, expr -> verbatim."""
        if not isinstance(ref, Ref):
            return _lit(ref)
        if ref.kind == "literal":
            return _lit(ref.value)
        if ref.kind == "var":
            name = _check_identifier(ref.value, "Ref.var")
            if header and self.producer_kind.get(name) == "json":
                return f"str({name})"  # JSON leaves may be numbers; header values must be str
            return name
        if ref.kind == "expr":
            return _check_expr(ref.value)
        raise CodegenError(f"unknown Ref kind {ref.kind!r}")

    def _ref_comment(self, ref: Ref) -> Optional[str]:
        """Provenance note for a var Ref at its usage site."""
        if not self.opts.comments or not isinstance(ref, Ref):
            return None
        if ref.kind == "var":
            if ref.value in self.producer:
                return f"{self.producer[ref.value]} で取得"
            if ref.value in self.loop_vars:
                return "ループ変数"
            return None
        if ref.kind == "expr":
            names = [n for n in _expr_names(_check_expr(ref.value)) if n in self.producer]
            if names:
                return ", ".join(f"{n} は {self.producer[n]} で取得" for n in names)
            if "time.time" in ref.value:
                return "実行時の時刻"
            if "session.cookies" in ref.value:
                return "Cookie から取得"
            raw = _bytes_literal_value(ref.value)
            if raw is not None:
                return _legacy_bytes_note(raw)
        return None

    def _pairs(self, pairs: Sequence[tuple[str, Ref]], *, header: bool = False) -> list[str]:
        """``{name: value}`` when names are unique, else ``[(name, value), ...]``."""
        names = [str(n) for n, _ in pairs]
        items: list[tuple[list, Optional[str]]] = []
        if len(set(names)) == len(names):
            for name, ref in pairs:
                items.append(([f"{_lit(name)}: {self._ref(ref, header=header)}"], self._ref_comment(ref)))
            return _container("{", "}", items)
        for name, ref in pairs:
            items.append(([f"({_lit(name)}, {self._ref(ref, header=header)})"], self._ref_comment(ref)))
        return _container("[", "]", items)

    def _json_lit(self, node: Any) -> list[str]:
        """A JSON-like structure (with Ref leaves) as a Python literal block."""
        if isinstance(node, Ref):
            return [self._ref(node)]
        if isinstance(node, dict):
            items = []
            for key, value in node.items():
                block = self._json_lit(value)
                items.append((_join_first(f"{_lit(key)}: ", block), self._ref_comment(value)))
            return _container("{", "}", items)
        if isinstance(node, (list, tuple)):
            items = [(self._json_lit(v), self._ref_comment(v)) for v in node]
            return _container("[", "]", items)
        if node is None:
            return ["None"]
        if isinstance(node, (bool, int, float)):
            return [_num_lit(node)]
        if isinstance(node, (bytes, bytearray)):
            return [_bytes_lit(node)]
        return [_lit(node)]

    def _url(self, pieces: Sequence[Ref]) -> str:
        """URL expression: a single literal, or literal/str(var) pieces joined with ``+``."""
        if not pieces:
            return "''"
        parts: list[str] = []
        buf = ""
        for piece in pieces:
            if not isinstance(piece, Ref) or piece.kind == "literal":
                buf += str(piece.value if isinstance(piece, Ref) else piece)
                continue
            if buf:
                parts.append(_lit(buf))
                buf = ""
            src = self._ref(piece)
            if piece.kind == "expr" and _expr_is_str_call(src):
                parts.append(src)
            else:
                parts.append(f"str({src})")
        if buf or not parts:
            parts.append(_lit(buf))
        return " + ".join(parts)

    def _url_display(self, pieces: Sequence[Ref]) -> str:
        out = []
        for piece in pieces:
            if not isinstance(piece, Ref) or piece.kind == "literal":
                out.append(str(piece.value if isinstance(piece, Ref) else piece))
            else:
                out.append("{" + str(piece.value) + "}")
        return "".join(out)

    # ------------------------------------------------------------------ step analysis

    def _iter_refs(self, step: Step) -> Iterator[Ref]:
        """Every Ref of a step in the order the request is assembled (URL, params, headers, body)."""
        for piece in step.url:
            if isinstance(piece, Ref):
                yield piece
        for _, ref in step.params or []:
            yield ref
        for _, ref in step.headers or []:
            yield ref
        if step.body_kind == "form":
            for _, ref in step.form or []:
                yield ref
        elif step.body_kind == "json":
            yield from _json_refs(step.json_body)
        elif step.body_kind == "multipart":
            for part in step.multipart or []:
                if part.value is not None:
                    yield part.value
        elif step.body_kind == "raw":
            for _, ref in self._raw_form(step) or []:
                yield ref

    @staticmethod
    def _raw_form(step: Step) -> Optional[list[tuple[str, Ref]]]:
        """Form pairs a ``raw`` body is rebuilt from, or None to send ``raw_body`` verbatim.

        DESIGN.md §13.4: a form recorded percent-encoded in a legacy charset (cp932 ``%93%FA``)
        is kept raw by the plan, with ``Step.form`` as the field hint (legacy values are ``bytes``
        expressions, traced values are vars).  Rebuilding from the pairs lets fresh ``__VIEWSTATE``
        values reach the server while the legacy bytes stay byte-exact.
        """
        if (step.body_kind or "none") != "raw" or not step.form:
            return None
        for name, ref in step.headers or []:
            if str(name).lower() == "content-type":
                literal = ref.value if isinstance(ref, Ref) and ref.kind == "literal" else None
                if literal is None or not str(literal).lower().startswith(_FORM_MIME):
                    return None
        return list(step.form)

    def _step_params(self, step: Step) -> list[str]:
        """Function parameters after ``session``: the loop var first, then the extractor
        variables the step uses (constants are module globals and are skipped)."""
        known = set(self.producer) | self.loop_vars
        params: list[str] = []
        loop_var = step.loop.var if step.loop is not None else None
        if loop_var:
            params.append(loop_var)
        for ref in self._iter_refs(step):
            if not isinstance(ref, Ref):
                continue
            if ref.kind == "var":
                name = _check_identifier(ref.value, "Ref.var")
                if name in self.constant_names or name == loop_var or name in params:
                    continue
                if name not in known:
                    self._note(f"{step.func_name}: 変数 {name!r} はどのステップでも取得されていません（実行時に KeyError になります）")
                params.append(name)
            elif ref.kind == "expr":
                for name in _expr_names(_check_expr(ref.value)):
                    if name in known and name not in self.constant_names and name != loop_var and name not in params:
                        params.append(name)
        return params

    # ------------------------------------------------------------------ sections

    def _render(self, extra: Optional[list[str]] = None) -> str:
        self.w = _Writer()
        self._emit_docstring(extra=extra)
        self._emit_imports()
        self._emit_settings()
        self._emit_helpers()
        self._emit_steps()
        self._emit_main()
        self.w.blank(2)
        self.w.line('if __name__ == "__main__":')
        with self.w.indent():
            self.w.line("main()")
        return self.w.text()

    def generate(self) -> str:
        src = self._render()
        if self.warnings:
            # regenerate once: the docstring lists the notes collected while rendering the steps
            frozen = list(self.warnings)
            src = self._render(extra=frozen)
            for note in frozen:
                if note not in self.plan.warnings:
                    self.plan.warnings.append(note)
        return src

    def _source_summary(self) -> str:
        meta = self.plan.meta if isinstance(self.plan.meta, dict) else {}
        src = meta.get("source")
        if not isinstance(src, dict):
            src = {"source": src} if src else {}
        kind = str(src.get("source") or "不明")
        label = {"har": "HAR ファイル", "mitmproxy": "mitmproxy 録画", "mitm": "mitmproxy フローファイル"}.get(kind.lower(), kind)
        parts = [label]
        if src.get("file"):
            parts.append(f"({src['file']})")
        if src.get("creator"):
            parts.append(f"作成: {src['creator']}")
        if src.get("started_at"):
            parts.append(f"記録開始: {src['started_at']}")
        return " ".join(str(p) for p in parts)

    def _emit_docstring(self, extra: Optional[list[str]] = None) -> None:
        meta = self.plan.meta if isinstance(self.plan.meta, dict) else {}
        steps = self.plan.steps
        lines = [
            "reqrec が HTTP 通信の記録から自動生成したスクレイピングスクリプト",
            "",
            f"生成: reqrec {_VERSION} / {meta.get('generated_at') or util.now_iso()}",
            f"記録元: {self._source_summary()}",
        ]
        count = f"ステップ数: {len(steps)}"
        if isinstance(meta.get("flows_total"), int) and isinstance(meta.get("flows_kept"), int):
            count += f"（記録 {meta['flows_total']} リクエストのうち {meta['flows_kept']} 件を使用）"
        lines.append(count)
        if self.final_step is not None and self.plan.final_step_index is not None:
            lines.append(
                f"結果として表示するステップ: {self.final_step.index}"
                f"（{str(self.final_step.method).upper()} {self._url_display(self.final_step.url)}）"
            )
        if self.plan.auth is not None:
            lines += ["", self._auth_summary()]
        secrets = [c for c in self._all_constants() if c.secret]
        if secrets:
            envs = ", ".join(_env_name(c) for c in secrets)
            lines += ["", f"実行前に環境変数 {envs} を設定してください（記録時の値は出力していません）。"]
        warnings = list(self.plan.warnings) + [w for w in (extra or []) if w not in self.plan.warnings]
        notes = self._auth_notes() + warnings
        if notes:
            lines += ["", "注意:"]
            for wmsg in notes:
                lines.append(f"  - {wmsg}")
        lines += ["", "使い方: python このファイル.py"]
        for ln in _docstring_lines(lines):
            self.w.line(ln)

    def _auth_summary(self) -> str:
        auth = self.plan.auth
        kind = str(auth.kind or "").lower()
        who = f"（記録時のユーザー: {auth.username}）" if auth.username else ""
        if kind in ("ntlm", "negotiate"):
            return (f"認証: 統合 Windows 認証（{_AUTH_LABELS[kind]}）を使うサイトです。"
                    f"生成コードは session.auth を設定します{who}。")
        if kind == "basic":
            return (f"認証: HTTP Basic 認証。生成コードは session.auth = ({self.auth_user_const}, {self.auth_pw_const}) "
                    f"を設定します{who}。")
        if kind == "digest":
            return (f"認証: HTTP Digest 認証。生成コードは session.auth = "
                    f"requests.auth.HTTPDigestAuth({self.auth_user_const}, {self.auth_pw_const}) を設定します{who}。")
        return f"認証: 未対応の方式 {kind!r} が検出されました。session.auth を手で設定してください（main() の TODO）。"

    def _auth_notes(self) -> list[str]:
        """Docstring 注意 entries for the authentication scheme (package / env vars needed)."""
        auth = self.plan.auth
        if auth is None:
            return []
        kind = str(auth.kind or "").lower()
        if kind in ("ntlm", "negotiate"):
            default_user = auth.username or "DOMAIN\\user"
            return [
                '統合 Windows 認証には追加パッケージが必要です。Windows: pip install "reqrec[sspi]"'
                "（今ログインしているユーザーで認証します）",
                'Windows 以外 / 別のユーザーで実行する場合: pip install "reqrec[ntlm]" のうえ、環境変数 '
                f"REQREC_NTLM_USER（例: {default_user}）と REQREC_NTLM_PASSWORD を設定してください",
            ]
        if kind in ("basic", "digest"):
            pw = next((c for c in self._all_constants() if c.name == self.auth_pw_const), None)
            if pw is not None and pw.secret:
                return [f"HTTP {_AUTH_LABELS[kind]} 認証のパスワードは環境変数 {_env_name(pw)} から読み込みます"]
            return []
        return [f"認証方式 {kind!r} は自動設定できません。main() の TODO で session.auth を設定してください"]

    def _emit_imports(self) -> None:
        w = self.w
        w.blank()
        w.line("import json")
        w.line("import os")
        w.line("import re")
        if self.opts.legacy_tls:
            w.line("import ssl")
        w.line("import sys")
        w.line("import time")
        if self.opts.legacy_tls:
            w.line("import warnings")
        names = ["unquote", "urljoin"] + (["urlencode"] if self.needs_urlencode else [])
        w.line("from urllib.parse import " + ", ".join(sorted(names)))
        w.blank()
        w.line("import requests")
        w.line("from bs4 import BeautifulSoup")

    def _emit_settings(self) -> None:
        w = self.w
        opts = self.opts
        w.blank(2)
        self._c("===== 設定 =====")
        timeout = float(opts.timeout) if opts.timeout is not None else 30.0
        delay = float(opts.delay) if opts.delay else 0.0
        c = self._comment("各リクエストのタイムアウト（秒）")
        w.line(f"TIMEOUT = {timeout!r}" + (f"  # {c}" if c else ""))
        c = self._comment("ステップ間の待ち時間（秒）。サーバーに負荷をかけないための配慮")
        w.line(f"DELAY = {delay!r}" + (f"  # {c}" if c else ""))
        self._cl("VERIFY_TLS = True", "自己署名証明書のサイトなら False か CA 証明書 (.pem) のパスに")

        constants = self._all_constants()
        if constants:
            w.blank()
            self._c("===== 定数（必要に応じて書き換えてください） =====")
            for const in constants:
                self._emit_constant(const)

        w.blank()
        self._c("全てのリクエストに共通して送るヘッダー")
        items = [([f"{_lit(k)}: {_lit(v)}"], None) for k, v in (self.plan.base_headers or [])]
        w.block(_container("{", "}", items, inline_ok=False), prefix="BASE_HEADERS = ")

        w.blank()
        self._c("記録開始時点でブラウザが既に持っていた Cookie（ログイン済みセッションなど）")
        if self.plan.initial_cookies:
            self._c("期限切れになっている場合は、再度ブラウザから値を取得して書き換えてください")
        items = []
        for ck in self.plan.initial_cookies or []:
            items.append(([
                "{" + ", ".join([
                    f"'name': {_lit(ck.name)}",
                    f"'value': {_lit(ck.value)}",
                    f"'domain': {_lit(ck.domain)}",
                    f"'path': {_lit(ck.path or '/')}",
                ]) + "}"
            ], None))
        w.block(_container("[", "]", items, inline_ok=False), prefix="INITIAL_COOKIES = ")

    def _emit_constant(self, const: Constant) -> None:
        w = self.w
        name = _check_identifier(const.name, "constant name")
        if const.comment:
            self._c(const.comment)
        if const.secret:
            env = _env_name(const)
            self._c(f"記録時の値は安全のため出力していません。環境変数 {env} で指定してください（下の行の '' に直接書いても動きます）")
            w.line(f"{name} = os.environ.get({_lit(env)}, '')")
        else:
            w.line(f"{name} = {_lit(const.value)}")

    # ------------------------------------------------------------------ helpers

    def _emit_helpers(self) -> None:
        w = self.w
        parser = _lit(self.opts.html_parser or "html.parser")
        w.blank(2)
        self._c("===== ヘルパー =====")
        self._emit_encoding_helpers()
        if "_soup" in self.helpers_needed:
            w.blank(2)
            w.line("def _soup(resp):")
            with w.indent():
                w.line('"""レスポンスの HTML を BeautifulSoup で解析する。')
                w.line("")
                w.line("バイト列を渡し、文字コードは BeautifulSoup に判定させる（<meta charset> / BOM / 推定）。")
                w.line("Content-Type ヘッダーに charset があればそれを優先する。")
                w.line('"""')
                w.line(f"return BeautifulSoup(resp.content, {parser}, from_encoding=_charset(resp))")
        w.blank(2)

        w.line("def _check(resp, expected, step):")
        with w.indent():
            if self.opts.strict_status:
                w.line('"""ステータスコードが記録時と一致することを確認する。"""')
                w.line("if resp.status_code != expected:")
                with w.indent():
                    w.line("raise RuntimeError(")
                    with w.indent():
                        w.line('f"{step}: 想定外のステータスコード {resp.status_code} "')
                        w.line('f"(記録時: {expected}) {resp.request.method} {resp.url}"')
                    w.line(")")
            else:
                w.line('"""エラー応答（4xx/5xx）なら例外にし、記録時と違うステータスなら警告を出す。"""')
                w.line("if resp.status_code != expected:")
                with w.indent():
                    w.line("print(")
                    with w.indent():
                        w.line('f"[警告] {step}: ステータスコード {resp.status_code} (記録時: {expected}) {resp.url}",')
                        w.line("file=sys.stderr,")
                    w.line(")")
                w.line("resp.raise_for_status()")

        if "_regex" in self.helpers_needed:
            w.blank(2)
            w.line("def _regex(text, pattern):")
            with w.indent():
                w.line('"""正規表現で最初にマッチした部分（グループ 1）を返す。見つからなければエラー。"""')
                w.line('m = re.search(pattern, text or "")')
                w.line("if not m:")
                with w.indent():
                    w.line('raise RuntimeError(f"パターンに一致しませんでした: {pattern!r}")')
                w.line("return m.group(1) if m.re.groups else m.group(0)")

        if "_json_path" in self.helpers_needed:
            w.blank(2)
            w.line("def _json_path(data, path):")
            with w.indent():
                w.line('"""JSON のキー / 配列インデックスの列（例: ["data", 0, "id"]）を辿って値を返す。"""')
                w.line("current = data")
                w.line("for i, key in enumerate(path):")
                with w.indent():
                    w.line("try:")
                    with w.indent():
                        w.line("current = current[key]")
                    w.line("except (KeyError, IndexError, TypeError):")
                    with w.indent():
                        w.line("raise RuntimeError(")
                        with w.indent():
                            w.line('f"JSON にパス {path!r} が見つかりません（{path[:i + 1]!r} の位置で失敗）"')
                        w.line(") from None")
                w.line("return current")

        if "_attr" in self.helpers_needed or "_elem_text" in self.helpers_needed:
            w.blank(2)
            w.line("def _select(soup, selector):")
            with w.indent():
                w.line('"""CSS セレクタに一致する最初の要素を返す。見つからなければエラー。"""')
                w.line("element = soup.select_one(selector)")
                w.line("if element is None:")
                with w.indent():
                    w.line('raise RuntimeError(f"要素が見つかりません: {selector!r}")')
                w.line("return element")

        if "_attr" in self.helpers_needed:
            w.blank(2)
            w.line("def _attr(soup, selector, attr):")
            with w.indent():
                w.line('"""CSS セレクタに一致する最初の要素の属性値を返す。"""')
                w.line("value = _select(soup, selector).get(attr)")
                w.line("if value is None:")
                with w.indent():
                    w.line('raise RuntimeError(f"要素 {selector!r} に属性 {attr!r} がありません")')
                w.line("if isinstance(value, list):")
                with w.indent():
                    w.line('value = " ".join(value)')
                w.line("return value")

        if "_elem_text" in self.helpers_needed:
            w.blank(2)
            w.line("def _elem_text(soup, selector):")
            with w.indent():
                w.line('"""CSS セレクタに一致する最初の要素のテキスト（前後の空白を除く）を返す。"""')
                w.line("return _select(soup, selector).get_text(strip=True)")

        if "_save_download" in self.helpers_needed:
            w.blank(2)
            for ln in _DOWNLOAD_HELPERS_SRC.strip("\n").split("\n"):
                w.line(ln)

        if self.opts.legacy_tls:
            self._emit_legacy_adapter()

    def _emit_encoding_helpers(self) -> None:
        """``_charset`` / ``_normalise_charset`` / ``_text`` (DESIGN.md §13.4)."""
        w = self.w
        self._c("Shift_JIS 系の文字コード名の表記ゆれ（Python の名前に揃える）")
        w.line("_CHARSET_ALIASES = {")
        with w.indent():
            w.line('"shift_jis": "cp932", "shift-jis": "cp932", "sjis": "cp932", "x-sjis": "cp932",')
            w.line('"windows-31j": "cp932", "ms932": "cp932", "ms_kanji": "cp932", "x-euc-jp": "euc_jp",')
        w.line("}")
        w.line("_META_CHARSET_RE = re.compile(rb" + '"""' + r"""<meta[^>]+charset=["']?\s*([-\w.:]+)""" + '"""' + ", re.I)")
        w.line("_XML_ENCODING_RE = re.compile(rb" + '"""' + r"""^\s*<\?xml[^>]*encoding=["']([-\w.:]+)["']""" + '"""' + ", re.I)")
        w.blank(2)
        w.line("def _normalise_charset(name):")
        with w.indent():
            w.line('"""文字コード名を Python が理解する名前に揃える（Shift_JIS 系は cp932）。不明な名前なら None。"""')
            w.line('name = (name or "").strip().strip(' + repr("\"'") + ').lower()')
            w.line("if not name:")
            with w.indent():
                w.line("return None")
            w.line("name = _CHARSET_ALIASES.get(name, name)")
            w.line("try:")
            with w.indent():
                self._cl('"".encode(name)', "Python が知らない名前なら LookupError（空のバイト列の decode は検査をしない）")
            w.line("except (LookupError, TypeError):")
            with w.indent():
                w.line("return None")
            w.line("return name")
        w.blank(2)
        w.line("def _charset(resp):")
        with w.indent():
            w.line('"""Content-Type ヘッダーに書かれた文字コード（無ければ None）。"""')
            w.line('content_type = resp.headers.get("Content-Type") or ""')
            w.line('for part in content_type.split(";")[1:]:')
            with w.indent():
                w.line('key, _, value = part.strip().partition("=")')
                w.line('if key.strip().lower() == "charset":')
                with w.indent():
                    w.line("return _normalise_charset(value)")
            w.line("return None")
        w.blank(2)
        w.line("def _text(resp):")
        with w.indent():
            w.line('"""レスポンス本文を正しい文字コードで文字列にして返す。')
            w.line("")
            w.line("requests は charset の無い text/* を ISO-8859-1 とみなすため、Shift_JIS のページがそのままでは")
            w.line("文字化けする。ヘッダーの charset → 本文先頭の <meta charset> / <?xml encoding> → JSON なら UTF-8 →")
            w.line("本文からの推定、の順に文字コードを決め、resp.encoding に設定したうえで resp.text を返す。")
            w.line('"""')
            w.line("charset = _charset(resp)")
            w.line("if charset is None:")
            with w.indent():
                w.line('head = (resp.content or b"")[:4096]')
                w.line("m = _META_CHARSET_RE.search(head) or _XML_ENCODING_RE.search(head)")
                w.line("if m:")
                with w.indent():
                    w.line('charset = _normalise_charset(m.group(1).decode("ascii", "replace"))')
            w.line("if charset is None:")
            with w.indent():
                w.line('mime = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()')
                self._cl('charset = "utf-8" if mime.endswith("json") else resp.apparent_encoding', "JSON は UTF-8（RFC 8259）")
            w.line("if charset:")
            with w.indent():
                w.line("resp.encoding = charset")
            w.line("return resp.text")

    def _emit_legacy_adapter(self) -> None:
        """``_LegacyTLSAdapter`` (DESIGN.md §13.3): TLS 1.0+ and ``@SECLEVEL=1`` ciphers, verification
        still governed by ``VERIFY_TLS`` (requests sets ``verify_mode``; we only keep ``check_hostname``
        consistent with it, which urllib3 requires before it can set ``CERT_NONE``)."""
        w = self.w
        w.blank(2)
        self._c("===== 古い TLS しか使えないサーバー向けの接続設定（--legacy-tls） =====")
        w.line("class _LegacyTLSAdapter(requests.adapters.HTTPAdapter):")
        with w.indent():
            w.line('"""TLS 1.0 / 1.1 や古い暗号スイートしか使えないサーバーに接続するための HTTPS アダプター。')
            w.line("")
            w.line("IE モードで使っている古い社内サーバー向け。新しい OpenSSL は既定で TLS 1.2 未満と弱い暗号を")
            w.line("拒否するため、最低バージョンとセキュリティレベルを下げる。証明書の検証は VERIFY_TLS の設定に従う")
            w.line("（このクラスでは無効化しない）。")
            w.line('"""')
            w.blank()
            w.line("def _ssl_context(self):")
            with w.indent():
                w.line("ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)")
                w.line("with warnings.catch_warnings():")
                with w.indent():
                    self._cl('warnings.simplefilter("ignore", DeprecationWarning)', "TLS 1.0 の指定は非推奨扱いだが意図したもの")
                    w.line("try:")
                    with w.indent():
                        w.line("ctx.minimum_version = ssl.TLSVersion.TLSv1")
                    w.line("except (AttributeError, ValueError):")
                    with w.indent():
                        self._cl("pass", "この Python / OpenSSL では TLS 1.0 を有効にできない")
                w.line("try:")
                with w.indent():
                    self._cl('ctx.set_ciphers("DEFAULT:@SECLEVEL=1")',
                             "それでも接続できなければ @SECLEVEL=0 に（OpenSSL 3 系で TLS 1.0/1.1 を使う場合）")
                w.line("except ssl.SSLError:")
                with w.indent():
                    w.line("pass")
                self._cl('ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)',
                         "安全でない再ネゴシエーションしかできないサーバー向け")
                w.line("try:")
                with w.indent():
                    self._cl("ctx.load_default_certs()", "OS の証明書ストア（社内 CA など）も信頼する")
                w.line("except Exception:")
                with w.indent():
                    w.line("pass")
                w.line("return ctx")
            w.blank()
            w.line("def init_poolmanager(self, *args, **kwargs):")
            with w.indent():
                w.line('kwargs["ssl_context"] = self._ssl_context()')
                w.line("return super().init_poolmanager(*args, **kwargs)")
            w.blank()
            w.line("def proxy_manager_for(self, *args, **kwargs):")
            with w.indent():
                w.line('kwargs["ssl_context"] = self._ssl_context()')
                w.line("return super().proxy_manager_for(*args, **kwargs)")
            w.blank()
            w.line("def cert_verify(self, conn, url, verify, cert):")
            with w.indent():
                w.line("super().cert_verify(conn, url, verify, cert)")
                w.line('ctx = getattr(conn, "conn_kw", {}).get("ssl_context")')
                w.line("if ctx is not None:")
                with w.indent():
                    self._cl("ctx.check_hostname = bool(verify)", "VERIFY_TLS = False のときはホスト名の検証も行わない")

    # ------------------------------------------------------------------ steps

    def _emit_steps(self) -> None:
        self.w.blank(2)
        self._c("===== 各ステップ（記録順） =====")
        for step, fname in zip(self.plan.steps, self.func_names):
            self._emit_step(step, fname)

    def _emit_step(self, step: Step, fname: str) -> None:
        w = self.w
        params = self._step_params(step)
        w.line(f"def {fname}({', '.join(['session'] + params)}):")
        with w.indent():
            head = f"{str(step.method).upper()} {self._url_display(step.url)}"
            doc = [head]
            if step.loop is not None:
                doc[0] += f"  （{step.loop.var} を変えて繰り返し）"
            if step.comment:
                comment = str(step.comment)
                # plan.py writes "METHOD URL -> STATUS mime ..."; avoid repeating the head line
                if comment.startswith(str(step.method).upper() + " ") and " -> " in comment:
                    doc += ["", "記録時のレスポンス: " + comment.split(" -> ", 1)[1]]
                else:
                    doc += ["", comment]
            for ln in _docstring_lines(doc):
                w.line(ln)
            self._emit_request(step)
            try:
                expected = int(step.expected_status)
            except (TypeError, ValueError):
                expected = 200
            w.line(f"_check(resp, {expected}, {_lit(fname)})")
            outputs = self._emit_extractors(step, fname)
            items = [([f"{_lit(v)}: {v}"], None) for v in outputs]
            w.block(_container("{", "}", items), prefix="return resp, ")
        w.blank(2)

    def _step_headers(self, step: Step) -> list[tuple[str, Ref]]:
        """Per-step headers to emit: without ``Authorization`` of the scheme ``session.auth`` handles
        (DESIGN.md §13.2, defensive) and with a ``Content-Type`` when a legacy form is rebuilt."""
        headers = list(step.headers or [])
        auth = self.plan.auth
        if auth is not None:
            family = _AUTH_FAMILIES.get(str(auth.kind or "").lower(), frozenset())
            kept: list[tuple[str, Ref]] = []
            for name, ref in headers:
                scheme = _auth_scheme_of(ref) if str(name).lower() == "authorization" else None
                if scheme is not None and scheme in family:
                    self._note(
                        f"{step.func_name}: Authorization ヘッダー（{_AUTH_LABELS.get(scheme, scheme)}）は "
                        f"session.auth が処理するため生成コードから除きました"
                    )
                    continue
                kept.append((name, ref))
            headers = kept
        if self._raw_form(step) is not None and not any(str(n).lower() == "content-type" for n, _ in headers):
            headers.append(("Content-Type", Ref.lit(_FORM_MIME)))
        return headers

    def _emit_request(self, step: Step) -> None:
        w = self.w
        method = str(step.method or "GET").upper()
        kwargs: list[tuple[str, list[str], Optional[str]]] = []
        if step.params:
            kwargs.append(("params", self._pairs(step.params), None))
        headers = self._step_headers(step)
        if headers:
            kwargs.append(("headers", self._pairs(headers, header=True), None))
        if self._raw_form(step) is not None:
            self._note(
                f"{step.func_name}: UTF-8 以外の文字コードで送られたフォーム本文は、各フィールドの値から URL エンコードして"
                f"組み直します（取得した値は差し替え、Shift_JIS などの値は記録時のバイト列のまま）"
            )
            self._c("フォームの値を記録時の文字コード（バイト列）のまま URL エンコードして送る（Shift_JIS などのサイト）")
        kwargs.extend(self._body_kwargs(step))
        if step.allow_redirects is False:
            kwargs.append(("allow_redirects", ["False"], None))
        kwargs.append(("timeout", ["TIMEOUT"], None))

        url = self._url(step.url)
        if method in _METHOD_SHORTCUTS and method.isidentifier():
            head = f"resp = session.{method.lower()}("
            positional = [url]
        else:
            head = "resp = session.request("
            positional = [_lit(method), url]

        single = all(len(b) == 1 and not c for _, b, c in kwargs)
        if single:
            args = positional + [f"{k}={b[0]}" for k, b, _ in kwargs]
            line = head + ", ".join(args) + ")"
            if len(line) + len(_INDENT) * w.level <= 100:
                w.line(line)
                return
        w.line(head)
        with w.indent():
            for p in positional:
                w.line(p + ",")
            for name, block, comment in kwargs:
                w.block(block, prefix=f"{name}=", suffix="," + (f"  # {comment}" if comment else ""))
        w.line(")")

    def _body_kwargs(self, step: Step) -> list[tuple[str, list[str], Optional[str]]]:
        """``(kwarg_name, rendered_block, inline_comment)`` entries for the step's body."""
        kind = step.body_kind or "none"
        out: list[tuple[str, list[str], Optional[str]]] = []
        if kind == "none":
            return out
        if kind == "form":
            out.append(("data", self._pairs(step.form or []), None))
        elif kind == "json":
            out.append(("json", self._json_lit(step.json_body), None))
        elif kind == "multipart":
            files: list[tuple[list, Optional[str]]] = []
            texts: list[tuple[str, Ref]] = []
            file_names: list[str] = []
            for part in step.multipart or []:
                if part.filename is not None or part.content is not None:
                    file_names.append(str(part.name))
                    files.append(self._multipart_file(step, part))
                else:
                    texts.append((part.name, part.value if part.value is not None else Ref.lit("")))
            if files:
                unique = len(set(file_names)) == len(file_names)
                items = []
                for (block, comment), name in zip(files, file_names):
                    if unique:
                        items.append((_join_first(f"{_lit(name)}: ", block), comment))
                    else:
                        items.append((_join_first(f"({_lit(name)}, ", block, ")"), comment))
                out.append(("files", _container("{" if unique else "[", "}" if unique else "]", items, inline_ok=False), None))
            if texts:
                out.append(("data", self._pairs(texts), None))
            if not files and not texts:
                out.append(("files", ["{}"], None))
        elif kind == "raw":
            form = self._raw_form(step)
            if form is not None:
                out.append(("data", _join_first("urlencode(", self._pairs(form), ")"), None))
                return out
            body = step.raw_body if step.raw_body is not None else b""
            if not isinstance(body, (bytes, bytearray)):
                body = str(body).encode("utf-8", "surrogateescape")
            if len(body) > MAX_INLINE_BODY:
                self._note(f"{step.func_name}: リクエスト本文が {len(body)} バイトと大きいためスクリプトに埋め込んでいません（TODO を確認してください）")
                c = self._comment(f"TODO: 記録時の本文（{len(body)} バイト）は大きすぎるため省略しました。ここで設定してください")
                out.append(("data", ["b''"], c))
            else:
                out.append(("data", [_bytes_lit(bytes(body))], None))
        else:
            self._note(f"{step.func_name}: 未対応のボディ種別 {kind!r} のため本文を送信していません")
        return out

    def _multipart_file(self, step: Step, part) -> tuple[list, Optional[str]]:
        content = part.content if part.content is not None else b""
        if not isinstance(content, (bytes, bytearray)):
            content = str(content).encode("utf-8", "surrogateescape")
        comment: Optional[str] = None
        if len(content) > MAX_INLINE_BODY:
            self._note(f"{step.func_name}: アップロードファイル {part.name!r} ({part.filename!r}, {len(content)} バイト) は大きいため内容を埋め込んでいません（TODO を確認してください）")
            comment = self._comment(f"TODO: {len(content)} バイトのファイル内容は省略しました。open(path, 'rb').read() などで設定してください")
            content_src = "b''"
        else:
            content_src = _bytes_lit(bytes(content))
        filename_src = _lit(part.filename) if part.filename is not None else "None"
        if part.content_type:
            tup = f"({filename_src}, {content_src}, {_lit(part.content_type)})"
        else:
            tup = f"({filename_src}, {content_src})"
        return [tup], comment

    # ------------------------------------------------------------------ extractors

    def _emit_extractors(self, step: Step, fname: str) -> list[str]:
        w = self.w
        outputs: list[str] = []
        exts = list(step.extractors or [])
        if not exts:
            return outputs
        if any(e.kind in ("html_input", "html_meta", "html_attr", "html_text") for e in exts):
            w.line("soup = _soup(resp)")
        if any(e.kind == "json" for e in exts):
            w.line("data = resp.json()")
        for ext in exts:
            var = _check_identifier(ext.var, "extractor variable")
            if var in outputs:
                self._note(f"{fname}: 変数 {var!r} が複数回抽出されています（後の定義が有効）")
            expr, desc = self._extractor_expr(ext, fname)
            if self.opts.comments:
                note = f"{var}: {desc}"
                if ext.sample is not None:
                    note += f"（記録時の値: {_lit(util.truncate(str(ext.sample), _SAMPLE_LEN))}）"
                if ext.note:
                    note += f" — {ext.note}"
                self._c(note)
            w.line(f"{var} = {expr}")
            if var not in outputs:
                outputs.append(var)
        return outputs

    def _extractor_expr(self, ext: Extractor, fname: str) -> tuple[str, str]:
        """``(python_expression, japanese_description)`` for one extractor."""
        kind = ext.kind
        pattern = ext.pattern
        if kind == "cookie":
            if ext.name is None:
                return self._todo(ext, fname, "cookie 名がありません")
            return f"session.cookies.get({_lit(ext.name)})", f"Cookie {_lit(ext.name)} の値"
        if kind == "header":
            if ext.name is None:
                return self._todo(ext, fname, "ヘッダー名がありません")
            return f"resp.headers.get({_lit(ext.name)})", f"レスポンスヘッダー {_lit(ext.name)}"
        if kind == "json":
            if ext.path is None:
                return self._todo(ext, fname, "JSON パスがありません")
            path_src = "[" + ", ".join(_num_lit(p) if isinstance(p, int) and not isinstance(p, bool) else _lit(p) for p in ext.path) + "]"
            return f"_json_path(data, {path_src})", f"レスポンス JSON の {_comment_text(_dotted(ext.path))}"
        if kind == "html_input":
            if ext.name is None:
                return self._todo(ext, fname, "input 名がありません")
            selector = f"input[name={_css_string(ext.name)}]"
            return f"_attr(soup, {_lit(selector)}, 'value')", f"<input name={_lit(ext.name)}> の value"
        if kind == "html_meta":
            if ext.name is None:
                return self._todo(ext, fname, "meta 名がありません")
            selector = f"meta[name={_css_string(ext.name)}]"
            return f"_attr(soup, {_lit(selector)}, 'content')", f"<meta name={_lit(ext.name)}> の content"
        if kind == "html_attr":
            if ext.selector is None or ext.attr is None:
                return self._todo(ext, fname, "セレクタまたは属性名がありません")
            expr = f"_attr(soup, {_lit(ext.selector)}, {_lit(ext.attr)})"
            desc = f"要素 {_lit(ext.selector)} の属性 {_lit(ext.attr)}"
            if pattern:
                expr = f"_regex({expr}, {_lit(pattern)})"
                desc += " から正規表現で抽出"
            return expr, desc
        if kind == "html_text":
            if ext.selector is None:
                return self._todo(ext, fname, "セレクタがありません")
            expr = f"_elem_text(soup, {_lit(ext.selector)})"
            desc = f"要素 {_lit(ext.selector)} のテキスト"
            if pattern:
                expr = f"_regex({expr}, {_lit(pattern)})"
                desc += " から正規表現で抽出"
            return expr, desc
        if kind == "regex":
            if pattern is None:
                return self._todo(ext, fname, "正規表現がありません")
            return f"_regex(_text(resp), {_lit(pattern)})", "レスポンス本文を正規表現で検索"
        if kind == "url":
            if pattern is None:
                return self._todo(ext, fname, "正規表現がありません")
            return f"_regex(resp.url, {_lit(pattern)})", "最終的な URL（リダイレクト後）を正規表現で検索"
        return self._todo(ext, fname, f"未対応の抽出方法 {kind!r}")

    def _todo(self, ext: Extractor, fname: str, why: str) -> tuple[str, str]:
        self._note(f"{fname}: 変数 {ext.var!r} を抽出できません（{why}）。生成されたスクリプトの TODO を確認してください")
        c = self._comment(f"TODO: {why}。ここで値を設定してください")
        return ("None" + (f"  # {c}" if c else "")), f"TODO: {why}"

    # ------------------------------------------------------------------ main

    def _emit_main(self) -> None:
        w = self.w
        steps = self.plan.steps
        w.line("def main():")
        with w.indent():
            required = self._required_secrets()
            if required:
                self._c("パスワードなど、実行時に入力が必要な値（環境変数、または定数に直接書いた値）がそろっているか先に確認する")
                items = [([f"({_lit(env)}, {name})"], None) for env, name in required]
                pairs = _container("[", "]", items, inline_ok=len(required) <= 2)
                w.block(_join_first("missing = [env for env, value in ", pairs, " if not value]"))
                w.line("if missing:")
                with w.indent():
                    w.line('sys.exit("環境変数 " + ", ".join(missing) + " が設定されていません（パスワードなど、実行時に入力が必要な値です）")')
            w.line("session = requests.Session()")
            self._emit_session_auth()
            self._cl("session.verify = VERIFY_TLS", "証明書の検証（設定ブロックの VERIFY_TLS を参照）")
            if self.opts.legacy_tls:
                self._cl('session.mount("https://", _LegacyTLSAdapter())', "古い TLS / 暗号しか使えないサーバー向けの接続設定")
            w.line("session.headers.update(BASE_HEADERS)")
            w.line("for c in INITIAL_COOKIES:")
            with w.indent():
                w.line("session.cookies.set(c['name'], c['value'], domain=c['domain'], path=c['path'])")
            w.line("ctx = {}")
            if not steps:
                w.line('print("記録に再現できるリクエストがありませんでした", file=sys.stderr)')
                w.line("return ctx")
                return
            sleep = (self.opts.delay or 0) > 0
            for i, (step, fname) in enumerate(zip(steps, self.func_names)):
                last = i == len(steps) - 1
                w.blank()
                self._emit_main_step(
                    step, fname,
                    sleep=sleep and (not last or step.loop is not None),
                    final=self.opts.print_final and step is self.final_step,
                )
            if self.opts.print_final and self.final_step is not None:
                w.blank()
                self._emit_final(self.final_step)
            w.line("return ctx")

    def _emit_session_auth(self) -> None:
        """``session.auth`` for ``Plan.auth`` (DESIGN.md §13.2), right after the Session is created."""
        auth = self.plan.auth
        if auth is None:
            return
        w = self.w
        kind = str(auth.kind or "").lower()
        who = f"（記録時のユーザー: {auth.username}）" if auth.username else ""
        if kind == "basic":
            self._c(f"HTTP Basic 認証{who}")
            w.line(f"session.auth = ({self.auth_user_const}, {self.auth_pw_const})")
        elif kind == "digest":
            self._c(f"HTTP Digest 認証{who}")
            w.line(f"session.auth = requests.auth.HTTPDigestAuth({self.auth_user_const}, {self.auth_pw_const})")
        elif kind in ("ntlm", "negotiate"):
            self._c(f"統合 Windows 認証（NTLM / Negotiate）: 記録時のユーザー: {auth.username or '不明'}")
            w.line("try:")
            with w.indent():
                self._cl("from requests_negotiate_sspi import HttpNegotiateAuth",
                         'Windows: 今ログインしているユーザーで認証（pip install "reqrec[sspi]"）')
                w.line("session.auth = HttpNegotiateAuth()")
            w.line("except ImportError:")
            with w.indent():
                w.line("try:")
                with w.indent():
                    self._cl("from requests_ntlm import HttpNtlmAuth",
                             '他の OS / 別ユーザーで認証する場合（pip install "reqrec[ntlm]"）')
                w.line("except ImportError:")
                with w.indent():
                    w.line("raise SystemExit(")
                    with w.indent():
                        w.line(_lit('統合 Windows 認証には追加パッケージが必要です: pip install "reqrec[sspi]"（Windows）'
                                    ' または pip install "reqrec[ntlm]"（他の OS。環境変数 REQREC_NTLM_USER / REQREC_NTLM_PASSWORD も設定）'))
                    w.line(") from None")
                user_default = _lit(auth.username) if auth.username else _NTLM_USER_PLACEHOLDER
                w.line(
                    f'session.auth = HttpNtlmAuth(os.environ.get("REQREC_NTLM_USER", {user_default}), '
                    'os.environ.get("REQREC_NTLM_PASSWORD", ""))'
                )
        else:
            self._note(f"未対応の認証方式 {kind!r} が検出されました。生成コードの TODO で session.auth を設定してください")
            self._c(f"TODO: 認証方式 {kind!r} は自動設定できません。ここで session.auth を設定してください")

    def _call(self, step: Step, fname: str) -> list[str]:
        params = self._step_params(step)
        args = ["session"]
        for p in params:
            if step.loop is not None and p == step.loop.var:
                args.append(p)
            else:
                args.append(f"{p}=ctx[{_lit(p)}]")
        line = f"resp, out = {fname}({', '.join(args)})"
        if len(line) <= 92:
            return [line]
        return [f"resp, out = {fname}("] + _indent_block([a + "," for a in args]) + [")"]

    @staticmethod
    def _final_needs_saved(step: Step) -> bool:
        """Whether the final print block depends on ``final_saved`` (the step was saved as a file)."""
        return step.loop is None and (step.response_kind or "empty") in ("json", "html", "empty")

    def _emit_save(self, step: Step, *, target: str = "") -> None:
        """Save the response just received when it is a file (DESIGN.md §13.13 download rule):
        a binary body always, any other kind when ``Content-Disposition`` says attachment."""
        if step.response_kind == "binary":
            self._cl(target + "_save_download(resp)", "ダウンロードしたファイル（Excel など）を、サーバーが付けた名前で保存する")
        else:
            self._cl(target + "_save_if_attachment(resp)", "ファイル（Excel / CSV など）として返ってきたら保存する")

    def _emit_main_step(self, step: Step, fname: str, *, sleep: bool, final: bool = False) -> None:
        w = self.w
        desc = step.comment or f"{str(step.method).upper()} {self._url_display(step.url)}"
        if step.loop is None:
            self._c(f"ステップ {step.index}: {desc}")
            w.block(self._call(step, fname))
            w.line("ctx.update(out)")
            if final:
                self._cl("final_resp = resp", "このステップの結果を最後に表示する")
            # a file is saved right after its own request, so a later failing step cannot lose it
            self._emit_save(step, target="final_saved = " if final and self._final_needs_saved(step) else "")
            if sleep:
                w.line("time.sleep(DELAY)")
            return
        loop = step.loop
        var = _check_identifier(loop.var, "loop variable")
        iterable = self._loop_iterable(loop)
        self._c(f"ステップ {step.index}: {desc}")
        if loop.note and str(loop.note) not in desc:
            self._c(f"繰り返し: {loop.note}")
        w.line("results = []")
        if iterable == "[]":
            w.line("out = {}")
        w.line(f"for {var} in {iterable}:")
        with w.indent():
            w.block(self._call(step, fname))
            if step.response_kind == "binary":
                self._cl("results.append(_save_download(resp))", "ファイルを保存し、保存先のパスを結果に入れる")
            else:
                self._emit_save(step)
                w.line("results.append(" + ("resp.json()" if step.response_kind == "json" else "_text(resp)") + ")")
            if sleep:
                w.line("time.sleep(DELAY)")
        w.line("ctx.update(out)")
        if final:
            self._cl("final_results = results", "このステップの結果（全ページ）を最後に表示する")

    @staticmethod
    def _loop_iterable(loop) -> str:
        rng = loop.numeric_range
        if rng is not None:
            try:
                start, end = int(rng[0]), int(rng[1])
            except (TypeError, ValueError, IndexError):
                start = end = None  # type: ignore[assignment]
            if start is not None:
                if start <= end:
                    return f"range({start}, {end + 1})"
                return f"range({start}, {end - 1}, -1)"
        values = list(loop.values or [])
        if not values:
            return "[]"
        return "[" + ", ".join(_lit(v) for v in values) + "]"

    def _emit_final(self, step: Step) -> None:
        """Print block for the chosen step (``final_resp`` / ``final_results`` set in main())."""
        w = self.w
        kind = step.response_kind or "empty"
        looped = step.loop is not None
        label = f"ステップ {step.index}: {str(step.method).upper()} {self._url_display(step.url)}"
        if self.plan.final_step_index is not None:
            self._c(f"===== 結果を表示（{label}） =====")
        else:
            self._c(f"===== 最後のステップの結果を表示（{label}） =====")
        # Files were already saved right after the step's own request (_emit_main_step): this block
        # only prints / previews, it never saves a second time.
        if looped and kind == "json":
            w.line("print(json.dumps(final_results, ensure_ascii=False, indent=2))")
            return
        if looped and kind == "binary":
            self._c("各回のファイルは上で保存済みです（final_results に保存先のパスが入っています）")
            return
        if looped:
            self._c("final_results に各ページの本文（文字列）が入っています")
            w.line("for text in final_results:")
            with w.indent():
                w.line("print(text[:2000])")
            return
        if kind == "binary":
            self._c("ダウンロードしたファイルは上（このステップの直後）で保存済みです")
            return
        if not self._final_needs_saved(step):  # text / xml / unknown: the same preview either way
            w.line("print(_text(final_resp)[:2000])")
            return
        if kind == "json":
            self._c("ファイルとして保存した場合は先頭だけ表示する")
            w.line("if final_saved:")
            with w.indent():
                w.line("print(_text(final_resp)[:2000])")
            w.line("else:")
            with w.indent():
                w.line("try:")
                with w.indent():
                    w.line("print(json.dumps(final_resp.json(), ensure_ascii=False, indent=2))")
                w.line("except ValueError:")
                with w.indent():
                    w.line("print(_text(final_resp)[:2000])")
            return
        self._c("ファイルとして保存した場合は、上の「保存しました」の表示だけ")
        w.line("if not final_saved:")
        with w.indent():
            if kind == "html":
                w.line("soup = _soup(final_resp)")
                w.line("print(soup.title.get_text(strip=True) if soup.title else final_resp.url)")
                self._c("TODO: 必要なデータを soup から取り出してください（例: soup.select('table tr')）")
            else:  # empty
                w.line("print(final_resp.status_code, final_resp.url)")


# =========================================================================== module-level helpers

#: Emitted verbatim (top level) whenever the plan has steps: the DESIGN.md §13.13 download rule.
#:
#: * ``_is_attachment``: ``Content-Disposition`` (stripped, lower-cased) starts with ``attachment``,
#:   or contains ``filename`` and does not start with ``inline`` (``inline; filename=f.txt`` is
#:   Spring's RFD protection on every JSON response, not a download).  ``util.is_attachment_disposition``
#:   is the same rule for the GUI.
#: * ``_download_name``: RFC 6266 ``filename*=``, RFC 2047 encoded words (``=?UTF-8?B?...?=`` from
#:   .NET), IE-style percent-encoded UTF-8, or raw UTF-8 / Shift_JIS bytes that http.client decoded
#:   as Latin-1; else the URL's last segment; else ``output`` + an extension from the MIME type.
#:   ``_safe_file_name`` removes path parts and characters Windows forbids, prefixes reserved device
#:   names (``CON``, ``NUL``, ``COM1`` ... with any extension) with ``_`` and shortens names longer
#:   than 150 characters keeping the extension.  ``util.download_filename`` mirrors it.
#: * ``_save_download``: writes into ``REQREC_OUTPUT_DIR`` or the current directory and prints the
#:   path; a second file with the same name in one run becomes ``name (2).ext``, then ``(3)``
#:   (``_SAVED_PATHS``, module level = one run); a file left by a previous run is overwritten.
#: * ``_save_if_attachment``: ``_save_download`` when ``_is_attachment``, else None.
#:
#: No ``#`` comments (``comments=False`` must produce a comment-free script); Python 3.8 syntax.
_DOWNLOAD_HELPERS_SRC = r'''
def _is_attachment(resp):
    """サーバーが「ファイルとして保存」を指示しているか（Content-Disposition を見る）。

    attachment で始まるか、filename を含む（inline で始まるものを除く）ときに True。
    "inline; filename=..." は「画面に表示してよい」という指示なので保存しない。
    """
    disposition = (resp.headers.get("Content-Disposition") or "").strip().lower()
    if disposition.startswith("attachment"):
        return True
    return "filename" in disposition and not disposition.startswith("inline")


_PAGE_EXTENSIONS = {
    "aspx", "asp", "ashx", "asmx", "axd", "php", "jsp", "jspx", "do", "action", "cgi", "pl", "py",
    "html", "htm", "shtml", "xhtml", "cfm", "nsf",
}
_RESERVED_FILE_NAME_RE = re.compile(r"(con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])", re.I)
_MAX_FILE_NAME = 150
_SAVED_PATHS = set()


def _unquote(text, encoding):
    """URL エンコードされたファイル名を戻す（知らない文字コード名なら UTF-8 として読む）。"""
    from urllib.parse import unquote
    try:
        return unquote(text, encoding=encoding or "utf-8", errors="replace")
    except LookupError:
        return unquote(text, encoding="utf-8", errors="replace")


def _decode_words(text):
    """=?UTF-8?B?...?= / =?Shift_JIS?Q?...?= の形（RFC 2047。.NET などが付ける）を元の文字に戻す。"""
    from email.header import decode_header
    try:
        parts = decode_header(text)
    except Exception:
        return text
    out = []
    for part, charset in parts:
        if isinstance(part, str):
            out.append(part)
        elif charset:
            out.append(part.decode(_normalise_charset(charset) or "utf-8", "replace"))
        else:
            out.append(part.decode("raw-unicode-escape", "replace"))
    return "".join(out)


def _safe_file_name(name):
    """Windows でそのまま使えるファイル名にする。

    フォルダ部分と使えない文字を除き、予約名（CON, NUL, COM1 など。拡張子付きも）には先頭に _ を付け、
    150 文字を超える名前は拡張子を残して短くする。
    """
    name = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", name).strip(" .")
    if not name:
        return ""
    if _RESERVED_FILE_NAME_RE.fullmatch(name.split(".", 1)[0].rstrip(" ")):
        name = "_" + name
    if len(name) > _MAX_FILE_NAME:
        stem, ext = os.path.splitext(name)
        if len(ext) > 16:
            stem, ext = name, ""
        name = stem[:_MAX_FILE_NAME - len(ext)].rstrip(" .") + ext
    return name


def _download_name(resp):
    """保存するファイル名: Content-Disposition のファイル名 → URL の末尾 → output + 拡張子。

    filename*=UTF-8''...（RFC 6266）、=?UTF-8?B?...?=（RFC 2047）、IE 向けに URL エンコードされた
    UTF-8、Shift_JIS / UTF-8 の生バイト（requests は Latin-1 として読むので元に戻して読み直す）に対応する。
    """
    from urllib.parse import urlsplit
    import mimetypes

    disposition = resp.headers.get("Content-Disposition") or ""
    name = None
    m = re.search(r"filename\*\s*=\s*([^';]*)'[^']*'([^;]+)", disposition, re.I)
    if m:
        name = _unquote(m.group(2).strip().strip('"'), m.group(1).strip())
    else:
        m = re.search(r'filename\s*=\s*(?:"([^"]*)"|([^;]+))', disposition, re.I)
        if m:
            raw = (m.group(1) if m.group(1) is not None else m.group(2)).strip()
            decoded = _decode_words(raw) if "=?" in raw else raw
            if decoded != raw:
                name = decoded
            elif re.search(r"%[0-9A-Fa-f]{2}", raw):
                name = _unquote(raw, "utf-8")
            else:
                name = raw
                for codec in ("utf-8", "cp932"):
                    try:
                        name = raw.encode("latin-1").decode(codec)
                        break
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        continue
    name = _safe_file_name(name)
    if not name:
        last = _unquote(urlsplit(resp.url).path.rsplit("/", 1)[-1], "utf-8")
        ext = last.rsplit(".", 1)[-1].lower() if "." in last else ""
        name = _safe_file_name(last) if ext and ext not in _PAGE_EXTENSIONS else ""
    if not name:
        mime = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        known = {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
            "application/vnd.ms-excel": ".xls",
            "text/csv": ".csv",
            "application/pdf": ".pdf",
            "application/zip": ".zip",
            "text/plain": ".txt",
            "application/octet-stream": ".bin",
        }
        name = "output" + (known.get(mime) or mimetypes.guess_extension(mime or "") or ".bin")
    return name


def _save_download(resp):
    """本文をファイルに保存し、保存先を表示してパスを返す。

    保存先は環境変数 REQREC_OUTPUT_DIR（無ければ実行したフォルダ）。1 回の実行で同じ名前のファイルが
    2 つ目以降に来たら「名前 (2).xlsx」「名前 (3).xlsx」のように番号を付ける（前回の実行で残った
    ファイルは上書きする）。
    """
    folder = os.environ.get("REQREC_OUTPUT_DIR") or os.getcwd()
    os.makedirs(folder, exist_ok=True)
    stem, ext = os.path.splitext(_download_name(resp))
    path = os.path.join(folder, stem + ext)
    number = 2
    while os.path.normcase(os.path.abspath(path)) in _SAVED_PATHS:
        path = os.path.join(folder, "{} ({}){}".format(stem, number, ext))
        number += 1
    _SAVED_PATHS.add(os.path.normcase(os.path.abspath(path)))
    with open(path, "wb") as fh:
        fh.write(resp.content)
    print("{} に保存しました ({} バイト)".format(path, len(resp.content)))
    return path


def _save_if_attachment(resp):
    """サーバーが「ファイルとして保存」を指示していれば保存してパスを返す（それ以外は None）。"""
    if _is_attachment(resp):
        return _save_download(resp)
    return None
'''

#: Names the download helpers define at module level (step functions must not reuse them).
_DOWNLOAD_HELPER_NAMES = frozenset({
    "_is_attachment", "_PAGE_EXTENSIONS", "_RESERVED_FILE_NAME_RE", "_MAX_FILE_NAME", "_SAVED_PATHS",
    "_unquote", "_decode_words", "_safe_file_name", "_download_name", "_save_download", "_save_if_attachment",
})


def _env_name(const: Constant) -> str:
    env = const.env_var or f"REQREC_{const.name}"
    env = re.sub(r"[^0-9A-Za-z_]", "_", str(env)).upper() or f"REQREC_{const.name}"
    return env


def _dotted(path: Sequence[Any]) -> str:
    out = ""
    for p in path:
        if isinstance(p, int) and not isinstance(p, bool):
            out += f"[{p}]"
        else:
            out += ("." if out else "") + str(p)
    return out or "(root)"


def _auth_scheme_of(ref: Any) -> Optional[str]:
    """Lower-case ``Authorization`` scheme of a header Ref (``"NTLM TlRM..."`` -> ``"ntlm"``), or None
    when it cannot be told statically (``Ref.var``, exprs not starting with a scheme literal)."""
    if not isinstance(ref, Ref):
        return str(ref).split(None, 1)[0].lower() if str(ref).strip() else None
    if ref.kind == "literal":
        parts = str(ref.value).split(None, 1)
        return parts[0].lower() if parts else None
    if ref.kind == "expr":
        m = _AUTH_EXPR_SCHEME_RE.match(str(ref.value))
        return m.group(2).lower() if m else None
    return None


def _bytes_literal_value(src: str) -> Optional[bytes]:
    """The value of a ``Ref.expr`` that is a plain ``bytes`` literal (plan.py emits recorded
    legacy-charset form values that way), else None."""
    try:
        node = ast.parse(str(src).strip(), mode="eval").body
    except SyntaxError:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return node.value
    return None


def _legacy_bytes_note(raw: bytes) -> str:
    """Comment for a legacy-charset form value: decoded text (when it is cp932 / EUC-JP) and the
    percent-encoded spelling the browser sent, so the user can recognise ``b'\\x93\\xfa'`` as 日本."""
    spelled = quote_from_bytes(raw, safe="").upper()
    for enc in ("cp932", "euc_jp", "iso2022_jp"):
        try:
            text = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if text and all(ch.isprintable() for ch in text):
            return _comment_text(f"{enc} で「{util.truncate(text, 40)}」（記録時の表記: {util.truncate(spelled, 60)}）")
    return _comment_text(f"記録時の表記: {util.truncate(spelled, 60)}")


def _helpers_for_extractor(ext: Extractor) -> set[str]:
    kind = ext.kind
    need: set[str] = set()
    if kind in ("html_input", "html_meta", "html_attr"):
        need |= {"_soup", "_attr"}
    elif kind == "html_text":
        need |= {"_soup", "_elem_text"}
    elif kind == "json":
        need.add("_json_path")
    if kind in ("regex", "url") or (kind in ("html_attr", "html_text") and ext.pattern):
        need.add("_regex")
    return need


def _json_refs(node: Any) -> Iterator[Ref]:
    if isinstance(node, Ref):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _json_refs(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _json_refs(v)


# =========================================================================== public API

def generate(plan: Plan, opts: Optional[GenOptions] = None) -> str:
    """Render ``plan`` as the source of a standalone Python scraping script.

    The result always compiles (``compile(src, "<gen>", "exec")``), ends with a newline and has
    no trailing whitespace.  Codegen-time notes (oversized bodies that were not embedded,
    extractors that could not be rendered, dropped ``Authorization`` headers, a missing final
    step) are listed in the module docstring and appended to ``plan.warnings``.  Raises
    :class:`CodegenError` when the plan holds an invalid identifier or a malformed ``Ref.expr``.
    """
    return _Generator(plan, opts or GenOptions()).generate()


__all__ = ["generate", "CodegenError", "MAX_INLINE_BODY"]
