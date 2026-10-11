"""Recording -> Plan.  Contract: DESIGN.md §7.

``build_plan`` turns the kept flows of a recording into ``Step`` objects, replacing every request
value that can be traced to an earlier response (``deps``), to a cookie, to the clock, or to a
repeated literal (``Constant``) by a ``Ref`` that the generated script resolves at run time.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import unquote, urlsplit

from . import deps, util
from .filters import (
    SESSION_AUTH_SCHEMES,
    auth_family,
    classify_cookies,
    clean_request_headers,
    collapse_auth_handshakes,
    collapse_redirects,
    compute_base_headers,
    decode_basic_credentials,
    filter_flows,
    normalise_flow_id,
)
from .loops import LoopGroup, detect_loops
from .model import (
    AuthInfo,
    Constant,
    Dropped,
    Extractor,
    Flow,
    Loop,
    MultipartPart,
    Plan,
    PlanOptions,
    Recording,
    Ref,
    Step,
)

#: Identifiers the generated script defines itself; never reused for variables / constants.
_CODEGEN_NAMES = frozenset({
    "TIMEOUT", "DELAY", "BASE_HEADERS", "INITIAL_COOKIES", "main", "session", "resp", "soup", "ctx",
    "results", "data", "step", "requests", "re", "json", "os", "sys", "time", "unquote", "urljoin",
    "BeautifulSoup", "_soup", "_check", "_regex", "_json_path", "_attr", "_text",
})
_GENERIC_JSON_KEYS = frozenset({"id", "value", "token", "code", "key", "name", "data", "result"})
_WORD_RE = re.compile(r"^[A-Za-z][A-Za-z_-]*$")
_FILENAME_RE = re.compile(r"^[A-Za-z][A-Za-z_-]*\.[A-Za-z]{1,5}$")  # Default.aspx, index.html ...
_IDENT_HINT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]{2,})[^A-Za-z0-9_-]*$")
_MAX_SLUG_LEN = 40


def _singular(word: str) -> str:
    """Crude English singularisation for variable names (``orgs`` -> ``org``)."""
    w = word.lower()
    if len(w) > 4 and w.endswith("ies"):
        return w[:-3] + "y"
    if len(w) > 4 and w.endswith(("ses", "xes", "zes", "shes", "ches")):
        return w[:-2]
    if len(w) > 3 and w.endswith("s") and not w.endswith(("ss", "us", "is")):
        return w[:-1]
    return w


def _path_segments(url: str) -> list[str]:
    """Path segments as recorded (percent-encoding kept); index ``i`` matches ``Candidate.name``."""
    path = urlsplit(url).path
    if not path:
        return []
    return path.split("/")[1:] if path.startswith("/") else path.split("/")


def _json_leaf_name(path: Optional[list]) -> str:
    """Variable base name for a JSON path: the last object key, prefixed by its parent when generic."""
    if not path:
        return "value"
    keys = [p for p in path if isinstance(p, str)]
    if not keys:
        return "item"
    last = keys[-1]
    if last.lower() in _GENERIC_JSON_KEYS and len(keys) >= 2:
        return f"{_singular(keys[-2])}_{last}"
    return last


def _path_seg_name(segments: list[str], index: int) -> str:
    """Variable base name for a dynamic path segment: ``orgs/77`` -> ``org_id``."""
    prev = segments[index - 1] if 0 < index <= len(segments) else ""
    if prev and _WORD_RE.match(prev):
        return f"{_singular(prev)}_id"
    return f"path_seg_{index}"


def _route_word(url: str) -> str:
    """Identifier-friendly stem of the last path segment: ``/Report.aspx`` -> ``report``,
    ``/api/items`` -> ``item``; ``""`` when the path is ``/``."""
    segments = [s for s in _path_segments(url) if s]
    if not segments:
        return ""
    stem = segments[-1].rsplit(".", 1)[0] if _FILENAME_RE.match(segments[-1]) else segments[-1]
    word = util.safe_identifier(stem, default="")
    return _singular(word) if word and _WORD_RE.match(stem) else word


def _is_reserved_name(base: str) -> bool:
    """True when ``safe_identifier`` had to rename ``base`` because it is a keyword / builtin
    (``id`` -> ``id_``, ``type`` -> ``type_``)."""
    ident = util.safe_identifier(base, default="value")
    return ident.endswith("_") and not base.rstrip().endswith("_")


def _route_like(value: str) -> bool:
    """Plain words and file names (``dashboard``, ``Default.aspx``) are route names, not tokens."""
    return _WORD_RE.match(value) is not None or _FILENAME_RE.match(value) is not None


def _name_hint_from_pattern(pattern: Optional[str]) -> Optional[str]:
    """``window\\.API_TOKEN="(...)`` -> ``API_TOKEN``: the last identifier before the capture group."""
    if not pattern:
        return None
    head = pattern.split("(", 1)[0]
    head = re.sub(r"\\(.)", r"\1", head)
    m = _IDENT_HINT_RE.search(head)
    return m.group(1) if m else None


def _with_prefix(prefix: str, ref: Ref) -> Ref:
    """Re-attach an ``Authorization`` scheme prefix (``"Bearer "``) to a resolved token Ref."""
    if not prefix:
        return ref
    if ref.is_literal:
        return Ref.lit(prefix + ref.value)
    src = ref.value
    if ref.kind == "expr" and (" + " in src or " if " in src or " or " in src):
        src = f"({src})"
    return Ref.expr(f"{json.dumps(prefix)} + {src}")


def _response_kind(flow: Flow) -> str:
    resp = flow.response
    if resp is None or not resp.body:
        return "empty"
    mime = (resp.mime_type or "").lower()
    if util.is_html_mime(mime):
        return "html"
    if util.is_json_mime(mime):
        return "json"
    if util.is_xml_mime(mime):
        return "xml"
    if util.is_textual_mime(mime):
        return "json" if deps.parse_json_text(resp.text()) is not None else "text"
    if not mime or mime == "application/octet-stream":
        head = resp.body[:4096]
        if b"\x00" in head:
            return "binary"
        text = resp.text() or ""
        if deps.parse_json_text(text) is not None:
            return "json"
        lead = text.lstrip()[:15].lower()
        if lead.startswith(("<!doctype", "<html")):
            return "html"
        if lead.startswith("<?xml"):
            return "xml"
        return "text" if not mime else "binary"
    return "binary"


@dataclass
class _Unit:
    """One future step: a list of redirect chains (several only when a loop was folded).

    ``hops`` maps ``id(flow)`` to the 401 challenge flows an authentication handshake folded into
    that flow (DESIGN.md §13.2); they are listed in ``source_flow_ids`` but never replayed."""

    groups: list[list[Flow]]
    loop: Optional[LoopGroup] = None
    hops: dict[int, list[Flow]] = field(default_factory=dict)

    @property
    def first_flow(self) -> Flow:
        return self.groups[0][0]

    @property
    def response_chain(self) -> list[Flow]:
        return self.groups[-1]

    @property
    def last_flow(self) -> Flow:
        return self.groups[-1][-1]

    @property
    def all_flows(self) -> list[Flow]:
        """Every recorded flow behind the step, chronologically (auth hops before their retry)."""
        out: list[Flow] = []
        for g in self.groups:
            for f in g:
                out.extend(self.hops.get(id(f), ()))
                out.append(f)
        return out

    @property
    def auth_hops(self) -> list[Flow]:
        return [h for g in self.groups for f in g for h in self.hops.get(id(f), ())]


@dataclass
class _Built:
    step: Step
    unit: _Unit
    extractors: dict[tuple, Extractor] = field(default_factory=dict)


class _Builder:
    """Stateful plan construction (one instance per ``build_plan`` call)."""

    def __init__(self, recording: Recording, opts: PlanOptions) -> None:
        self.recording = recording
        self.opts = opts
        self.warnings: list[str] = []
        self.constants: list[Constant] = []
        self.const_by_value: dict[str, Constant] = {}
        self.const_uses: dict[str, list[str]] = {}
        self.taken: set[str] = set(_CODEGEN_NAMES) | {n.lower() for n in _CODEGEN_NAMES}
        self.func_names: set[str] = set()
        self.built: list[_Built] = []
        self.earlier_flows: list[Flow] = []
        self.value_units: dict[str, set[int]] = {}
        self.base_headers = []
        self.base_set: set[tuple[str, str]] = set()
        # --- phase 2 (DESIGN.md §13) ---
        self.auth: Optional[AuthInfo] = None
        self.auth_hops: dict[int, list[Flow]] = {}  # id(final attempt) -> its 401 hops
        self.auth_credentials: Optional[tuple[str, str]] = None  # Basic: (user, password) behind Plan.auth
        self.auth_token_units: dict[str, set[int]] = {}  # session-auth tokens sent by several steps
        self.auth_header_warned: set[tuple[str, str]] = set()
        self.legacy_form_steps: list[int] = []

    # ------------------------------------------------------------------ naming

    def _cand_base_name(self, cand: deps.Candidate, flow: Flow) -> str:
        if cand.location == "json":
            return _json_leaf_name(cand.json_path)
        if cand.location == "path":
            try:
                return _path_seg_name(_path_segments(flow.request.url), int(cand.name))
            except ValueError:
                return f"path_seg_{cand.name}"
        return cand.name

    def _var_name(self, cand: deps.Candidate, ext: Extractor, flow: Flow) -> str:
        base = self._cand_base_name(cand, flow)
        if cand.location == "header" and cand.name == "authorization":
            # "authorization" says nothing about the token; prefer the name it had in the response
            hint = None
            if ext.kind == "json":
                hint = _json_leaf_name(ext.path)
            elif ext.kind in ("html_input", "html_meta", "header"):
                hint = ext.name
            elif ext.pattern:
                hint = _name_hint_from_pattern(ext.pattern)
            base = hint or "access_token"
        elif cand.location in ("query", "form", "multipart") and _is_reserved_name(base):
            # ``id`` / ``type`` ... are builtins: qualify them with the route they belong to
            # (``Report.aspx?id=`` -> ``report_id``) instead of the bare ``id_``
            route = _route_word(flow.request.url)
            if route and route != util.safe_identifier(base).rstrip("_"):
                base = f"{route}_{base}"
        return util.unique_name(util.safe_identifier(base, default="value"), self.taken)

    def _loop_var(self, lg: LoopGroup, flow: Flow) -> str:
        if lg.location == "json":
            base = lg.name.split(".")[-1].split("[")[0] or "item"  # last object key of the dotted path
        elif lg.location == "path":
            try:
                base = _path_seg_name(_path_segments(flow.request.url), int(lg.name))
            except ValueError:
                base = "page"
        else:
            base = lg.name
        return util.unique_name(util.safe_identifier(base, default="page"), self.taken)

    def _func_name(self, index: int, flow: Flow, dynamic_segments: set[int]) -> str:
        segments = _path_segments(flow.request.url)
        parts = [s for i, s in enumerate(segments) if s and i not in dynamic_segments and not s.isdigit()]
        slug_src = "_".join(parts[-2:]) if parts else flow.request.host
        slug = util.safe_identifier(slug_src, default="root")[:_MAX_SLUG_LEN].strip("_") or "root"
        base = f"step_{index:02d}_{flow.request.method.lower()}_{slug}"
        return util.unique_name(base, self.func_names)

    # ------------------------------------------------------------------ constants

    def _constant(self, cand: deps.Candidate, value: str, flow: Flow, step_no: int, force_secret: bool = False) -> Ref:
        secret = self.opts.redact_secrets and (force_secret or util.looks_like_secret_name(cand.name))
        const = self.const_by_value.get(value)
        if const is None:
            base = util.safe_identifier(self._cand_base_name(cand, flow), default="value").upper()
            name = util.unique_name(base, self.taken)
            const = Constant(name=name, value=value, secret=secret, env_var=f"REQREC_{name}" if secret else None)
            self.constants.append(const)
            self.const_by_value[value] = const
            self.const_uses[name] = []
            if secret:
                self.warnings.append(
                    f"step {step_no}: `{cand.name}` looks like a credential; the script reads it from the "
                    f"environment variable {const.env_var} (set it before running)"
                )
        elif secret and not const.secret:
            const.secret = True
            const.env_var = f"REQREC_{const.name}"
        self.const_uses[const.name].append(f"step {step_no} ({cand.location} `{cand.name}`)")
        return Ref.var(const.name)

    # ------------------------------------------------------------------ HTTP authentication (DESIGN.md §13.2)

    def _setup_auth(self, flows: list[Flow]) -> None:
        """Turn the detected ``AuthInfo`` into constants / warnings before any step is built.

        Basic: ``AUTH_USERNAME`` (plain) + ``AUTH_PASSWORD`` (secret, env ``REQREC_AUTH_PASSWORD``
        unless ``redact_secrets`` is off).  Digest: the same two, but the password is never on the
        wire, so it is always read from the environment.  NTLM / Negotiate: no constants (codegen
        uses ``REQREC_NTLM_USER`` / ``REQREC_NTLM_PASSWORD`` with the recorded user as default)."""
        auth = self.auth
        if auth is None:
            return
        kind = auth.kind
        if kind in ("ntlm", "negotiate"):
            who = f"（記録時のユーザー: {auth.username}）" if auth.username else "（記録からユーザー名を特定できませんでした）"
            self.warnings.append(
                f"統合 Windows 認証 ({kind}) を検出しました{who}。Windows 以外で実行する場合や別のユーザーで実行する場合は"
                f"環境変数 REQREC_NTLM_USER / REQREC_NTLM_PASSWORD を設定してください"
            )
            return
        user = auth.username or ""
        password: Optional[str] = None
        if kind == "basic":
            for flow in flows:
                value = flow.request.header("authorization")
                prefix, token = deps.split_auth_header(value)
                if prefix.strip().lower() != "basic":
                    continue
                if auth.hosts and flow.request.host not in auth.hosts:
                    continue
                creds = decode_basic_credentials(token)
                if creds is not None:
                    user, password = creds
                    self.auth_credentials = creds
                    break
        secret = self.opts.redact_secrets or password is None
        user_const = Constant(
            name=util.unique_name("AUTH_USERNAME", self.taken), value=user, secret=False,
            comment=f"HTTP {kind.capitalize()} 認証のユーザー名",
        )
        pw_const = Constant(
            name=util.unique_name("AUTH_PASSWORD", self.taken), value=password or "", secret=secret,
            env_var=None, comment=f"HTTP {kind.capitalize()} 認証のパスワード",
        )
        if secret:
            pw_const.env_var = f"REQREC_{pw_const.name}"
            pw_const.comment += f"（環境変数 {pw_const.env_var} で指定）"
        self.constants.extend((user_const, pw_const))
        for const in (user_const, pw_const):
            self.const_uses[const.name] = []
        if user:
            self.const_by_value.setdefault(user, user_const)
        if password:
            self.const_by_value.setdefault(password, pw_const)
        auth.username_const = user_const.name
        auth.password_const = pw_const.name
        if not auth.username and user:
            auth.username = user
        if password is None:
            self.warnings.append(
                f"HTTP {kind.capitalize()} 認証を検出しましたが、パスワードは記録から取得できません。"
                f"実行前に環境変数 {pw_const.env_var} を設定してください"
            )
        elif secret:
            self.warnings.append(
                f"HTTP {kind.capitalize()} 認証（ユーザー: {user}）を検出しました。パスワードは環境変数 {pw_const.env_var} "
                f"から読み込みます（実行前に設定してください）"
            )

    def _auth_covers(self, scheme: str, token: str) -> bool:
        """Does ``session.auth`` (from ``Plan.auth``) replace this ``Authorization`` header?"""
        if self.auth is None or scheme not in auth_family(self.auth.kind):
            return False
        if scheme == "basic" and self.auth_credentials is not None:
            creds = decode_basic_credentials(token)
            return creds is None or creds == self.auth_credentials
        return True

    def _session_auth_header(self, value: str, flow: Flow, step_no: int) -> Optional[Ref]:
        """Ref for an NTLM / Negotiate / Basic / Digest ``Authorization`` header, or None when
        the header must be dropped because ``Plan.auth`` configures the same authentication.

        A header that is *not* covered (detection disabled, or different credentials / scheme than
        the detected one) is kept, but never as a plain literal when secrets are redacted."""
        prefix, token = deps.split_auth_header(value)
        scheme = prefix.strip().lower()
        if self._auth_covers(scheme, token):
            return None
        host = flow.request.host
        if self.auth is not None and (scheme, host) not in self.auth_header_warned:
            self.auth_header_warned.add((scheme, host))
            self.warnings.append(
                f"step {step_no}: {host} への Authorization ({prefix.strip()}) は検出した認証 ({self.auth.kind}) の対象外のため、"
                f"ヘッダーをそのまま再送します"
            )
        if not token:
            return Ref.lit(value)
        cand = deps.Candidate("header", "authorization", token, prefix=prefix)
        if self.opts.redact_secrets or len(self.auth_token_units.get(token, ())) >= 2:
            return _with_prefix(prefix, self._constant(cand, token, flow, step_no, force_secret=True))
        return Ref.lit(prefix + token)

    # ------------------------------------------------------------------ legacy-charset forms (DESIGN.md §13.4)

    @staticmethod
    def _legacy_form_hint(body: Optional[bytes], parsed: list[tuple[str, str]],
                          form: list[tuple[str, Ref]]) -> list[tuple[str, Ref]]:
        """``form`` pairs for a body replayed as raw bytes: traced values keep their Ref, values
        that are not UTF-8 become bytes literals (``requests`` percent-encodes bytes verbatim)."""
        raw_pairs = deps.form_pairs_bytes(body)
        out: list[tuple[str, Ref]] = []
        for i, (name, ref) in enumerate(form):
            raw_value = raw_pairs[i][1] if i < len(raw_pairs) else b""
            if ref.is_literal:
                try:
                    raw_value.decode("utf-8")
                except UnicodeDecodeError:
                    ref = Ref.expr(repr(raw_value))
            out.append((name, ref))
        return out

    # ------------------------------------------------------------------ manual overrides (DESIGN.md §13.1)

    def _final_step_index(self, steps: list[Step], dropped: list[Dropped]) -> Optional[int]:
        raw = self.opts.final_flow_id
        if raw is None or not str(raw).strip():
            return None
        wanted = normalise_flow_id(raw)
        for step in steps:
            ids = set(step.source_flow_ids) | {normalise_flow_id(i) for i in step.source_flow_ids}
            if wanted in ids or str(raw).strip() in ids:
                return step.index
        hit = next((d for d in dropped if d.flow_id == wanted or normalise_flow_id(d.flow_id) == wanted), None)
        if hit is not None:
            self.warnings.append(
                f"結果に指定したフロー {wanted} は除外されているためステップになっていません（{hit.reason}）。"
                f"最後のステップの結果を表示します"
            )
        elif self.recording.flow_by_id(wanted) is None and self.recording.flow_by_id(str(raw).strip()) is None:
            self.warnings.append(f"結果に指定したフロー {wanted} は記録に存在しません。最後のステップの結果を表示します")
        else:  # pragma: no cover - every kept flow is in some step
            self.warnings.append(f"結果に指定したフロー {wanted} はステップになっていません。最後のステップの結果を表示します")
        return None

    # ------------------------------------------------------------------ resolution

    @staticmethod
    def _cookie_ref(name: str, cookie_value: str, value: str) -> Ref:
        get = f"session.cookies.get({json.dumps(name)})"
        if cookie_value == value:
            return Ref.expr(get)
        if unquote(cookie_value) == value:
            return Ref.expr(f"unquote({get})")
        if cookie_value.strip('"') == value:
            return Ref.expr(f"{get}.strip('\"')")
        return Ref.expr(get)  # value is an encoded spelling of the cookie: requests encodes it again

    @staticmethod
    def _adapt(ext: Extractor, value: str) -> Ref:
        """Ref for an extractor whose recorded spelling may differ from the request value."""
        var = ext.var
        sample = ext.sample
        if sample is None or sample == value:
            return Ref.var(var)
        if unquote(sample) == value:
            return Ref.expr(f"unquote({var})")
        if sample == value.replace("/", "\\/"):
            return Ref.expr(f"{var}.replace({'\\/'!r}, '/')")
        return Ref.var(var)

    def _extractor_key(self, ext: Extractor) -> tuple:
        return (ext.kind, ext.name, tuple(ext.path) if ext.path else None, ext.selector, ext.attr, ext.pattern)

    def _register(self, built: _Built, ext: Extractor, cand: deps.Candidate, flow: Flow, step_no: int,
                  note: Optional[str] = None) -> Extractor:
        key = self._extractor_key(ext)
        use = f"step {step_no} ({cand.location} `{cand.name}`)"
        existing = built.extractors.get(key)
        if existing is not None:
            if existing.note and use not in existing.note:
                existing.note += f", {use}"
            return existing
        ext.var = self._var_name(cand, ext, flow)
        ext.note = f"used by {use}" + (f"; {note}" if note else "")
        built.extractors[key] = ext
        built.step.extractors.append(ext)
        return ext

    def _structural_only(self, value: str) -> bool:
        """Values that must be found by an exact structural match (JSON leaf, ``<input>``, ``<meta>``,
        whole attribute / text, header), never by a regex or a substring pattern: plain words such as
        path names (``dashboard``, ``Default.aspx``) and values shorter than ``min_value_length``
        (a short id like ``77``) occur in many places by coincidence."""
        return len(value) < self.opts.min_value_length or _route_like(value)

    def _accept(self, ext: Optional[Extractor], value: str) -> Optional[Extractor]:
        if ext is not None and ext.pattern and self._structural_only(value):
            return None
        return ext

    def _trace(self, value: str, cand: deps.Candidate, flow: Flow, step_no: int) -> Optional[Ref]:
        """Search earlier steps' responses, latest first."""
        for built in reversed(self.built):
            chain = built.unit.response_chain
            ext = self._accept(deps.locate_value(value, chain[-1]), value)
            note = None
            if ext is None:
                for k in range(len(chain) - 2, -1, -1):
                    kinds = frozenset({"header", "url"}) if k == len(chain) - 2 else frozenset({"header"})
                    ext = self._accept(deps.locate_value_kinds(value, chain[k], kinds), value)
                    if ext is not None:
                        if ext.kind == "header":
                            note = f"from an intermediate redirect response ({chain[k].id}); check resp.history"
                        break
            if ext is None:
                continue
            ext = self._register(built, ext, cand, flow, step_no, note)
            return self._adapt(ext, value)
        return None

    def _resolve(self, cand: deps.Candidate, unit: _Unit, step_no: int, cache: dict[str, Ref]) -> Ref:
        value = cand.value
        if value in cache:
            return cache[value]
        flow = unit.first_flow
        ref: Optional[Ref] = None
        ts = util.looks_like_timestamp(value, around=flow.started_at)
        if ts:
            expr = "int(time.time()*1000)" if ts == "ms" else "int(time.time())"
            ref = Ref.expr(expr if cand.numeric else f"str({expr})")
        if ref is None:
            hit = deps.find_cookie(value, self.earlier_flows)
            if hit:
                ref = self._cookie_ref(hit[0], hit[1], value)
        if ref is None:
            ref = self._trace(value, cand, flow, step_no)
        if ref is None and len(self.value_units.get(value, ())) >= 2 and not (cand.location == "path" and _route_like(value)):
            # a repeated literal becomes a shared Constant - except route names in the path
            # (``GET /Default.aspx`` then ``POST /Default.aspx``), which stay part of the URL
            ref = self._constant(cand, value, flow, step_no)
        if ref is None and value in self.const_by_value:
            # the same value already has a Constant (e.g. AUTH_USERNAME from the Basic handshake)
            ref = self._constant(cand, value, flow, step_no)
        if ref is None and self.opts.redact_secrets and util.looks_like_secret_name(cand.name):
            ref = self._constant(cand, value, flow, step_no, force_secret=True)
        if ref is None:
            if deps.is_dynamic_looking(value):
                label = f"path segment {cand.name}" if cand.location == "path" else cand.name
                self.warnings.append(
                    f"step {step_no}: value of `{label}` looks dynamic but could not be traced to any earlier "
                    f"response; replaying the recorded literal may fail"
                )
            ref = Ref.lit(value)
        cache[value] = ref
        return ref

    # ------------------------------------------------------------------ step construction

    def _build_step(self, unit: _Unit, index: int) -> Step:
        flow = unit.first_flow
        req = flow.request
        last = unit.last_flow
        resp = last.response
        step_no = index
        cands = deps.find_candidates(flow, self.opts)
        loop: Optional[Loop] = None
        loop_key: Optional[tuple[str, str, int]] = None
        loop_first_value: Optional[tuple[str, str, str]] = None
        if unit.loop is not None:
            lg = unit.loop
            var = self._loop_var(lg, flow)
            loop = Loop(var=var, values=list(lg.values), numeric_range=lg.numeric_range,
                        note=f"{len(lg.groups)} iterations of {lg.location} `{lg.name}`: {util.truncate(', '.join(lg.values), 60)}")
            loop_key = (lg.location, lg.name, lg.occurrence)
            loop_first_value = (lg.location, lg.name, lg.values[0] if lg.values else "")

        refs: dict[tuple[str, str, str], Ref] = {}
        cand_by_key: dict[tuple[str, str, str], deps.Candidate] = {}
        cache: dict[str, Ref] = {}
        for cand in cands:
            key = (cand.location, cand.name, cand.value)
            cand_by_key.setdefault(key, cand)
            if key in refs or key == loop_first_value:
                continue
            refs[key] = self._resolve(cand, unit, step_no, cache)

        counters: dict[tuple[str, str], int] = {}

        def ref_for(location: str, name: str, value: str) -> Ref:
            occ = counters.get((location, name), 0)
            counters[(location, name)] = occ + 1
            if loop is not None and loop_key == (location, name, occ):
                return Ref.var(loop.var)
            return refs.get((location, name, value), Ref.lit(value))

        # URL pieces (path segments may be dynamic)
        parts = urlsplit(req.url)
        segments = _path_segments(req.url)
        url: list[Ref] = []
        buf = f"{parts.scheme}://{parts.netloc}"
        dynamic_segments: set[int] = set()
        for i, seg in enumerate(segments):
            buf += "/"
            ref = ref_for("path", str(i), seg) if seg else Ref.lit(seg)
            if ref.is_literal:
                buf += ref.value
            else:
                dynamic_segments.add(i)
                if buf:
                    url.append(Ref.lit(buf))
                url.append(ref)
                buf = ""
        if buf or not url:
            url.append(Ref.lit(buf))

        params = [(name, ref_for("query", name, value)) for name, value in util.parse_query(req.query)]

        # body
        body_kind, parsed = deps.classify_body(req)
        form = json_body = multipart = raw_body = None
        if body_kind == "form":
            form = [(name, ref_for("form", name, value)) for name, value in parsed]
            if not deps.form_body_is_utf8(req.body):
                # DESIGN.md §13.4: the browser encoded the form in a legacy charset (IE on a
                # Shift_JIS page).  ``requests`` would re-encode str values as UTF-8, so the
                # recorded percent-encoded bytes are kept (``raw_body``) together with the original
                # Content-Type.  ``form`` stays filled in as the field list: literal pairs plus
                # bytes literals for the legacy values, so codegen rebuilds the body with fresh
                # dynamic values (``__VIEWSTATE`` ...) while the legacy bytes stay byte-exact.
                dynamic = [name for name, ref in form if not ref.is_literal]
                form = self._legacy_form_hint(req.body, parsed, form)
                raw_body = req.body
                body_kind = "raw"
                self.legacy_form_steps.append(step_no)
                note = ""
                if dynamic:
                    listed = ", ".join(dynamic[:4]) + (" …" if len(dynamic) > 4 else "")
                    note = f"（{listed} は前のステップのレスポンスから取得した値に差し替えます）"
                self.warnings.append(
                    f"step {step_no}: フォーム本文が UTF-8 以外の文字コード（Shift_JIS など）でパーセントエンコードされているため、"
                    f"日本語などの値は記録時のバイト列のまま、Content-Type も記録どおりに送信します{note}"
                )
        elif body_kind == "json":
            json_body = self._substitute_json(parsed, [], ref_for)
        elif body_kind == "multipart":
            multipart = []
            for fld in parsed:
                if fld.is_file:
                    multipart.append(MultipartPart(name=fld.name, filename=fld.filename,
                                                   content_type=fld.content_type, content=fld.content))
                else:
                    multipart.append(MultipartPart(name=fld.name, value=ref_for("multipart", fld.name, fld.text())))
        elif body_kind == "raw":
            raw_body = req.body

        # headers
        headers: list[tuple[str, Ref]] = []
        header_cands: dict[str, list[deps.Candidate]] = {}
        for cand in cands:
            if cand.location == "header":
                header_cands.setdefault(cand.name, []).append(cand)
        for name, value in clean_request_headers(req.headers):
            lname = name.lower()
            if (lname, value) in self.base_set:
                continue
            if lname == "content-type" and body_kind in ("form", "json", "multipart"):
                continue
            if lname == "authorization" and deps.is_session_auth_header(value):
                # NTLM / Negotiate / Basic / Digest: configured once on the session (DESIGN.md §13.2)
                ref_or_none = self._session_auth_header(value, flow, step_no)
                if ref_or_none is not None:
                    headers.append((name, ref_or_none))
                continue
            ref = Ref.lit(value)
            for cand in header_cands.get(lname, []):
                if cand.prefix + cand.value == value.strip():
                    resolved = refs.get((cand.location, cand.name, cand.value))
                    if resolved is not None:
                        ref = _with_prefix(cand.prefix, resolved)
                    break
            headers.append((name, ref))

        status = resp.status if resp else 200
        mime = (resp.mime_type or "") if resp else ""
        comment = f"{req.method} {util.truncate(req.url_without_query, 90)} -> {status}" + (f" {mime}" if mime else "")
        if len(unit.response_chain) > 1:
            comment += f" (redirect chain of {len(unit.response_chain)} hops)"
        if loop is not None:
            comment += f" x{len(unit.groups)} ({loop.note})"

        return Step(
            index=index,
            func_name=self._func_name(index, flow, dynamic_segments),
            method=req.method.upper(),
            url=url,
            params=params,
            headers=headers,
            body_kind=body_kind,
            form=form,
            json_body=json_body,
            multipart=multipart,
            raw_body=raw_body,
            response_kind=_response_kind(last),
            expected_status=status,
            loop=loop,
            source_flow_ids=[f.id for f in unit.all_flows],
            comment=comment,
            allow_redirects=True,
        )

    def _substitute_json(self, doc: Any, path: list, ref_for) -> Any:
        if isinstance(doc, dict):
            return {k: self._substitute_json(v, path + [str(k)], ref_for) for k, v in doc.items()}
        if isinstance(doc, list):
            return [self._substitute_json(v, path + [i], ref_for) for i, v in enumerate(doc)]
        conv = deps._leaf_as_str(doc)
        if conv is None:
            return doc
        ref = ref_for("json", deps.json_dotted(path), conv[0])
        return doc if ref.is_literal else ref

    # ------------------------------------------------------------------ driver

    def build(self) -> Plan:
        opts = self.opts
        kept, dropped = filter_flows(self.recording, opts)
        # §13.2: fold 401 handshakes first; the final attempt represents each handshake from here on
        if opts.detect_auth:
            auth_groups, self.auth = collapse_auth_handshakes(kept)
        else:
            auth_groups = [[f] for f in kept]
        for group in auth_groups:
            if len(group) > 1:
                self.auth_hops[id(group[-1])] = group[:-1]
        attempts = [group[-1] for group in auth_groups]
        groups = collapse_redirects(attempts) if opts.collapse_redirects else [[f] for f in attempts]
        loops = detect_loops(groups, opts) if opts.detect_loops else []
        loop_at: dict[int, LoopGroup] = {id(lg.groups[0]): lg for lg in loops}
        units: list[_Unit] = []
        i = 0
        while i < len(groups):
            lg = loop_at.get(id(groups[i]))
            if lg is not None:
                units.append(_Unit(groups=list(lg.groups), loop=lg, hops=self.auth_hops))
                i += len(lg.groups)
            else:
                units.append(_Unit(groups=[groups[i]], hops=self.auth_hops))
                i += 1

        if opts.max_steps is not None and opts.max_steps >= 0 and len(units) > opts.max_steps:
            cut = units[opts.max_steps:]
            units = units[:opts.max_steps]
            self.warnings.append(
                f"recording has {len(units) + len(cut)} steps; truncated to --max-steps {opts.max_steps} "
                f"({len(cut)} step(s) ignored)"
            )
            for unit in cut:
                for f in unit.all_flows:
                    dropped.append(Dropped(flow_id=f.id, method=f.request.method, url=f.request.url,
                                           reason="beyond --max-steps"))
            kept = [f for unit in units for f in unit.all_flows]

        initial_cookies, _managed = classify_cookies(kept)
        self.base_headers = compute_base_headers(kept)
        self.base_set = {(k.lower(), v) for k, v in self.base_headers}
        self._setup_auth(kept)

        # which values are sent by more than one step (-> Constant when not traced)
        for idx, unit in enumerate(units):
            for cand in deps.find_candidates(unit.first_flow, opts):
                self.value_units.setdefault(cand.value, set()).add(idx)
            for cand in deps.header_candidates(unit.first_flow, skip_session_auth=False):
                if cand.prefix.strip().lower() in SESSION_AUTH_SCHEMES:
                    self.auth_token_units.setdefault(cand.value, set()).add(idx)

        steps: list[Step] = []
        for idx, unit in enumerate(units, start=1):
            step = self._build_step(unit, idx)
            steps.append(step)
            self.built.append(_Built(step=step, unit=unit))
            self.earlier_flows.extend(unit.all_flows)
            if unit.auth_hops and step.expected_status in (401, 403, 407):
                self.warnings.append(
                    f"step {idx}: 認証ハンドシェイクの最後の応答が HTTP {step.expected_status} でした"
                    f"（記録時に認証が失敗しています）。資格情報を確認してください"
                )

        for const in self.constants:
            uses = self.const_uses.get(const.name, [])
            where = ", ".join(uses[:6]) + (" ..." if len(uses) > 6 else "")
            if where:
                text = ("secret; " if const.secret else "") + f"used in {where}"
                const.comment = f"{const.comment}; {text}" if const.comment else text

        final_step_index = self._final_step_index(steps, dropped)

        if initial_cookies:
            names = ", ".join(sorted({c.name for c in initial_cookies})[:8])
            self.warnings.append(
                f"{len(initial_cookies)} cookie(s) existed before the recording started ({names}); they are replayed "
                f"as INITIAL_COOKIES and may have expired"
            )

        meta = {
            "source": dict(self.recording.meta),
            "generated_at": util.now_iso(),
            "flows_total": len(self.recording.flows),
            "flows_kept": len(kept),
            "steps": len(steps),
        }
        if self.auth is not None:
            meta["auth"] = self.auth.kind
        return Plan(
            steps=steps,
            constants=self.constants,
            base_headers=self.base_headers,
            initial_cookies=initial_cookies,
            dropped=dropped,
            warnings=self.warnings,
            meta=meta,
            auth=self.auth,
            final_step_index=final_step_index,
        )


def build_plan(recording: Recording, opts: Optional[PlanOptions] = None) -> Plan:
    """Analyse a ``Recording`` and return the ``Plan`` the code generator turns into a script.

    See DESIGN.md §7 for the algorithm.  Never raises on odd recordings (binary bodies, missing
    responses, broken encodings); problems surface as ``Plan.warnings`` / ``Plan.dropped``.
    """
    deps.clear_cache()
    try:
        return _Builder(recording, opts or PlanOptions()).build()
    finally:
        deps.clear_cache()


__all__ = ["build_plan"]
