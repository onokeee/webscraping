"""Dependency detection: which request values came from earlier responses.  Contract: DESIGN.md §5.

Two halves:

* **candidates** - every value a request sends that *could* have come from somewhere
  (``find_candidates``), plus the shared request-body parsers used by ``loops.py`` / ``plan.py``;
* **locators** - given a value and an earlier flow, build a stable ``Extractor`` that re-extracts
  the value from that flow's response on the next run (``locate_value``), or find the cookie that
  carries it (``locate_in_cookies``).

Locators are never keyed on the dynamic value itself and every regex is verified against the
recorded text before it is returned.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Optional
from urllib.parse import urljoin, urlsplit

from urllib.parse import quote_from_bytes, unquote_to_bytes

from bs4 import BeautifulSoup, NavigableString, Tag

from . import util
from .filters import DROP_REQUEST_HEADERS, SESSION_AUTH_SCHEMES, parse_set_cookie
from .model import Extractor, Flow, PlanOptions, RecordedRequest


# --------------------------------------------------------------------------- candidates

@dataclass
class Candidate:
    """A value sent by a request that may depend on an earlier response.

    ``prefix`` is set for scheme-prefixed headers (``Authorization: Bearer X`` -> value ``X``,
    prefix ``"Bearer "``) so plan.py can rebuild the header.  ``numeric`` marks JSON leaves that
    were numbers (the value is their ``str()``)."""

    location: str  # "path" | "query" | "form" | "json" | "header" | "multipart"
    name: str
    value: str
    json_path: Optional[list] = None
    prefix: str = ""
    numeric: bool = False


@dataclass
class MultipartField:
    """One part of a ``multipart/form-data`` body."""

    name: str
    content: bytes
    filename: Optional[str] = None
    content_type: Optional[str] = None

    @property
    def is_file(self) -> bool:
        return self.filename is not None

    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


_BOUNDARY_RE = re.compile(r'boundary=(?:"([^"]+)"|([^;,\s]+))', re.I)
_DISPOSITION_PARAM_RE = re.compile(r';\s*([\w*-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;]*))')


def parse_multipart(body: Optional[bytes], content_type: Optional[str]) -> list[MultipartField]:
    """Split a multipart body into fields.  Never raises; unparsable input yields ``[]``."""
    if not body:
        return []
    boundary: Optional[bytes] = None
    if content_type:
        m = _BOUNDARY_RE.search(content_type)
        if m:
            boundary = (m.group(1) or m.group(2) or "").encode("latin-1", "replace")
    if not boundary:
        # sniff: the body starts with the delimiter line
        first_line = body.split(b"\n", 1)[0].rstrip(b"\r")
        if first_line.startswith(b"--") and len(first_line) > 2:
            boundary = first_line[2:]
    if not boundary:
        return []
    delimiter = b"--" + boundary
    fields: list[MultipartField] = []
    chunks = body.split(delimiter)
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            break  # closing delimiter
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        elif chunk.startswith(b"\n"):
            chunk = chunk[1:]
        sep = chunk.find(b"\r\n\r\n")
        sep_len = 4
        if sep < 0:
            sep = chunk.find(b"\n\n")
            sep_len = 2
        if sep < 0:
            continue
        raw_headers = chunk[:sep].decode("utf-8", errors="replace")
        content = chunk[sep + sep_len:]
        if content.endswith(b"\r\n"):
            content = content[:-2]
        elif content.endswith(b"\n"):
            content = content[:-1]
        name: Optional[str] = None
        filename: Optional[str] = None
        part_ct: Optional[str] = None
        for line in raw_headers.replace("\r\n", "\n").split("\n"):
            if ":" not in line:
                continue
            hname, hval = line.split(":", 1)
            hname = hname.strip().lower()
            hval = hval.strip()
            if hname == "content-disposition":
                for pm in _DISPOSITION_PARAM_RE.finditer(";" + hval.split(";", 1)[1] if ";" in hval else ""):
                    key = pm.group(1).lower()
                    val = pm.group(2) if pm.group(2) is not None else (pm.group(3) or "").strip()
                    val = val.replace('\\"', '"')
                    if key == "name":
                        name = val
                    elif key == "filename":
                        filename = val
            elif hname == "content-type":
                part_ct = hval
        if name is None:
            continue
        fields.append(MultipartField(name=name, content=content, filename=filename, content_type=part_ct))
    return fields


def json_leaves(doc: Any, path: Optional[list] = None) -> Iterator[tuple[list, Any]]:
    """Yield ``(path, leaf)`` for every scalar leaf of a parsed JSON document (depth first).

    Paths are lists of ``str`` (object keys) and ``int`` (array indexes)."""
    if path is None:
        path = []
    if isinstance(doc, dict):
        for key, val in doc.items():
            yield from json_leaves(val, path + [str(key)])
    elif isinstance(doc, list):
        for idx, val in enumerate(doc):
            yield from json_leaves(val, path + [idx])
    else:
        yield path, doc


def json_dotted(path: list) -> str:
    """``["a", "b", 0, "c"]`` -> ``"a.b[0].c"``."""
    out = ""
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += ("." if out else "") + str(part)
    return out


def _leaf_as_str(leaf: Any) -> Optional[tuple[str, bool]]:
    """``(str_value, numeric)`` for str/int/float leaves, None for bool/None/other."""
    if isinstance(leaf, bool) or leaf is None:
        return None
    if isinstance(leaf, str):
        return leaf, False
    if isinstance(leaf, (int, float)):
        return str(leaf), True
    return None


def parse_json_text(text: Optional[str]) -> Any:
    """``json.loads`` for texts that look like a JSON object/array; ``None`` otherwise/when invalid."""
    if not text:
        return None
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        doc = json.loads(stripped)
    except (ValueError, RecursionError):
        return None
    return doc if isinstance(doc, (dict, list)) else None


# --------------------------------------------------------------------------- urlencoded forms (byte level)

def split_form_segments(body: Optional[bytes]) -> list[bytes]:
    """Non-empty ``name=value`` segments of an ``application/x-www-form-urlencoded`` body, in
    order.  ``parse_form_bytes`` returns exactly one pair per segment, so the two line up."""
    if not body:
        return []
    return [seg for seg in bytes(body).split(b"&") if seg]


def _form_segment_bytes(segment: bytes) -> tuple[bytes, bytes]:
    """Decoded (``+`` -> space, ``%XX`` -> byte) name and value bytes of one segment."""
    name, _sep, value = segment.partition(b"=")
    return unquote_to_bytes(name.replace(b"+", b" ")), unquote_to_bytes(value.replace(b"+", b" "))


def form_pairs_bytes(body: Optional[bytes]) -> list[tuple[bytes, bytes]]:
    """Percent-decoded ``(name, value)`` byte pairs, one per segment (same order as
    ``split_form_segments`` / ``parse_form_bytes``)."""
    return [_form_segment_bytes(segment) for segment in split_form_segments(body)]


def form_body_is_utf8(body: Optional[bytes]) -> bool:
    """True when every name and value of the form body is valid UTF-8 after percent-decoding.

    False means the browser encoded the form in a legacy charset (IE on a Shift_JIS page sends
    ``%93%FA%96%7B`` for 日本): ``requests`` would re-encode such values as UTF-8, so the plan has
    to keep the recorded bytes (DESIGN.md §13.4)."""
    for segment in split_form_segments(body):
        for raw in _form_segment_bytes(segment):
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                return False
    return True


def _form_text(raw: bytes, charset: Optional[str]) -> str:
    """Decode one form name / value: declared charset first, then UTF-8; a value that is neither
    keeps a percent-encoded spelling so nothing is lost or garbled."""
    if charset and charset != "utf-8":
        try:
            return raw.decode(charset)
        except (UnicodeDecodeError, LookupError):
            pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return quote_from_bytes(raw, safe="")


def parse_form_bytes(body: Optional[bytes], charset: Optional[str] = None) -> list[tuple[str, str]]:
    """``application/x-www-form-urlencoded`` bytes -> ordered ``(name, value)`` pairs.

    Equivalent to ``util.parse_form`` for UTF-8 bodies (blank values kept, repeated names kept,
    one pair per non-empty segment) but works on bytes: values in a legacy charset are decoded
    with ``charset`` when it is declared on the request, otherwise they stay percent-encoded."""
    pairs: list[tuple[str, str]] = []
    for segment in split_form_segments(body):
        name_b, value_b = _form_segment_bytes(segment)
        pairs.append((_form_text(name_b, charset), _form_text(value_b, charset)))
    return pairs


def request_form_charset(request: RecordedRequest) -> Optional[str]:
    """Normalised charset parameter of the request ``Content-Type`` (None when absent)."""
    ct = request.header("content-type")
    if not ct or not util.parse_content_type(ct)[1].get("charset"):
        return None
    return util.detect_charset(b"", ct)


def classify_body(request: RecordedRequest) -> tuple[str, Any]:
    """``(body_kind, parsed)`` for a request body.

    kinds: ``none``, ``form`` (ordered pairs), ``json`` (dict/list), ``multipart``
    (``MultipartField`` list), ``raw`` (``None``).

    A form in a legacy charset still classifies as ``form`` (its pairs are what dependency
    detection needs); ``plan.py`` checks ``form_body_is_utf8`` to decide whether the recorded
    bytes must be replayed verbatim."""
    body = request.body
    if body is None or len(body) == 0:
        return "none", None
    ct = request.content_type or ""
    if ct == "application/x-www-form-urlencoded":
        return "form", parse_form_bytes(body, request_form_charset(request))
    if ct.startswith("multipart/"):
        fields = parse_multipart(body, request.header("content-type"))
        if fields:
            return "multipart", fields
        return "raw", None
    textual = not ct or util.is_textual_mime(ct) or ct == "application/octet-stream"
    if util.is_json_mime(ct) or textual:
        if util.is_json_mime(ct) or b"\x00" not in body[:4096]:
            doc = parse_json_text(request.text())
            if doc is not None:
                return "json", doc
    return "raw", None


def request_params(flow: Flow) -> list[Candidate]:
    """Every parameter of a request as (unfiltered) ``Candidate`` objects, in a stable order:
    path segments, query pairs, then body values (form / JSON leaves / multipart text fields).
    Header values are *not* included (see ``header_candidates``)."""
    req = flow.request
    out: list[Candidate] = []
    path = urlsplit(req.url).path
    segments = path.split("/")[1:] if path.startswith("/") else path.split("/")
    for idx, seg in enumerate(segments):
        if seg:
            out.append(Candidate("path", str(idx), seg))
    for name, value in util.parse_query(req.query):
        out.append(Candidate("query", name, value))
    kind, parsed = classify_body(req)
    if kind == "form":
        for name, value in parsed:
            out.append(Candidate("form", name, value))
    elif kind == "json":
        for jpath, leaf in json_leaves(parsed):
            conv = _leaf_as_str(leaf)
            if conv is None:
                continue
            value, numeric = conv
            out.append(Candidate("json", json_dotted(jpath), value, json_path=list(jpath), numeric=numeric))
    elif kind == "multipart":
        for fld in parsed:
            if not fld.is_file:
                out.append(Candidate("multipart", fld.name, fld.text()))
    return out


_SKIP_HEADER_EXACT = frozenset(DROP_REQUEST_HEADERS) | frozenset({
    "user-agent", "referer", "origin", "cache-control", "pragma", "dnt", "priority", "content-type",
    "cookie", "x-requested-with", "upgrade-insecure-requests", "range", "if-match", "if-unmodified-since",
    "via", "forwarded", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "date", "from",
    "max-forwards", "purpose", "service-worker", "save-data", "device-memory", "downlink", "ect", "rtt",
    "viewport-width", "width", "early-data", "alt-used", "content-md5",
})
_SKIP_HEADER_PREFIXES = ("accept", "sec-", "proxy-", ":")
_AUTH_SCHEME_RE = re.compile(r"^(\s*(?:Bearer|Basic|Digest|Token|JWT|Api-?Key|OAuth|Negotiate|NTLM)\s+)(\S.*?)\s*$", re.I)


def split_auth_header(value: Optional[str]) -> tuple[str, str]:
    """``"Bearer X"`` -> ``("Bearer ", "X")``; ``("", value)`` when no known scheme prefix."""
    value = (value or "").strip()
    m = _AUTH_SCHEME_RE.match(value)
    if m:
        return m.group(1), m.group(2)
    return "", value


def is_session_auth_header(value: Optional[str]) -> bool:
    """True for ``Authorization`` values of a scheme that ``session.auth`` handles (NTLM /
    Negotiate / Basic / Digest) - never traceable to an earlier response."""
    prefix, _token = split_auth_header(value)
    return prefix.strip().lower() in SESSION_AUTH_SCHEMES


def header_candidates(flow: Flow, skip_session_auth: bool = True) -> list[Candidate]:
    """Header values that may depend on earlier responses (unfiltered).  Names are lower-cased;
    ``Authorization: <scheme> X`` yields value ``X`` with ``prefix="<scheme> "``.

    With ``skip_session_auth`` (the default, DESIGN.md §13.2) NTLM / Negotiate / Basic / Digest
    ``Authorization`` values are left out: they are credentials or handshake tokens configured
    through ``session.auth``, not values produced by an earlier response.  Bearer / JWT / Token
    style headers are unaffected."""
    out: list[Candidate] = []
    for name, value in flow.request.headers:
        lname = (name or "").strip().lower()
        if not lname or lname in _SKIP_HEADER_EXACT or lname.startswith(_SKIP_HEADER_PREFIXES):
            continue
        value = (value or "").strip()
        if not value:
            continue
        prefix = ""
        if lname == "authorization":
            prefix, value = split_auth_header(value)
            if skip_session_auth and prefix.strip().lower() in SESSION_AUTH_SCHEMES:
                continue
            if not value:
                continue
        out.append(Candidate("header", lname, value, prefix=prefix))
    return out


_PLAIN_WORD_RE = re.compile(r"^[A-Za-z][A-Za-z_-]*$")


def is_candidate_value(value: str, opts: PlanOptions) -> bool:
    """The §5 value filter: long enough, and not a short purely-alphabetic word (``true``, ``json`` ...)."""
    if value is None or len(value) < opts.min_value_length:
        return False
    if len(value) <= 6 and _PLAIN_WORD_RE.match(value):
        return False
    return True


def is_numeric_path_id(cand: Candidate) -> bool:
    """A digits-only path segment (``/orgs/77/items``) is an identifier by position."""
    return cand.location == "path" and cand.value.isdigit()


#: Extensions of server-side pages: a segment such as ``SC0010.aspx`` / ``KJ010Search.aspx`` is a
#: screen id, i.e. a page name, even though it contains digits.
_PAGE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*\.(?:aspx|asp|ashx|asmx|axd|svc|html?|php|jsp|jspx|do|action|cgi|pl)$", re.I)
#: A word or a letters-only (file) name (``orders``, ``export-csv``, ``Login.aspx``, ``jquery.min.js``).
_LETTERS_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z_.~-]*$")
_NAME_DOTS_RE = re.compile(r"[.~]+")
_DIGIT_RUN_RE = re.compile(r"\d+")
_NON_LETTERS_RE = re.compile(r"[^A-Za-z]+")


def is_route_like(value: str) -> bool:
    """A route / page name rather than a per-session value: a word (``dashboard``,
    ``ProductionResultCSV``), a letters-only file name (``Default.aspx``) or a screen-id page
    (``SC0010.aspx``, ``KJ010Search.aspx``, ``Menu01.aspx``) - unless the name (or the stem before
    the extension) looks random (``xBBHOHpXYZgFKyNZpuWy``, ``xBBHOH-pXYZgFKyNZpuWy.aspx``).

    Such values occur in many places of the previous page (``action="Login.aspx"``, link texts,
    menu markup) by coincidence, so plan.py only traces them through exact structural matches
    (JSON leaf, header, cookie, ``<input>`` / ``<meta>``), never through markup or a pattern."""
    if not isinstance(value, str) or not value:
        return False
    if _LETTERS_NAME_RE.match(value):
        return not (looks_random_letters(value) or any(looks_random_letters(p) for p in _NAME_DOTS_RE.split(value) if p))
    if _PAGE_NAME_RE.match(value):
        return not _looks_random_stem(value.rsplit(".", 1)[0])
    return False


def is_structural_path_segment(cand: Candidate) -> bool:
    """A route-like path segment (``Login.aspx``, ``orders``, ``SC0010.aspx``; see ``is_route_like``).

    It stays a trace candidate - an all-uppercase key such as ``/s/QZVBNMWRTYPXSDFKHJ/items`` can
    be a JSON leaf of an earlier response - but plan.py never traces it through markup
    (``html_attr`` / ``html_text`` / ``regex`` / ``url``): tracing ``Login.aspx`` to
    ``action="Login.aspx"`` would only make the script depend on that markup for a constant."""
    return cand.location == "path" and is_route_like(cand.value)


def find_candidates(flow: Flow, opts: PlanOptions) -> list[Candidate]:
    """All request values worth tracing to earlier responses (see DESIGN.md §5).

    Digits-only path segments are kept even when shorter than ``opts.min_value_length``: an id in
    the URL path almost always comes from an earlier JSON / HTML response (``org.id`` -> ``/orgs/77``).
    plan.py accepts only exact structural matches (JSON leaf, attribute, header ...) for such short
    values, never a regex, so a two-digit number cannot be traced by coincidence.  Route-like path
    segments (``is_structural_path_segment``) are candidates as well; plan.py restricts the
    locators it accepts for them."""
    return [
        c for c in request_params(flow) + header_candidates(flow)
        if is_candidate_value(c.value, opts) or is_numeric_path_id(c)
    ]


# --------------------------------------------------------------------------- dynamic-value heuristic

_URL_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:)?//")
_PATH_RE = re.compile(r"^/[A-Za-z0-9_./~-]*$")
_DATE_RE = re.compile(r"^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}([ T].*)?$")
_MIME_RE = re.compile(r"^[a-z]+/[a-z0-9.+-]+$")
_VERSION_RE = re.compile(r"^v?\d+(\.\d+)+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_PLAIN_WORDS_RE = re.compile(r"^[A-Za-z][A-Za-z_.:/,-]*$")
_WORD_WITH_SMALL_NUMBER_RE = re.compile(r"^[A-Za-z][A-Za-z_.-]*\d{1,3}$")
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")  # base64 of '{"' + two more segments


_PCT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def is_dynamic_looking(value: str) -> bool:
    """Heuristic: does ``value`` look like a random token (session id, CSRF token, signature ...)?

    True for long strings mixing letters and digits, hex / base64 / UUID / JWT shaped strings;
    False for words, URLs, paths, dates, MIME types, versions, e-mails and pure numbers.  Used
    only to decide whether to *warn* about an untraced literal, so it errs on the side of False.

    Percent-encoded values are judged on their decoded text; one that does not decode as UTF-8
    (``%93%FA%96%7B`` - cp932 text typed into a form on a Shift_JIS page) is plain text, not a token.
    """
    if not isinstance(value, str):
        return False
    value = value.strip()
    if _PCT_ESCAPE_RE.search(value):
        try:
            value = unquote_to_bytes(value).decode("utf-8").strip()
        except UnicodeDecodeError:
            return False
    return _is_dynamic_text(value)


#: Upper- / lowercase runs of a letters-only identifier part.
_CASE_RUN_RE = re.compile(r"[A-Z]+|[a-z]+")
#: Two-letter words (a capital + one lowercase letter) common in identifiers: English (``ById``,
#: ``DownloadAsPDF``), Japanese-system abbreviations (``TokuisakiCd``, ``ShohinNm``, ``UpdDt``,
#: ``DelFg``) and date / time parts (``txtFromYy``, ``ddlFromMm``, ``StartHh``).
#: A capital followed by one lowercase *vowel* is accepted too (romaji syllables: ``SeisanSu``).
_TWO_LETTER_WORDS = frozenset({
    "by", "id", "as", "is", "of", "to", "on", "in", "at", "up", "no", "or", "an", "if", "do", "go", "ok", "my",
    "me", "we", "be", "ex", "cd", "nm", "dt", "kb", "ym", "pc", "db", "ui", "io", "js", "ip", "op", "qr",
    "yy", "mm", "dd", "hh", "ss", "ms", "tm", "ts", "fg", "wk", "st",
})
_SEPARATOR_RE = re.compile(r"[-_]+")
_EXTENSION_RE = re.compile(r"^([^.]+)\.[A-Za-z0-9]{1,5}$")


def _case_irregularities(part: str) -> int:
    """How many places of a letters-only ``part`` do not fit the structure of an identifier.

    The part is read as ``lower* (UPPER+ lower*)*``: an uppercase run followed by lowercase letters
    is an acronym (of any length, or none) plus a capitalised word that starts with the run's last
    capital (``XMLHttp`` = ``XML`` + ``Http``); a trailing uppercase run is an acronym (``CSV``).
    Irregular are a lone capital between words (``...kAValue``), a single capital closing the part
    after a word (``...ColumnX``) and a two-letter word that is neither a known one nor a capital +
    vowel (``Fk``, ``Zg``).  Random mixed-case letters have such places almost everywhere; names
    such as ``getElementById``, ``txtTokuisakiCD`` or ``getXMLHttpRequest`` have none."""
    runs = _CASE_RUN_RE.findall(part)
    count = 0
    i = 1 if runs and runs[0].islower() else 0
    while i < len(runs):
        upper = runs[i]
        lower = runs[i + 1] if i + 1 < len(runs) else ""
        if lower:
            if len(upper) == 2:
                count += 1
            if len(lower) == 1 and lower not in "aeiou" and (upper[-1] + lower).lower() not in _TWO_LETTER_WORDS:
                count += 1
        elif len(upper) == 1 and i > 0:
            count += 1
        i += 2
    return count


def _strip_extension(value: str) -> str:
    """``xBBHOHpXYZgFKyNZpuWy.pdf`` -> ``xBBHOHpXYZgFKyNZpuWy`` (one short extension at most)."""
    m = _EXTENSION_RE.match(value)
    return m.group(1) if m else value


def looks_random_letters(value: str) -> bool:
    """A long letters-only value with irregular mixed case (``xBBHOHpXYZgFKyNZpuWy``) is a random
    token, not a word: sites generate such keys (a URL key, a nonce) and about one in ten random
    20-character alphanumeric tokens happens to contain no digit at all.

    ``-`` / ``_`` separate parts that are judged one by one (base64url without digits:
    ``xBBHOH-pXYZgFKyNZpuWy``) and a file name is judged by its stem (``xBBHOHpXYZgFKyNZpuWy.pdf``).
    Identifiers with acronyms anywhere (``txtTokuisakiCD``, ``CustomerIDList``, ``DownloadAsPDF``,
    ``getXMLHttpRequest``) are words.  Measured on random mixed-case letter strings: about 96 % of
    16-24 characters (also with ``-`` / ``_``) and about 89 % of 12-15 characters are recognised as
    tokens (tests/test_review3_analysis.py)."""
    if not isinstance(value, str) or not value.isascii():
        return False
    stem = _strip_extension(value)
    if len(stem) < 12:
        return False
    parts = [p for p in _SEPARATOR_RE.split(stem) if p]
    if not parts or not all(p.isalpha() for p in parts):
        return False
    letters = "".join(parts)
    if letters.islower() or letters.isupper():
        return False
    return any(_case_irregularities(p) for p in parts)


def _looks_random_stem(stem: str) -> bool:
    """The stem of a page name (before ``.aspx`` ...) is random: random letters, or digits in more
    than two runs or next to random-case letters (``a8F3kQ9zP2``).  Screen ids such as ``SC0010``,
    ``KJ010Search`` or ``Menu01`` are not random."""
    if looks_random_letters(stem):
        return True
    if not any(ch.isdigit() for ch in stem):
        return False
    if len(_DIGIT_RUN_RE.findall(stem)) > 2:
        return True
    return len(stem) >= 12 and any(_case_irregularities(p) for p in _NON_LETTERS_RE.split(stem) if p)


def _is_dynamic_text(value: str) -> bool:
    if len(value) < 12 or any(ch.isspace() for ch in value):
        return False
    if _UUID_RE.match(value) or _JWT_RE.match(value):
        return True
    if looks_random_letters(value):
        return True
    if _URL_RE.match(value) or _PATH_RE.match(value) or _DATE_RE.match(value) or _MIME_RE.match(value) \
            or _VERSION_RE.match(value) or _EMAIL_RE.match(value) or _DOMAIN_RE.match(value):
        return False
    if _PLAIN_WORDS_RE.match(value) or _WORD_WITH_SMALL_NUMBER_RE.match(value):
        return False
    if value.isdigit():
        return False
    has_alpha = any(ch.isalpha() for ch in value)
    has_digit = any(ch.isdigit() for ch in value)
    if has_alpha and has_digit:
        return True
    if _HEX_RE.match(value):
        return True
    if has_alpha and _BASE64_RE.match(value) and len(value) >= 16:
        has_upper = any(ch.isupper() for ch in value)
        has_lower = any(ch.islower() for ch in value)
        return has_upper and has_lower and (value.endswith("=") or any(ch in "+/" for ch in value))
    return False


# --------------------------------------------------------------------------- response views (cached parsing)

_MAX_SOUP_BYTES = 3 * 1024 * 1024
_MAX_TEXT_BYTES = 16 * 1024 * 1024
_SKIP_TEXT_PARENTS = frozenset({"script", "style", "template", "[document]", "head", "html"})


class _SoupIndex:
    """Lookup tables over a parsed HTML document (built once per response)."""

    def __init__(self, soup: BeautifulSoup) -> None:
        self.input_by_value: dict[str, str] = {}  # value -> name of the *first* input with that name
        self.meta_by_content: dict[str, str] = {}
        self.attr_index: dict[str, list[tuple[Tag, str]]] = {}
        self.attr_items: list[tuple[Tag, str, str]] = []
        self.text_index: dict[str, list[Tag]] = {}
        self.text_nodes: list[tuple[str, Tag]] = []
        first_input: dict[str, Tag] = {}
        first_meta: dict[str, Tag] = {}
        for el in soup.find_all(True):
            if not isinstance(el, Tag):
                continue
            if el.name == "input":
                nm = el.get("name")
                if isinstance(nm, str) and nm and nm not in first_input:
                    first_input[nm] = el
            elif el.name == "meta":
                nm = el.get("name")
                if isinstance(nm, str) and nm and nm not in first_meta:
                    first_meta[nm] = el
            for attr, val in el.attrs.items():
                if isinstance(val, str) and val:
                    self.attr_index.setdefault(val, []).append((el, attr))
                    self.attr_items.append((el, attr, val))
        for nm, el in first_input.items():
            val = el.get("value")
            if isinstance(val, str) and val and val not in self.input_by_value:
                self.input_by_value[val] = nm
        for nm, el in first_meta.items():
            val = el.get("content")
            if isinstance(val, str) and val and val not in self.meta_by_content:
                self.meta_by_content[val] = nm
        for node in soup.find_all(string=True):
            if type(node) is not NavigableString:
                continue  # comments, CDATA, script/style contents ...
            parent = node.parent
            if parent is None or not isinstance(parent, Tag) or parent.name in _SKIP_TEXT_PARENTS:
                continue
            stripped = node.strip()
            if not stripped:
                continue
            self.text_nodes.append((stripped, parent))
            self.text_index.setdefault(stripped, []).append(parent)


class _ResponseView:
    """Lazily decoded / parsed view of one response, cached across ``locate_value`` calls."""

    def __init__(self, flow: Flow) -> None:
        self.flow = flow
        resp = flow.response
        self.status = resp.status if resp else 0
        self.mime = (resp.mime_type or "").lower() if resp else ""
        self.body: bytes = (resp.body if resp and resp.body else b"")
        self._text: Optional[str] = None
        self._json: Any = Ellipsis
        self._soup: Any = Ellipsis
        self._index: Optional[_SoupIndex] = None
        self._leaf_index: Optional[dict[str, list]] = None

    @property
    def textual(self) -> bool:
        if not self.body or len(self.body) > _MAX_TEXT_BYTES:
            return False
        if util.is_textual_mime(self.mime):
            return True
        if not self.mime or self.mime == "application/octet-stream":
            return b"\x00" not in self.body[:4096]
        return False

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = self.flow.response.text() or "" if self.flow.response else ""
        return self._text

    @property
    def json_doc(self) -> Any:
        if self._json is Ellipsis:
            self._json = None
            if self.textual and (util.is_json_mime(self.mime) or self.text.lstrip()[:1] in ("{", "[")):
                self._json = parse_json_text(self.text)
        return self._json

    @property
    def leaf_index(self) -> dict[str, list]:
        if self._leaf_index is None:
            index: dict[str, list] = {}
            if self.json_doc is not None:
                for path, leaf in json_leaves(self.json_doc):
                    conv = _leaf_as_str(leaf)
                    if conv is not None and conv[0] not in index:
                        index[conv[0]] = path
            self._leaf_index = index
        return self._leaf_index

    @property
    def is_htmlish(self) -> bool:
        if not self.textual or self.json_doc is not None:
            return False
        if util.is_html_mime(self.mime) or util.is_xml_mime(self.mime):
            return True
        return self.text.lstrip()[:1] == "<"

    @property
    def soup(self) -> Optional[BeautifulSoup]:
        if self._soup is Ellipsis:
            self._soup = None
            if self.is_htmlish and len(self.body) <= _MAX_SOUP_BYTES:
                try:
                    self._soup = BeautifulSoup(self.text, "html.parser")
                except Exception:  # pragma: no cover - defensive
                    self._soup = None
        return self._soup

    @property
    def index(self) -> Optional[_SoupIndex]:
        if self._index is None and self.soup is not None:
            self._index = _SoupIndex(self.soup)
        return self._index


_VIEW_CACHE: "OrderedDict[int, tuple[Flow, _ResponseView]]" = OrderedDict()
_VIEW_CACHE_SIZE = 48


def _view(flow: Flow) -> _ResponseView:
    key = id(flow)
    hit = _VIEW_CACHE.get(key)
    if hit is not None and hit[0] is flow:
        _VIEW_CACHE.move_to_end(key)
        return hit[1]
    view = _ResponseView(flow)
    _VIEW_CACHE[key] = (flow, view)
    while len(_VIEW_CACHE) > _VIEW_CACHE_SIZE:
        _VIEW_CACHE.popitem(last=False)
    return view


def clear_cache() -> None:
    """Drop cached parsed responses (tests / long-running processes)."""
    _VIEW_CACHE.clear()


# --------------------------------------------------------------------------- pattern building

_REGEX_UNSAFE_RE = re.compile(r"""["'<>\s]""")
_MIN_REGEX_VALUE_LEN = 6
_WORD_CHAR_RE = re.compile(r"\w")
_LEADING_WORD_RE = re.compile(r"^\w+")


def _capture_group(value: str, greedy: bool) -> str:
    cls = '[^"\'&<>\\s]' if "&" not in value else '[^"\'<>\\s]'
    return f"({cls}+)" if greedy else f"({cls}+?)"


def _stable_prefix(prefix: str, haystack: str, win_start: int, cut_at_newline: bool) -> str:
    """Drop the least stable leading context: indentation, and the tail of a word the context
    window happened to cut through (``ipt>window.`` from ``<script>window.``).  The original
    prefix is kept when nothing would remain."""
    trimmed = prefix
    if not cut_at_newline and win_start > 0 and _WORD_CHAR_RE.match(haystack[win_start - 1]):
        trimmed = _LEADING_WORD_RE.sub("", trimmed, count=1)
    trimmed = trimmed.lstrip()
    return trimmed or prefix


def build_pattern(haystack: str, value: str, context: int = 24) -> Optional[str]:
    """A verified regex with exactly one capture group that extracts ``value`` from ``haystack``.

    Up to ``context`` characters of literal (escaped) context are used on each side, trimmed at
    line boundaries; the capture group matches token-like text.  Returns None when the value
    contains quotes / whitespace / angle brackets or no verifiable pattern can be built."""
    if not value or not haystack or _REGEX_UNSAFE_RE.search(value):
        return None
    # A short suffix first: the capture group is delimited by its character class, so a few
    # characters suffice and trailing context (often other dynamic values) is less likely to
    # break the pattern on the next run.  Longer context is tried only when needed.
    for before, after in ((context, 4), (context, context), (context * 2, context * 2), (context * 4, context * 4)):
        start = 0
        tries = 0
        while tries < 12:
            idx = haystack.find(value, start)
            if idx < 0:
                break
            tries += 1
            start = idx + 1
            end = idx + len(value)
            win_start = max(0, idx - before)
            prefix = haystack[win_start:idx]
            cut = max(prefix.rfind("\n"), prefix.rfind("\r"))
            if cut >= 0:
                prefix = prefix[cut + 1:]
            prefix = _stable_prefix(prefix, haystack, win_start, cut_at_newline=cut >= 0)
            suffix = haystack[end:end + after]
            cut = min([p for p in (suffix.find("\n"), suffix.find("\r")) if p >= 0], default=-1)
            if cut >= 0:
                suffix = suffix[:cut]
            group = _capture_group(value, greedy=not suffix)
            pattern = ("" if prefix else "^") + re.escape(prefix) + group + (re.escape(suffix) if suffix else "$")
            if not prefix or not suffix:
                pattern = "(?m)" + pattern
            try:
                m = re.search(pattern, haystack)
            except re.error:  # pragma: no cover - re.escape makes this unreachable
                continue
            if m and m.group(1) == value:
                return pattern
    return None


# --------------------------------------------------------------------------- CSS selectors

_CSS_IDENT_RE = re.compile(r"^-?[_a-zA-Z][_a-zA-Z0-9-]*$")
_TAG_RE = re.compile(r"^[a-zA-Z][\w-]*$")
_DATA_ATTR_RE = re.compile(r"^data-[\w-]+$")


def _css_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _unique(soup: BeautifulSoup, selector: str, el: Tag) -> bool:
    try:
        found = soup.select(selector)
    except Exception:
        return False
    return len(found) == 1 and found[0] is el


def _attr_ok(val: Any, forbidden: list[str]) -> bool:
    if not isinstance(val, str) or not val or "\n" in val or "\r" in val:
        return False
    if any(f in val for f in forbidden):
        return False
    return not is_dynamic_looking(val)


def _id_selector(el_id: str) -> str:
    return f"#{el_id}" if _CSS_IDENT_RE.match(el_id) else f"[id={_css_quote(el_id)}]"


def _selector_for(el: Tag, soup: BeautifulSoup, forbidden: list[str], exclude_attr: Optional[str] = None) -> Optional[str]:
    """A stable, unique CSS selector for ``el`` that never contains any of ``forbidden`` strings
    (the dynamic value's spellings).  Preference: ``#id``, ``tag[name=..]``, ``tag[data-x=..]``,
    ``tag[property/itemprop=..]``, ``tag.class1.class2``, bare ``tag``, then ``#ancestor tag``."""
    tag = el.name or ""
    if not _TAG_RE.match(tag):
        return None
    attrs = el.attrs
    candidates: list[str] = []
    el_id = attrs.get("id")
    if exclude_attr != "id" and _attr_ok(el_id, forbidden):
        candidates.append(_id_selector(el_id))
    for key in ("name",):
        val = attrs.get(key)
        if exclude_attr != key and _attr_ok(val, forbidden):
            candidates.append(f"{tag}[{key}={_css_quote(val)}]")
    for key, val in attrs.items():
        if key != exclude_attr and _DATA_ATTR_RE.match(key) and _attr_ok(val, forbidden):
            candidates.append(f"{tag}[{key}={_css_quote(val)}]")
    for key in ("property", "itemprop"):
        val = attrs.get(key)
        if exclude_attr != key and _attr_ok(val, forbidden):
            candidates.append(f"{tag}[{key}={_css_quote(val)}]")
    classes = attrs.get("class") or []
    if isinstance(classes, str):
        classes = classes.split()
    good_classes = [c for c in classes if _CSS_IDENT_RE.match(c) and _attr_ok(c, forbidden)]
    class_sel = tag + "".join("." + c for c in good_classes) if good_classes else None
    if class_sel:
        candidates.append(class_sel)
    candidates.append(tag)
    for sel in candidates:
        if _unique(soup, sel, el):
            return sel
    # descendant of an identifiable ancestor
    for anc in el.parents:
        if not isinstance(anc, Tag) or anc.name == "[document]":
            continue
        anc_id = anc.attrs.get("id")
        if not _attr_ok(anc_id, forbidden):
            continue
        base = _id_selector(anc_id)
        for tail in ([class_sel] if class_sel else []) + [tag]:
            sel = f"{base} {tail}"
            if _unique(soup, sel, el):
                return sel
        break
    return None


# --------------------------------------------------------------------------- locators

_HEADER_DENY = frozenset({
    "set-cookie", "date", "content-length", "content-type", "server", "connection", "transfer-encoding",
    "vary", "cache-control", "pragma", "expires", "last-modified", "age", "content-encoding", "keep-alive",
    "strict-transport-security", "x-powered-by", "via", "accept-ranges", "content-language",
    "x-content-type-options", "x-frame-options", "x-xss-protection", "referrer-policy",
    "content-security-policy", "alt-svc", "x-cache", "cf-ray", "cf-cache-status", "x-served-by",
})
_ALL_KINDS = frozenset({"header", "json", "html_input", "html_meta", "html_attr", "html_text", "regex", "url"})
_BODY_KINDS = frozenset({"json", "html_input", "html_meta", "html_attr", "html_text", "regex"})


def _ordered_variants(value: str) -> list[str]:
    others = sorted(v for v in util.value_variants(value) if v != value)
    return [value] + others


def _locate_header(flow: Flow, variants: list[str]) -> Optional[Extractor]:
    resp = flow.response
    for name, val in resp.headers:
        lname = name.lower()
        if lname in _HEADER_DENY:
            continue
        if lname == "location" and 300 <= resp.status < 400:
            continue  # followed by requests -> only reachable through resp.url (kind "url")
        if val in variants or val.strip() in variants:
            return Extractor(var="", kind="header", name=name, sample=val.strip())
    return None


def _locate_json(view: _ResponseView, variants: list[str]) -> Optional[Extractor]:
    index = view.leaf_index
    for v in variants:
        path = index.get(v)
        if path is not None:
            return Extractor(var="", kind="json", name=json_dotted(path), path=list(path), sample=v)
    return None


def _locate_html(view: _ResponseView, variants: list[str], allow: Callable[[str], bool]) -> Optional[Extractor]:
    soup, idx = view.soup, view.index
    if soup is None or idx is None:
        return None
    if allow("html_input"):
        for v in variants:
            name = idx.input_by_value.get(v)
            if name and v not in name:
                return Extractor(var="", kind="html_input", name=name, sample=v)
    if allow("html_meta"):
        for v in variants:
            name = idx.meta_by_content.get(v)
            if name and v not in name:
                return Extractor(var="", kind="html_meta", name=name, sample=v)
    if allow("html_attr"):
        for v in variants:
            for el, attr in idx.attr_index.get(v, []):
                sel = _selector_for(el, soup, variants, exclude_attr=attr)
                if sel:
                    return Extractor(var="", kind="html_attr", selector=sel, attr=attr, sample=v)
    if allow("html_text"):
        for v in variants:
            for el in idx.text_index.get(v, []):
                if el.get_text(strip=True) != v:
                    continue
                sel = _selector_for(el, soup, variants)
                if sel:
                    return Extractor(var="", kind="html_text", selector=sel, sample=v)
    if allow("html_attr"):
        for v in variants:
            if _REGEX_UNSAFE_RE.search(v):
                continue
            for el, attr, val in idx.attr_items:
                if v not in val or val == v:
                    continue
                sel = _selector_for(el, soup, variants, exclude_attr=attr)
                if not sel:
                    continue
                pattern = build_pattern(val, v)
                if pattern:
                    return Extractor(var="", kind="html_attr", selector=sel, attr=attr, pattern=pattern, sample=v)
    if allow("html_text"):
        for v in variants:
            if _REGEX_UNSAFE_RE.search(v):
                continue
            for stripped, el in idx.text_nodes:
                if v not in stripped or stripped == v:
                    continue
                full = el.get_text(strip=True)
                sel = _selector_for(el, soup, variants)
                if not sel:
                    continue
                pattern = build_pattern(full, v)
                if pattern:
                    return Extractor(var="", kind="html_text", selector=sel, pattern=pattern, sample=v)
    return None


def _locate_regex(text: str, variants: list[str]) -> Optional[Extractor]:
    for v in variants:
        if len(v) < _MIN_REGEX_VALUE_LEN or v not in text:
            continue
        pattern = build_pattern(text, v)
        if pattern:
            return Extractor(var="", kind="regex", pattern=pattern, sample=v)
    return None


def _locate_url(flow: Flow, variants: list[str]) -> Optional[Extractor]:
    resp = flow.response
    location = (resp.location or "").strip()
    if not location:
        return None
    try:
        resolved = urljoin(flow.request.url, location)
    except ValueError:
        return None
    for v in variants:
        if v in resolved:
            pattern = build_pattern(resolved, v)
            if pattern:
                return Extractor(var="", kind="url", name="Location", pattern=pattern, sample=v)
    return None


def locate_value_kinds(value: str, source: Flow, kinds: Optional[frozenset] = None) -> Optional[Extractor]:
    """``locate_value`` restricted to the given extractor kinds (plan.py uses this for the
    intermediate hops of a collapsed redirect chain)."""
    resp = source.response
    if resp is None or not value:
        return None
    allowed = _ALL_KINDS if kinds is None else frozenset(kinds)

    def allow(kind: str) -> bool:
        return kind in allowed

    variants = _ordered_variants(value)
    if allow("header"):
        ext = _locate_header(source, variants)
        if ext:
            return ext
    if allowed & _BODY_KINDS:
        view = _view(source)
        if view.textual:
            if allow("json") and view.json_doc is not None:
                ext = _locate_json(view, variants)
                if ext:
                    return ext
            text = view.text
            present = [v for v in variants if v in text]
            non_ascii = any(ord(ch) > 127 for ch in value)
            if present or (non_ascii and "&" in text):
                if view.soup is not None:
                    # the parser unescapes entities, so every spelling must be tried here
                    ext = _locate_html(view, variants, allow)
                    if ext:
                        return ext
                if allow("regex") and present:
                    ext = _locate_regex(text, present)
                    if ext:
                        return ext
    if allow("url"):
        ext = _locate_url(source, variants)
        if ext:
            return ext
    return None


def locate_value(value: str, source: Flow) -> Optional[Extractor]:
    """Find how ``value`` can be re-extracted from ``source``'s response (DESIGN.md §5 priority).

    The returned ``Extractor`` has ``var == ""`` (the caller names it) and ``sample`` set to the
    spelling that was actually found (it may be a URL-encoded / JSON-escaped variant of ``value``).
    Returns None when the value does not occur or no stable locator exists.
    """
    return locate_value_kinds(value, source, None)


def find_cookie(value: str, earlier: list[Flow]) -> Optional[tuple[str, str]]:
    """``(cookie_name, recorded_cookie_value)`` of the latest earlier ``Set-Cookie`` whose value
    equals ``value`` or one of its spellings, else None."""
    if not value:
        return None
    variants = set(util.value_variants(value))
    for flow in reversed(earlier):
        if flow.response is None:
            continue
        for raw in reversed(flow.response.set_cookies):
            parsed = parse_set_cookie(raw)
            if not parsed:
                continue
            name, cval = parsed
            if not cval or cval.lower() == "deleted":
                continue
            if cval in variants or cval.strip('"') in variants:
                return name, cval
    return None


def locate_in_cookies(value: str, earlier: list[Flow]) -> Optional[str]:
    """Name of the cookie (from an earlier ``Set-Cookie``) carrying ``value``, else None."""
    hit = find_cookie(value, earlier)
    return hit[0] if hit else None


__all__ = [
    "Candidate", "MultipartField", "parse_multipart", "json_leaves", "json_dotted", "parse_json_text",
    "split_form_segments", "form_pairs_bytes", "form_body_is_utf8", "parse_form_bytes", "request_form_charset",
    "classify_body", "request_params", "split_auth_header", "is_session_auth_header", "header_candidates",
    "is_candidate_value", "is_numeric_path_id", "is_route_like", "is_structural_path_segment", "find_candidates",
    "looks_random_letters",
    "is_dynamic_looking", "build_pattern", "locate_value", "locate_value_kinds", "find_cookie",
    "locate_in_cookies", "clear_cache",
]
