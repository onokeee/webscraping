"""Shared, dependency-free helpers (stdlib only).  Used by every other module."""

from __future__ import annotations

import builtins
import keyword
import re
import time
from datetime import datetime, timezone
from typing import Iterable, Optional
from urllib.parse import parse_qsl, quote, unquote, unquote_plus, urlsplit, urlunsplit

# --------------------------------------------------------------------------- content types

TEXTUAL_MIME_PREFIXES = ("text/",)
TEXTUAL_MIME_EXACT = {
    "application/json",
    "application/ld+json",
    "application/problem+json",
    "application/xml",
    "application/xhtml+xml",
    "application/x-www-form-urlencoded",
    "application/javascript",
    "application/x-javascript",
    "application/graphql",
    "application/soap+xml",
    "application/atom+xml",
    "application/rss+xml",
    "application/x-ndjson",
}
TEXTUAL_MIME_SUFFIXES = ("+json", "+xml")


def parse_content_type(value: Optional[str]) -> tuple[Optional[str], dict[str, str]]:
    """``'text/html; charset=UTF-8'`` -> ``('text/html', {'charset': 'utf-8'})``.

    Parameter *names* and the ``charset`` value are lower-cased; other values (notably the
    case-sensitive multipart ``boundary``) keep their original case."""
    if not value:
        return None, {}
    parts = [p.strip() for p in value.split(";")]
    mime = parts[0].lower() or None
    params: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            k = k.strip().lower()
            v = v.strip().strip('"')
            params[k] = v.lower() if k == "charset" else v
    return mime, params


def is_textual_mime(mime: Optional[str]) -> bool:
    if not mime:
        return False
    mime = mime.lower()
    return (
        mime.startswith(TEXTUAL_MIME_PREFIXES)
        or mime in TEXTUAL_MIME_EXACT
        or mime.endswith(TEXTUAL_MIME_SUFFIXES)
    )


def is_json_mime(mime: Optional[str]) -> bool:
    return bool(mime) and (mime == "application/json" or mime.endswith("+json") or mime == "text/json")


def is_html_mime(mime: Optional[str]) -> bool:
    return mime in ("text/html", "application/xhtml+xml")


def is_xml_mime(mime: Optional[str]) -> bool:
    return bool(mime) and (mime in ("text/xml", "application/xml") or (mime.endswith("+xml") and mime != "application/xhtml+xml"))


_META_CHARSET_RE = re.compile(rb"""<meta[^>]+charset=["']?\s*([-\w.:]+)""", re.I)
_XML_ENCODING_RE = re.compile(rb"""^\s*<\?xml[^>]*encoding=["']([-\w.:]+)["']""", re.I)


def detect_charset(body: bytes, content_type: Optional[str]) -> str:
    """Charset from Content-Type, else from <meta charset> / <?xml encoding>, else utf-8."""
    mime, params = parse_content_type(content_type)
    cs = params.get("charset")
    if cs:
        return _normalise_charset(cs)
    head = body[:4096]
    m = _META_CHARSET_RE.search(head) or _XML_ENCODING_RE.search(head)
    if m:
        return _normalise_charset(m.group(1).decode("ascii", "replace"))
    return "utf-8"


def _normalise_charset(cs: str) -> str:
    cs = cs.strip().lower()
    aliases = {"shift-jis": "cp932", "shift_jis": "cp932", "sjis": "cp932", "x-sjis": "cp932", "windows-31j": "cp932", "ms932": "cp932"}
    cs = aliases.get(cs, cs)
    try:
        b"".decode(cs)
    except (LookupError, TypeError):
        return "utf-8"
    return cs


def decode_body(body: bytes, content_type: Optional[str]) -> str:
    """Best-effort decode of a body to str; never raises."""
    cs = detect_charset(body, content_type)
    try:
        return body.decode(cs, errors="replace")
    except Exception:  # pragma: no cover - defensive
        return body.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- URLs

def strip_query(url: str) -> str:
    """URL without query string and fragment."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def parse_query(query: str) -> list[tuple[str, str]]:
    """Ordered (name, value) pairs, keeping blank values and repeated names."""
    if not query:
        return []
    return parse_qsl(query, keep_blank_values=True)


def parse_form(body: str) -> list[tuple[str, str]]:
    """application/x-www-form-urlencoded body -> ordered pairs."""
    return parse_qsl(body, keep_blank_values=True)


def host_matches(host: str, patterns: Iterable[str]) -> bool:
    """True if ``host`` equals or is a sub-domain of any pattern (case-insensitive)."""
    host = (host or "").lower().rstrip(".")
    for p in patterns:
        p = (p or "").lower().strip().rstrip(".")
        if not p:
            continue
        if p.startswith("*."):
            p = p[2:]
        if host == p or host.endswith("." + p):
            return True
    return False


def url_extension(url: str) -> str:
    """Lower-case file extension of the URL path ('' when none), e.g. '.png'."""
    path = urlsplit(url).path
    last = path.rsplit("/", 1)[-1]
    if "." not in last:
        return ""
    return "." + last.rsplit(".", 1)[-1].lower()


def value_variants(value: str) -> set[str]:
    """Spellings a request value may have had inside a response: raw, URL-(un)quoted, HTML-escaped."""
    out = {value}
    try:
        out.add(unquote(value))
        out.add(unquote_plus(value))
        out.add(quote(value, safe=""))
        out.add(quote(value, safe="/:"))
    except Exception:  # pragma: no cover
        pass
    out.add(value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;"))
    out.add(value.replace("/", "\\/"))  # JSON-escaped slash
    return {v for v in out if v}


# --------------------------------------------------------------------------- identifiers

_IDENT_CLEAN_RE = re.compile(r"[^0-9a-zA-Z_]+")
_RESERVED = set(keyword.kwlist) | set(dir(builtins)) | {
    "session", "resp", "soup", "data", "ctx", "main", "step", "requests", "re", "json", "os", "sys", "time",
    "BeautifulSoup", "BASE_HEADERS", "INITIAL_COOKIES", "TIMEOUT",
}


def safe_identifier(text: str, default: str = "value") -> str:
    """Turn arbitrary text into a valid, non-reserved, snake_case Python identifier."""
    s = _IDENT_CLEAN_RE.sub("_", text.strip())
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", s).lower()  # camelCase -> camel_case
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = default
    if s[0].isdigit():
        s = "_" + s
    if s in _RESERVED or keyword.iskeyword(s):
        s += "_"
    return s


def unique_name(base: str, taken: set[str]) -> str:
    """``base`` if free, else ``base_2``, ``base_3`` ...  Adds the result to ``taken``."""
    name = base
    i = 2
    while name in taken:
        name = f"{base}_{i}"
        i += 1
    taken.add(name)
    return name


# --------------------------------------------------------------------------- misc

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def looks_like_timestamp(value: str, around: Optional[float] = None, tolerance_days: float = 400.0) -> Optional[str]:
    """If ``value`` is an epoch timestamp (seconds or milliseconds) near ``around`` (default: now),
    return ``'s'`` or ``'ms'``; otherwise None.  Used to replace cache-busters like ``_=1696...``."""
    if not value.isdigit():
        return None
    n = int(value)
    ref = around if around is not None else time.time()
    tol = tolerance_days * 86400
    if len(value) == 13 and abs(n / 1000 - ref) < tol:
        return "ms"
    if len(value) == 10 and abs(n - ref) < tol:
        return "s"
    return None


SECRET_NAME_RE = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(orization)?$|^token$|bearer|otp|pin$|credential)",
    re.I,
)


def looks_like_secret_name(name: str) -> bool:
    """Heuristic: does a parameter / header name denote a credential?"""
    return bool(SECRET_NAME_RE.search(name or ""))


def truncate(s: str, n: int = 80) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"
