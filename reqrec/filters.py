"""Noise filtering, redirect collapsing, cookie classification, header hygiene.  Contract: DESIGN.md §4.

Everything here is deliberately conservative: a flow is only dropped when we are confident it is
noise (tracking beacons, static assets, cache revalidations ...).  HTML documents, APIs, redirects
and downloads are always kept.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
from typing import Iterable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

from . import util
from .model import AuthInfo, Dropped, Flow, Headers, InitialCookie, PlanOptions, Recording

# --------------------------------------------------------------------------- constants

#: Analytics / advertising / monitoring hosts (sub-domains match too).  Never a host that serves
#: real content a user might want to scrape.
TRACKER_HOSTS: list[str] = [
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "connect.facebook.net",
    "hotjar.com",
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "sentry.io",
    "ingest.sentry.io",
    "newrelic.com",
    "nr-data.net",
    "clarity.ms",
    "bat.bing.com",
    "demdex.net",
    "omtrdc.net",
    "optimizely.com",
    "fullstory.com",
    "criteo.com",
    "criteo.net",
    "adnxs.com",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "taboola.com",
    "outbrain.com",
    "scorecardresearch.com",
    "quantserve.com",
    "chartbeat.com",
    "treasuredata.com",
    "in.treasuredata.com",
    "mc.yandex.ru",
    "px.ads.linkedin.com",
    "snap.licdn.com",
    "analytics.twitter.com",
    "static.ads-twitter.com",
    "cdn.cookielaw.org",
    "onetrust.com",
    "browser-intake-datadoghq.com",
    "rum.browser-intake-datadoghq.com",
    "logrocket.com",
    "heapanalytics.com",
    "plausible.io",
    "matomo.cloud",
]

#: URL path extensions that denote static assets.
STATIC_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".apng", ".bmp", ".tif", ".tiff", ".svg", ".ico", ".cur",
    ".css", ".js", ".mjs", ".map",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".mp3", ".ogg", ".oga", ".ogv", ".wav", ".m4a", ".m4v", ".flac", ".aac",
    ".wasm",
})

#: HAR ``_resourceType`` values that denote static / non-document resources.
STATIC_RESOURCE_TYPES: frozenset[str] = frozenset({
    "image", "stylesheet", "script", "font", "media", "manifest", "texttrack", "ping", "beacon",
    "csp_report", "prefetch", "preflight", "signedexchange", "other",
})

#: Request headers that are never replayed (hop-by-hop, connection management, cache validators,
#: and everything ``requests`` manages itself).  Headers starting with ``:`` (HTTP/2 pseudo
#: headers) or ``proxy-`` are dropped as well.  ``content-type`` is kept here and handled by plan.py.
DROP_REQUEST_HEADERS: frozenset[str] = frozenset({
    "host", "cookie", "content-length", "connection", "accept-encoding", "transfer-encoding", "te",
    "trailer", "keep-alive", "upgrade", "if-none-match", "if-modified-since", "if-range", "expect",
})

#: Headers that are never part of ``Plan.base_headers`` (they must stay per-step so dependency
#: detection can replace them, or they are managed by requests).
_NEVER_BASE_HEADERS = frozenset({"referer", "content-type", "origin", "authorization", "cookie", "content-length"})

_STATIC_MIME_PREFIXES = ("image/", "font/", "audio/", "video/")


# --------------------------------------------------------------------------- header helpers

def clean_request_headers(headers: Headers) -> Headers:
    """Remove hop-by-hop / managed headers (see ``DROP_REQUEST_HEADERS``), HTTP/2 pseudo headers
    (``:authority`` ...) and ``proxy-*``.  Order and original spelling are preserved."""
    out: Headers = []
    for name, value in headers:
        lname = (name or "").strip().lower()
        if not lname or lname.startswith(":") or lname.startswith("proxy-") or lname in DROP_REQUEST_HEADERS:
            continue
        out.append((name, value))
    return out


def parse_cookie_header(value: Optional[str]) -> list[tuple[str, str]]:
    """``"a=1; b=2"`` -> ``[("a", "1"), ("b", "2")]`` (tolerant of garbage)."""
    pairs: list[tuple[str, str]] = []
    if not value:
        return pairs
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            name, val = chunk.split("=", 1)
        else:
            name, val = chunk, ""
        name = name.strip()
        if name:
            pairs.append((name, val.strip()))
    return pairs


def parse_set_cookie(value: Optional[str]) -> Optional[tuple[str, str]]:
    """First ``name=value`` segment of a ``Set-Cookie`` header, or None when unparsable."""
    if not value:
        return None
    first = value.split(";", 1)[0].strip()
    if "=" not in first:
        return None
    name, val = first.split("=", 1)
    name = name.strip()
    if not name:
        return None
    return name, val.strip()


# --------------------------------------------------------------------------- noise classification

def _static_reason(flow: Flow) -> Optional[str]:
    """Why ``flow`` is a static asset, or None.  Implements rule 6 of §4."""
    rtype = (flow.resource_type or "").strip().lower()
    if rtype and rtype in STATIC_RESOURCE_TYPES:
        return f"resource type {rtype}"
    url = flow.request.url
    ext = util.url_extension(url)
    mime = (flow.response.mime_type or "").lower() if flow.response else ""
    if ext == ".map":
        return "source map"
    if mime:
        if mime.startswith(_STATIC_MIME_PREFIXES) or mime == "text/css" or "javascript" in mime \
                or mime == "application/wasm" or "font" in mime or mime == "text/ecmascript":
            return f"mime {mime}"
        if mime in ("application/octet-stream", "text/plain") and ext in STATIC_EXTENSIONS:
            return f"{ext} file"
    elif ext in STATIC_EXTENSIONS:
        return f"{ext} file"
    path = (urlsplit(url).path or "").lower()
    if path.endswith("/favicon.ico"):
        return "favicon"
    return None


_FLOW_ID_RE = re.compile(r"^[fF]?0*(\d+)$")


def normalise_flow_id(value: object) -> str:
    """Canonical ``f0008`` spelling of a user-typed flow id (``f8``, ``8``, ``F0008`` ...).

    Anything that is not a (optionally ``f``-prefixed) number is returned stripped, as is."""
    text = str(value if value is not None else "").strip()
    m = _FLOW_ID_RE.match(text)
    if m:
        return f"f{int(m.group(1)):04d}"
    return text


def _flow_id_set(ids: Optional[Iterable[object]]) -> set[str]:
    out: set[str] = set()
    for value in ids or ():
        if value is None:
            continue
        # tolerate comma separated lists ("f0003,f0004") coming straight from a form field
        for part in str(value).split(","):
            norm = normalise_flow_id(part)
            if norm:
                out.add(norm)
    return out


def classify_noise(flow: Flow, opts: PlanOptions) -> Optional[str]:
    """Return a human readable reason to drop ``flow``, or None to keep it.

    Rules are applied in the order of DESIGN.md §4; the first hit wins.  ``opts.keep_all``
    disables rules 4-9 only (host rules and "no response" always apply).

    Manual overrides (DESIGN.md §13.1): a flow listed in ``opts.exclude_flow_ids`` is dropped
    before anything else (``"excluded by user"``); one listed in ``opts.include_flow_ids`` skips
    the noise rules 4-9 but still needs a response and still obeys the host rules.
    """
    req = flow.request
    host = req.host
    excluded = _flow_id_set(opts.exclude_flow_ids)
    flow_id = normalise_flow_id(flow.id)
    if excluded and (flow.id in excluded or flow_id in excluded):
        return "excluded by user"
    if opts.include_hosts and not util.host_matches(host, opts.include_hosts):
        return "host not in --include-host"
    if opts.exclude_hosts and util.host_matches(host, opts.exclude_hosts):
        return "host excluded"
    resp = flow.response
    if resp is None:
        return "no response recorded"
    included = _flow_id_set(opts.include_flow_ids)
    if included and (flow.id in included or flow_id in included):
        return None
    if opts.keep_all:
        return None
    if (req.method or "").upper() == "OPTIONS":
        return "CORS preflight"
    if not opts.keep_trackers and util.host_matches(host, TRACKER_HOSTS):
        return "tracker/analytics host"
    if not opts.keep_static:
        why = _static_reason(flow)
        if why:
            return f"static asset ({why})"
    if resp.status == 304:
        return "304 not modified (browser cache)"
    upgrade = (req.header("upgrade") or "").lower()
    if resp.status == 101 or "websocket" in upgrade:
        return "websocket"
    if (resp.mime_type or "") == "text/event-stream":
        return "server-sent events stream"
    return None


def filter_flows(recording: Recording, opts: PlanOptions) -> tuple[list[Flow], list[Dropped]]:
    """Split a recording into kept flows (chronological) and ``Dropped`` entries with reasons."""
    kept: list[Flow] = []
    dropped: list[Dropped] = []
    for flow in recording.flows:
        reason = classify_noise(flow, opts)
        if reason is None:
            kept.append(flow)
        else:
            dropped.append(Dropped(flow_id=flow.id, method=flow.request.method, url=flow.request.url, reason=reason))
    return kept, dropped


# --------------------------------------------------------------------------- redirects

def _normalise_url(url: str) -> str:
    """Comparable form of a URL: lower-case scheme/host, no fragment, ``/`` for an empty path."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc.lower()
    if (parts.scheme == "http" and netloc.endswith(":80")) or (parts.scheme == "https" and netloc.endswith(":443")):
        netloc = netloc.rsplit(":", 1)[0]
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def _redirect_follows(prev: Flow, nxt: Flow) -> bool:
    """True when ``nxt`` is the browser following the redirect in ``prev``'s response."""
    resp = prev.response
    if resp is None or not resp.is_redirect or nxt.response is None:
        return False
    location = (resp.location or "").strip()
    if not location:
        return False
    try:
        target = urljoin(prev.request.url, location)
    except ValueError:
        return False
    if _normalise_url(target) != _normalise_url(nxt.request.url):
        return False
    orig = (prev.request.method or "GET").upper()
    follow = (nxt.request.method or "GET").upper()
    if resp.status in (307, 308):
        return follow in (orig, "GET")
    # 301 / 302 / 303 (and anything else): browsers switch to GET (HEAD stays HEAD)
    if orig == "HEAD":
        return follow in ("HEAD", "GET")
    return follow == "GET"


def collapse_redirects(flows: list[Flow]) -> list[list[Flow]]:
    """Group each redirect with the flow(s) that followed it: ``[[first, ..., final], [single], ...]``."""
    groups: list[list[Flow]] = []
    i = 0
    n = len(flows)
    while i < n:
        chain = [flows[i]]
        j = i
        while j + 1 < n and _redirect_follows(flows[j], flows[j + 1]):
            chain.append(flows[j + 1])
            j += 1
        groups.append(chain)
        i = j + 1
    return groups


# --------------------------------------------------------------------------- cookies

def classify_cookies(flows: list[Flow]) -> tuple[list[InitialCookie], set[str]]:
    """Pre-existing cookies (sent before any response set them) and the set of managed names."""
    managed: set[str] = set()
    initial: list[InitialCookie] = []
    seen: set[tuple[str, str]] = set()
    for flow in flows:
        host = flow.request.host
        for raw in [v for k, v in flow.request.headers if k.lower() == "cookie"]:
            for name, value in parse_cookie_header(raw):
                if name in managed or (name, host) in seen:
                    continue
                seen.add((name, host))
                initial.append(InitialCookie(name=name, value=value, domain=host, path="/"))
        if flow.response is not None:
            for sc in flow.response.set_cookies:
                parsed = parse_set_cookie(sc)
                if parsed:
                    managed.add(parsed[0])
    return initial, managed


# --------------------------------------------------------------------------- base headers

def compute_base_headers(flows: list[Flow]) -> Headers:
    """(name, value) pairs identical across *every* kept request, first-seen spelling.

    Excludes referer / content-type / origin / authorization / cookie / content-length and all
    ``x-*`` headers; a header repeated with different values inside one request never qualifies.
    """
    if not flows:
        return []
    per_flow: list[dict[str, Optional[str]]] = []
    for flow in flows:
        table: dict[str, Optional[str]] = {}
        for name, value in clean_request_headers(flow.request.headers):
            lname = name.lower()
            if lname in table and table[lname] != value:
                table[lname] = None  # conflicting duplicates -> never a base header
            elif lname not in table:
                table[lname] = value
        per_flow.append(table)
    base: Headers = []
    emitted: set[str] = set()
    for name, value in clean_request_headers(flows[0].request.headers):
        lname = name.lower()
        if lname in emitted or lname in _NEVER_BASE_HEADERS or lname.startswith("x-"):
            continue
        if per_flow[0].get(lname) != value:
            continue
        if all(table.get(lname) == value for table in per_flow[1:]):
            base.append((name, value))
            emitted.add(lname)
    return base


# --------------------------------------------------------------------------- HTTP authentication handshakes

#: Authentication schemes the generated script configures once on the ``requests.Session``
#: (``session.auth``) instead of replaying ``Authorization`` headers.  Token schemes (Bearer,
#: JWT, ...) are *not* here: their values are traced like any other header value.
SESSION_AUTH_SCHEMES: frozenset[str] = frozenset({"ntlm", "negotiate", "basic", "digest"})

#: Schemes that share one ``session.auth`` object in the generated script (Negotiate usually
#: carries NTLM tokens on an intranet; both are handled by the same NTLM/SSPI auth class).
AUTH_FAMILIES: dict[str, frozenset[str]] = {
    "ntlm": frozenset({"ntlm", "negotiate"}),
    "negotiate": frozenset({"ntlm", "negotiate"}),
    "basic": frozenset({"basic"}),
    "digest": frozenset({"digest"}),
}

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9._-]*)(?:\s+(.*))?$", re.S)
_TOKEN68_RE = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")
_AUTH_PARAM_RE = re.compile(r'([A-Za-z0-9_*-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]*))')
_NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
_NTLM_UNICODE_FLAG = 0x00000001


def auth_family(kind: Optional[str]) -> frozenset[str]:
    """Schemes covered by ``session.auth`` for an ``AuthInfo.kind`` (empty for unknown kinds)."""
    return AUTH_FAMILIES.get((kind or "").lower(), frozenset())


def authorization_scheme(value: Optional[str]) -> tuple[str, str]:
    """``"NTLM TlRM..."`` -> ``("ntlm", "TlRM...")``; ``("", "")`` for empty / unparsable values."""
    if not value:
        return "", ""
    m = _SCHEME_RE.match(value.strip())
    if not m:
        return "", ""
    return m.group(1).lower(), (m.group(2) or "").strip()


def _split_commas(value: str) -> list[str]:
    """Split on commas outside double quotes (backslash escapes honoured inside quotes)."""
    parts: list[str] = []
    buf: list[str] = []
    quoted = False
    escape = False
    for ch in value:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if quoted and ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            quoted = not quoted
        if ch == "," and not quoted:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _parse_auth_params(text: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for m in _AUTH_PARAM_RE.finditer(text or ""):
        name = m.group(1).lower()
        if m.group(2) is not None:
            value = re.sub(r"\\(.)", r"\1", m.group(2))
        else:
            value = (m.group(3) or "").strip()
        params.setdefault(name, value)
    return params


def parse_www_authenticate(values: Iterable[Optional[str]]) -> list[tuple[str, dict[str, str], str]]:
    """Challenges of one or more ``WWW-Authenticate`` headers as ``(scheme, params, token68)``.

    Scheme and parameter names are lower-cased.  Tolerates several challenges per header
    (``Negotiate, NTLM``), quoted / escaped parameters (``Basic realm="Intra, net"``), bare tokens
    (``NTLM TlRMTVNTUAAC...``) and garbage (ignored).  Never raises."""
    out: list[tuple[str, dict[str, str], str]] = []
    current: Optional[tuple[str, dict[str, str], str]] = None
    for raw in values:
        if not raw or not isinstance(raw, str):
            continue
        for item in _split_commas(raw):
            m = _SCHEME_RE.match(item)
            rest = (m.group(2) or "").strip() if m else ""
            if m and not rest.startswith("="):
                scheme = m.group(1).lower()
                params: dict[str, str] = {}
                token = ""
                if rest:
                    if _TOKEN68_RE.match(rest):
                        token = rest
                    else:
                        params = _parse_auth_params(rest)
                current = (scheme, params, token)
                out.append(current)
            elif current is not None:
                current[1].update({k: v for k, v in _parse_auth_params(item).items() if k not in current[1]})
    return out


def _b64decode_lenient(text: Optional[str]) -> bytes:
    """Base64 decode tolerating whitespace, URL-safe alphabets and missing padding; ``b""`` on failure."""
    if not text or not isinstance(text, str):
        return b""
    cleaned = "".join(text.split()).replace("-", "+").replace("_", "/")
    if not cleaned:
        return b""
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=False)
    except (binascii.Error, ValueError):
        return b""


def _ntlm_field(blob: bytes, offset: int) -> Optional[bytes]:
    """Payload of an NTLM security buffer (``Len u16, MaxLen u16, Offset u32`` at ``offset``)."""
    if offset + 8 > len(blob):
        return None
    length, _max_length, start = struct.unpack_from("<HHI", blob, offset)
    if length == 0:
        return b""
    if start + length > len(blob):
        return None
    return blob[start:start + length]


def _ntlm_decode(raw: bytes, unicode: bool) -> str:
    if unicode:
        return raw.decode("utf-16-le", errors="replace")
    for charset in ("cp932", "latin-1"):
        try:
            return raw.decode(charset)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")  # pragma: no cover - latin-1 never fails


def parse_ntlm_type3(data: Optional[bytes]) -> Optional[dict[str, str]]:
    """Fields of an NTLM ``AUTHENTICATE_MESSAGE`` (type 3): ``domain``, ``user``, ``workstation``.

    ``data`` may be the bare NTLMSSP blob or a GSS-API / SPNEGO wrapper that embeds one (the
    signature is searched for).  Strings are UTF-16LE when the Unicode flag is set, else OEM
    (cp932, then latin-1).  Returns None for anything that is not a type-3 message; never raises."""
    if not data or not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    idx = data.find(_NTLMSSP_SIGNATURE)
    if idx < 0:
        return None
    blob = data[idx:]
    if len(blob) < 64:
        return None
    try:
        if struct.unpack_from("<I", blob, 8)[0] != 3:
            return None
        flags = struct.unpack_from("<I", blob, 60)[0]
    except struct.error:  # pragma: no cover - length checked above
        return None
    unicode = bool(flags & _NTLM_UNICODE_FLAG)
    out: dict[str, str] = {}
    for name, offset in (("domain", 28), ("user", 36), ("workstation", 44)):
        raw = _ntlm_field(blob, offset)
        out[name] = _ntlm_decode(raw, unicode).strip("\x00") if raw else ""
    return out


def ntlm_type3_user(token: Optional[str]) -> Optional[str]:
    """``DOMAIN\\user`` recovered from a base64 NTLM / Negotiate type-3 token, or None.

    Informational only (the token never contains the password)."""
    info = parse_ntlm_type3(_b64decode_lenient(token))
    if not info or not info.get("user"):
        return None
    return f"{info['domain']}\\{info['user']}" if info.get("domain") else info["user"]


def decode_basic_credentials(token: Optional[str]) -> Optional[tuple[str, str]]:
    """``(user, password)`` from a Basic token (UTF-8, then latin-1); None when unparsable.
    The password may itself contain ``:`` (only the first colon separates)."""
    data = _b64decode_lenient(token)
    if not data or b":" not in data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    user, _, password = text.partition(":")
    return user, password


def digest_username(credentials: Optional[str]) -> Optional[str]:
    """``username`` (or RFC 7616 ``username*``) of a Digest ``Authorization`` parameter list."""
    params = _parse_auth_params(credentials or "")
    name = params.get("username")
    if name:
        return name
    ext = params.get("username*")
    if ext:
        # ext-value: charset'language'pct-encoded
        pieces = ext.split("'", 2)
        if len(pieces) == 3:
            from urllib.parse import unquote

            try:
                return unquote(pieces[2], encoding=pieces[0] or "utf-8", errors="replace")
            except LookupError:
                return unquote(pieces[2])
    return None


def _challenge_schemes(flow: Flow) -> set[str]:
    """Session-auth schemes offered by a 401 response (empty when the flow is no challenge)."""
    resp = flow.response
    if resp is None or resp.status != 401:
        return set()
    values = [v for k, v in resp.headers if k.lower() == "www-authenticate"]
    return {scheme for scheme, _params, _token in parse_www_authenticate(values)} & SESSION_AUTH_SCHEMES


def _request_auth(flow: Flow) -> tuple[str, str]:
    """``(scheme, credentials)`` of the request's ``Authorization`` header (scheme lower-cased)."""
    return authorization_scheme(flow.request.header("authorization"))


def _auth_key(flow: Flow) -> tuple[str, str]:
    return (flow.request.method or "GET").upper(), _normalise_url(flow.request.url)


def _realm_for(chain: list[Flow], scheme: str) -> Optional[str]:
    for hop in chain:
        if hop.response is None:
            continue
        values = [v for k, v in hop.response.headers if k.lower() == "www-authenticate"]
        for ch_scheme, params, _token in parse_www_authenticate(values):
            if ch_scheme == scheme and params.get("realm"):
                return params["realm"]
    return None


def auth_username(scheme: str, credentials: str) -> Optional[str]:
    """Recorded user name for one ``Authorization`` value of ``scheme`` (never the password)."""
    scheme = (scheme or "").lower()
    if scheme in ("ntlm", "negotiate"):
        return ntlm_type3_user(credentials)
    if scheme == "basic":
        creds = decode_basic_credentials(credentials)
        return creds[0] if creds else None
    if scheme == "digest":
        return digest_username(credentials)
    return None


def _username_from_chain(chain: list[Flow], scheme: str) -> Optional[str]:
    for hop in reversed(chain):
        hop_scheme, creds = _request_auth(hop)
        if hop_scheme in auth_family(scheme) or hop_scheme == scheme:
            name = auth_username(hop_scheme, creds)
            if name:
                return name
    return None


def _build_auth_info(chain: list[Flow]) -> Optional[AuthInfo]:
    """``AuthInfo`` describing one completed handshake (kind = the client's final scheme)."""
    scheme, _creds = _request_auth(chain[-1])
    if scheme not in SESSION_AUTH_SCHEMES:
        return None
    return AuthInfo(
        kind=scheme,
        hosts=[chain[-1].request.host],
        realm=_realm_for(chain, scheme),
        username=_username_from_chain(chain, scheme),
    )


def collapse_auth_handshakes(flows: list[Flow]) -> tuple[list[list[Flow]], Optional[AuthInfo]]:
    """Fold HTTP authentication handshakes (DESIGN.md §13.2) into single groups.

    A handshake is a run of requests with the same method + URL (fragment ignored) in which every
    hop but the last got a ``401`` whose ``WWW-Authenticate`` offers an NTLM / Negotiate / Basic /
    Digest challenge and the following hop answers with ``Authorization:`` in one of the offered
    schemes.  Hops of several handshakes may interleave (parallel connections), but an unrelated
    request in between abandons the pending ones: a ``401`` that is never retried stays a normal
    group of its own.  Each returned group is ``[hop1_401, ..., final_attempt]``; everything else
    is a singleton, and groups are ordered by their final flow.

    The ``AuthInfo`` describes the first completed handshake (hosts of all handshakes of the same
    family are listed).  When no handshake was recorded but requests carry ``Authorization`` with
    one of those schemes (credentials sent pre-emptively / cached by the browser), the scheme is
    inferred from the first such header instead.  ``None`` when no such authentication was seen.
    """
    positioned: list[tuple[int, list[Flow]]] = []
    pending: dict[tuple[str, str], list[Flow]] = {}
    completed: list[tuple[int, list[Flow]]] = []
    index_of = {id(f): i for i, f in enumerate(flows)}

    def flush(chain: list[Flow]) -> None:
        for hop in chain:
            positioned.append((index_of[id(hop)], [hop]))

    for i, flow in enumerate(flows):
        if flow.request is None:  # pragma: no cover - defensive
            positioned.append((i, [flow]))
            continue
        key = _auth_key(flow)
        scheme, _creds = _request_auth(flow)
        offered = _challenge_schemes(flow)
        chain = pending.get(key)
        if chain is not None and scheme in SESSION_AUTH_SCHEMES and scheme in _challenge_schemes(chain[-1]):
            chain.append(flow)
            if offered and flow.response is not None and flow.response.status == 401:
                continue  # another round (NTLM type-2 challenge) - keep waiting for the next hop
            del pending[key]
            positioned.append((i, chain))
            completed.append((i, chain))
            continue
        if chain is not None:
            del pending[key]
            flush(chain)
        handshake_activity = bool(offered) or scheme in SESSION_AUTH_SCHEMES
        if not handshake_activity and pending:
            for stale in list(pending.values()):
                flush(stale)
            pending.clear()
        if offered:
            pending[key] = [flow]
            continue
        positioned.append((i, [flow]))
    for stale in pending.values():
        flush(stale)
    positioned.sort(key=lambda t: t[0])
    groups = [g for _, g in positioned]

    auth: Optional[AuthInfo] = None
    for _pos, chain in sorted(completed, key=lambda t: t[0]):
        info = _build_auth_info(chain)
        if info is None:
            continue
        if auth is None:
            auth = info
            continue
        if info.kind in auth_family(auth.kind):
            for host in info.hosts:
                if host not in auth.hosts:
                    auth.hosts.append(host)
            if auth.username is None and info.username:
                auth.username = info.username
            if auth.realm is None and info.realm:
                auth.realm = info.realm
    if auth is None:
        auth = _infer_auth_from_headers(flows)
    return groups, auth


def _infer_auth_from_headers(flows: list[Flow]) -> Optional[AuthInfo]:
    """Fallback when no 401 handshake was captured: the scheme of the first ``Authorization``
    header that uses a session-level scheme (browser credentials cached before recording)."""
    auth: Optional[AuthInfo] = None
    for flow in flows:
        scheme, creds = _request_auth(flow)
        if scheme not in SESSION_AUTH_SCHEMES:
            continue
        if auth is None:
            auth = AuthInfo(kind=scheme, hosts=[flow.request.host], username=auth_username(scheme, creds),
                            comment="401 チャレンジは記録されていません（Authorization ヘッダーから推定）")
        elif scheme in auth_family(auth.kind):
            if flow.request.host not in auth.hosts:
                auth.hosts.append(flow.request.host)
            if auth.username is None:
                auth.username = auth_username(scheme, creds)
    return auth


__all__ = [
    "TRACKER_HOSTS", "STATIC_EXTENSIONS", "STATIC_RESOURCE_TYPES", "DROP_REQUEST_HEADERS",
    "SESSION_AUTH_SCHEMES", "AUTH_FAMILIES",
    "classify_noise", "filter_flows", "collapse_redirects", "classify_cookies", "compute_base_headers",
    "clean_request_headers", "parse_cookie_header", "parse_set_cookie", "normalise_flow_id",
    "collapse_auth_handshakes", "auth_family", "authorization_scheme", "parse_www_authenticate",
    "parse_ntlm_type3", "ntlm_type3_user", "decode_basic_credentials", "digest_username", "auth_username",
]
