"""HAR 1.2 importer (Chrome / Firefox / Safari DevTools exports).  Contract: DESIGN.md §2.

The importer is deliberately forgiving: real-world HAR files miss fields, contain ``null`` where
the spec says string, use odd timestamp formats and carry lossy text for binary bodies.  An entry
is skipped **only** when it has no usable URL (or is so malformed that it cannot be read at all);
everything else is imported on a best-effort basis.  Skipped entries are counted in
``Recording.meta["skipped_entries"]``.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import secrets
from datetime import datetime, timezone
from email.utils import formatdate
from typing import Any, Optional
from urllib.parse import urlencode

from .. import util
from ..model import Flow, Headers, RecordedRequest, RecordedResponse, Recording, header_get

log = logging.getLogger(__name__)

__all__ = ["load_har", "recording_from_har", "parse_har_timestamp"]

# Chrome / Firefox write this when they do not know the MIME type; treat as "unknown".
_UNKNOWN_MIME_TYPES = {"x-unknown", "application/x-unknown-content-type", ""}

# Cookie attribute names as they appear in HAR cookie objects (lower-case) -> Set-Cookie spelling.
_COOKIE_FLAG_ATTRS = (("httponly", "HttpOnly"), ("secure", "Secure"))


# --------------------------------------------------------------------------- file loading

def _read_text_file(path: str) -> str:
    """Read a (possibly BOM-prefixed, possibly UTF-16) text file as str."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    # utf-8-sig strips an optional UTF-8 BOM (Windows DevTools exports sometimes have one).
    return raw.decode("utf-8-sig", errors="replace")


def load_har(path: str) -> Recording:
    """Load a ``.har`` file into a :class:`Recording`.

    Raises ``ValueError`` when the file is not JSON or not a HAR document.
    """
    text = _read_text_file(path)
    try:
        har = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: HARファイルとしてJSONを解析できません / not valid JSON ({exc})") from exc
    return recording_from_har(har, source=os.fspath(path))


# --------------------------------------------------------------------------- top level

def recording_from_har(har: dict[str, Any], source: str = "") -> Recording:
    """Convert an in-memory HAR document (``{"log": {...}}``) into a :class:`Recording`.

    Entries are sorted by ``startedDateTime`` (stable: entries with an unparseable timestamp keep
    their position relative to their neighbours) and numbered ``f0001``, ``f0002``, ...
    """
    har_log = _extract_log(har)
    raw_entries = har_log.get("entries")
    if not isinstance(raw_entries, list):
        raw_entries = []

    skipped = 0
    converted: list[tuple[float, int, Flow]] = []
    last_ts = float("-inf")
    for index, entry in enumerate(raw_entries):
        try:
            flow = _flow_from_entry(entry)
        except Exception as exc:  # pragma: no cover - last line of defence; never crash on a HAR
            log.warning("HAR entry %d could not be imported: %s", index, exc)
            flow = None
        if flow is None:
            skipped += 1
            continue
        if flow.started_at is None:
            sort_key = last_ts  # keep unknown-time entries next to their predecessor
        else:
            sort_key = flow.started_at
            last_ts = flow.started_at
        converted.append((sort_key, index, flow))

    converted.sort(key=lambda t: (t[0], t[1]))
    flows: list[Flow] = []
    for n, (_, _, flow) in enumerate(converted, start=1):
        flow.id = f"f{n:04d}"
        flows.append(flow)

    meta: dict[str, Any] = {
        "source": "har",
        "file": source,
        "creator": _creator_string(har_log.get("creator")),
        "imported_at": util.now_iso(),
        "entries": len(raw_entries),
        "skipped_entries": skipped,
    }
    browser = _creator_string(har_log.get("browser"))
    if browser:
        meta["browser"] = browser
    return Recording(flows=flows, meta=meta)


def _extract_log(har: Any) -> dict[str, Any]:
    """Return the ``log`` object of a HAR document; also accept a bare ``log`` object."""
    if not isinstance(har, dict):
        raise ValueError("HARドキュメントではありません / not a HAR document (top level is not an object)")
    har_log = har.get("log")
    if isinstance(har_log, dict):
        return har_log
    if "entries" in har:  # some tools dump the log object itself
        return har
    raise ValueError('HARドキュメントではありません / not a HAR document ("log" object missing)')


def _creator_string(creator: Any) -> str:
    if not isinstance(creator, dict):
        return ""
    name = str(creator.get("name") or "").strip()
    version = str(creator.get("version") or "").strip()
    if name and version:
        return f"{name}/{version}"
    return name or version


# --------------------------------------------------------------------------- entries

def _flow_from_entry(entry: Any) -> Optional[Flow]:
    """Convert one HAR entry; ``None`` when it has no usable URL."""
    if not isinstance(entry, dict):
        return None
    req_obj = entry.get("request")
    if not isinstance(req_obj, dict):
        return None
    url = req_obj.get("url")
    if not isinstance(url, str) or not url.strip():
        return None

    request = _request_from_har(req_obj, url.strip())
    response = _response_from_har(entry.get("response"))

    resource_type = entry.get("_resourceType")
    if isinstance(resource_type, str) and resource_type.strip():
        resource_type = resource_type.strip().lower()
    else:
        resource_type = None

    page_ref = entry.get("pageref")
    page_ref = str(page_ref) if page_ref not in (None, "") else None

    return Flow(
        id="",  # assigned after sorting
        request=request,
        response=response,
        started_at=parse_har_timestamp(entry.get("startedDateTime")),
        page_ref=page_ref,
        resource_type=resource_type,
    )


def _headers_from_har(items: Any) -> Headers:
    """``[{"name": ..., "value": ...}]`` -> list of (name, value) str tuples (kept verbatim)."""
    headers: Headers = []
    if not isinstance(items, list):
        return headers
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if name is None or str(name) == "":
            continue
        value = item.get("value")
        headers.append((str(name), "" if value is None else str(value)))
    return headers


def _cookie_pairs(items: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if not isinstance(items, list):
        return pairs
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if name is None or str(name) == "":
            continue
        value = item.get("value")
        pairs.append((str(name), "" if value is None else str(value)))
    return pairs


# --------------------------------------------------------------------------- request

def _request_from_har(req: dict[str, Any], url: str) -> RecordedRequest:
    method = str(req.get("method") or "GET").strip().upper() or "GET"
    headers = _headers_from_har(req.get("headers"))

    # Some exports (Safari, privacy-stripped HARs) drop the Cookie header but keep the array.
    if header_get(headers, "cookie") is None:
        cookie_pairs = _cookie_pairs(req.get("cookies"))
        if cookie_pairs:
            headers.append(("Cookie", "; ".join(f"{k}={v}" for k, v in cookie_pairs)))

    body = None
    post = req.get("postData")
    if isinstance(post, dict):
        body, headers = _request_body_from_post_data(post, headers)

    return RecordedRequest(method=method, url=url, headers=headers, body=body)


def _request_body_from_post_data(post: dict[str, Any], headers: Headers) -> tuple[Optional[bytes], Headers]:
    """Body bytes from ``postData`` (``text`` preferred, else ``params``); may add Content-Type."""
    mime = post.get("mimeType")
    mime = mime.strip() if isinstance(mime, str) else ""
    content_type_header = header_get(headers, "content-type")
    if mime and content_type_header is None:
        headers = headers + [("Content-Type", mime)]
        content_type_header = mime

    text = post.get("text")
    encoding = str(post.get("encoding") or "").lower()
    if isinstance(text, str):
        if encoding == "base64":
            return _b64decode_lenient(text), headers
        charset = _charset_for_text(text, content_type_header, mime)
        return _encode_text(text, charset), headers

    params = post.get("params")
    if isinstance(params, list) and params:
        mime_main = util.parse_content_type(content_type_header or mime)[0] or ""
        if mime_main.startswith("multipart/"):
            return _multipart_from_params(params, headers, content_type_header or mime)
        pairs = []
        for p in params:
            if not isinstance(p, dict) or p.get("name") is None:
                continue
            value = p.get("value")
            pairs.append((str(p["name"]), "" if value is None else str(value)))
        return urlencode(pairs).encode("ascii"), headers

    return None, headers


_BOUNDARY_RE = re.compile(r"""boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))""", re.I)


def _multipart_boundary(content_type: Optional[str]) -> Optional[str]:
    """Case-preserving boundary parameter (``util.parse_content_type`` lower-cases values)."""
    if not content_type:
        return None
    m = _BOUNDARY_RE.search(content_type)
    if not m:
        return None
    return m.group(1) or m.group(2)


def _multipart_from_params(params: list[Any], headers: Headers, content_type: Optional[str]) -> tuple[bytes, Headers]:
    """Rebuild a ``multipart/form-data`` body from HAR ``params`` (text and file parts)."""
    boundary = _multipart_boundary(content_type)
    if not boundary:
        boundary = "----reqrecFormBoundary" + secrets.token_hex(8)
        # Replace / add the Content-Type header so the boundary is consistent with the body.
        headers = [(k, v) for k, v in headers if k.lower() != "content-type"]
        headers.append(("Content-Type", f"multipart/form-data; boundary={boundary}"))
    b = boundary.encode("ascii", "replace")
    out = bytearray()
    for p in params:
        if not isinstance(p, dict) or p.get("name") is None:
            continue
        name = str(p["name"]).replace('"', "%22")
        out += b"--" + b + b"\r\n"
        disposition = f'Content-Disposition: form-data; name="{name}"'
        filename = p.get("fileName")
        if filename not in (None, ""):
            disposition += f'; filename="{str(filename).replace(chr(34), "%22")}"'
        out += disposition.encode("utf-8", "replace") + b"\r\n"
        part_type = p.get("contentType")
        if isinstance(part_type, str) and part_type:
            out += b"Content-Type: " + part_type.encode("ascii", "replace") + b"\r\n"
        out += b"\r\n"
        value = p.get("value")
        out += ("" if value is None else str(value)).encode("utf-8", "replace") + b"\r\n"
    out += b"--" + b + b"--\r\n"
    return bytes(out), headers


# --------------------------------------------------------------------------- response

def _response_from_har(resp: Any) -> Optional[RecordedResponse]:
    if not isinstance(resp, dict):
        return None
    status = _to_int(resp.get("status"))
    if not status or status <= 0:  # 0 = blocked / failed / aborted (Chrome), missing = no response
        return None

    headers = _headers_from_har(resp.get("headers"))
    if header_get(headers, "set-cookie") is None:
        for cookie in _set_cookie_lines(resp.get("cookies")):
            headers.append(("Set-Cookie", cookie))

    content = resp.get("content")
    if not isinstance(content, dict):
        content = {}
    content_mime_raw = content.get("mimeType")
    content_mime_raw = content_mime_raw.strip() if isinstance(content_mime_raw, str) else ""
    content_type_header = header_get(headers, "content-type")

    mime_type = util.parse_content_type(content_mime_raw)[0]
    if mime_type in _UNKNOWN_MIME_TYPES or mime_type is None:
        mime_type = util.parse_content_type(content_type_header)[0]
        if mime_type in _UNKNOWN_MIME_TYPES:
            mime_type = None

    body = _response_body(content, content_type_header, content_mime_raw)
    return RecordedResponse(status=status, headers=headers, body=body, mime_type=mime_type)


def _response_body(content: dict[str, Any], content_type_header: Optional[str], content_mime: str) -> Optional[bytes]:
    text = content.get("text")
    if not isinstance(text, str):
        return None  # body not captured (redirects, 304, "Save all as HAR with content" unchecked, ...)
    encoding = str(content.get("encoding") or "").lower()
    if encoding == "base64":
        return _b64decode_lenient(text)
    charset = _charset_for_text(text, content_type_header, content_mime)
    return _encode_text(text, charset)


def _set_cookie_lines(items: Any) -> list[str]:
    """HAR response ``cookies`` -> ``Set-Cookie`` header values (one per cookie)."""
    lines: list[str] = []
    if not isinstance(items, list):
        return lines
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if name is None or str(name) == "":
            continue
        value = item.get("value")
        parts = [f"{name}={'' if value is None else value}"]
        path = item.get("path")
        if path not in (None, ""):
            parts.append(f"Path={path}")
        domain = item.get("domain")
        if domain not in (None, ""):
            parts.append(f"Domain={domain}")
        expires = item.get("expires")
        if expires not in (None, ""):
            parts.append(f"Expires={_http_date(str(expires))}")
        max_age = item.get("maxAge") if "maxAge" in item else item.get("max-age")
        if max_age not in (None, ""):
            parts.append(f"Max-Age={max_age}")
        lowered = {str(k).lower(): v for k, v in item.items()}
        for key, spelling in _COOKIE_FLAG_ATTRS:
            if lowered.get(key) is True:
                parts.append(spelling)
        same_site = lowered.get("samesite")
        if isinstance(same_site, str) and same_site.strip():
            parts.append(f"SameSite={same_site.strip().capitalize()}")
        lines.append("; ".join(parts))
    return lines


def _http_date(value: str) -> str:
    """ISO-8601 (HAR cookie ``expires``) -> RFC 1123 date; pass through anything unparseable."""
    ts = parse_har_timestamp(value)
    if ts is None:
        return value
    try:
        return formatdate(ts, usegmt=True)
    except (OverflowError, ValueError, OSError):  # pragma: no cover - absurd dates
        return value


# --------------------------------------------------------------------------- encoding helpers

def _charset_for_text(text: str, content_type_header: Optional[str], content_mime: str) -> str:
    """Charset to re-encode HAR text with: Content-Type header, else content.mimeType, else the
    document's own ``<meta charset>`` / ``<?xml encoding?>`` declaration, else utf-8."""
    header_charset = util.parse_content_type(content_type_header)[1].get("charset")
    mime_charset = util.parse_content_type(content_mime)[1].get("charset")
    if header_charset:
        ct = content_type_header
    elif mime_charset:
        ct = content_mime
    else:
        ct = content_type_header or content_mime or None
    sample = text[:4096].encode("utf-8", "replace")  # only used for <meta charset> sniffing
    return util.detect_charset(sample, ct)


def _encode_text(text: str, charset: str) -> bytes:
    try:
        return text.encode(charset, errors="replace")
    except (LookupError, UnicodeError):  # pragma: no cover - detect_charset validates the codec
        return text.encode("utf-8", errors="replace")


def _b64decode_lenient(text: str) -> bytes:
    """Base64 decode tolerating whitespace, URL-safe alphabets and missing padding."""
    cleaned = "".join(text.split())
    if not cleaned:
        return b""
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        # Not base64 after all (mislabelled export) - keep the text so nothing is lost.
        return text.encode("utf-8", errors="replace")


def _to_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- timestamps

def parse_har_timestamp(value: Any) -> Optional[float]:
    """ISO-8601 ``startedDateTime`` (``Z`` / ``+09:00`` / ``+0900`` offsets, any fractional-second
    precision, naive = UTC) or a numeric epoch -> epoch seconds as float; ``None`` if unparseable."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
        return ts / 1000.0 if ts > 1e11 else ts  # milliseconds vs seconds
    s = str(value).strip()
    if not s:
        return None
    candidate = s
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        dt = _parse_iso_fallback(candidate)
        if dt is None:
            try:  # numeric string?
                ts = float(s)
            except ValueError:
                return None
            return ts / 1000.0 if ts > 1e11 else ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return dt.timestamp()
    except (OverflowError, OSError, ValueError):  # pragma: no cover - absurd dates
        return None


def _parse_iso_fallback(s: str) -> Optional[datetime]:
    """Handle forms ``fromisoformat`` rejects: fractional seconds with >6 digits plus an offset
    without colon, or a space separator with unusual precision."""
    s = s.replace(" ", "T", 1)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M%z", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(_trim_fraction(s), fmt)
        except ValueError:
            continue
    return None


def _trim_fraction(s: str) -> str:
    """Trim fractional seconds to 6 digits so ``%f`` accepts them."""
    if "." not in s:
        return s
    head, _, tail = s.partition(".")
    digits = ""
    rest = tail
    for i, ch in enumerate(tail):
        if ch.isdigit():
            digits += ch
        else:
            rest = tail[i:]
            break
    else:
        rest = ""
    return f"{head}.{digits[:6] or '0'}{rest}"
