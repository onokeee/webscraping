"""mitmproxy flow-file importer and mitmproxy<->Flow conversion.  Contract: DESIGN.md §2.

``flow_from_mitm`` is shared with the live recorder addon (``reqrec.recorder.addon``).  It only
touches public attributes of ``mitmproxy.http.HTTPFlow`` so it also works on duck-typed objects
and does not itself need mitmproxy importable; ``load_mitm`` does (``mitmproxy.io.FlowReader``).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Iterable, Optional

from .. import util
from ..model import Flow, Headers, RecordedRequest, RecordedResponse, Recording

log = logging.getLogger(__name__)

__all__ = ["MITMPROXY_INSTALL_HINT", "load_mitm", "flow_from_mitm", "decode_header_fields", "infer_resource_type"]

MITMPROXY_INSTALL_HINT = (
    "mitmproxy がインストールされていません。次のコマンドでインストールしてください:\n"
    '    pip install "reqrec[record]"\n'
    'mitmproxy is not installed. Install it with: pip install "reqrec[record]"'
)

# ``Sec-Fetch-Dest`` request header -> HAR-style resource type.  Browsers send this on every
# request, so a mitmproxy capture can be classified almost as precisely as a DevTools HAR.
_SEC_FETCH_DEST_TO_RESOURCE_TYPE = {
    "document": "document",
    "iframe": "document",
    "frame": "document",
    "embed": "other",
    "object": "other",
    "image": "image",
    "style": "stylesheet",
    "script": "script",
    "font": "font",
    "audio": "media",
    "video": "media",
    "track": "texttrack",
    "manifest": "manifest",
    "report": "csp_report",
    "worker": "script",
    "sharedworker": "script",
    "serviceworker": "script",
    "paintworklet": "script",
    "audioworklet": "script",
    "xslt": "other",
    "websocket": "websocket",
}


# --------------------------------------------------------------------------- file loading

def _import_mitmproxy():
    """Import the mitmproxy pieces we need, with a friendly hint when it is missing."""
    try:
        from mitmproxy import http as mhttp
        from mitmproxy import io as mio
        from mitmproxy.exceptions import FlowReadException
    except ImportError as exc:
        raise ImportError(MITMPROXY_INSTALL_HINT) from exc
    return mio, mhttp, FlowReadException


def load_mitm(path: str) -> Recording:
    """Load a mitmproxy flow file (``mitmdump -w flows.mitm``) into a :class:`Recording`.

    Only ``HTTPFlow`` objects are imported (TCP/UDP/DNS flows are counted and skipped).  A file
    truncated by a killed mitmdump yields the flows read up to the corruption point and records the
    error in ``meta["read_error"]``.  Flows are sorted by ``timestamp_start`` and numbered
    ``f0001``, ``f0002``, ...
    """
    mio, mhttp, FlowReadException = _import_mitmproxy()
    http_flows: list[Any] = []
    skipped = 0
    read_error: Optional[str] = None
    with open(path, "rb") as fh:
        reader = mio.FlowReader(fh)
        try:
            for mflow in reader.stream():
                if isinstance(mflow, mhttp.HTTPFlow):
                    http_flows.append(mflow)
                else:
                    skipped += 1
        except FlowReadException as exc:
            read_error = str(exc)
            log.warning("%s: flow file truncated or corrupt, keeping %d flows (%s)", path, len(http_flows), exc)

    flows = _flows_in_order(http_flows)
    meta: dict[str, Any] = {
        "source": "mitmproxy",
        "file": os.fspath(path),
        "imported_at": util.now_iso(),
        "flows_total": len(http_flows) + skipped,
        "skipped_flows": skipped,
    }
    if read_error:
        meta["read_error"] = read_error
    return Recording(flows=flows, meta=meta)


def _flows_in_order(mitm_flows: Iterable[Any]) -> list[Flow]:
    """Sort by ``request.timestamp_start`` (stable; unknown timestamps stay in place) and assign ids."""
    keyed: list[tuple[float, int, Any]] = []
    last_ts = float("-inf")
    for index, mflow in enumerate(mitm_flows):
        ts = _timestamp(mflow)
        if ts is None:
            ts = last_ts
        else:
            last_ts = ts
        keyed.append((ts, index, mflow))
    keyed.sort(key=lambda t: (t[0], t[1]))
    out: list[Flow] = []
    for n, (_, _, mflow) in enumerate(keyed, start=1):
        try:
            out.append(flow_from_mitm(mflow, f"f{n:04d}"))
        except Exception as exc:  # pragma: no cover - defensive: never lose a whole file for one flow
            log.warning("mitmproxy flow %d could not be converted: %s", n, exc)
    # Re-number in case a flow was dropped so ids stay contiguous.
    for n, flow in enumerate(out, start=1):
        flow.id = f"f{n:04d}"
    return out


def _timestamp(mflow: Any) -> Optional[float]:
    req = getattr(mflow, "request", None)
    ts = getattr(req, "timestamp_start", None)
    if ts is None:
        return None
    try:
        return float(ts)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- conversion

def flow_from_mitm(flow: Any, flow_id: str) -> Flow:
    """Convert a ``mitmproxy.http.HTTPFlow`` into a :class:`Flow` with the given id.

    * URL: ``request.pretty_url`` (host from the Host header / SNI rather than the IP).
    * Headers: ``headers.fields`` byte pairs decoded tolerantly (UTF-8, falling back to latin-1),
      kept exactly as captured.
    * Bodies: ``.content`` (Content-Encoding removed); ``.raw_content`` when decoding fails.
    * ``started_at``: ``request.timestamp_start``; ``resource_type`` inferred from ``Sec-Fetch-Dest``.

    Raises ``TypeError`` for flows without an HTTP request (TCP / UDP / DNS flows).
    """
    request = getattr(flow, "request", None)
    if request is None or not hasattr(request, "method"):
        raise TypeError(f"not an HTTP flow: {type(flow).__name__}")

    req_headers = decode_header_fields(_header_fields(request))
    req_body = _message_body(request)
    if req_body == b"" and not _has_header(req_headers, "content-type"):
        # mitmproxy reports b"" for a body-less GET; HAR has no postData -> None.  Normalise so
        # both importers agree ("no body"); an explicitly typed empty body (POST with
        # Content-Type) is kept as b"".
        req_body = None
    recorded_request = RecordedRequest(
        method=_text(getattr(request, "method", "GET")).upper() or "GET",
        url=_request_url(request),
        headers=req_headers,
        body=req_body,
    )

    recorded_response: Optional[RecordedResponse] = None
    response = getattr(flow, "response", None)
    if response is not None:
        try:
            status = int(getattr(response, "status_code", 0) or 0)
        except (TypeError, ValueError):
            status = 0
        if status > 0:
            recorded_response = RecordedResponse(
                status=status,
                headers=decode_header_fields(_header_fields(response)),
                body=_message_body(response),
            )

    return Flow(
        id=flow_id,
        request=recorded_request,
        response=recorded_response,
        started_at=_timestamp(flow),
        page_ref=None,
        resource_type=infer_resource_type(req_headers),
    )


def _request_url(request: Any) -> str:
    for attr in ("pretty_url", "url"):
        try:
            url = getattr(request, attr)
        except Exception:  # pragma: no cover - mitmproxy raises on malformed authority
            continue
        if url:
            return _text(url)
    # Last resort: assemble from parts.
    scheme = _text(getattr(request, "scheme", "http") or "http")
    host = _text(getattr(request, "pretty_host", "") or getattr(request, "host", "") or "")
    path = _text(getattr(request, "path", "/") or "/")
    return f"{scheme}://{host}{path}"


def _header_fields(message: Any) -> Iterable[tuple[Any, Any]]:
    headers = getattr(message, "headers", None)
    if headers is None:
        return ()
    fields = getattr(headers, "fields", None)
    if fields is not None:
        return fields
    try:
        return list(headers.items(multi=True))  # mitmproxy Headers without .fields (very old versions)
    except TypeError:
        return list(headers.items())


def decode_header_fields(fields: Iterable[tuple[Any, Any]]) -> Headers:
    """``((b"name", b"value"), ...)`` -> ``[("name", "value"), ...]``; bytes that are not UTF-8 are
    decoded as latin-1 so nothing ever raises.  ``str`` pairs pass through."""
    out: Headers = []
    for pair in fields:
        try:
            name, value = pair
        except (TypeError, ValueError):
            continue
        out.append((_text(name), _text(value)))
    return out


def _has_header(headers: Headers, name: str) -> bool:
    lname = name.lower()
    return any(k.lower() == lname for k, _ in headers)


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")
    if value is None:
        return ""
    return str(value)


def _message_body(message: Any) -> Optional[bytes]:
    """Decoded body (``.content``), falling back to ``.raw_content`` when Content-Encoding decoding
    fails (corrupt gzip, unknown ``br`` without brotli, ...)."""
    try:
        content = message.content
    except Exception:
        content = None
        try:
            content = message.raw_content
        except Exception:  # pragma: no cover - defensive
            content = None
    if content is None:
        # mitmproxy uses None for "no body" / "body not captured"; a response that was streamed
        # without buffering also lands here.
        raw = getattr(message, "raw_content", None)
        if raw is None:
            return None
        content = raw
    if isinstance(content, (bytearray, memoryview)):
        content = bytes(content)
    if not isinstance(content, bytes):
        content = _text(content).encode("utf-8", "replace")
    return content


def infer_resource_type(headers: Headers) -> Optional[str]:
    """HAR-style resource type from the browser's ``Sec-Fetch-Dest`` header, or ``None``.

    ``empty`` (fetch/XHR) is split using ``X-Requested-With: XMLHttpRequest`` -> ``xhr``,
    otherwise ``fetch``.
    """
    dest = None
    requested_with = None
    for name, value in headers:
        lname = name.lower()
        if lname == "sec-fetch-dest" and dest is None:
            dest = value.strip().lower()
        elif lname == "x-requested-with" and requested_with is None:
            requested_with = value.strip().lower()
    if dest is None:
        return None
    if dest == "empty":
        return "xhr" if requested_with == "xmlhttprequest" else "fetch"
    return _SEC_FETCH_DEST_TO_RESOURCE_TYPE.get(dest)
