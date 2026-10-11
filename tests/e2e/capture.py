"""Record a ``requests`` session as a reqrec ``Recording`` (the e2e stand-in for mitmproxy / HAR).

``capture`` installs a ``"response"`` hook on a ``requests.Session``; every ``Response`` the
session produces - including the intermediate hops in ``resp.history`` - is converted into a
``reqrec.model.Flow`` with ``flow_from_response``:

* request: method, URL, the headers ``requests`` actually sent (``resp.request.headers``, so the
  ``Cookie`` header the cookie jar added is included) and the body as bytes;
* response: status, headers taken from ``resp.raw.headers`` (a urllib3 ``HTTPHeaderDict`` whose
  ``items()`` yields repeated ``Set-Cookie`` headers one by one - ``resp.headers`` would merge
  them), body ``resp.content``;
* ``started_at`` from the wall clock at hook time (minus ``resp.elapsed`` where available), kept
  strictly increasing so flow order is unambiguous; ``resource_type`` / ``page_ref`` are None.

Flow ids are ``f0001, f0002, ...`` in order.  Redirect hops are de-duplicated by ``id()`` because
recent ``requests`` versions dispatch the hook for every hop *and* list the hops in ``history``.

``default_scenario`` drives the e2e site (``tests/e2e/server.py``) the way a browser user would:
login page (+ static noise), form login with the hidden ``_token``, dashboard, three JSON pages,
one JSON POST and a CSV export.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from reqrec import util
from reqrec.model import Flow, RecordedRequest, RecordedResponse, Recording

#: Headers a real browser sends on every request; they become ``BASE_HEADERS`` in generated code.
BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/129.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ja,en;q=0.8",
}

#: Credentials used by ``default_scenario`` (must match ``tests/e2e/server.py``).
USERNAME = "alice"
PASSWORD = "Secr3t!"

_API_TOKEN_RE = re.compile(r'window\.API_TOKEN\s*=\s*"([^"]+)"')

Scenario = Callable[..., Any]


# --------------------------------------------------------------------------- Response -> Flow

def _header_value(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


def _request_headers(prepared: requests.PreparedRequest) -> list[tuple[str, str]]:
    headers = getattr(prepared, "headers", None) or {}
    try:
        return [(str(k), _header_value(v)) for k, v in headers.items()]
    except Exception:  # pragma: no cover - defensive
        return []


def _request_body(prepared: requests.PreparedRequest) -> Optional[bytes]:
    """``PreparedRequest.body`` (str / bytes / file / iterable) as bytes, None when there is none."""
    body = getattr(prepared, "body", None)
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    try:
        if hasattr(body, "read"):
            data = body.read()
            return data.encode("utf-8") if isinstance(data, str) else bytes(data)
        chunks = [c.encode("utf-8") if isinstance(c, str) else bytes(c) for c in body]
        return b"".join(chunks)
    except Exception:
        return None


def _response_headers(resp: requests.Response) -> list[tuple[str, str]]:
    """Header pairs with duplicates (``Set-Cookie``) preserved: prefer the urllib3 header dict."""
    raw = getattr(resp, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "items"):
        try:
            return [(str(k), _header_value(v)) for k, v in raw_headers.items()]
        except Exception:  # pragma: no cover - odd transport adapters
            pass
    try:
        return [(str(k), _header_value(v)) for k, v in resp.headers.items()]
    except Exception:  # pragma: no cover
        return []


def _response_body(resp: requests.Response) -> Optional[bytes]:
    try:
        content = resp.content
    except Exception:  # stream already consumed, connection error while reading, ...
        return None
    if content is None:
        return None
    return bytes(content)


def flow_from_response(resp: requests.Response, flow_id: str, started_at: Optional[float] = None) -> Flow:
    """Convert one ``requests.Response`` (and the request that produced it) into a ``Flow``."""
    prepared = resp.request
    method = (getattr(prepared, "method", None) or "GET").upper()
    url = getattr(prepared, "url", None) or resp.url or ""
    request = RecordedRequest(
        method=method,
        url=url,
        headers=_request_headers(prepared) if prepared is not None else [],
        body=_request_body(prepared) if prepared is not None else None,
    )
    response = RecordedResponse(
        status=int(resp.status_code or 0),
        headers=_response_headers(resp),
        body=_response_body(resp),
    )
    return Flow(
        id=flow_id,
        request=request,
        response=response,
        started_at=time.time() if started_at is None else started_at,
        page_ref=None,
        resource_type=None,
    )


# --------------------------------------------------------------------------- capture

class _Capturer:
    """The hook state: flows in order, plus the ``Response`` objects seen (kept alive so their
    ``id()`` values stay unique for the duration of the capture)."""

    def __init__(self) -> None:
        self.flows: list[Flow] = []
        self._seen: set[int] = set()
        self._responses: list[requests.Response] = []
        self._last_ts = 0.0
        self._lock = threading.Lock()

    def hook(self, resp: requests.Response, **kwargs: Any) -> requests.Response:
        # Older requests versions only call the hook for the final response, so walk history too.
        for hop in list(getattr(resp, "history", None) or []) + [resp]:
            self._add(hop)
        return resp

    def _add(self, resp: requests.Response) -> None:
        with self._lock:
            if id(resp) in self._seen:
                return
            self._seen.add(id(resp))
            self._responses.append(resp)
            now = time.time()
            elapsed = getattr(resp, "elapsed", None)
            started = now - elapsed.total_seconds() if elapsed is not None else now
            if started <= self._last_ts:  # keep the order strictly chronological
                started = self._last_ts + 1e-6
            self._last_ts = started
            flow_id = f"f{len(self.flows) + 1:04d}"
            self.flows.append(flow_from_response(resp, flow_id, started_at=started))


def make_session() -> requests.Session:
    """A ``requests.Session`` with browser-like default headers."""
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)
    return session


def capture(fn: Scenario, session: Optional[requests.Session] = None,
            base_url: Optional[str] = None) -> Recording:
    """Run ``fn`` against ``session`` and return everything it did as a ``Recording``.

    ``fn`` is called as ``fn(session, base_url)`` when ``base_url`` is given, else ``fn(session)``.
    A fresh browser-like session (``make_session``) is used when ``session`` is None; a caller's
    session gets the browser headers only where it has none, and the hook is removed afterwards.
    """
    own_session = session is None
    if session is None:
        session = make_session()
    else:
        for name, value in BROWSER_HEADERS.items():
            session.headers.setdefault(name, value)
    capturer = _Capturer()
    session.hooks.setdefault("response", [])
    if not isinstance(session.hooks["response"], list):
        session.hooks["response"] = [session.hooks["response"]]
    session.hooks["response"].append(capturer.hook)
    try:
        if base_url is None:
            fn(session)
        else:
            fn(session, base_url)
    finally:
        try:
            session.hooks["response"].remove(capturer.hook)
        except ValueError:  # pragma: no cover
            pass
        if own_session:
            session.close()
    meta = {"source": "e2e-capture", "captured_at": util.now_iso(), "scenario": getattr(fn, "__name__", repr(fn))}
    if base_url:
        meta["base_url"] = base_url
    return Recording(flows=capturer.flows, meta=meta)


# --------------------------------------------------------------------------- the scenario

def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(f"e2e site misbehaved: {message}")


def default_scenario(session: requests.Session, base_url: str) -> dict[str, str]:
    """Browse the e2e site like a user: login (with the page's hidden token), dashboard, 3 API
    pages, one JSON POST and the CSV export - plus the static noise a browser would fetch.

    Returns the dynamic values it parsed (``login_token``, ``csrf``, ``api_token``,
    ``export_sig``, ``sid``) so tests can prove a later server rejects them.
    """
    base_url = base_url.rstrip("/")

    # 1. login page + static noise
    login_page = session.get(f"{base_url}/login", timeout=10)
    _require(login_page.status_code == 200, f"GET /login -> {login_page.status_code}")
    noise_headers = {"Referer": f"{base_url}/login"}
    session.get(f"{base_url}/static/app.css", headers={**noise_headers, "Accept": "text/css,*/*;q=0.1"}, timeout=10)
    session.get(f"{base_url}/static/logo.png", headers={**noise_headers, "Accept": "image/avif,image/webp,*/*"}, timeout=10)
    session.get(f"{base_url}/favicon.ico", headers={**noise_headers, "Accept": "image/avif,image/webp,*/*"}, timeout=10)

    soup = BeautifulSoup(login_page.text, "html.parser")
    token_input = soup.find("input", {"name": "_token"})
    _require(token_input is not None and token_input.get("value"), "login page has no hidden _token")
    login_token = str(token_input["value"])

    # 2. form login; requests follows the 302 so resp.history holds the redirect hop
    login = session.post(
        f"{base_url}/login",
        data={"_token": login_token, "username": USERNAME, "password": PASSWORD},
        headers={"Referer": f"{base_url}/login", "Origin": base_url},
        allow_redirects=True,
        timeout=10,
    )
    _require(login.status_code == 200 and login.history and login.history[0].status_code == 302,
             f"POST /login -> {login.status_code} (history {[h.status_code for h in login.history]})")

    # 3. dashboard
    dashboard = session.get(f"{base_url}/dashboard", timeout=10)
    _require(dashboard.status_code == 200, f"GET /dashboard -> {dashboard.status_code}")
    soup = BeautifulSoup(dashboard.text, "html.parser")
    meta = soup.find("meta", {"name": "csrf-token"})
    _require(meta is not None and meta.get("content"), "dashboard has no csrf-token meta")
    csrf = str(meta["content"])
    m = _API_TOKEN_RE.search(dashboard.text)
    _require(m is not None, "dashboard has no window.API_TOKEN")
    api_token = m.group(1)
    link = soup.select_one("#export-link")
    _require(link is not None and link.get("href"), "dashboard has no #export-link")
    export_href = str(link["href"])
    export_sig = parse_qs(urlsplit(export_href).query).get("sig", [""])[0]
    _require(bool(export_sig), f"export link has no sig: {export_href}")

    # 4. JSON API: three pages, then create an item
    api_headers = {
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "X-CSRF-Token": csrf,
        "Authorization": f"Bearer {api_token}",
        "Referer": f"{base_url}/dashboard",
    }
    for page in (1, 2, 3):
        resp = session.get(f"{base_url}/api/items", params={"page": page}, headers=api_headers, timeout=10)
        _require(resp.status_code == 200, f"GET /api/items?page={page} -> {resp.status_code} {resp.text[:200]}")
        _require(resp.json().get("page") == page, "API returned the wrong page")
    created = session.post(
        f"{base_url}/api/items",
        json={"name": "new-item", "csrf": csrf},
        headers={**api_headers, "Origin": base_url},
        timeout=10,
    )
    _require(created.status_code == 201, f"POST /api/items -> {created.status_code} {created.text[:200]}")

    # 5. CSV export via the signed link
    export = session.get(urljoin(f"{base_url}/dashboard", export_href),
                         headers={"Referer": f"{base_url}/dashboard"}, timeout=10)
    _require(export.status_code == 200, f"GET /export -> {export.status_code}")

    return {
        "login_token": login_token,
        "csrf": csrf,
        "api_token": api_token,
        "export_sig": export_sig,
        "sid": session.cookies.get("sid", ""),
    }


__all__ = [
    "BROWSER_HEADERS", "USERNAME", "PASSWORD",
    "capture", "default_scenario", "flow_from_response", "make_session",
]
