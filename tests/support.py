"""Shared end-to-end test helpers (not collected by pytest; imported as ``tests.support``).

* an in-process ``requests`` transport (:class:`MockAdapter`, :func:`run_generated`) that runs a
  generated script against scripted fake sites,
* a real local web site (:class:`SiteServer`, :func:`start_server`) that hands out fresh tokens on
  every session and rejects replayed ones,
* :func:`capture`, which drives that site with ``requests`` and records it as a reqrec ``Recording``.

One section per former module of ``tests/e2e/`` (headed ``# ===== former tests/e2e/<name>.py ... =====``).
"""

from __future__ import annotations

import contextlib
import html
import http.client
import io
import json
import os
import re
import secrets
import socketserver
import struct
import sys
import threading
import time
import types
import zlib
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping, Optional, Sequence, Union
from unittest import mock
from urllib.parse import parse_qs, parse_qsl, urljoin, urlsplit

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest
from urllib3._collections import HTTPHeaderDict
from urllib3.response import HTTPResponse

import reqrec as util
from reqrec import Flow, RecordedRequest, RecordedResponse, Recording

__all__ = [
    # MockAdapter (in-process transport)
    "Call", "Rule", "MockAdapter", "install", "run_generated",
    # the e2e web site
    "USERNAME", "PASSWORD", "ITEMS_PER_PAGE", "LAST_PAGE", "TOKEN_KINDS", "Site", "SiteHandler", "SiteServer",
    "start_server", "stop_server", "restart_server", "make_png", "make_ico", "LOGO_PNG", "FAVICON_ICO", "APP_CSS",
    # capture
    "BROWSER_HEADERS", "capture", "default_scenario", "flow_from_response", "make_session",
]


# ===== former tests/e2e/mock_adapter.py: MockAdapter, an in-process transport for generated scripts =====
# A ``requests`` transport adapter that serves scripted responses in-process.
#
# Generated scripts talk to real hosts (``https://example.com/...``).  Mounting :class:`MockAdapter`
# on a ``requests.Session`` lets a test execute such a script without any network: every request
# is matched against a routing table of :class:`Rule` objects and answered with a canned (or
# computed) response, and every request the adapter saw is recorded in ``adapter.calls``.
#
# The adapter subclasses :class:`requests.adapters.HTTPAdapter` and reuses its ``build_response``
# so the resulting ``requests.Response`` behaves exactly like a real one: redirects are followed by
# ``Session``, multiple ``Set-Cookie`` headers end up in the session cookie jar, ``resp.json()`` /
# ``resp.text`` / ``resp.history`` all work.
#
# Typical use::
#
#     adapter = MockAdapter([
#         Rule("https://example.com/login", method="GET", body="<html>...</html>",
#              headers=[("Set-Cookie", "sid=abc; Path=/")], content_type="text/html"),
#         Rule(re.compile(r"https://example.com/api/items"), handler=my_handler),
#     ])
#     out = run_generated(script_source, adapter, env={"REQREC_PASSWORD": "x"})
#     assert adapter.calls[1].form["_token"] == "..."

HeaderPairs = Sequence[tuple[str, str]]
HeadersLike = Union[HeaderPairs, Mapping[str, str], None]
BodyLike = Union[bytes, str, dict, list, None]
Handler = Callable[[PreparedRequest], tuple]


# --------------------------------------------------------------------------- recorded calls

@dataclass
class Call:
    """One request the adapter received (a snapshot of the ``PreparedRequest``)."""

    method: str
    url: str
    headers: dict[str, str]
    body: Optional[bytes]
    request: PreparedRequest = field(repr=False)

    # -- convenience accessors ------------------------------------------------------------
    @property
    def path(self) -> str:
        return urlsplit(self.url).path

    @property
    def url_without_query(self) -> str:
        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.netloc}{parts.path}"

    @property
    def query(self) -> list[tuple[str, str]]:
        return parse_qsl(urlsplit(self.url).query, keep_blank_values=True)

    @property
    def query_dict(self) -> dict[str, str]:
        return dict(self.query)

    @property
    def form_pairs(self) -> list[tuple[str, str]]:
        """Body parsed as ``application/x-www-form-urlencoded`` pairs."""
        if not self.body:
            return []
        return parse_qsl(self.body.decode("utf-8", "replace"), keep_blank_values=True)

    @property
    def form(self) -> dict[str, str]:
        return dict(self.form_pairs)

    @property
    def text(self) -> str:
        return (self.body or b"").decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads((self.body or b"").decode("utf-8"))

    def header(self, name: str) -> Optional[str]:
        lname = name.lower()
        for k, v in self.headers.items():
            if k.lower() == lname:
                return v
        return None

    @property
    def cookies(self) -> dict[str, str]:
        """Cookies sent with the request, parsed from the ``Cookie`` header."""
        raw = self.header("Cookie") or ""
        out: dict[str, str] = {}
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            name, _, value = part.partition("=")
            out[name.strip()] = value.strip()
        return out


# --------------------------------------------------------------------------- routing rules

@dataclass
class Rule:
    """One entry of the routing table.

    * ``url`` - exact URL string or a compiled regex (matched with ``.search`` against the full
      request URL).  A plain string without a query string also matches requests to the same URL
      *with* a query string (so ``"https://h/api"`` serves ``https://h/api?page=2``).
    * ``method`` - ``None`` matches any method.
    * ``status`` / ``headers`` / ``body`` - the canned response.  ``body`` may be ``bytes``,
      ``str`` (UTF-8) or a ``dict``/``list`` (JSON-encoded, ``Content-Type: application/json``).
    * ``handler`` - ``callable(PreparedRequest) -> (status, headers, body)`` computed per request;
      when set it overrides ``status``/``headers``/``body``.
    * ``content_type`` - convenience: adds a ``Content-Type`` header when none is given.
    """

    url: Union[str, re.Pattern]
    method: Optional[str] = None
    status: int = 200
    headers: HeadersLike = None
    body: BodyLike = b""
    handler: Optional[Handler] = None
    content_type: Optional[str] = None

    @classmethod
    def coerce(cls, obj: Union["Rule", Mapping[str, Any]]) -> "Rule":
        if isinstance(obj, Rule):
            return obj
        d = dict(obj)
        if "body" in d and callable(d["body"]) and d.get("handler") is None:
            d["handler"] = d.pop("body")
        return cls(**d)

    def matches(self, request: PreparedRequest) -> bool:
        if self.method is not None and self.method.upper() != (request.method or "").upper():
            return False
        url = request.url if isinstance(request.url, str) else (request.url or b"").decode("utf-8", "replace")
        if isinstance(self.url, re.Pattern):
            return self.url.search(url) is not None
        if url == self.url:
            return True
        if "?" not in self.url and url.split("?", 1)[0] == self.url:
            return True
        return False

    def respond(self, request: PreparedRequest) -> tuple[int, list[tuple[str, str]], bytes]:
        """Resolve the rule to ``(status, header_pairs, body_bytes)`` for this request."""
        status, headers, body = self.status, self.headers, self.body
        if self.handler is not None:
            result = self.handler(request)
            if isinstance(result, requests.Response):  # pragma: no cover - rarely useful
                raise TypeError("handler must return (status, headers, body), not a Response")
            status, headers, body = _unpack_handler_result(result)
        pairs = _header_pairs(headers)
        body_bytes, implied_ct = _encode_body(body)
        if not any(k.lower() == "content-type" for k, _ in pairs):
            ct = self.content_type or implied_ct
            if ct:
                pairs.append(("Content-Type", ct))
        return int(status), pairs, body_bytes


def _unpack_handler_result(result: Any) -> tuple[int, HeadersLike, BodyLike]:
    if isinstance(result, tuple):
        if len(result) == 3:
            return result  # type: ignore[return-value]
        if len(result) == 2:
            return result[0], None, result[1]
        if len(result) == 1:
            return 200, None, result[0]
        raise TypeError(f"handler returned a tuple of length {len(result)}; expected (status, headers, body)")
    return 200, None, result


def _header_pairs(headers: HeadersLike) -> list[tuple[str, str]]:
    if not headers:
        return []
    if isinstance(headers, Mapping):
        return [(str(k), str(v)) for k, v in headers.items()]
    return [(str(k), str(v)) for k, v in headers]


def _encode_body(body: BodyLike) -> tuple[bytes, Optional[str]]:
    """Body as bytes plus the Content-Type implied by its Python type (None when unknown)."""
    if body is None:
        return b"", None
    if isinstance(body, bytes):
        return body, None
    if isinstance(body, str):
        return body.encode("utf-8"), "text/plain; charset=utf-8"
    if isinstance(body, (dict, list)):
        return json.dumps(body, ensure_ascii=False).encode("utf-8"), "application/json"
    raise TypeError(f"unsupported body type {type(body).__name__}")


# --------------------------------------------------------------------------- the adapter

class _FakeHTTPLibResponse:
    """The minimal ``http.client.HTTPResponse`` surface urllib3 / requests touch.

    ``requests.cookies.extract_cookies_to_jar`` reads ``raw._original_response.msg`` (an
    ``HTTPMessage``), urllib3 calls ``isclosed()`` / ``close()`` and reads ``_method``.
    """

    def __init__(self, msg: http.client.HTTPMessage, method: str) -> None:
        self.msg = msg
        self._method = method
        self._closed = False

    def isclosed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True


class MockAdapter(HTTPAdapter):
    """Serve scripted responses; record every request in ``calls``.

    Unmatched requests get a ``404`` whose body names the URL (and are listed in ``unmatched``)
    so a generated script fails loudly through ``raise_for_status()`` instead of hanging.
    """

    def __init__(self, rules: Sequence[Union[Rule, Mapping[str, Any]]] = ()) -> None:
        super().__init__()
        self.rules: list[Rule] = [Rule.coerce(r) for r in rules]
        self.calls: list[Call] = []
        self.unmatched: list[Call] = []

    # -- routing table ---------------------------------------------------------------------
    def add(self, url: Union[str, re.Pattern], method: Optional[str] = None, status: int = 200,
            headers: HeadersLike = None, body: BodyLike = b"", handler: Optional[Handler] = None,
            content_type: Optional[str] = None) -> Rule:
        rule = Rule(url=url, method=method, status=status, headers=headers, body=body,
                    handler=handler, content_type=content_type)
        self.rules.append(rule)
        return rule

    def find_rule(self, request: PreparedRequest) -> Optional[Rule]:
        for rule in self.rules:
            if rule.matches(request):
                return rule
        return None

    # -- transport ---------------------------------------------------------------------------
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):  # noqa: D401
        call = Call(
            method=(request.method or "").upper(),
            url=request.url if isinstance(request.url, str) else request.url.decode("utf-8", "replace"),
            headers={k: v for k, v in request.headers.items()},
            body=_request_body_bytes(request.body),
            request=request,
        )
        self.calls.append(call)
        rule = self.find_rule(request)
        if rule is None:
            self.unmatched.append(call)
            status, pairs, body = 404, [("Content-Type", "text/plain; charset=utf-8")], (
                f"mock_adapter: no rule matches {call.method} {call.url}".encode("utf-8"))
        else:
            status, pairs, body = rule.respond(request)
        raw = _build_raw_response(request, status, pairs, body)
        return self.build_response(request, raw)

    def close(self) -> None:  # nothing to release
        pass

    # -- helpers for assertions --------------------------------------------------------------
    def reset(self) -> None:
        self.calls.clear()
        self.unmatched.clear()


def _request_body_bytes(body: Any) -> Optional[bytes]:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    if hasattr(body, "read"):
        data = body.read()
        return data if isinstance(data, bytes) else str(data).encode("utf-8")
    try:  # generator / iterable of chunks (streaming uploads)
        return b"".join(chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8") for chunk in body)
    except TypeError:
        return str(body).encode("utf-8")


def _build_raw_response(request: PreparedRequest, status: int, pairs: list[tuple[str, str]], body: bytes) -> HTTPResponse:
    """urllib3 ``HTTPResponse`` carrying the headers twice: as ``HTTPHeaderDict`` for urllib3 /
    requests and as an ``http.client.HTTPMessage`` for ``http.cookiejar`` (multiple
    ``Set-Cookie`` headers survive in both)."""
    headers = HTTPHeaderDict()
    msg = http.client.HTTPMessage()
    for k, v in pairs:
        headers.add(k, v)
        msg.add_header(k, v)
    if "content-length" not in headers and (request.method or "").upper() != "HEAD":
        headers["Content-Length"] = str(len(body))
        msg.add_header("Content-Length", str(len(body)))
    try:
        reason = HTTPStatus(status).phrase
    except ValueError:
        reason = ""
    return HTTPResponse(
        body=io.BytesIO(body),
        headers=headers,
        status=status,
        version=11,
        version_string="HTTP/1.1",
        reason=reason,
        preload_content=False,
        decode_content=True,
        original_response=_FakeHTTPLibResponse(msg, (request.method or "GET").upper()),  # type: ignore[arg-type]
        enforce_content_length=False,
        request_method=request.method,
        request_url=request.url if isinstance(request.url, str) else None,
    )


# --------------------------------------------------------------------------- public helpers

def install(session: requests.Session, adapter: MockAdapter) -> requests.Session:
    """Mount ``adapter`` for both schemes so every request of ``session`` is served by it."""
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def run_generated(script_source: str, adapter: MockAdapter, env: Optional[Mapping[str, str]] = None,
                  *, patch_sleep: bool = True, filename: str = "<generated>",
                  namespace: Optional[dict] = None) -> str:
    """Execute a generated script against ``adapter`` and return what it printed to stdout.

    The source is compiled and executed in a fresh module namespace (``__name__`` is *not*
    ``"__main__"``), then its ``main()`` is called.  ``requests.Session`` is patched for the
    duration so every session the script creates has ``adapter`` mounted; ``time.sleep`` is
    replaced by a no-op unless ``patch_sleep`` is False; ``env`` entries are added to
    ``os.environ`` temporarily.  Pass a dict as ``namespace`` to inspect the module globals
    afterwards.  Exceptions raised by the script propagate.
    """
    code = compile(script_source, filename, "exec")
    ns: dict[str, Any] = namespace if namespace is not None else {}
    module = types.ModuleType("reqrec_generated_script")
    module.__dict__.update(ns)
    module.__file__ = filename
    real_session_cls = requests.Session

    def session_factory(*args: Any, **kwargs: Any) -> requests.Session:
        return install(real_session_cls(*args, **kwargs), adapter)

    stdout = io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(requests, "Session", session_factory))
        stack.enter_context(mock.patch.dict(os.environ, dict(env or {})))
        if patch_sleep:
            stack.enter_context(mock.patch.object(time, "sleep", lambda *_a, **_k: None))
        stack.enter_context(contextlib.redirect_stdout(stdout))
        exec(code, module.__dict__)
        main = module.__dict__.get("main")
        if not callable(main):
            raise RuntimeError("generated script defines no main()")
        main()
    if namespace is not None:
        namespace.update(module.__dict__)
    return stdout.getvalue()


# ===== former tests/e2e/server.py: the local e2e web site (fresh tokens per session) =====
# A small but realistic local web site for reqrec's end-to-end tests (stdlib only).
#
# The site imitates the shape of a typical session-cookie + CSRF-token web application so that a
# script generated by reqrec has to *re-derive* every dynamic value instead of replaying literals:
#
# ================  ==========================================================================
# route             behaviour
# ================  ==========================================================================
# GET  /login       HTML login form.  Creates a session (``Set-Cookie: sid=...``) and a hidden
#                   one-time ``_token`` input bound to that session.  Also sets ``lang=ja`` so
#                   responses with *several* ``Set-Cookie`` headers are exercised.
# POST /login       form ``_token`` / ``username`` / ``password``.  Requires the ``sid`` cookie and
#                   a matching ``_token``; on success rotates the session id (new ``Set-Cookie``),
#                   marks the session logged in and answers ``302 Location: /dashboard``.
# GET  /dashboard   Logged-in only.  HTML with ``<meta name="csrf-token">``, an inline
#                   ``window.API_TOKEN = "..."`` script and ``<a id="export-link" href="/export?sig=...">``.
# GET  /api/items   ``?page=N``; requires ``X-CSRF-Token`` **and** ``Authorization: Bearer`` matching
#                   the session.  JSON ``{"page", "items", "next"}`` (3 pages of 3 items).
# POST /api/items   JSON ``{"name", "csrf"}`` with the same auth headers -> ``201`` JSON item.
# GET  /export      ``?sig=S`` must equal the session's export signature -> ``text/csv``.
# GET  /static/*    ``app.css`` / ``logo.png`` (valid tiny PNG); ``/favicon.ico``; pure noise.
# GET  /ping        ``text/plain`` ``ok`` (health check).
# ================  ==========================================================================
#
# Every token (``sid``, ``_token``, csrf, API bearer token, export signature) is random per
# **server start and per session**.  A recorded literal therefore never works against a restarted
# server - which is exactly what the e2e test relies on to prove the generated script extracts the
# values afresh.
#
# Every request the server receives is appended to ``Site.log`` (see ``Site.record`` for the entry
# layout) so tests can assert precisely what a generated script sent.

#: Credentials accepted by ``POST /login``.
USERNAME = "alice"
PASSWORD = "Secr3t!"

ITEMS_PER_PAGE = 3
LAST_PAGE = 3
#: Largest request body the server reads (anything beyond is discarded) - keeps a misbehaving
#: client from exhausting memory.
MAX_BODY = 4 * 1024 * 1024

TOKEN_KINDS = ("sid", "login_token", "csrf", "api_token", "export_sig")


# --------------------------------------------------------------------------- static assets

def _png_chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)


def make_png(width: int = 1, height: int = 1, rgb: tuple[int, int, int] = (0xE6, 0x3A, 0x2E)) -> bytes:
    """A valid, minimal 8-bit RGB PNG filled with one colour."""
    raw = b"".join(b"\x00" + bytes(rgb) * width for _ in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(raw, 9))
        + _png_chunk(b"IEND", b"")
    )


def make_ico(png: bytes) -> bytes:
    """A valid ``.ico`` container holding ``png`` as its single image."""
    header = struct.pack("<HHH", 0, 1, 1)  # reserved, type=icon, count
    entry = struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, len(png), 6 + 16)
    return header + entry + png


LOGO_PNG = make_png()
FAVICON_ICO = make_ico(LOGO_PNG)
APP_CSS = "body { font-family: sans-serif; margin: 2rem; }\n#items li { padding: .25rem 0; }\n"


# --------------------------------------------------------------------------- site state

class Site:
    """All server-side state: sessions, their tokens, created items and the request log.

    Thread-safe (the HTTP server handles each connection in its own thread).

    * ``sessions`` - ``sid -> session dict`` (``login_token``, ``logged_in``, ``csrf``,
      ``api_token``, ``export_sig`` ...).  A successful login *moves* the dict to a new ``sid``.
    * ``issued`` - every token value ever handed out, by kind (``TOKEN_KINDS``); lets tests check
      that a request carried a token *this* server instance generated.
    * ``items`` - items created through ``POST /api/items``.
    * ``log`` - one dict per request, in arrival order (see ``record``).
    """

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.sessions: dict[str, dict[str, Any]] = {}
        self.items: list[dict[str, Any]] = []
        self.log: list[dict[str, Any]] = []
        self.issued: dict[str, set[str]] = {kind: set() for kind in TOKEN_KINDS}
        self.boot_id = secrets.token_hex(4)

    # -- tokens -----------------------------------------------------------------------------
    def _fresh(self, kind: str) -> str:
        token = secrets.token_hex(16)
        self.issued[kind].add(token)
        return token

    def issued_tokens(self, kind: str) -> set[str]:
        """Copy of every value of ``kind`` this server instance has issued so far."""
        with self.lock:
            return set(self.issued[kind])

    # -- sessions ---------------------------------------------------------------------------
    def create_session(self) -> tuple[str, dict[str, Any]]:
        """New anonymous session with a one-time login token; returns ``(sid, session)``."""
        with self.lock:
            sid = self._fresh("sid")
            session = {
                "sid": sid,
                "login_token": self._fresh("login_token"),
                "logged_in": False,
                "user": None,
                "csrf": None,
                "api_token": None,
                "export_sig": None,
                "created_at": time.time(),
            }
            self.sessions[sid] = session
            return sid, session

    def get_session(self, sid: Optional[str]) -> Optional[dict[str, Any]]:
        with self.lock:
            return self.sessions.get(sid) if sid else None

    def login(self, sid: Optional[str], token: Optional[str], username: Optional[str],
              password: Optional[str]) -> Optional[str]:
        """Validate a login attempt.  On success rotate the session id, mark the session logged
        in, mint csrf / API / export tokens and return the **new** sid; otherwise return None."""
        with self.lock:
            session = self.sessions.get(sid) if sid else None
            if session is None:
                return None
            expected = session.get("login_token")
            if not expected or not token or not secrets.compare_digest(token, expected):
                return None
            if username != USERNAME or password != PASSWORD:
                return None
            new_sid = self._fresh("sid")
            del self.sessions[sid]
            session.update(
                sid=new_sid,
                login_token=None,  # one-time token: consumed
                logged_in=True,
                user=username,
                csrf=self._fresh("csrf"),
                api_token=self._fresh("api_token"),
                export_sig=self._fresh("export_sig"),
            )
            self.sessions[new_sid] = session
            return new_sid

    # -- items ------------------------------------------------------------------------------
    @staticmethod
    def page_items(page: int) -> list[dict[str, Any]]:
        """The catalogue page ``page`` (1-based): ids ``(page-1)*3+1 ..``, names ``item-<page>-<n>``."""
        base = (page - 1) * ITEMS_PER_PAGE
        return [{"id": base + n, "name": f"item-{page}-{n}"} for n in range(1, ITEMS_PER_PAGE + 1)]

    def add_item(self, name: str) -> dict[str, Any]:
        with self.lock:
            item = {"id": 1000 + len(self.items) + 1, "name": name}
            self.items.append(item)
            return item

    # -- request log ------------------------------------------------------------------------
    def record(self, entry: dict[str, Any]) -> None:
        """Append a request-log entry.  Keys: ``method``, ``path`` (raw request target, query
        included), ``route`` (path only), ``query`` (dict, last value wins), ``headers`` (dict with
        **lower-cased** names), ``cookies`` (dict), ``body`` (bytes), ``form`` (dict or None),
        ``json`` (parsed JSON or None), ``time``."""
        with self.lock:
            self.log.append(entry)

    def requests_for(self, method: Optional[str] = None, route: Optional[str] = None) -> list[dict[str, Any]]:
        """Log entries filtered by HTTP method and/or exact route (path without query)."""
        with self.lock:
            return [
                e for e in self.log
                if (method is None or e["method"] == method.upper()) and (route is None or e["route"] == route)
            ]

    def reset_log(self) -> None:
        with self.lock:
            self.log.clear()


# --------------------------------------------------------------------------- HTML templates

def _login_html(token: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<title>ログイン - reqrec e2e</title>
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<header><img src="/static/logo.png" alt="logo" width="16" height="16"><h1>ログイン</h1></header>
<form method="post" action="/login" id="login-form">
  <input type="hidden" name="_token" value="{html.escape(token)}">
  <label>ユーザー名 <input type="text" name="username" autocomplete="username"></label>
  <label>パスワード <input type="password" name="password" autocomplete="current-password"></label>
  <button type="submit">ログイン</button>
</form>
</body>
</html>
"""


def _dashboard_html(session: dict[str, Any]) -> str:
    items = "\n".join(
        f'  <li data-id="{it["id"]}">{html.escape(it["name"])}</li>' for it in Site.page_items(1)
    )
    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="csrf-token" content="{html.escape(session["csrf"])}">
<title>ホーム - reqrec e2e</title>
<link rel="stylesheet" href="/static/app.css">
<script>window.API_TOKEN = "{session["api_token"]}";</script>
</head>
<body>
<h1>ようこそ、{html.escape(session["user"] or "")} さん</h1>
<nav><a id="export-link" href="/export?sig={session["export_sig"]}">CSV</a> <a href="/logout">ログアウト</a></nav>
<ul id="items">
{items}
</ul>
</body>
</html>
"""


def _error_html(status: int, title: str, detail: str) -> str:
    return (
        f"<!DOCTYPE html><html lang=\"ja\"><head><meta charset=\"utf-8\"><title>{status} {html.escape(title)}</title>"
        f"</head><body><h1>{status} {html.escape(title)}</h1><p>{html.escape(detail)}</p></body></html>\n"
    )


# --------------------------------------------------------------------------- request handler

class SiteHandler(BaseHTTPRequestHandler):
    """Routes requests to the ``Site`` owned by the server (``self.server.site``)."""

    protocol_version = "HTTP/1.1"
    server_version = "reqrec-e2e/0.1"
    sys_version = ""
    timeout = 10  # idle keep-alive connections are dropped so handler threads do not pile up

    # -- plumbing ---------------------------------------------------------------------------
    @property
    def site(self) -> Site:
        return self.server.site  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Silence the default stderr access log (keeps pytest output readable)."""

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_HEAD(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def do_OPTIONS(self) -> None:
        self._dispatch()

    def _read_body(self) -> bytes:
        """Request body (``Content-Length`` or chunked); never more than ``MAX_BODY`` bytes."""
        length = self.headers.get("Content-Length")
        if length is None:
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                return self._read_chunked()
            return b""
        try:
            n = int(length)
        except ValueError:
            return b""
        if n <= 0:
            return b""
        data = self.rfile.read(min(n, MAX_BODY))
        remaining = n - len(data)
        while remaining > 0:  # discard the excess so the connection stays in sync
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        return data

    def _read_chunked(self) -> bytes:
        out = bytearray()
        while True:
            line = self.rfile.readline(1024).strip()
            try:
                size = int(line.split(b";", 1)[0], 16)
            except ValueError:
                break
            if size == 0:
                while True:  # trailers
                    trailer = self.rfile.readline(1024)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                break
            chunk = self.rfile.read(size)
            self.rfile.readline(8)  # CRLF after the chunk
            if len(out) < MAX_BODY:
                out += chunk[: MAX_BODY - len(out)]
        return bytes(out)

    def _cookies(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for raw in self.headers.get_all("Cookie") or []:
            for part in raw.split(";"):
                part = part.strip()
                if not part:
                    continue
                name, _, value = part.partition("=")
                if name.strip():
                    out[name.strip()] = value.strip()
        return out

    def _dispatch(self) -> None:
        parts = urlsplit(self.path)
        route = parts.path or "/"
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        query = dict(query_pairs)
        body = self._read_body()
        headers: dict[str, str] = {}
        for name, value in self.headers.items():
            lname = name.lower()
            headers[lname] = f"{headers[lname]}, {value}" if lname in headers else value
        entry: dict[str, Any] = {
            "method": self.command,
            "path": self.path,
            "route": route,
            "query": query,
            "headers": headers,
            "cookies": self._cookies(),
            "body": body,
            "form": None,
            "json": None,
            "time": time.time(),
        }
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if body and ctype == "application/x-www-form-urlencoded":
            entry["form"] = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
        elif body and (ctype == "application/json" or ctype.endswith("+json")):
            try:
                entry["json"] = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                entry["json"] = None
        self.site.record(entry)

        handler = self._route(route)
        try:
            if handler is None:
                self._send_html(404, _error_html(404, "Not Found", f"{route} はありません"))
            else:
                handler(entry)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as exc:  # pragma: no cover - a bug in the fake site must not hang the client
            self._send_html(500, _error_html(500, "Internal Server Error", repr(exc)))

    def _route(self, route: str) -> Optional[Callable[[dict[str, Any]], None]]:
        table: dict[tuple[str, str], Callable[[dict[str, Any]], None]] = {
            ("GET", "/login"): self._get_login,
            ("POST", "/login"): self._post_login,
            ("GET", "/dashboard"): self._get_dashboard,
            ("GET", "/api/items"): self._get_api_items,
            ("POST", "/api/items"): self._post_api_items,
            ("GET", "/export"): self._get_export,
            ("GET", "/static/app.css"): self._get_css,
            ("GET", "/static/logo.png"): self._get_png,
            ("GET", "/favicon.ico"): self._get_favicon,
            ("GET", "/ping"): self._get_ping,
        }
        handler = table.get((self.command, route))
        if handler is None and self.command == "HEAD":
            handler = table.get(("GET", route))
        if handler is None and any(r == route for (_m, r) in table):
            return self._method_not_allowed
        return handler

    # -- response helpers -------------------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str,
              extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_html(self, status: int, markup: str, extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        self._send(status, markup.encode("utf-8"), "text/html; charset=utf-8", extra_headers)

    def _send_json(self, status: int, obj: Any, extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(status, payload, "application/json; charset=utf-8", extra_headers)

    def _method_not_allowed(self, entry: dict[str, Any]) -> None:
        self._send_html(405, _error_html(405, "Method Not Allowed", f"{self.command} は使えません"))

    def _logged_in_session(self, entry: dict[str, Any]) -> Optional[dict[str, Any]]:
        session = self.site.get_session(entry["cookies"].get("sid"))
        if session is None or not session.get("logged_in"):
            return None
        return session

    def _auth_failure(self, entry: dict[str, Any], session: dict[str, Any]) -> Optional[str]:
        """Reason the API auth headers are wrong, or None when both match the session."""
        csrf = entry["headers"].get("x-csrf-token")
        if not csrf or csrf != session["csrf"]:
            return "X-CSRF-Token が不正です"
        auth = entry["headers"].get("authorization")
        if not auth or auth != f"Bearer {session['api_token']}":
            return "Authorization が不正です"
        return None

    # -- routes -----------------------------------------------------------------------------
    def _get_login(self, entry: dict[str, Any]) -> None:
        sid, session = self.site.create_session()
        self._send_html(
            200,
            _login_html(session["login_token"]),
            (("Set-Cookie", f"sid={sid}; Path=/; HttpOnly"), ("Set-Cookie", "lang=ja; Path=/")),
        )

    def _post_login(self, entry: dict[str, Any]) -> None:
        form = entry["form"] or {}
        new_sid = self.site.login(
            entry["cookies"].get("sid"), form.get("_token"), form.get("username"), form.get("password")
        )
        if new_sid is None:
            self._send_html(403, _error_html(403, "Forbidden", "ログインに失敗しました（トークンまたは認証情報が不正です）"))
            return
        self._send_html(
            302,
            "<!DOCTYPE html><html><body><p>Redirecting...</p></body></html>\n",
            (("Location", "/dashboard"), ("Set-Cookie", f"sid={new_sid}; Path=/; HttpOnly")),
        )

    def _get_dashboard(self, entry: dict[str, Any]) -> None:
        session = self._logged_in_session(entry)
        if session is None:
            self._send_html(403, _error_html(403, "Forbidden", "ログインが必要です"))
            return
        self._send_html(200, _dashboard_html(session))

    def _get_api_items(self, entry: dict[str, Any]) -> None:
        session = self._logged_in_session(entry)
        if session is None:
            self._send_json(401, {"error": "unauthorized", "reason": "ログインが必要です"})
            return
        reason = self._auth_failure(entry, session)
        if reason:
            self._send_json(401, {"error": "unauthorized", "reason": reason})
            return
        try:
            page = int(entry["query"].get("page", "1"))
        except ValueError:
            self._send_json(400, {"error": "bad_request", "reason": "page は整数で指定してください"})
            return
        if page < 1 or page > LAST_PAGE:
            self._send_json(404, {"error": "not_found", "reason": "そのページはありません"})
            return
        self._send_json(200, {
            "page": page,
            "items": Site.page_items(page),
            "next": page + 1 if page < LAST_PAGE else None,
        })

    def _post_api_items(self, entry: dict[str, Any]) -> None:
        session = self._logged_in_session(entry)
        if session is None:
            self._send_json(401, {"error": "unauthorized", "reason": "ログインが必要です"})
            return
        reason = self._auth_failure(entry, session)
        if reason:
            self._send_json(401, {"error": "unauthorized", "reason": reason})
            return
        data = entry["json"]
        if not isinstance(data, dict):
            self._send_json(400, {"error": "bad_request", "reason": "JSON オブジェクトを送ってください"})
            return
        if data.get("csrf") != session["csrf"]:
            self._send_json(403, {"error": "forbidden", "reason": "csrf が不正です"})
            return
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            self._send_json(400, {"error": "bad_request", "reason": "name は必須です"})
            return
        self._send_json(201, self.site.add_item(name.strip()))

    def _get_export(self, entry: dict[str, Any]) -> None:
        session = self._logged_in_session(entry)
        if session is None:
            self._send_html(403, _error_html(403, "Forbidden", "ログインが必要です"))
            return
        sig = entry["query"].get("sig")
        if not sig or sig != session["export_sig"]:
            self._send_html(403, _error_html(403, "Forbidden", "sig が不正です"))
            return
        rows = ["id,name"] + [f"{it['id']},{it['name']}" for it in Site.page_items(1)]
        csv = ("\n".join(rows) + "\n").encode("utf-8")
        self._send(200, csv, "text/csv; charset=utf-8",
                   (("Content-Disposition", 'attachment; filename="items.csv"'),))

    def _get_css(self, entry: dict[str, Any]) -> None:
        self._send(200, APP_CSS.encode("utf-8"), "text/css; charset=utf-8")

    def _get_png(self, entry: dict[str, Any]) -> None:
        self._send(200, LOGO_PNG, "image/png")

    def _get_favicon(self, entry: dict[str, Any]) -> None:
        self._send(200, FAVICON_ICO, "image/x-icon")

    def _get_ping(self, entry: dict[str, Any]) -> None:
        self._send(200, b"ok", "text/plain; charset=utf-8")


# --------------------------------------------------------------------------- server lifecycle

class SiteServer(ThreadingHTTPServer):
    """``ThreadingHTTPServer`` that owns a ``Site`` and can be re-bound to the same port quickly."""

    allow_reuse_address = True  # re-bind the same port right after a shutdown (TIME_WAIT sockets)
    daemon_threads = True

    def __init__(self, address: tuple[str, int], site: Optional[Site] = None) -> None:
        self.site = site or Site()
        self.thread: Optional[threading.Thread] = None
        super().__init__(address, SiteHandler)

    def server_bind(self) -> None:
        """Bind without the reverse-DNS lookup ``HTTPServer.server_bind`` performs (it can stall)."""
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port

    @property
    def base_url(self) -> str:
        host, port = self.server_address[:2]
        if ":" in host:  # IPv6 literal
            host = f"[{host}]"
        return f"http://{host}:{port}"


def start_server(host: str = "127.0.0.1", port: int = 0, site: Optional[Site] = None) -> tuple[SiteServer, str]:
    """Start a site in a daemon thread.  ``port=0`` picks a free port; an explicit port re-binds
    (``allow_reuse_address``) so a *fresh* site can replace a stopped one at the same URL.
    Returns ``(server, base_url)``; the ``Site`` is ``server.site``."""
    server = SiteServer((host, port), site)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05},
        name=f"reqrec-e2e-site-{server.server_port}", daemon=True,
    )
    server.thread = thread
    thread.start()
    return server, server.base_url


def stop_server(server: SiteServer) -> None:
    """Stop serving and close the listening socket (idempotent)."""
    try:
        server.shutdown()
    except Exception:  # pragma: no cover - already stopped
        pass
    server.server_close()
    thread = getattr(server, "thread", None)
    if thread is not None and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=5)


def restart_server(server: SiteServer, attempts: int = 50, delay: float = 0.1) -> tuple[SiteServer, str]:
    """Stop ``server`` and start a brand-new ``Site`` on the **same** host and port.

    Recorded URLs embed the port, so the replacement must listen at the same address while
    every token is regenerated.  Binding is retried briefly in case the OS has not released the
    port yet."""
    host, port = server.server_address[:2]
    stop_server(server)
    last_error: Optional[BaseException] = None
    for _ in range(max(1, attempts)):
        try:
            return start_server(host, port)
        except OSError as exc:  # EADDRINUSE while the kernel finishes closing the old socket
            last_error = exc
            time.sleep(delay)
    raise RuntimeError(f"could not re-bind {host}:{port}: {last_error!r}")


# ===== former tests/e2e/capture.py: record a requests session as a Recording =====
# Record a ``requests`` session as a reqrec ``Recording`` (the e2e stand-in for mitmproxy / HAR).
#
# ``capture`` installs a ``"response"`` hook on a ``requests.Session``; every ``Response`` the
# session produces - including the intermediate hops in ``resp.history`` - is converted into a
# ``reqrec.core.Flow`` with ``flow_from_response``:
#
# * request: method, URL, the headers ``requests`` actually sent (``resp.request.headers``, so the
#   ``Cookie`` header the cookie jar added is included) and the body as bytes;
# * response: status, headers taken from ``resp.raw.headers`` (a urllib3 ``HTTPHeaderDict`` whose
#   ``items()`` yields repeated ``Set-Cookie`` headers one by one - ``resp.headers`` would merge
#   them), body ``resp.content``;
# * ``started_at`` from the wall clock at hook time (minus ``resp.elapsed`` where available), kept
#   strictly increasing so flow order is unambiguous; ``resource_type`` / ``page_ref`` are None.
#
# Flow ids are ``f0001, f0002, ...`` in order.  Redirect hops are de-duplicated by ``id()`` because
# recent ``requests`` versions dispatch the hook for every hop *and* list the hops in ``history``.
#
# ``default_scenario`` drives the e2e site (the server section above) the way a browser user would:
# login page (+ static noise), form login with the hidden ``_token``, dashboard, three JSON pages,
# one JSON POST and a CSV export.

#: Headers a real browser sends on every request; they become ``BASE_HEADERS`` in generated code.
BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/129.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ja,en;q=0.8",
}


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


# ===== smoke test of the MockAdapter section (former tests/e2e/mock_adapter.py __main__) =====

if __name__ == "__main__":  # pragma: no cover - tiny smoke test
    _ad = MockAdapter([Rule("https://example.test/", body="ok", headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])])
    _s = install(requests.Session(), _ad)
    _r = _s.get("https://example.test/")
    print(_r.status_code, _r.text, dict(_s.cookies), file=sys.stderr)
