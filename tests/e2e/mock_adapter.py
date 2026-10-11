"""A ``requests`` transport adapter that serves scripted responses in-process.

Generated scripts talk to real hosts (``https://example.com/...``).  Mounting :class:`MockAdapter`
on a ``requests.Session`` lets a test execute such a script without any network: every request
is matched against a routing table of :class:`Rule` objects and answered with a canned (or
computed) response, and every request the adapter saw is recorded in ``adapter.calls``.

The adapter subclasses :class:`requests.adapters.HTTPAdapter` and reuses its ``build_response``
so the resulting ``requests.Response`` behaves exactly like a real one: redirects are followed by
``Session``, multiple ``Set-Cookie`` headers end up in the session cookie jar, ``resp.json()`` /
``resp.text`` / ``resp.history`` all work.

Typical use::

    adapter = MockAdapter([
        Rule("https://example.com/login", method="GET", body="<html>...</html>",
             headers=[("Set-Cookie", "sid=abc; Path=/")], content_type="text/html"),
        Rule(re.compile(r"https://example.com/api/items"), handler=my_handler),
    ])
    out = run_generated(script_source, adapter, env={"REQREC_PASSWORD": "x"})
    assert adapter.calls[1].form["_token"] == "..."
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import re
import sys
import time
import types
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any, Callable, Mapping, Optional, Sequence, Union
from unittest import mock
from urllib.parse import parse_qsl, urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest
from urllib3._collections import HTTPHeaderDict
from urllib3.response import HTTPResponse

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
    def calls_to(self, path_or_url: str) -> list[Call]:
        """Calls whose URL (or path) equals the argument, ignoring the query string."""
        return [c for c in self.calls if c.url_without_query == path_or_url or c.path == path_or_url]

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


__all__ = ["Call", "Rule", "MockAdapter", "install", "run_generated"]

if __name__ == "__main__":  # pragma: no cover - tiny smoke test
    _ad = MockAdapter([Rule("https://example.test/", body="ok", headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])])
    _s = install(requests.Session(), _ad)
    _r = _s.get("https://example.test/")
    print(_r.status_code, _r.text, dict(_s.cookies), file=sys.stderr)
