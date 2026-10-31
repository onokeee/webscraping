"""reqrec - record a website's HTTP traffic and generate a standalone Python scraping script from it.

Pipeline:  record (GUI) / import  ->  Recording  ->  build_plan  ->  Plan  ->  generate  ->  script.py

Target: legacy LAN sites used in Edge's IE mode, over plain ``http://``, from a Windows PC with
Python installed.  Recording is done through the GUI's own IE-engine recording browser, which is
this file running in python.exe (no exe of reqrec's own, no Windows setting, no certificate).

The whole application is this one file (DESIGN.md "Module layout"):

* ``python reqrec.py`` - starts the GUI on this PC and opens it in the browser (:func:`main` without
  arguments); ``python -m flask --app reqrec run`` uses :func:`create_app` the same way;
* ``python reqrec.py <command>`` - the command line: ``import`` / ``inspect`` / ``generate`` / ``gui`` /
  ``record`` (the recording browser; the GUI starts it as a child process);
* ``import reqrec`` - the library (``load_recording``, ``build_plan``, ``generate``, ``create_app`` ...).

Sections, in this order (search for ``# ===== ``): core, importers, analysis, codegen, recorder (the
recording proxy and the IE-engine window), gui (followed by the page ``GUI_HTML``), cli and the entry
point (:func:`main`).  Every top-level name is defined once; names that clashed between former
modules carry a section prefix.

Importing has no side effects (nothing is started, written or read); bs4, winreg and ctypes are
imported only where they are used.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import builtins
import contextlib
import dataclasses
import errno
import hashlib
import hmac
import http.client
import http.server
import io
import ipaddress
import json
import keyword
import logging
import math
import os
import re
import secrets
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tokenize
import traceback
import types
import typing
import unicodedata
import webbrowser
from collections import OrderedDict, deque
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import datetime, timezone
from email.utils import formatdate
from typing import Any, Callable, Iterable, Iterator, Literal, Optional, Sequence, Union
from urllib.parse import (
    parse_qsl,
    quote,
    quote_from_bytes,
    unquote,
    unquote_plus,
    unquote_to_bytes,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

from flask import (
    Blueprint,
    Flask,
    Response,
    current_app,
    jsonify,
    redirect,
    render_template,
    send_from_directory,
)
# Flask's ``request`` / ``session`` proxies are bound as ``flask_request`` / ``flask_session`` (the
# analysis uses ``request`` for recorded requests).
from flask import request as flask_request
from flask import session as flask_session
from jinja2 import DictLoader
from werkzeug.exceptions import HTTPException

__version__ = "0.1.0"

# 他の PC から GUI を開くときのパスワード（この PC の中から使うときは不要）。ここを書き換えてください。
# 環境変数 REQREC_GUI_PASSWORD を設定した場合は、そちらが優先されます。"" にすると他の PC からは使えません。
#: Password for opening the GUI from ANOTHER PC (``reqrec gui --host 0.0.0.0`` /
#: ``flask --app reqrec run --host 0.0.0.0``); requests from this PC itself never need it.  The
#: environment variable ``REQREC_GUI_PASSWORD`` wins when set; ``""`` = other PCs cannot use the GUI.
GUI_PASSWORD = "adminpass"
#: The initial value of :data:`GUI_PASSWORD`: a warning is printed while it is still in use.
_DEFAULT_GUI_PASSWORD = "adminpass"

__all__ = [
    # core
    "RECORDING_FORMAT_VERSION", "Headers", "header_get", "header_get_all", "RecordedRequest",
    "RecordedResponse", "Flow", "Recording", "Ref", "RefKind", "Extractor", "ExtractorKind", "MultipartPart",
    "Loop", "Step", "Constant", "InitialCookie", "Dropped", "AuthInfo", "Plan", "PlanOptions", "GenOptions",
    "BodyKind", "ResponseKind", "to_plain", "NOT_WINDOWS_MESSAGE", "is_windows",
    "VALUE_CLASSES", "Binding", "CookieLookup", "CookieSet", "CookieInfo", "SessionSwitch",
    # importers
    "load_recording", "load_recordings", "load_har", "recording_from_har", "HAR_EXTENSIONS",
    "parse_har_timestamp", "decode_header_fields", "infer_resource_type",
    # analysis
    "TRACKER_HOSTS", "STATIC_EXTENSIONS", "STATIC_RESOURCE_TYPES", "DROP_REQUEST_HEADERS",
    "SESSION_AUTH_SCHEMES", "AUTH_FAMILIES", "classify_noise", "filter_flows", "collapse_redirects",
    "classify_cookies", "compute_base_headers", "clean_request_headers", "parse_cookie_header",
    "parse_set_cookie", "normalise_flow_id", "collapse_auth_handshakes", "auth_family",
    "COOKIE_PROFILES", "cookie_profile_for", "SetCookieInfo", "parse_set_cookie_attrs", "set_cookie_lines",
    "cookie_domain_match", "cookie_default_path", "cookie_path_match", "cookie_scope_url", "CookieVersion",
    "CookieTimeline", "initial_cookie_for", "split_path_segment", "describe_extractor", "describe_cookie",
    "authorization_scheme", "parse_www_authenticate", "parse_ntlm_type3", "ntlm_type3_user",
    "decode_basic_credentials", "digest_username", "auth_username", "Candidate", "MultipartField",
    "parse_multipart", "json_leaves", "json_dotted", "parse_json_text", "split_form_segments",
    "form_pairs_bytes", "form_body_is_utf8", "parse_form_bytes", "request_form_charset", "classify_body",
    "request_params", "split_auth_header", "is_session_auth_header", "header_candidates",
    "is_candidate_value", "is_numeric_path_id", "is_route_like", "is_structural_path_segment",
    "find_candidates", "looks_random_letters", "is_dynamic_looking", "build_pattern", "locate_value",
    "locate_value_kinds", "find_cookie", "clear_cache", "LoopGroup", "detect_loops",
    "build_plan",
    # codegen
    "generate", "CodegenError", "MAX_INLINE_BODY",
    # recorder
    "BROWSER_TITLE", "RECORD_LISTEN_HOST", "SCRIPT_PATH", "EMULATION_MODES", "RECORD_EXIT_OK", "RECORD_EXIT_START",
    "RECORD_EXIT_USAGE", "RECORD_EXIT_TIMEOUT", "RECORD_EXIT_PROXY", "RECORD_READY_TIMEOUT", "RecorderError",
    "write_recording_atomic", "RecordingStore", "RecordingProxy", "recorder_availability", "emulation_user_agent",
    "RECORD_BROWSERS", "find_edge", "edge_availability", "edge_command",
    "RecBrowserApp", "run_recorder", "recorder_command", "count_flows_in_file", "RecorderManager",
    # gui
    "open_folder", "validate_url", "ApiError", "AppState", "ScriptRunner", "SUBDIRS", "safe_name",
    "plan_options_from_json", "gen_options_from_json", "options_to_plain", "load_sources", "exclude_netlocs",
    "normalise_netloc", "RECORDING_EXTENSIONS", "bp", "get_state", "create_app", "run_gui", "TOKEN_HEADER",
    "GUI_PASSWORD", "GUI_PASSWORD_ENV", "WORKDIR_ENV", "LOGIN_HTML",
    "GUI_HTML",
    # cli
    "EXIT_OK", "EXIT_ERROR", "EXIT_USAGE", "main", "build_parser", "add_filter_options",
    "add_generate_options", "plan_options_from_args", "gen_options_from_args", "split_hosts",
    "split_flow_ids", "cli_normalise_flow_id", "load_inputs", "resolve_overrides", "build_inspect_report",
    "format_inspect_report", "format_plan_summary", "run_script",
]


# ===== former reqrec/core.py: data model + shared helpers (stdlib only) =====
# Core of reqrec: the data model every other module speaks in, plus the shared helpers.
#
# Sections (each one a former module):
#
# * data model (former ``reqrec/model.py``) - ``Recording`` / ``Flow`` (what was captured) and
#   ``Plan`` / ``Step`` / ``Ref`` / ``Extractor`` ... (what the generated script does);
# * shared helpers (former ``reqrec/util.py``) - URL, body, charset, naming and platform helpers.
#
# Keep this section dependency-free (stdlib only).


# ===== former reqrec/model.py: data model (Recording / Plan layers) =====
# Core data model for reqrec.
#
# Two layers:
#
# 1. **Recording layer** - what was captured on the wire.
#    ``Recording`` -> ``Flow`` -> ``RecordedRequest`` / ``RecordedResponse``
#    Serialised to a JSON file (``Recording.save`` / ``Recording.load``); bodies are base64.
#
# 2. **Plan layer** - what the generated script should do.
#    ``Plan`` -> ``Step`` (one HTTP call) with ``Ref`` values (literal / variable / expression),
#    ``Extractor`` (how a later step gets a value out of this step's response), ``Loop``
#    (pagination), plus ``Constant`` (user-supplied literals lifted to the top of the script),
#    ``InitialCookie`` (cookies that pre-dated the recording) and ``Dropped`` (noise, with reason).
#
# Every other module speaks in these types. Keep this section dependency-free (stdlib only).

RECORDING_FORMAT_VERSION = 1

Headers = list[tuple[str, str]]


# --------------------------------------------------------------------------- helpers

def header_get(headers: Headers, name: str) -> Optional[str]:
    """First header value with the given name (case-insensitive) or None."""
    lname = name.lower()
    for k, v in headers:
        if k.lower() == lname:
            return v
    return None


def header_get_all(headers: Headers, name: str) -> list[str]:
    lname = name.lower()
    return [v for k, v in headers if k.lower() == lname]


def _b64e(data: Optional[bytes]) -> Optional[str]:
    return None if data is None else base64.b64encode(data).decode("ascii")


def _b64d(data: Optional[str]) -> Optional[bytes]:
    return None if data is None else base64.b64decode(data)


# --------------------------------------------------------------------------- recording layer

@dataclass
class RecordedRequest:
    method: str
    url: str
    headers: Headers = field(default_factory=list)
    body: Optional[bytes] = None

    # -- derived -------------------------------------------------------------
    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme.lower()

    @property
    def host(self) -> str:
        """Hostname (lowercase, no port)."""
        return (urlsplit(self.url).hostname or "").lower()

    @property
    def netloc(self) -> str:
        return urlsplit(self.url).netloc

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def query(self) -> str:
        return urlsplit(self.url).query

    @property
    def url_without_query(self) -> str:
        return strip_query(self.url)

    @property
    def query_pairs(self) -> list[tuple[str, str]]:
        # byte level: a value a Shift_JIS page sent keeps its percent-encoded spelling (never U+FFFD)
        return parse_form_bytes(query_bytes(self.query))

    def header(self, name: str) -> Optional[str]:
        return header_get(self.headers, name)

    @property
    def content_type(self) -> Optional[str]:
        """Lower-cased MIME type of the request body without parameters, or None."""
        ct = self.header("content-type")
        return parse_content_type(ct)[0] if ct else None

    def text(self) -> Optional[str]:
        """Request body decoded to str (None when there is no body)."""
        if self.body is None:
            return None
        return decode_body(self.body, self.header("content-type"))


@dataclass
class RecordedResponse:
    status: int
    headers: Headers = field(default_factory=list)
    body: Optional[bytes] = None
    mime_type: Optional[str] = None  # lower-case, no parameters; derived from Content-Type if absent

    def __post_init__(self) -> None:
        if not self.mime_type:
            ct = self.header("content-type")
            self.mime_type = parse_content_type(ct)[0] if ct else None
        if self.mime_type:
            self.mime_type = self.mime_type.lower()

    def header(self, name: str) -> Optional[str]:
        return header_get(self.headers, name)

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400 and self.header("location") is not None

    @property
    def location(self) -> Optional[str]:
        return self.header("location")

    @property
    def set_cookies(self) -> list[str]:
        return header_get_all(self.headers, "set-cookie")

    def text(self) -> Optional[str]:
        """Response body decoded to str (None when there is no body)."""
        if self.body is None:
            return None
        return decode_body(self.body, self.header("content-type"))


@dataclass
class Flow:
    id: str
    request: RecordedRequest
    response: Optional[RecordedResponse] = None
    started_at: Optional[float] = None  # epoch seconds (float)
    page_ref: Optional[str] = None  # HAR pageref / navigation grouping, if known
    resource_type: Optional[str] = None  # HAR _resourceType: document, xhr, fetch, script, image, ...

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "started_at": self.started_at,
            "page_ref": self.page_ref,
            "resource_type": self.resource_type,
            "request": {
                "method": self.request.method,
                "url": self.request.url,
                "headers": [list(h) for h in self.request.headers],
                "body_b64": _b64e(self.request.body),
            },
            "response": None
            if self.response is None
            else {
                "status": self.response.status,
                "headers": [list(h) for h in self.response.headers],
                "body_b64": _b64e(self.response.body),
                "mime_type": self.response.mime_type,
            },
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Flow":
        req = d["request"]
        resp = d.get("response")
        return cls(
            id=str(d["id"]),
            started_at=d.get("started_at"),
            page_ref=d.get("page_ref"),
            resource_type=d.get("resource_type"),
            request=RecordedRequest(
                method=req["method"].upper(),
                url=req["url"],
                headers=[(h[0], h[1]) for h in req.get("headers", [])],
                body=_b64d(req.get("body_b64")),
            ),
            response=None
            if resp is None
            else RecordedResponse(
                status=int(resp["status"]),
                headers=[(h[0], h[1]) for h in resp.get("headers", [])],
                body=_b64d(resp.get("body_b64")),
                mime_type=resp.get("mime_type"),
            ),
        )


@dataclass
class Recording:
    flows: list[Flow] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": RECORDING_FORMAT_VERSION,
            "meta": self.meta,
            "flows": [f.to_dict() for f in self.flows],
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Recording":
        version = d.get("version", 1)
        if version != RECORDING_FORMAT_VERSION:
            raise ValueError(f"unsupported recording version {version!r}")
        return cls(meta=dict(d.get("meta", {})), flows=[Flow.from_dict(f) for f in d.get("flows", [])])

    @classmethod
    def from_json(cls, s: str) -> "Recording":
        return cls.from_dict(json.loads(s))

    def save(self, path: str) -> None:
        """Write the recording as JSON: a temp file in the same directory is ``os.replace``d onto
        ``path`` so a crash never leaves a half-written file."""
        data = self.to_json(indent=1)
        directory = os.path.dirname(os.path.abspath(path)) or "."
        fd, tmp = tempfile.mkstemp(prefix=".reqrec-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @classmethod
    def merge(cls, recordings: list["Recording"]) -> "Recording":
        """Combine several recordings (e.g. one HAR per browser tab) into one.

        Flows are ordered by ``started_at`` (stable sort; flows without a timestamp keep their
        relative position after the timestamped ones of the same source) and re-numbered
        ``f0001``.. so ids are unique.  ``meta`` becomes ``{"source": "merged", "sources": [...]}``
        unless there is exactly one recording, which is returned re-numbered but otherwise as is.
        """
        import copy

        if not recordings:
            return cls(meta={"source": "merged", "sources": []})
        flows: list[tuple[float, int, int, Flow]] = []
        for si, rec in enumerate(recordings):
            for fi, flow in enumerate(rec.flows):
                ts = flow.started_at if flow.started_at is not None else float("inf")
                flows.append((ts, si, fi, flow))
        flows.sort(key=lambda t: (t[0], t[1], t[2]))
        merged: list[Flow] = []
        for n, (_, _, _, flow) in enumerate(flows, start=1):
            f2 = copy.copy(flow)
            f2.id = f"f{n:04d}"
            merged.append(f2)
        if len(recordings) == 1:
            return cls(flows=merged, meta=dict(recordings[0].meta))
        return cls(flows=merged, meta={"source": "merged", "sources": [dict(r.meta) for r in recordings]})

    @classmethod
    def load(cls, path: str) -> "Recording":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_json(fh.read())

    def flow_by_id(self, flow_id: str) -> Optional[Flow]:
        for f in self.flows:
            if f.id == flow_id:
                return f
        return None


# --------------------------------------------------------------------------- plan layer

RefKind = Literal["literal", "var", "expr"]


@dataclass(frozen=True)
class Ref:
    """A value that appears in a generated request.

    * ``literal`` - ``value`` is the exact string to send (codegen emits ``repr(value)``).
    * ``var``     - ``value`` is a Python identifier available in scope (an Extractor's ``var``,
                    a Constant's ``name``, or a Loop's ``var``).
    * ``expr``    - ``value`` is Python source for an expression (e.g. ``str(int(time.time()*1000))``).
                    Codegen must emit it verbatim; whoever creates an ``expr`` is responsible for
                    its safety and for any imports it needs being in codegen's standard import set
                    (``re``, ``json``, ``os``, ``sys``, ``time``, ``requests``, ``BeautifulSoup``).
    """

    kind: RefKind
    value: str

    @staticmethod
    def lit(value: str) -> "Ref":
        return Ref("literal", value)

    @staticmethod
    def var(name: str) -> "Ref":
        return Ref("var", name)

    @staticmethod
    def expr(src: str) -> "Ref":
        return Ref("expr", src)

    @property
    def is_literal(self) -> bool:
        return self.kind == "literal"


ExtractorKind = Literal[
    "cookie",      # _cookie(session, name, cookie_url, path=, domain=)  -> name (+ scope); RFC 6265
    "header",      # resp.headers.get(name) (+ optional pattern; ``hop`` = redirect response)  -> name
    "json",        # resp.json()[path[0]][path[1]]...                 -> path
    "html_input",  # soup.find("input", {"name": name})["value"]      -> name
    "html_meta",   # soup.find("meta", {"name": name})["content"]     -> name
    "html_attr",   # soup.select_one(selector)[attr] (+ optional pattern applied to that string)
    "html_text",   # soup.select_one(selector).get_text(strip=True) (+ optional pattern)
    "regex",       # re.search(pattern, resp.text).group(1)           -> pattern
    "url",         # re.search(pattern, resp.url).group(1)  (final URL after redirects) -> pattern
]


@dataclass
class Extractor:
    """How to pull one value out of a step's response so later steps can use it.

    ``var`` is the Python identifier that receives the value.  Only the fields relevant to
    ``kind`` are set (see ``ExtractorKind``).  ``pattern`` always has exactly one capture group.
    ``sample`` is the value seen during recording (for comments / tests), ``note`` is free text
    for a code comment (e.g. where the value was used).
    """

    var: str
    kind: str
    name: Optional[str] = None
    path: Optional[list[Any]] = None  # list of str (object key) / int (array index)
    selector: Optional[str] = None
    attr: Optional[str] = None
    pattern: Optional[str] = None
    sample: Optional[str] = None
    note: Optional[str] = None
    #: index into the step's redirect chain (``list(resp.history) + [resp]``) for values that only an
    #: intermediate redirect response carried (``header`` with ``name``, or its ``Location`` matched by
    #: ``pattern``); None = the final response
    hop: Optional[int] = None
    #: kind ``cookie``: the cookie's scope (``_cookie(session, name, cookie_url, path=, domain=)``); URL pieces
    #: (a ``Ref`` tuple) when it holds a path segment the step reads afresh; ``cookie_url`` None = ``resp.url``
    cookie_url: Union[None, str, tuple] = None
    cookie_path: Union[None, str, tuple] = None
    cookie_domain: Optional[str] = None
    #: kind ``json``, one row of a list the user chose (``_json_row``): ``path[row]`` is the recorded row
    #: number - the script reads ``path[row + 1:]`` from the row of the list ``path[:row]`` whose ``row_key``
    #: leaf is ``row_value`` (the request sends it in its field ``row_field``; ``row_ref``: the constant, an
    #: 入力値, compared instead of the recorded value)
    row: Optional[int] = None
    row_key: Optional[list[Any]] = None
    row_value: Optional[str] = None
    row_field: Optional[str] = None
    row_ref: Optional[str] = None
    #: a key the server hands out anew on every run, judged by behaviour (a page's links handed it out
    #: although it reads like words): comments show only its length, never the recorded value
    renewed: bool = False


@dataclass
class MultipartPart:
    name: str
    value: Optional[Ref] = None  # text field
    filename: Optional[str] = None  # file field (then ``content`` holds the bytes)
    content_type: Optional[str] = None
    content: Optional[bytes] = None


@dataclass
class Loop:
    """Pagination / repetition: the step is executed once per value, bound to ``var``.

    The paginated parameter inside the Step is already represented as ``Ref.var(var)``.
    ``values`` are the recorded literal values in order (e.g. ["1", "2", "3"]).  When
    ``numeric_range`` is set codegen may emit ``range(start, stop)`` instead of the list.
    """

    var: str
    values: list[str]
    numeric_range: Optional[tuple[int, int]] = None  # inclusive start, inclusive end
    note: str = ""


BodyKind = Literal["none", "form", "json", "multipart", "raw"]
ResponseKind = Literal["html", "json", "xml", "text", "binary", "empty"]


@dataclass
class Step:
    """One HTTP call in the generated script.

    * ``url`` - pieces concatenated to form the URL **without** query string; usually a single
      literal Ref, with var/expr pieces for dynamic path segments.
    * ``params`` - query string as ordered (name, Ref) pairs; repeated names allowed.
    * ``headers`` - per-step request headers **after** removing those in ``Plan.base_headers``
      and the hop-by-hop / managed headers (Host, Cookie, Content-Length, ...).
    * body: exactly one of ``form`` / ``json_body`` / ``multipart`` / ``raw_body`` is used,
      selected by ``body_kind``.  ``json_body`` is a JSON-like structure (dict/list/str/int/
      float/bool/None) in which any leaf may be a ``Ref``.
    * ``extractors`` - values later steps need from *this* step's response.
    * ``response_kind`` / ``expected_status`` - describe the recorded response so codegen can
      emit the right parsing/asserts.  For collapsed redirect chains this describes the final hop.
    * ``loop`` - when set, the step repeats (see ``Loop``).
    * ``source_flow_ids`` - the recorded flows this step came from (several when a redirect chain
      was collapsed or a loop was folded).
    """

    index: int
    func_name: str
    method: str
    url: list[Ref]
    params: list[tuple[str, Ref]] = field(default_factory=list)
    headers: list[tuple[str, Ref]] = field(default_factory=list)
    body_kind: str = "none"
    form: Optional[list[tuple[str, Ref]]] = None
    json_body: Any = None
    multipart: Optional[list[MultipartPart]] = None
    raw_body: Optional[bytes] = None
    extractors: list[Extractor] = field(default_factory=list)
    response_kind: str = "empty"
    expected_status: int = 200
    loop: Optional[Loop] = None
    source_flow_ids: list[str] = field(default_factory=list)
    comment: str = ""
    allow_redirects: bool = True
    #: cookie values read from the jar before the request (class D) and cookies set before it
    lookups: list[CookieLookup] = field(default_factory=list)
    cookie_sets: list[CookieSet] = field(default_factory=list)
    #: where each dynamic value of this request comes from (classes B-E, plus untraced A values)
    bindings: list[Binding] = field(default_factory=list)

    def literal_url(self) -> Optional[str]:
        """URL string if all pieces are literal, else None."""
        if all(r.is_literal for r in self.url):
            return "".join(r.value for r in self.url)
        return None


@dataclass
class Constant:
    """A literal lifted to module level (shared value, user input, or secret).

    When ``secret`` is True and ``env_var`` is set, codegen emits
    ``NAME = os.environ.get("ENV_VAR", "")`` instead of the recorded value.
    """

    name: str
    value: str
    secret: bool = False
    env_var: Optional[str] = None
    comment: str = ""
    #: ``"input"`` - a value the user typed or chose (class B, the script's 入力値 section);
    #: ``"shared"`` - a fixed value used in several places (class A); ``"auth"`` - HTTP auth
    kind: str = "shared"
    #: a password / credential: reports and the GUI never show its value (the script holds it in plain
    #: text unless ``secret``, as the user decided)
    sensitive: bool = False
    #: the value was sent in this legacy charset (a Shift_JIS page): the constant holds the text and the
    #: requests send ``NAME.encode(encoding)``
    encoding: Optional[str] = None


@dataclass
class InitialCookie:
    """A cookie the browser sent although no recorded response had set it in that scope.

    ``origin`` is ``"pre-existing"`` (the browser had it before the recording started) or
    ``"script"`` (the page wrote it, e.g. ``document.cookie``, with a value that could not be traced
    to an earlier response).  ``domain`` is the host it was sent to (or the Domain it was adopted
    from, see ``CookieTimeline``), ``path`` the narrowest path consistent with where it was and was
    not sent, ``url`` the scope URL the generated script sets it for (``_set_cookie``), so host-only
    cookies of dot-less LAN hosts (``http://kanri/``) are stored exactly like server cookies."""

    name: str
    value: str
    domain: str
    path: str = "/"
    url: str = ""
    host_only: bool = True
    origin: str = "pre-existing"


#: Value classes of the dependency analysis (DESIGN.md §14): how a request value is obtained when the
#: generated script runs.
VALUE_CLASSES: dict[str, str] = {
    "A": "固定値",
    "B": "入力値",
    "C": "レスポンスから取得",
    "D": "Cookie / セッション",
    "E": "実行時の値",
}


@dataclass
class Binding:
    """Where one request value of a step comes from (the dependency graph, value-free).

    * ``location`` - ``path`` | ``path_param`` | ``query`` | ``form`` | ``json`` | ``multipart`` |
      ``header`` | ``cookie`` | ``referer`` | ``auth``; ``name`` - parameter / header / cookie name,
      dotted JSON path or path segment number;
    * ``value_class`` - ``A`` fixed, ``B`` user input, ``C`` response-derived, ``D`` cookie /
      session-derived, ``E`` runtime environment (see ``VALUE_CLASSES``);
    * ``source`` - plain-Japanese description of the source (never the value itself);
      ``source_step`` / ``source_kind`` - producing step and locator kind (``set-cookie``,
      ``cookie-jar``, ``html_input``, ``json``, ``header``, ``url``, ``time``, ``input`` ...);
    * ``var`` - the script variable / constant carrying the value; ``cookie`` / ``cookie_domain`` /
      ``cookie_path`` - the cookie identity for class D."""

    location: str
    name: str
    value_class: str
    source: str = ""
    source_step: Optional[int] = None
    source_kind: str = ""
    var: Optional[str] = None
    cookie: Optional[str] = None
    cookie_domain: Optional[str] = None
    cookie_path: Optional[str] = None
    note: str = ""


@dataclass
class CookieLookup:
    """A cookie value a step reads from the session's jar right before its request (class D):
    ``var = _cookie(session, name, url, path=path, domain=domain)`` - the cookie of that name the jar
    would send to ``url``, the recorded ``path`` / ``domain`` breaking ties between same-name
    cookies (RFC 6265: several cookies may share a name in different scopes).  For a cookie the request
    sends, ``url`` is the request's own URL; ``url`` / ``path`` are URL pieces (a ``Ref`` tuple joined like
    ``Step.url``) when they hold a path segment the step reads afresh (``/s/<key>/`` a redirect handed out),
    ``path`` None when it cannot be built from them (then the longest path wins)."""

    var: str
    name: str
    url: Union[str, tuple]
    path: Union[None, str, tuple] = None
    domain: Optional[str] = None
    note: str = ""


@dataclass
class CookieSet:
    """A cookie a step sets in the jar right before its request: a cookie the page's script wrote
    (``document.cookie``) or one copied into another scope, whose value is ``value`` (a Ref: traced,
    cookie-derived or literal).  Emitted as ``_set_cookie(session, url, name, value, path=...)``.  A path
    holding a segment the step reads afresh is not written: ``url`` is then that path built from the
    step's URL pieces (a ``Ref`` tuple) and ``path`` None (the jar takes the path from ``url``)."""

    name: str
    url: Union[str, tuple]
    value: Ref
    path: Optional[str] = None
    domain: Optional[str] = None
    note: str = ""


@dataclass
class CookieInfo:
    """One cookie identity (name, domain, path) of the recording, for the generated script's cookie
    table and the debug output: where it came from and which steps sent it."""

    name: str
    domain: str
    path: str
    host_only: bool = True
    origin: str = "server"  # "server" (Set-Cookie) | "pre-existing" | "script" | "dropped"
    issued_steps: list[int] = field(default_factory=list)
    used_steps: list[int] = field(default_factory=list)
    switch_steps: list[int] = field(default_factory=list)
    note: str = ""


@dataclass
class SessionSwitch:
    """A step whose response (re)issued a cookie that later steps send instead of an earlier value of
    the same name: ``kind`` ``"rotation"`` (same name, domain and path; e.g. a new session id at
    login) or ``"context"`` (same name in a new domain / path; e.g. a portal handing over to a
    business application)."""

    step: int
    name: str
    domain: str
    path: str
    kind: str
    previous: str = ""


@dataclass
class Dropped:
    flow_id: str
    method: str
    url: str
    reason: str


@dataclass
class AuthInfo:
    """HTTP authentication the recorded conversation used (detected from a 401 challenge /
    ``Authorization`` handshake).  The generated script sets ``session.auth`` once, so the
    handshake flows are collapsed and ``Authorization`` headers of that scheme are dropped.

    * ``kind``: ``"ntlm"`` | ``"negotiate"`` | ``"basic"`` | ``"digest"``
    * ``hosts``: hosts the handshake was seen on
    * ``realm``: from ``WWW-Authenticate`` when present
    * ``username``: recorded user (Basic: decoded; NTLM: parsed from the Type-3 message when
      possible, as ``DOMAIN\\user``) - informational, never a secret
    * ``username_const`` / ``password_const``: names of the ``Constant`` entries codegen uses
      (``Plan.constants`` holds them; the password one is ``secret=True`` with an ``env_var``)
    """

    kind: str
    hosts: list[str] = field(default_factory=list)
    realm: Optional[str] = None
    username: Optional[str] = None
    username_const: Optional[str] = None
    password_const: Optional[str] = None
    comment: str = ""


@dataclass
class Plan:
    steps: list[Step] = field(default_factory=list)
    constants: list[Constant] = field(default_factory=list)
    base_headers: Headers = field(default_factory=list)
    initial_cookies: list[InitialCookie] = field(default_factory=list)
    dropped: list[Dropped] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    auth: Optional[AuthInfo] = None  # HTTP auth scheme to configure on the session (see AuthInfo)
    final_step_index: Optional[int] = None  # Step.index whose result main() prints; None = last step
    #: every cookie identity (name, domain, path) the steps send or receive, and the session switches
    cookies: list[CookieInfo] = field(default_factory=list)
    session_switches: list[SessionSwitch] = field(default_factory=list)
    #: where a step's redirect handed out a value later steps read afresh (a key in the path, a ``;name=`` /
    #: query value): ``(step, "path" | "path_param" | "query", segment number of the Location's path | name)``,
    #: never the value - the script hides the value found there whatever its spelling (``_note_issued``)
    issued_places: list[tuple[int, str, str]] = field(default_factory=list)
    #: dot-less hosts (``http://kanri/``) that set cookies with ``Domain=<host>`` (an RFC 6265 browser
    #: sends them back, Python's cookie jar only after the script's ``_host_cookie_hook``; the IE engine
    #: refuses them)
    dotless_domain_hosts: list[str] = field(default_factory=list)
    #: hosts that set (or delete) cookies with ``Domain=<that host>``: browsers treat them as the host-only
    #: cookie of the same name, Python's jar as a second cookie - the script's ``_host_cookie_hook``
    #: (``_ie_cookie_hook`` for the IE engine) aligns them
    domain_is_host_hosts: list[str] = field(default_factory=list)
    #: hosts whose ``Set-Cookie`` lines carry attributes browsers ignore but Python's jar does not (an
    #: empty Domain, a Max-Age that is not an integer, a Path not starting with ``/``): Python would drop
    #: the cookie or never send it - the script's ``_cookie_attr_hook`` removes them
    malformed_cookie_hosts: list[str] = field(default_factory=list)
    #: IE engine: hosts that set cookies without ``Path`` below the root (IE's default path keeps the
    #: trailing ``/``, Python's does not) - the script's ``_ie_cookie_hook`` gives them IE's path
    ie_default_path_hosts: list[str] = field(default_factory=list)
    #: RFC 6265 browsers: hosts whose host-only cookies the browser did not send to a sub-domain the
    #: plan requests, while Python's default cookie policy would - the script then uses ``_Session``
    host_only_cookie_hosts: list[str] = field(default_factory=list)
    #: hosts whose response sets a cookie and then deletes it again: browsers apply the lines in order, Python's jar
    #: applies the deletion first - the script's ``_host_cookie_hook`` / ``_ie_cookie_hook`` keep the last line
    repeated_cookie_hosts: list[str] = field(default_factory=list)
    #: hosts a recorded request sent two cookies of one name to (servers read the first): older Pythons (3.8 / 3.9)
    #: send them sorted by domain - the script's ``_cookies_in_order`` keeps the order they were received in
    same_name_cookie_hosts: list[str] = field(default_factory=list)
    #: IE engine: hosts that set or delete cookies with ``Domain=<a parent domain>`` that the parent host
    #: also has without ``Domain``: one cookie for IE, two in Python's jar - the script's
    #: ``_ie_cookie_hook`` removes the parent host's copy
    parent_domain_cookie_hosts: list[str] = field(default_factory=list)
    cookie_profile: str = "rfc6265"  # the recording browser's cookie rules (COOKIE_PROFILES)
    #: hosts the steps (or their redirects) reach over https:// (only HAR files have them): the script checks
    #: their certificates with the Windows certificate store too (``_windows_certificates``), as Edge does
    https_hosts: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- options

@dataclass
class PlanOptions:
    """Knobs for ``analysis.build_plan``.  All host matching is case-insensitive and also matches
    sub-domains (``example.com`` matches ``api.example.com``)."""

    include_hosts: Optional[list[str]] = None  # when set, keep only flows to these hosts
    exclude_hosts: list[str] = field(default_factory=list)
    keep_static: bool = False  # keep images/css/js/fonts
    keep_trackers: bool = False  # keep analytics / tracking hosts
    keep_all: bool = False  # disable every noise filter (host filters still apply)
    collapse_redirects: bool = True
    detect_loops: bool = True
    # write recorded passwords into the script as they are (False, the default) or read them from
    # environment variables at run time (True: 詳細設定 / ``--redact``)
    redact_secrets: bool = False
    min_value_length: int = 4  # shortest request value considered for dependency detection
    max_steps: Optional[int] = None  # truncate (with a warning) - safety valve for huge recordings
    # --- manual overrides (GUI / CLI) ---
    exclude_flow_ids: list[str] = field(default_factory=list)  # always dropped, reason "excluded by user"
    include_flow_ids: list[str] = field(default_factory=list)  # kept even if a noise rule would drop them
    final_flow_id: Optional[str] = None  # the flow whose step becomes Plan.final_step_index
    detect_auth: bool = True  # detect NTLM / Negotiate / Basic / Digest handshakes -> Plan.auth
    #: put back a request the noise filter dropped (static file, tracker, 304) when its response sets a
    #: cookie or carries a value that a kept request needs and no kept response provides
    include_producers: bool = True


@dataclass
class GenOptions:
    """Knobs for ``codegen.generate``."""

    html_parser: str = "html.parser"  # or "lxml"
    comments: bool = True  # emit explanatory comments
    delay: float = 0.0  # seconds to sleep between steps (politeness)
    timeout: float = 30.0
    print_final: bool = True  # print the final step's result in main() (Plan.final_step_index or last)
    strict_status: bool = False  # assert resp.status_code == expected_status (else raise_for_status)


# --------------------------------------------------------------------------- generic (de)serialisation for debugging

def to_plain(obj: Any) -> Any:
    """Convert dataclasses / bytes / tuples into JSON-serialisable structures (debug dumps)."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_plain(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, bytes):
        return {"__bytes_b64__": _b64e(obj)}
    if isinstance(obj, (list, tuple)):
        return [to_plain(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}
    return obj


# ===== former reqrec/util.py: shared helpers (stdlib only) =====
# Shared, dependency-free helpers (stdlib only).  Used by every other module.

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
        "".encode(cs)  # an unknown name raises LookupError (decoding b"" skips the codec lookup)
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
    """Spellings a request value may have had inside a response: raw, URL-(un)quoted, HTML-escaped.
    A percent-encoded value whose bytes are not UTF-8 (cp932 from a Shift_JIS page) has no unquoted
    spelling: decoding it gives U+FFFD, which only matches garbled text by coincidence."""
    out = {value}
    try:
        out.add(unquote(value, errors="strict"))
        out.add(unquote_plus(value, errors="strict"))
    except UnicodeDecodeError:
        pass
    try:
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
    "BeautifulSoup", "BASE_HEADERS", "INITIAL_COOKIES", "TIMEOUT", "DEBUG", "DEPENDENCIES",
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
    if not (value.isascii() and value.isdigit()):  # '①' is a digit to str.isdigit() but not to int()
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


# --------------------------------------------------------------------------- downloads (GUI display)
#
# These mirror the helpers the generated scripts carry (``codegen._DOWNLOAD_HELPERS_SRC``) so the GUI
# shows the same decision and the same file name the script will use (DESIGN.md §13.13).

_DISPOSITION_EXT_RE = re.compile(r"filename\*\s*=\s*([^';]*)'[^']*'([^;]+)", re.I)
_DISPOSITION_RE = re.compile(r'filename\s*=\s*(?:"([^"]*)"|([^;]+))', re.I)
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_RESERVED_FILE_NAME_RE = re.compile(r"(con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])", re.I)
MAX_FILE_NAME = 150


def is_attachment_disposition(content_disposition: Optional[str]) -> bool:
    """Is a response with this ``Content-Disposition`` a file download?

    True when the value (stripped, lower-cased) starts with ``attachment``, or contains
    ``filename`` and does not start with ``inline``.  ``inline; filename=f.txt`` (Spring's
    reflected-file-download protection on every JSON response) is *not* a download.  The generated
    scripts' ``_is_attachment`` applies the same rule."""
    disposition = (content_disposition or "").strip().lower()
    if disposition.startswith("attachment"):
        return True
    return "filename" in disposition and not disposition.startswith("inline")


def _decode_encoded_words(text: str) -> str:
    """RFC 2047 encoded words (``=?UTF-8?B?...?=``, ``=?Shift_JIS?Q?...?=``) -> text; unchanged when
    there are none or they cannot be decoded."""
    from email.header import decode_header

    try:
        parts = decode_header(text)
    except Exception:
        return text
    out: list[str] = []
    for part, charset in parts:
        if isinstance(part, str):
            out.append(part)
        elif charset:
            try:
                out.append(part.decode(_normalise_charset(charset), "replace"))
            except LookupError:  # pragma: no cover - _normalise_charset only returns known codecs
                out.append(part.decode("utf-8", "replace"))
        else:
            out.append(part.decode("raw-unicode-escape", "replace"))
    return "".join(out)


def safe_file_name(name: Optional[str]) -> str:
    """A file name usable on Windows: no folder part, no forbidden characters, reserved device names
    (``CON``, ``NUL``, ``COM1`` ... with any extension) prefixed with ``_``, at most
    :data:`MAX_FILE_NAME` characters (the extension is kept).  ``''`` when nothing is left."""
    name = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", name).strip(" .")
    if not name:
        return ""
    if _RESERVED_FILE_NAME_RE.fullmatch(name.split(".", 1)[0].rstrip(" ")):
        name = "_" + name
    if len(name) > MAX_FILE_NAME:
        stem, ext = os.path.splitext(name)
        if len(ext) > 16:  # not a real extension
            stem, ext = name, ""
        name = stem[: MAX_FILE_NAME - len(ext)].rstrip(" .") + ext
    return name


def download_filename(content_disposition: Optional[str]) -> Optional[str]:
    """File name from a ``Content-Disposition`` header, decoded the way the generated scripts do
    (RFC 6266 ``filename*=``, RFC 2047 ``=?UTF-8?B?...?=``, IE-style percent-encoded UTF-8, raw
    UTF-8 / Shift_JIS bytes read as Latin-1) and made safe with :func:`safe_file_name`; ``None``
    when the header names no file.  It only decodes the name: whether the response is a download
    at all is :func:`is_attachment_disposition`.  Used to show 「保存されるファイル」 in the GUI."""
    from urllib.parse import unquote

    value = content_disposition or ""
    m = _DISPOSITION_EXT_RE.search(value)
    name: Optional[str] = None
    if m:
        try:
            name = unquote(m.group(2).strip().strip('"'), encoding=m.group(1).strip() or "utf-8", errors="replace")
        except LookupError:
            name = unquote(m.group(2).strip().strip('"'), encoding="utf-8", errors="replace")
    else:
        m = _DISPOSITION_RE.search(value)
        if m:
            raw = (m.group(1) if m.group(1) is not None else m.group(2)).strip()
            decoded = _decode_encoded_words(raw) if "=?" in raw else raw
            if decoded != raw:
                name = decoded
            elif _PCT_RE.search(raw):
                name = unquote(raw, encoding="utf-8", errors="replace")
            else:
                name = raw
                for codec in ("utf-8", "cp932"):
                    try:
                        name = raw.encode("latin-1").decode(codec)
                        break
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        continue
    return safe_file_name(name) or None


# --------------------------------------------------------------------------- platform
# (formerly in reqrec/winsupport.py; used by the recorder section)

NOT_WINDOWS_MESSAGE = "Windows 以外では使えません"


def is_windows() -> bool:
    """True when running on Windows (``sys.platform == "win32"``)."""
    return sys.platform == "win32" or os.name == "nt"


# ===== former reqrec/importers.py: HAR / reqrec JSON -> Recording =====
# Load a Recording from a HAR file or a reqrec JSON recording.  Contract: DESIGN.md §2.
#
# Sections (each one a former module):
#
# * dispatcher (former ``reqrec/importers/__init__.py``) - ``load_recording`` / ``load_recordings``;
# * HAR importer (former ``reqrec/importers/har.py``) - ``load_har`` / ``recording_from_har``;
# * header helpers shared with the recording proxy - ``infer_resource_type`` / ``decode_header_fields``.


# ===== former reqrec/importers/__init__.py: dispatcher (load_recording / load_recordings) =====
# Load a Recording from a HAR file or a reqrec JSON recording.
#
# Contract: see DESIGN.md §2.
#
# Dispatch is by extension: ``.har`` -> HAR importer, ``.json`` -> sniffed (a HAR document has a
# top-level ``"log"``; a reqrec recording has ``"flows"``).  Anything else raises ``ValueError``.

_importers_log = logging.getLogger("reqrec.importers")

HAR_EXTENSIONS = frozenset({".har"})
JSON_EXTENSIONS = frozenset({".json"})


def load_recording(path: str) -> Recording:
    """Dispatch on extension / content (see DESIGN.md §2).

    Raises ``ValueError`` for unsupported extensions or unrecognised JSON and the usual ``OSError``
    family when the file cannot be read.
    """
    path = os.fspath(path)
    ext = os.path.splitext(path)[1].lower()
    if ext in HAR_EXTENSIONS:
        return load_har(path)
    if ext in JSON_EXTENSIONS:
        return _load_json_sniffed(path)
    supported = ", ".join(sorted(HAR_EXTENSIONS | JSON_EXTENSIONS))
    raise ValueError(
        f"{path}: 対応していないファイル形式です ({ext or '拡張子なし'})。対応形式: {supported}\n"
        f"unsupported input file type {ext or '(no extension)'}; supported: {supported}"
    )


def load_recordings(paths: Union[str, "os.PathLike[str]", Iterable[Union[str, "os.PathLike[str]"]]]) -> Recording:
    """Load one or more files and merge them into a single ``Recording`` (DESIGN.md §13.5).

    Typical use: one HAR per browser tab (DevTools saves each tab separately), merged so that a
    screen opened in a new tab becomes part of the same conversation.  Flows are re-ordered by
    their timestamps across files and re-numbered ``f0001``...; ``meta`` becomes
    ``{"source": "merged", "sources": [<meta of each file>]}``.  A single path (or a one-element
    list) behaves exactly like ``load_recording`` (same flows, same ``meta``).  The same file
    listed twice is loaded once (a duplicate would double every step).

    Raises ``ValueError`` for an empty list and whatever ``load_recording`` raises per file, with
    the offending file named.
    """
    if isinstance(paths, (str, bytes, os.PathLike)):
        paths = [paths]
    unique: list[str] = []
    seen: set[str] = set()
    for p in paths:
        text = os.fsdecode(p) if isinstance(p, bytes) else os.fspath(p)
        key = os.path.normcase(os.path.realpath(text))
        if key in seen:
            _importers_log.warning("%s: 同じファイルが複数回指定されました（1 回だけ読み込みます）", text)
            continue
        seen.add(key)
        unique.append(text)
    if not unique:
        raise ValueError("読み込むファイルが指定されていません / no input files given")
    recordings = [load_recording(p) for p in unique]
    if len(recordings) == 1:
        return recordings[0]
    return Recording.merge(recordings)


def _load_json_sniffed(path: str) -> Recording:
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: JSONを解析できません / not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: JSONのトップレベルがオブジェクトではありません / top-level JSON value is not an object")
    if isinstance(data.get("log"), dict):
        return recording_from_har(data, source=path)
    if "flows" in data:
        return Recording.from_dict(data)
    raise ValueError(
        f'{path}: HAR ("log") でも reqrec の記録 ("flows") でもないJSONです\n'
        f'JSON file is neither a HAR document ("log") nor a reqrec recording ("flows")'
    )


# ===== former reqrec/importers/har.py: HAR 1.2 importer =====
# HAR 1.2 importer (Chrome / Firefox / Safari DevTools exports).  Contract: DESIGN.md §2.
#
# The importer is deliberately forgiving: real-world HAR files miss fields, contain ``null`` where
# the spec says string, use odd timestamp formats and carry lossy text for binary bodies.  An entry
# is skipped **only** when it has no usable URL (or is so malformed that it cannot be read at all);
# everything else is imported on a best-effort basis.  Skipped entries are counted in
# ``Recording.meta["skipped_entries"]``.

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
            _importers_log.warning("HAR entry %d could not be imported: %s", index, exc)
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
        "imported_at": now_iso(),
        "entries": len(raw_entries),
        "skipped_entries": skipped,
    }
    browser = _creator_string(har_log.get("browser"))
    if browser:
        meta["browser"] = browser
    if _har_without_sensitive_data(raw_entries, har_log.get("creator")):
        meta["sensitive_data_removed"] = True
    return Recording(flows=flows, meta=meta)


def _har_without_sensitive_data(entries: list[Any], creator: Any) -> bool:
    """A HAR that the F12 tools of Edge / Chrome (creator ``WebInspector``) saved without the sensitive
    data - their default "Export HAR (sanitized)": not one Cookie / Set-Cookie / Authorization header and
    no cookie list anywhere, although one site was asked more than once."""
    name = str(creator.get("name") or "") if isinstance(creator, dict) else ""
    if "webinspector" not in name.lower():
        return False
    per_host: dict[str, int] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            continue
        req, resp = entry["request"], entry.get("response")
        url = str(req.get("url") or "")
        if not url.lower().startswith(("http://", "https://")):
            continue
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            continue
        per_host[host] = per_host.get(host, 0) + 1
        for part, names in ((req, ("cookie", "authorization")), (resp, ("set-cookie",))):
            if not isinstance(part, dict):
                continue
            if part.get("cookies"):
                return False
            for item in part.get("headers") or []:
                if isinstance(item, dict) and str(item.get("name") or "").strip().lower() in names:
                    return False
    return max(per_host.values(), default=0) >= 2


def har_sensitive_data_removed(meta: dict[str, Any]) -> bool:
    """Whether a recording (or one of the files merged into it) is such a HAR."""
    if meta.get("sensitive_data_removed"):
        return True
    return any(isinstance(m, dict) and m.get("sensitive_data_removed") for m in meta.get("sources") or [])


#: What a generated script prints under ``[n/N] ERROR`` when an https:// certificate could not be checked
#: (neither requests' list nor the Windows certificate store knows it: a self-signed certificate ...).
CERTIFICATE_HINT = (
    "ヒント: https のサイトの証明書を確認できませんでした。Windows に入っている証明書でも確認できない証明書です"
    "（自己署名の証明書など）。サイトの管理者から証明書のファイル（Base64 形式の .cer / .pem）をもらい、"
    "実行する前に「set REQUESTS_CA_BUNDLE=そのファイルの場所」を入力してください"
    "（例: set REQUESTS_CA_BUNDLE=C:\\reqrec\\site.cer）。"
)

#: The plan's warning for such a HAR (shown first, under 「確認してください」).
SANITIZED_HAR_WARNING = (
    "読み込んだ HAR ファイルには、Cookie とログインの情報（Authorization ヘッダー）が 1 つも入っていません。"
    "Edge や Chrome の F12 開発者ツールで、機密データを除く形（既定の「Export HAR (sanitized)」）で保存したためと"
    "思われます。このままでは、ログインのあとの手順が失敗することがあります。F12 の設定（歯車）で「Allow to "
    "generate HAR with sensitive data」をオンにして、「Export HAR (with sensitive data)」で保存し直してください"
    "（Cookie を使わないサイトなら、このままで構いません）。"
)


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
            return _importers_b64decode_lenient(text), headers
        charset = _charset_for_text(text, content_type_header, mime)
        return _encode_text(text, charset), headers

    params = post.get("params")
    if isinstance(params, list) and params:
        mime_main = parse_content_type(content_type_header or mime)[0] or ""
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


_IMPORTERS_BOUNDARY_RE = re.compile(r"""boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))""", re.I)


def _multipart_boundary(content_type: Optional[str]) -> Optional[str]:
    """Case-preserving boundary parameter (``core.parse_content_type`` lower-cases values)."""
    if not content_type:
        return None
    m = _IMPORTERS_BOUNDARY_RE.search(content_type)
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

    mime_type = parse_content_type(content_mime_raw)[0]
    if mime_type in _UNKNOWN_MIME_TYPES or mime_type is None:
        mime_type = parse_content_type(content_type_header)[0]
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
        return _importers_b64decode_lenient(text)
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
    header_charset = parse_content_type(content_type_header)[1].get("charset")
    mime_charset = parse_content_type(content_mime)[1].get("charset")
    if header_charset:
        ct = content_type_header
    elif mime_charset:
        ct = content_mime
    else:
        ct = content_type_header or content_mime or None
    sample = text[:4096].encode("utf-8", "replace")  # only used for <meta charset> sniffing
    return detect_charset(sample, ct)


def _encode_text(text: str, charset: str) -> bytes:
    try:
        return text.encode(charset, errors="replace")
    except (LookupError, UnicodeError):  # pragma: no cover - detect_charset validates the codec
        return text.encode("utf-8", errors="replace")


def _importers_b64decode_lenient(text: str) -> bytes:
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


# ===== header helpers (shared by the importers and the recording proxy) =====
# ``infer_resource_type`` (HAR-style resource type from the browser's ``Sec-Fetch-Dest`` header; the
# IE engine never sends it, so its flows are classified by URL extension and MIME type instead),
# ``decode_header_fields`` and ``_text`` (bytes -> str that never raises).

# ``Sec-Fetch-Dest`` request header -> HAR-style resource type.
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


# ===== former reqrec/analysis.py: Recording -> Plan (filters, deps, loops, plan) =====
# Analysis: Recording -> Plan.  Contract: DESIGN.md §4-§7 and §13.
#
# Sections (each one a former module, in dependency order):
#
# * filters (former ``reqrec/filters.py``) - noise filtering, redirect / auth-handshake collapsing,
#   cookie classification, header hygiene;
# * deps (former ``reqrec/deps.py``) - which request values came from earlier responses
#   (candidates + locators);
# * loops (former ``reqrec/loops.py``) - pagination / repetition detection;
# * plan (former ``reqrec/plan.py``) - ``build_plan``: kept flows -> ``Step`` objects whose values are
#   ``Ref`` s the generated script resolves at run time.


# ===== former reqrec/filters.py: noise filtering, redirects, cookies, auth handshakes, header hygiene =====
# Noise filtering, redirect collapsing, cookie classification, header hygiene.  Contract: DESIGN.md §4.
#
# Everything here is deliberately conservative: a flow is only dropped when we are confident it is
# noise (tracking beacons, static assets, cache revalidations ...).  HTML documents, APIs, redirects
# and downloads are always kept.

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
#: headers) or ``proxy-`` are dropped as well.  ``content-type`` is kept here and handled by the plan section.
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
    ext = url_extension(url)
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
    if opts.include_hosts and not host_matches(host, opts.include_hosts):
        return "host not in --include-host"
    if opts.exclude_hosts and host_matches(host, opts.exclude_hosts):
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
    if not opts.keep_trackers and host_matches(host, TRACKER_HOSTS):
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


# --------------------------------------------------------------------------- cookies (RFC 6265 model)
#
# Cookies are identified the way a browser identifies them - by name, domain and path (RFC 6265
# §5.3) - never by name alone: a portal and a business application often both issue a cookie named
# like a session id, on different paths or hosts, and both are live at the same time.

@dataclass
class SetCookieInfo:
    """One ``Set-Cookie`` header as the recording browser applies it (``CookieTimeline`` profiles).

    ``path`` is the browser's path, ``py_path`` the path Python's cookie jar (the generated script)
    stores: the same path - for a cookie without ``Path`` recorded by the IE engine (whose default path
    keeps the trailing ``/``) the script's ``_ie_cookie_hook`` gives Python IE's path."""

    name: str
    value: str
    domain: str  # lower-case, no leading dot; the request host for host-only cookies
    host_only: bool
    path: str
    secure: bool = False
    http_only: bool = False
    expires: Optional[float] = None  # absolute epoch seconds; None = session cookie
    deletion: bool = False  # Max-Age <= 0 or an Expires date in the past: removes the cookie
    py_path: str = ""
    domain_is_host: bool = False  # a Domain attribute equal to the request host (host-only in browsers)


#: Without a usable clock (no recording time, no response Date) only dates before this count as "in
#: the past" - the usual way of deleting a cookie (``expires=Thu, 01 Jan 1970 00:00:00 GMT``).
_COOKIE_EPOCH_FLOOR = 946684800.0  # 2000-01-01
_MAX_AGE_RE = re.compile(r"^-?\d+$")
#: ``Set-Cookie`` attributes browsers ignore (RFC 6265 §5.2) but Python's http.cookiejar does not: an
#: empty / value-less / dots-only Domain, a Max-Age that is not an integer (Python drops the cookie) and
#: a value-less Path or one not starting with ``/`` (dropped, or stored where it is never sent).  The
#: generated ``_cookie_attr_hook`` removes exactly these (same pattern).
_IGNORED_COOKIE_ATTR_RE = re.compile(
    r";\s*(?:domain\s*(?:=[\s.]*)?|max-age\s*(?:=(?!\s*-?\d+\s*(?:;|$))[^;]*)?|path\s*(?:=\s*[^\s;/][^;]*)?)(?=;|$)",
    re.I)
_COOKIE_PATH_ATTR_RE = re.compile(r";\s*path\s*=\s*/", re.I)  # a usable Path attribute

#: Cookie rules of the recording browser.  ``rfc6265``: RFC 6265 (Chrome / Edge / Firefox HAR
#: files).  ``wininet``: the IE engine (reqrec's recording browser, Edge IE mode, IE11 HAR files), as
#: observed on Windows 11: a ``Path`` matches as a plain prefix (``/app`` reaches ``/application``),
#: the default path keeps its trailing ``/``, a cookie without ``Domain`` reaches sub-domains too,
#: ``Domain=<name without a dot>`` is refused, and host-only / ``Domain=<host>`` are one cookie.
COOKIE_PROFILES = ("rfc6265", "wininet")


def cookie_profile_for(recording: "Recording") -> str:
    """``"wininet"`` for recordings of the IE engine (reqrec's recording browser, or a HAR whose
    requests carry an IE ``User-Agent``), else ``"rfc6265"``."""
    meta = recording.meta if isinstance(recording.meta, dict) else {}
    if str(meta.get("source") or "").lower() == "recbrowser":
        return "wininet"
    for flow in recording.flows[:50]:
        agent = flow.request.header("user-agent") or ""
        if "Trident/" in agent or "MSIE " in agent:
            return "wininet"
    return "rfc6265"


def _cookie_host(url: str) -> str:
    """Lower-case host of ``url`` without port (cookies ignore ports, RFC 6265 §8.5)."""
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
    except ValueError:
        return False
    return True


def cookie_domain_match(host: str, domain: str) -> bool:
    """RFC 6265 §5.1.3: ``host`` equals ``domain`` or is a sub-domain of it; an IP address only
    matches itself."""
    host = (host or "").lower().rstrip(".")
    domain = (domain or "").lower().lstrip(".").rstrip(".")
    if not host or not domain:
        return False
    if host == domain:
        return True
    return host.endswith("." + domain) and not _is_ip_host(host)


def cookie_default_path(url: str, profile: str = "rfc6265") -> str:
    """The default path of a cookie set without ``Path``: RFC 6265 §5.1.4 (the request path up to, not
    including, its last ``/``; Python's cookie jar does the same) or, for ``wininet``, up to and
    including it (``/app/login.aspx`` -> ``/app/``)."""
    try:
        path = urlsplit(url).path
    except ValueError:
        return "/"
    if not path.startswith("/"):
        return "/"
    if profile == "wininet":
        return path[: path.rfind("/") + 1] or "/"
    if path.count("/") <= 1:
        return "/"
    return path[: path.rfind("/")]


def cookie_path_match(request_path: str, cookie_path: str, profile: str = "rfc6265") -> bool:
    """RFC 6265 §5.1.4 path-match; for ``wininet`` a plain, case-sensitive prefix test."""
    request_path = request_path or "/"
    cookie_path = cookie_path or "/"
    if profile == "wininet":
        return request_path.startswith(cookie_path)
    if request_path == cookie_path:
        return True
    if request_path.startswith(cookie_path):
        return cookie_path.endswith("/") or request_path[len(cookie_path):len(cookie_path) + 1] == "/"
    return False


def cookie_scope_url(url: str, path: Optional[str]) -> str:
    """``scheme://host[:port]`` of ``url`` followed by the cookie ``path``: a URL the cookie is sent
    to, used by the generated script to pick the cookie out of the jar (``_cookie``) or to store
    it there (``_set_cookie``)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    return urlunsplit((parts.scheme or "http", parts.netloc, path or "/", "", ""))


def _cookie_date(text: str) -> Optional[float]:
    """Epoch seconds of a cookie / HTTP date (RFC 1123, RFC 850 with dashes, asctime ...)."""
    import http.cookiejar  # stdlib; imported on first use

    try:
        return http.cookiejar.http2time(str(text).strip())
    except Exception:  # pragma: no cover - defensive
        return None


def set_cookie_lines(response: Optional["RecordedResponse"]) -> list[str]:
    """Every ``Set-Cookie`` value of a response; a value some exporters joined with line breaks is
    split (a cookie line never contains one)."""
    if response is None:
        return []
    out: list[str] = []
    for raw in response.set_cookies:
        out.extend(line for line in str(raw).replace("\r", "\n").split("\n") if line.strip())
    return out


def parse_set_cookie_attrs(raw: Optional[str], request_url: str, clock: Optional[float] = None,
                           profile: str = "rfc6265") -> Optional[SetCookieInfo]:
    """Parse one ``Set-Cookie`` value the way the recording browser stores it for a response to
    ``request_url`` (see ``COOKIE_PROFILES``).

    Returns None for an unparsable header and for a cookie the browser ignores (a ``Domain`` the
    request host does not domain-match; for ``wininet`` also a ``Domain`` without an embedded dot).
    ``clock`` (epoch seconds of the recording) decides whether ``Expires`` lies in the past; without
    one only dates before 2000 count (the usual deletion idiom).  ``Max-Age`` wins over ``Expires``
    (RFC 6265 §5.3 step 3)."""
    parsed = parse_set_cookie(raw)
    if parsed is None:
        return None
    name, value = parsed
    host = _cookie_host(request_url)
    domain_attr: Optional[str] = None
    path_attr: Optional[str] = None
    secure = http_only = False
    max_age: Optional[int] = None
    expires: Optional[float] = None
    for part in str(raw).split(";")[1:]:
        key, _sep, val = part.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key == "domain":
            if val.strip("."):  # RFC 6265 §5.2.3: an empty Domain attribute is ignored
                domain_attr = val.strip().lstrip(".").lower()
        elif key == "path":
            path_attr = val if val.startswith("/") else None  # §5.2.4: otherwise the default-path
        elif key == "secure":
            secure = True
        elif key == "httponly":
            http_only = True
        elif key == "max-age":
            if _MAX_AGE_RE.match(val):
                max_age = int(val)
        elif key == "expires":
            when = _cookie_date(val)
            if when is not None:
                expires = when
    domain_is_host = False
    if domain_attr:
        if profile == "wininet" and "." not in domain_attr:
            return None  # IE refuses Domain=kanri / .kanri
        if not cookie_domain_match(host, domain_attr):
            return None  # RFC 6265 §5.3 step 6: a cookie for a foreign domain is ignored
        domain, host_only = domain_attr, False
        domain_is_host = domain_attr == host
    else:
        domain, host_only = host, True
    path = path_attr or cookie_default_path(request_url, profile)
    py_path = path  # IE's default path too: the script's _ie_cookie_hook gives it to Python's jar
    deletion = False
    absolute: Optional[float] = None
    if max_age is not None:
        if max_age <= 0:
            deletion = True
        elif clock is not None:
            absolute = clock + max_age
    elif expires is not None:
        if expires <= (clock if clock is not None else _COOKIE_EPOCH_FLOOR):
            deletion = True
        else:
            absolute = expires
    return SetCookieInfo(name=name, value=value, domain=domain, host_only=host_only, path=path, secure=secure,
                         http_only=http_only, expires=absolute, deletion=deletion, py_path=py_path,
                         domain_is_host=domain_is_host)


@dataclass(eq=False)
class CookieVersion:
    """One value of one cookie in the simulated browser jar.  The identity is ``key`` (name,
    domain, path); a later ``Set-Cookie`` with the same key starts a new version (``previous`` /
    ``replaced_by``).  ``origin`` is ``"server"`` (a ``Set-Cookie``) or ``"external"`` (sent by the
    browser although no recorded response set it in that scope: written by the page's script, there
    before the recording, or set by a response that was not recorded); ``external_kind`` tells
    ``"pre-existing"`` (sent before the host answered anything) from ``"script"``.  ``py_path`` is
    the path the generated script's jar stores (``_cookie`` / ``_set_cookie`` use it)."""

    name: str
    value: str
    domain: str
    host_only: bool
    path: str
    secure: bool = False
    expires: Optional[float] = None
    origin: str = "server"
    external_kind: str = ""
    flow: Optional[Flow] = None  # the flow whose response set it / whose request first sent it
    created: int = 0  # creation order of the key (RFC 6265 §5.4.2; kept when a value replaces another)
    seq: int = 0
    previous: Optional["CookieVersion"] = None
    replaced_by: Optional["CookieVersion"] = None
    ended_by: Optional[Flow] = None  # the flow that replaced / deleted it (None: alive to the end)
    sent_by: list[Flow] = field(default_factory=list)
    py_path: str = ""
    #: the browser was expected to send it but a request with cookies did not (blocked, expired in the
    #: browser, never really stored): not a source until a request sends it again
    held: bool = True

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.name, self.domain, self.path)

    @property
    def jar_path(self) -> str:
        return self.py_path or self.path

    def scope_url(self, base_url: Optional[str] = None) -> str:
        """A URL this cookie is sent to: ``base_url``'s (default: the setting flow's) scheme and
        host with the cookie path (as the generated script's jar stores it)."""
        base = base_url or (self.flow.request.url if self.flow is not None else "")
        return cookie_scope_url(base, self.jar_path)


def _infer_cookie_path(sent_paths: Sequence[str], unsent_paths: Sequence[str]) -> str:
    """The shallowest cookie path that path-matches every request path that carried a cookie and
    none of the (same host, same lifetime) request paths that did not; the deepest common directory
    when the observations contradict each other.  RFC 6265 path-match (the generated script's jar)."""
    dirs: list[list[str]] = []
    for path in sent_paths:
        directory = cookie_default_path("http://h" + (path if str(path).startswith("/") else "/" + str(path)))
        dirs.append([s for s in directory.split("/") if s])
    common: list[str] = []
    for parts in zip(*dirs) if dirs else ():
        if all(p == parts[0] for p in parts):
            common.append(parts[0])
        else:
            break
    candidates = ["/"] + ["/" + "/".join(common[:i]) for i in range(1, len(common) + 1)]
    for candidate in candidates:
        if not any(cookie_path_match(p, candidate) for p in unsent_paths):
            return candidate
    return candidates[-1]


def _shared_folder(a: tuple[str, ...], b: tuple[str, ...]) -> tuple[str, ...]:
    """The leading folder segments ``a`` and ``b`` have in common."""
    n = 0
    while n < len(a) and n < len(b) and a[n] == b[n]:
        n += 1
    return a[:n]


def _request_path(flow: Flow) -> str:
    """The request path without ``;name=value`` path parameters (a session id there is never part of a
    cookie path the script would write)."""
    try:
        path = urlsplit(flow.request.url).path or "/"
    except ValueError:
        return "/"
    return "/".join(seg.split(";", 1)[0] for seg in path.split("/")) or "/"


class CookieTimeline:
    """The recording browser's cookie jar replayed over a recording, driven by the recorded
    ``Set-Cookie`` headers and checked against the recorded ``Cookie`` headers.

    ``profile`` selects the browser's cookie rules (``COOKIE_PROFILES``: RFC 6265, or WinINet for the
    IE engine).  Every flow - kept and dropped, redirect and 401 hops, in recording order - is
    processed in two phases.  The request phase matches each recorded ``Cookie`` pair to a cookie the
    jar holds for that URL (domain match, path match, Secure, expiry; longest path first): such a pair
    is *explained* and carries its cookie identity.  A pair equal to a cookie of that name the jar
    holds for the host under another path is a *leak* of that cookie (a browser quirk) and is
    explained by it too.  Anything else becomes an *external* version (written by the page's script,
    there before the recording, or set by an unrecorded response); a new external value of a name
    replaces the old one when the request no longer sends the old one and one path fits both.  A cookie
    the jar should have sent but a request with cookies did not is marked not held until it is sent
    again.  The response
    phase applies the ``Set-Cookie`` headers (store / replace / delete).  The clock is the recording
    time, so cookies that were valid while recording never count as expired.

    After the walk each external version gets the narrowest scope consistent with where it was and was
    not sent (``_infer_cookie_path``; one scope for the values the page wrote over each other), and
    adopts the domain / path of a later server ``Set-Cookie`` of the same name that took its place on
    that host (the browser replaced it, so both had the same identity).  An external value sent in place
    of a cookie the jar holds (the page's script overwrote it), and one a ``Set-Cookie`` deletes or
    replaces, takes that cookie's identity at once."""

    def __init__(self, flows: Sequence[Flow], profile: str = "rfc6265") -> None:
        self.flows: list[Flow] = list(flows)
        self.profile = profile if profile in COOKIE_PROFILES else "rfc6265"
        self.versions: list[CookieVersion] = []
        self.externals: list[CookieVersion] = []
        #: hosts whose responses set cookies with ``Domain=<that host>``: Python keeps those apart from
        #: the host-only cookie of the same name (browsers do not), see the generated ``_host_cookie_hook``
        self.domain_is_host_hosts: set[str] = set()
        #: hosts without a dot that set cookies with ``Domain=<host>`` (accepted by RFC browsers; Python's
        #: jar never sends them back)
        self.dotless_domain_hosts: set[str] = set()
        #: hosts whose ``Set-Cookie`` lines carry attributes browsers ignore but Python does not
        #: (``_IGNORED_COOKIE_ATTR_RE``), and (IE engine) hosts that set cookies without ``Path`` below the
        #: root: see ``_hook_hosts``
        self.malformed_cookie_hosts: set[str] = set()
        self.ie_default_path_hosts: set[str] = set()
        #: IE engine: ``(host, cookie key)`` of each line that sets / deletes ``Domain=<a parent domain>``
        self.parent_domain_lines: list[tuple[str, tuple[str, str, str]]] = []
        #: hosts whose response sets a cookie and then deletes it again (``_hook_hosts``)
        self.repeated_cookie_hosts: set[str] = set()
        self._jar: dict[tuple[str, str, str], CookieVersion] = {}
        self._externals_live: list[CookieVersion] = []
        self._sent: dict[int, list[tuple[str, str, CookieVersion]]] = {}
        self._live: dict[int, list[CookieVersion]] = {}
        self._stored: dict[int, list[CookieVersion]] = {}
        self._index: dict[int, int] = {}
        self._answered_hosts: set[str] = set()
        self._seq = 0
        #: externals whose identity is known (the cookie the page's script overwrote, the Set-Cookie that
        #: deleted / replaced them): kept in the jar under it and never re-inferred
        self._scoped: set[int] = set()
        #: a value the page wrote over other externals -> ``(folders, unsent)`` of those (``_chain_scope``)
        self._chains: dict[int, tuple[tuple[str, ...], list[str]]] = {}
        #: per flow position: the request's cookie host, path and folder (segments), for the window scans
        self._hosts = [_cookie_host(f.request.url) for f in self.flows]
        self._paths = [_request_path(f) for f in self.flows]
        self._folders = [tuple(s for s in cookie_default_path("http://h" + p).split("/") if s) for p in self._paths]
        for pos, flow in enumerate(self.flows):
            self._index[id(flow)] = pos
            clock = self._clock(flow)
            self._request_phase(flow, clock)
            if flow.response is not None:
                self._response_phase(flow, clock)
                self._answered_hosts.add(_cookie_host(flow.request.url))
        self._infer_external_scopes()

    # ------------------------------------------------------------------ queries

    def position(self, flow: Flow) -> int:
        return self._index.get(id(flow), -1)

    def sent_with(self, flow: Flow) -> list[tuple[str, str, CookieVersion]]:
        """``(name, value, version)`` for every cookie the flow's request sent, in header order."""
        return list(self._sent.get(id(flow), ()))

    def live_at(self, flow: Flow) -> list[CookieVersion]:
        """Every cookie the browser held when the flow's request was sent (all hosts and paths)."""
        return list(self._live.get(id(flow), ()))

    def stored_by(self, flow: Flow) -> list[CookieVersion]:
        """The cookie versions the flow's response stored (``Set-Cookie``, deletions excluded)."""
        return list(self._stored.get(id(flow), ()))

    def _host_match(self, host: str, ver: CookieVersion) -> bool:
        if self.profile == "wininet" or not ver.host_only:
            return cookie_domain_match(host, ver.domain)
        return host == ver.domain

    def cookies_for(self, url: str, clock: Optional[float] = None) -> list[CookieVersion]:
        """The cookies the jar sends to ``url`` now, longest path first."""
        host = _cookie_host(url)
        try:
            parts = urlsplit(url)
        except ValueError:
            return []
        path = parts.path or "/"
        https = (parts.scheme or "").lower() == "https"
        out: list[CookieVersion] = []
        for ver in list(self._jar.values()) + self._externals_live:
            if not self._host_match(host, ver):
                continue
            if not cookie_path_match(path, ver.path, self.profile):
                continue
            if ver.secure and not https:
                continue
            if ver.expires is not None and clock is not None and ver.expires <= clock:
                continue
            out.append(ver)
        out.sort(key=lambda v: (-len(v.path), v.created))
        return out

    def switch_events(self, kept: set[int]) -> list[tuple[Flow, CookieVersion, str, CookieVersion]]:
        """Session switches among kept flows (``id(flow)`` in ``kept``): ``(flow, new version, kind,
        previous version)``.  ``"rotation"``: the response gave a cookie identity that was in use a
        new value that later requests send; ``"context"``: it issued a cookie whose name was in use
        in another scope.  Cookies whose every value is sent at most once by kept requests (a value
        refreshed on each response) are not switches."""
        out: list[tuple[Flow, CookieVersion, str, CookieVersion]] = []
        for ver in self.versions:
            if ver.origin != "server" or ver.flow is None or id(ver.flow) not in kept:
                continue
            if not any(id(f) in kept for f in ver.sent_by) or self._volatile(ver, kept):
                continue
            pos = self.position(ver.flow)
            prev = ver.previous
            if prev is not None:
                if prev.value != ver.value and any(id(f) in kept for f in prev.sent_by):
                    out.append((ver.flow, ver, "rotation", prev))
                continue
            rivals = [
                v for v in self.versions
                if v is not ver and v.name == ver.name and v.seq < ver.seq and v.value != ver.value
                and (v.ended_by is None or self.position(v.ended_by) >= pos)
                and any(id(f) in kept and self.position(f) < pos for f in v.sent_by)
            ]
            if rivals:
                rival = rivals[-1]
                out.append((ver.flow, ver, "rotation" if rival.key == ver.key else "context", rival))
        return out

    # ------------------------------------------------------------------ the walk

    @staticmethod
    def _clock(flow: Flow) -> Optional[float]:
        """The client's clock (the recording time); the response ``Date`` only without one."""
        if flow.started_at:
            return flow.started_at
        date = flow.response.header("date") if flow.response is not None else None
        return _cookie_date(date) if date else None

    def _leak_source(self, flow: Flow, name: str, value: str, taken: set[int]) -> Optional[CookieVersion]:
        """A cookie of that name and value the browser holds for this host under another path (or a
        parent domain): the browser sent it outside the scope our rules give it.  Never a host-only
        cookie a response of another host set, for an RFC 6265 browser: it never sends one there, so the
        pair is this host's own cookie with the same value (``lang=ja``)."""
        host = _cookie_host(flow.request.url)
        for ver in list(self._jar.values()) + self._externals_live:
            if id(ver) in taken or ver.name != name or ver.value != value:
                continue
            if self.profile != "wininet" and ver.origin == "server" and ver.host_only and ver.domain != host:
                continue
            if cookie_domain_match(host, ver.domain):
                return ver
        return None

    def _request_phase(self, flow: Flow, clock: Optional[float]) -> None:
        predicted = self.cookies_for(flow.request.url, clock)
        pairs = [p for raw in header_get_all(flow.request.headers, "cookie") for p in parse_cookie_header(raw)]
        taken: set[int] = set()
        sent: list[list[Any]] = []
        host = _cookie_host(flow.request.url)
        for name, value in pairs:
            match = next((v for v in predicted if id(v) not in taken and v.name == name and v.value == value), None)
            if match is None:
                match = self._leak_source(flow, name, value, taken)
            if match is None:
                # a pre-existing / script cookie first sent to a sub-domain of this host: one cookie of this
                # (parent) domain reaches both (the IE engine sends host-only cookies to sub-domains too)
                match = next((v for v in self._externals_live if id(v) not in taken and v.name == name and v.value == value
                              and v.domain != host and cookie_domain_match(v.domain, host)), None)
                if match is not None:
                    match.domain, match.host_only = host, self.profile == "wininet"
                    if pairs.count((name, value)) == 1:
                        # the value first sent to other sub-domains of this host too is that one cookie (never when
                        # one request sent both, or the page wrote it over another value): one cookie in the script
                        for other in [v for v in self._externals_live if v is not match and id(v) not in taken
                                      and v.name == name and v.value == value and v.domain != host
                                      and cookie_domain_match(v.domain, host) and v.previous is None and v.replaced_by is None
                                      and not {id(f) for f in v.sent_by} & {id(f) for f in match.sent_by}]:
                            self._merge_external(other, match)
            if match is not None:
                taken.add(id(match))
            sent.append([name, value, match])
        fresh: list[CookieVersion] = []
        for entry in sent:
            if entry[2] is None:
                entry[2] = self._new_external(flow, entry[0], entry[1])
                fresh.append(entry[2])
        sent_ids = {id(entry[2]) for entry in sent}
        predicted_ids = {id(v) for v in predicted}
        for ver in fresh:
            # the page's script overwrote a cookie the jar holds for this URL (sent in its place): the new
            # value has that cookie's identity and is set right before the step (never INITIAL_COOKIES)
            target = next((v for v in predicted if v.name == ver.name and id(v) not in sent_ids
                           and self._jar.get(v.key) is v), None)
            if target is not None:
                self._settle(ver, target.domain, target.host_only, target.path, target.jar_path)
                ver.created, ver.previous, ver.external_kind = target.created, target, "script"
                target.ended_by, target.replaced_by = flow, ver
                continue
            # the page wrote a new value for the name: the old value is not sent any more (the same cookie:
            # the new value keeps its domain - with the IE engine a cookie of the parent host).  Not when no one
            # path fits both: then the old value's own path keeps it off this request (another cookie)
            for old in list(self._externals_live):
                if (old is not ver and old.name == ver.name and id(old) not in sent_ids and id(old) in predicted_ids
                        and self._one_scope(old, flow)):
                    old.ended_by, old.replaced_by = flow, ver
                    self._externals_live.remove(old)
                    if ver.previous is None:
                        ver.previous, ver.created, ver.external_kind = old, old.created, "script"
                        ver.domain, ver.host_only = old.domain, old.host_only
                        folders, unsent = self._chain_scope(old)
                        self._chains[id(ver)] = (folders, unsent + list(self._unsent(old, self.position(flow))))
        for entry in sent:
            entry[2].sent_by.append(flow)
            entry[2].held = True
        if pairs:
            # a request that carried cookies but not one the rules say it should have: the browser did
            # not hold that one (blocked, expired in the browser ...)
            for ver in predicted:
                if id(ver) not in sent_ids:
                    ver.held = False
        self._sent[id(flow)] = [(entry[0], entry[1], entry[2]) for entry in sent]
        live = list(self._jar.values()) + list(self._externals_live)
        self._live[id(flow)] = [v for v in live if v.held and (v.expires is None or clock is None or v.expires > clock)]

    def _new_external(self, flow: Flow, name: str, value: str) -> CookieVersion:
        host = _cookie_host(flow.request.url)
        self._seq += 1
        ver = CookieVersion(
            name=name, value=value, domain=host, host_only=True, path="/", origin="external",
            external_kind="script" if host in self._answered_hosts else "pre-existing",
            flow=flow, created=self._seq, seq=self._seq,
        )
        self._externals_live.append(ver)
        self.versions.append(ver)
        self.externals.append(ver)
        return ver

    def _merge_external(self, other: CookieVersion, into: CookieVersion) -> None:
        """``other`` (an external a sibling sub-domain sent) is the external ``into``: its requests sent ``into``."""
        known = {id(f) for f in into.sent_by}
        into.sent_by = sorted(into.sent_by + [f for f in other.sent_by if id(f) not in known], key=self.position)
        for f in other.sent_by:
            self._sent[id(f)] = [(n, v, into if ver is other else ver) for n, v, ver in self._sent.get(id(f), ())]
        for key, live in self._live.items():
            if other in live:
                self._live[key] = [v for v in live if v is not other] if into in live else [into if v is other else v for v in live]
        into.held = into.held or other.held
        for pool in (self._externals_live, self.externals, self.versions):
            if other in pool:
                pool.remove(other)

    def _response_phase(self, flow: Flow, clock: Optional[float]) -> None:
        stored: list[CookieVersion] = []
        host = _cookie_host(flow.request.url)
        for raw in set_cookie_lines(flow.response):
            info = parse_set_cookie_attrs(raw, flow.request.url, clock, self.profile)
            if info is None:
                continue
            key = (info.name, info.domain, info.path)
            old = self._jar.get(key)
            if old is None:
                old = self._external_ended_by(flow, info)  # a pre-existing / script cookie this line ends
            if info.deletion:
                if old is not None:
                    old.ended_by = flow
                    del self._jar[key]
                continue
            self._seq += 1
            ver = CookieVersion(
                name=info.name, value=info.value, domain=info.domain, host_only=info.host_only, path=info.path,
                secure=info.secure, expires=info.expires, origin="server", flow=flow,
                created=old.created if old is not None else self._seq, seq=self._seq, previous=old,
                py_path=info.py_path,
            )
            if old is not None:
                old.ended_by, old.replaced_by = flow, ver
            self._jar[key] = ver
            self.versions.append(ver)
            stored.append(ver)
        self._stored[id(flow)] = stored
        self._hook_hosts(flow, host)

    def _hook_hosts(self, flow: Flow, host: str) -> None:
        """Register the hosts whose ``Set-Cookie`` lines (deletions included) the generated script's response
        hooks rewrite, so that Python's jar stores, replaces and deletes the cookies the recording browser
        did: ``Domain=<that host>`` (dot-less hosts too: Python never sends those back by itself),
        attributes browsers ignore, and for the IE engine a missing ``Path`` below the root and
        ``Domain=<a parent domain>`` (one cookie with the parent host's own one: the builder decides).  Also a
        cookie one response sets and then deletes (Python's jar applies the deletion first)."""
        url = flow.request.url
        clock = self._clock(flow)
        set_here: set[tuple[str, str, str]] = set()  # the cookies this response set so far
        for raw in set_cookie_lines(flow.response):
            info = parse_set_cookie_attrs(raw, url, clock, self.profile)
            if info is None:
                continue
            # one response sets a cookie and then deletes it: browsers apply the lines in order, Python's jar applies
            # the deletion first and keeps the cookie - the host hooks keep the last line of a cookie
            if info.deletion and (info.name, info.domain, info.path) in set_here:
                self.repeated_cookie_hosts.add(host)
            elif not info.deletion:
                set_here.add((info.name, info.domain, info.path))
            if info.domain_is_host:
                self.domain_is_host_hosts.add(host)
                if "." not in host and not _is_ip_host(host):
                    self.dotless_domain_hosts.add(host)
            if _IGNORED_COOKIE_ATTR_RE.search(raw):
                self.malformed_cookie_hosts.add(host)
            if self.profile == "wininet" and not _COOKIE_PATH_ATTR_RE.search(raw) and info.path != cookie_default_path(url):
                self.ie_default_path_hosts.add(host)
            if self.profile == "wininet" and not info.host_only and not info.domain_is_host:
                self.parent_domain_lines.append((host, (info.name, info.domain, info.path)))

    def _volatile(self, ver: CookieVersion, kept: Optional[set[int]] = None) -> bool:
        """A cookie identity whose value changes on (almost) every response: three or more values,
        none of them sent more than once (by kept requests, when ``kept`` is given)."""
        chain: list[CookieVersion] = []
        cur: Optional[CookieVersion] = ver
        while cur is not None and len(chain) < 64:
            chain.append(cur)
            cur = cur.previous
        cur = ver.replaced_by
        while cur is not None and len(chain) < 128:
            chain.append(cur)
            cur = cur.replaced_by

        def uses(v: CookieVersion) -> int:
            return sum(1 for f in v.sent_by if kept is None or id(f) in kept)

        return len(chain) >= 3 and all(uses(v) <= 1 for v in chain)

    def _infer_external_scopes(self) -> None:
        def rewrite(ver: Optional[CookieVersion], prev: Optional[CookieVersion]) -> bool:
            # ``ver`` is a value the page's script wrote over ``prev``, another pre-existing / script cookie
            return (ver is not None and prev is not None and ver.previous is prev and prev.replaced_by is ver
                    and ver.origin == prev.origin == "external")

        for ver in self.externals:
            if id(ver) in self._scoped or rewrite(ver, ver.previous):
                continue  # its identity is known (``_settle``) / the one of the value it replaced (below)
            chain = [ver]  # with the values the page's script wrote over it later: one cookie, one identity
            while rewrite(chain[-1].replaced_by, chain[-1]):
                chain.append(chain[-1].replaced_by)
            known = next((link for link in chain if id(link) in self._scoped), None)  # a later value's is known
            if known is None:
                sent_paths: list[str] = []
                unsent_paths: list[str] = []
                for link in chain:
                    sent_paths += [_request_path(f) for f in link.sent_by]
                    unsent_paths += self._unsent(link, self.position(link.ended_by) if link.ended_by is not None else len(self.flows))
                known = chain[-1]
                known.path = _infer_cookie_path(sent_paths, unsent_paths)
                known.py_path = known.path
                self._adopt_server_scope(known)
            for link in chain:
                if id(link) not in self._scoped:
                    link.domain, link.host_only, link.path, link.py_path = known.domain, known.host_only, known.path, known.py_path

    def _adopt_server_scope(self, ver: CookieVersion) -> None:
        """A later server cookie of the same name took this external value's place on its host: the
        browser replaced it, so the external value had that cookie's identity."""
        host = ver.domain
        for later in self.versions:
            if later.origin != "server" or later.name != ver.name or later.seq <= ver.seq or later.flow is None:
                continue
            set_pos = self.position(later.flow)
            evidence = [
                f for f in later.sent_by
                if self.position(f) > set_pos and _cookie_host(f.request.url) == host
                and cookie_path_match(_request_path(f), ver.path) and ver not in [s[2] for s in self._sent.get(id(f), ())]
            ]
            if not evidence:
                continue
            if any(self.position(f) > set_pos for f in ver.sent_by):
                continue  # still sent next to the server cookie: a different identity
            ver.domain, ver.host_only, ver.path, ver.py_path = later.domain, later.host_only, later.path, later.jar_path
            if ver.ended_by is None or self.position(ver.ended_by) > set_pos:
                ver.ended_by, ver.replaced_by = later.flow, later
            if later.previous is None:
                later.previous = ver
            return

    def _settle(self, ext: CookieVersion, domain: str, host_only: bool, path: str, py_path: str) -> None:
        """Give an external cookie a known identity and keep it in the jar under it (a later
        ``Set-Cookie`` of that identity replaces / deletes it like any cookie)."""
        if ext in self._externals_live:
            self._externals_live.remove(ext)
        ext.domain, ext.host_only, ext.path, ext.py_path = domain, host_only, path, py_path
        self._jar[ext.key] = ext
        self._scoped.add(id(ext))

    def _unsent(self, ext: CookieVersion, end: int) -> Iterator[str]:
        """The paths of the requests of its hosts that did not send an external cookie, from its first
        request up to flow position ``end``.  The IE engine sends every cookie that applies; an RFC 6265
        browser leaves cookies off cross-site requests, so there only requests with cookies count."""
        start = self.position(ext.flow) if ext.flow is not None else 0
        sent = {self.position(f) for f in ext.sent_by}
        return (self._paths[i] for i in range(start, end)
                if i not in sent and (self.profile == "wininet" or self.flows[i].request.header("cookie"))
                and self._host_match(self._hosts[i], ext))

    def _one_scope(self, old: CookieVersion, flow: Flow) -> bool:
        """Whether a value first sent by ``flow`` can be the external ``old`` (with the values the page
        wrote before it) written over: one path reaches every request that sent them and this one, and
        none of the requests that did not send them so far (no path fits when the deepest folder holding
        the first ones holds one of the others)."""
        pos = self.position(flow)
        folders, unsent = self._chain_scope(old)
        folder = "/" + "/".join(_shared_folder(folders, self._folders[pos]))
        return not any(cookie_path_match(p, folder) for p in unsent) and not any(
            cookie_path_match(p, folder) for p in self._unsent(old, pos))

    def _chain_scope(self, ext: CookieVersion) -> tuple[tuple[str, ...], list[str]]:
        """The folder (segments) holding every request that sent the external ``ext`` or the values the
        page wrote before it, and the paths of the requests that did not send those earlier values (kept
        for each value when it is written over: a long chain is walked once)."""
        folders, unsent = self._chains.get(id(ext), (None, []))
        for f in ext.sent_by:
            mine = self._folders[self.position(f)]
            folders = mine if folders is None else _shared_folder(folders, mine)
        return folders or (), unsent

    def _external_ended_by(self, flow: Flow, info: SetCookieInfo) -> Optional[CookieVersion]:
        """A live external cookie (there before the recording / written by the page) that this
        ``Set-Cookie`` deletes or replaces: same name, sent (from its first request up to this one)
        exactly by the requests the line's identity reaches, and no later request sends its value again
        (before a response sets that value again).  The browser replaced it, so it had the line's
        identity: it moves into the jar under it.  A cookie of a parent domain first sent to two sibling
        hosts is an external on each: the live externals with its value are tried together first (never
        those a request sent together: two cookies)."""

        def in_scope(i: int) -> bool:
            host = self._hosts[i]
            if not (host == info.domain if info.host_only and self.profile != "wininet" else cookie_domain_match(host, info.domain)):
                return False
            return cookie_path_match(self._paths[i], info.path, self.profile)

        def ends(members: list[CookieVersion]) -> bool:
            sent = {self.position(f) for ext in members for f in ext.sent_by}
            start = min(self.position(ext.flow) if ext.flow is not None else 0 for ext in members)
            if any((i in sent) != in_scope(i) for i in range(start, pos + 1)):
                return False
            value = members[0].value
            if info.deletion or info.value != value:  # a re-set to the same value: later sends are the new one's
                for later in self.flows[pos + 1:]:
                    pairs = [p for raw in header_get_all(later.request.headers, "cookie") for p in parse_cookie_header(raw)]
                    if (info.name, value) in pairs:  # still sent (on another host: a cookie of a parent domain)
                        return False
                    if (info.name, value) in [parse_set_cookie(line) for line in set_cookie_lines(later.response)]:
                        break
            return True

        def host_only(ext: CookieVersion, members: list[CookieVersion]) -> bool:
            # Domain=<host> is one identity with that host's host-only cookie (the script's hooks delete the other
            # copy): an external only that host ever sent stays host-only, as the browser held it
            return info.host_only or (info.domain_is_host and len(members) == 1 and ext.domain == info.domain
                                      and all(self._hosts[self.position(f)] == ext.domain for f in ext.sent_by))

        pos = self.position(flow)
        named = [ext for ext in self._externals_live if ext.name == info.name]
        for ext in named:
            group = [other for other in named if other.value == ext.value]
            apart = len({id(f) for other in group for f in other.sent_by}) == sum(len(other.sent_by) for other in group)
            for members in ([group, [ext]] if len(group) > 1 and apart else [[ext]]):
                if ends(members):
                    for other in members:
                        if other is not ext:  # one cookie: ends here too
                            self._settle(other, info.domain, host_only(other, members), info.path, info.py_path)
                            other.ended_by = flow
                    self._settle(ext, info.domain, host_only(ext, members), info.path, info.py_path)
                    return ext
        return None

    def script_scope(self, ver: CookieVersion, url: str) -> tuple[str, Optional[str]]:
        """``(url, domain)`` with which the generated script stores ``ver`` (``_set_cookie``,
        ``INITIAL_COOKIES``) for a request to ``url``.  ``domain`` is None (host-only, ``url`` on the
        cookie's own host) for a host-only cookie and for a cookie of a host without a dot (Python never
        sends a ``Domain=<dot-less host>`` cookie back).  A ``Domain=<host>`` cookie stays a domain cookie:
        the script's ``_host_cookie_hook`` deletes the other copy when the server sets either, so the jar
        never holds both (the stale one would be sent first)."""
        host = _cookie_host(url)
        host_only = ver.host_only or "." not in ver.domain
        if host_only and ver.domain and ver.domain != host:
            try:
                scheme = urlsplit(url).scheme or "http"
            except ValueError:
                scheme = "http"
            url = f"{scheme}://{'[' + ver.domain + ']' if ':' in ver.domain else ver.domain}/"
        return cookie_scope_url(url, ver.jar_path), None if host_only else ver.domain


def initial_cookie_for(ver: CookieVersion, first_sender: Optional[Flow] = None,
                       timeline: Optional[CookieTimeline] = None) -> InitialCookie:
    """The ``InitialCookie`` that recreates an external cookie version at run time (stored as
    ``CookieTimeline.script_scope`` decides when ``timeline`` is given)."""
    base = (first_sender or ver.flow).request.url if (first_sender or ver.flow) is not None else ""
    url, domain = timeline.script_scope(ver, base) if timeline is not None else (
        cookie_scope_url(base, ver.jar_path), None if ver.host_only else ver.domain)
    return InitialCookie(
        name=ver.name, value=ver.value, domain=ver.domain, path=ver.jar_path,
        url=url, host_only=domain is None,
        origin=ver.external_kind or "pre-existing",
    )


def _page_writes_cookie(flow: Flow, name: str, value: str) -> bool:
    """Whether the response is a page or a script holding ``value`` next to the cookie's name and the
    word ``cookie`` (a script writing ``document.cookie``), not the value echoed in data."""
    resp = flow.response
    if resp is None or not resp.body or not value:
        return False
    mime = (resp.mime_type or "").lower()
    if not (mime in ("text/html", "application/xhtml+xml") or "javascript" in mime or "ecmascript" in mime):
        return False
    text = resp.text() or ""
    at = text.find(value)
    while at >= 0:
        around = text[max(0, at - 300):at + len(value) + 300]
        if name in around and "cookie" in around.lower():
            return True
        at = text.find(value, at + 1)
    return False


def classify_cookies(flows: list[Flow], profile: str = "rfc6265") -> tuple[list[InitialCookie], set[str]]:
    """Cookies the browser sent although no earlier response set them in that scope (pre-existing or
    written by the page; copies of a cookie the jar already held under another scope excluded) and
    the names of the cookies responses set.  See ``CookieTimeline``."""
    timeline = CookieTimeline(flows, profile)
    initial: list[InitialCookie] = []
    for ver in timeline.externals:
        live = timeline.live_at(ver.flow) if ver.flow is not None else []
        if any(v.origin == "server" and v.name == ver.name and v.value == ver.value for v in live):
            continue
        initial.append(initial_cookie_for(ver, timeline=timeline))
    managed = {v.name for v in timeline.versions if v.origin == "server"}
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
        traceable = lname not in _SKIP_HEADER_EXACT and not lname.startswith(_SKIP_HEADER_PREFIXES)
        if traceable and is_dynamic_looking(split_auth_header(value)[1]):
            continue  # a token sent with every request is still a token: it stays per step and is traced
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


# ===== former reqrec/deps.py: dependency detection (candidates + locators) =====
# Dependency detection: which request values came from earlier responses.  Contract: DESIGN.md §5.
#
# Two halves:
#
# * **candidates** - every value a request sends that *could* have come from somewhere
#   (``find_candidates``), plus the shared request-body parsers used by the loops / plan sections;
# * **locators** - given a value and an earlier flow, build a stable ``Extractor`` that re-extracts
#   the value from that flow's response on the next run (``locate_value``), or find the cookie that
#   carries it (``find_cookie``).
#
# Locators are never keyed on the dynamic value itself and every regex is verified against the
# recorded text before it is returned.

# --------------------------------------------------------------------------- candidates

@dataclass
class Candidate:
    """A value sent by a request that may depend on an earlier response.

    ``prefix`` is set for scheme-prefixed headers (``Authorization: Bearer X`` -> value ``X``,
    prefix ``"Bearer "``) so the plan section can rebuild the header.  ``numeric`` marks JSON leaves that
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
        """The part's text: UTF-8, else (IE posts the text parts of a Shift_JIS page as cp932 bytes) a
        percent-encoded spelling like a urlencoded value's - never U+FFFD (``_Builder._field_text``
        decodes it with the page's charset)."""
        return _form_text(self.content, None)


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
    """Decode one form name / value: bytes that are UTF-8 are that text (they are replayed as UTF-8),
    else the declared charset; a value that is neither keeps a percent-encoded spelling so nothing is
    lost or garbled."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if charset and charset != "utf-8":
        try:
            return raw.decode(charset)
        except (UnicodeDecodeError, LookupError):
            pass
    return quote_from_bytes(raw, safe="")


_JS_ESCAPE_RE = re.compile(rb"%u[0-9A-Fa-f]{4}")
_JS_UNIT_RE = re.compile(rb"%u([0-9A-Fa-f]{4})|%([0-9A-Fa-f]{2})|(.)", re.S)


def js_unescape(spelling: bytes) -> Optional[str]:
    """The text of a value an old page script built with JavaScript ``escape()`` (``%u5C71%u7530`` =
    山田, which IIS / ASP.NET decode), from its spelling on the wire (not yet percent-decoded); None
    when the spelling has no ``%uXXXX``.  ``%XX`` is then a character code and ``+`` a space."""
    if not _JS_ESCAPE_RE.search(spelling):
        return None
    units = bytearray()
    for m in _JS_UNIT_RE.finditer(spelling):
        u4, x2, other = m.groups()
        code = int(u4, 16) if u4 else int(x2, 16) if x2 else (0x20 if other == b"+" else other[0])
        units += code.to_bytes(2, "little")
    try:
        return bytes(units).decode("utf-16-le")
    except UnicodeDecodeError:
        return None  # a lone surrogate


def parse_form_bytes(body: Optional[bytes], charset: Optional[str] = None) -> list[tuple[str, str]]:
    """``application/x-www-form-urlencoded`` bytes -> ordered ``(name, value)`` pairs.

    Equivalent to ``core.parse_form`` for UTF-8 bodies (blank values kept, repeated names kept,
    one pair per non-empty segment) but works on bytes: values in a legacy charset are decoded
    with ``charset`` when it is declared on the request, otherwise they stay percent-encoded.  A value
    built with ``escape()`` (``%uXXXX``) is its text (``js_unescape``)."""
    pairs: list[tuple[str, str]] = []
    for segment in split_form_segments(body):
        name_b, value_b = _form_segment_bytes(segment)
        text = js_unescape(segment.partition(b"=")[2])
        pairs.append((_form_text(name_b, charset), _form_text(value_b, charset) if text is None else text))
    return pairs


def request_form_charset(request: RecordedRequest) -> Optional[str]:
    """Normalised charset parameter of the request ``Content-Type`` (None when absent)."""
    ct = request.header("content-type")
    if not ct or not parse_content_type(ct)[1].get("charset"):
        return None
    return detect_charset(b"", ct)


def query_bytes(query: Optional[str]) -> bytes:
    """A recorded query string as bytes (a ``str`` URL keeps undecodable bytes as surrogates)."""
    if not query:
        return b""
    try:
        return query.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return query.encode("utf-8", "surrogatepass")


def is_utf8(raw: bytes) -> bool:
    """True when ``raw`` is valid UTF-8 (ASCII included): a value sent as UTF-8, not in a legacy charset."""
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _encodes_to(text: Any, charset: Optional[str], raw: bytes) -> bool:
    """Does ``text`` in ``charset`` give back exactly the recorded bytes?"""
    try:
        return isinstance(text, str) and bool(charset) and text.encode(charset) == raw
    except (UnicodeError, LookupError):
        return False


#: A request value already sent in a legacy charset (``var.encode('cp932')``, a value the page pre-filled).
_ENCODED_VAR_RE = re.compile(r"[A-Za-z_]\w*\.encode\('[\w-]+'\)")


def _legacy_text(raw: bytes, charset: Optional[str]) -> Optional[str]:
    """``raw`` decoded with a legacy ``charset`` when the text gives back exactly those bytes, else None."""
    if not charset or charset == "utf-8":
        return None
    try:
        text = raw.decode(charset)
    except (UnicodeDecodeError, LookupError):
        return None
    return text if _encodes_to(text, charset, raw) else None


def recorded_fields(req: RecordedRequest, location: str) -> list[tuple[str, str, bytes]]:
    """``(name, value, recorded value bytes)`` of the query string (``location="query"``), the
    ``application/x-www-form-urlencoded`` body (``"form"``) or the multipart text parts (``"multipart"``),
    in order, with the values ``request_params`` gives.  The bytes tell whether a value was sent in a
    legacy charset (they are not UTF-8), never ``%XX`` in its text: a typed ``%AB%`` is UTF-8 text."""
    if location == "query":
        data, charset = query_bytes(req.query), None
    elif location == "form" and req.body and req.content_type == "application/x-www-form-urlencoded":
        data, charset = req.body, request_form_charset(req)
    elif location == "multipart" and req.body and (req.content_type or "").startswith("multipart/"):
        return [(fld.name, fld.text(), fld.content) for fld in parse_multipart(req.body, req.header("content-type"))
                if not fld.is_file]
    else:
        return []
    return [(name, value, raw) for (name, value), (_n, raw) in zip(parse_form_bytes(data, charset), form_pairs_bytes(data))]


def _field_bytes(req: RecordedRequest, location: str, name: str, occurrence: int) -> Optional[bytes]:
    """The recorded bytes of the ``occurrence``-th query / form field called ``name`` (None if absent)."""
    found = [raw for n, _value, raw in recorded_fields(req, location) if n == name]
    return found[occurrence] if 0 <= occurrence < len(found) else None


def _field_list(names: Sequence[str]) -> str:
    """Field names for a warning (``a, b, c, d …``)."""
    names = list(dict.fromkeys(names))
    return ", ".join(names[:4]) + (" …" if len(names) > 4 else "")


def classify_body(request: RecordedRequest) -> tuple[str, Any]:
    """``(body_kind, parsed)`` for a request body.

    kinds: ``none``, ``form`` (ordered pairs), ``json`` (dict/list), ``multipart``
    (``MultipartField`` list), ``raw`` (``None``).

    A form in a legacy charset still classifies as ``form`` (its pairs are what dependency
    detection needs); the plan section checks ``form_body_is_utf8`` to decide whether the recorded
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
    textual = not ct or is_textual_mime(ct) or ct == "application/octet-stream"
    if is_json_mime(ct) or textual:
        if is_json_mime(ct) or b"\x00" not in body[:4096]:
            doc = parse_json_text(request.text())
            if doc is not None:
                return "json", doc
    return "raw", None


def split_path_segment(segment: str) -> tuple[str, list[tuple[str, Optional[str]]]]:
    """``"list.do;jsessionid=AB12;v"`` -> ``("list.do", [("jsessionid", "AB12"), ("v", None)])``.

    Path parameters (RFC 3986 §3.3 ``;name=value``) carry URL-embedded session ids
    (``;jsessionid=``) and similar one-time values; each one is its own dependency candidate.  A
    parameter without ``=`` has the value None (a flag that stays literal)."""
    base, *params = segment.split(";")
    out: list[tuple[str, Optional[str]]] = []
    for param in params:
        name, eq, value = param.partition("=")
        out.append((name, value if eq else None))
    return base, out


def request_params(flow: Flow) -> list[Candidate]:
    """Every parameter of a request as (unfiltered) ``Candidate`` objects, in a stable order:
    path segments (``;name=value`` path parameters as separate ``path_param`` candidates named
    ``"<segment index>;<name>"``), query pairs, then body values (form / JSON leaves / multipart text
    fields).  Header values are *not* included (see ``header_candidates``)."""
    req = flow.request
    out: list[Candidate] = []
    path = urlsplit(req.url).path
    segments = path.split("/")[1:] if path.startswith("/") else path.split("/")
    for idx, seg in enumerate(segments):
        if not seg:
            continue
        base, params = split_path_segment(seg)
        if base:
            out.append(Candidate("path", str(idx), base))
        for pname, pvalue in params:
            if pvalue:
                out.append(Candidate("path_param", f"{idx};{pname}", pvalue))
    # byte level, like form bodies: a value a Shift_JIS page sent keeps its percent-encoded spelling
    for name, value in parse_form_bytes(query_bytes(req.query)):
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


#: Request headers that never carry a value of an earlier response: protocol / browser headers, and
#: the Cookie header (cookies are analysed separately, ``CookieTimeline``).  ``If-Match`` /
#: ``If-Unmodified-Since`` are *not* here: they echo an earlier ``ETag`` / ``Last-Modified``.
_SKIP_HEADER_EXACT = frozenset(DROP_REQUEST_HEADERS) | frozenset({
    "user-agent", "referer", "origin", "cache-control", "pragma", "dnt", "priority", "content-type",
    "cookie", "x-requested-with", "upgrade-insecure-requests", "range",
    "via", "forwarded", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "date", "from",
    "max-forwards", "purpose", "service-worker", "save-data", "device-memory", "downlink", "ect", "rtt",
    "viewport-width", "width", "early-data", "alt-used", "content-md5",
})
_SKIP_HEADER_PREFIXES = ("accept", "sec-", "proxy-", ":")
#: The HTTP authentication schemes reqrec knows by name (their credentials may be an auth-param list).
_AUTH_SCHEME_RE = re.compile(r"^(\s*(?:Bearer|Basic|Digest|Token|JWT|Api-?Key|OAuth|Negotiate|NTLM)\s+)(\S.*?)\s*$", re.I)
#: Any other ``<scheme> <token68>`` value (RFC 7235 credentials: DPoP, SSWS, vendor schemes ...).
_GENERIC_CREDENTIALS_RE = re.compile(r"^(\s*[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*\s+)([A-Za-z0-9._~+/-]+=*)\s*$")


def split_auth_header(value: Optional[str]) -> tuple[str, str]:
    """``"Bearer X"`` -> ``("Bearer ", "X")``; any ``<scheme> <token68>`` value (``"DPoP X"``) is split
    the same way, so the token can be traced whatever the scheme is called; ``("", value)`` otherwise."""
    value = (value or "").strip()
    m = _AUTH_SCHEME_RE.match(value) or _GENERIC_CREDENTIALS_RE.match(value)
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
        else:
            # ``X-Auth: <scheme> <token>`` (any header, any scheme word): the token is the candidate
            # when it is long enough to be traced, the whole value otherwise
            m = _GENERIC_CREDENTIALS_RE.match(value)
            if m and len(m.group(2)) >= 8:
                prefix, value = m.group(1), m.group(2)
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
    menu markup) by coincidence, so the plan section only traces them through exact structural matches
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

    It stays a trace candidate - a short letters key such as ``/s/QZVBNMWRT/items`` can be a JSON
    leaf of an earlier response - but the plan section never traces it through markup
    (``html_attr`` / ``html_text`` / ``regex`` / ``url``): tracing ``Login.aspx`` to
    ``action="Login.aspx"`` would only make the script depend on that markup for a constant (a key
    a redirect handed out is the exception: ``_Builder._issued_by_redirect``)."""
    return cand.location == "path" and is_route_like(cand.value)


def find_candidates(flow: Flow, opts: PlanOptions) -> list[Candidate]:
    """All request values worth tracing to earlier responses (see DESIGN.md §5).

    Digits-only path segments are kept even when shorter than ``opts.min_value_length``: an id in
    the URL path almost always comes from an earlier JSON / HTML response (``org.id`` -> ``/orgs/77``).
    The plan section accepts only exact structural matches (JSON leaf, attribute, header ...) for such short
    values, never a regex, so a two-digit number cannot be traced by coincidence.  Route-like path
    segments (``is_structural_path_segment``) are candidates as well; the plan section restricts the
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


#: Consonant clusters that start a syllable (``str``, ``sch``) and that end one (``ght``, ``nds``) in
#: English and romaji words; any single consonant does both.  Every run of consonants inside a word is
#: the end of one syllable plus the start of the next (``pass|word|change``, ``kan|ri``, ``hac|chuu``),
#: which random letters (``QZVBNMWRTYPX``) almost never allow.
_SYLLABLE_STARTS = frozenset("""
bl br ch chr cl cr dr dw fl fr gh gl gn gr kl kn kr ph phr pl pr ps sc sch scr sh shr sk sl sm sn sp sph spl spr sq
st str sw th thr tr ts tw wh wr
""".split())
_SYLLABLE_END_STEMS = """
bt ch ck ct dd dg dth ff fth ft gg gh ght gn lb ld lf lk ll lm ln lp lt lth lv mb mn mp mph mpt mt nc nch nct nd ng
ngth nk nst nt nth nx nz ph pp pt pth rb rc rch rd rf rg rk rl rld rm rn rp rr rsh rst rt rth rv sc sch sh sk sp ss
st tch th tt tz wd wl wn xt xth zz
ghth lfth thm
""".split()
#: ... and with a plural / third-person ``-s`` (``nds``, ``mpts``, ``ds``)
_SYLLABLE_ENDS = frozenset(_SYLLABLE_END_STEMS + [c + "s" for c in _SYLLABLE_END_STEMS + list("bcdfgklmnprtvw")
                                                   if not c.endswith(("s", "sh", "ch", "x", "z"))])
#: Acronyms and abbreviations that names are built from (``ExportCSV``, ``SHOHINMSTMNT``, ``jquery-ui``,
#: ``CSRFTOKENCHECK``, ``faqcategory``): file formats, protocols, security, Java / .NET, databases,
#: business / factory / logistics systems, Japanese-system abbreviations, control prefixes.  Their
#: letters are not judged (only entries with two consonants side by side, a ``q`` or a ``j`` / ``z``
#: ending a syllable are needed).
_NAME_ACRONYMS = frozenset("""
adm amt apqp aql ascx ashx asmx asn asp aspx awb axd biz bmp bpm btn cbo cdn cfg cgi chk cifs ckeditor cmms cms cnc
cnt conf cpa cpi crl crm crp csr csrf css csv cvs dcs ddl dfs dhcp dhtml dll dlp dms dns docx dsa dtd dtl dwh ecm
edr ehr ejb emr eoq erp faq flg fmea frm ftp gcp gpg gps grd gst gtin gwt gzip hdn hdr hmac hmi hotp hrm htm html
http https img inf ins jdbc jdk jms jndi jpa jpeg jpg jquery jre jsf json jsp jstl jsx jvm jwe jwk jwks jws jwt kbn
kpi krb lbl ldap lims lms lnk lst lzh mfa mgmt mgr mnt mpeg mpg mps mrp msa msg msi mssql mst mtd mvc mvn mvvm ncr
nfc nfs npm ntlm ntp oauth ocsp odbc oltp orm otp pdf pdm pgp pgsql php pki plc plm plsql pms png pnl ppap ppm ppt
pptx proj prt pwa pwd qms qtd qty quiz rbac rdo rdp rfid rpc rpt rsa rss rtf saml scm scp scss sdk sfa sftp
smb smtp snmp spc sql srch ssh ssl sso sts svc svg svn tbl tcp tfs tgz tiff tls tms totp tpm tqm tsql tsv tsx txt
udp upc upd url usr vlan vmi vnc vpc vpn wbs wcf wlan wms wpf wsdl www xdr xhtml xls xlsx xml xsd xsl xslt xsrf xss
ymd ytd
dwg dxf ecg ecn ecr itsm msds rfq sds usb
""".split())
#: every acronym starting at a position, the longest first (grouped by first letter: four times faster)
_NAME_ACRONYM_RE = re.compile("(?=(" + "|".join(
    first + "(?:" + "|".join(sorted((a[1:] for a in _NAME_ACRONYMS if a[0] == first), key=len, reverse=True)) + ")"
    for first in sorted({a[0] for a in _NAME_ACRONYMS})) + "))")
#: Two-letter acronyms that names start with (``qcresultlist``, ``qrcodereader``): not judged only there
#: (elsewhere a ``q`` without ``u`` is a strong sign of random letters).
_NAME_PREFIX_ACRONYMS = ("qa", "qc", "qr")
_CONSONANT_RUN_RE = re.compile(r"[^aeiouy]+")
_Q_WITHOUT_U_RE = re.compile(r"q(?!u)")
#: Words of an identifier part: a capitalised / lowercase word, or an acronym run (``XML`` in ``XMLHttp``).
_CASE_WORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")


def _syllable_run(run: str, first: bool, last: bool) -> bool:
    """Can a run of consonants stand there in a word (``first`` / ``last``: it starts / ends the word)?
    A known two-letter word may start or end it (``cd`` in ``tokuisakicd``).  Inside a word a syllable
    ends in a cluster of ``_SYLLABLE_ENDS`` or in a single consonant other than ``j`` / ``z`` (``ex|port``,
    ``nav|bar``; never ``jm`` / ``zk``: abbreviations such as ``proj`` / ``biz`` are acronyms)."""
    if len(run) <= 1 or ((first or last) and run in _TWO_LETTER_WORDS):
        return True
    if first:
        return not last and run in _SYLLABLE_STARTS
    if last:
        return run in _SYLLABLE_ENDS
    return any((i == 0 or (i == 1 and run[0] not in "jz") or run[:i] in _SYLLABLE_ENDS)
               and (len(run) - i <= 1 or run[i:] in _SYLLABLE_STARTS) for i in range(len(run) + 1))


def _unpronounceable(word: str, acronym_start: bool = False) -> bool:
    """A word (3+ letters) that English and romaji spelling do not allow: a run of consonants that is
    not a syllable end plus a syllable start (at the start of the word: a start; at its end: an end),
    or a ``q`` without ``u``.  ``y`` counts as a vowel; the letters of known acronyms
    (``_NAME_ACRONYMS``; ``_NAME_PREFIX_ACRONYMS`` at the start) are not judged.  ``seisankanri``,
    ``PASSWORDCHANGE``, ``xmlhttprequest``, ``qcresultlist`` are pronounceable, ``qzvbnmwrtypxsdfkhj`` is not.
    ``acronym_start``: the consonants a word starts with may be an acronym the table does not know
    (``pc|management``, ``mfg|orderlist``, ``hq|announcement``, ``Bmn``): up to 4 of them are not judged."""
    word = word.lower()
    if len(word) < 3:
        return False
    letters = list(word)
    if word.startswith(_NAME_PREFIX_ACRONYMS):
        letters[:2] = "aa"
    for m in _NAME_ACRONYM_RE.finditer(word):
        letters[m.start():m.start() + len(m.group(1))] = "a" * len(m.group(1))
    word = "".join(letters)
    if acronym_start:
        lead = len(word) - len(word.lstrip("bcdfghjklmnpqrstvwxz"))
        if lead <= 4:
            word = "a" * lead + word[lead:]
    if _Q_WITHOUT_U_RE.search(word):
        return True
    return any(not _syllable_run(m.group(0), m.start() == 0, m.end() == len(word))
               for m in _CONSONANT_RUN_RE.finditer(word))


def _spelled_as_words(value: str) -> bool:
    """Letters (``-`` / ``_`` separated parts, any length) that read as words one by one: single-case
    parts are pronounceable (``_unpronounceable``); mixed-case parts have no case irregularity and no
    unpronounceable word of 3+ letters (acronym runs aside).  ``ProductionResult``, ``txtTokuisakiCD``,
    ``seisankanri`` are words, ``hwtkLiXgkUpljLymEiXB`` and ``QZVBNMWRTYPXSDFKHJ`` are not.  Stricter
    than ``looks_random_letters`` (no minimum length, every word judged, the consonants it starts with
    too): used only where behaviour already points to a token.  Values that are not letters-only
    (``Default.aspx``) count as words."""
    parts = [p for p in _SEPARATOR_RE.split(value) if p]
    if not parts or not all(p.isascii() and p.isalpha() for p in parts):
        return True
    letters = "".join(parts)
    if letters.islower() or letters.isupper():
        return not any(_unpronounceable(p) for p in parts)
    if any(_case_irregularities(p) for p in parts):
        return False
    return not any(_unpronounceable(w) for p in parts for w in _CASE_WORD_RE.findall(p) if not w.isupper())


def _strip_extension(value: str) -> str:
    """``xBBHOHpXYZgFKyNZpuWy.pdf`` -> ``xBBHOHpXYZgFKyNZpuWy`` (one short extension at most)."""
    m = _EXTENSION_RE.match(value)
    return m.group(1) if m else value


def looks_random_letters(value: str, single_case: bool = True) -> bool:
    """A long letters-only value with irregular mixed case (``xBBHOHpXYZgFKyNZpuWy``) is a random
    token, not a word: sites generate such keys (a URL key, a nonce) and about one in ten random
    20-character alphanumeric tokens happens to contain no digit at all.

    ``-`` / ``_`` separate parts that are judged one by one (base64url without digits:
    ``xBBHOH-pXYZgFKyNZpuWy``) and a file name is judged by its stem (``xBBHOHpXYZgFKyNZpuWy.pdf``).
    Identifiers with acronyms anywhere (``txtTokuisakiCD``, ``CustomerIDList``, ``DownloadAsPDF``,
    ``getXMLHttpRequest``) are words.  Mixed case that fits the identifier structure is still random
    when two of its words, or one of 5+ letters, cannot be pronounced (``_unpronounceable``; one short
    word may be an acronym written as a word: ``CsrfToken``).  Single-case values
    (``QZVBNMWRTYPXSDFKHJ``, ``SEARCHRESULTLIST``) have no case structure: their parts of 4+ letters
    are judged by spelling alone.  The consonants a word starts with may be an unknown acronym
    (``PCBINSPECTION``, ``hrdepartment``, ``BmnTntMaster``) and are not judged.

    ``single_case=False`` never calls a single-case value random (``is_dynamic_looking``): with no case
    to judge, spelling alone misjudges some names (a vowel-less abbreviation such as ``SYKKSJISEARCH``),
    which must still get no positional pattern and keep their 入力値 and selectors; only route names
    and pattern context use that verdict.

    Measured on random letters (tests/test_analysis.py, review3 and g_pathkey sections): mixed case
    about 98 % of 16-24 characters and 94 % of 12-15 (also with ``-`` / ``_``), single case about
    99.2 % of 16-24 (98 % or more at every length) and 96 % of 12-15 are tokens.  About 3,400 route /
    page / control names and values in English and romaji, also with acronyms (``PRODUCTIONRESULTCSV``,
    ``tokuisakimaster``, ``shohin_mst_mnt``, ``CSRFTOKENCHECK``, ``pcbinspection``, ``ohtsukahiroshi``),
    stay words; vowel-less abbreviations (``PRDCTNRSLTLIST``) do not."""
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
        return single_case and any(_unpronounceable(p, acronym_start=True) for p in parts if len(p) >= 4)
    if any(_case_irregularities(p) for p in parts):
        return True
    # well-formed case: random when two words, or one of 5+ letters, cannot be pronounced (one short
    # word may be an acronym written as a word: ``CsrfToken``, ``ctlMenu``)
    bad = [w for p in parts for w in _CASE_WORD_RE.findall(p)
           if not w.isupper() and _unpronounceable(w, acronym_start=True)]
    return len(bad) >= 2 or any(len(w) >= 5 for w in bad)


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
    if looks_random_letters(value, single_case=False) or (
            value[-1].isdigit() and looks_random_letters(value.rstrip("0123456789"), single_case=False)):
        return True  # also random letters with a short number behind (``fnXttwFErwXJmYe2``)
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


#: ``<input type>`` values of controls whose value the user types (``""`` = no type = text).
_TYPED_INPUT_TYPES = frozenset({
    "", "text", "search", "email", "tel", "url", "number", "date", "datetime-local", "datetime", "month", "week",
    "time", "range", "color",
})
_BUTTON_INPUT_TYPES = frozenset({"submit", "button", "image", "reset"})


@dataclass
class FormField:
    """One named control of an HTML form (several radio / checkbox inputs merge into one field).

    ``control``: ``text`` (any typed input), ``password``, ``textarea``, ``select``, ``radio``,
    ``checkbox``, ``hidden``, ``button``, ``file`` or ``other``.  ``defaults`` are the values the form
    would send untouched; ``editable`` is True for a visible control the user can change (not hidden,
    readonly, disabled or a button) - a value sent for it is user input."""

    name: str
    control: str
    defaults: list[str] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    editable: bool = False


@dataclass
class FormInfo:
    """An HTML ``<form>``: its raw ``action`` (resolved against the page URL by the caller), method and
    named controls."""

    action: str
    method: str
    fields: dict[str, FormField] = field(default_factory=dict)


def _form_fields(form: Tag) -> dict[str, FormField]:
    out: dict[str, FormField] = {}
    for el in form.find_all(["input", "select", "textarea", "button"]):
        name = el.get("name")
        if not isinstance(name, str) or not name:
            continue
        locked = el.has_attr("readonly") or el.has_attr("disabled")
        tag = el.name
        value = el.get("value")
        value = value if isinstance(value, str) else None
        defaults: list[str] = []
        options: list[str] = []
        if tag == "textarea":
            control, defaults = "textarea", [el.get_text()]
        elif tag == "select":
            control = "select"
            opts = el.find_all("option")
            for opt in opts:
                ov = opt.get("value")
                options.append(ov if isinstance(ov, str) else " ".join(opt.get_text().split()))
            chosen = [options[i] for i, opt in enumerate(opts) if opt.has_attr("selected")]
            if not chosen and options and not el.has_attr("multiple"):
                chosen = [options[0]]
            defaults = chosen
        elif tag == "button":
            control = "button"
            defaults = [value or ""]
        else:
            kind = str(el.get("type") or "").strip().lower()
            if kind == "password":
                control, defaults = "password", [value or ""]
            elif kind == "hidden":
                control, defaults = "hidden", [value or ""]
            elif kind in ("radio", "checkbox"):
                control = kind
                options = [value if value is not None else "on"]
                defaults = options[:] if el.has_attr("checked") else []
            elif kind in _BUTTON_INPUT_TYPES:
                control, defaults = "button", [value or ""]
            elif kind == "file":
                control = "file"
            elif kind in _TYPED_INPUT_TYPES:
                control, defaults = "text", [value or ""]
            else:
                control, defaults = "other", [value or ""]
        editable = control in ("text", "password", "textarea", "select", "radio", "checkbox") and not locked
        known = out.get(name)
        if known is None:
            out[name] = FormField(name=name, control=control, defaults=defaults, options=options, editable=editable)
        else:  # radio groups, checkbox lists, duplicated names
            known.defaults.extend(defaults)
            known.options.extend(options)
            known.editable = known.editable or editable
    return out


class _SoupIndex:
    """Lookup tables over a parsed HTML document (built once per response)."""

    def __init__(self, soup: BeautifulSoup) -> None:
        from bs4 import NavigableString, Tag  # imported on first use: importing reqrec stays cheap

        self._soup = soup
        self._forms: Optional[list[FormInfo]] = None
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

    @property
    def forms(self) -> list[FormInfo]:
        """Every ``<form>`` of the page with its named controls (parsed on first use)."""
        if self._forms is None:
            forms: list[FormInfo] = []
            for form in self._soup.find_all("form"):
                action = form.get("action")
                method = str(form.get("method") or "GET").strip().upper() or "GET"
                forms.append(FormInfo(action=action if isinstance(action, str) else "", method=method,
                                      fields=_form_fields(form)))
            self._forms = forms
        return self._forms


class _ResponseView:
    """Lazily decoded / parsed view of one response, cached across ``locate_value`` calls."""

    def __init__(self, flow: Flow) -> None:
        self.flow = flow
        resp = flow.response
        self.status = resp.status if resp else 0
        self.mime = (resp.mime_type or "").lower() if resp else ""
        self.body: bytes = (resp.body if resp and resp.body else b"")
        self._text: Optional[str] = None
        self._unescaped: Optional[str] = None
        self._json: Any = Ellipsis
        self._soup: Any = Ellipsis
        self._index: Optional[_SoupIndex] = None
        self._leaf_index: Optional[dict[str, list]] = None

    @property
    def textual(self) -> bool:
        if not self.body or len(self.body) > _MAX_TEXT_BYTES:
            return False
        if is_textual_mime(self.mime):
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
    def unescaped(self) -> str:
        """The text with HTML character references resolved (``&#x3D;`` -> ``=``)."""
        if self._unescaped is None:
            from html import unescape  # stdlib; imported on first use

            self._unescaped = unescape(self.text) if "&" in self.text else self.text
        return self._unescaped

    @property
    def json_doc(self) -> Any:
        if self._json is Ellipsis:
            self._json = None
            if self.textual and (is_json_mime(self.mime) or self.text.lstrip()[:1] in ("{", "[")):
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
        if is_html_mime(self.mime) or is_xml_mime(self.mime):
            return True
        return self.text.lstrip()[:1] == "<"

    @property
    def soup(self) -> Optional[BeautifulSoup]:
        if self._soup is Ellipsis:
            self._soup = None
            if self.is_htmlish and len(self.body) <= _MAX_SOUP_BYTES:
                from bs4 import BeautifulSoup  # imported on first use: importing reqrec stays cheap

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
    """Drop cached parsed responses and the values the last plan traced (tests / long-running processes)."""
    _VIEW_CACHE.clear()
    _TRACED.values = frozenset()


# --------------------------------------------------------------------------- pattern building

_REGEX_UNSAFE_RE = re.compile(r"""["'<>\s]""")
_MIN_REGEX_VALUE_LEN = 6
#: How many matches of a candidate pattern ``build_pattern`` checks for ambiguity.
_MAX_PATTERN_MATCHES = 200
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


_CONTEXT_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+=.%~]+")
_HEXISH_RE = re.compile(r"^[0-9a-fA-F]+$")
#: Values the plan being built reads afresh on every run (``_note_traced``), per thread; emptied by
#: ``clear_cache``.
_TRACED = threading.local()


def _note_traced(value: Any) -> None:
    """Remember a value the plan reads afresh on every run (an extractor's sample, a cookie the script
    looks up): later patterns leave it out of their context (``_run_specific``), so the token after a
    short path key (``/s/QZVBNMWRT/list?tk=...``) is read with ``/list?tk=``, which still matches on the
    next run.  Plain words (``search``) stay context."""
    if (isinstance(value, str) and len(value) >= _MIN_REGEX_VALUE_LEN and not any(ch.isspace() for ch in value)
            and not (_PLAIN_WORDS_RE.match(value) and _spelled_as_words(value))):
        _TRACED.values = getattr(_TRACED, "values", frozenset()) | {value}


def _run_specific(token: str) -> bool:
    """A piece of pattern context that probably differs on the next run: a value the plan being built
    reads afresh (``_note_traced``; also the piece of one the context window cut off), a number of 3+
    digits (a record id, the tail of a session id), a UUID / JWT, a hex string mixing letters and
    digits, or a random-looking token.  Identifiers such as ``ctl00_MainContent_txtUser`` are not."""
    tok = token.strip("-_.=+~%")
    if not tok:
        return False
    if len(tok) >= _MIN_REGEX_VALUE_LEN and any(  # (traced values are at least that long)
            v in tok or ((v.startswith(tok) or v.endswith(tok)) and _CONTEXT_TOKEN_RE.fullmatch(v))
            for v in getattr(_TRACED, "values", ())):
        return True
    if tok.isdigit():
        return len(tok) >= 3
    if _UUID_RE.match(tok) or _JWT_RE.match(tok):
        return True
    if len(tok) >= 8 and _HEXISH_RE.match(tok) and any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok):
        return True
    if looks_random_letters(tok):
        return True
    return len(tok) >= 16 and is_dynamic_looking(tok) and len(_DIGIT_RUN_RE.findall(tok)) >= 3


def _stable_context(prefix: str, suffix: str) -> tuple[str, str]:
    """The pattern context without run-specific tokens: the prefix keeps what follows the last such
    token, the suffix what precedes the first one."""
    last = 0
    for m in _CONTEXT_TOKEN_RE.finditer(prefix):
        if _run_specific(m.group(0)):
            last = m.end()
    if last:
        prefix = prefix[last:]
    for m in _CONTEXT_TOKEN_RE.finditer(suffix):
        if _run_specific(m.group(0)):
            suffix = suffix[:m.start()]
            break
    return prefix, suffix


def _verified_pattern(haystack: str, value: str, prefix: str, suffix: str, allow_ambiguous: bool) -> Optional[str]:
    group = _capture_group(value, greedy=not suffix)
    pattern = ("" if prefix else "^") + re.escape(prefix) + group + (re.escape(suffix) if suffix else "$")
    if not prefix or not suffix:
        pattern = "(?m)" + pattern
    try:
        found = [m.group(1) for m, _ in zip(re.finditer(pattern, haystack), range(_MAX_PATTERN_MATCHES))]
    except re.error:  # pragma: no cover - re.escape makes this unreachable
        return None
    if found and found[0] == value and (allow_ambiguous or all(f == value for f in found)):
        return pattern
    return None


def build_pattern(haystack: str, value: str, context: int = 24, allow_ambiguous: bool = True) -> Optional[str]:
    """A verified regex with exactly one capture group that extracts ``value`` from ``haystack``.

    Up to ``context`` characters of literal (escaped) context are used on each side, trimmed at
    line boundaries and at other occurrences of ``value`` (a context that contains the value would only
    ever match the recorded one); the capture group matches token-like text.

    ``allow_ambiguous`` (the callers pass it for random-looking tokens): the first pattern whose
    first match is ``value`` is returned, as always.  Without it (a code or a number, e.g. a customer
    chosen in a picker) a pattern that also matches other values is refused - finding the value as the
    *first* match only means "the first row", and a new row listed first would silently replace the
    user's choice - and only the shortest context is tried, so the pattern is anchored by what stands
    right next to the value (its name on the same row), never by the neighbouring rows.  Returns None
    when the value contains quotes / whitespace / angle brackets or no acceptable pattern exists (the
    caller then keeps the recorded value)."""
    if not value or not haystack or _REGEX_UNSAFE_RE.search(value):
        return None
    # A short suffix first: the capture group is delimited by its character class, so a few
    # characters suffice and trailing context (often other dynamic values) is less likely to
    # break the pattern on the next run.  Longer context is tried only when needed.
    windows = ((context, 4), (context, context), (context * 2, context * 2), (context * 4, context * 4))
    for before, after in windows if allow_ambiguous else windows[:1]:
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
            own = prefix.rfind(value)
            if own >= 0:  # an earlier occurrence of the value is never context
                prefix = prefix[own + len(value):]
                if not prefix:
                    continue
            suffix = haystack[end:end + after]
            cut = min([p for p in (suffix.find("\n"), suffix.find("\r"), suffix.find(value)) if p >= 0], default=-1)
            if cut >= 0:
                suffix = suffix[:cut]
            # context holding another run-specific value (a session id in the same URL, a record
            # number) would only match the recorded page: try the context without it first
            stable_prefix, stable_suffix = _stable_context(prefix, suffix)
            if (stable_prefix, stable_suffix) != (prefix, suffix) and (len(stable_prefix.strip()) >= 3 or len(stable_suffix.strip()) >= 3):
                pattern = _verified_pattern(haystack, value, stable_prefix, stable_suffix, allow_ambiguous)
                if pattern:
                    return pattern
            pattern = _verified_pattern(haystack, value, prefix, suffix, allow_ambiguous)
            if pattern:
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
    if any(f in val for f in forbidden) or any(v in val for v in getattr(_TRACED, "values", ())):
        return False  # (a value the plan reads afresh, such as a session key in an id, changes next run)
    return not is_dynamic_looking(val)


#: How many elements carrying the same value ``_locate_html`` compares for the stablest selector.
_MAX_LOCATE_ELEMENTS = 30


def _stablest(candidates: Iterable[tuple[str, Any]]) -> Optional[tuple[str, Any]]:
    """The first ``(selector, payload)`` whose selector has the fewest digits: ``#o_10009`` /
    ``#row17`` name a record that may be gone on the next run, ``#lnkCsv`` does not.  Document order
    breaks ties; a digit-free selector ends the search."""
    best: Optional[tuple[str, Any]] = None
    best_digits = 0
    for n, (selector, payload) in enumerate(candidates):
        digits = sum(ch.isdigit() for ch in selector)
        if best is None or digits < best_digits:
            best, best_digits = (selector, payload), digits
            if not digits:
                break
        if n + 1 >= _MAX_LOCATE_ELEMENTS:
            break
    return best


def _id_selector(el_id: str) -> str:
    return f"#{el_id}" if _CSS_IDENT_RE.match(el_id) else f"[id={_css_quote(el_id)}]"


def _selector_for(el: Tag, soup: BeautifulSoup, forbidden: list[str], exclude_attr: Optional[str] = None) -> Optional[str]:
    """A stable, unique CSS selector for ``el`` that never contains any of ``forbidden`` strings
    (the dynamic value's spellings).  Preference: ``#id``, ``tag[name=..]``, ``tag[data-x=..]``,
    ``tag[property/itemprop=..]``, ``tag.class1.class2``, bare ``tag``, then ``#ancestor tag``."""
    from bs4 import Tag  # imported on first use: importing reqrec stays cheap

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

#: Response headers that never carry a value a later request reuses (protocol / caching / security
#: headers; ``Set-Cookie`` is handled by ``CookieTimeline``).  ``ETag`` and ``Last-Modified`` are
#: *not* here: ``If-Match`` / ``If-Unmodified-Since`` send them back.
_HEADER_DENY = frozenset({
    "set-cookie", "date", "content-length", "content-type", "server", "connection", "transfer-encoding",
    "vary", "cache-control", "pragma", "expires", "age", "content-encoding", "keep-alive",
    "strict-transport-security", "x-powered-by", "via", "accept-ranges", "content-language",
    "x-content-type-options", "x-frame-options", "x-xss-protection", "referrer-policy",
    "content-security-policy", "alt-svc", "x-cache", "cf-ray", "cf-cache-status", "x-served-by",
})
_ALL_KINDS = frozenset({"header", "json", "html_input", "html_meta", "html_attr", "html_text", "regex", "url", "location"})
_BODY_KINDS = frozenset({"json", "html_input", "html_meta", "html_attr", "html_text", "regex"})


def _ordered_variants(value: str) -> list[str]:
    others = sorted(v for v in value_variants(value) if v != value)
    return [value] + others


def _locate_header(flow: Flow, variants: list[str]) -> Optional[Extractor]:
    """A response header whose value is the value (exact), else one that contains it (``Refresh:
    0; url=...?sid=X``, ``Link: <...?cursor=X>``, a ``Location`` of a non-redirect response): then
    the extractor carries a verified pattern applied to that header."""
    resp = flow.response
    usable = [
        (name, val) for name, val in resp.headers
        if name.lower() not in _HEADER_DENY and not (name.lower() == "location" and 300 <= resp.status < 400)
    ]
    for name, val in usable:
        if val in variants or val.strip() in variants:
            return Extractor(var="", kind="header", name=name, sample=val.strip())
    for name, val in usable:
        for v in variants:
            if len(v) < _MIN_REGEX_VALUE_LEN or v not in val or v == val.strip():
                continue
            pattern = build_pattern(val, v, allow_ambiguous=is_dynamic_looking(v))
            if pattern:
                return Extractor(var="", kind="header", name=name, pattern=pattern, sample=v)
    return None


def _locate_location(flow: Flow, variants: list[str]) -> Optional[Extractor]:
    """A value in the ``Location`` of a redirect response (the generated script reads it from that
    response of the redirect chain, ``Extractor.hop``)."""
    resp = flow.response
    if resp is None or not (300 <= resp.status < 400):
        return None
    location = (resp.location or "").strip()
    if not location:
        return None
    for v in variants:
        if v == location:
            return Extractor(var="", kind="header", name="Location", sample=v)
    for v in variants:
        if len(v) >= _MIN_REGEX_VALUE_LEN and v in location:
            pattern = build_pattern(location, v, allow_ambiguous=is_dynamic_looking(v))
            if pattern:
                return Extractor(var="", kind="header", name="Location", pattern=pattern, sample=v)
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
    # When several elements carry the value (a session id in every link), the one with the stablest
    # selector is used (``_stablest``).
    if allow("html_attr"):
        for v in variants:
            best = _stablest((sel, attr) for el, attr in idx.attr_index.get(v, [])
                             for sel in [_selector_for(el, soup, variants, exclude_attr=attr)] if sel)
            if best:
                return Extractor(var="", kind="html_attr", selector=best[0], attr=best[1], sample=v)
    if allow("html_text"):
        for v in variants:
            best = _stablest((sel, None) for el in idx.text_index.get(v, []) if el.get_text(strip=True) == v
                             for sel in [_selector_for(el, soup, variants)] if sel)
            if best:
                return Extractor(var="", kind="html_text", selector=best[0], sample=v)
    if allow("html_attr"):
        for v in variants:
            if not _REGEX_UNSAFE_RE.search(v):
                best = _stablest(_attr_patterns(idx, soup, variants, v))
                if best:
                    return Extractor(var="", kind="html_attr", selector=best[0], attr=best[1][0],
                                     pattern=best[1][1], sample=v)
    if allow("html_text"):
        for v in variants:
            if not _REGEX_UNSAFE_RE.search(v):
                best = _stablest(_text_patterns(idx, soup, variants, v))
                if best:
                    return Extractor(var="", kind="html_text", selector=best[0], pattern=best[1], sample=v)
    return None


def _attr_patterns(idx: _SoupIndex, soup: BeautifulSoup, variants: list[str], v: str) -> Iterator[tuple[str, tuple[str, str]]]:
    """``(selector, (attribute, pattern))`` for every attribute that contains ``v`` among other text."""
    for el, attr, val in idx.attr_items:
        if v not in val or val == v:
            continue
        sel = _selector_for(el, soup, variants, exclude_attr=attr)
        pattern = build_pattern(val, v, allow_ambiguous=is_dynamic_looking(v)) if sel else None
        if pattern:
            yield sel, (attr, pattern)


def _text_patterns(idx: _SoupIndex, soup: BeautifulSoup, variants: list[str], v: str) -> Iterator[tuple[str, str]]:
    """``(selector, pattern)`` for every element whose text contains ``v`` among other text."""
    for stripped, el in idx.text_nodes:
        if v not in stripped or stripped == v:
            continue
        sel = _selector_for(el, soup, variants)
        pattern = build_pattern(el.get_text(strip=True), v, allow_ambiguous=is_dynamic_looking(v)) if sel else None
        if pattern:
            yield sel, pattern


# --------------------------------------------------------------------------- values a page put into a form field

#: Field names / ids shorter than this never count as naming the field in a script or a text body.
_MIN_ANCHOR_LEN = 3
#: How far (same line) from a value the field's name / id may stand in a text body.
_ANCHOR_WINDOW = 64
#: The whole body of a text response, without surrounding white space.
_WHOLE_BODY_PATTERN = r"(?s)^\s*(.*?)\s*$"
#: Markup in a body: one without it is plain text whatever its Content-Type says (a JSP / an .ashx that
#: answers the bare value as text/html).
_MARKUP_RE = re.compile(r"<[A-Za-z/!?]")


def _form_tag(view: _ResponseView, form: FormInfo) -> Optional[Tag]:
    """The ``<form>`` element of ``view``'s page that ``form`` describes (None when it is not there)."""
    idx, soup = view.index, view.soup
    if idx is None or soup is None:
        return None
    forms = idx.forms
    i = next((n for n, known in enumerate(forms) if known is form), None)
    if i is None:  # the page was parsed again since: the first equal form
        i = next((n for n, known in enumerate(forms) if known == form), None)
    tags = getattr(view, "_form_tags", None)
    if tags is None:
        tags = view._form_tags = soup.find_all("form")
    return tags[i] if i is not None and i < len(tags) else None


def _form_input_selector(view: _ResponseView, form: FormInfo, name: str, value: str) -> Optional[str]:
    """A CSS selector for the first ``<input name=..>`` of the submitted form when it holds ``value``,
    scoped to that form by its id or its name (``registerForm`` may contain a word such as ``register``),
    and checked on the recorded page (the page's first ``<input>`` of that name may belong to another
    form).  The form's position among its sibling forms is used only for a run-specific value (a token):
    for a plain value a form added before it on the next run would be read silently, while the recorded
    value is right.  A run-specific value of one row of a list (another row form holds another one) is read
    from that row only, told apart by the row's own values (``_row_scope``), never by position."""
    soup, tag = view.soup, _form_tag(view, form)
    if soup is None or tag is None:
        return None
    field_sel = f"input[name={_css_quote(name)}]"
    forbidden = [] if _route_like(value) else [value]
    try:
        target = tag.select_one(field_sel)
        if target is None or target.get("value") != value:
            return None
        if is_dynamic_looking(value) and _row_forms(view, form, name, value):
            return _row_scope(view, form, tag, field_sel, target)
        scopes = [_id_selector(tag["id"])] if _attr_ok(tag.get("id"), forbidden) else []
        if _attr_ok(tag.get("name"), forbidden):
            scopes.append(f"form[name={_css_quote(tag['name'])}]")
        if is_dynamic_looking(value):
            scopes.append(f"form:nth-of-type({1 + len(tag.find_previous_siblings('form'))})")
        for scope in scopes:
            if soup.select_one(f"{scope} {field_sel}") is target:
                return f"{scope} {field_sel}"
    except Exception:  # a name a CSS string cannot hold (soupsieve's SelectorSyntaxError)
        return None
    return None


def _row_forms(view: _ResponseView, form: FormInfo, name: str, value: str) -> bool:
    """Is ``form`` one of several forms of the page that differ only in their values (one form per row of a
    list: the same method, action and fields), another of which holds another value in ``name``?  Then the
    value is the row the user chose, not a default of the page."""
    idx = view.index
    if idx is None:
        return False
    names = set(form.fields)
    for other in idx.forms:
        if other.method != form.method or other.action != form.action or set(other.fields) != names:
            continue
        fld = other.fields.get(name)
        if fld is not None and fld.defaults and value not in fld.defaults:
            return True
    return False


def _row_values(view: _ResponseView, form: FormInfo, name: str) -> set[str]:
    """What the forms of ``form``'s list (the same method, action and fields, ``_row_forms``) hold in ``name``."""
    names = set(form.fields)
    return {d for other in (view.index.forms if view.index is not None else [])
            if other.method == form.method and other.action == form.action and set(other.fields) == names
            for d in (other.fields[name].defaults if name in other.fields else [])}


def _opened_row(view: _ResponseView, form: FormInfo, sent: list[tuple[str, str, bytes]],
                charsets: Sequence[Optional[str]]) -> FormInfo:
    """The form of the row the user opened when ``form`` is one of several forms of the page that differ
    only in their values (one form per row of a list, ``_row_forms``): the one whose defaults hold the most
    submitted ``(name, value, recorded bytes)`` pairs (a legacy-charset value by its bytes in ``charsets``).
    ``form`` itself (the first such form) when no other holds more."""
    idx = view.index
    if idx is None:
        return form
    names = set(form.fields)

    def held(candidate: FormInfo) -> int:
        count = 0
        for name, value, raw in sent:
            fld = candidate.fields.get(name)
            if fld is not None and (value in fld.defaults or (not is_utf8(raw) and any(
                    _encodes_to(d, cs, raw) for d in fld.defaults for cs in charsets))):
                count += 1
        return count

    best, most = form, held(form)
    for other in idx.forms:
        if other is form or other.method != form.method or other.action != form.action or set(other.fields) != names:
            continue
        count = held(other)
        if count > most:
            best, most = other, count
    return best


def _row_scope(view: _ResponseView, form: FormInfo, tag: Tag, field_sel: str, target: Tag) -> Optional[str]:
    """``form:has(input[name=..][value=..]) <field_sel>``: ``target`` (an input of ``form``, one form per row
    of a list) read from its row, told apart from the other rows by the values that identify the row - plain
    values of hidden / locked inputs that another row form holds differently (``_row_forms``; the request
    sends them as recorded) - one of them, else all of them; the selector must select ``target`` alone on
    the recorded page.  None when no such value tells the row apart."""
    keys: list[str] = []
    for el in tag.find_all("input"):
        key, val = el.get("name"), el.get("value")
        fld = form.fields.get(key) if isinstance(key, str) else None
        if (fld is None or fld.editable or fld.control not in ("hidden", "text") or not isinstance(val, str) or not val
                or "\n" in val or "\r" in val or is_dynamic_looking(val) or not _row_forms(view, form, key, val)):
            continue
        keys.append(f":has(input[name={_css_quote(key)}][value={_css_quote(val)}])")
    for scope in [f"form{k}" for k in keys] + ([f"form{''.join(keys)}"] if len(keys) > 1 else []):
        if _unique(view.soup, f"{scope} {field_sel}", target):
            return f"{scope} {field_sel}"
    return None


def _json_at(doc: Any, path: list) -> Any:
    """The node at ``path`` (object keys / array indexes), ``Ellipsis`` when there is none."""
    node = doc
    for key in path:
        if isinstance(node, dict) and isinstance(key, str) and key in node:
            node = node[key]
        elif isinstance(node, list) and isinstance(key, int) and not isinstance(key, bool) and 0 <= key < len(node):
            node = node[key]
        else:
            return Ellipsis
    return node


#: A number as a list shows it (``1200``, ``1,200``, ``-3``, ``12.5``).
_NUMBER_TEXT_RE = re.compile(r"^[-+]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?$")


def _value_kind(text: str) -> str:
    """The rough kind of a value in a JSON list: ``date``, ``number``, ``code`` (letters with digits) or
    ``text``.  The rows of a list the user chooses from hold values of one kind; a date next to a price
    is one record (``{"d": ["2026/10/30", "1,200"]}``)."""
    if _DATE_RE.match(text):
        return "date"
    if _NUMBER_TEXT_RE.match(text):
        return "number"
    return "code" if any(ch.isdigit() for ch in text) else "text"


def _named_row(rows: list, i: int, field: str, made: frozenset) -> bool:
    """Does a leaf of row ``i`` (an object) set it apart from the other rows by a name the field shares
    (a WCF dictionary ``{"Key": "shipDate", "Value": ...}`` for ``txtShipDate``) or by a value the request
    that answered the list sent (``made``: ``{"item": "B002"}`` created the row holding ``B002``)?"""
    row = rows[i]
    if not isinstance(row, dict):
        return False
    for key, leaf in row.items():
        conv = _leaf_as_str(leaf)
        if conv is None or not ((field and _names_related(conv[0], field)) or conv[0] in made):
            continue
        if not any(isinstance(other, dict) and _leaf_as_str(other.get(key)) == conv
                   for j, other in enumerate(rows) if j != i):
            return True
    return False


def _list_pick(doc: Any, path: list, field: str = "", others: frozenset = frozenset(),
               made: frozenset = frozenset()) -> bool:
    """Is the JSON leaf at ``path`` one row of a list the user chose from (``rows[1].code`` next to other
    codes)?  Then reading "row 1" again would pick whatever is listed there on the next run.  It is when
    another row holds, under the same keys, another value of the same kind (``_value_kind``) that the
    request does not send in another field (``others``: rows that several fields use are one record), and
    the row is not set apart by its name or by what the answering request sent (``_named_row``)."""
    return bool(_pick_levels(doc, path, field, others, made))


def _pick_levels(doc: Any, path: list, field: str = "", others: frozenset = frozenset(),
                 made: frozenset = frozenset()) -> list[int]:
    """The places in ``path`` of the row numbers at which the leaf is one row of a list the user chose
    from (``_list_pick``)."""
    own = _leaf_as_str(_json_at(doc, path))
    if own is None:
        return []
    kind = _value_kind(own[0])
    levels: list[int] = []
    for i, key in enumerate(path):
        if not isinstance(key, int) or isinstance(key, bool):
            continue
        rows = _json_at(doc, path[:i])
        if not isinstance(rows, list) or len(rows) < 2 or _named_row(rows, key, field, made):
            continue
        for j, row in enumerate(rows):
            other = _leaf_as_str(_json_at(row, path[i + 1:])) if j != key else None
            if other is not None and other[0] != own[0] and other[0] not in others and _value_kind(other[0]) == kind:
                levels.append(i)
                break
    return levels


def _pick_context(view: _ResponseView, field: str, consumer: Optional[Flow]) -> tuple[frozenset, frozenset]:
    """``(others, made)`` for ``_list_pick``: the values the consumer sends in its other fields, and those a
    request other than GET that answered the list sent (it may have made the row)."""
    others = frozenset(c.value for c in request_params(consumer) if c.name != field) if consumer else frozenset()
    answered = view.flow.request
    made = (frozenset(c.value for c in request_params(view.flow))
            if (answered.method or "GET").upper() not in ("GET", "HEAD") else frozenset())
    return others, made


def _unpicked_json(view: _ResponseView, ext: Extractor, field: str = "",
                   consumer: Optional[Flow] = None) -> Optional[Extractor]:
    """``ext`` (a JSON leaf), else a leaf with the same value outside such a list, else None: a value
    found only as one row of a list (``_list_pick``) is the user's choice, not the response's.  ``field``
    and ``consumer``: the name of the request value and its request (the values it sends in other fields);
    a request other than GET that answered the list may have made the row (``_named_row``)."""
    doc = view.json_doc
    if doc is None or not ext.path or not any(isinstance(k, int) and not isinstance(k, bool) for k in ext.path):
        return ext
    others, made = _pick_context(view, field, consumer)
    if not _list_pick(doc, ext.path, field, others, made):
        return ext
    for path, leaf in json_leaves(doc):
        conv = _leaf_as_str(leaf)
        if conv is not None and conv[0] == ext.sample and not _list_pick(doc, path, field, others, made):
            return Extractor(var="", kind="json", name=json_dotted(path), path=list(path), sample=ext.sample)
    return None


def _row_label(doc: Any, path: list, level: int, sends: dict) -> Optional[tuple[list, str, Optional[str]]]:
    """The leaf of the chosen row (``path[:level + 1]``) that tells it apart from the other rows of its list, as
    ``(its path in the row, its value, the request field that sends the same value)``.  First a leaf whose value
    the request sends in another field (``sends``: text -> field name; ``txtCustomerName=大阪商事`` next to
    ``{"name": "大阪商事"}``) when that value has 6 bytes or more or the leaf's key is named like the field (a
    number only then), else the first leaf that does not look random and is no number (a name or a code; a
    date only when there is nothing else).  Only a column every row has, whose value no other row shares,
    counts; never a leaf in a list inside the row.  None when no leaf does."""
    rows = _json_at(doc, path[:level])
    row = rows[path[level]] if isinstance(rows, list) else None
    if not isinstance(row, dict):
        return None
    own = list(path[level + 1:])

    def column(sub: list, text: str) -> bool:  # every other row has the leaf, with another value
        for j, other in enumerate(rows):
            if j == path[level]:
                continue
            conv = _leaf_as_str(_json_at(other, sub))
            if conv is None or conv[0] == text:
                return False
        return True
    leaves = [(sub, conv[0]) for sub, leaf in json_leaves(row) for conv in [_leaf_as_str(leaf)]
              if conv is not None and sub != own and conv[0].strip() and not is_dynamic_looking(conv[0])
              and not any(isinstance(k, int) for k in sub)]
    for sub, text in leaves:
        sent_in = sends.get(text)
        if (sent_in is not None and (_names_alike(str(sub[-1]), sent_in)
                                     or (_value_kind(text) != "number" and len(text.encode("utf-8")) >= 6))
                and column(sub, text)):
            return sub, text, sent_in
    for dates in (False, True):
        for sub, text in leaves:
            kind = _value_kind(text)
            if kind != "number" and (kind == "date") == dates and column(sub, text):
                return sub, text, None
    return None


def _row_pick(view: _ResponseView, ext: Extractor, field: str, consumer: Optional[Flow],
              sends: dict) -> Optional[Extractor]:
    """``ext`` (a JSON leaf the user chose as one row of a list, ``_list_pick``) read from the row that holds
    its label (``_row_label``) instead of from its row number: so the next run sends the value of the row
    the user chose, whatever the order of the list.  None when no leaf tells the row apart, or the list
    lies in another list the user chose from."""
    doc = view.json_doc
    if doc is None or not ext.path:
        return None
    others, made = _pick_context(view, field, consumer)
    levels = _pick_levels(doc, ext.path, field, others, made)
    label = _row_label(doc, ext.path, levels[0], sends) if len(levels) == 1 else None
    if label is None:
        return None
    key, text, sent_in = label
    return Extractor(var="", kind="json", name=ext.name, path=list(ext.path), sample=ext.sample,
                     row=levels[0], row_key=key, row_value=text, row_field=sent_in)


def _anchor_re(anchor: str) -> re.Pattern:
    """A field name / id, not as part of a longer identifier."""
    return re.compile(rf"(?<![\w$-]){re.escape(anchor)}(?![\w$-])")


#: What follows a field reference that writes the field: ``getElementById('x').value =``,
#: ``form1.x.value =``, ``getElementsByName('x')[0].value =``, ``$('#x').val(...`` (``.val()`` reads),
#: ``.attr('value', ``.
_FIELD_WRITE_RE = re.compile(r"""(?:['"\])\s]|\[\d+\])*\.(?:(?:value|defaultValue)\s*=(?!=)|val\s*\((?!\s*\))"""
                             r"""|(?:attr|setAttribute)\s*\(\s*['"]value['"]\s*,)\s*""")
#: ``var el = <a reference to the field>``: a statement up to the reference (the field is then written as
#: ``el.value``).
_ALIAS_RE = re.compile(r"""\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=(?!=)[^;{}\n\r=]*$""")
#: A character that continues a name / an id (see ``_anchor_re``).
_NAME_CHAR_RE = re.compile(r"[\w$-]")
#: The rest of such a statement after the reference: only its closing quotes / brackets.
_REF_END_RE = re.compile(r"""(?:['"\])\s]|\[\d+\])*(?:;|$|[\n\r}])""")
#: A variable or a property in a written expression (``SYS_DATE``, ``CONFIG.today``).
_JS_NAME_PATH_RE = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")
#: Element properties: ``other.value`` copies another field, it is no variable the page set.
_DOM_VALUE_PROPS = frozenset({"value", "defaultValue", "text", "innerText", "innerHTML", "textContent"})
#: An attribute selector naming the field by the end of its id / name (``input[id$='txtDate']``: ASP.NET
#: master pages) or by a part of it (``*=``); the element part before it keeps the match at a word start.
_ATTR_SELECTOR_RE = re.compile(r"""[\w-]*\[\s*(?:id|name)\s*([$*])=\s*(['"]?)([^'"\]\s]+)\2\s*\]""")


def _field_writes(code: str, anchors: list[str]) -> list[tuple[int, int]]:
    """Where a script writes one of the fields ``anchors`` name (not only configures it: a date picker's
    ``minDate``): ``(start of the field reference, start of the written expression)``, directly, through
    an attribute selector matching the field (``$("input[id$='txtDate']").val(...)``) or through a
    variable holding the element (``var el = document.getElementById('x'); el.value = ...``, until the
    variable is set again)."""
    found: list[tuple[int, int]] = []
    aliases: list[tuple[str, int]] = []
    for anchor in anchors:
        at = code.find(anchor)
        while at >= 0:  # whole names only (``_anchor_re``), found with str.find: scripts can be long
            start, end = at, at + len(anchor)
            at = code.find(anchor, at + 1)
            if (start and _NAME_CHAR_RE.match(code, start - 1)) or _NAME_CHAR_RE.match(code, end):
                continue
            write = _FIELD_WRITE_RE.match(code, end)
            if write:
                found.append((start, write.end()))
                continue
            lo = max(0, start - 200)
            stmt = max(code.rfind(c, lo, start) for c in ";{}\n\r")
            alias = _ALIAS_RE.match(code, stmt + 1, start) if stmt >= 0 or lo == 0 else None
            if alias and _REF_END_RE.match(code, end):
                aliases.append((alias.group(1), end))
    if "$=" in code or "*=" in code:
        for m in _ATTR_SELECTOR_RE.finditer(code):
            op, part = m.group(1), m.group(3)
            if len(part) < _MIN_ANCHOR_LEN or part in anchors:
                continue  # a whole name is an anchor of its own
            if any(a.endswith(part) if op == "$" else part in a for a in anchors):
                write = _FIELD_WRITE_RE.match(code, m.end())
                if write:
                    found.append((m.start(), write.end()))
    for alias, start in aliases:
        name = re.escape(alias)
        again = re.compile(rf"(?<![\w$.]){name}\s*=(?!=)").search(code, start)
        for m in re.compile(rf"(?<![\w$.]){name}(?![\w$])").finditer(code, start, again.start() if again else len(code)):
            write = _FIELD_WRITE_RE.match(code, m.end())
            if write:
                found.append((m.start(), write.end()))
    return found


def _written_expr(code: str, pos: int) -> str:
    """The expression a field write starting at ``pos`` assigns (up to the end of its statement)."""
    end = len(code)
    for stop in (";", "\n", "\r", "}"):
        k = code.find(stop, pos, end)
        if k >= 0:
            end = k
    return code[pos:end]


def _literal_end(code: str, pos: int, value: str) -> Optional[str]:
    """The character closing the script literal ``value`` at ``code[pos]`` (its quote, or what follows a
    bare number), None when the value is only part of a literal or a name."""
    end = pos + len(value)
    before, after = code[max(0, pos - 1):pos], code[end:end + 1]
    if before in ("'", '"'):
        return after if after == before else None
    bare = re.compile(r"[\w$.'\"]")
    if re.fullmatch(r"\d+(?:\.\d+)?", value) and after and not bare.match(after) and not bare.match(before or " "):
        return after
    return None


_BRACKET_RE = re.compile(r"[()\[\]{}]")


def _list_item(code: str, pos: int) -> bool:
    """Is the literal at ``code[pos]`` an item of a list in a script (``['L01', 'L02']``,
    ``new Array('L01', ...)``, ``[{code: 'C-1'}, ...]``)?  Looking back, the innermost open bracket is
    ``[`` / ``Array(``, or an object ``{`` that is itself such an item."""
    depth = 0
    in_object = False
    lo = max(0, pos - 1999)
    for m in reversed(list(_BRACKET_RE.finditer(code, lo, pos))):
        i, ch = m.start(), m.group(0)
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth:
                depth -= 1
            elif ch == "{" and not in_object:
                in_object = True
            else:
                return ch == "[" or (ch == "(" and code[max(0, i - 5):i] == "Array")
    return False


def _only_captures(text: str, pattern: str, value: str) -> bool:
    """Does ``pattern`` match ``text`` and capture ``value`` at every match?"""
    found = False
    for m, _ in zip(re.finditer(pattern, text), range(_MAX_PATTERN_MATCHES)):
        if m.group(1) != value:
            return False
        found = True
    return found


#: Elements whose event handlers may fill a field in by themselves: the page (``onload=``), buttons (a
#: 「今日」 button) and form controls.  A handler on a link, a table cell, a list item or a radio button
#: is a row of a list the user picked from, even when the list has a single row.
_WRITER_HANDLER_TAGS = frozenset({"body", "frameset", "form", "input", "button", "select", "textarea"})
#: A script reading an element: ``x.value``, ``$('#x').val()`` / ``.text()`` / ``.html()``, ``innerText`` ...
_ELEMENT_READ_RE = re.compile(r"\.(?:value|defaultValue|innerText|innerHTML|textContent)\b(?!\s*=[^=])"
                              r"|\.(?:val|text|html)\s*\(\s*\)")
#: Names a script may give an element by: identifiers and the words of its strings (``form1.hidToday``,
#: ``getElementById('hidToday')``, ``$('#lblToday')``).
_ELEMENT_NAME_RE = re.compile(r"[A-Za-z_$][\w$:.-]*")


def _page_codes(view: _ResponseView) -> list[str]:
    """The page's scripts: ``<script>`` contents and the event handlers of ``_WRITER_HANDLER_TAGS``
    elements (built once per page)."""
    codes = getattr(view, "_page_codes", None)
    if codes is None:
        soup, idx = view.soup, view.index
        codes = [s.string for s in soup.find_all("script") if s.string] if soup is not None else []
        if idx is not None:
            codes += [val for el, attr, val in idx.attr_items
                      if attr.startswith("on") and el.name in _WRITER_HANDLER_TAGS
                      and not (el.name == "input" and str(el.get("type") or "").strip().lower() == "radio")]
        starts, at = [], 0
        for code in codes:
            starts.append(at)
            at += len(code) + 1
        view._page_codes, view._page_joined = codes, ("\x00".join(codes), starts)
    return codes


def _codes_with(view: _ResponseView, needles: Iterable[str]) -> list[str]:
    """The page's scripts (``_page_codes``) containing one of ``needles``, in page order: one search over
    all of them (a page may have hundreds of handlers)."""
    from bisect import bisect_right  # stdlib; imported on first use

    codes = _page_codes(view)
    joined, starts = view._page_joined
    hits: set[int] = set()
    for needle in needles:
        at = joined.find(needle) if needle else -1
        while at >= 0:
            k = bisect_right(starts, at) - 1
            hits.add(k)
            at = joined.find(needle, starts[k + 1]) if k + 1 < len(starts) else -1
    return [codes[k] for k in sorted(hits)]


def _element_read(view: _ResponseView, expr: str, value: str) -> Optional[Extractor]:
    """The element of the page a written expression copies (``document.form1.hidToday.value``,
    ``$('#lblToday').text()``) when the server rendered exactly ``value`` into it (a hidden input, a
    label): the value is read from that element again."""
    soup, idx = view.soup, view.index
    if soup is None or idx is None or not _ELEMENT_READ_RE.search(expr):
        return None
    names: list[str] = []
    for m in _ELEMENT_NAME_RE.finditer(expr):
        names += [m.group(0)] + m.group(0).split(".")
    for name in dict.fromkeys(n for n in names if n):
        for el, attr in idx.attr_index.get(name, []):
            if attr not in ("id", "name"):
                continue
            if el.name == "input":
                if el.get("value") != value:
                    continue
                nm = el.get("name")
                first = (next((e for e, a in idx.attr_index.get(nm, []) if a == "name" and e.name == "input"), None)
                         if isinstance(nm, str) and nm else None)
                if first is el:
                    return Extractor(var="", kind="html_input", name=nm, sample=value)
                sel = _selector_for(el, soup, [value], exclude_attr="value")
                if sel:
                    return Extractor(var="", kind="html_attr", selector=sel, attr="value", sample=value)
            elif el.name not in ("select", "textarea", "option", "script", "style") and el.get_text(strip=True) == value:
                sel = _selector_for(el, soup, [value])
                if sel:
                    return Extractor(var="", kind="html_text", selector=sel, sample=value)
    return None


def _page_script_source(view: _ResponseView, value: str, anchors: list[str]) -> Optional[Extractor]:
    """Where the form page's own scripts (``_page_codes``) got the value they write into the field
    (``_field_writes``): the written literal (``getElementById('txtDate').value = '...'``), an element of
    the page the written expression copies (``_element_read``), or a variable / property the expression
    uses and the scripts set to it (``var SYS_DATE = '...'`` ... ``.value = SYS_DATE``).  A literal is read
    with a regex verified to capture only that value on the page: never an item of a list or one of
    several handlers writing other values (a choice), never a value that merely stands in a script naming
    the field (a date picker's ``minDate``)."""
    if not anchors or view.soup is None:
        return None
    writes = [(code, ref, pos) for code in _codes_with(view, list(anchors) + ["$=", "*="])
              for ref, pos in _field_writes(code, anchors)]
    if not writes:
        return None
    holding = [] if _REGEX_UNSAFE_RE.search(value) else _codes_with(view, [value])
    literal = bool(holding)
    for code, ref, pos in writes:
        expr = _written_expr(code, pos)
        spots = [(code, ref, pos + k) for k in range(len(expr)) if expr.startswith(value, k)] if literal else []
        if not spots:
            copied = _element_read(view, expr, value)
            if copied is not None:
                return copied
        names = [] if spots or not literal else [(m.group(0).rsplit(".", 1)[-1], expr[m.end():].lstrip())
                                                 for m in _JS_NAME_PATH_RE.finditer(expr)]
        for name, rest in names:
            if name in _DOM_VALUE_PROPS or rest.startswith("("):
                continue  # another field's value, a function call
            assign = re.compile(rf"(?<![\w$]){re.escape(name)}['\"]?\s*[:=](?!=)\s*['\"]?{re.escape(value)}")
            spots += [(other, a.start(), a.end() - len(value)) for other in holding for a in assign.finditer(other)]
        for where, start, at in spots:
            close = _literal_end(where, at, value)
            if close is None or _list_item(where, at):
                continue
            pattern = (r"(?<![\w$])" + re.escape(where[start:at]) + _capture_group(value, greedy=False)
                       + re.escape(close))
            if _only_captures(view.text, pattern, value):
                return Extractor(var="", kind="regex", pattern=pattern, sample=value)
    return None


def _anchored_pattern(text: str, value: str, anchors: list[str]) -> Optional[str]:
    """A verified regex for ``value`` whose context reaches the field's name or id on the same line, at
    most ``_ANCHOR_WINDOW`` characters away (``name="txtShipDate" type="text" value="..."``), with no
    list, object or other element between them."""
    if not anchors or _REGEX_UNSAFE_RE.search(value):
        return None
    start = 0
    for _ in range(12):
        idx = text.find(value, start)
        if idx < 0:
            break
        start, end = idx + 1, idx + len(value)
        line_start = max(text.rfind("\n", 0, idx), text.rfind("\r", 0, idx)) + 1
        line_end = min([p for p in (text.find("\n", end), text.find("\r", end)) if p >= 0], default=len(text))
        for anchor in anchors:
            rx = _anchor_re(anchor)
            # whole names only: the lookahead sees the end of the window as the end of the text
            spans = [m.span() for lo, hi in ((max(line_start, idx - _ANCHOR_WINDOW), idx),
                                             (end, min(line_end, end + _ANCHOR_WINDOW)))
                     for m in rx.finditer(text, lo, hi) if not re.match(r"[\w$-]", text[m.end():m.end() + 1])]
            before = [s for s, e in spans if e <= idx]
            after = [e for s, e in spans if s >= end]
            # the other side: only the punctuation next to the value (the capture group stops at quotes)
            if before:
                quote = text[idx - 1:idx] if idx and text[idx - 1] in "'\"" and text[end:end + 1] == text[idx - 1] else ""
                prefix, suffix = text[before[-1]:idx], quote or re.match(r"\W{0,4}", text[end:line_end]).group(0)
                between, (kept, _) = prefix, _stable_context(prefix, "")
            elif after:
                prefix, suffix = re.search(r"\W{0,4}$", text[line_start:idx]).group(0), text[end:after[0]]
                between, (_, kept) = suffix, _stable_context("", suffix)
            else:
                continue
            if value in between or kept != between or any(c in between for c in "[]{}<") or ">" in between[:-1]:
                continue  # another value, a run-specific token, a list or another element in between
            pattern = _verified_pattern(text, value, prefix, suffix, allow_ambiguous=False)
            if pattern:
                return pattern
    return None


def _text_body_source(view: _ResponseView, value: str, anchors: list[str]) -> Optional[Extractor]:
    """A text response without markup (a text/plain XHR, an UpdatePanel delta, JavaScript, a bare value
    answered as text/html) the page's script copied the value from: its whole body (never a bare number),
    or a value whose context names the field (``_anchored_pattern``; also its HTML-escaped spelling in a
    delta's markup).  A value merely somewhere in the text is not enough."""
    if not view.textual or (view.is_htmlish and _MARKUP_RE.search(view.text)):
        return None
    text = view.text
    if text.strip() == value:
        return None if value.isdigit() else Extractor(var="", kind="regex", pattern=_WHOLE_BODY_PATTERN, sample=value)
    escaped = value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    for spelling in dict.fromkeys((value, escaped)):
        pattern = _anchored_pattern(text, spelling, anchors)
        if pattern:
            return Extractor(var="", kind="regex", pattern=pattern, sample=spelling)
    return None


def _locate_regex(text: str, variants: list[str]) -> Optional[Extractor]:
    for v in variants:
        if len(v) < _MIN_REGEX_VALUE_LEN or v not in text:
            continue
        pattern = build_pattern(text, v, allow_ambiguous=is_dynamic_looking(v))
        if pattern:
            return Extractor(var="", kind="regex", pattern=pattern, sample=v)
    return None


def _locate_url(flow: Flow, variants: list[str]) -> Optional[Extractor]:
    """A value in the redirect target of a 3xx response: read at run time from ``resp.url`` (the
    URL requests ends up at after following the redirect).  A ``Location`` of any other status is a
    plain header (``_locate_header``)."""
    resp = flow.response
    if not (300 <= resp.status < 400):
        return None
    location = (resp.location or "").strip()
    if not location:
        return None
    try:
        resolved = urljoin(flow.request.url, location)
    except ValueError:
        return None
    for v in variants:
        if v in resolved:
            pattern = build_pattern(resolved, v, allow_ambiguous=is_dynamic_looking(v))
            if pattern:
                return Extractor(var="", kind="url", name="Location", pattern=pattern, sample=v)
    return None


def locate_value_kinds(value: str, source: Flow, kinds: Optional[frozenset] = None) -> Optional[Extractor]:
    """``locate_value`` restricted to the given extractor kinds (the plan section uses this for the
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
            # values written with character references (``&#x3D;``, ``&amp;``) are only visible once
            # the parser has unescaped them
            escaped = not present and "&" in text and any(v in view.unescaped for v in variants)
            if present or escaped:
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
    if allow("location"):
        ext = _locate_location(source, variants)
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
    equals ``value`` or one of its spellings, else None.  Deletions (``Max-Age=0`` or an
    ``Expires`` date in the past, RFC 6265) are never a source.

    The plan builder does not use this name-only lookup: it asks ``CookieTimeline`` which cookie
    (name, domain, path) held the value when the request was sent."""
    if not value:
        return None
    variants = set(value_variants(value))
    for flow in reversed(earlier):
        if flow.response is None:
            continue
        for raw in reversed(set_cookie_lines(flow.response)):
            info = parse_set_cookie_attrs(raw, flow.request.url, flow.started_at or None)
            if info is None or info.deletion or not info.value:
                continue
            cval = info.value
            if cval in variants or cval.strip('"') in variants:
                return info.name, cval
    return None


# ===== former reqrec/loops.py: pagination / repetition detection =====
# Pagination / repetition detection.  Contract: DESIGN.md §6.
#
# Three or more *consecutive* kept groups (redirect chains) whose first requests are identical
# except for exactly one parameter value fold into a single looped step.  Comparison covers method,
# scheme + host, path segment count, parameter names (path / query / form / JSON leaf paths /
# multipart text fields), body kind, raw body and request headers (after
# ``clean_request_headers``, ignoring ``Referer``).

_LOOPABLE_LOCATIONS = frozenset({"query", "form", "json", "path"})
_MIN_ITERATIONS = 3
_INT_RE = re.compile(r"^-?\d+$")


@dataclass
class LoopGroup:
    """Consecutive groups that fold into one looped step.

    ``occurrence`` disambiguates repeated parameter names (``id=1&id=2``): it is the 0-based index
    of the varying pair among the pairs sharing ``(location, name)``."""

    groups: list[list[Flow]]
    location: str  # "query" | "form" | "json" | "path"
    name: str  # param name / json dotted path / path segment index
    values: list[str]
    numeric_range: Optional[tuple[int, int]] = None
    occurrence: int = 0


@dataclass
class _Signature:
    shape: tuple  # everything that must be identical
    keys: list[tuple[str, str, int]]  # (location, name, occurrence) per parameter position
    values: list[str]


def _signature(flow: Flow) -> Optional[_Signature]:
    req = flow.request
    try:
        parts = urlsplit(req.url)
    except ValueError:
        return None
    params = request_params(flow)
    counter: dict[tuple[str, str], int] = {}
    keys: list[tuple[str, str, int]] = []
    values: list[str] = []
    for p in params:
        occ = counter.get((p.location, p.name), 0)
        counter[(p.location, p.name)] = occ + 1
        keys.append((p.location, p.name, occ))
        # cache-busters (``_=1700000000123``) become clock expressions in the plan, so they must
        # not count as the "one differing value"
        values.append("<timestamp>" if looks_like_timestamp(p.value, around=flow.started_at) else p.value)
    kind, _parsed = classify_body(req)
    headers = tuple(sorted((k.lower(), v) for k, v in clean_request_headers(req.headers) if k.lower() != "referer"))
    raw = req.body if kind == "raw" else None
    shape = ((req.method or "").upper(), parts.scheme.lower(), parts.netloc.lower(), tuple(keys), kind, headers, raw)
    return _Signature(shape=shape, keys=keys, values=values)


def _numeric_range(values: list[str]) -> Optional[tuple[int, int]]:
    """``(first, last)`` when the values are consecutive integers (step +1 or -1), else None."""
    if len(values) < 2 or not all(_INT_RE.match(v) for v in values):
        return None
    ints = [int(v) for v in values]
    if any(str(n) != v for n, v in zip(ints, values)):
        return None  # zero padded ("01") -> keep the literal list
    step = ints[1] - ints[0]
    if step not in (1, -1):
        return None
    if all(b - a == step for a, b in zip(ints, ints[1:])):
        return ints[0], ints[-1]
    return None


def _credential_parameter(groups: list[list[Flow]], first: int, location: str, name: str) -> bool:
    """Is the parameter a run of requests varies a credential: a credential-like name (``password``,
    ``txtPW``, ``pin``), or a password control of the form the run's first request submits (on the page
    its ``Referer`` names, else the page before)?  Such a run is never folded into a loop: each value
    stays its own 入力値 (read from the environment with ``--redact``) and no progress line shows it."""
    leaf = name.rsplit(".", 1)[-1].split("[", 1)[0] if location == "json" else name
    if looks_like_secret_name(leaf) or _looks_like_password_name(leaf):
        return True
    pages = [g[-1] for g in groups[:first] if g]
    if location not in ("query", "form") or not pages:
        return False
    referer = groups[first][0].request.header("referer")
    page = next((f for f in reversed(pages) if _same_page(f.request.url, referer)), pages[-1])
    view = _view(page)
    index = view.index if view.is_htmlish else None
    return index is not None and any(
        form.fields[name].control == "password" for form in index.forms if name in form.fields)


def detect_loops(groups: list[list[Flow]], opts: PlanOptions) -> list[LoopGroup]:
    """Find runs of >= 3 consecutive groups differing in exactly one parameter value."""
    sigs = [_signature(g[0]) if g else None for g in groups]
    out: list[LoopGroup] = []
    i = 0
    n = len(groups)
    while i < n:
        base = sigs[i]
        if base is None:
            i += 1
            continue
        pos: Optional[int] = None
        j = i + 1
        while j < n:
            sig = sigs[j]
            if sig is None or sig.shape != base.shape:
                break
            diffs = [k for k, (a, b) in enumerate(zip(base.values, sig.values)) if a != b]
            if len(diffs) != 1:
                break
            if pos is None:
                pos = diffs[0]
            elif diffs[0] != pos:
                break
            j += 1
        if pos is not None and j - i >= _MIN_ITERATIONS:
            location, name, occurrence = base.keys[pos]
            values = [sigs[k].values[pos] for k in range(i, j)]
            # Hash-like values (cursors, ids from a listing) are each traceable to an earlier
            # response; folding them into a literal list would break that chain, so only
            # counter-like / word-like values are folded.  Credentials (a mistyped password retried)
            # never are: the loop would print them and write them into the script.
            if (location in _LOOPABLE_LOCATIONS and not any(is_dynamic_looking(v) for v in values)
                    and not _credential_parameter(groups, i, location, name)):
                out.append(LoopGroup(
                    groups=list(groups[i:j]),
                    location=location,
                    name=name,
                    values=values,
                    numeric_range=_numeric_range(values),
                    occurrence=occurrence,
                ))
                i = j
                continue
        i += 1
    return out


# ===== former reqrec/plan.py: Recording -> Plan (build_plan) =====
# Recording -> Plan.  Contract: DESIGN.md §7.
#
# ``build_plan`` turns the kept flows of a recording into ``Step`` objects, replacing every request
# value that can be traced to an earlier response (``deps``), to a cookie, to the clock, or to a
# repeated literal (``Constant``) by a ``Ref`` that the generated script resolves at run time.

#: Identifiers the generated script defines itself; never reused for variables / constants.
_CODEGEN_NAMES = frozenset({
    "TIMEOUT", "DELAY", "BASE_HEADERS", "INITIAL_COOKIES", "main", "session", "resp", "soup", "ctx",
    "results", "data", "step", "requests", "re", "json", "os", "sys", "time", "unquote", "urljoin",
    "BeautifulSoup", "_soup", "_check", "_regex", "_json_path", "_json_row", "_attr", "_text",
    "DEBUG", "DEPENDENCIES", "SESSION_SWITCHES", "ISSUED_PLACES", "urlencode", "urlsplit",
    "_debug", "_mask_url", "_mask_text", "_cookie", "_cookie_keys", "_set_cookie", "_need", "_hop",
    "_host_cookie_hook",
    "_cookie_attr_hook", "_ie_cookie_hook", "_Session", "functools", "warnings", "_windows_certificates",
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


_DOTTED_PART_RE = re.compile(r"\[(\d+)\]|([^.\[\]]+)")


def _dotted_to_path(dotted: str) -> list:
    """``"a.b[0].c"`` -> ``["a", "b", 0, "c"]`` (inverse of ``json_dotted`` for naming)."""
    return [int(m.group(1)) if m.group(1) is not None else m.group(2) for m in _DOTTED_PART_RE.finditer(dotted or "")]


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
    word = safe_identifier(stem, default="")
    return _singular(word) if word and _WORD_RE.match(stem) else word


def _is_reserved_name(base: str) -> bool:
    """True when ``safe_identifier`` had to rename ``base`` because it is a keyword / builtin
    (``id`` -> ``id_``, ``type`` -> ``type_``)."""
    ident = safe_identifier(base, default="value")
    return ident.endswith("_") and not base.rstrip().endswith("_")


def _route_like(value: str) -> bool:
    """Plain words, file names and screen-id pages (``dashboard``, ``Default.aspx``,
    ``SC0010.aspx``) are route names, not tokens; a value with random-looking letters
    (``xBBHOHpXYZgFKyNZpuWy``, also before an extension or between ``-`` / ``_``) is a token.
    See ``is_route_like``."""
    return is_route_like(value)


#: Locators that read markup or match a pattern.  A route-like path segment (``Login.aspx``) found
#: there is a coincidence (``action="Login.aspx"``), never the source of the value.
_MARKUP_KINDS = frozenset({"html_attr", "html_text", "regex", "url"})
#: What a route-like path segment may still be traced to: exact structural matches (a short letters
#: session key ``/s/QZVBNMWRT/`` can be a JSON leaf or a header of an earlier response).
_ROUTE_SEGMENT_KINDS = frozenset({"header", "json", "html_input", "html_meta"})


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


#: Traced values shorter than this are not substituted inside a ``Referer`` (a short id could equal
#: an unrelated query value or path segment by coincidence).
_REFERER_MIN_VALUE = 8
#: ``scheme://host[:port]`` | path | ``?query`` | ``#fragment`` of an absolute URL, split so that
#: joining the groups gives back the exact recorded text.
_ABS_URL_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://[^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$", re.S)


def _unquoted_source(ref: Ref) -> Optional[str]:
    """``X`` for a Ref ``unquote(X)`` (a value whose recorded source spelling was percent-encoded),
    else None."""
    if ref.kind != "expr":
        return None
    try:
        node = ast.parse(ref.value, mode="eval").body
    except SyntaxError:
        return None
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "unquote"
            and len(node.args) == 1 and not node.keywords and not isinstance(node.args[0], ast.Starred)):
        return ast.get_source_segment(ref.value, node.args[0])
    return None


def _referer_token(token: str, swaps: dict[str, Ref], plus: bool) -> Optional[str]:
    """Expression source producing a fresh spelling of a whole Referer token, or None to keep it.

    The token is either the recorded value itself (-> ``str(ref)``) or its percent-encoded
    spelling (``a%2Bb%3D`` for ``a+b=``): then the encoded source the value was decoded from is
    used when the Ref is ``unquote(X)``, else ``requests.utils.quote(str(ref), safe='')`` (the
    generated script always imports ``requests``; ``requests.utils.quote`` is
    ``urllib.parse.quote``)."""
    ref = swaps.get(token)
    if ref is not None:
        return f"str({ref.value})"
    if "%" not in token and not (plus and "+" in token):
        return None
    decoded = unquote(token.replace("+", " ") if plus else token)
    ref = swaps.get(decoded)
    if ref is None or decoded == token:
        return None
    source = _unquoted_source(ref)
    if source is not None:
        return f"str({source})"
    return f"requests.utils.quote(str({ref.value}), safe='')"


def _referer_with_fresh_values(value: str, refs: dict, secrets: Optional[dict[str, Ref]] = None) -> Ref:
    """``Referer: .../Search.aspx?key=<recorded key>`` -> the same URL built with the key traced for
    this step or an earlier one (the Referer is usually the URL of an earlier step), so the header
    never carries a stale session value.

    Only whole tokens are replaced: a whole path segment (or the value of a ``;name=value`` path
    parameter such as ``;jsessionid=``) and a whole query value (or a query item without ``=``),
    each either verbatim or in its percent-encoded spelling.  ``scheme://host`` and the fragment
    stay literal, and a value is never replaced inside a longer token.  Only non-literal refs in
    ``refs`` (this step's first, then the earlier steps' extractor variables) whose recorded value
    has at least ``_REFERER_MIN_VALUE`` characters are used; anything else stays literal - except a
    traced path segment, ``;name=`` path parameter or query value (not a number), which is replaced at
    the same place of the Referer (the same path index, parameter name, query name) whatever its length
    (a short session key: ``/oms/s/XRLDNXD/menu``, ``menu.do;sid=XRLDNXD``, ``menu.do?sid=XRLDNXD``).

    ``secrets`` (recorded value -> Ref of a secret constant) is used, whatever the value's length,
    for query items whose name looks like a credential (``Login.aspx?pw=abc`` as the previous
    page), so a password never reaches the script through the Referer."""
    swaps: dict[str, Ref] = {}
    place_swaps: dict[tuple[str, str, str], Ref] = {}  # (candidate location, name, value) -> Ref
    for (loc, name, raw), ref in refs.items():
        if ref is None or ref.is_literal or not isinstance(raw, str):
            continue
        if loc in ("path", "path_param", "query") and raw and not raw.isdigit():
            place_swaps.setdefault((loc, name, raw), ref)
        if len(raw) < _REFERER_MIN_VALUE:
            continue
        swaps.setdefault(raw, ref)
    secrets = {raw: ref for raw, ref in (secrets or {}).items() if raw and ref is not None and not ref.is_literal}
    m = _ABS_URL_RE.match(value) if swaps or secrets or place_swaps else None
    if m is None:
        return Ref.lit(value)
    head, path, query, fragment = m.groups()
    pieces: list[tuple[bool, str]] = [(False, head)]  # (is_expr, text)

    def token(text: str, plus: bool, name: str = "", place: Optional[tuple[str, str, str]] = None) -> None:
        expr = _referer_token(text, swaps, plus) if text else None
        if expr is None and place in place_swaps:
            expr = f"str({place_swaps[place].value})"
        if expr is None and text and secrets and looks_like_secret_name(unquote(name.replace("+", " "))):
            expr = _referer_token(text, secrets, plus)
        pieces.append((True, expr) if expr is not None else (False, text))

    for i, segment in enumerate(path.split("/")):
        if i:
            pieces.append((False, "/"))
        first, *params = segment.split(";")
        token(first, False, place=("path", str(i - 1), first))  # i - 1: the index after the leading "/"
        for param in params:
            pieces.append((False, ";"))
            pname, eq, pvalue = param.partition("=")
            if eq:
                pieces.append((False, pname + "="))
                token(pvalue, False, place=("path_param", f"{i - 1};{pname}", pvalue))
            else:
                token(param, False)
    if query is not None:
        pieces.append((False, "?"))
        for i, item in enumerate(query.split("&")):
            if i:
                pieces.append((False, "&"))
            qname, eq, qvalue = item.partition("=")
            if eq:
                pieces.append((False, qname + "="))
                token(qvalue, True, qname, place=("query", qname, qvalue))
            else:
                token(item, True)
    if fragment is not None:
        pieces.append((False, "#" + fragment))
    if not any(is_expr for is_expr, _ in pieces):
        return Ref.lit(value)
    parts: list[str] = []
    literal = ""
    for is_expr, text in pieces:
        if not is_expr:
            literal += text
            continue
        if literal:
            parts.append(repr(literal))
            literal = ""
        parts.append(text)
    if literal:
        parts.append(repr(literal))
    return Ref.expr(" + ".join(parts))


def _response_kind(flow: Flow) -> str:
    resp = flow.response
    if resp is None or not resp.body:
        return "empty"
    mime = (resp.mime_type or "").lower()
    if is_html_mime(mime):
        return "html"
    if is_json_mime(mime):
        return "json"
    if is_xml_mime(mime):
        return "xml"
    if is_textual_mime(mime):
        return "json" if parse_json_text(resp.text()) is not None else "text"
    if not mime or mime == "application/octet-stream":
        head = resp.body[:4096]
        if b"\x00" in head:
            return "binary"
        text = resp.text() or ""
        if parse_json_text(text) is not None:
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


def describe_extractor(ext: Extractor) -> str:
    """Plain-Japanese, value-free description of where an extractor reads its value (the script's
    dependency table, comments and debug output)."""
    kind = ext.kind
    hop = f"リダイレクト中の {ext.hop + 1} 番目の応答の" if ext.hop is not None else ""
    regex = "（正規表現で抽出）" if ext.pattern else ""
    if kind == "cookie":
        if ext.cookie_url is None and ext.cookie_path is None:  # read for the step's final URL (resp.url)
            return f"Cookie {ext.name}（domain={ext.cookie_domain or '-'}、このステップの最後の URL に送られるもの）"
        return f"Cookie {ext.name}（domain={ext.cookie_domain or '-'}, path={_scope_text(ext.cookie_path) or '/'}）"
    if kind == "header":
        return f"{hop}レスポンスヘッダー {ext.name}{regex}"
    if kind == "json" and ext.row is not None and ext.row_key:
        path = list(ext.path or [])
        by = f" {ext.row_field} と同じ値" if ext.row_field else "記録時と同じ値"
        return (f"レスポンス JSON の一覧 {json_dotted(path[:ext.row]) or '(全体)'} で {json_dotted(list(ext.row_key))} が{by}の行の "
                f"{json_dotted(path[ext.row + 1:]) or '(行全体)'}")
    if kind == "json":
        return f"レスポンス JSON の {json_dotted(list(ext.path or [])) or '(全体)'}"
    if kind == "html_input":
        return f'HTML の <input name="{ext.name}"> の value'
    if kind == "html_meta":
        return f'HTML の <meta name="{ext.name}"> の content'
    if kind == "html_attr":
        return f"HTML の要素 {ext.selector} の属性 {ext.attr}{regex}"
    if kind == "html_text":
        return f"HTML の要素 {ext.selector} のテキスト{regex}"
    if kind == "regex":
        return "レスポンス本文（スクリプト内の値を含む）を正規表現で検索"
    if kind == "url":
        return "リダイレクト先の URL"
    return str(kind)


def describe_cookie(ver: CookieVersion, issued_step: Optional[int] = None, path: Optional[str] = None) -> str:
    """``Cookie NAME（domain=..., path=...、ステップ 2 の Set-Cookie で発行）`` (never the value).  ``path``: the
    path as shown when a segment of it is read afresh (``/s/{s_id}/``), never the recorded key."""
    if ver.origin == "server":
        how = f"ステップ {issued_step} の Set-Cookie で発行" if issued_step else "Set-Cookie で発行"
    elif ver.external_kind == "pre-existing":
        how = "記録を始める前からブラウザにあった Cookie"
    else:
        how = "画面のスクリプトが設定した Cookie"
    return f"Cookie {ver.name}（domain={ver.domain}, path={path or ver.jar_path}、{how}）"


def _scope_text(scope: Any) -> str:
    """A cookie scope URL / path as text: a str as it is; URL pieces (``Ref`` tuple, joined like ``Step.url``)
    with every non-literal piece shown as ``{var}`` (never a value)."""
    if isinstance(scope, (list, tuple)):
        return "".join(str(p.value) if isinstance(p, Ref) and p.is_literal else "{" + str(getattr(p, "value", p)) + "}"
                       for p in scope)
    return "" if scope is None else str(scope)


def _joined_pieces(pieces: Sequence[Ref]) -> tuple:
    """URL pieces with neighbouring literals joined (``('http://h/a/', s_id, '/')``)."""
    out: list[Ref] = []
    for piece in pieces:
        if piece.is_literal and out and out[-1].is_literal:
            out[-1] = Ref.lit(out[-1].value + piece.value)
        elif not (piece.is_literal and not piece.value):
            out.append(piece)
    return tuple(out)


def _ref_names(ref: Ref) -> Optional[set[str]]:
    """The variables / constants a Ref reads (None: an expression that does not parse)."""
    if ref.is_literal:
        return set()
    if ref.kind == "var":
        return {str(ref.value)}
    try:
        return set(_expr_names(str(ref.value)))
    except SyntaxError:
        return None


def _request_scope(url: str, segments: dict[int, tuple[str, Ref]], fallback: str) -> Union[str, tuple]:
    """A request's own URL as the scope of a cookie it sends (``_cookie``'s URL): scheme://host and the
    path segments as ``segments`` gives their Refs (``;params`` and the query left out); it ends before a
    segment ``segments`` does not hold.  A str when every piece is literal."""
    try:
        parts = urlsplit(url)
        pieces: list[Ref] = [Ref.lit(f"{parts.scheme or 'http'}://{parts.netloc}")]
        for i, seg in enumerate(_path_segments(url)):
            pieces.append(Ref.lit("/"))
            base = split_path_segment(seg)[0]
            if base and i not in segments:
                break
            if base:
                pieces.append(segments[i][1])
    except ValueError:
        return fallback
    joined = _joined_pieces(pieces)
    return joined[0].value if len(joined) == 1 and joined[0].is_literal else joined


def _fresh_cookie_path(path: str, segments: dict[int, tuple[str, Ref]]) -> tuple[bool, Optional[tuple], str]:
    """A recorded cookie path against the path segments of a request it reaches (``segments``: index ->
    (recorded segment, Ref)): whether a segment of it is one the request reads afresh (``/s/<key>/``), the
    path built from the same pieces (None when none is), and the path shown with such a segment as ``{var}``."""
    pieces: list[Ref] = []
    fresh = False
    for j, part in enumerate((path or "/").split("/")):
        if j:
            pieces.append(Ref.lit("/"))
        hit = segments.get(j - 1) if j and part else None
        if hit is not None and hit[0] == part and not hit[1].is_literal:
            fresh = True
            pieces.append(hit[1])
        else:
            pieces.append(Ref.lit(part))
    joined = _joined_pieces(pieces)
    return fresh, (joined if fresh else None), _scope_text(joined)


def _referer_places(value: str) -> list[tuple[str, str, str]]:
    """``(location, name, token)`` of the whole tokens of an absolute Referer URL, named as
    ``_referer_with_fresh_values`` places them: a path segment (its index after the leading ``/``), a
    ``;name=`` path parameter (``<index>;<name>``), a query value (its name)."""
    m = _ABS_URL_RE.match(value or "")
    if m is None:
        return []
    _head, path, query, _fragment = m.groups()
    out: list[tuple[str, str, str]] = []
    for i, segment in enumerate(path.split("/")):
        first, *params = segment.split(";")
        if i and first:
            out.append(("path", str(i - 1), first))
        for param in params:
            pname, eq, pvalue = param.partition("=")
            if i and eq and pvalue:
                out.append(("path_param", f"{i - 1};{pname}", pvalue))
    for item in query.split("&") if query else ():
        qname, eq, qvalue = item.partition("=")
        if eq and qvalue:
            out.append(("query", qname, qvalue))
    return out


def _issued_token(value: str) -> bool:
    """A value worth reading again from the redirect that handed it out: a token, an id with digits, a
    number of 8+ digits or letters not spelled as words - never a word or a small number (``mode=list``,
    ``page=2`` stay as recorded)."""
    if len(value) < 6:
        return False
    if value.isdigit():
        return len(value) >= _REFERER_MIN_VALUE
    if value.isascii() and value.isalpha():
        return not _spelled_as_words(value)
    return is_dynamic_looking(value) or _token_shaped(value)


@dataclass
class _Resolution:
    """How one request value was resolved (feeds ``Step.bindings``)."""

    value_class: str
    source: str = ""
    source_step: Optional[int] = None
    source_kind: str = ""
    var: Optional[str] = None
    cookie: Optional[CookieVersion] = None
    note: str = ""


#: Dropped-flow reasons whose flows may be put back as producers (``PlanOptions.include_producers``);
#: never "excluded by user", host filters, trackers (internet hosts a LAN PC may not reach), missing
#: responses, preflights or streams.
_PRODUCER_REASON_PREFIXES = ("static asset", "304 not modified")
#: Untraced literals at least this long are looked up in dropped flows.
_PRODUCER_MIN_VALUE = 6
#: Credential-like names whose values may look random and are still user input (passwords).
_PASSWORD_NAME_RE = re.compile(r"pass|pwd|secret", re.I)


#: Locators that find a value exactly (no pattern): what "the field was filled by script" needs.
_EXACT_KINDS = frozenset({"header", "json", "html_input", "html_meta", "html_attr", "html_text"})
_NAME_TOKEN_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
#: Name parts of a password field (``txtPW``, ``j_password``, ``userPwd``); used only to keep such values
#: out of the request code (an 入力値 constant), never to decide where a value comes from.
_PASSWORD_TOKENS = frozenset({"pass", "password", "passwd", "pwd", "pw", "passphrase", "pin"})


def _looks_like_password_name(name: str) -> bool:
    """Does a field name have a password-like part (``txtPW``, ``userPwd``; not ``passengerName``)?"""
    return any(tok.lower() in _PASSWORD_TOKENS for tok in _NAME_TOKEN_RE.findall(name or ""))


def _names_related(a: str, b: str) -> bool:
    """Two names that share a run of at least 4 letters / digits (``slipNo`` / ``txtSlipNo``,
    ``XSRF-TOKEN`` / ``X-XSRF-TOKEN``): a coincidence guard, never a source by itself."""
    x = re.sub(r"[^a-z0-9]", "", (a or "").lower())
    y = re.sub(r"[^a-z0-9]", "", (b or "").lower())
    short, long_ = sorted((x, y), key=len)
    return len(short) >= 4 and short in long_


def _names_alike(a: str, b: str) -> bool:
    """Names of one field in two places (a form field and the JSON key / query name the page's script
    sends it under): related (``dateFrom`` / ``txtDateFrom``), or the words of one end the other
    (``to`` / ``txtTo``, ``no`` / ``txtNo``)."""
    if _names_related(a, b):
        return True
    x = [t.lower() for t in _NAME_TOKEN_RE.findall(a or "")]
    y = [t.lower() for t in _NAME_TOKEN_RE.findall(b or "")]
    short, long_ = sorted((x, y), key=len)
    return bool(short) and long_[len(long_) - len(short):] == short


def _token_shaped(value: str) -> bool:
    """At least 6 characters mixing letters with digits or ``|%_-.~+/=`` - a token, not a date, a word
    or a number (``xsrf|AbC123``, ``S3SS10N``)."""
    v = value or ""
    if len(v) < 6 or v.isdigit() or _DATE_RE.match(v) or _PLAIN_WORDS_RE.match(v):
        return False
    return any(c.isalpha() for c in v) and any(c.isdigit() or c in "|%_-.~+/=" for c in v)


def _submitted_fields(req: RecordedRequest) -> list[tuple[str, str, str]]:
    """``(location, name, value)`` of the query and form / multipart text fields, in request order."""
    out = [("query", name, value) for name, value in parse_form_bytes(query_bytes(req.query))]
    kind, parsed = classify_body(req)
    if kind == "form":
        out.extend(("form", name, value) for name, value in parsed)
    elif kind == "multipart":
        out.extend(("multipart", fld.name, fld.text()) for fld in parsed if not fld.is_file)
    return out


def _field_key(location: str, name: str) -> str:
    """A form / query / JSON field across locations: its (last) name, lower-cased (``username`` in a login
    form and in a later JSON body are the same field)."""
    name = str(name or "")
    if location == "json":
        name = name.rsplit(".", 1)[-1].split("[", 1)[0]
    return name.lower()


def _ref_name(ref: Ref) -> str:
    """The constant / variable a Ref reads (``NAME`` of ``NAME.encode('cp932')``)."""
    return str(ref.value).split(".", 1)[0] if ref.kind == "expr" else str(ref.value)


def _same_page(a: Optional[str], b: Optional[str]) -> bool:
    """The same URL apart from the fragment and the case of scheme / host."""
    if not a or not b:
        return False
    return _normalise_url(str(a).split("#", 1)[0]) == _normalise_url(str(b).split("#", 1)[0])


@dataclass
class _FormMatch:
    """The HTML form a request submits: the form, the step whose page holds it and the page charset."""

    form: FormInfo
    built: "_Built"
    charset: str = "utf-8"


class _Builder:
    """Stateful plan construction (one instance per ``build_plan`` call)."""

    def __init__(self, recording: Recording, opts: PlanOptions) -> None:
        self.recording = recording
        self.opts = opts
        self.warnings: list[str] = []
        self.constants: list[Constant] = []
        self.const_by_value: dict[str, Constant] = {}
        #: secret constants by value: a field whose name looks secret never shares a plain constant
        #: (``txtUserId=tanaka01&txtPassword=tanaka01`` -> a literal user id and a secret password)
        self.secret_by_value: dict[str, Constant] = {}
        self.const_uses: dict[str, list[str]] = {}
        self.taken: set[str] = set(_CODEGEN_NAMES) | {n.lower() for n in _CODEGEN_NAMES}
        self.func_names: set[str] = set()
        self.built: list[_Built] = []
        self.earlier_flows: list[Flow] = []
        #: values traced for the steps built so far -> their extractor variable, for the Referer of a later
        #: step (usually the URL of an earlier step: ``/search?tk=<the token of that step>``)
        self.traced_refs: dict[tuple[str, str, str], Ref] = {}
        self.value_units: dict[str, set[int]] = {}
        self.base_headers = []
        self.base_set: set[tuple[str, str]] = set()
        # --- phase 2 (DESIGN.md §13) ---
        self.auth: Optional[AuthInfo] = None
        self.auth_hops: dict[int, list[Flow]] = {}  # id(final attempt) -> its 401 hops
        self.auth_credentials: Optional[tuple[str, str]] = None  # Basic: (user, password) behind Plan.auth
        self.auth_token_units: dict[str, set[int]] = {}  # session-auth tokens sent by several steps
        self.auth_header_warned: set[tuple[str, str]] = set()
        # --- dependency analysis (DESIGN.md §14) ---
        self.timeline: Optional[CookieTimeline] = None
        self.kept_ids: set[int] = set()
        self.flow_step: dict[int, int] = {}  # id(flow) -> step index of every kept flow
        #: the text of each 入力値 (user input, B) -> ``(field name, Ref)`` of every field typed with it, in
        #: order (a later request that sends the text again - an XHR JSON body, a query the page's script
        #: builds - stays that user input: ``_typed_elsewhere``)
        self.input_refs: dict[str, list[tuple[str, Ref]]] = {}
        #: per step: the recorded bytes of each query / form value (``(location, name, value)``) and the
        #: charset the request body declares - they decide whether a value was sent in a legacy charset
        self._raw_fields: dict[tuple[str, str, str], bytes] = {}
        self._raw_charset: Optional[str] = None
        #: dropped flows a kept request needs (flow id -> what it provides), put back by build_plan
        self.needed_producers: dict[str, list[str]] = {}
        self.dropped_by_id: dict[str, Dropped] = {}
        self.dropped_flows: list[Flow] = []
        #: per step: cookie lookups / cookie sets / value resolutions (reset by _build_step)
        self._lookups: dict[tuple, CookieLookup] = {}
        #: the request's path segments resolved so far (``_segment_refs``: refs, loop key, loop Ref), those of
        #: every built step, and cookie paths with a segment read afresh as shown (``/s/{s_id}/``) by identity
        self._step_scope: tuple = ({}, None, None)
        self._step_segments: dict[int, dict[int, tuple[str, Ref]]] = {}
        self.shown_cookie_paths: dict[tuple[str, str, str], str] = {}
        self._meta: dict[tuple, _Resolution] = {}
        self._last_meta = _Resolution("A")
        #: per step: rows of JSON lists chosen by a value the request sends in another field (``_json_choice``)
        self._row_choices: list[Extractor] = []
        self.cookie_first_use: set[int] = set()  # server cookie versions already listed as a binding
        #: (location, field name) -> (sent value, Ref, step, resolution) of the fields that were user input
        self.input_fields: dict[str, tuple[str, Ref, int, _Resolution]] = {}
        self._short_metas: dict[tuple[str, str, str], _Resolution] = {}
        self.loop_spans: list[tuple[int, int]] = []  # timeline positions of the folded loops' requests
        self._warned_values: set[str] = set()
        self._link_urls: dict[int, list[str]] = {}  # per page flow: the URLs its links / forms / frames go to
        self._first_sent: dict[str, int] = {}  # per value: position of the first request URL holding it
        #: external cookie versions already set by an earlier step (or INITIAL_COOKIES)
        self.external_done: set[int] = set()
        #: per page-written cookie version: the steps that do not send it although the browser did (the page
        #: that writes it answers later - see ``_written_by_a_later_page``)
        self.cookie_unsent: dict[int, set[int]] = {}
        self.plan_units: list[_Unit] = []  # the steps' units in order (set by ``build``)
        self.initial_cookies: list[InitialCookie] = []

    # ------------------------------------------------------------------ naming

    def _cand_base_name(self, cand: Candidate, flow: Flow) -> str:
        if cand.location == "json":
            return _json_leaf_name(cand.json_path)
        if cand.location == "path_param":
            return cand.name.split(";", 1)[-1] or "path_param"
        if cand.location == "path":
            try:
                return _path_seg_name(_path_segments(flow.request.url), int(cand.name))
            except ValueError:
                return f"path_seg_{cand.name}"
        return cand.name

    def _var_name(self, cand: Candidate, ext: Extractor, flow: Flow) -> str:
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
            if route and route != safe_identifier(base).rstrip("_"):
                base = f"{route}_{base}"
        return unique_name(safe_identifier(base, default="value"), self.taken)

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
        return unique_name(safe_identifier(base, default="page"), self.taken)

    def _func_name(self, index: int, flow: Flow, dynamic_segments: set[int]) -> str:
        # path parameters (``;jsessionid=...``) never become part of a name
        segments = [split_path_segment(s)[0] for s in _path_segments(flow.request.url)]
        parts = [s for i, s in enumerate(segments) if s and i not in dynamic_segments and not s.isdigit()]
        slug_src = "_".join(parts[-2:]) if parts else flow.request.host
        slug = safe_identifier(slug_src, default="root")[:_MAX_SLUG_LEN].strip("_") or "root"
        base = f"step_{index:02d}_{flow.request.method.lower()}_{slug}"
        return unique_name(base, self.func_names)

    # ------------------------------------------------------------------ constants

    def _secret_field(self, name: str) -> bool:
        """Is ``name`` a field whose value must be read from the environment (DESIGN.md §7)?"""
        return bool(self.opts.redact_secrets and looks_like_secret_name(name))

    def _constant(self, cand: Candidate, value: str, flow: Flow, step_no: int, force_secret: bool = False,
                  kind: str = "shared") -> Ref:
        """The shared ``Constant`` for ``value`` (created on first use).

        A secret use (``force_secret`` or a credential-like name, when ``redact_secrets``) only ever
        reuses a *secret* constant: a password equal to the user id gets its own environment variable
        instead of turning the user id's constant into one.  A plain use reuses any constant of the
        value (a form field carrying the Basic password reuses ``AUTH_PASSWORD`` rather than leaking it).
        ``kind="input"`` marks the constant as user input (class B: the script's 入力値 section): one per
        field, never found by value (another field or a later value with the same text gets its own); it
        shares only a constant read from the environment (never written out) or, for a password, an
        earlier password with the same value (a confirmation field)."""
        secret = self.opts.redact_secrets and (force_secret or looks_like_secret_name(cand.name))
        const = self.secret_by_value.get(value) if secret else self.const_by_value.get(value)
        if kind == "input" and not secret:
            if const is not None and not const.secret:
                const = None
            if const is None and force_secret:
                const = next((c for c in self.constants if c.kind == "input" and c.sensitive and c.value == value), None)
        if const is not None and kind == "input" and const.kind == "shared":
            const.kind = "input"
        if const is None:
            base = safe_identifier(self._cand_base_name(cand, flow), default="value").upper()
            name = unique_name(base, self.taken)
            const = Constant(name=name, value=value, secret=secret, env_var=f"REQREC_{name}" if secret else None,
                             kind=kind)
            self.constants.append(const)
            if kind != "input" or secret:
                self.const_by_value.setdefault(value, const)
            if secret:
                self.secret_by_value[value] = const
            self.const_uses[name] = []
            if secret:
                self.warnings.append(
                    f"step {step_no}: `{cand.name}` looks like a credential; the script reads it from the "
                    f"environment variable {const.env_var} (set it before running)"
                )
        self.const_uses[const.name].append(f"step {step_no} ({cand.location} `{cand.name}`)")
        return Ref.var(const.name)

    def _secret_ref(self, location: str, name: str, value: str, flow: Flow, step_no: int) -> Optional[Ref]:
        """Secret constant for a field that is *not* a trace candidate (``password=admin``,
        ``pin=123``: too short or a plain word) but whose name looks like a credential; None when
        the value must stay literal (redaction off, ordinary name, empty value)."""
        if not value or not self._secret_field(name):
            return None
        json_path = _dotted_to_path(name) if location == "json" else None
        cand = Candidate(location, name, value, json_path=json_path)
        return self._constant(cand, value, flow, step_no, force_secret=True)

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
                prefix, token = split_auth_header(value)
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
            name=unique_name("AUTH_USERNAME", self.taken), value=user, secret=False,
            comment=f"HTTP {kind.capitalize()} 認証のユーザー名",
        )
        pw_const = Constant(
            name=unique_name("AUTH_PASSWORD", self.taken), value=password or "", secret=secret,
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
            if pw_const.secret:
                self.secret_by_value.setdefault(password, pw_const)
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
        prefix, token = split_auth_header(value)
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
        cand = Candidate("header", "authorization", token, prefix=prefix)
        if self.opts.redact_secrets or len(self.auth_token_units.get(token, ())) >= 2:
            return _with_prefix(prefix, self._constant(cand, token, flow, step_no, force_secret=True))
        return Ref.lit(prefix + token)

    # ------------------------------------------------------------------ legacy-charset forms (DESIGN.md §13.4)

    def _legacy_form_hint(self, body: Optional[bytes], form: list[tuple[str, Ref]], charset: Optional[str] = None,
                          keep: Iterable[str] = (), raws: Optional[list[bytes]] = None
                          ) -> tuple[list[tuple[str, Ref]], list[str]]:
        """``form`` pairs for a body (or query) replayed in its recorded legacy charset (``charset``: the one
        the request declares), and the names of the pairs sent as the recorded bytes.  ``raws``: the
        recorded values instead of ``body`` (multipart text parts).

        A pair whose recorded bytes are UTF-8 keeps its Ref.  For the others (IE on a Shift_JIS page): a
        constant holding the text (an 入力値) is sent as ``NAME.encode(charset)``, a value read from a
        response or a cookie is converted the same way or from its percent-encoded spelling (a value the
        page pre-filled arrives as ``var.encode(charset)`` already), the loop variable in ``keep`` (it
        already gives the bytes) stays, a password read from the environment is sent in the form's charset
        when it is known, and anything else becomes the recorded bytes (``requests`` percent-encodes bytes
        verbatim and sends them as they are in a multipart part)."""
        if raws is None:
            raws = [value for _name, value in form_pairs_bytes(body)]
            texts = [value for _name, value in parse_form_bytes(body, charset)]
        else:
            texts = [_form_text(raw, charset) for raw in raws]
        by_name = {c.name: c for c in self.constants}
        keep = set(keep)
        out: list[tuple[str, Ref]] = []
        kept: list[str] = []
        for i, (name, ref) in enumerate(form):
            raw_value = raws[i] if i < len(raws) else b""
            if is_utf8(raw_value) or (not ref.is_literal and _ref_name(ref) in keep) or (
                    ref.kind == "expr" and _ENCODED_VAR_RE.fullmatch(ref.value)):  # already var.encode(charset)
                out.append((name, ref))
                continue
            text = texts[i] if i < len(texts) else ""
            const = by_name.get(ref.value) if ref.kind == "var" else None
            sent: Optional[Ref] = None
            if const is not None:
                encoding = const.encoding or charset
                if const.secret:
                    # read from the environment as text (--redact): sent in the charset the form used
                    sent = Ref.expr(f"{const.name}.encode({encoding!r})") if encoding else ref
                elif isinstance(const.value, (bytes, bytearray)):
                    sent = ref
                elif _encodes_to(const.value, encoding, raw_value):
                    sent = Ref.expr(f"{const.name}.encode({encoding!r})")
            elif not ref.is_literal:
                src = ref.value if ref.kind == "var" else f"({ref.value})"
                if unquote_to_bytes(text) == raw_value:  # the source holds the percent-encoded spelling
                    sent = Ref.expr(f"unquote({src}.replace('+', ' '), 'latin-1').encode('latin-1')")
                elif _encodes_to(text, charset, raw_value):
                    sent = Ref.expr(f"{src}.encode({charset!r})")
            if sent is None:
                sent = Ref.expr(repr(raw_value))
                kept.append(name)
            out.append((name, sent))
        return out, kept

    def _escaped_hint(self, body: Optional[bytes], pairs: list[tuple[str, Ref]], charset: Optional[str]
                      ) -> tuple[list[tuple[str, Ref]], list[str]]:
        """``pairs`` of a query / form body whose values an old page script built with ``escape()``
        (``%uXXXX``), and their names.  ``requests`` cannot send that spelling (it percent-encodes the
        ``%``), so such a value (its Ref holds the text, ``js_unescape``) is sent in the page's ``charset``
        instead: IIS / ASP.NET decode both spellings to the same text."""
        by_name = {c.name: c for c in self.constants}
        out = list(pairs)
        names: list[str] = []
        for i, segment in enumerate(split_form_segments(body)[:len(pairs)]):
            text = js_unescape(segment.partition(b"=")[2])
            if text is None:
                continue
            name, ref = pairs[i]
            names.append(name)
            if not charset or charset == "utf-8" or _legacy_text(text.encode(charset, "replace"), charset) != text:
                continue  # sent as UTF-8 like any str (also a text the page's charset cannot hold)
            const = by_name.get(ref.value) if ref.kind == "var" else None
            if ref.is_literal:
                out[i] = (name, Ref.expr(f"{_lit(ref.value)}.encode({charset!r})"))
                continue
            if const is not None and not isinstance(const.value, str):
                continue  # recorded bytes already
            if const is not None and not const.secret:
                const.encoding = const.encoding or charset  # its comment then says it is converted
            src = ref.value if ref.kind == "var" else f"({ref.value})"
            out[i] = (name, Ref.expr(f"{src}.encode({charset!r})"))
        return out, names

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

    # ------------------------------------------------------------------ resolution (DESIGN.md §14)
    #
    # A request value is resolved in this order (the first source that explains it wins).  Per form
    # field (``_field_decision``, never shared with other fields):
    #
    # 1. the same field was user input in an earlier step with this value -> the same 入力値 (B);
    # 2. the field's own default on the form page (an <input> the server filled in) -> that page (C);
    # 3. an editable field an XHR / popup response filled exactly -> that response (C);
    # 4. a visible control the user changed (typed / chosen / password) -> 入力値 constant (B).
    #
    # Per value (cached within a step):
    #
    # 5. a cookie the browser held at that moment, by its identity (name, domain, path) -> jar lookup (D);
    # 6. an earlier response, latest step first: a cookie renewed since (D, read right after that step),
    #    the final response (every locator), the redirect responses (headers / Location) (C);
    # 7. (a dropped request holding it is put back by build_plan);  8. the clock (E);
    # 9. a value typed into another field earlier, a credential-like name, a visible input the user changed
    #    (B);  10. a value several steps send (A, shared constant);  11. an existing constant;
    # 12. the recorded literal (A; warned when it looks dynamic).

    @staticmethod
    def _cookie_transform(cookie_value: str, value: str) -> Optional[str]:
        """How a request value is spelled relative to a cookie value: ``""`` (as is), ``"unquote"``,
        ``"strip"`` (surrounding quotes removed), or None when the two are unrelated."""
        if not cookie_value:
            return None
        if cookie_value == value:
            return ""
        if unquote(cookie_value) == value:
            return "unquote"
        if cookie_value.strip('"') == value:
            return "strip"
        if cookie_value in value_variants(value):
            return ""  # the request carried an encoded spelling: requests encodes the value again
        return None

    @staticmethod
    def _transformed(var: str, transform: str) -> Ref:
        if transform == "unquote":
            return Ref.expr(f"unquote({var})")
        if transform == "strip":
            return Ref.expr(f"{var}.strip('\"')")
        return Ref.var(var)

    def _replayable(self, ver: CookieVersion) -> bool:
        """Will the script's jar hold this cookie?  Cookies set by replayed responses and the cookies
        the script sets itself (external ones, and those of dropped responses that a replayed request
        sends) - not cookies only a dropped response knew about."""
        if ver.origin == "external" or (ver.flow is not None and id(ver.flow) in self.kept_ids):
            return True
        return any(id(f) in self.kept_ids for f in ver.sent_by)

    def _cookie_source(self, value: str, flow: Flow, exclude: Optional[CookieVersion] = None,
                       field_name: str = "") -> Optional[tuple[CookieVersion, str, bool]]:
        """The cookie that held ``value`` when ``flow``'s request was sent: ``(version, transform,
        sent_by_this_request)``.  Cookies the request itself sent come first (header order: longest
        path first), then the rest of the jar (latest first).  Coincidence guards: a short number only
        matches a cookie the request sent (or one named like the field); a cookie the request did not
        send (a token the page copied from another host's cookie) only matches a server cookie when the
        value is token-shaped or the names are related.  For a cookie the script sets itself
        (``exclude``) only cookies of replayed responses count: another cookie the script sets itself
        (pre-existing, written by the page, or from a response it does not replay) has no server behind
        it, and is read before it is set (two such cookies with one value would read each other)."""
        timeline = self.timeline
        if timeline is None or not value:
            return None
        sent = [ver for _n, _v, ver in timeline.sent_with(flow)]
        others = sorted((v for v in timeline.live_at(flow) if all(v is not s for s in sent)), key=lambda v: -v.seq)
        for is_sent, pool in ((True, sent), (False, others)):
            for ver in pool:
                if exclude is not None and (ver.origin != "server" or ver.flow is None or id(ver.flow) not in self.kept_ids):
                    continue  # a cookie the script sets itself: never read from another one it sets (circular)
                if not self._replayable(ver):
                    continue
                transform = self._cookie_transform(ver.value, value)
                if transform is None:
                    continue
                related = _names_related(ver.name, field_name)
                if is_sent:
                    if value.isdigit() and len(value) < 8 and not related:
                        continue
                elif ver.origin != "server" or not (is_dynamic_looking(value) or _token_shaped(value) or related):
                    continue
                return ver, transform, is_sent
        return None

    def _lookup_ref(self, ver: CookieVersion, transform: str, flow: Flow, sent: bool) -> tuple[Ref, CookieLookup]:
        """The step's ``_cookie(...)`` lookup of ``ver``'s identity (one per identity and scope URL)
        and the Ref of the request value.  The scope URL is the request's own URL when the request
        sent the cookie (the cookie that goes to this request), built from the same parts as the step's
        URL: a cookie under a path segment the step reads afresh (``/s/<key>/`` a redirect handed out) is
        found under this run's key, its ``path`` built from those parts too.  Else the origin that set it (a
        cookie of another host or path whose value the page copied, e.g. a CSRF token sent as a header to
        an API host)."""
        base = flow.request.url if sent or ver.flow is None else ver.flow.request.url
        url = cookie_scope_url(base, ver.jar_path)
        key = (ver.name, ver.domain, ver.jar_path, url)
        lookup = self._lookups.get(key)
        if lookup is None:
            issued = self.flow_step.get(id(ver.flow)) if ver.origin == "server" and ver.flow is not None else None
            scope, path, shown = url, ver.jar_path, None
            if sent:
                segments = self._segment_refs(flow)
                scope = _request_scope(flow.request.url, segments, url)
                pieces, shown = self._fresh_scope(ver, segments)
                if shown is not None:
                    path = pieces
            lookup = CookieLookup(
                var=unique_name(safe_identifier(ver.name, default="cookie"), self.taken),
                name=ver.name, url=scope, path=path, domain=ver.domain, note=describe_cookie(ver, issued, shown),
            )
            self._lookups[key] = lookup
            _note_traced(ver.value)
        return self._transformed(lookup.var, transform), lookup

    def _segment_refs(self, flow: Flow) -> dict[int, tuple[str, Ref]]:
        """``index -> (recorded segment, Ref)`` of the path segments of the step's request ``flow`` as
        resolved so far (path segments are resolved before the other values of a request).  Stops at a
        segment not resolved yet or read with a cookie lookup of the step itself (a scope built from it
        would read that cookie before it exists)."""
        refs, loop_key, loop_ref = self._step_scope
        own = {str(lk.var) for lk in self._lookups.values()}
        out: dict[int, tuple[str, Ref]] = {}
        for i, seg in enumerate(_path_segments(flow.request.url)):
            base = split_path_segment(seg)[0]
            if not base:
                continue
            key = ("path", str(i), base)
            if loop_ref is not None and loop_key == ("path", str(i), 0):
                ref = loop_ref
            elif refs.get(key) is not None:
                ref = refs[key]
            elif is_candidate_value(base, self.opts) or base.isdigit():
                break  # resolved after the value being resolved now
            else:
                ref = Ref.lit(base)
            names = _ref_names(ref)
            if names is None or names & own:
                break
            out[i] = (base, ref)
        return out

    def _fresh_scope(self, ver: CookieVersion, segments: dict[int, tuple[str, Ref]]) -> tuple[Optional[tuple], Optional[str]]:
        """``ver``'s cookie path built from a request's path pieces, and as shown (``/s/{s_id}/``), when a
        segment of it is one the step reads afresh (remembered for the cookie table); else ``(None, None)``."""
        fresh, pieces, shown = _fresh_cookie_path(ver.jar_path, segments)
        if not fresh:
            return None, None
        self.shown_cookie_paths.setdefault((ver.name, ver.domain, ver.jar_path), shown)
        return pieces, shown

    def _set_scope(self, ver: CookieVersion, unit: _Unit, url: str) -> tuple[Union[str, tuple], Optional[str]]:
        """``_set_cookie``'s URL and path for a cookie set before the step's request: as recorded, unless the
        path holds a segment the step reads afresh - then no path is written (it would keep the recorded
        key) and the URL is that path built from the step's pieces, from which the jar takes the path."""
        pieces, _shown = self._fresh_scope(ver, self._segment_refs(unit.first_flow))
        origin = cookie_scope_url(unit.first_flow.request.url, "/")[:-1]
        if pieces is None or not str(url).startswith(origin + "/"):
            return url, ver.jar_path
        tail = "" if ver.jar_path.endswith("/") else "/"
        return _joined_pieces((Ref.lit(origin),) + tuple(pieces) + (Ref.lit(tail),)), None

    def _snapshot_scope(self, built: _Built, flow: Flow, ver: CookieVersion) -> tuple:
        """``(cookie_url, cookie_path)`` with which the script reads ``ver`` right after ``built``'s step: its
        scope, unless its path holds a segment that differs on every run.  Set by the step's request under
        a path segment the step reads afresh: the request's URL and the path built from its pieces; set by
        the step's last response under a segment a redirect of the step handed out: ``resp.url`` (None)
        and no path (the longest path wins)."""
        unit = built.unit
        if unit.loop is None and flow is unit.first_flow:
            segments = self._step_segments.get(built.step.index, {})
            pieces, shown = self._fresh_scope(ver, segments)
            if shown is not None:
                return _request_scope(flow.request.url, segments, ver.scope_url()), pieces
        chain = unit.response_chain
        if unit.loop is None and flow is chain[-1] and len(chain) > 1:
            target = _path_segments(flow.request.url)
            for j, part in enumerate(ver.jar_path.split("/")[1:]):
                if part and j < len(target) and split_path_segment(target[j])[0] == part and any(
                        self._redirect_introduced(part, "path", str(j), chain[k]) for k in range(len(chain) - 1)):
                    return None, None
        return ver.scope_url(), ver.jar_path

    def _redirect_introduced(self, value: str, location: str, name: str, hop: Flow) -> bool:
        """``hop``'s redirect ``Location`` holds ``value`` at the place (path segment ``name``, not the
        target's last one; ``<index>;<name>`` path parameter; query ``name``) and no request URL up to that
        redirect held it: the redirect handed it out (``_issued_by_redirect`` without its word rule)."""
        resp = hop.response
        if resp is None or not resp.is_redirect or self.timeline is None or not value:
            return False
        try:
            target = urljoin(hop.request.url, (resp.location or "").strip())
            if location == "query":
                same = (name, value) in parse_query(urlsplit(target).query)
            elif location in ("path", "path_param"):
                index = int(name.split(";", 1)[0])
                segments = _path_segments(target)
                base, params = split_path_segment(segments[index]) if 0 <= index < len(segments) else ("", [])
                same = (base == value and index < len(segments) - 1 if location == "path"
                        else (name.split(";", 1)[-1], value) in params)
            else:
                return False
        except ValueError:
            return False
        upto = self.timeline.position(hop)
        return same and upto >= 0 and not any(value in f.request.url for f in self.timeline.flows[:upto + 1])

    def _referer_sources(self, referer: str, flow: Flow, step_no: int, known: dict) -> None:
        """Adds to ``known`` (``_referer_with_fresh_values``) the whole tokens of the Referer that no value
        traced for this or an earlier step explains: a cookie the browser held when the request was sent
        (``menu.do;jsessionid=<id>`` after a login that renewed the session id: read from the jar), else
        a value the redirect ``Location`` of an earlier step handed out (``Done.aspx?no=<number>``: read
        from that ``Location`` / the final URL), so no recorded session id stays in the header."""
        covered = {raw for (_loc, _name, raw), r in known.items() if isinstance(raw, str) and r is not None
                   and not r.is_literal and len(raw) >= _REFERER_MIN_VALUE}
        for location, name, token in _referer_places(referer):
            place = (location, name, token)
            done = known.get(place)
            if (done is not None and not done.is_literal) or token in covered or unquote(token) in covered:
                continue
            if "%" in token or "+" in token:
                continue  # only plain spellings (a session id, a key, a number)
            if is_candidate_value(token, self.opts) and not token.isdigit() and not _route_like(token):
                hit = self._cookie_source(token, flow, field_name=name.split(";")[-1])
                if hit is not None:
                    ver, transform, sent = hit
                    known[place] = self._lookup_ref(ver, transform, flow, sent)[0]
                    continue
            if not _issued_token(token):
                continue
            for built in reversed(self.built):
                chain = built.unit.response_chain
                hops = [k for k in range(len(chain) - 2, -1, -1) if self._redirect_introduced(token, location, name, chain[k])]
                if not hops:
                    continue
                k = hops[0]
                ext = locate_value_kinds(token, chain[k], frozenset({"location", "url"} if k == len(chain) - 2 else {"location"}))
                if ext is not None:
                    if ext.kind == "header":
                        ext.hop = k
                    ext = self._register(built, ext, Candidate(location, name, token), chain[k + 1], step_no,
                                         note="in the Referer")
                    known[place] = self._adapt(ext, token)
                break

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
            escaped_slash = repr("\\/")  # outside the f-string: Python < 3.12 forbids backslashes in its expressions
            return Ref.expr(f"{var}.replace({escaped_slash}, '/')")
        if sample.strip('"') == value:
            return Ref.expr(f"{var}.strip('\"')")
        if sample == value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;"):
            # the HTML-escaped spelling (``value_variants``) a regex read from markup: undo the escaping
            undo = (("&quot;", '"'), ("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"))
            return Ref.expr(var + "".join(f".replace({ent!r}, {ch!r})" for ent, ch in undo))
        return Ref.var(var)

    def _extractor_key(self, ext: Extractor) -> tuple:
        return (ext.kind, ext.name, tuple(ext.path) if ext.path else None, ext.selector, ext.attr, ext.pattern,
                ext.hop, ext.cookie_url, ext.cookie_path, ext.cookie_domain,
                ext.row, tuple(ext.row_key) if ext.row_key else None, ext.row_value)

    def _register(self, built: _Built, ext: Extractor, cand: Candidate, flow: Flow, step_no: int,
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
        _note_traced(ext.sample)  # read afresh from now on: no context for later patterns
        return ext

    def _structural_only(self, value: str) -> bool:
        """Values that must be found by an exact structural match (JSON leaf, ``<input>``, ``<meta>``,
        whole attribute / text, header), never by a regex or a substring pattern: plain words such as
        path names (``dashboard``, ``Default.aspx``) and values shorter than ``min_value_length``
        (a short id like ``77``) occur in many places by coincidence."""
        return len(value) < self.opts.min_value_length or _route_like(value)

    def _accept(self, ext: Optional[Extractor], value: str, cand: Optional[Candidate] = None) -> Optional[Extractor]:
        if ext is None:
            return None
        if ext.pattern and self._structural_only(value):
            return None
        if cand is not None and ext.kind in _MARKUP_KINDS and is_structural_path_segment(cand):
            # a route-like path segment (``Login.aspx``, ``SC0010.aspx``) in markup is a coincidence;
            # only exact structural matches (JSON leaf, header, <input> / <meta>, cookie) trace it
            return None
        return ext

    def _snapshot_cookie(self, built: _Built, value: str, consumer: Flow) -> Optional[Extractor]:
        """A cookie that the step's responses set to ``value`` but that the jar no longer holds when the
        value is used (it was renewed or deleted in between): the script reads it right after that step
        (``Extractor`` kind ``cookie``).  A cookie still held is the jar lookup's business."""
        timeline = self.timeline
        if timeline is None or (value.isdigit() and len(value) < 8):
            return None
        live = timeline.live_at(consumer)
        for f in reversed(built.unit.all_flows):
            for ver in reversed(timeline.stored_by(f)):
                if self._cookie_transform(ver.value, value) is None or any(ver is v for v in live):
                    continue
                url, path = self._snapshot_scope(built, f, ver)
                return Extractor(var="", kind="cookie", name=ver.name, sample=ver.value,
                                 cookie_url=url, cookie_path=path, cookie_domain=ver.domain)
        return None

    def _issued_by_redirect(self, value: str, cand: Candidate, flow: Flow, hop: Flow) -> bool:
        """A route-like value that is a key by behaviour: the same path segment (not the request's last
        one), ``;name=`` path parameter or query value (``?sid=<key>``) of ``hop``'s redirect ``Location``
        (the login answers ``302 /s/<key>/menu``), in no request URL up to that redirect, and not spelled
        like words (``_spelled_as_words``).  It may be read from that ``Location`` (or the final URL)
        although route-like values are otherwise traced exactly."""
        resp = hop.response
        if (cand.location not in ("path", "path_param", "query") or resp is None or not resp.is_redirect
                or self.timeline is None):
            return False
        try:
            target = urljoin(hop.request.url, (resp.location or "").strip())
            if cand.location == "query":
                same = (cand.name, value) in parse_query(urlsplit(target).query)
            else:
                index = int(cand.name.split(";", 1)[0])
                segments = _path_segments(target)
                base, params = split_path_segment(segments[index]) if index < len(segments) else ("", [])
                same = (base == value and index < len(_path_segments(flow.request.url)) - 1 if cand.location == "path"
                        else (cand.name.split(";", 1)[1], value) in params)
        except ValueError:
            return False
        if not same or _spelled_as_words(value):
            return False
        upto = self.timeline.position(hop)
        return upto >= 0 and not any(value in f.request.url for f in self.timeline.flows[:upto + 1])

    def _page_link_urls(self, page: Flow) -> list[str]:
        """The absolute URLs a page's links, forms and frames go to (cached per page)."""
        urls = self._link_urls.get(id(page))
        if urls is None:
            urls = []
            soup = _view(page).soup
            for tag, attr in (("a", "href"), ("area", "href"), ("form", "action"), ("frame", "src"), ("iframe", "src")):
                for el in soup.find_all(tag) if soup is not None else ():
                    target = el.get(attr)
                    if (not isinstance(target, str) or not target.strip()
                            or target.strip().lower().startswith(("javascript:", "#", "mailto:"))):
                        continue
                    try:
                        urls.append(urljoin(page.request.url, target.strip()))
                    except ValueError:
                        continue
            self._link_urls[id(page)] = urls
        return urls

    def _first_request_with(self, value: str) -> int:
        """Timeline position of the first request whose URL holds ``value`` (cached; -1: none)."""
        pos = self._first_sent.get(value)
        if pos is None:
            pos = next((i for i, f in enumerate(self.timeline.flows) if value in f.request.url), -1)
            self._first_sent[value] = pos
        return pos

    @staticmethod
    def _at_place(value: str, cand: Candidate, flow: Flow, url: str) -> bool:
        """Is ``value`` at the candidate's place in ``url``: the same path segment (not the request's last
        one), ``;name=`` path parameter or query ``name``?"""
        try:
            if cand.location == "query":
                return (cand.name, value) in parse_query(urlsplit(url).query)
            index = int(cand.name.split(";", 1)[0])
            segments = _path_segments(url)
            base, params = split_path_segment(segments[index]) if index < len(segments) else ("", [])
            if cand.location == "path":
                return base == value and index < len(_path_segments(flow.request.url)) - 1
            return (cand.name.split(";", 1)[1], value) in params
        except ValueError:
            return False

    def _issued_by_link(self, value: str, cand: Candidate, flow: Flow, page: Flow) -> Optional[str]:
        """A route-like value a page's links handed out (``_issued_by_redirect`` for links): at the same place
        in a URL a link / form / frame of ``page`` goes to, and in no request URL up to that page.  ``"key"``:
        read it from the page - it is not spelled like words, or (12+ letters) it stands at that place in most
        of the page's links (a session key in every URL); ``"word"``: handed out by a link but it reads like a
        page name; None: not handed out by this page."""
        if (cand.location not in ("path", "path_param", "query") or self.timeline is None or page.response is None
                or value not in _view(page).text):
            return None
        upto = self.timeline.position(page)
        first = self._first_request_with(value)
        if upto < 0 or 0 <= first <= upto:
            return None  # a request sent it before (a typed or bookmarked URL, an earlier visit)
        urls = self._page_link_urls(page)
        holders = [u for u in urls if self._at_place(value, cand, flow, u)]
        if not holders:
            return None
        if not _spelled_as_words(value) and not (cand.location == "path" and cand.name == "0"):
            return "key"  # (the first path segment is an application's name a portal links to, not a key)
        if len(value) >= 12 and len(set(holders)) >= 3 and len(holders) * 10 >= len(urls) * 6:
            return "key"
        return "word"

    def _trace(self, value: str, cand: Candidate, flow: Flow, step_no: int) -> Optional[tuple[Ref, _Resolution]]:
        """Search earlier steps, latest first.  Per step: a cookie its responses set that has been
        renewed since (``_snapshot_cookie``), then its final response (every locator; a step that does
        not follow redirects has no final URL to read), then its redirect responses latest first
        (headers and ``Location``, read from that response of ``resp.history``; the last ``Location``
        as the final URL).  Route-like values are traced only exactly (``_accept``; a route-like path
        segment never through markup), unless a redirect handed them out (``_issued_by_redirect``): then
        also from that ``Location`` / the final URL."""
        route_segment = is_structural_path_segment(cand)
        exact_only = self._structural_only(value)
        word_link: Optional[int] = None  # a step whose page links handed out the value, which reads like a word
        for built in reversed(self.built):
            chain = built.unit.response_chain
            ext = self._snapshot_cookie(built, value, flow)
            if ext is None:
                if route_segment:
                    kinds: Optional[frozenset] = _ROUTE_SEGMENT_KINDS
                else:
                    kinds = None if built.step.allow_redirects else _ALL_KINDS - {"url"}
                ext = self._accept(locate_value_kinds(value, chain[-1], kinds), value, cand)
                if ext is None and exact_only and self._issued_by_redirect(value, cand, flow, chain[-1]):
                    ext = locate_value_kinds(value, chain[-1], frozenset({"location"}))  # a redirect not followed
                if ext is None and exact_only and len(value) >= _MIN_REGEX_VALUE_LEN:
                    verdict = self._issued_by_link(value, cand, flow, chain[-1])
                    if verdict == "key":  # a key the page's links handed out: read it from the page
                        ext = locate_value_kinds(value, chain[-1], frozenset({"html_attr", "regex"}))
                        if ext is not None:
                            ext.renewed = True
                    elif verdict == "word" and word_link is None:
                        word_link = built.step.index
            if ext is None:
                for k in range(len(chain) - 2, -1, -1):
                    hop_kinds = {"header", "location"} | ({"url"} if k == len(chain) - 2 else set())
                    if route_segment:
                        hop_kinds &= _ROUTE_SEGMENT_KINDS
                    ext = self._accept(locate_value_kinds(value, chain[k], frozenset(hop_kinds)), value, cand)
                    if ext is None and exact_only and self._issued_by_redirect(value, cand, flow, chain[k]):
                        # a key the redirect handed out: its Location, the last one as the final URL
                        ext = locate_value_kinds(value, chain[k], frozenset({"location", "url"} if k == len(chain) - 2
                                                                            else {"location"}))
                    if ext is not None:
                        if ext.kind == "header":
                            ext.hop = k
                        break
            if ext is not None and ext.kind == "json":
                ext = self._json_choice(_view(chain[-1]), ext, value, cand, flow, step_no,  # one row of a list was chosen, not "row n"
                                        built.step.loop is not None)
            if ext is None:
                continue
            ext = self._register(built, ext, cand, flow, step_no)
            src_step = built.step.index
            if ext.kind == "cookie":
                res = _Resolution("D", source=f"ステップ {src_step} の直後に取得した {describe_extractor(ext)}",
                                  source_step=src_step, source_kind="set-cookie", var=ext.var)
            else:
                res = _Resolution("C", source=f"ステップ {src_step} のレスポンス: {describe_extractor(ext)}",
                                  source_step=src_step, source_kind=ext.kind, var=ext.var)
            return self._adapt(ext, value), res
        if word_link is not None and len(value) >= 12 and value not in self._warned_values:
            # a long value only links handed out, spelled like words: possibly a session key - say so once
            self._warned_values.add(value)
            index, _, pname = cand.name.partition(";")
            if cand.location == "path":
                place = f"URL のパスの {int(index) + 1} 番目" if index.isdigit() else "URL のパス"
            elif cand.location == "path_param":
                place = f"URL のパスパラメーター ;{pname}"
            else:
                place = f"クエリ {cand.name}"
            text = (f"step {step_no}: {place} の値は、ステップ {word_link} の画面のリンクで渡されたものですが、"
                    f"ページ名のようにも見えるため記録時の値を送ります。セッション ID などの毎回変わる値なら実行に"
                    f"失敗するので、その場合は詳細設定で確認してください")
            if text not in self.warnings:
                self.warnings.append(text)
        return None

    def _in_loop_span(self, flow: Flow) -> bool:
        """Does a (dropped) flow lie between the first and the last request of a folded loop?"""
        pos = self.timeline.position(flow) if self.timeline is not None else -1
        return any(first < pos < last for first, last in self.loop_spans)

    def _find_dropped_producer(self, value: str, flow: Flow, cand: Candidate) -> None:
        """A request the noise filter dropped (static file, tracker, 304) whose response carries
        ``value``: build_plan puts it back as a step (``PlanOptions.include_producers``)."""
        if self.timeline is None:
            return
        pos = self.timeline.position(flow)
        for dropped_flow in reversed(self.dropped_flows):
            if self.timeline.position(dropped_flow) >= pos or dropped_flow.response is None:
                continue
            if self._in_loop_span(dropped_flow):
                continue  # putting it back would split the repeated requests of a loop
            ext = locate_value(value, dropped_flow)
            if ext is None or (ext.pattern and self._structural_only(value)):
                continue
            self.needed_producers.setdefault(dropped_flow.id, []).append(f"{cand.location} `{cand.name}`")
            return

    def _input_constant(self, cand: Candidate, value: str, flow: Flow, step_no: int, *, secret: bool, why: str,
                        encoding: Optional[str] = None) -> tuple[Ref, _Resolution]:
        """The 入力値 constant (class B) for a value the user typed or chose.  ``encoding``: the value was
        sent in a legacy charset - the constant holds the text, and a request pair sent in that charset
        sends its bytes (``_legacy_form_hint``; the Ref itself stays the plain constant, so a later JSON /
        UTF-8 use gets the text).  A legacy value whose charset is unknown is held as the recorded bytes."""
        raw = self._raw_fields.get((cand.location, cand.name, cand.value))
        if encoding is None and raw is not None and not is_utf8(raw):
            if cand.location == "form" and _encodes_to(value, self._raw_charset, raw):
                encoding = self._raw_charset
            else:
                value = raw
        ref = self._constant(cand, value, flow, step_no, force_secret=secret, kind="input")
        const = next((c for c in self.constants if c.name == ref.value), None)
        if const is not None:
            if secret:
                const.sensitive = True
            if encoding:  # also a secret read from the environment: the form sends it in this charset
                const.encoding = encoding
        meta = _Resolution("B", source=f"入力値 {ref.value}（{why}）", source_kind="input", var=ref.value)
        if not secret and isinstance(value, str):
            # a password is never the source of another field that happens to hold the same text
            holders = self.input_refs.setdefault(value, [])
            if (cand.name, ref) not in holders:
                holders.append((cand.name, ref))
        self.input_fields[_field_key(cand.location, cand.name)] = (cand.value, ref, step_no, meta)
        return ref, meta

    def _holds(self, ref: Ref, location: str, name: str, value: str) -> bool:
        """Is a recorded value the text of the 入力値 behind ``ref``: that text sent as UTF-8 (or in a JSON
        body), or the bytes it gives in the 入力値's legacy charset (typed on a Shift_JIS page)?"""
        const = next((c for c in self.constants if c.name == _ref_name(ref)), None)
        if const is None or const.secret or not isinstance(const.value, str):
            return False
        raw = self._raw_fields.get((location, name, value))
        if raw is None or is_utf8(raw):
            return const.value == value
        return _encodes_to(const.value, const.encoding, raw)

    def _typed_elsewhere(self, cand: Candidate, value: str) -> Optional[Ref]:
        """The 入力値 of another field that an untraced value repeats (the page's script sends a typed value
        again: an XHR JSON body, a query it builds): the one field named like this one that holds it
        (``dateFrom`` / ``txtDateFrom``, dates and numbers too), else the first field that holds it when the
        value is too long to match by coincidence (6 bytes or more in UTF-8 - ``山田`` but not ``12`` or
        ``abc`` - and not a number, a date or a token).  Fields typed with the same short value (``txtFrom``
        / ``txtTo`` of a one-day range) and a typed quantity and an order id stay apart."""
        raw = self._raw_fields.get((cand.location, cand.name, value))
        if raw is None or is_utf8(raw):
            text: Optional[str] = value
        else:  # sent in a legacy charset: the text of an 入力値 that gives these bytes
            text = next((c.value for c in self.constants
                         if c.kind == "input" and c.encoding and _encodes_to(c.value, c.encoding, raw)), None)
        holders = [(n, r) for n, r in self.input_refs.get(text, []) if self._holds(r, cand.location, cand.name, value)] if text else []
        if not holders:
            return None
        own = "" if cand.location in ("path", "path_param") else str(cand.name)
        if cand.location == "json":
            own = own.rsplit(".", 1)[-1].split("[", 1)[0]  # the last key (``cond.dateFrom`` -> ``dateFrom``)
        alike = list(dict.fromkeys(r for n, r in holders if own and _names_alike(own, n)))
        if len(alike) == 1:
            return alike[0]
        if (len(text.encode("utf-8")) >= 6 and not text.isdigit() and not _DATE_RE.match(text)
                and not is_dynamic_looking(text)):
            return holders[0][1]
        return None

    def _note_use(self, ref: Ref, cand: Candidate, step_no: int) -> None:
        """Record that a step reuses an 入力値 constant (its comment lists the uses)."""
        uses = self.const_uses.get(_ref_name(ref))
        if uses is not None:
            uses.append(f"step {step_no} ({cand.location} `{cand.name}`)")

    # ------------------------------------------------------------------ field-level decisions (forms)

    def _field_text(self, location: str, name: str, value: str,
                    match: "_FormMatch") -> Optional[tuple[str, Optional[str]]]:
        """``(text, encoding)`` of a submitted form value, decided by its recorded bytes: bytes that are
        UTF-8 are the text as sent (a typed ``%AB%`` stays ``%AB%``, ``encoding`` None); other bytes were
        sent in a legacy charset (IE on a Shift_JIS page) and stand for their text in the charset the
        request declares, else the page's (``encoding``).  None when no charset gives back those bytes."""
        raw = self._raw_fields.get((location, name, value))
        if raw is None or is_utf8(raw):
            return value, None
        for charset in (self._raw_charset if location == "form" else None, match.charset):
            text = _legacy_text(raw, charset)
            if text is not None:
                return text, charset
        return None

    def _referer_charset(self, req: RecordedRequest) -> Optional[str]:
        """The charset of the page the request's ``Referer`` names (the page its link / form was on)."""
        referer = req.header("referer")
        for built in reversed(self.built):
            page = built.unit.response_chain[-1]
            if page.response is not None and _same_page(page.request.url, referer):
                return detect_charset(page.response.body or b"", page.response.header("content-type"))
        return None

    @staticmethod
    def _is_default(fld: FormField, text: str) -> bool:
        """Does the submitted text equal what the form sends untouched (browser rules: a textarea loses
        one leading line break and sends CRLF)?"""
        for default in fld.defaults:
            if fld.control == "textarea":
                default = default[1:] if default.startswith("\n") else default
                if default.replace("\r\n", "\n") == text.replace("\r\n", "\n"):
                    return True
            elif default == text:
                return True
        return False

    def _seen_in_responses(self, value: str) -> bool:
        for built in self.built:
            view = _view(built.unit.response_chain[-1])
            if view.textual and value in view.text:
                return True
        return False

    def _json_choice(self, view: _ResponseView, ext: Extractor, value: str, cand: Candidate, flow: Flow,
                     step_no: int, looped: bool = False) -> Optional[Extractor]:
        """Where to read a JSON leaf, or None (``_unpicked_json``: one row of a list the user chose is no
        source).  A random-looking value (a GUID, a code or an id issued per run) that is such a row is read
        from the row the user chose, found again by the leaf that tells it apart (``_row_pick``); without
        such a leaf a GUID - a fixed key of the row - stays the recorded value (None), anything else is read
        from the same row number, with a warning (the next run may list another row there).  The list of a
        folded loop (``looped``: each page is read in turn, the last one wins) keeps the row number too."""
        found = _unpicked_json(view, ext, cand.name, flow)
        if found is not None or not is_dynamic_looking(value):
            return found
        row = None if looped else _row_pick(view, ext, cand.name, flow, self._sent_texts(cand, flow))
        if row is not None:
            if row.row_field is not None:
                self._row_choices.append(row)  # compared with that field's 入力値 once the request is resolved
            return row
        if _UUID_RE.match(value.strip("{}")):
            return None
        why = "このステップはページを変えて繰り返すため" if looped else "行を見分ける項目がないため"
        text = (f"step {step_no}: {_LOCATION_LABELS.get(cand.location, cand.location)} {cand.name} の値は JSON の一覧から"
                f"選んだ行のもの（{json_dotted(list(ext.path or []))}）ですが、{why}、記録時と同じ位置の行から"
                f"読みます。一覧の並び順が変わると別の行の値を送ります")
        if text not in self.warnings:
            self.warnings.append(text)
        return ext

    def _sent_texts(self, cand: Candidate, flow: Flow) -> dict[str, str]:
        """What the request sends in its other fields (query, form, JSON body, multipart text) as text ->
        field name; a value sent in a legacy charset as its text (in the charset the request declares, else
        in the one of the page its Referer names).  Never a password: it is no label of a row."""
        sent: dict[str, str] = {}
        for c in request_params(flow):
            if (c.location in ("path", "path_param") or c.name == cand.name or looks_like_secret_name(c.name)
                    or _looks_like_password_name(c.name)):
                continue
            text: Optional[str] = c.value
            raw = self._raw_fields.get((c.location, c.name, c.value))
            if raw is not None and not is_utf8(raw):
                text = (_legacy_text(raw, self._raw_charset if c.location == "form" else None)
                        or _legacy_text(raw, self._referer_charset(flow.request)))
            if text:
                sent.setdefault(text, c.name)
        return sent

    def _bind_row_choices(self, refs: dict, short_refs: dict) -> None:
        """A row of a JSON list chosen by the value the request sends in another field (``_json_choice``):
        when that field sends a constant (an 入力値), the script compares the rows with the constant, so a
        changed 入力値 chooses its own row."""
        choices, self._row_choices = self._row_choices, []
        for ext in choices:
            for (_location, name, _value), ref in list(refs.items()) + list(short_refs.items()):
                if name != ext.row_field or ref is None or ref.kind not in ("var", "expr"):
                    continue
                const = next((c for c in self.constants if c.name == _ref_name(ref)), None)
                if const is not None and not (const.secret or const.sensitive) and const.value == ext.row_value:
                    ext.row_ref = const.name
                    break

    def _script_source(self, cand: Candidate, value: str, flow: Flow, step_no: int,
                       match: "_FormMatch", encoding: Optional[str] = None) -> Optional[tuple[Ref, _Resolution]]:
        """A source of the value the page's script wrote into the field (it was not typed), latest first:
        a response between the form page and this request that holds it exactly (an XHR, a popup; never
        one row of a JSON list - a choice), a text response (text/plain, UpdatePanel delta, JavaScript,
        a bare value) that is the value or names the field next to it, else the form page itself when its
        scripts write the field (by its name or id: a literal, a variable, a hidden input / a label they
        copy).  A response to a request that sent the value itself (a check of a typed code) only echoes
        it.  ``encoding``: the pair was sent in that legacy charset - ``value`` is its text, and the
        request sends ``var.encode(encoding)``."""
        page = _view(match.built.unit.response_chain[-1])
        tag = _form_tag(page, match.form)
        named = page.index.attr_index.get(cand.name, []) if tag is not None and page.index is not None else []
        ids = [el.get("id") for el, attr in named if attr == "name" and any(p is tag for p in el.parents)]
        anchors = [a for a in dict.fromkeys([cand.name] + ids) if isinstance(a, str) and len(a) >= _MIN_ANCHOR_LEN]
        found: Optional[tuple[_Built, Extractor]] = None
        for built in reversed([b for b in self.built if b.step.index > match.built.step.index]):
            source = built.unit.response_chain[-1]
            ext = locate_value_kinds(value, source, _EXACT_KINDS)
            if ext is not None and ext.kind == "json":
                ext = self._json_choice(_view(source), ext, value, cand, flow, step_no,  # a row chosen from a list (B), not "row n"
                                        built.step.loop is not None)
            if ext is None or ext.pattern:
                ext = _text_body_source(_view(source), value, anchors)
            elif value.isdigit() and not _names_related(ext.name or ext.attr or json_dotted(list(ext.path or [])),
                                                        cand.name):
                ext = None  # a bare number equals many things: only a source named like the field
            if ext is not None and any(c.value == value for c in request_params(built.unit.response_chain[0])):
                ext = None  # an echo of what the request sent (a check of a typed code)
            if ext is not None:
                found = (built, ext)
                break
        if found is None:
            self._dropped_script_source(value, flow, cand, match, anchors)
            ext = _page_script_source(page, value, anchors)
            if ext is None:
                return None
            found = (match.built, ext)
        built, ext = found
        ext = self._register(built, ext, cand, flow, step_no)
        src = built.step.index
        ref = Ref.expr(f"{ext.var}.encode({encoding!r})") if encoding else self._adapt(ext, value)
        return ref, _Resolution(
            "C", source=f"ステップ {src} のレスポンス: {describe_extractor(ext)}（画面のスクリプトが入力欄に入れた値）",
            source_step=src, source_kind=ext.kind, var=ext.var)

    def _dropped_script_source(self, value: str, flow: Flow, cand: Candidate, match: "_FormMatch",
                               anchors: list[str]) -> None:
        """A request the noise filter dropped between the form page and this request (an XHR answered as
        JavaScript looks like a static file) whose response is the value the page's script wrote into the
        field, or names the field next to it: build_plan puts it back, and the next pass reads the value
        there (``_script_source``)."""
        if not self.opts.include_producers or self.timeline is None:
            return
        low = self.timeline.position(match.built.unit.response_chain[-1])
        high = self.timeline.position(flow)
        for dropped in reversed(self.dropped_flows):
            if not low < self.timeline.position(dropped) < high or dropped.response is None or self._in_loop_span(dropped):
                continue
            if any(c.value == value for c in request_params(dropped)):
                continue  # an echo of what that request sent
            ext = locate_value_kinds(value, dropped, _EXACT_KINDS)
            if ext is None or ext.pattern:
                ext = _text_body_source(_view(dropped), value, anchors)
            if ext is not None:
                self.needed_producers.setdefault(dropped.id, []).append(f"{cand.location} `{cand.name}`")
                return

    @staticmethod
    def _own_input(match: "_FormMatch", name: str, value: str) -> Optional[Extractor]:
        """How to read a field's own default from its page: ``<input name=..>`` when the page's first
        input of that name holds it, else that input of the submitted form (``_form_input_selector``);
        None when neither is safe (another input of that name in the same form holds it)."""
        view = _view(match.built.unit.response_chain[-1])
        named = view.index.attr_index.get(name, []) if view.index is not None else []
        first = next((el for el, attr in named if attr == "name" and el.name == "input"), None)
        # (a token of one row of a list is read from that row, even when it is the first row)
        if (first is not None and first.get("value") == value
                and not (is_dynamic_looking(value) and _row_forms(view, match.form, name, value))):
            return Extractor(var="", kind="html_input", name=name, sample=value)
        selector = _form_input_selector(view, match.form, name, value)
        return Extractor(var="", kind="html_attr", selector=selector, attr="value", sample=value) if selector else None

    def _row_choice(self, cand: Candidate, value: str, flow: Flow, step_no: int, page: "_Built", others: set[str],
                    how: str) -> tuple[Ref, _Resolution]:
        """The value of the row the user opened from a list on ``page`` (one form / link per row; ``others``:
        the other rows' values): the recorded value (A), the same record on the next run wherever it is listed
        - unless a request that changed data put it into an earlier response (the order the user had just
        registered, ``_created_source``): then it is read from there (C)."""
        created = self._created_source(cand, value, flow, step_no, page, others)
        if created is not None:
            return created
        return Ref.lit(value), _Resolution("A", source=f"記録時の値（一覧の行ごとの{how}で選んだ行）", source_kind="literal")

    def _created_source(self, cand: Candidate, value: str, flow: Flow, step_no: int, page: "_Built",
                        others: set[str]) -> Optional[tuple[Ref, _Resolution]]:
        """Where to read a row value afresh that a request that changed data created: the first response
        before the list ``page`` that shows the value answered a request that is not a GET, did not send the
        value and shows no other row of the list (a registration, not a search) - traced over the steps
        before the list, never from the list itself (that would be "row n")."""
        earlier = [b for b in self.built if b.step.index < page.step.index]
        for built in earlier:
            chain = built.unit.response_chain
            texts = [_view(f).text for f in chain if _view(f).textual]
            texts += [f.response.header("location") or "" for f in chain if f.response is not None]
            if not any(value in t for t in texts):
                continue
            req = chain[0].request
            if ((req.method or "GET").upper() in ("GET", "HEAD") or any(o in t for o in others for t in texts)
                    or any(c.value == value for c in request_params(chain[0]))):
                return None  # a page / a list showed it (an existing record), or an echo of what was sent
            break
        else:
            return None
        built_all = self.built
        self.built = earlier  # (``_trace`` searches ``self.built``: the steps before the list only)
        try:
            return self._trace(value, cand, flow, step_no)
        finally:
            self.built = built_all

    def _row_link(self, cand: Candidate, value: str, flow: Flow) -> Optional[tuple["_Built", set[str]]]:
        """Is the GET one of several links (``<a href>``) of the page its ``Referer`` names that differ only
        in their query values (one link per row of a list: the same path and query names), another of which
        holds another value in ``cand.name``?  Then the value is the row the user chose (the links' version
        of ``_row_forms``): returns that page's step and the other rows' values.  A date only when the link's
        label does not tell it apart from the date (「表示」 on every row, the date or a calendar's day
        number): a link to another day (前日 / 翌日) moves with the day and is read from the page by its
        label."""
        req = flow.request
        if (req.method or "GET").upper() != "GET":
            return None
        dated = bool(_DATE_RE.match(value)) or (len(value) == 8 and value.isdigit() and value[:2] in ("19", "20")
                                                and "01" <= value[4:6] <= "12" and "01" <= value[6:] <= "31")
        referer = req.header("referer")
        target = _form_target(req.url)
        names = {n for n, _v in parse_form_bytes(query_bytes(req.query))}
        for built in reversed(self.built):
            page = built.unit.response_chain[-1]
            if not _same_page(page.request.url, referer):
                continue
            view = _view(page)
            links = getattr(view, "_links", None)
            if links is None:  # (target, query names, query pairs, label) of every link, parsed once per page
                links = view._links = []
                for a in view.soup.find_all("a", href=True) if view.soup is not None else ():
                    href = a.get("href")
                    try:
                        url = urljoin(page.request.url, href) if isinstance(href, str) else ""
                        pairs = parse_form_bytes(query_bytes(urlsplit(url).query))
                    except ValueError:
                        continue
                    if url:
                        links.append((_form_target(url), {n for n, _v in pairs}, pairs, " ".join(a.get_text().split())))
            held = [(v, label) for t, n_set, pairs, label in links if t == target and n_set == names
                    for n, v in pairs if n == cand.name]
            mine = {label for v, label in held if v == value}
            others = {label for v, label in held if v != value}
            if mine and others and (not dated or any(
                    label in others or value in label or (label and label in value) for label in mine)):
                return built, {v for v, _label in held if v != value}
            return None
        return None

    def _field_decision(self, cand: Candidate, value: str, flow: Flow, step_no: int,
                        match: Optional["_FormMatch"]) -> Optional[tuple[Ref, _Resolution]]:
        """Decisions that belong to one form field, never shared with other fields through the cache:

        1. the same field was user input in an earlier step with this value -> the same 入力値 (B);
        2. the value is the field's own default on the form page (an ``<input>``) -> read it from that
           input of the submitted form (C) - the server filled it in (a date, a remembered id), so it is
           fetched again (``_own_input``); but a form of one row of a list (``_row_forms``) holds the row
           the user chose -> the recorded value (A), and so does a link of one row of a list (a GET that
           submits no form, ``_row_link``) - unless the recording created that row (``_row_choice``);
        3. an editable field the page's script filled in (``_script_source``: an XHR / popup response,
           a text response naming the field, the page's own scripts) -> that response (C);
        4. a visible editable control the user changed (typed, chose, a password) -> 入力値 (B)."""
        if cand.location not in ("form", "multipart", "query", "json"):
            return None
        prev = self.input_fields.get(_field_key(cand.location, cand.name))
        if (prev is not None and (prev[0] == value or self._holds(prev[1], cand.location, cand.name, value))
                and prev[2] < step_no and not is_dynamic_looking(value)):
            meta = replace(prev[3], source=prev[3].source.split("（", 1)[0] + "（前の手順で同じ欄に入力した値）")
            self._note_use(prev[1], cand, step_no)
            return prev[1], meta
        if match is None or cand.location == "json":
            row = (self._row_link(cand, value, flow) if match is None and cand.location == "query"
                   and not is_dynamic_looking(value) else None)
            return self._row_choice(cand, value, flow, step_no, *row, "リンク") if row is not None else None
        fld = match.form.fields.get(cand.name)
        if fld is None:
            return None
        text, encoding = self._field_text(cand.location, cand.name, value, match) or (None, None)
        if text is None:
            return None  # a legacy-charset value of unknown charset: keep the recorded bytes
        # a value sent in a legacy charset (Shift_JIS ...): pages and responses hold its text, the request its bytes
        legacy = encoding is not None and text != value
        if self._is_default(fld, text):
            if (fld.control in ("text", "hidden", "password") and (text == value or legacy)
                    and is_candidate_value(text, self.opts)):
                page = _view(match.built.unit.response_chain[-1])
                if not is_dynamic_looking(text) and _row_forms(page, match.form, cand.name, text):
                    return self._row_choice(cand, value, flow, step_no, match.built,
                                            _row_values(page, match.form, cand.name) - {text}, "フォーム")
                own = self._own_input(match, cand.name, text)
                if own is not None:  # else traced like any other value (``_resolve``)
                    ext = self._register(match.built, own, cand, flow, step_no)
                    src = match.built.step.index
                    # a legacy pair: the page's text, sent in the page's charset (_legacy_form_hint keeps it)
                    return (Ref.expr(f"{ext.var}.encode({encoding!r})") if legacy else self._adapt(ext, value)), _Resolution(
                        "C", source=f"ステップ {src} のレスポンス: {describe_extractor(ext)}（画面にあらかじめ入っていた値）",
                        source_step=src, source_kind=ext.kind, var=ext.var)
            return None
        if not fld.editable:
            return None
        hit = self._script_source(cand, text if legacy else value, flow, step_no, match,
                                  encoding=encoding if legacy else None)
        if hit is not None:
            return hit
        password = fld.control == "password"
        if password or not is_dynamic_looking(text) or not self._seen_in_responses(value):
            label = {"password": "パスワード欄", "select": "選択欄", "radio": "選択ボタン", "checkbox": "チェックボックス"}.get(
                fld.control, "入力欄")
            return self._input_constant(cand, text, flow, step_no, secret=password,
                                        why=f"画面の{label} {cand.name} に入力・選択した値",
                                        encoding=encoding)
        return None

    # ------------------------------------------------------------------ value resolution

    def _resolve(self, cand: Candidate, unit: _Unit, step_no: int, cache: dict, form: Optional["_FormMatch"] = None,
                 exclude: Optional[CookieVersion] = None) -> Ref:
        value = cand.value
        flow = unit.first_flow
        decided = self._field_decision(cand, value, flow, step_no, form)
        if decided is not None:
            self._last_meta = decided[1]
            return decided[0]
        secret_name = self._secret_field(cand.name)
        credential = looks_like_secret_name(cand.name) or _looks_like_password_name(cand.name)
        fld = form.form.fields.get(cand.name) if form is not None and cand.location in ("form", "multipart", "query") else None
        # keyed by secrecy too: ``txtUserId=tanaka01&txtPassword=tanaka01`` must not hand the user
        # id's literal to the password; and by the field (the cookie guard compares names)
        cache_key = (value, secret_name, credential, cand.location == "cookie", cand.name)
        if cache_key in cache:
            self._last_meta = self._meta.get(cache_key) or _Resolution("A")
            return cache[cache_key]
        ref: Optional[Ref] = None
        meta = _Resolution("A", source="記録時の値", source_kind="literal")
        route_segment = is_structural_path_segment(cand)
        is_cookie = cand.location == "cookie"
        # sent in a legacy charset (a Shift_JIS page): never a shared constant, its pair sends the bytes
        legacy = not is_utf8(self._raw_fields.get((cand.location, cand.name, value), b""))
        # a cookie the browser held when the request was sent (read from the jar by identity)
        hit = self._cookie_source(value, flow, exclude, cand.name)
        if hit is not None:
            ver, transform, sent = hit
            ref, lookup = self._lookup_ref(ver, transform, flow, sent)
            issued = self.flow_step.get(id(ver.flow)) if ver.origin == "server" and ver.flow is not None else None
            meta = _Resolution("D", source=lookup.note, source_step=issued, source_kind="cookie-jar",
                               var=lookup.var, cookie=ver)
        # an earlier response
        if ref is None:
            hit2 = self._trace(value, cand, flow, step_no)
            if hit2 is not None:
                ref, meta = hit2
        # a request the noise filter dropped may hold it (build_plan then keeps that request)
        epoch = looks_like_timestamp(value, around=flow.started_at)
        if ref is None and self.opts.include_producers and (is_dynamic_looking(value) or epoch):
            self._find_dropped_producer(value, flow, cand)
        # the clock: a cache-buster / client timestamp nothing else explains
        if ref is None and epoch:
            expr = "int(time.time()*1000)" if epoch == "ms" else "int(time.time())"
            ref = Ref.expr(expr if cand.numeric else f"str({expr})")
            meta = _Resolution("E", source="実行時の時刻（ミリ秒）" if epoch == "ms" else "実行時の時刻（秒）", source_kind="time")
        # a value the user typed into another field earlier (one named like it, else a long text)
        typed = self._typed_elsewhere(cand, value) if ref is None and not is_cookie and not credential else None
        if typed is not None:
            ref = typed
            meta = _Resolution("B", source=f"入力値 {_ref_name(ref)}（前の手順で入力した値）", source_kind="input",
                               var=_ref_name(ref))
            self._note_use(ref, cand, step_no)
        # a credential-like field (a password sent by a scripted / JSON login), never a hidden one
        if (ref is None and not is_cookie and value and credential and not (fld is not None and fld.control == "hidden")
                and (not is_dynamic_looking(value) or _PASSWORD_NAME_RE.search(cand.name))):
            ref, meta = self._input_constant(cand, value, flow, step_no, secret=True, why="パスワードなどの値")
        # a visible input the user changed whose (token-like) value no response explains: typed / scanned
        if ref is None and fld is not None and fld.editable and is_dynamic_looking(value):
            text, encoding = self._field_text(cand.location, cand.name, value, form) or (None, None)
            if text is not None and not self._is_default(fld, text):
                ref, meta = self._input_constant(cand, text, flow, step_no, secret=fld.control == "password",
                                                 why=f"画面の入力欄 {cand.name} に入力した値",
                                                 encoding=encoding)
        # --redact: a field whose name looks like a credential is read from the environment
        if ref is None and secret_name:
            ref, meta = self._input_constant(cand, value, flow, step_no, secret=True, why="パスワードなどの値")
        # a value several steps send: one shared constant (route names in the path stay in the URL)
        if ref is None and not is_cookie and len(self.value_units.get(value, ())) >= 2 and not route_segment and not legacy:
            ref = self._constant(cand, value, flow, step_no)
            meta = _Resolution("A", source=f"定数 {ref.value}（複数の手順で同じ値）", source_kind="constant", var=ref.value)
            if is_dynamic_looking(value) and not credential:
                meta.note = "dynamic"
                self._warn_untraced(cand, step_no)
        # the value already has a constant (e.g. AUTH_USERNAME from the Basic handshake)
        if ref is None and not is_cookie and value in self.const_by_value and not route_segment and not legacy:
            ref = self._constant(cand, value, flow, step_no)
            const = self.const_by_value[value]
            meta = _Resolution("B" if const.kind in ("input", "auth") else "A", source=f"定数 {ref.value}",
                               source_kind="constant", var=ref.value)
        # the recorded literal
        if ref is None:
            # a password written into the script as recorded (no redaction) is meant to be replayed
            # as it is: no "looks dynamic" warning for it
            if is_dynamic_looking(value) and not credential:
                meta.note = "dynamic"
                self._warn_untraced(cand, step_no)
            ref = Ref.lit(value)
        cache[cache_key] = ref
        self._meta[cache_key] = meta
        self._last_meta = meta
        return ref

    def _short_field_ref(self, location: str, name: str, value: str, flow: Flow, step_no: int,
                         match: Optional["_FormMatch"]) -> Optional[Ref]:
        """A form field too short / word-like to be a trace candidate (``tanaka``, ``01``): still user
        input when it is a visible control the user changed (the 入力値 section lists every input)."""
        if location not in ("form", "multipart", "query") or not value:
            return None
        cand = Candidate(location, name, value)
        prev = self.input_fields.get(_field_key(location, name))
        if prev is not None and (prev[0] == value or self._holds(prev[1], location, name, value)) and prev[2] < step_no:
            self._short_metas[(location, name, value)] = prev[3]
            self._note_use(prev[1], cand, step_no)
            return prev[1]
        if match is None:
            return None
        fld = match.form.fields.get(name)
        if fld is None or not fld.editable:
            return None
        text, encoding = self._field_text(location, name, value, match) or (None, None)
        if text is None or self._is_default(fld, text):
            return None
        label = {"password": "パスワード欄", "select": "選択欄", "radio": "選択ボタン", "checkbox": "チェックボックス"}.get(
            fld.control, "入力欄")
        ref, meta = self._input_constant(cand, text, flow, step_no, secret=fld.control == "password",
                                         why=f"画面の{label} {name} に入力・選択した値",
                                         encoding=encoding)
        self._short_metas[(location, name, value)] = meta
        return ref

    def _warn_untraced(self, cand: Candidate, step_no: int) -> None:
        if cand.value in self._warned_values:
            return  # one warning per value, at its first step
        self._warned_values.add(cand.value)
        if cand.location == "path":
            label = f"path segment {cand.name}"
        elif cand.location == "path_param":
            label = ";" + cand.name.split(";", 1)[-1]
        elif cand.location == "cookie":
            label = f"Cookie {cand.name}"
        else:
            label = cand.name
        text = (f"step {step_no}: value of `{label}` looks dynamic but could not be traced to any earlier "
                f"response; replaying the recorded literal may fail")
        if text not in self.warnings:
            self.warnings.append(text)

    # ------------------------------------------------------------------ step construction

    def _submitted_form(self, flow: Flow) -> Optional[_FormMatch]:
        """The HTML form of an earlier page that this request submits.

        Candidates are the forms of the earlier pages (final responses, latest first) with the request's
        method that hold at least 60 % of the submitted field names.  Preferred, in this order: a form
        of the page the request's ``Referer`` names (IE sends it with every submission, script-driven
        ones and posts from a popup to its opener included); a form whose action (resolved against its
        page, path parameters ignored) is the request URL; a form holding at least 80 % of the fields and
        one of them visible (a script changed the action).  Of several forms of that page that differ only
        in their values (one form per row of a list), the one holding the most submitted values."""
        req = flow.request
        kind, parsed = classify_body(req)
        if kind == "form":
            names = {name for name, _value in parsed}
        elif kind == "multipart":
            names = {fld.name for fld in parsed}
        elif (req.method or "").upper() == "GET":
            names = {name for name, _value in parse_query(req.query)}
        else:
            names = set()
        if not names:
            return None
        method = (req.method or "GET").upper()
        target = _form_target(req.url)
        referer = req.header("referer")
        by_referer = by_action = loose = None
        for built in reversed(self.built):
            page = built.unit.response_chain[-1]
            view = _view(page)
            index = view.index if view.is_htmlish else None
            if index is None:
                continue
            charset = detect_charset(page.response.body or b"", page.response.header("content-type")) if page.response else "utf-8"
            for form in index.forms:
                if form.method != method:
                    continue
                shared = names & set(form.fields)
                if not shared or len(shared) * 5 < len(names) * 3:
                    continue
                match = _FormMatch(form=form, built=built, charset=charset)
                if by_referer is None and _same_page(page.request.url, referer):
                    by_referer = match
                try:
                    action = urljoin(page.request.url, form.action or page.request.url)
                except ValueError:
                    action = ""
                if by_action is None and _form_target(action) == target:
                    by_action = match
                visible = any(form.fields[n].control not in ("hidden", "button") for n in shared)
                if loose is None and visible and len(shared) * 5 >= len(names) * 4:
                    loose = match
            if by_referer is not None:
                break
        match = by_referer or by_action or loose
        if match is None:
            return None
        # one form per row of a list: the row the user opened, never the first row (``_opened_row``)
        sent = recorded_fields(req, kind if kind in ("form", "multipart") else "query")
        row = _opened_row(_view(match.built.unit.response_chain[-1]), match.form, sent,
                          (request_form_charset(req), match.charset))
        return match if row is match.form else _FormMatch(form=row, built=match.built, charset=match.charset)

    def _written_by_a_later_page(self, ver: CookieVersion, flow: Flow, step_no: int) -> bool:
        """``ver`` - a cookie the page's script wrote, its value in no earlier response - is first sent by
        ``flow`` (step ``step_no``): whether a page or script the steps fetch from that request on, before
        the step that sends the cookie next, writes that value (the reloaded page itself answers ``flow``).
        The page's first load is then missing from the recording, as when a popup's F12 window opened
        after it; the later steps can read the value from the page that is recorded."""
        later = sorted(s for s in (self.flow_step.get(id(g)) for g in ver.sent_by) if s is not None and s > step_no)
        if not later or self.timeline is None:
            return False
        start = self.timeline.position(flow)
        for unit in self.plan_units[step_no - 1:later[0] - 1]:
            for g in unit.all_flows:
                if self.timeline.position(g) >= start and _page_writes_cookie(g, ver.name, ver.value):
                    return True
        return False

    def _cookie_bindings(self, unit: _Unit, step_no: int, cache: dict) -> tuple[list[CookieSet], list[Binding]]:
        """The cookies this step's requests send that the script's jar would not hold by itself: those
        the page's script wrote (or the browser had before the recording) and those set by a response
        the script does not replay.  Returns the cookies to set before the request and the bindings
        (a server cookie is listed once, at its first use)."""
        sets: list[CookieSet] = []
        bindings: list[Binding] = []
        timeline = self.timeline
        if timeline is None:
            return sets, bindings
        for f in unit.all_flows:
            for name, value, ver in timeline.sent_with(f):
                if ver.origin == "server" and ver.flow is not None and id(ver.flow) in self.kept_ids:
                    if id(ver) not in self.cookie_first_use:
                        self.cookie_first_use.add(id(ver))
                        issued = self.flow_step.get(id(ver.flow))
                        shown = self._fresh_scope(ver, self._segment_refs(unit.first_flow))[1]  # /s/{s_id}/
                        bindings.append(Binding(
                            location="cookie", name=name, value_class="D",
                            source=describe_cookie(ver, issued, shown) + "。requests.Session が自動で送ります",
                            source_step=issued, source_kind="set-cookie", cookie=name,
                            cookie_domain=ver.domain, cookie_path=ver.jar_path,
                        ))
                    continue
                if id(ver) in self.external_done:
                    continue
                self.external_done.add(id(ver))
                if ver.origin == "server":
                    # set by a response the script does not replay (a dropped request)
                    if ver.previous is not None:
                        # a later value of a cookie the script's jar already holds (a load balancer
                        # refreshing it on an image): the jar keeps whatever the server gives it
                        continue
                    if ver.flow is not None and not self._in_loop_span(ver.flow):
                        self.needed_producers.setdefault(ver.flow.id, []).append(f"Cookie `{name}`")
                    url, domain = timeline.script_scope(ver, f.request.url)
                    url, path = self._set_scope(ver, unit, url)
                    sets.append(CookieSet(name=name, url=url, value=Ref.lit(value), path=path, domain=domain,
                                          note="除外したリクエストのレスポンスが設定した Cookie（記録時の値）"))
                    bindings.append(Binding(location="cookie", name=name, value_class="A",
                                            source="除外したリクエストが設定した Cookie（記録時の値）", source_kind="literal",
                                            cookie=name, cookie_domain=ver.domain, cookie_path=ver.jar_path))
                    continue
                cand = Candidate("cookie", name, value)
                if is_candidate_value(value, self.opts):
                    warnings_before, warned_before = len(self.warnings), value in self._warned_values
                    ref = self._resolve(cand, unit, step_no, cache, None, exclude=ver)
                    meta = self._last_meta
                    if ref.is_literal and ver.external_kind == "script" and self._written_by_a_later_page(ver, f, step_no):
                        # the page that writes the value answers this request or a later one (the person reloaded
                        # it, or its first load is not in the recording: a popup's F12 window opened late).  This
                        # step goes without the cookie, as a fresh browser's would; a later step sets it from that page
                        prefix = f"step {step_no}: value of `Cookie {name}`"
                        self.warnings[warnings_before:] = [w for w in self.warnings[warnings_before:] if not w.startswith(prefix)]
                        if not warned_before:
                            self._warned_values.discard(value)
                        self.external_done.discard(id(ver))
                        self.cookie_unsent.setdefault(id(ver), set()).add(step_no)
                        continue
                else:
                    # a short / word-like value (``lang=ja``) is never traced: it would match by coincidence
                    ref, meta = Ref.lit(value), _Resolution("A", source="記録時の値", source_kind="literal")
                if ref.is_literal and ver.external_kind == "pre-existing":
                    self.initial_cookies.append(initial_cookie_for(ver, f, timeline))
                    bindings.append(Binding(location="cookie", name=name, value_class="A",
                                            source="記録を始める前からあった Cookie（INITIAL_COOKIES に記録時の値）",
                                            source_kind="initial-cookie", cookie=name, cookie_domain=ver.domain,
                                            cookie_path=ver.jar_path))
                    continue
                how = "画面のスクリプトが設定した Cookie" if ver.external_kind == "script" else "記録前からあった Cookie"
                url, domain = timeline.script_scope(ver, f.request.url)
                url, path = self._set_scope(ver, unit, url)
                sets.append(CookieSet(name=name, url=url, value=ref, path=path, domain=domain,
                                      note=f"{how}。値: {meta.source}" if meta.value_class != "A" else f"{how}（記録時の値）"))
                bindings.append(Binding(location="cookie", name=name, value_class=meta.value_class,
                                        source=f"{how}。値: {meta.source}", source_step=meta.source_step,
                                        source_kind=meta.source_kind, var=meta.var, cookie=name,
                                        cookie_domain=ver.domain, cookie_path=ver.jar_path, note=meta.note))
        return sets, bindings

    def _build_step(self, unit: _Unit, index: int) -> Step:
        flow = unit.first_flow
        req = flow.request
        last = unit.last_flow
        resp = last.response
        step_no = index
        self._lookups = {}
        self._meta = {}
        self._short_metas = {}
        self._row_choices = []
        self._raw_charset = request_form_charset(req)
        self._raw_fields = {}
        for location in ("query", "form", "multipart"):
            for name, value, raw in recorded_fields(req, location):
                self._raw_fields.setdefault((location, name, value), raw)
        cands = find_candidates(flow, self.opts)
        form_info = self._submitted_form(flow)
        loop: Optional[Loop] = None
        loop_key: Optional[tuple[str, str, int]] = None
        loop_first_value: Optional[tuple[str, str, str]] = None
        loop_ref: Optional[Ref] = None
        if unit.loop is not None:
            lg = unit.loop
            var = self._loop_var(lg, flow)
            values: list = list(lg.values)
            loop_ref = Ref.var(var)
            raws = [_field_bytes(g[0].request, lg.location, lg.name, lg.occurrence) for g in lg.groups]
            if raws and all(r is not None for r in raws) and not all(is_utf8(r) for r in raws):
                # sent in a legacy charset (a Shift_JIS page): the loop goes over the texts and sends each one
                # in that charset, or over the recorded bytes when no known charset gives them back exactly
                values = raws
                for charset in (self._raw_charset if lg.location == "form" else None,
                                form_info.charset if form_info is not None else None, self._referer_charset(req)):
                    texts = [_legacy_text(r, charset) for r in raws]
                    if all(t is not None for t in texts):
                        values, loop_ref = texts, Ref.expr(f"{var}.encode({charset!r})")
                        break
            shown = ", ".join(_constant_display(v) for v in values)
            loop = Loop(var=var, values=values, numeric_range=lg.numeric_range,
                        note=f"{len(lg.groups)} iterations of {lg.location} `{lg.name}`: {truncate(shown, 60)}")
            loop_key = (lg.location, lg.name, lg.occurrence)
            loop_first_value = (lg.location, lg.name, lg.values[0] if lg.values else "")

        refs: dict[tuple[str, str, str], Ref] = {}
        self._step_scope = (refs, loop_key, loop_ref)  # the scope of the cookies the request sends
        metas: dict[tuple[str, str, str], _Resolution] = {}
        cand_by_key: dict[tuple[str, str, str], Candidate] = {}
        cache: dict[tuple, Ref] = {}
        # fields too short to be trace candidates that the user typed (a login id): decided first, in the
        # order of the request, so the 入力値 section lists them in the form's order
        short_refs: dict[tuple[str, str, str], Optional[Ref]] = {}
        cand_keys = {(c.location, c.name, c.value) for c in cands}
        for key in _submitted_fields(req):
            if key not in cand_keys and key not in short_refs:
                short_refs[key] = self._short_field_ref(*key, flow, step_no, form_info)
        for cand in cands:
            key = (cand.location, cand.name, cand.value)
            cand_by_key.setdefault(key, cand)
            if key in refs or key == loop_first_value:
                continue
            refs[key] = self._resolve(cand, unit, step_no, cache, form_info)
            metas[key] = self._last_meta
        self._bind_row_choices(refs, short_refs)

        counters: dict[tuple[str, str], int] = {}
        secret_refs: dict[tuple[str, str, str], Optional[Ref]] = {}

        def secret_ref(location: str, name: str, value: str) -> Optional[Ref]:
            # a credential that is not a trace candidate (``password=admin``, ``pin=123``) is still
            # read from the environment - never written into the script
            key = (location, name, value)
            if key not in secret_refs:
                secret_refs[key] = self._secret_ref(location, name, value, flow, step_no)
            return secret_refs[key]

        def ref_for(location: str, name: str, value: str) -> Ref:
            occ = counters.get((location, name), 0)
            counters[(location, name)] = occ + 1
            if loop is not None and loop_key == (location, name, occ):
                return loop_ref or Ref.var(loop.var)
            ref = refs.get((location, name, value))
            if ref is None:
                ref = secret_ref(location, name, value) or short_refs.get((location, name, value)) or Ref.lit(value)
            return ref

        # URL pieces: path segments and their ``;name=value`` parameters may be dynamic
        parts = urlsplit(req.url)
        segments = _path_segments(req.url)
        url: list[Ref] = []
        buf = f"{parts.scheme}://{parts.netloc}"
        dynamic_segments: set[int] = set()

        def emit(piece: Ref) -> None:
            nonlocal buf
            if piece.is_literal:
                buf += piece.value
                return
            if buf:
                url.append(Ref.lit(buf))
            url.append(piece)
            buf = ""

        for i, seg in enumerate(segments):
            buf += "/"
            if not seg:
                continue
            base, seg_params = split_path_segment(seg)
            if base:
                piece = ref_for("path", str(i), base)
                if not piece.is_literal:
                    dynamic_segments.add(i)
                emit(piece)
            for pname, pvalue in seg_params:
                emit(Ref.lit(";" + pname + ("=" if pvalue is not None else "")))
                if pvalue:
                    emit(ref_for("path_param", f"{i};{pname}", pvalue))
        if buf or not url:
            url.append(Ref.lit(buf))

        raw_query = query_bytes(req.query)
        params = [(name, ref_for("query", name, value)) for name, value in parse_form_bytes(raw_query)]
        keep = {loop.var} if loop is not None else set()
        if raw_query and not form_body_is_utf8(raw_query):
            # a query a Shift_JIS page sent (``?q=%93%FA%96%7B``): its values are sent as those bytes
            params, kept = self._legacy_form_hint(raw_query, params, keep=keep)
            if kept:
                self.warnings.append(
                    f"step {step_no}: URL のクエリが UTF-8 以外の文字コード（Shift_JIS など）でパーセントエンコードされているため、"
                    f"{_field_list(kept)} は記録時のバイト列のまま送信します"
                )
        # values an old page script built with escape() (``%uXXXX``): sent in the referring page's charset
        js_charset = self._referer_charset(req) or (form_info.charset if form_info is not None else None)
        params, escaped = self._escaped_hint(raw_query, params, js_charset)

        # body
        body_kind, parsed = classify_body(req)
        form = json_body = multipart = raw_body = None
        if body_kind == "form":
            form = [(name, ref_for("form", name, value)) for name, value in parsed]
            if not form_body_is_utf8(req.body):
                # DESIGN.md §13.4: the browser encoded the form in a legacy charset (IE on a
                # Shift_JIS page).  ``requests`` would re-encode str values as UTF-8, so the
                # recorded percent-encoded bytes are kept (``raw_body``) together with the original
                # Content-Type.  ``form`` stays filled in as the field list: literal pairs plus
                # bytes literals for the legacy values, so codegen rebuilds the body with fresh
                # dynamic values (``__VIEWSTATE`` ...) while the legacy bytes stay byte-exact.
                constant_names = {c.name for c in self.constants} | keep
                dynamic = [name for name, ref in form if not ref.is_literal and _ref_name(ref) not in constant_names]
                form, kept = self._legacy_form_hint(req.body, form, request_form_charset(req), keep)
                raw_body = req.body
                body_kind = "raw"
                note = ""
                if dynamic:
                    listed = ", ".join(dynamic[:4]) + (" …" if len(dynamic) > 4 else "")
                    note = f"（{listed} は前のステップのレスポンスから取得した値に差し替えます）"
                if kept:
                    self.warnings.append(
                        f"step {step_no}: フォーム本文が UTF-8 以外の文字コード（Shift_JIS など）でパーセントエンコードされているため、"
                        f"{_field_list(kept)} は記録時のバイト列のまま、Content-Type も記録どおりに送信します{note}"
                    )
            form, escaped_form = self._escaped_hint(req.body, form, js_charset)
            escaped += escaped_form
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
            text_parts = [(part, fld.content) for part, fld in zip(multipart, parsed) if not fld.is_file]
            if not all(is_utf8(raw) for _part, raw in text_parts):
                # text parts IE sent in the page's charset (raw cp932 bytes, not percent-encoded): an 入力値 is
                # sent in that charset, anything else as the recorded bytes
                sent, kept = self._legacy_form_hint(None, [(p.name, p.value) for p, _raw in text_parts], keep=keep,
                                                    raws=[raw for _part, raw in text_parts])
                for (part, _raw), (_name, ref) in zip(text_parts, sent):
                    part.value = ref
                if kept:
                    self.warnings.append(
                        f"step {step_no}: multipart の本文が UTF-8 以外の文字コード（Shift_JIS など）で送られているため、"
                        f"{_field_list(kept)} は記録時のバイト列のまま送信します"
                    )
        elif body_kind == "raw":
            raw_body = req.body
        if escaped:
            how = f"画面の文字コード（{js_charset}）" if js_charset and js_charset != "utf-8" else "UTF-8"
            self.warnings.append(
                f"step {step_no}: {_field_list(escaped)} は画面のスクリプトが escape() で %uXXXX の形にした値です。"
                f"この形のままでは送れないため、同じ文字を{how}でパーセントエンコードして送ります（IIS / ASP.NET は同じ値として受け取ります）"
            )

        # headers
        headers: list[tuple[str, Ref]] = []
        header_cands: dict[str, list[Candidate]] = {}
        for cand in cands:
            if cand.location == "header":
                header_cands.setdefault(cand.name, []).append(cand)
        referer_rebuilt = False
        for name, value in clean_request_headers(req.headers):
            lname = name.lower()
            if (lname, value) in self.base_set:
                continue
            if lname == "content-type" and body_kind in ("form", "json", "multipart"):
                continue
            if lname == "authorization" and is_session_auth_header(value):
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
            if ref.is_literal and lname not in ("referer", "cookie") and value.strip():
                # ``X-Api-Key: abc`` / ``Authorization: Bearer xyz`` too short to be a candidate
                prefix, token = split_auth_header(value) if lname == "authorization" else ("", value.strip())
                hidden = secret_ref("header", lname, token)
                if hidden is not None:
                    ref = _with_prefix(prefix, hidden)
            if lname == "referer" and ref.is_literal:
                secrets = {c.value: Ref.var(c.name) for c in self.secret_by_value.values()}
                # this step's values first (a constant sent in a legacy charset holds its text, not the
                # spelling the URL shows), then those traced for earlier steps
                names = {c.name for c in self.constants}
                known = {k: r for k, r in refs.items() if is_utf8(self._raw_fields.get(k, b"")) or _ref_name(r) not in names}
                for key, earlier in self.traced_refs.items():
                    known.setdefault(key, earlier)
                self._referer_sources(value, flow, step_no, known)  # a cookie held, a value a redirect handed out
                ref = _referer_with_fresh_values(value, known, secrets)
                referer_rebuilt = not ref.is_literal
            headers.append((name, ref))
        constant_names = {c.name for c in self.constants}
        for key, resolved in refs.items():
            meta = metas.get(key)
            if resolved is None or meta is None or meta.value_class not in ("C", "D"):
                continue
            if resolved.kind == "var" and resolved.value not in constant_names or resolved.kind == "expr":
                self.traced_refs[key] = resolved  # the latest source of a value wins (the referring page)

        # cookies the script has to set itself, and the dependency records of this request
        cookie_sets, bindings = self._cookie_bindings(unit, step_no, cache)
        for key, resolved in refs.items():
            meta = metas.get(key)
            if meta is None or (meta.value_class == "A" and meta.note != "dynamic"):
                continue
            location, name, _value = key
            cookie = meta.cookie
            bindings.append(Binding(
                location=location, name=name, value_class=meta.value_class, source=meta.source,
                source_step=meta.source_step, source_kind=meta.source_kind, var=meta.var,
                cookie=cookie.name if cookie is not None else None,
                cookie_domain=cookie.domain if cookie is not None else None,
                cookie_path=cookie.path if cookie is not None else None, note=meta.note,
            ))
        for (location, name, _value), meta in self._short_metas.items():
            bindings.append(Binding(location=location, name=name, value_class=meta.value_class, source=meta.source,
                                    source_kind=meta.source_kind, var=meta.var))
        if referer_rebuilt:
            bindings.append(Binding(location="referer", name="Referer", value_class="C",
                                    source="前の画面の URL に含まれる動的な値を、今回取得した値に置き換え", source_kind="referer"))
        if self.auth is not None and unit.auth_hops and not any(b.location == "auth" for s in self.built for b in s.step.bindings):
            kind = str(self.auth.kind or "").lower()
            if kind in ("ntlm", "negotiate"):
                bindings.append(Binding(location="auth", name="session.auth", value_class="E",
                                        source="実行時の Windows のログインユーザー（統合 Windows 認証、session.auth）",
                                        source_kind="session-auth"))
            else:
                bindings.append(Binding(location="auth", name="session.auth", value_class="B",
                                        source=f"入力値 {self.auth.username_const} / {self.auth.password_const}（HTTP {kind} 認証、session.auth）",
                                        source_kind="session-auth"))

        self._step_segments[index] = self._segment_refs(flow)  # the scope of cookies read right after the step
        status = resp.status if resp else 200
        mime = (resp.mime_type or "") if resp else ""
        comment = f"{req.method} {truncate(req.url_without_query, 90)} -> {status}" + (f" {mime}" if mime else "")
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
            # a step whose recorded answer is itself a redirect (its target was not recorded or not
            # kept) does not follow it either
            allow_redirects=not (resp is not None and resp.is_redirect),
            lookups=list(self._lookups.values()),
            cookie_sets=cookie_sets,
            bindings=bindings,
        )

    def _substitute_json(self, doc: Any, path: list, ref_for) -> Any:
        if isinstance(doc, dict):
            return {k: self._substitute_json(v, path + [str(k)], ref_for) for k, v in doc.items()}
        if isinstance(doc, list):
            return [self._substitute_json(v, path + [i], ref_for) for i, v in enumerate(doc)]
        conv = _leaf_as_str(doc)
        if conv is None:
            return doc
        ref = ref_for("json", json_dotted(path), conv[0])
        if ref.is_literal:
            return doc
        if conv[1] and ref.kind == "var" and any(c.name == ref.value for c in self.constants):
            # a constant (an environment variable for a secret) is a str: keep the number a number
            return Ref.expr(f"{'int' if isinstance(doc, int) else 'float'}({ref.value})")
        return ref

    # ------------------------------------------------------------------ driver

    def build(self) -> Plan:
        opts = self.opts
        if har_sensitive_data_removed(self.recording.meta):
            self.warnings.append(SANITIZED_HAR_WARNING)
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

        # the browser's cookie jar over the whole recording (kept and dropped requests: a dropped response
        # still set its cookies in the browser), and where each kept request ends up in the plan
        self.kept_ids = {id(f) for unit in units for f in unit.all_flows}
        self.plan_units = list(units)
        for idx, unit in enumerate(units, start=1):
            for f in unit.all_flows:
                self.flow_step[id(f)] = idx
        self.cookie_profile = cookie_profile_for(self.recording)
        self.timeline = CookieTimeline(self.recording.flows, self.cookie_profile)
        self.host_only_hosts = self._host_only_cookie_hosts(kept)  # before the steps: may widen external cookies
        self.dropped_by_id = {d.flow_id: d for d in dropped}
        self.loop_spans = [
            (self.timeline.position(unit.all_flows[0]), self.timeline.position(unit.all_flows[-1]))
            for unit in units if unit.loop is not None and unit.all_flows
        ]
        producer_ids = {d.flow_id for d in dropped if d.reason.startswith(_PRODUCER_REASON_PREFIXES)}
        self.dropped_flows = [f for f in self.recording.flows if f.id in producer_ids and id(f) not in self.kept_ids]
        self.base_headers = compute_base_headers(kept)
        self.base_set = {(k.lower(), v) for k, v in self.base_headers}
        self._setup_auth(kept)

        # which values are sent by more than one step (-> Constant when not traced)
        for idx, unit in enumerate(units):
            for cand in find_candidates(unit.first_flow, opts):
                if is_structural_path_segment(cand):
                    continue  # route names in the path never become constants (and do not make others one)
                self.value_units.setdefault(cand.value, set()).add(idx)
            for cand in header_candidates(unit.first_flow, skip_session_auth=False):
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
        initial_cookies = self.initial_cookies
        if initial_cookies:
            names = ", ".join(sorted({c.name for c in initial_cookies})[:8])
            self.warnings.append(
                f"{len(initial_cookies)} cookie(s) existed before the recording started ({names}); they are replayed "
                f"as INITIAL_COOKIES and may have expired"
            )
        switches = self._session_switches()
        for sw in switches:
            what = "新しい値に切り替わり" if sw.kind == "rotation" else "別の場所（domain / path）で新しく発行され"
            shown = self.shown_cookie_paths.get((sw.name, sw.domain, sw.path), sw.path)
            self.warnings.append(
                f"step {sw.step}: セッション切替を検出しました: Cookie {sw.name}（domain={sw.domain}, path={shown}）が"
                f"{what}、以降の手順はこの Cookie を使います（生成コードは Cookie を domain / path ごとに使い分けます）"
            )
        kept_hosts = {_cookie_host(f.request.url) for f in kept}
        dotless = sorted(h for h in (self.timeline.dotless_domain_hosts if self.timeline else set()) if h in kept_hosts)
        domain_is_host = sorted(h for h in (self.timeline.domain_is_host_hosts if self.timeline else set()) if h in kept_hosts)
        # Set-Cookie lines the script's hooks rewrite (attributes browsers ignore, the IE engine's default path)
        malformed_cookie = sorted(h for h in (self.timeline.malformed_cookie_hosts if self.timeline else set()) if h in kept_hosts)
        ie_default_path = sorted(h for h in (self.timeline.ie_default_path_hosts if self.timeline else set()) if h in kept_hosts)
        repeated_cookie = sorted(h for h in (self.timeline.repeated_cookie_hosts if self.timeline else set()) if h in kept_hosts)
        # requests that sent two cookies of one name: their order matters (servers read the first one)
        same_name = sorted({_cookie_host(f.request.url) for f in kept if self.timeline and len(self.timeline.sent_with(f))
                            > len({name for name, _v, _ver in self.timeline.sent_with(f)})})
        # IE engine: a sub-domain's Domain=<parent> line is the same cookie as the parent host's own (host-only) one
        parent_domain = sorted({h for h, key in (self.timeline.parent_domain_lines if self.timeline else []) if h in kept_hosts
                                and any(v.host_only and v.key == key for v in self.timeline.versions)})
        for flow in kept:
            if flow.response is not None and flow.response.status == 401 and set_cookie_lines(flow.response)                     and self.auth is not None and str(self.auth.kind or "").lower() in ("ntlm", "negotiate")                     and any(id(flow) in {id(h) for h in hops} for hops in self.auth_hops.values()):
                names = ", ".join(dict.fromkeys(p[0] for p in (parse_set_cookie(l) for l in set_cookie_lines(flow.response)) if p))
                self.warnings.append(
                    f"統合 Windows 認証の途中の応答（{flow.id}）が Cookie（{names}）を発行しています。認証の途中の Cookie は認証用の"
                    f"パッケージ（requests_negotiate_sspi / requests_ntlm）が扱うため、記録どおりには送られないことがあります"
                )

        meta = {
            "source": dict(self.recording.meta),
            "generated_at": now_iso(),
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
            cookies=self._cookie_table(switches),
            session_switches=switches,
            issued_places=self._issued_places(),
            dotless_domain_hosts=dotless,
            domain_is_host_hosts=domain_is_host,
            malformed_cookie_hosts=malformed_cookie,
            ie_default_path_hosts=ie_default_path,
            host_only_cookie_hosts=self.host_only_hosts,
            repeated_cookie_hosts=repeated_cookie,
            same_name_cookie_hosts=same_name,
            parent_domain_cookie_hosts=parent_domain,
            cookie_profile=self.cookie_profile,
            https_hosts=sorted({_cookie_host(f.request.url) for f in kept if f.request.url.lower().startswith("https:")}),
        )

    def _session_switches(self) -> list[SessionSwitch]:
        out: list[SessionSwitch] = []
        seen: set[tuple] = set()
        if self.timeline is None:
            return out
        for flow, ver, kind, prev in self.timeline.switch_events(self.kept_ids):
            step = self.flow_step.get(id(flow))
            key = (step, ver.name, ver.domain, ver.path)
            if step is None or key in seen:
                continue
            seen.add(key)
            previous = f"domain={prev.domain}, path={prev.path}"
            out.append(SessionSwitch(step=step, name=ver.name, domain=ver.domain, path=ver.jar_path, kind=kind,
                                     previous=previous))
        return out

    def _issued_places(self) -> list[tuple[int, str, str]]:
        """``Plan.issued_places``: where a step's redirect handed out a value the plan reads afresh (the value of
        an extractor of any step: a key the login's ``302 /s/<key>/menu`` hands out, read again from the menu
        page) - the place in that redirect's ``Location``: a whole path segment (its number), ``;name=`` value
        or query value (its name), when no request URL up to that redirect had the value.  A page address it
        hands over (``?ReturnUrl=%2fapp%2fDefault.aspx``) is no key.  The script hides what the replay's
        redirect puts there whatever its spelling: a fresh key may read like words."""
        samples = {s for b in self.built for e in b.step.extractors for s in (e.sample, unquote_plus(e.sample or "")) if s}
        places: set[tuple[int, str, str]] = set()
        for built in self.built if self.timeline is not None else []:
            for hop in built.unit.response_chain:
                upto = self.timeline.position(hop)
                if hop.response is None or not hop.response.is_redirect or upto < 0:
                    continue
                try:
                    target = urljoin(hop.request.url, (hop.response.location or "").strip())
                except ValueError:
                    continue
                segments = _path_segments(target)
                pieces = [("path", str(i), split_path_segment(s)[0]) for i, s in enumerate(segments)]
                pieces += [("path_param", name, v or "") for s in segments for name, v in split_path_segment(s)[1] if name]
                pieces += [("query", unquote_plus(name), v) for name, eq, v in (p.partition("=") for p in urlsplit(target).query.split("&"))
                           if eq and name]
                earlier = [f.request.url for f in self.timeline.flows[:upto + 1]]
                for kind, where, value in pieces:
                    if (value and (value in samples or unquote_plus(value) in samples) and "/" not in unquote_plus(value)
                            and not any(value in url for url in earlier)):
                        places.add((built.step.index, kind, where))
        return sorted(places)

    def _cookie_table(self, switches: list[SessionSwitch]) -> list[CookieInfo]:
        """Every cookie identity a replayed request sends or a replayed response sets."""
        table: dict[tuple[str, str, str], CookieInfo] = {}
        if self.timeline is None:
            return []
        for ver in self.timeline.versions:
            used = sorted({self.flow_step[id(f)] for f in ver.sent_by if id(f) in self.flow_step}
                          - self.cookie_unsent.get(id(ver), set()))
            issued = self.flow_step.get(id(ver.flow)) if ver.origin == "server" and ver.flow is not None else None
            if not used and issued is None:
                continue
            if ver.origin == "external":
                origin = ver.external_kind or "pre-existing"
            elif issued is None:
                origin = "dropped"
            else:
                origin = "server"
            key = (ver.name, ver.domain, ver.jar_path)
            info = table.get(key)
            if info is None:
                # a path holding a segment the steps read afresh is shown as /s/{s_id}/, never the recorded key
                info = CookieInfo(name=ver.name, domain=ver.domain, path=self.shown_cookie_paths.get(key, ver.jar_path),
                                  host_only=ver.host_only, origin=origin)
                table[key] = info
            if issued is not None and issued not in info.issued_steps:
                info.issued_steps.append(issued)
            for s in used:
                if s not in info.used_steps:
                    info.used_steps.append(s)
        for sw in switches:
            info = table.get((sw.name, sw.domain, sw.path))
            if info is not None and sw.step not in info.switch_steps:
                info.switch_steps.append(sw.step)
        for info in table.values():
            info.issued_steps.sort()
            info.used_steps.sort()
        return list(table.values())

    def _host_only_cookie_hosts(self, kept: list[Flow]) -> list[str]:
        """RFC 6265 recordings: the hosts whose host-only cookies the browser did not send to a sub-domain a
        kept request goes to, although the script holds them then and Python's default cookie policy would
        send them there (domain, path, Secure and lifetime match).  The script then uses ``_Session``,
        which keeps them on their host like the browser.  The script holds a pre-existing cookie from its
        start (INITIAL_COOKIES) and one the page wrote from the start of its step, earlier than the
        request that first sent it: the requests before that count too.

        Called before the steps are built: a pre-existing / script cookie the browser did send to a
        sub-domain of its host is a domain cookie, so it becomes ``host_only=False`` (the script sets it
        with ``domain`` and ``_Session`` still sends it there; one it also left off another sub-domain
        reaches that one too, as with Python's own rule).  When the recording contradicts that (a
        host-only server cookie sent to a sub-domain, or such a cookie sharing its identity with a server
        cookie) nothing changes: Python's own rule, as before."""
        timeline = self.timeline
        if timeline is None or self.cookie_profile != "rfc6265":
            return []
        leaked: dict[int, CookieVersion] = {}
        for flow in kept:
            host = _cookie_host(flow.request.url)
            for _n, _v, ver in timeline.sent_with(flow):
                if ver.host_only and ver.domain != host:  # the browser sent it to a sub-domain
                    if ver.origin != "external" or any(v.origin == "server" and v.key == ver.key for v in timeline.versions):
                        return []
                    leaked[id(ver)] = ver
        early: list[tuple[CookieVersion, int, Optional[int]]] = []  # (external, its first request, its step)
        for ver in timeline.externals:
            first = next((f for f in ver.sent_by if id(f) in self.kept_ids), None)
            if first is not None and ver.flow is not None and id(ver) not in leaked:
                step = None if ver.external_kind == "pre-existing" else self.flow_step.get(id(first))
                early.append((ver, timeline.position(ver.flow), step))
        out: set[str] = set()
        for flow in kept:
            host = _cookie_host(flow.request.url)
            try:
                parts = urlsplit(flow.request.url)
            except ValueError:
                continue
            https = (parts.scheme or "").lower() == "https"
            sent = {id(ver) for _n, _v, ver in timeline.sent_with(flow)}
            pos = timeline.position(flow)
            held = timeline.live_at(flow) + [ver for ver, first, step in early
                                             if pos < first and step in (None, self.flow_step.get(id(flow)))]
            for ver in held:
                if (ver.host_only and id(ver) not in leaked and id(ver) not in sent and ver.domain != host
                        and cookie_domain_match(host, ver.domain) and (https or not ver.secure)
                        and cookie_path_match(parts.path or "/", ver.jar_path) and self._replayable(ver)):
                    out.add(ver.domain)
        if not out:
            return []
        for ver in leaked.values():
            ver.host_only = False
        return sorted(out)


def _form_target(url: str) -> tuple[str, str, str]:
    """``(scheme, host[:port], path)`` of a URL, lower-cased scheme / host, ``;params`` dropped from the
    path: what a form's action and the request it produced are compared on."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ("", "", url)
    path = "/".join(seg.split(";", 1)[0] for seg in (parts.path or "/").split("/"))
    return (parts.scheme.lower(), parts.netloc.lower(), path or "/")


#: Rounds of putting back dropped producers (each round may reveal the next producer of a chain).
_PRODUCER_ROUNDS = 3


def build_plan(recording: Recording, opts: Optional[PlanOptions] = None) -> Plan:
    """Analyse a ``Recording`` and return the ``Plan`` the code generator turns into a script.

    See DESIGN.md §7 and §14 for the algorithm.  When a request the noise filter dropped (a static
    file, a tracker, a 304) turns out to set a cookie or to carry a value a kept request needs, the
    plan is built again with that request kept (``PlanOptions.include_producers``).  Never raises on
    odd recordings (binary bodies, missing responses, broken encodings); problems surface as
    ``Plan.warnings`` / ``Plan.dropped``.
    """
    opts = opts or PlanOptions()
    clear_cache()
    try:
        builder = _Builder(recording, opts)
        plan = builder.build()
        put_back: list[tuple[str, list[str]]] = []
        for _round in range(_PRODUCER_ROUNDS):
            if not opts.include_producers or not builder.needed_producers:
                break
            excluded = _flow_id_set(opts.exclude_flow_ids)
            included = set(opts.include_flow_ids or [])
            extra = [fid for fid in builder.needed_producers
                     if fid not in included and fid not in excluded and normalise_flow_id(fid) not in excluded
                     and fid in builder.dropped_by_id
                     and builder.dropped_by_id[fid].reason.startswith(_PRODUCER_REASON_PREFIXES)]
            if not extra:
                break
            put_back.extend((fid, builder.needed_producers[fid]) for fid in extra)
            opts = replace(opts, include_flow_ids=list(opts.include_flow_ids or []) + extra)
            clear_cache()
            builder = _Builder(recording, opts)
            plan = builder.build()
        for fid, uses in put_back:
            flow = recording.flow_by_id(fid)
            step = next((s.index for s in plan.steps if fid in s.source_flow_ids), None)
            label = f"{flow.request.method} {truncate(flow.request.url_without_query, 80)}" if flow is not None else fid
            what = ", ".join(dict.fromkeys(uses))
            plan.warnings.append(
                f"step {step}: 除外していたリクエスト {fid}（{label}）は、後の手順で使う値（{truncate(what, 80)}）を返しているため、"
                f"手順に含めました" if step is not None else
                f"除外していたリクエスト {fid}（{label}）は、後の手順で使う値（{truncate(what, 80)}）を返しているため、手順に含めました"
            )
        return plan
    finally:
        clear_cache()


# ===== former reqrec/codegen.py: Plan -> standalone Python script =====
# Plan -> standalone Python script source.  Contract: DESIGN.md §8.
#
# ``generate(plan, opts)`` renders a :class:`Plan` as a self-contained, readable
# Python 3.8+ script built on ``requests`` + ``BeautifulSoup``: one function per step, a ``main()``
# that threads extracted values between steps through a ``ctx`` dict, and a handful of small
# runtime helpers (``_charset`` / ``_text`` for response encoding, ``_soup``, ``_check``, ``_regex``,
# ``_json_path``, ``_select`` / ``_attr`` / ``_elem_text``).
#
# Phase 2 (DESIGN.md §13)
# -----------------------
# * ``main()`` runs every step but prints the result of the step named by ``Plan.final_step_index``
#   (``final_resp`` / ``final_results``; the last step when unset).
# * ``Plan.auth`` becomes ``session.auth`` (Basic tuple, ``HTTPDigestAuth``, or the
#   ``requests_negotiate_sspi`` -> ``requests_ntlm`` fallback for NTLM / Negotiate); recorded
#   ``Authorization`` headers of that scheme are never emitted.
# * Responses are decoded from bytes: ``_soup`` parses ``resp.content`` and ``_text(resp)`` sniffs the
#   charset (header -> ``<meta>`` / ``<?xml`` -> JSON = UTF-8 -> ``apparent_encoding``), so Shift_JIS
#   pages served without a charset do not become mojibake.
# * A ``raw`` body that carries ``Step.form`` (a form recorded percent-encoded in a legacy charset) is
#   rebuilt with ``urlencode`` from the form pairs, so fresh ``__VIEWSTATE``-style values reach the server.
# * Downloads (DESIGN.md §13.13): right after its own request, every step's response is saved as a
#   file when it is binary or ``Content-Disposition`` names an attachment (any response kind, loop
#   iterations included; ``_save_download`` / ``_save_if_attachment``, unique names per run); the final
#   print block only prints.  ``main()`` first checks the required secret *constants* (recorded
#   non-empty secrets and the Basic / Digest password) and exits with a plain message.
#
# Security boundary
# -----------------
# Everything in a ``Plan`` that came from the recording (URLs, header names and values, parameter
# names and values, form fields, JSON bodies, cookie values, regex patterns, CSS selectors,
# constants, sample values, free-text comments) is attacker-controlled.  It only ever reaches the
# generated source through :func:`_lit` (``repr()``), :func:`_json_lit` (JSON bodies rendered as
# Python literals leaf by leaf), :func:`_docstring_lines` (a ``repr``-equivalent escaper for
# triple-quoted strings) or :func:`_comment_text` (line breaks and control characters removed so a
# comment can never continue onto a new line).  Identifiers (``Ref.var``, extractor variables,
# constant and function names, loop variables) are validated with ``str.isidentifier`` and
# ``Ref.expr`` sources must parse as a single Python expression without comments or line breaks;
# anything else raises :class:`CodegenError` instead of being written into the script.


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

#: Names the generated script defines itself (functions, globals, helpers, imports): never used for a
#: step function (constants and variables are kept off them by the plan's ``_CODEGEN_NAMES``).
_CODEGEN_RESERVED = frozenset({
    "main", "session", "resp", "soup", "data", "ctx", "results", "out", "requests", "re", "json",
    "os", "sys", "time", "unquote", "urlencode", "urljoin", "BeautifulSoup", "email", "http", "exc",
    "traceback", "_mask_values", "_note_issued", "_looks_random",
    "TIMEOUT", "DELAY", "DEBUG", "BASE_HEADERS", "INITIAL_COOKIES", "DEPENDENCIES", "SESSION_SWITCHES",
    "ISSUED_PLACES", "_SPELLING", "_misspelled",
    "_soup", "_check", "_regex", "_json_path", "_json_row", "_select", "_attr", "_elem_text", "_text", "_charset",
    "_normalise_charset", "final_resp", "final_results", "final_saved", "_STEP", "_step_start", "_step_ok",
    "_debug", "_mask_url", "_mask_text", "_cookie", "_cookie_keys", "_set_cookie", "_need", "_hop",
    "_host_cookie_hook", "_cookies_in_order", "urlsplit", "HttpNegotiateAuth", "HttpNtlmAuth",
    "_cookie_attr_hook", "_ie_cookie_hook", "_Session", "functools", "warnings", "_windows_certificates",
})

#: How the dependency table names the place a value is sent to.
_LOCATION_LABELS = {
    "path": "URL のパス", "path_param": "URL のパスパラメーター", "query": "クエリ", "form": "フォーム",
    "json": "JSON", "multipart": "フォーム（ファイル送信）", "header": "ヘッダー", "cookie": "Cookie",
    "referer": "ヘッダー", "auth": "認証",
}

#: Default for ``REQREC_NTLM_USER`` when the recording did not reveal the user (emitted verbatim;
#: it is our own text, not recorded content).
_NTLM_USER_PLACEHOLDER = 'r"DOMAIN\\user"'

_FORM_MIME = "application/x-www-form-urlencoded"
_AUTH_EXPR_SCHEME_RE = re.compile(r"""^\s*(?:[bru]*)(["'])([A-Za-z][A-Za-z0-9._-]*)\s""")



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


_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_COOKIE_PATH_RE = re.compile(r"^/[^;,\x00-\x1f\x7f]*$")
_COOKIE_DOMAIN_RE = re.compile(r"^\.?[A-Za-z0-9._:\[\]-]+$")


def _cookie_attrs_problem(name: Any, path: Any, domain: Any) -> Optional[str]:
    """Why a cookie name / path / domain cannot go into a ``Set-Cookie`` line the script builds (it must
    not be able to add attributes of its own, ``/; Domain=other``), or None: an RFC 6265 token,
    ``/...`` without ``;`` or ``,``, host-name characters."""
    if not isinstance(name, str) or not _COOKIE_NAME_RE.match(name):
        return "名前に使えない文字があります"
    if path is not None and (not isinstance(path, str) or not _COOKIE_PATH_RE.match(path)):
        return "path に使えない文字があります"
    if domain is not None and (not isinstance(domain, str) or not _COOKIE_DOMAIN_RE.match(domain)):
        return "domain がホスト名ではありません"
    return None


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
        self.lookup_vars: set[str] = set()  # cookie values read from the jar before a step's request
        self.input_names: set[str] = {str(c.name) for c in plan.constants if getattr(c, "kind", "") == "input"}
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
        reserved = set(self.constant_names) | _CODEGEN_RESERVED | _DOWNLOAD_HELPER_NAMES
        for step in self.plan.steps:
            base = _check_identifier(step.func_name or f"step_{step.index:02d}", "step function name")
            self.func_names.append(unique_name(base, reserved))
        for step, fname in zip(self.plan.steps, self.func_names):
            for lookup in getattr(step, "lookups", None) or []:
                var = _check_identifier(lookup.var, "cookie lookup variable")
                if var in self.constant_names:
                    raise CodegenError(f"cookie lookup variable {var!r} collides with a constant")
                self.producer.setdefault(var, fname)
                self.producer_kind.setdefault(var, "cookie")
                self.lookup_vars.add(var)
                self.helpers_needed.add("_cookie")
            if getattr(step, "cookie_sets", None):
                self.helpers_needed.add("_set_cookie")
            for ext in step.extractors:
                self.producer.setdefault(ext.var, fname)
                self.producer_kind.setdefault(ext.var, ext.kind)
                self.helpers_needed.update(_helpers_for_extractor(ext))
            for ref in self._iter_refs(step):
                if isinstance(ref, Ref) and ref.kind == "expr" and "_cookie(" in str(ref.value):
                    self.helpers_needed.add("_cookie")
            if self._raw_form(step) is not None:
                self.needs_urlencode = True
        if self.plan.initial_cookies:
            self.helpers_needed.add("_set_cookie")
        # Set-Cookie lines rewritten before Python's jar sees them, and the browser's cookie policy
        ie = getattr(self.plan, "cookie_profile", "") == "wininet"
        if getattr(self.plan, "malformed_cookie_hosts", None):
            self.helpers_needed.add("_cookie_attr_hook")
        if getattr(self.plan, "domain_is_host_hosts", None) or (ie and (getattr(self.plan, "ie_default_path_hosts", None)
                                                                       or getattr(self.plan, "parent_domain_cookie_hosts", None))):
            self.helpers_needed.add("_ie_cookie_hook" if ie else "_host_cookie_hook")
        if getattr(self.plan, "repeated_cookie_hosts", None):  # a cookie set and deleted by one response: the last line wins
            self.helpers_needed.add("_ie_cookie_hook" if ie else "_host_cookie_hook")
        if not ie and getattr(self.plan, "host_only_cookie_hosts", None):
            self.helpers_needed.add("_Session")
        if getattr(self.plan, "same_name_cookie_hosts", None):  # two cookies of one name: keep the browser's order
            self.helpers_needed.add("_cookies_in_order")
        if getattr(self.plan, "https_hosts", None):  # https:// sites (HAR files): Windows' certificates too, as in Edge
            self.helpers_needed.add("_windows_certificates")
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

        ``analysis.py`` (plan builder) provides ``AUTH_USERNAME`` / ``AUTH_PASSWORD`` (``AuthInfo.username_const`` /
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
        name = unique_name(default_name, taken)
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
            if ref.value in self.lookup_vars:
                return "Cookie から取得（送り先に合う domain / path のもの）"
            if ref.value in self.producer:
                return f"{self.producer[ref.value]} で取得"
            if ref.value in self.loop_vars:
                return "ループ変数"
            if ref.value in self.input_names:
                return "入力値"
            return None
        if ref.kind == "expr":
            names = [n for n in _expr_names(_check_expr(ref.value)) if n in self.producer]
            if any(n in self.lookup_vars for n in names) or "_cookie(" in ref.value:
                return "Cookie から取得（送り先に合う domain / path のもの）"
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

    def _scope(self, value: Any) -> str:
        """A cookie scope URL / path: a str literal, or URL pieces (a ``Ref`` tuple: a path segment the step
        reads afresh) joined like ``_url``."""
        if isinstance(value, (list, tuple)):
            return self._url(value)
        return _lit(value)

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
        """Every Ref of a step in the order the request is assembled (cookies set before it, URL, params,
        headers, body)."""
        for cookie in getattr(step, "cookie_sets", None) or []:
            if isinstance(cookie.value, Ref):
                yield cookie.value
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
        local = {str(lookup.var) for lookup in getattr(step, "lookups", None) or []}  # read in the step itself
        params: list[str] = []
        loop_var = step.loop.var if step.loop is not None else None
        if loop_var:
            params.append(loop_var)
        for ref in self._iter_refs(step):
            if not isinstance(ref, Ref):
                continue
            if ref.kind == "var":
                name = _check_identifier(ref.value, "Ref.var")
                if name in self.constant_names or name == loop_var or name in params or name in local:
                    continue
                if name not in known:
                    self._note(f"{step.func_name}: 変数 {name!r} はどのステップでも取得されていません（実行時に KeyError になります）")
                params.append(name)
            elif ref.kind == "expr":
                for name in _expr_names(_check_expr(ref.value)):
                    if (name in known and name not in self.constant_names and name != loop_var and name not in params
                            and name not in local):
                        params.append(name)
        return params

    # ------------------------------------------------------------------ sections

    def _render(self, extra: Optional[list[str]] = None) -> str:
        self.w = _Writer()
        self._emit_docstring(extra=extra)
        self._emit_imports()
        self._emit_settings()
        self._emit_helpers()
        self._emit_dependency_table()
        self._emit_steps()
        self._emit_main()
        self.w.blank(2)
        self.w.line('if __name__ == "__main__":')
        with self.w.indent():
            self.w.line("try:")
            with self.w.indent():
                self.w.line("main()")
            self.w.line("except Exception as exc:")
            with self.w.indent():
                self._c("どの手順で止まったかを「[3/16] ERROR ...」と表示してから、エラーの詳細を出す（URL や Cookie の値は *** で隠す）")
                self.w.line('if _STEP["no"] and not _STEP["ok"]:')
                with self.w.indent():
                    self.w.line('reason = "{}: {}".format(type(exc).__name__, _mask_text(exc))[:300]')
                    self.w.line('print("[{}/{}] ERROR  {}  ({})".format(_STEP["no"], _STEP["total"], _STEP["label"], reason), file=sys.stderr, flush=True)')
                if "_windows_certificates" in self.helpers_needed:
                    self.w.line('if "CERTIFICATE_VERIFY_FAILED" in str(exc):')
                    with self.w.indent():
                        self.w.line(f"print({_lit(CERTIFICATE_HINT)}, file=sys.stderr, flush=True)")
                self.w.line("import traceback")
                self.w.line('for line in "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).splitlines():')
                with self.w.indent():
                    self.w.line("print(line[:len(line) - len(line.lstrip())] + _mask_text(line), file=sys.stderr)")
                self.w.line("sys.exit(1)")
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
        label = {"har": "HAR ファイル", "recbrowser": "記録用ブラウザ", "edge": "Edge（記録用）",
                 "mitmproxy": "mitmproxy 録画"}.get(kind.lower(), kind)
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
            f"生成: reqrec {__version__} / {meta.get('generated_at') or now_iso()}",
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
                "統合 Windows 認証には追加パッケージが必要です。Windows: python -m pip install requests_negotiate_sspi"
                "（今ログインしているユーザーで認証します）",
                "Windows 以外 / 別のユーザーで実行する場合: python -m pip install requests_ntlm のうえ、環境変数 "
                f"REQREC_NTLM_USER（例: {default_user}）と REQREC_NTLM_PASSWORD を設定してください"
                "（requests_negotiate_sspi が入っている PC では、今ログインしているユーザーで認証します）",
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
        if "_set_cookie" in self.helpers_needed:
            w.line("import email.message")
        if "_ie_cookie_hook" in self.helpers_needed:
            w.line("import functools")
        if {"_Session", "_cookies_in_order"} & self.helpers_needed:
            w.line("import http.cookiejar")
        w.line("import json")
        w.line("import os")
        w.line("import re")
        w.line("import sys")
        w.line("import time")
        if "_cookie_attr_hook" in self.helpers_needed:
            w.line("import warnings")
        names = ["unquote", "urljoin"] + (["urlencode"] if self.needs_urlencode else [])
        if {"_host_cookie_hook", "_ie_cookie_hook"} & self.helpers_needed:
            names.append("urlsplit")
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
        c = self._comment("True にするか、環境変数 REQREC_DEBUG=1 で、動的な値の取得元・送り先・Cookie の domain / path を表示（値そのものは表示しません）")
        w.line('DEBUG = os.environ.get("REQREC_DEBUG", "") not in ("", "0")' + (f"  # {c}" if c else ""))

        constants = self._all_constants()
        inputs = [c for c in constants if getattr(c, "kind", "") == "input"]
        others = [c for c in constants if getattr(c, "kind", "") != "input"]
        if inputs:
            w.blank()
            self._c("===== 入力値（記録したときに画面で入力・選択した値。別の値で実行したいときは書き換えてください） =====")
            for const in inputs:
                self._emit_constant(const)
        if others:
            w.blank()
            self._c("===== 定数（必要に応じて書き換えてください） =====")
            for const in others:
                self._emit_constant(const)

        w.blank()
        self._c("全てのリクエストに共通して送るヘッダー")
        items = [([f"{_lit(k)}: {_lit(v)}"], None) for k, v in (self.plan.base_headers or [])]
        w.block(_container("{", "}", items, inline_ok=False), prefix="BASE_HEADERS = ")

        w.blank()
        self._c("記録を始める前からブラウザが持っていた Cookie（url のサーバーが発行したのと同じ扱いで設定します）")
        if self.plan.initial_cookies:
            self._c("期限切れになっている場合は、再度ブラウザから値を取得して書き換えてください")
        items = []
        for ck in self.plan.initial_cookies or []:
            url = getattr(ck, "url", "") or f"http://{ck.domain}{ck.path or '/'}"
            problem = _cookie_attrs_problem(ck.name, ck.path or "/", None if getattr(ck, "host_only", True) else ck.domain)
            if problem:
                self._note(f"記録前からあった Cookie を 1 つ設定できません（{problem}）。その Cookie は送りません")
                continue
            entry = [
                f"'name': {_lit(ck.name)}",
                f"'value': {_lit(ck.value)}",
                f"'url': {_lit(url)}",
                f"'path': {_lit(ck.path or '/')}",
            ]
            if not getattr(ck, "host_only", True):
                entry.append(f"'domain': {_lit(ck.domain)}")
            items.append((["{" + ", ".join(entry) + "}"], None))
        w.block(_container("[", "]", items, inline_ok=False), prefix="INITIAL_COOKIES = ")

    def _binding_rows(self) -> list[tuple[int, str, str, str, str, Optional[str]]]:
        """``(step, place, name, class, source, variable)`` for every recorded binding (value-free)."""
        rows = []
        for step in self.plan.steps:
            for b in getattr(step, "bindings", None) or []:
                location = str(b.location)
                place = _LOCATION_LABELS.get(location, location)
                name = str(b.name)
                if location == "path":
                    try:
                        name = f"{int(name) + 1} 番目"
                    except ValueError:
                        pass
                elif location == "path_param":
                    name = ";" + name.split(";", 1)[-1]
                var = b.var if b.var and str(b.var).isidentifier() else None
                rows.append((int(step.index), place, name, str(b.value_class), str(b.source or ""), var))
        return rows

    def _emit_dependency_table(self) -> None:
        """``DEPENDENCIES`` (what each step sends that is not a fixed value, and where it comes from),
        ``SESSION_SWITCHES`` and the cookie table as comments.  Never any value: names, steps, kinds and
        sources only (the DEBUG output prints this table at run time)."""
        w = self.w
        rows = self._binding_rows()
        w.blank()
        self._c("===== 動的な値の一覧（実行のたびに取り直す値と入力値。値そのものはここには書きません） =====")
        self._c("種類: A=固定値（記録時の値のまま） B=入力値 C=前のレスポンスから取得 D=Cookie / セッション E=実行時の値（時刻など）")
        self._c("(手順, 送る場所, 名前, 種類, 取得元, 値が入る変数)")
        items = []
        for no, place, name, kind, source, var in rows:
            items.append(([f"({no}, {_lit(place)}, {_lit(name)}, {_lit(kind)}, {_lit(source)}, {_lit(var) if var else 'None'})"], None))
        w.block(_container("[", "]", items, inline_ok=False), prefix="DEPENDENCIES = ")
        switches = sorted({(int(sw.step), str(sw.name)) for sw in getattr(self.plan, "session_switches", None) or []})
        if switches:
            self._c("セッション切替（Cookie が新しく発行され、以降の手順はそちらを使う）: (手順, Cookie 名)")
        w.line("SESSION_SWITCHES = " + ("{" + ", ".join(f"({no}, {_lit(name)})" for no, name in switches) + "}" if switches else "set()"))
        places = sorted({(int(no), str(kind), int(name) + 1 if kind == "path" else str(name))
                         for no, kind, name in getattr(self.plan, "issued_places", None) or []
                         if kind in ("path_param", "query") or (kind == "path" and str(name).isdigit())})
        if places:
            self._c("リダイレクト先の URL で渡される値（セッションのキーなど）の場所: (手順, 場所, パスの何番目 / 名前)。"
                    "表示するメッセージでは、その値を *** にします")
        w.line("ISSUED_PLACES = " + ("{" + ", ".join(f"({no}, {_lit(kind)}, {where if kind == 'path' else _lit(where)})"
                                                    for no, kind, where in places) + "}" if places else "set()"))
        cookies = getattr(self.plan, "cookies", None) or []
        if cookies and self.opts.comments:
            w.blank()
            self._c("Cookie の一覧（requests.Session が domain / path ごとに管理し、送り先に合うものだけを送ります）")
            origins = {"server": "", "pre-existing": "記録前からあった Cookie", "script": "画面のスクリプトが設定",
                       "dropped": "除外したリクエストが設定"}
            for info in cookies:
                parts = [f"{info.name}  domain={info.domain}  path={info.path}"]
                if info.issued_steps:
                    parts.append(f"手順 {_steps_text(info.issued_steps)} で発行")
                origin = origins.get(info.origin, "")
                if origin:
                    parts.append(origin)
                if info.switch_steps:
                    parts.append(f"手順 {_steps_text(info.switch_steps)} でセッション切替")
                if info.used_steps:
                    parts.append(f"手順 {_steps_text(info.used_steps)} で送信")
                self._c("  " + "、".join(parts))

    def _emit_constant(self, const: Constant) -> None:
        w = self.w
        name = _check_identifier(const.name, "constant name")
        if const.comment:
            self._c(const.comment)
        if const.secret:
            env = _env_name(const)
            self._c(f"記録時の値は安全のため出力していません。環境変数 {env} で指定してください（下の行の '' に直接書いても動きます）")
            w.line(f"{name} = os.environ.get({_lit(env)}, '')")
        elif isinstance(const.value, (bytes, bytearray)):
            # a value a Shift_JIS (or other legacy charset) page sent: the recorded bytes
            self._c(_legacy_bytes_note(bytes(const.value)) + "。書き換えるときは '日本語'.encode('cp932') のように書きます")
            w.line(f"{name} = {_lit(bytes(const.value))}")
        else:
            if getattr(const, "encoding", None):
                self._c(f"画面の文字コード（{const.encoding}）に変換して送ります。日本語のまま書き換えてかまいません")
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
                w.line('"""ステータスコードが記録時と一致することを確認する（記録時 304 なら 200 も可。URL の値は *** で隠す）。"""')
                w.line("if resp.status_code != expected and not (expected == 304 and resp.status_code == 200):")
                with w.indent():
                    w.line("raise RuntimeError(")
                    with w.indent():
                        w.line('f"{step}: 想定外のステータスコード {resp.status_code} "')
                        w.line('f"(記録時: {expected}) {resp.request.method} {_mask_url(resp.url)}"')
                    w.line(")")
            else:
                w.line('"""記録時と違うステータスなら警告を出し、記録時に無かったエラー応答（4xx/5xx）なら例外にする（URL の値は *** で隠す）。"""')
                w.line("if resp.status_code == expected or (expected == 304 and resp.status_code == 200):")
                with w.indent():
                    w.line("return")
                w.line("print(")
                with w.indent():
                    w.line('f"[警告] {step}: ステータスコード {resp.status_code} (記録時: {expected}) {_mask_url(resp.url)}",')
                    w.line("file=sys.stderr,")
                w.line(")")
                w.line("if resp.status_code >= 400:")
                with w.indent():
                    w.line('raise requests.HTTPError(f"{step}: HTTP {resp.status_code} {_mask_url(resp.url)}", response=resp)')

        self._emit_progress_helpers()
        self._emit_cookie_helpers()
        if "_windows_certificates" in self.helpers_needed:
            self._emit_certificate_helper()

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

        if "_json_row" in self.helpers_needed:
            w.blank(2)
            w.line("def _json_row(data, rows_path, key_path, wanted, leaf_path):")
            with w.indent():
                w.line('"""JSON の一覧（rows_path）から key_path の値が wanted の行を探し、その行の leaf_path の値を返す。')
                w.line("")
                w.line("画面の一覧で選んだ行は、行の番号ではなくこの値で探す（次の実行で一覧の並び順が変わっても、")
                w.line("同じ行の値を送るため）。その行がない・複数あるときはエラー（値は表示しない）。")
                w.line('"""')
                w.line("found = []")
                w.line("rows = _json_path(data, rows_path)")
                w.line("for row in rows if isinstance(rows, list) else []:")
                with w.indent():
                    w.line("key = row")
                    w.line("for k in key_path:")
                    with w.indent():
                        w.line("key = key.get(k) if isinstance(key, dict) else None")
                    w.line("if key is not None and not isinstance(key, (bool, dict, list)) and str(key) == str(wanted):")
                    with w.indent():
                        w.line("found.append(row)")
                w.line("if len(found) != 1:")
                with w.indent():
                    w.line('how = "ありません" if not found else "複数あります"')
                    w.line('raise RuntimeError(f"JSON の一覧 {rows_path!r} の中に、{key_path!r} が選んだ値の行が{how}")')
                w.line("return _json_path(found[0], leaf_path)")

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

    def _emit_progress_helpers(self) -> None:
        """``_step_start`` / ``_step_ok``: one line per step on stderr while the script runs, so the
        user sees how far it got ("[2/9] OK  POST /Login.aspx (200)  「メニュー」"); the ``__main__``
        block adds "[3/9] ERROR ..." when a step raises.  stderr keeps stdout for the result.  With
        ``DEBUG`` they also print the step's ``DEPENDENCIES`` rows and the cookies it received
        (``[3/9]   ...`` lines; names, domains, paths, kinds and lengths - never values)."""
        w = self.w
        w.blank(2)
        self._c("どこまで進んだかの表示（標準エラー出力に出すので、結果の表示とは混ざらない）")
        for ln in _PROGRESS_HELPERS_SRC.strip("\n").split("\n"):
            w.line(ln)

    def _emit_certificate_helper(self) -> None:
        """``_windows_certificates(session)``: https:// certificates are checked with requests' own list
        (certifi) and the Windows certificate store (an organisation's CA that Edge trusts).  Standard
        library only: ``SSLContext.load_default_certs`` reads the Windows stores; elsewhere it reads the
        system's.  Any failure, or a transport adapter someone else mounted (a test's), leaves the session
        as it was."""
        w = self.w
        w.blank(2)
        w.line("def _windows_certificates(session):")
        with w.indent():
            w.line('"""https のサイトの証明書を、requests の証明書リストに加えて、Windows に入っている証明書')
            w.line("（信頼されたルート証明機関など。Edge が使うもの）でも確かめる。使えないときは requests の標準のまま。")
            w.line('"""')
            w.line("try:")
            with w.indent():
                w.line("import warnings")
                w.line("from requests.adapters import HTTPAdapter")
                w.line("from requests.certs import where")
                w.line("from urllib3.util.ssl_ import create_urllib3_context")
                w.line("if type(session.get_adapter(\"https://\")) is not HTTPAdapter:")
                with w.indent():
                    self._cl("return", "ほかの通信の部品が入れてあるときは、そのまま使う")
                w.line("context = create_urllib3_context()")
                w.line("with warnings.catch_warnings():")
                with w.indent():
                    self._cl('warnings.simplefilter("ignore")', "読めない証明書が Windows にあっても警告は出さない")
                    self._cl("context.load_default_certs()", "Windows では Windows の証明書ストアを読む")
                self._cl("context.load_verify_locations(where())", "requests の証明書リスト")
            w.line("except Exception:")
            with w.indent():
                w.line("return")
            w.blank()
            w.line("class _Adapter(HTTPAdapter):")
            with w.indent():
                w.line("def init_poolmanager(self, *args, **kwargs):")
                with w.indent():
                    w.line('kwargs["ssl_context"] = context')
                    w.line("return super().init_poolmanager(*args, **kwargs)")
                w.blank()
                w.line("def proxy_manager_for(self, proxy, **kwargs):")
                with w.indent():
                    w.line('kwargs.setdefault("ssl_context", context)')
                    w.line("return super().proxy_manager_for(proxy, **kwargs)")
            w.blank()
            w.line('session.mount("https://", _Adapter())')

    def _emit_cookie_helpers(self) -> None:
        """``_cookie`` / ``_set_cookie`` / ``_need`` / ``_hop`` / ``_host_cookie_hook`` when the plan uses them."""
        w = self.w
        for name, src in _COOKIE_HELPERS_SRC:
            if name in self.helpers_needed:
                w.blank(2)
                for ln in src.strip("\n").split("\n"):
                    w.line(ln)

    def _progress_label(self, step: Step) -> str:
        """``"POST /Login.aspx"``: the method and the path of the step's URL (no host, no query; the
        recorded values of ``;name=value`` path parameters are not shown)."""
        path = urlsplit(self._url_display(step.url)).path or "/"
        path = _PATH_PARAM_VALUE_RE.sub(r"\1…", path)
        return f"{str(step.method).upper()} {path}"

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
            w.line("文字化けする。ヘッダーの charset → 本文先頭の <meta charset> / <?xml encoding> → UTF-8 として読めれば")
            w.line("UTF-8 → JSON なら UTF-8 → 本文からの推定、の順に文字コードを決め、resp.encoding に設定したうえで")
            w.line("resp.text を返す（短い本文の推定はよく外れるため、UTF-8 で読めるものは推定しない）。")
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
                w.line("try:")
                with w.indent():
                    w.line('(resp.content or b"").decode("utf-8")')
                    w.line('charset = "utf-8"')
                w.line("except UnicodeDecodeError:")
                with w.indent():
                    w.line('mime = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()')
                    self._cl('charset = "utf-8" if mime.endswith("json") else resp.apparent_encoding', "JSON は UTF-8（RFC 8259）")
            w.line("if charset:")
            with w.indent():
                w.line("resp.encoding = charset")
            w.line("return resp.text")

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
                # build_plan writes "METHOD URL -> STATUS mime ..."; avoid repeating the head line
                if comment.startswith(str(step.method).upper() + " ") and " -> " in comment:
                    doc += ["", "記録時のレスポンス: " + comment.split(" -> ", 1)[1]]
                else:
                    doc += ["", comment]
            rows = [r for r in self._binding_rows() if r[0] == int(step.index)]
            if rows:
                doc += ["", "送る値の取得元（A=固定 B=入力値 C=前のレスポンス D=Cookie/セッション E=実行時）:"]
                doc += [f"  {place} {name}: [{kind}] {source}" for _no, place, name, kind, source, _var in rows]
            for ln in _docstring_lines(doc):
                w.line(ln)
            lookups = self._emit_pre_request(step)
            self._emit_request(step)
            try:
                expected = int(step.expected_status)
            except (TypeError, ValueError):
                expected = 200
            w.line(f"_check(resp, {expected}, {_lit(fname)})")
            outputs = lookups + [v for v in self._emit_extractors(step, fname) if v not in lookups]
            items = [([f"{_lit(v)}: {v}"], None) for v in outputs]
            w.block(_container("{", "}", items), prefix="return resp, ")
        w.blank(2)

    def _emit_pre_request(self, step: Step) -> list[str]:
        """Before the request: the cookie lookups the cookies set by this step need, the cookies set
        (``_set_cookie``), then the remaining lookups (a lookup may read a cookie the step has just set).
        Returns the lookup variables."""
        lookups = list(getattr(step, "lookups", None) or [])
        sets = list(getattr(step, "cookie_sets", None) or [])
        needed: set[str] = set()
        for cookie in sets:
            ref = cookie.value
            if isinstance(ref, Ref) and ref.kind == "var":
                needed.add(str(ref.value))
            elif isinstance(ref, Ref) and ref.kind == "expr":
                needed.update(_expr_names(_check_expr(ref.value)))
        first = [lk for lk in lookups if str(lk.var) in needed]
        rest = [lk for lk in lookups if str(lk.var) not in needed]
        out = self._emit_lookups(first)
        self._emit_cookie_sets(step)
        return out + self._emit_lookups(rest)

    def _emit_lookups(self, lookups: Sequence[CookieLookup]) -> list[str]:
        """``var = _cookie(session, name, url, path=..., domain=...)`` for every cookie value the request
        sends (class D): the cookie of that name the jar sends to that URL, read right before the request
        (so a session switched by an earlier step is picked up).  Returns the variables."""
        out: list[str] = []
        for lookup in lookups:
            var = _check_identifier(lookup.var, "cookie lookup variable")
            args = ["session", _lit(lookup.name), self._scope(lookup.url)]
            if lookup.path:
                args.append(f"path={self._scope(lookup.path)}")
            if lookup.domain:
                args.append(f"domain={_lit(lookup.domain)}")
            if lookup.note:
                self._c(f"D: {lookup.note}。送り先に合う domain / path の Cookie を読む")
            w = self.w
            w.line(f"{var} = _cookie({', '.join(args)})")
            out.append(var)
        return out

    def _emit_cookie_sets(self, step: Step) -> None:
        """``_set_cookie(session, url, name, value, path=...)`` for the cookies the page's script wrote
        (or the browser had) before this request, with their value from an earlier response or the jar."""
        for cookie in getattr(step, "cookie_sets", None) or []:
            problem = _cookie_attrs_problem(cookie.name, cookie.path, cookie.domain)
            if problem:
                self._note(f"{step.func_name}: 画面のスクリプトが設定した Cookie を 1 つ設定できません（{problem}）。その Cookie は送りません")
                continue
            args = ["session", self._scope(cookie.url), _lit(cookie.name), self._ref(cookie.value)]
            if cookie.path:
                args.append(f"path={_lit(cookie.path)}")
            if cookie.domain:
                args.append(f"domain={_lit(cookie.domain)}")
            if cookie.note:
                self._c(f"Cookie {cookie.name}: {cookie.note}")
            self.w.line(f"_set_cookie({', '.join(args)})")

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
        raw_form = self._raw_form(step)
        if raw_form is not None:
            # only the pairs still sent as the recorded bytes are named (an 入力値 is converted, a fetched value replaced)
            kept = [str(n) for n, r in raw_form if isinstance(r, Ref) and r.kind == "expr" and _bytes_literal_value(r.value) is not None]
            if kept:
                self._note(
                    f"{step.func_name}: UTF-8 以外の文字コードで送られたフォーム本文は、各フィールドの値から URL エンコードして"
                    f"組み直します（取得した値は差し替え、{_field_list(kept)} は記録時のバイト列のまま）"
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
                if ext.sample is not None and (ext.kind == "cookie" or is_dynamic_looking(str(ext.sample)) or ext.renewed
                                               or (len(str(ext.sample)) > 6 and not _spelled_as_words(str(ext.sample)))):
                    # a session id / token (also a key of letters that are no words): only its length
                    # (it is renewed on every run anyway)
                    note += f"（記録時は {len(str(ext.sample))} 文字）"
                elif ext.sample is not None:
                    note += f"（記録時の値: {_lit(truncate(str(ext.sample), _SAMPLE_LEN))}）"
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
            # the cookie of that name the jar sends to its scope URL (RFC 6265), never a lookup by name only
            args = ["session", _lit(ext.name), self._scope(ext.cookie_url) if ext.cookie_url else "resp.url"]
            if ext.cookie_path:
                args.append(f"path={self._scope(ext.cookie_path)}")
            if ext.cookie_domain:
                args.append(f"domain={_lit(ext.cookie_domain)}")
            return f"_cookie({', '.join(args)})", f"Cookie {_lit(ext.name)} の値（domain / path で選んだもの）"
        if kind == "header":
            if ext.name is None:
                return self._todo(ext, fname, "ヘッダー名がありません")
            source = "resp" if ext.hop is None else f"_hop(resp, {int(ext.hop)})"
            where = f"リダイレクト中の {int(ext.hop) + 1} 番目の応答の" if ext.hop is not None else ""
            expr = f"_need({source}.headers.get({_lit(ext.name)}), {_lit(f'{fname} の{where}レスポンスヘッダー {ext.name}')})"
            desc = f"{where}レスポンスヘッダー {_lit(ext.name)}"
            if pattern:
                expr = f"_regex({expr}, {_lit(pattern)})"
                desc += " から正規表現で抽出"
            return expr, desc
        if kind == "json":
            if ext.path is None:
                return self._todo(ext, fname, "JSON パスがありません")
            path_src = "[" + ", ".join(_num_lit(p) if isinstance(p, int) and not isinstance(p, bool) else _lit(p) for p in ext.path) + "]"
            row = ext.row
            if (ext.row_key and isinstance(row, int) and not isinstance(row, bool) and 0 <= row < len(ext.path)
                    and isinstance(ext.path[row], int)):
                return self._json_row_expr(ext, row, fname)
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

    def _json_row_expr(self, ext: Extractor, row: int, fname: str) -> tuple[str, str]:
        """``_json_row(data, <list>, <key in the row>, <value>, <leaf in the row>)`` for a row of a JSON list
        the user chose (``Extractor.row``): the row is found by its label, compared with the constant the
        plan names (an 入力値) or else with the recorded value."""
        def src(path: Sequence[Any]) -> str:
            return "[" + ", ".join(_num_lit(p) if isinstance(p, int) and not isinstance(p, bool) else _lit(p) for p in path) + "]"
        rows, key, leaf = list(ext.path or [])[:row], list(ext.row_key or []), list(ext.path or [])[row + 1:]
        if ext.row_ref is not None and _check_identifier(ext.row_ref, "JSON row constant") in self.constant_names:
            wanted, who = ext.row_ref, f"{'入力値' if ext.row_ref in self.input_names else '定数'} {ext.row_ref} "
        elif ext.row_value is not None:
            wanted, who = _lit(ext.row_value), "記録時の値"
        else:
            return self._todo(ext, fname, "一覧の行を見分ける値がありません")
        desc = (f"レスポンス JSON の一覧 {_comment_text(_dotted(rows))} で {_comment_text(_dotted(key))} が{who}と同じ行の "
                f"{_comment_text(_dotted(leaf))}")
        return f"_json_row(data, {src(rows)}, {src(key)}, {wanted}, {src(leaf)})", desc

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
            if steps:
                w.line(f'_STEP["total"] = {len(steps)}')
            if "_cookies_in_order" in self.helpers_needed:
                self._c("同じ名前の Cookie を、ブラウザと同じく受け取った順に送る（古い Python は domain の名前順に並べ替える）")
                w.line("_cookies_in_order()")
            if "_Session" in self.helpers_needed:
                self._c("Cookie の送り先をブラウザと同じにする（Domain 属性なしの Cookie はそのホストにだけ送る）")
                w.line("session = _Session()")
            else:
                w.line("session = requests.Session()")
            if "_windows_certificates" in self.helpers_needed:
                self._c("https のサイトの証明書を、Windows に入っている証明書でも確かめる（Edge と同じく、組織の認証局の証明書も信頼する）")
                w.line("_windows_certificates(session)")
            if "_cookie_attr_hook" in self.helpers_needed:
                self._c("ブラウザが無視する Cookie の属性（空の Domain、数字でない Max-Age など）を外して受け取る")
                w.line('session.hooks["response"].append(_cookie_attr_hook)')
                self._c("そのような属性を requests が先に読んだときの Python の内部警告（http.cookiejar bug!）は表示しない"
                        "（Cookie は上のフックで正しく受け取る）")
                w.line('warnings.filterwarnings("ignore", message="http.cookiejar bug!")')
            if "_host_cookie_hook" in self.helpers_needed:
                self._c("Domain=そのホスト の Cookie を、ブラウザと同じく Domain なしの Cookie と同じものとして扱う")
                if getattr(self.plan, "repeated_cookie_hosts", None):
                    self._c("1 つの応答が設定してすぐ消した Cookie は、ブラウザと同じく消えたままにする")
                w.line('session.hooks["response"].append(_host_cookie_hook)')
            if "_ie_cookie_hook" in self.helpers_needed:
                self._c("Cookie を IE（記録したブラウザ）と同じ Path / Domain で受け取る")
                if getattr(self.plan, "repeated_cookie_hosts", None):
                    self._c("1 つの応答が設定してすぐ消した Cookie は、IE と同じく消えたままにする")
                w.line('session.hooks["response"].append(functools.partial(_ie_cookie_hook, jar=session.cookies))')
            self._emit_session_auth()
            w.line("session.headers.update(BASE_HEADERS)")
            w.line("for c in INITIAL_COOKIES:")
            with w.indent():
                if self.plan.initial_cookies:
                    w.line("_set_cookie(session, c['url'], c['name'], c['value'], path=c['path'], domain=c.get('domain'))")
                else:
                    w.line("session.cookies.set(c['name'], c['value'], domain=c['domain'], path=c['path'])")
            w.line("ctx = {}")
            if not steps:
                w.line('print("記録に再現できるリクエストがありませんでした", file=sys.stderr)')
                w.line("return ctx")
                return
            sleep = (self.opts.delay or 0) > 0
            total = len(steps)
            for i, (step, fname) in enumerate(zip(steps, self.func_names)):
                last = i == len(steps) - 1
                w.blank()
                self._emit_main_step(
                    step, fname,
                    sleep=sleep and (not last or step.loop is not None),
                    final=self.opts.print_final and step is self.final_step,
                    progress=(i + 1, total),
                )
            w.blank()
            w.line(f'print("[完了] すべての手順が終わりました（{total} 手順）", file=sys.stderr, flush=True)')
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
                         "Windows: 今ログインしているユーザーで認証（python -m pip install requests_negotiate_sspi）")
                w.line("session.auth = HttpNegotiateAuth()")
            w.line("except ImportError:")
            with w.indent():
                w.line("try:")
                with w.indent():
                    self._cl("from requests_ntlm import HttpNtlmAuth",
                             "他の OS / 別ユーザーで認証する場合（python -m pip install requests_ntlm）")
                w.line("except ImportError:")
                with w.indent():
                    w.line("raise SystemExit(")
                    with w.indent():
                        # the GUI's ERROR_HINTS recognise this message by its first sentence
                        w.line(_lit("統合 Windows 認証には追加パッケージが必要です: "
                                    "python -m pip install requests_negotiate_sspi（今ログインしているユーザーで認証） または "
                                    "python -m pip install requests_ntlm（他の OS / 別のユーザー。"
                                    "環境変数 REQREC_NTLM_USER / REQREC_NTLM_PASSWORD も設定）"))
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

    def _step_desc(self, step: Step) -> str:
        """``GET http://h/app/{jsessionid}/list -> 200 text/html``: the step's URL as the script builds it
        (dynamic pieces as ``{var}``, never a recorded session value) and the recorded response."""
        desc = f"{str(step.method).upper()} {self._url_display(step.url)}"
        comment = str(step.comment or "")
        if " -> " in comment:
            desc += " -> " + comment.split(" -> ", 1)[1]
        return desc

    def _emit_main_step(self, step: Step, fname: str, *, sleep: bool, final: bool = False,
                        progress: tuple[int, int] = (0, 0)) -> None:
        w = self.w
        desc = self._step_desc(step)
        no, total = progress
        label = self._progress_label(step)
        if step.loop is None:
            self._c(f"ステップ {step.index}: {desc}")
            w.line(f"_step_start({no}, {total}, {_lit(label)}, session, ctx)")
            w.block(self._call(step, fname))
            w.line("ctx.update(out)")
            if final:
                self._cl("final_resp = resp", "このステップの結果を最後に表示する")
            # a file is saved right after its own request, so a later failing step cannot lose it, and
            # before _step_ok, so a file that cannot be saved is this step's "[n/N] ERROR"
            self._emit_save(step, target="final_saved = " if final and self._final_needs_saved(step) else "")
            w.line("_step_ok(resp, session)")
            if sleep:
                w.line("time.sleep(DELAY)")
            return
        loop = step.loop
        var = _check_identifier(loop.var, "loop variable")
        iterable = self._loop_iterable(loop)
        shown = f"str({var})"
        if any(isinstance(v, (bytes, bytearray)) for v in loop.values or []):
            # recorded legacy-charset bytes (the charset was unknown): the progress line shows their text
            shown = f"{var}.decode({_lit(_bytes_display_charset(loop.values))}, 'replace')"
        self._c(f"ステップ {step.index}: {desc}")
        if loop.note and str(loop.note) not in desc:
            self._c(f"繰り返し: {loop.note}")
        w.line("results = []")
        if iterable == "[]":
            w.line("out = {}")
        w.line(f"for {var} in {iterable}:")
        with w.indent():
            w.line(f"_step_start({no}, {total}, {_lit(label + ' ' + var + '=')} + {shown}, session, ctx)")
            w.block(self._call(step, fname))
            if step.response_kind == "binary":
                self._cl("results.append(_save_download(resp))", "ファイルを保存し、保存先のパスを結果に入れる")
            else:
                self._emit_save(step)
                w.line("results.append(" + ("resp.json()" if step.response_kind == "json" else "_text(resp)") + ")")
            w.line("_step_ok(resp, session)")
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
        # never the response's URL: it can hold the session id / tokens of this run (R9); the step's label
        # names dynamic parts as {var}, like the "[n/N] OK" line
        done = _lit(self._progress_label(step))
        w.line("if not final_saved:")
        with w.indent():
            if kind == "html":
                w.line("soup = _soup(final_resp)")
                self._c("タイトルが無い画面は、ステータスと手順を表示する（URL にはセッション ID が入ることがあるので表示しない）")
                w.line(f'print(soup.title.get_text(strip=True) if soup.title else "{{}} {{}}".format(final_resp.status_code, {done}))')
                self._c("TODO: 必要なデータを soup から取り出してください（例: soup.select('table tr')）")
            else:  # empty
                self._c("ステータスと手順を表示する（URL にはセッション ID が入ることがあるので表示しない）")
                w.line(f"print(final_resp.status_code, {done})")


# =========================================================================== module-level helpers

#: ``;name=value`` path parameter values in a progress label (the recorded value is not shown).
_PATH_PARAM_VALUE_RE = re.compile(r"(;[^/;=]+=)(?!\{)[^/;]*")

#: Emitted verbatim into every script: the progress / debug / masking helpers (DESIGN.md §14.4).  Our
#: own text, no recorded content; no ``#`` comments (``GenOptions(comments=False)`` yields comment-free
#: code); Python 3.8 syntax (``str.format``).
_PROGRESS_HELPERS_SRC = r'''
_STEP = {"no": 0, "total": 0, "label": "", "ok": True, "jar": None, "session": None, "ctx": None, "issued": set()}


def _mask_values(text):
    """この実行で受け取った Cookie の値、リダイレクト先の URL で渡された値（_note_issued）と、手順で取り出した値
    （6 文字以上）を *** にする（形では見分けられない値も隠すため）。"""
    values = set(_STEP.get("issued") or ())
    for value in (_STEP.get("ctx") or {}).values():
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            values.add(str(value).strip())
    session = _STEP.get("session")
    for cookie in getattr(session, "cookies", None) or []:
        values.add((cookie.value or "").strip().strip('"'))
    text = str(text)
    for value in sorted(values, key=len, reverse=True):
        if len(value) >= 6:
            text = text.replace(value, "***")
    return text


_SPELLING = {
    "starts": "bl br ch chr cl cr dr dw fl fr gh gl gn gr kl kn kr ph phr pl pr ps sc sch scr sh shr sk sl sm sn sp sph "
              "spl spr sq st str sw th thr tr ts tw wh wr",
    "ends": "bt ch ck ct dd dg dth ff fth ft gg gh ght ghth gn lb ld lf lfth lk ll lm ln lp lt lth lv mb mn mp mph mpt mt "
            "nc nch nct nd ng ngth nk nst nt nth nx nz ph pp pt pth rb rc rch rd rf rg rk rl rld rm rn rp rr rsh rst rt "
            "rth rv sc sch sh sk sp ss st tch th thm tt tz wd wl wn xt xth zz",
    "last": "cd db dd dt fg hh js kb mm ms nm pc qr ss st tm ts wk",
    "acronyms": "asp cgi cms crm csrf csv dll docx erp ftp html http jsp json jwt kbn ldap mnt mst ntlm pdf php saml smtp "
                "sql txt xls xml xsrf",
}


def _misspelled(word):
    """英字だけの語が、英語やローマ字のつづりにならないか（NIPAHCRBADWX、QZVBNMWRTPXK のような値）。

    語の中の子音の並びは「音節の終わり（_SPELLING の ends。1 文字でもよい）+ 次の音節の始まり（starts。1 文字でもよい）」、
    語の終わりの子音の並びは音節の終わり（ends、その複数形、last）になるのが英語やローマ字のつづり（pass|word、kan|ri）。
    そうならないものと、u の付かない q があるものを値とみなす。語の始まりの子音と、名前によく使う略語（acronyms。
    SEISANKANRICSV の CSV）の文字は判定しない。
    """
    starts, ends, last, acronyms = (set(_SPELLING[k].split()) for k in ("starts", "ends", "last", "acronyms"))
    ends |= {c + "s" for c in ends | set("bcdfgklmnprtvw") if not c.endswith(("s", "sh", "ch", "x", "z"))}
    word = word.lower()
    letters = list(word)
    for acronym in acronyms:
        for m in re.finditer("(?={})".format(acronym), word):
            letters[m.start():m.start() + len(acronym)] = "a" * len(acronym)
    word = "".join(letters)
    if re.search(r"q(?!u)", word[2:] if word[:2] in ("qa", "qc", "qr") else word):
        return True
    for m in re.finditer(r"(?<=[aeiouy])[^aeiouy]{2,}", word):
        run = m.group(0)
        if m.end() == len(word):
            if run not in ends and run not in last:
                return True
        elif not any((i == 0 or (i == 1 and run[0] not in "jz") or run[:i] in ends)
                     and (len(run) - i <= 1 or run[i:] in starts) for i in range(len(run) + 1)):
            return True
    return False


def _looks_random(word):
    """英字だけの文字列（- と _ で区切ってもよい）が、単語の並び（CustomerMaintenance、kensaku、TOPMENU、MyPage）ではなく
    値に見えるか。

    単語に見えるのは、小文字だけ・大文字だけ（16 文字未満）・CamelCase のどれかで、母音（aeiouy）が 4 分の 1 以上あり、
    子音が 5 文字以上続かないもの。大文字と小文字が不規則に混ざるもの（QviGcsvYKmnn）は値とみなす。小文字だけ・大文字
    だけで 12 文字以上のものは、区切りごとのつづりも見る（_misspelled。NIPAHCRBADWX は値、SEISANKANRICSV は単語）。
    """
    letters = re.sub(r"[_-]", "", word)
    low = letters.lower()
    regular = (letters.islower() or (letters.isupper() and len(letters) < 16)
               or re.fullmatch(r"[A-Z]?[a-z]+(?:[A-Z][a-z]{2,})*", letters))
    vowels = sum(1 for c in low if c in "aeiouy")
    cluster = max([len(r) for r in re.findall(r"[^aeiouy]+", low)] or [0])
    if not (regular and vowels * 4 >= len(low) and cluster < 5):
        return True
    return bool((letters.islower() or letters.isupper()) and len(letters) >= 12
                and any(_misspelled(p) for p in re.split(r"[_-]+", word) if len(p) >= 4))


def _mask_url(url):
    """表示用の URL: クエリと ;パラメーター の値、セッション ID らしいパス、ユーザー名とパスワード、
    この実行の Cookie の値、リダイレクト先で渡された値と取り出した値を *** にする。

    セッション ID らしいパスは 16 文字以上で、英字と数字が混ざるもの、または英字だけで単語の並びに見えないもの
    （_looks_random。例: QZVBNMWRTYPXSDFKHJ。CustomerMaintenance や juchukanrimenu はそのまま）。
    """
    text = re.sub(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/?#@]*@", r"\1***@", _mask_values(url or "")).split("#", 1)[0]
    path, sep, query = text.partition("?")
    origin = ""
    m = re.match(r"[A-Za-z][A-Za-z0-9+.-]*://[^/]*", path)
    if m:
        origin, path = m.group(0), path[m.end():]
    path = re.sub(r"(;[^/;=]*=)[^/;]+", r"\1***", path)
    path = re.sub(r"(?<=/)(?=[^/;.]*\d)(?=[^/;.]*[A-Za-z])[^/;.]{16,}(?=[/;]|$)", "***", path)
    path = re.sub(r"(?<=/)[A-Za-z]{16,}(?=[/;]|$)", lambda w: "***" if _looks_random(w.group(0)) else w.group(0), path)
    if sep:
        query = re.sub(r"(^|[&;])([^&;=]*=)?([^&;]*)",
                       lambda q: q.group(1) + (q.group(2) or "") + ("***" if q.group(3) else ""), query)
    return origin + path + sep + query


def _mask_text(text):
    """エラーメッセージを 1 行にし、この実行の値（_mask_values）と URL の中の値を _mask_url と同じように伏せ字にする。

    URL を囲む引用符やかっこはそのまま残す。
    """
    words = []
    for word in _mask_values(text).split():
        if "/" in word or "?" in word:
            m = re.match(r"([\"'(<\[]*)(.*?)([\"')>\],.:]*)$", word)
            word = m.group(1) + _mask_url(m.group(2)) + m.group(3)
        words.append(word)
    return " ".join(words)


def _note_issued(resp, *args, **kwargs):
    """応答の Location（リダイレクト先）にあって、リクエストの URL には無かった値（パスに入ったセッション ID など）を、
    表示で隠す値として覚える（session の response フック。_step_start が付ける）。

    requests はリダイレクト先へ進む前にこれを呼ぶので、その手順の警告やエラー（リダイレクト先に接続できなかったときも）に
    値は出ない。対象はパスの部分と「名前=値」の値で、6 文字以上で、数字を含むもの（menu01.do、JU0101_01.aspx のような
    画面のファイル名は除く）か、英字（と - _）だけで単語の並びに見えないもの（_looks_random。MainMenu や results はそのまま）。
    記録したときにこの手順のリダイレクトが値を渡した場所（ISSUED_PLACES）にある値は、つづりに関係なく覚える。
    """
    sent = str(getattr(getattr(resp, "request", None), "url", "") or "")
    location = re.sub(r"^([A-Za-z][A-Za-z0-9+.-]*:)?//[^/?#]*", "", resp.headers.get("Location") or "")
    for piece in re.split(r"[/;?&#]", location):
        part = piece.split("=", 1)[-1]
        if len(part) < 6 or part in sent:
            continue
        file_name = re.fullmatch(r"[A-Za-z][A-Za-z_-]*\d{0,4}(?:[_-]\d{1,4})?\.[A-Za-z][A-Za-z0-9]{0,4}", part)
        letters = re.sub(r"[_-]", "", part)
        if ((re.search(r"\d", part) and not file_name)
                or (re.fullmatch(r"[A-Za-z]{6,}", letters) and _looks_random(part))):
            _STEP["issued"].add(part)
    path, _, query = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*", "", urljoin(sent, location).split("#")[0]).partition("?")
    segments = path.split("/")[1:]
    for no, kind, where in ISSUED_PLACES if location else ():
        if no != _STEP["no"]:
            continue
        if kind == "path":
            found = [segments[where - 1].split(";")[0]] if 0 < where <= len(segments) else []
        elif kind == "path_param":
            found = [p.partition("=")[2] for s in segments for p in s.split(";")[1:] if p.partition("=")[0] == where]
        else:
            found = [p.partition("=")[2] for p in query.split("&") if unquote(p.partition("=")[0].replace("+", " ")) == where]
        for value in found:
            if value and value not in sent:
                _STEP["issued"].add(value)
    return resp


def _debug(text):
    """DEBUG のときだけ、手順の番号を付けて標準エラー出力に表示する（値そのものは表示しない。Cookie の path などに
    入った、この実行で受け取った値や取り出した値も _mask_values で *** にする）。"""
    if DEBUG:
        print("[{}/{}]   {}".format(_STEP["no"], _STEP["total"], " ".join(_mask_values(str(text)).split())), file=sys.stderr, flush=True)


def _cookie_keys(session):
    """session の Cookie を (名前, domain, path) ごとに。値は変化を調べるためだけに使い、表示しない。"""
    return {(c.name, c.domain, c.path): c.value for c in session.cookies}


def _step_start(no, total, label, session=None, ctx=None):
    """手順を始める前に呼ぶ（失敗したときに、どの手順で止まったかを表示するため）。

    session と ctx は、表示するメッセージから Cookie の値や取り出した値を隠すために覚えておく（_mask_values）。
    session には、リダイレクト先で渡された値を覚える _note_issued を一度だけ付ける。
    DEBUG のときは、この手順が送る動的な値の取得元と種類を DEPENDENCIES から表示する（値そのものは表示しない）。
    """
    _STEP.update(no=no, total=total, label=label, ok=False, session=session, ctx=ctx)
    hooks = (getattr(session, "hooks", None) or {}).get("response")
    if isinstance(hooks, list) and _note_issued not in hooks:
        hooks.append(_note_issued)
    if not DEBUG:
        return
    for step, place, name, kind, source, var in DEPENDENCIES:
        if step == no:
            size = ""
            if ctx is not None and var in ctx and kind in ("C", "D") and ctx[var] is not None:
                size = "（長さ {}）".format(len(str(ctx[var])))
            _debug("{} {}  [{}] {}{}".format(place, name, kind, source, size))
    if session is not None:
        _STEP["jar"] = _cookie_keys(session)


def _step_ok(resp, session=None):
    """手順が成功したら「[2/9] OK ...」と表示する。HTML なら、受け取った画面のタイトルも出す。

    DEBUG のときは、この手順で受け取った Cookie（新規 / 値の変更 / 削除と domain・path。値は表示しない）と、
    記録時にこの手順で起きたセッション切替が今回も起きたかを表示する。
    """
    _STEP["ok"] = True
    title = ""
    if "html" in resp.headers.get("Content-Type", "").lower():
        m = re.search(r"<title[^>]*>(.*?)</title>", _text(resp), re.I | re.S)
        if m and m.group(1).strip():
            title = "  「{}」".format(" ".join(m.group(1).split())[:60])
    line = "[{}/{}] OK  {} ({}){}".format(_STEP["no"], _STEP["total"], _STEP["label"], resp.status_code, title)
    print(line, file=sys.stderr, flush=True)
    if not DEBUG or session is None or _STEP.get("jar") is None:
        return
    before, after = _STEP["jar"], _cookie_keys(session)
    for key in after:
        if key in before and before[key] == after[key]:
            continue
        what = "新規" if key not in before else "値が変わりました"
        _debug("Cookie 受信 {}（domain={}, path={}）{}".format(key[0], key[1], key[2], what))
    for key in before:
        if key not in after:
            _debug("Cookie 削除 {}（domain={}, path={}）".format(key[0], key[1], key[2]))
    for no, name in SESSION_SWITCHES:
        if no == _STEP["no"]:
            changed = any(k[0] == name and before.get(k) != v for k, v in after.items())
            _debug("記録時はこの手順で Cookie {} が切り替わりました（今回: {}）".format(name, "切り替わりました" if changed else "変化なし"))
'''

#: Emitted when the plan needs them: ``(helper name, source)`` in emission order.
_COOKIE_HELPERS_SRC: tuple[tuple[str, str], ...] = (
    ("_cookie", r'''
def _cookie(source, name, url, path=None, domain=None):
    """Cookie name の値を返す（Cookie は名前だけでなく domain と path で区別する: RFC 6265）。

    url へのリクエストで送られる Cookie（domain / path / Secure / 有効期限で選ばれたもの）の中から name のものを
    選ぶ。同じ名前の Cookie が複数あるとき（ポータルと業務画面がそれぞれ発行した場合など）は、記録時と同じ
    path・domain のもの、無ければ path が最も長いもの。source は session か、リダイレクト途中の応答（_hop）。
    見つからなければ、値ではなく名前と送り先を示して止める。
    """
    jar = getattr(source, "cookies", source)
    request = requests.Request("GET", url).prepare()
    sent = (requests.cookies.get_cookie_header(jar, request) or "").split("; ")
    found = [c for c in jar if c.name == name and "{}={}".format(c.name, c.value) in sent]
    if not found:
        raise RuntimeError(
            "Cookie {} が見つかりません（送り先 {}、記録時 domain={} path={}）。ログインに失敗したか、"
            "セッションが切れている可能性があります".format(name, _mask_url(url), domain or "-", path or "/")
        )
    found.sort(key=lambda c: len(c.path or ""), reverse=True)
    wanted = (domain or "").lstrip(".").lower()
    exact = [
        c for c in found
        if (path is None or c.path == path)
        and (not wanted or (c.domain or "").lstrip(".").lower() in (wanted, wanted + ".local"))
    ]
    chosen = (exact or found)[0]
    _debug("Cookie {} を送り先 {} に合わせて選択: domain={} path={}（同じ名前 {} 件、長さ {}）".format(
        name, _mask_url(url), chosen.domain, chosen.path, len(found), len(chosen.value or "")))
    return chosen.value
'''),
    ("_set_cookie", r'''
def _set_cookie(session, url, name, value, path=None, domain=None):
    """Cookie を、url のサーバーが Set-Cookie で送ってきたのと同じ扱いで session に入れる。

    画面のスクリプトが設定した Cookie や、記録前からあった Cookie を再現するときに使う。domain を指定しなければ
    url のホストだけに送られる Cookie になる（http://kanri/ のようなドットの無いホスト名でも送られる）。
    日本語などの値は、ブラウザと同じように UTF-8 のバイト列として送る。
    """
    value = "" if value is None else str(value)
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        value = value.encode("utf-8").decode("latin-1")
    line = "{}={}".format(name, value)
    if path:
        line += "; Path=" + path
    if domain:
        line += "; Domain=" + domain
    headers = email.message.Message()
    headers["Set-Cookie"] = line
    request = requests.Request("GET", url).prepare()
    session.cookies.extract_cookies(requests.cookies.MockResponse(headers), requests.cookies.MockRequest(request))
    _debug("Cookie {} を設定: {}（path={}{}）".format(name, _mask_url(url), path or "/", ", domain=" + domain if domain else ""))
'''),
    ("_need", r'''
def _need(value, what):
    """取り出した値が無い（None）ときに、何が無かったかを示して止める（後の手順で分かりにくく失敗しないように）。"""
    if value is None:
        raise RuntimeError("{} が見つかりません。記録したときと画面の流れが違う可能性があります".format(what))
    return value
'''),
    ("_hop", r'''
def _hop(resp, index):
    """リダイレクトの途中の応答（最初の応答が 0 番目）を返す。"""
    chain = list(resp.history) + [resp]
    if index >= len(chain):
        raise RuntimeError("リダイレクトの {} 番目の応答がありません（今回の応答は {} 個）。記録したときと画面の流れが違う可能性があります"
                           .format(index + 1, len(chain)))
    return chain[index]
'''),
    ("_host_cookie_hook", r'''
def _host_cookie_hook(resp, *args, **kwargs):
    """「Domain なし」と「Domain=そのホスト」の同じ名前・path の Cookie を、ブラウザと同じく 1 つにして受け取る。

    ブラウザはこの 2 つを同じ Cookie として扱い置き換えるが、Python は別の Cookie として両方を持ち、両方を送って
    しまうため（古い値が先に送られる、ログアウトで消えない）、受け取ったのと違う方を消す（値は変えない）。1 つの
    応答に同じ Cookie が何度もあれば、ブラウザと同じく最後のものにする。http://kanri/ のようなドットの無い
    ホスト名の Domain は外す（外さないと Python が送り返さない）。
    """
    original = getattr(getattr(resp, "raw", None), "_original_response", None)
    msg = getattr(original, "msg", None)
    url = urlsplit(resp.url)
    host = (url.hostname or "").lower()
    if msg is None or not host:
        return resp
    pattern = r";\s*domain\s*=\s*\.?" + re.escape(host) + r"\.?\s*(?=;|$)"
    default_path = url.path[:url.path.rfind("/")] or "/"
    lines = msg.get_all("Set-Cookie") or []
    last = {}
    for line in lines:
        own = re.search(pattern, line, flags=re.I) is not None
        if "." not in host:
            line = re.sub(pattern, "", line, flags=re.I)
        path = re.search(r";\s*path\s*=([^;]*)", line, flags=re.I)
        domain = re.search(r";\s*domain\s*=([^;]*)", line, flags=re.I)
        name = line.split(";", 1)[0].split("=", 1)[0].strip()
        key = (name, path.group(1).strip() if path else default_path, "" if own or not domain else domain.group(1).strip().lstrip(".").lower())
        last[key] = (line, own, path is not None)
    fixed = []
    for (name, path, domain), (line, own, explicit) in last.items():
        if "." in host and not domain:
            fixed.append(name + "=" + ("" if own else "; Domain=" + host) + ("; Path=" + path if explicit else "") + "; Max-Age=0")
        fixed.append(line)
    if fixed != lines:
        del msg["Set-Cookie"]
        for line in fixed:
            msg["Set-Cookie"] = line
    return resp
'''),
    ("_cookie_attr_hook", r'''
def _cookie_attr_hook(resp, *args, **kwargs):
    """Set-Cookie から、ブラウザが無視する属性（空の Domain、整数でない Max-Age、/ で始まらない Path）を外して受け取る。

    ブラウザはその属性だけを無視して Cookie を受け取るが、Python は Cookie ごと捨てたり、送らない場所に置いたり
    するため（ログインの Cookie が送られない）。
    """
    original = getattr(getattr(resp, "raw", None), "_original_response", None)
    msg = getattr(original, "msg", None)
    if msg is None:
        return resp
    lines = msg.get_all("Set-Cookie") or []
    pattern = (r";\s*(?:domain\s*(?:=[\s.]*)?|max-age\s*(?:=(?!\s*-?\d+\s*(?:;|$))[^;]*)?"
               r"|path\s*(?:=\s*[^\s;/][^;]*)?)(?=;|$)")
    fixed = [re.sub(pattern, "", line, flags=re.I) for line in lines]
    if fixed != lines:
        del msg["Set-Cookie"]
        for line in fixed:
            msg["Set-Cookie"] = line
    return resp
'''),
    ("_ie_cookie_hook", r'''
def _ie_cookie_hook(resp, *args, jar=None, **kwargs):
    """Set-Cookie を、記録したブラウザ（IE モード）と同じ Cookie になるように直してから受け取る（値は変えない）。

    IE は Path のない Cookie をページのフォルダー（末尾の / まで）に置くが、Python は末尾の / を付けないため、同じ
    Cookie が 2 つになってしまう（古い値が先に送られる）。IE と同じ Path を付ける。また IE は「Domain なし」と
    「Domain=そのホスト」を同じ Cookie として扱うので、受け取ったのと違う方を消す（ログアウトで消えるように）。
    サブドメインからの「Domain=親のホスト」も、IE では親のホストの「Domain なし」の Cookie と同じものなので、
    jar（session.cookies）とこのリクエストの Cookie から親のホストの方を消す（リダイレクトの次のリクエストにも残らない）。
    1 つの応答に同じ Cookie が何度もあれば、IE と同じく最後のものにする。
    """
    original = getattr(getattr(resp, "raw", None), "_original_response", None)
    msg = getattr(original, "msg", None)
    url = urlsplit(resp.url)
    host = (url.hostname or "").lower()
    if msg is None or not host:
        return resp
    folder = url.path[:url.path.rfind("/") + 1] or "/"
    pattern = r";\s*domain\s*=\s*\.?" + re.escape(host) + r"\.?\s*(?=;|$)"
    lines = msg.get_all("Set-Cookie") or []
    last = {}
    for line in lines:
        line = re.sub(r";\s*path\s*(?:=(?!\s*/)[^;]*)?(?=;|$)", "", line, flags=re.I)
        if ";" not in folder and not re.search(r";\s*path\s*=", line, flags=re.I):
            line += "; Path=" + folder
        own = "." in host and re.search(pattern, line, flags=re.I) is not None
        path = re.search(r";\s*path\s*=([^;]*)", line, flags=re.I)
        domain = re.search(r";\s*domain\s*=([^;]*)", line, flags=re.I)
        name = line.split(";", 1)[0].split("=", 1)[0].strip()
        key = (name, path.group(1).strip() if path else folder, "" if own or not domain else domain.group(1).strip().lstrip(".").lower())
        last[key] = (line, own, path is not None)
    fixed = []
    for (name, path, domain), (line, own, explicit) in last.items():
        if "." in host and not domain:
            fixed.append(name + "=" + ("" if own else "; Domain=" + host) + ("; Path=" + path if explicit else "") + "; Max-Age=0")
        elif "." in domain and host.endswith("." + domain):
            for cookies in (jar, getattr(getattr(resp, "request", None), "_cookies", None)):
                try:
                    cookies.clear(domain, path, name)
                except (AttributeError, KeyError):
                    pass
        fixed.append(line)
    if fixed != lines:
        del msg["Set-Cookie"]
        for line in fixed:
            msg["Set-Cookie"] = line
    return resp
'''),
    ("_Session", r'''
class _Session(requests.Session):
    """ブラウザ（Chrome / Edge）と同じ送り先で Cookie を送る requests.Session（リダイレクトの途中も同じ）。

    Domain 属性なしで受け取った Cookie は、そのホストにだけ送る。Python の既定はサブドメインにも送るため、親の
    ホスト（ポータルなど）とサブドメイン（業務画面など）が同じ名前の Cookie を発行すると、両方が送られてしまう
    （違う値が先に送られる）。requests がリクエストごとに作る jar にも同じ規則を使う。
    """

    def __init__(self):
        super().__init__()
        self.cookies.set_policy(self._policy())

    @staticmethod
    def _policy():
        policy = http.cookiejar.DefaultCookiePolicy
        return policy(strict_ns_domain=policy.DomainStrictNonDomain)

    def prepare_request(self, request):
        prepared = super().prepare_request(request)
        jar = requests.cookies.RequestsCookieJar(self._policy())
        jar.update(prepared._cookies)
        prepared.headers.pop("Cookie", None)
        prepared.prepare_cookies(jar)
        return prepared
'''),
    ("_cookies_in_order", r'''
def _cookies_in_order():
    """同じ名前の Cookie を、ブラウザと同じく受け取った順に送るようにする（新しい Python と同じ並べ方にする）。

    古い Python（3.8 / 3.9 など）の http.cookiejar は Cookie を domain の名前順に並べ替えるため、ポータルと業務画面が
    同じ名前の Cookie を発行すると、送る順がブラウザと変わり、サーバーが別の方を読んでしまう（リダイレクトの途中も
    同じ）。並べ替える Python のときだけ、受け取った順に並べるようにする。
    """
    def in_order(mapping):
        for obj in list(mapping.values()):
            if hasattr(obj, "items"):
                yield from in_order(obj)
            else:
                yield obj

    if list(http.cookiejar.deepvalues({"b": 1, "a": 2})) != [1, 2]:
        http.cookiejar.deepvalues = in_order
'''),
)

#: Emitted verbatim (top level) whenever the plan has steps: the DESIGN.md §13.13 download rule.
#:
#: * ``_is_attachment``: ``Content-Disposition`` (stripped, lower-cased) starts with ``attachment``,
#:   or contains ``filename`` and does not start with ``inline`` (``inline; filename=f.txt`` is
#:   Spring's RFD protection on every JSON response, not a download).  ``core.is_attachment_disposition``
#:   is the same rule for the GUI.
#: * ``_download_name``: RFC 6266 ``filename*=``, RFC 2047 encoded words (``=?UTF-8?B?...?=`` from
#:   .NET), IE-style percent-encoded UTF-8, or raw UTF-8 / Shift_JIS bytes that http.client decoded
#:   as Latin-1; else the URL's last segment without its ``;params`` (``report.xls;jsessionid=...`` ->
#:   ``report.xls``: no session id in the name); else ``output`` + an extension from the MIME type.
#:   ``_safe_file_name`` removes path parts and characters Windows forbids, prefixes reserved device
#:   names (``CON``, ``NUL``, ``COM1`` ... with any extension) with ``_`` and shortens names longer
#:   than 150 characters keeping the extension.  ``core.download_filename`` mirrors it.
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
    """保存するファイル名: Content-Disposition のファイル名 → URL の末尾（;jsessionid=... などは除く） → output + 拡張子。

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
        last = _unquote(urlsplit(resp.url).path.rsplit("/", 1)[-1].split(";", 1)[0], "utf-8")
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


def _steps_text(numbers: Iterable[int]) -> str:
    """``[1, 2, 3, 5]`` -> ``"1〜3, 5"`` (step numbers for comments)."""
    nums = sorted({int(n) for n in numbers})
    parts: list[str] = []
    i = 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        parts.append(f"{nums[i]}〜{nums[j]}" if j > i + 1 else (f"{nums[i]}, {nums[j]}" if j == i + 1 else str(nums[i])))
        i = j + 1
    return ", ".join(parts)


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
    """The value of a ``Ref.expr`` that is a plain ``bytes`` literal (build_plan emits recorded
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
            return _comment_text(f"{enc} で「{truncate(text, 40)}」（記録時の表記: {truncate(spelled, 60)}）")
    return _comment_text(f"記録時の表記: {truncate(spelled, 60)}")


def _bytes_display_charset(values: Sequence[Any]) -> str:
    """The charset (cp932 / EUC-JP) that decodes every recorded legacy-charset value, for display only."""
    for enc in ("cp932", "euc_jp"):
        try:
            for value in values:
                if isinstance(value, (bytes, bytearray)):
                    bytes(value).decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "cp932"


def _helpers_for_extractor(ext: Extractor) -> set[str]:
    kind = ext.kind
    need: set[str] = set()
    if kind in ("html_input", "html_meta", "html_attr"):
        need |= {"_soup", "_attr"}
    elif kind == "html_text":
        need |= {"_soup", "_elem_text"}
    elif kind == "json":
        need.add("_json_path")
        if getattr(ext, "row_key", None):
            need.add("_json_row")
    elif kind == "cookie":
        need.add("_cookie")
    elif kind == "header":
        need.add("_need")
        if getattr(ext, "hop", None) is not None:
            need.add("_hop")
    if kind in ("regex", "url") or (kind in ("html_attr", "html_text", "header") and ext.pattern):
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


# ===== recorder: recording browser (IE engine in this python.exe) + recording proxy (standard library) =====
# Recording (Windows).  ``python reqrec.py record --out rec.json`` - the GUI starts exactly this as a
# child process for every recording - opens the recording browser and records every plain
# ``http://`` request it makes.  No exe of reqrec's own is involved: the process is python.exe
# running this file, with the standard library only (``http.server`` / ``http.client`` / ``ctypes``).
#
# * **recording proxy** - threads of the same process, listening on ``127.0.0.1`` on a free port.
#   Each request goes to the site as it is (one connection to the site per browser connection, so
#   Windows authentication - NTLM / Negotiate - keeps working), the response goes back unchanged
#   and both are stored as a :class:`Flow`.  ``https://`` is tunnelled untouched (``CONNECT``) and
#   is not recorded: no certificate is needed.
# * **recording browser** - the Internet Explorer engine (``WebBrowser`` control = Trident / MSHTML,
#   the engine of Edge's IE mode) hosted with ``ctypes`` in a window of this process: toolbar, tabs,
#   status bar.  Popups (``window.open``, ``target=_blank``, forms posted to a new window) open as tabs
#   of the same window with opener, window name, session and POST body intact (``NewWindow3`` is
#   answered with a fresh control); ``window.close()`` reaches the site's ``IOleCommandTarget`` as
#   ``OLECMDID_CLOSE``; ``showModalDialog`` / ``showModelessDialog`` are the engine's own windows.
# * **this process only** - the proxy is set with ``InternetSetOptionA(NULL, INTERNET_OPTION_PROXY)``
#   (ANSI; plus ``UrlMkSetSessionOption``) before the first control exists, with an EMPTY bypass list
#   (``<local>`` would exclude dotless intranet names such as ``http://kanri/``).  Nothing in Windows
#   changes: no Internet Options, no registry value, no certificate, no other process.  Cookies the
#   browser receives are not persisted and the session starts empty, so the login itself is recorded.
# * **表示モード** without the registry: ``ie8`` / ``ie11`` / ``ie11_force`` add an ``X-UA-Compatible``
#   header to the HTML the browser receives (the recording keeps the site's own response) and set the
#   matching User-Agent for this process.  A popup opened by ``window.open(url)`` from a page in IE9 or
#   later mode would come up in quirks mode (measured on Windows 11 with this engine); navigating the
#   fresh control to ``about:blank`` before the engine gets it avoids that.
#
# The process's bitness is the installed Python's: legacy pages whose 32-bit ActiveX controls must
# load (as in Edge's 32-bit IE mode) need a 32-bit Python.
#
# Output: the recording JSON (``--out``) is rewritten atomically about every half second while
# recording and once more at the end, so even a killed process leaves a valid file.  stdout carries
# ``READY <port>`` once the proxy listens and the window is open (the GUI waits for it); errors go to
# stderr in Japanese.  ``--control stdin``: a ``stop`` line (or the end of stdin) closes the browser
# like its own [記録をおわる] button.  Exit codes: :data:`RECORD_EXIT_OK` ... :data:`RECORD_EXIT_PROXY`.
#
# Sections: constants and the store; the proxy; availability and process helpers; the Win32 / COM
# declarations (built on first use, so importing reqrec stays free of ctypes on every OS); the browser
# window; ``run_recorder`` (the child process); :class:`RecorderManager` (the GUI's side).

#: Window title of the recording browser (「 — 記録中」 is appended).
BROWSER_TITLE = "reqrec 記録用ブラウザ"
#: The recording proxy listens on this PC only.
RECORD_LISTEN_HOST = "127.0.0.1"
#: This file: the GUI starts ``python <SCRIPT_PATH> record ...`` for every recording.
SCRIPT_PATH = os.path.abspath(__file__)
#: 表示モード -> ``X-UA-Compatible`` value added to the HTML the recording browser receives.  ``None``
#: (既定) = the engine's own default: IE7 mode for pages with a DOCTYPE, as Edge's IE mode shows
#: Compatibility-View intranet sites.  ``Emulate...`` follows the page's DOCTYPE; ``IE=edge`` forces IE11.
EMULATION_MODES: dict[str, Optional[str]] = {
    "default": None,
    "ie8": "IE=EmulateIE8",
    "ie11": "IE=EmulateIE11",
    "ie11_force": "IE=edge",
}
#: Exit codes of ``reqrec record``.
RECORD_EXIT_OK = 0         # the window was closed (or [記録をおわる] / ``stop``)
RECORD_EXIT_START = 1      # could not start: not Windows, no IE engine, the window could not be made
RECORD_EXIT_USAGE = 2      # command line error
RECORD_EXIT_TIMEOUT = 3    # ``--selftest`` guard timeout
RECORD_EXIT_PROXY = 4      # the per-process proxy could not be set: nothing would be recorded
#: Seconds the GUI waits for ``READY`` (a first start imports Flask and loads the IE engine).
RECORD_READY_TIMEOUT = 30.0


class RecorderError(RuntimeError):
    """Raised with a Japanese, user-facing message when a recording cannot start / stop / load."""


def write_recording_atomic(recording: Recording, path: str) -> str:
    """Serialise ``recording`` to ``path`` via a temp file in the same directory + ``os.replace``.

    Readers never observe a partially written file.  Returns the absolute path written.
    """
    path = os.path.abspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".reqrec-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(recording.to_json(indent=1))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


# --------------------------------------------------------------------------- recording store

class RecordingStore:
    """The flows the proxy recorded, kept on disk at ``out``.

    ``start()`` writes an empty, valid file at once; every :meth:`add` schedules a rewrite (a writer
    thread batches the flows of about half a second; the pause grows with the file so a large
    recording never keeps the process busy); :meth:`close` writes the final file.  Flows are ordered
    by the time their request started and numbered ``f0001``.. (the GUI counts them in the file).
    """

    def __init__(self, out: str, meta: Optional[dict[str, Any]] = None, flush_interval: float = 0.5) -> None:
        self.out = os.path.abspath(out)
        self.meta = dict(meta or {})
        self.started_at = now_iso()
        self.flush_interval = float(flush_interval)
        self.errors = 0
        self.last_flush_error: Optional[str] = None
        self._flows: list[Flow] = []
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._dirty = threading.Event()
        self._closed = False
        self._pause = self.flush_interval
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "RecordingStore":
        self.flush()
        self._thread = threading.Thread(target=self._writer, name="reqrec-recording-writer", daemon=True)
        self._thread.start()
        return self

    def add(self, flow: Flow, errored: bool = False) -> int:
        """Keep ``flow`` (any id; renumbered when written); returns the number of flows so far."""
        with self._lock:
            self._flows.append(flow)
            if errored:
                self.errors += 1
            count = len(self._flows)
        self._dirty.set()
        return count

    def __len__(self) -> int:
        with self._lock:
            return len(self._flows)

    def recording(self) -> Recording:
        """Snapshot: chronological (request start, then arrival), ids ``f0001``.., with meta."""
        with self._lock:
            flows = list(self._flows)
            errors = self.errors
        keyed = sorted(enumerate(flows), key=lambda t: (t[1].started_at if t[1].started_at is not None else float("inf"), t[0]))
        ordered = [replace(flow, id=f"f{n:04d}") for n, (_, flow) in enumerate(keyed, start=1)]
        meta: dict[str, Any] = {"source": "recbrowser"}
        meta.update(self.meta)
        meta.update(started_at=self.started_at, updated_at=now_iso(), flows_total=len(ordered), errors=errors)
        return Recording(flows=ordered, meta=meta)

    def flush(self) -> str:
        """Write the current recording atomically; returns the path."""
        with self._write_lock:
            began = time.monotonic()
            try:
                path = write_recording_atomic(self.recording(), self.out)
            except OSError as exc:
                self.last_flush_error = str(exc)
                raise
            self.last_flush_error = None
            # a recording that takes long to write is written less often (never more than 1/4 of the time)
            self._pause = max(self.flush_interval, min(10.0, (time.monotonic() - began) * 4))
            return path

    def _writer(self) -> None:
        while True:
            self._dirty.wait()
            if self._closed:
                return
            time.sleep(self._pause)  # the rest of the page's requests arrive meanwhile
            self._dirty.clear()
            if self._closed:
                return
            try:
                self.flush()
            except OSError:
                pass  # kept in last_flush_error; the next flow tries again

    def close(self) -> str:
        """Stop the writer thread and write the final file."""
        self._closed = True
        self._dirty.set()
        if self._thread is not None:
            self._thread.join(5.0)
        return self.flush()


# --------------------------------------------------------------------------- recording proxy

#: Never forwarded (they describe the connection to the proxy, not the request).
_HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})
#: Printable ASCII is kept as it is when a request line holds raw bytes (``%`` included).
_URL_SAFE_ASCII = "".join(chr(c) for c in range(0x21, 0x7F))


def _decode_content(data: bytes, encoding: Optional[str]) -> bytes:
    """The body without its ``Content-Encoding`` (gzip / deflate); anything else as received."""
    enc = (encoding or "").strip().lower()
    if not data or enc in ("", "identity"):
        return data
    import gzip
    import zlib

    try:
        if enc in ("gzip", "x-gzip"):
            return gzip.decompress(data)
        if enc == "deflate":
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)  # raw deflate (old IIS)
    except (OSError, EOFError, zlib.error):
        return data
    return data


def _header_text(value: str) -> str:
    """``http.server`` / ``http.client`` read header bytes as latin-1; UTF-8 bytes become text again."""
    try:
        raw = value.encode("latin-1")
    except UnicodeEncodeError:
        return value
    if raw.isascii():
        return value
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return value


def _recorded_url(raw_url: str) -> str:
    """The request URL as recorded: raw bytes of the request line (a Shift_JIS query string sent
    unescaped, ...) are percent-encoded, everything else is kept as sent."""
    try:
        raw = raw_url.encode("latin-1")
    except UnicodeEncodeError:
        return raw_url
    if raw.isascii() and " " not in raw_url:
        return raw_url
    return quote_from_bytes(raw, safe=_URL_SAFE_ASCII)


def _is_html_response(headers: Headers) -> bool:
    ct = header_get(headers, "content-type")
    return bool(ct) and parse_content_type(ct)[0] in ("text/html", "application/xhtml+xml")


class _UpstreamConnection(http.client.HTTPConnection):
    """Sends the request line with the browser's own bytes (latin-1 round trip) instead of
    refusing non-ASCII as ``http.client`` does."""

    def _encode_request(self, request: str) -> bytes:  # type: ignore[override]
        return request.encode("latin-1")


def _pipe(a: socket.socket, b: socket.socket, idle: float) -> None:
    """Copy bytes both ways until one side closes, fails or stays silent for ``idle`` seconds."""
    import select

    socks = [a, b]
    while True:
        try:
            readable, _, broken = select.select(socks, [], socks, idle)
        except (OSError, ValueError):
            return
        if broken or not readable:
            return
        for sock in readable:
            try:
                data = sock.recv(65536)
            except OSError:
                return
            if not data:
                return
            try:
                (b if sock is a else a).sendall(data)
            except OSError:
                return


class _RecordingProxyHandler(http.server.BaseHTTPRequestHandler):
    """One browser connection (kept alive): every request is forwarded and recorded."""

    protocol_version = "HTTP/1.1"
    timeout = 300  # an idle browser connection is closed after this many seconds

    def setup(self) -> None:
        super().setup()
        self._upstreams: dict[tuple[str, int], _UpstreamConnection] = {}

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            for conn in self._upstreams.values():
                try:
                    conn.close()
                except Exception:
                    pass
            self._upstreams.clear()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - http.server's signature
        pass

    def handle_one_request(self) -> None:
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline, self.request_version, self.command = "", "", ""
                self._plain_error(414, "reqrec: request line too long")
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return
            if self.command == "CONNECT":
                self._tunnel()
            else:
                self._relay()
            self.wfile.flush()
        except OSError:  # the browser went away / timed out
            self.close_connection = True

    # ------------------------------------------------------------------ helpers

    def _plain_error(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response_only(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self) -> bytes:
        """The request body (``Content-Length`` or chunked); ``ValueError`` when malformed."""
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            chunks: list[bytes] = []
            while True:
                line = self.rfile.readline(65537)
                if not line:
                    raise ValueError("truncated chunked body")
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline(65537) not in (b"\r\n", b"\n", b""):
                        pass  # trailers
                    return b"".join(chunks)
                chunks.append(self.rfile.read(size))
                self.rfile.readline(65537)  # CRLF after the chunk
        length = self.headers.get("Content-Length")
        if not length:
            return b""
        n = int(length)
        if n < 0:
            raise ValueError("negative Content-Length")
        data = self.rfile.read(n)
        if len(data) != n:
            raise ValueError("truncated body")
        return data

    def _drop_upstream(self, key: tuple[str, int]) -> None:
        conn = self._upstreams.pop(key, None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    def _exchange(self, host: str, port: int, target: str, headers: Headers, body: bytes) -> tuple[Any, bytes]:
        """Send the request on this browser connection's connection to ``host:port`` (opened when
        needed; a kept-alive one the site had closed is retried once on a new one)."""
        server: RecordingProxy = self.server  # type: ignore[assignment]
        key = (host.lower(), int(port))
        for attempt in (0, 1):
            conn = self._upstreams.get(key)
            reused = conn is not None
            if conn is None:
                conn = _UpstreamConnection(host, port, timeout=server.connect_timeout)
                self._upstreams[key] = conn
            try:
                if conn.sock is None:
                    conn.connect()
                    conn.sock.settimeout(server.read_timeout)  # connecting may take 30 s, a slow report longer
                conn.putrequest(self.command, target, skip_host=True, skip_accept_encoding=True)
                for name, value in headers:
                    conn.putheader(name, value)
                conn.endheaders(body if body else None)
                resp = conn.getresponse()
                data = resp.read()  # chunked transfer coding undone; Content-Encoding kept
            except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                self._drop_upstream(key)
                if reused and attempt == 0:
                    continue
                raise
            except BaseException:
                self._drop_upstream(key)
                raise
            if resp.will_close:
                self._drop_upstream(key)
            return resp, data
        raise OSError("unreachable")  # pragma: no cover

    # ------------------------------------------------------------------ http:// (recorded)

    def _relay(self) -> None:
        server: RecordingProxy = self.server  # type: ignore[assignment]
        started = time.time()
        raw_url = self.path
        parts = urlsplit(raw_url)
        if parts.scheme.lower() != "http" or not parts.hostname:
            self._plain_error(400, "reqrec: これは記録用の中継です (http:// のアドレスだけを中継します)")
            return
        try:
            body = self._read_body()
            port = parts.port or 80
        except ValueError:
            self._plain_error(400, "reqrec: リクエストの形式が不正です")
            return
        received = [(name, value) for name, value in self.headers.items()]
        forward = [(n, v) for n, v in received if n.lower() not in _HOP_BY_HOP_HEADERS]
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            forward.append(("Content-Length", str(len(body))))
        target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        rec_headers = [(name, _header_text(value)) for name, value in received]
        request = RecordedRequest(
            method=(self.command or "GET").upper(),
            url=_recorded_url(raw_url),
            headers=rec_headers,
            body=body if (body or header_get(rec_headers, "content-type") is not None) else None,
        )
        resource_type = infer_resource_type(rec_headers)
        try:
            resp, data = self._exchange(parts.hostname, port, target, forward, body)
        except (OSError, http.client.HTTPException) as exc:
            server.record(Flow(id="f0000", request=request, response=None, started_at=started, resource_type=resource_type), errored=True)
            self._plain_error(502, f"reqrec: {parts.hostname}:{port} に接続できません ({exc})")
            return
        status = int(resp.status)
        resp_headers = [(name, value) for name, value in resp.getheaders()]
        rec_resp_headers = [(name, _header_text(value)) for name, value in resp_headers]
        server.record(Flow(
            id="f0000",
            request=request,
            response=RecordedResponse(status=status, headers=rec_resp_headers,
                                      body=_decode_content(data, header_get(resp_headers, "content-encoding"))),
            started_at=started,
            resource_type=resource_type,
        ))
        out = [(n, v) for n, v in resp_headers if n.lower() not in _HOP_BY_HOP_HEADERS and n.lower() != "content-length"]
        if server.compat and _is_html_response(resp_headers) and header_get(resp_headers, "x-ua-compatible") is None:
            out.append(("X-UA-Compatible", server.compat))
        self.send_response_only(status, resp.reason)
        for name, value in out:
            self.send_header(name, value)
        bodyless = self.command == "HEAD" or status in (204, 304) or status < 200
        if not bodyless:
            self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not bodyless and data:
            self.wfile.write(data)

    # ------------------------------------------------------------------ https:// (tunnelled, not recorded)

    def _tunnel(self) -> None:
        server: RecordingProxy = self.server  # type: ignore[assignment]
        host, sep, port_text = self.path.rpartition(":")
        if not sep:
            host, port_text = self.path, "443"
        try:
            port = int(port_text)
        except ValueError:
            self._plain_error(400, "reqrec: CONNECT の宛先が不正です")
            return
        try:
            upstream = socket.create_connection((host.strip("[]"), port), timeout=server.connect_timeout)
        except OSError as exc:
            self._plain_error(502, f"reqrec: {host}:{port} に接続できません ({exc})")
            return
        try:
            self.send_response_only(200, "Connection Established")
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True
            _pipe(self.connection, upstream, server.read_timeout)
        finally:
            try:
                upstream.close()
            except OSError:
                pass


class RecordingProxy(http.server.ThreadingHTTPServer):
    """The recording proxy: ``127.0.0.1`` on a free port; every ``http://`` exchange goes to ``store``.

    ``compat`` is the ``X-UA-Compatible`` value added to HTML responses (表示モード, see
    :data:`EMULATION_MODES`); ``on_flow(count, flow)`` is called after each recorded flow.
    """

    daemon_threads = True
    allow_reuse_address = False  # Windows: SO_REUSEADDR would let another socket share the port

    def __init__(
        self,
        store: RecordingStore,
        host: str = RECORD_LISTEN_HOST,
        port: int = 0,
        compat: Optional[str] = None,
        on_flow: Optional[Callable[[int, Flow], None]] = None,
        connect_timeout: float = 30.0,
        read_timeout: float = 300.0,
    ) -> None:
        self.store = store
        self.compat = compat
        self.on_flow = on_flow
        self.connect_timeout = float(connect_timeout)
        self.read_timeout = float(read_timeout)
        super().__init__((host, int(port)), _RecordingProxyHandler)

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def record(self, flow: Flow, errored: bool = False) -> None:
        count = self.store.add(flow, errored=errored)
        if self.on_flow is not None:
            try:
                self.on_flow(count, flow)
            except Exception:
                pass

    def start(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.2}, name="reqrec-proxy", daemon=True)
        thread.start()
        return thread


# --------------------------------------------------------------------------- availability / process helpers

#: CLSID of the IE engine's WebBrowser control (``Shell.Explorer.2``, ieframe.dll).
_WEBBROWSER_CLSID = "{8856F961-340A-11D0-A96B-00C04FD705A2}"


def _ie_engine_registered() -> bool:
    """Is the WebBrowser control registered (read-only registry check)?"""
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{_WEBBROWSER_CLSID}\InprocServer32"):
            return True
    except OSError:
        return False


def recorder_availability(platform: Optional[str] = None, engine_check: Optional[Callable[[], bool]] = None) -> dict[str, Any]:
    """``{"available": bool, "reason": str|None}``: can this PC record (Windows with the IE engine)?"""
    if (platform or sys.platform) != "win32":
        return {"available": False, "reason": "記録用ブラウザ (IE エンジン) は Windows でのみ使えます。HAR ファイルからは作れます。"}
    check = engine_check or _ie_engine_registered
    try:
        ok = bool(check())
    except Exception:
        ok = False
    if not ok:
        return {"available": False, "reason": "この PC には IE エンジン (ieframe.dll) が見つかりません。HAR ファイルからは作れます。"}
    return {"available": True, "reason": None}


# ----- Microsoft Edge (記録に使うブラウザ「Edge」)
# Edge itself (not its IE mode) is started for one recording with a profile folder of its own and its
# http:// traffic sent to the recording proxy (command-line switches of that Edge only: no setting,
# registry value or certificate; the person's own Edge, its settings and sign-ins are untouched).  The
# msedge.exe that is started hands the window over to a new browser process and exits, so "our" Edge is
# the msedge.exe processes descended from it.

#: The browsers a recording can use: ``ie`` = the recording browser (the IE engine, as Edge's IE mode),
#: ``edge`` = Microsoft Edge.
RECORD_BROWSERS = ("ie", "edge")
#: Seconds to wait for Edge's window process to appear.
EDGE_START_TIMEOUT = 30.0


def find_edge() -> Optional[str]:
    """``msedge.exe`` of this PC (the environment variable ``REQREC_EDGE`` overrides), or None."""
    override = os.environ.get("REQREC_EDGE")
    if override:
        return override if os.path.isfile(override) else None
    bases = [os.environ.get(name) for name in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA")]
    candidates = [os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe") for base in bases if base]
    which = shutil.which("msedge")
    if which:
        candidates.append(which)
    return next((path for path in candidates if os.path.isfile(path)), None)


def edge_availability(platform: Optional[str] = None, finder: Optional[Callable[[], Optional[str]]] = None) -> dict[str, Any]:
    """``{"available": bool, "reason": str|None}``: can this PC record with Microsoft Edge?"""
    if (platform or sys.platform) != "win32":
        return {"available": False, "reason": "Edge での記録は Windows でのみ使えます。HAR ファイルからは作れます。"}
    if (finder or find_edge)() is None:
        return {"available": False, "reason": "この PC には Microsoft Edge (msedge.exe) が見つかりません。"}
    return {"available": True, "reason": None}


def edge_command(edge: str, port: int, url: Optional[str], profile: str) -> list[str]:
    """Microsoft Edge for one recording: the profile folder ``profile`` (the session starts empty, so the
    login itself is recorded), ``http://`` through the recording proxy (``https://`` goes directly and is
    not recorded: no certificate), and none of Edge's own background requests (they would end up in the
    recording and in the script)."""
    return [
        edge, f"--user-data-dir={profile}",
        f"--proxy-server=http={RECORD_LISTEN_HOST}:{int(port)}",
        "--proxy-bypass-list=<-loopback>",  # sites on this PC (127.0.0.1, localhost) go through the proxy too
        "--no-first-run", "--no-default-browser-check", "--disable-sync",
        "--disable-background-networking", "--disable-component-update", "--no-pings", "--disable-domain-reliability",
        "--disable-features=NetworkTimeServiceQuerying",
        "--new-window", url or "about:blank",
    ]


def _windows_processes() -> list[tuple[int, int, str]]:
    """``(pid, parent pid, exe name in lower case)`` of every process (a Toolhelp32 snapshot; [] elsewhere)."""
    if not is_windows():
        return []
    import ctypes
    from ctypes import wintypes

    class _Entry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == ctypes.c_void_p(-1).value:
        return []
    out: list[tuple[int, int, str]] = []
    try:
        entry = _Entry()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            out.append((int(entry.th32ProcessID), int(entry.th32ParentProcessID), entry.szExeFile.lower()))
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return out


def _edge_processes(launcher_pid: int, processes: Optional[list[tuple[int, int, str]]] = None) -> list[tuple[int, int]]:
    """``(pid, parent pid)`` of our Edge: the msedge.exe processes descended from the one started (it hands
    the window over to a new browser process and exits), and that one while it still runs."""
    procs = [(pid, ppid) for pid, ppid, exe in (_windows_processes() if processes is None else processes)
             if exe == "msedge.exe"]
    found = {launcher_pid} if any(pid == launcher_pid for pid, _ppid in procs) else set()
    frontier = {launcher_pid}
    while frontier:
        frontier = {pid for pid, ppid in procs if ppid in frontier and pid not in found}
        found |= frontier
    return [(pid, ppid) for pid, ppid in procs if pid in found]


def _stop_edge(launcher_pid: int) -> None:
    """Close our Edge, its whole process tree by pid (its profile is thrown away, so nothing is lost)."""
    procs = _edge_processes(launcher_pid)
    pids = {pid for pid, _ppid in procs}
    for pid, ppid in procs:
        if ppid not in pids:  # a top of our tree
            try:
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=15,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except (OSError, subprocess.SubprocessError):
                pass


def _remove_profile(profile: str) -> None:
    """Delete Edge's recording profile folder (its files stay locked for a moment after Edge ends)."""
    for _ in range(20):
        shutil.rmtree(profile, ignore_errors=True)
        if not os.path.exists(profile):
            return
        time.sleep(0.5)


def emulation_user_agent(default_ua: str, mode: str) -> Optional[str]:
    """The User-Agent the engine sends in 表示モード ``mode``, made from its default (IE7) one, or
    ``None`` to keep the default: ``ie11`` / ``ie11_force`` -> ``Mozilla/5.0 (...; rv:11.0) like
    Gecko``, ``ie8`` -> ``MSIE 8.0``."""
    ua = (default_ua or "").strip()
    if mode in ("ie11", "ie11_force"):
        m = re.match(r"Mozilla/4\.0 \(compatible; MSIE [\d.]+; (.*)\)$", ua)
        return f"Mozilla/5.0 ({m.group(1)}; rv:11.0) like Gecko" if m else None
    if mode == "ie8":
        return re.sub(r"MSIE [\d.]+", "MSIE 8.0", ua, count=1) if "MSIE " in ua else None
    return None


def _kill_on_close_job(proc: Any) -> Optional[int]:
    """Put ``proc`` in a Windows job object with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` and return the
    job handle (``None`` when unsupported or it failed - never raises).

    The handle stays open in the GUI process; if the GUI dies without cleaning up (console window
    closed, ended from Task Manager), Windows closes the handle and ends the recording browser too.
    No setting, file or registry value is involved.
    """
    if not is_windows():
        return None
    handle = getattr(proc, "_handle", None)
    if not handle:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class _IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class _BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimit),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _ExtendedLimit()
        # KILL_ON_JOB_CLOSE | SILENT_BREAKAWAY_OK: only the recording browser is tied to the GUI; programs
        # it starts (Excel opened from a download, a mail client ...) stay outside the job and survive.
        info.BasicLimitInformation.LimitFlags = 0x2000 | 0x1000
        ok = kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))  # JobObjectExtendedLimitInformation
        if ok:
            ok = kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(int(handle)))
        if not ok:
            kernel32.CloseHandle(job)
            return None
        return int(job)
    except Exception:
        return None


def _close_handle(handle: Optional[int]) -> None:
    if not handle or not is_windows():
        return
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle(wintypes.HANDLE(handle))
    except Exception:
        pass


# --------------------------------------------------------------------------- Win32 / COM declarations (ctypes)

_RB_WIN32: Optional[types.SimpleNamespace] = None


def _rb_win32() -> types.SimpleNamespace:
    """The ctypes declarations of the recording browser (Windows only), built once on first use."""
    global _RB_WIN32
    if _RB_WIN32 is None:
        _RB_WIN32 = _build_rb_win32()
    return _RB_WIN32


def _build_rb_win32() -> types.SimpleNamespace:  # noqa: C901 - a flat list of declarations
    import ctypes
    from ctypes import (
        POINTER, WINFUNCTYPE, Structure, Union, addressof, byref, c_int, c_long, c_short, c_size_t, c_uint,
        c_ulong, c_ushort, c_void_p, c_wchar_p, cast, pointer, sizeof,
    )
    from ctypes import wintypes as wt

    HRESULT = c_long
    LRESULT = wt.LPARAM
    IS_64BIT = sizeof(c_void_p) == 8

    def hr32(value: int) -> int:
        return c_long(value).value

    S_OK, S_FALSE = 0, 1
    E_NOTIMPL, E_NOINTERFACE, E_POINTER, E_FAIL = hr32(0x80004001), hr32(0x80004002), hr32(0x80004003), hr32(0x80004005)
    OLECMDERR_E_NOTSUPPORTED, OLECMDERR_E_UNKNOWNGROUP = hr32(0x80040100), hr32(0x80040104)

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32")
    ole32 = ctypes.WinDLL("ole32")
    oleaut32 = ctypes.WinDLL("oleaut32")
    wininet = ctypes.WinDLL("wininet", use_last_error=True)
    urlmon = ctypes.WinDLL("urlmon")

    # ------------------------------------------------------------------ structures
    class GUID(Structure):
        _fields_ = [("Data1", c_ulong), ("Data2", c_ushort), ("Data3", c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    class _VARIANT_U(Union):
        _fields_ = [("llVal", ctypes.c_longlong), ("lVal", c_long), ("iVal", c_short), ("boolVal", c_short),
                    ("fltVal", ctypes.c_float), ("dblVal", ctypes.c_double), ("bstrVal", c_void_p),
                    ("pdispVal", c_void_p), ("byref", c_void_p), ("_record", c_void_p * 2)]

    class VARIANT(Structure):
        _fields_ = [("vt", c_ushort), ("wReserved1", c_ushort), ("wReserved2", c_ushort), ("wReserved3", c_ushort),
                    ("u", _VARIANT_U)]

    class DISPPARAMS(Structure):
        _fields_ = [("rgvarg", POINTER(VARIANT)), ("rgdispidNamedArgs", POINTER(c_long)),
                    ("cArgs", c_uint), ("cNamedArgs", c_uint)]

    class EXCEPINFO(Structure):
        _fields_ = [("wCode", wt.WORD), ("wReserved", wt.WORD), ("bstrSource", c_void_p), ("bstrDescription", c_void_p),
                    ("bstrHelpFile", c_void_p), ("dwHelpContext", wt.DWORD), ("pvReserved", c_void_p),
                    ("pfnDeferredFillIn", c_void_p), ("scode", c_long)]

    class OLEINPLACEFRAMEINFO(Structure):
        _fields_ = [("cb", c_uint), ("fMDIApp", wt.BOOL), ("hwndFrame", wt.HWND), ("haccel", wt.HANDLE),
                    ("cAccelEntries", c_uint)]

    class INTERNET_PROXY_INFO(Structure):
        _fields_ = [("dwAccessType", wt.DWORD), ("lpszProxy", ctypes.c_char_p), ("lpszProxyBypass", ctypes.c_char_p)]

    WNDPROC = WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

    class WNDCLASSEXW(Structure):
        _fields_ = [("cbSize", wt.UINT), ("style", wt.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", c_int),
                    ("cbWndExtra", c_int), ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON), ("hCursor", wt.HANDLE),
                    ("hbrBackground", wt.HBRUSH), ("lpszMenuName", wt.LPCWSTR), ("lpszClassName", wt.LPCWSTR),
                    ("hIconSm", wt.HICON)]

    class MINMAXINFO(Structure):
        _fields_ = [("ptReserved", wt.POINT), ("ptMaxSize", wt.POINT), ("ptMaxPosition", wt.POINT),
                    ("ptMinTrackSize", wt.POINT), ("ptMaxTrackSize", wt.POINT)]

    class DRAWITEMSTRUCT(Structure):
        _fields_ = [("CtlType", c_uint), ("CtlID", c_uint), ("itemID", c_uint), ("itemAction", c_uint),
                    ("itemState", c_uint), ("hwndItem", wt.HWND), ("hDC", wt.HDC), ("rcItem", wt.RECT),
                    ("itemData", c_size_t)]

    class NMHDR(Structure):
        _fields_ = [("hwndFrom", wt.HWND), ("idFrom", c_size_t), ("code", c_int)]

    class TCITEMW(Structure):
        _fields_ = [("mask", c_uint), ("dwState", wt.DWORD), ("dwStateMask", wt.DWORD), ("pszText", c_wchar_p),
                    ("cchTextMax", c_int), ("iImage", c_int), ("lParam", wt.LPARAM)]

    class LOGFONTW(Structure):
        _fields_ = [("lfHeight", c_long), ("lfWidth", c_long), ("lfEscapement", c_long), ("lfOrientation", c_long),
                    ("lfWeight", c_long), ("lfItalic", ctypes.c_ubyte), ("lfUnderline", ctypes.c_ubyte),
                    ("lfStrikeOut", ctypes.c_ubyte), ("lfCharSet", ctypes.c_ubyte), ("lfOutPrecision", ctypes.c_ubyte),
                    ("lfClipPrecision", ctypes.c_ubyte), ("lfQuality", ctypes.c_ubyte),
                    ("lfPitchAndFamily", ctypes.c_ubyte), ("lfFaceName", ctypes.c_wchar * 32)]

    class NONCLIENTMETRICSW(Structure):
        _fields_ = [("cbSize", c_uint), ("iBorderWidth", c_int), ("iScrollWidth", c_int), ("iScrollHeight", c_int),
                    ("iCaptionWidth", c_int), ("iCaptionHeight", c_int), ("lfCaptionFont", LOGFONTW),
                    ("iSmCaptionWidth", c_int), ("iSmCaptionHeight", c_int), ("lfSmCaptionFont", LOGFONTW),
                    ("iMenuWidth", c_int), ("iMenuHeight", c_int), ("lfMenuFont", LOGFONTW),
                    ("lfStatusFont", LOGFONTW), ("lfMessageFont", LOGFONTW), ("iPaddedBorderWidth", c_int)]

    class INITCOMMONCONTROLSEX(Structure):
        _fields_ = [("dwSize", wt.DWORD), ("dwICC", wt.DWORD)]

    class ACTCTXW(Structure):
        _fields_ = [("cbSize", wt.ULONG), ("dwFlags", wt.DWORD), ("lpSource", wt.LPCWSTR),
                    ("wProcessorArchitecture", wt.USHORT), ("wLangId", wt.LANGID), ("lpAssemblyDirectory", wt.LPCWSTR),
                    ("lpResourceName", wt.LPCWSTR), ("lpApplicationName", wt.LPCWSTR), ("hModule", wt.HMODULE)]

    # ------------------------------------------------------------------ functions
    def proto(dll: Any, name: str, restype: Any, *argtypes: Any) -> Any:
        fn = getattr(dll, name)
        fn.restype = restype
        fn.argtypes = list(argtypes)
        return fn

    proto(user32, "RegisterClassExW", wt.ATOM, POINTER(WNDCLASSEXW))
    proto(user32, "CreateWindowExW", wt.HWND, wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, c_int, c_int, c_int, c_int,
          wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID)
    proto(user32, "DefWindowProcW", LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
    proto(user32, "CallWindowProcW", LRESULT, c_void_p, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
    proto(user32, "DestroyWindow", wt.BOOL, wt.HWND)
    proto(user32, "ShowWindow", wt.BOOL, wt.HWND, c_int)
    proto(user32, "MoveWindow", wt.BOOL, wt.HWND, c_int, c_int, c_int, c_int, wt.BOOL)
    proto(user32, "SetWindowPos", wt.BOOL, wt.HWND, wt.HWND, c_int, c_int, c_int, c_int, wt.UINT)
    proto(user32, "GetClientRect", wt.BOOL, wt.HWND, POINTER(wt.RECT))
    proto(user32, "GetWindowRect", wt.BOOL, wt.HWND, POINTER(wt.RECT))
    proto(user32, "MapWindowPoints", c_int, wt.HWND, wt.HWND, c_void_p, wt.UINT)
    proto(user32, "SetWindowTextW", wt.BOOL, wt.HWND, wt.LPCWSTR)
    proto(user32, "GetWindowTextW", c_int, wt.HWND, wt.LPWSTR, c_int)
    proto(user32, "GetWindowTextLengthW", c_int, wt.HWND)
    proto(user32, "GetMessageW", wt.BOOL, POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT)
    proto(user32, "TranslateMessage", wt.BOOL, POINTER(wt.MSG))
    proto(user32, "DispatchMessageW", LRESULT, POINTER(wt.MSG))
    proto(user32, "PostMessageW", wt.BOOL, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
    proto(user32, "SendMessageW", LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
    proto(user32, "PostQuitMessage", None, c_int)
    proto(user32, "SetTimer", c_size_t, wt.HWND, c_size_t, wt.UINT, c_void_p)
    proto(user32, "KillTimer", wt.BOOL, wt.HWND, c_size_t)
    proto(user32, "IsChild", wt.BOOL, wt.HWND, wt.HWND)
    proto(user32, "IsWindow", wt.BOOL, wt.HWND)
    proto(user32, "IsWindowEnabled", wt.BOOL, wt.HWND)
    proto(user32, "IsWindowVisible", wt.BOOL, wt.HWND)
    proto(user32, "EnableWindow", wt.BOOL, wt.HWND, wt.BOOL)
    proto(user32, "LoadCursorW", wt.HANDLE, wt.HINSTANCE, c_void_p)
    proto(user32, "LoadIconW", wt.HICON, wt.HINSTANCE, c_void_p)
    proto(user32, "SetFocus", wt.HWND, wt.HWND)
    proto(user32, "SetForegroundWindow", wt.BOOL, wt.HWND)
    proto(user32, "GetFocus", wt.HWND)
    proto(user32, "SystemParametersInfoW", wt.BOOL, wt.UINT, wt.UINT, c_void_p, wt.UINT)
    proto(user32, "GetDC", wt.HDC, wt.HWND)
    proto(user32, "ReleaseDC", c_int, wt.HWND, wt.HDC)
    proto(user32, "FillRect", c_int, wt.HDC, POINTER(wt.RECT), wt.HBRUSH)
    proto(user32, "DrawTextW", c_int, wt.HDC, wt.LPCWSTR, c_int, POINTER(wt.RECT), wt.UINT)
    proto(user32, "DrawFocusRect", wt.BOOL, wt.HDC, POINTER(wt.RECT))
    proto(user32, "InvalidateRect", wt.BOOL, wt.HWND, c_void_p, wt.BOOL)
    proto(user32, "GetClassNameW", c_int, wt.HWND, wt.LPWSTR, c_int)
    ENUMWINDOWSPROC = WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    proto(user32, "EnumThreadWindows", wt.BOOL, wt.DWORD, ENUMWINDOWSPROC, wt.LPARAM)
    set_window_long = getattr(user32, "SetWindowLongPtrW", None) or user32.SetWindowLongW  # 32-bit: no ...Ptr export
    set_window_long.restype = c_void_p
    set_window_long.argtypes = [wt.HWND, c_int, c_void_p]
    proto(kernel32, "GetModuleHandleW", wt.HMODULE, wt.LPCWSTR)
    proto(kernel32, "GetCurrentThreadId", wt.DWORD)
    proto(kernel32, "CreateActCtxW", wt.HANDLE, POINTER(ACTCTXW))
    proto(kernel32, "ActivateActCtx", wt.BOOL, wt.HANDLE, POINTER(c_size_t))
    proto(gdi32, "CreateFontIndirectW", wt.HFONT, POINTER(LOGFONTW))
    proto(gdi32, "CreateSolidBrush", wt.HBRUSH, wt.COLORREF)
    proto(gdi32, "DeleteObject", wt.BOOL, wt.HGDIOBJ)
    proto(gdi32, "SelectObject", wt.HGDIOBJ, wt.HDC, wt.HGDIOBJ)
    proto(gdi32, "SetTextColor", wt.COLORREF, wt.HDC, wt.COLORREF)
    proto(gdi32, "SetBkMode", c_int, wt.HDC, c_int)
    proto(gdi32, "GetTextExtentPoint32W", wt.BOOL, wt.HDC, wt.LPCWSTR, c_int, POINTER(wt.SIZE))
    proto(ole32, "CLSIDFromString", HRESULT, c_wchar_p, POINTER(GUID))
    proto(ole32, "OleInitialize", HRESULT, c_void_p)
    proto(ole32, "CoCreateInstance", HRESULT, POINTER(GUID), c_void_p, wt.DWORD, POINTER(GUID), POINTER(c_void_p))
    proto(ole32, "OleSetContainedObject", HRESULT, c_void_p, wt.BOOL)
    proto(oleaut32, "SysAllocString", c_void_p, c_wchar_p)
    proto(oleaut32, "SysFreeString", None, c_void_p)
    proto(oleaut32, "SysStringLen", c_uint, c_void_p)
    proto(oleaut32, "VariantClear", HRESULT, POINTER(VARIANT))
    proto(wininet, "InternetSetOptionA", wt.BOOL, c_void_p, wt.DWORD, c_void_p, wt.DWORD)
    proto(urlmon, "UrlMkSetSessionOption", HRESULT, wt.DWORD, c_void_p, wt.DWORD, wt.DWORD)
    proto(urlmon, "ObtainUserAgentString", HRESULT, wt.DWORD, ctypes.c_char_p, POINTER(wt.DWORD))

    # ------------------------------------------------------------------ constants
    WM_DESTROY, WM_SIZE, WM_SETFOCUS, WM_CLOSE = 0x0002, 0x0005, 0x0007, 0x0010
    WM_GETMINMAXINFO, WM_NOTIFY, WM_SETFONT, WM_KEYDOWN, WM_CHAR = 0x0024, 0x004E, 0x0030, 0x0100, 0x0102
    WM_COMMAND, WM_TIMER, WM_DRAWITEM, WM_KEYFIRST, WM_KEYLAST = 0x0111, 0x0113, 0x002B, 0x0100, 0x0109
    WM_APP = 0x8000
    WM_APP_CLOSE_TAB = WM_APP + 1   # wParam = the tab's container window
    WM_APP_STOP = WM_APP + 2        # ``stop`` on stdin / end of stdin
    WS_OVERLAPPEDWINDOW, WS_CHILD, WS_VISIBLE = 0x00CF0000, 0x40000000, 0x10000000
    WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_TABSTOP, WS_EX_CLIENTEDGE = 0x02000000, 0x04000000, 0x00010000, 0x00000200
    ES_AUTOHSCROLL, BS_PUSHBUTTON, BS_OWNERDRAW = 0x0080, 0x0000, 0x000B
    SW_HIDE, SW_SHOW = 0, 5
    SWP_NOMOVE, SWP_NOSIZE, SWP_NOACTIVATE = 0x0002, 0x0001, 0x0010
    HWND_TOP = 0
    GWLP_WNDPROC = -4
    VK_RETURN = 0x0D
    TCM_FIRST = 0x1300
    TCM_GETCURSEL, TCM_SETCURSEL, TCM_INSERTITEMW, TCM_SETITEMW = TCM_FIRST + 11, TCM_FIRST + 12, TCM_FIRST + 62, TCM_FIRST + 61
    TCM_DELETEITEM, TCM_ADJUSTRECT, TCM_SETPADDING = TCM_FIRST + 8, TCM_FIRST + 40, TCM_FIRST + 43
    TCIF_TEXT, TCIF_PARAM = 0x0001, 0x0008
    TCN_SELCHANGE = -551
    SB_SETTEXTW, SB_SETPARTS, SBT_OWNERDRAW = 0x0400 + 11, 0x0400 + 4, 0x1000
    ODT_BUTTON, ODS_SELECTED, ODS_FOCUS = 4, 0x0001, 0x0010
    DT_CENTER, DT_VCENTER, DT_SINGLELINE, DT_LEFT, DT_RIGHT, DT_END_ELLIPSIS = 0x1, 0x4, 0x20, 0x0, 0x2, 0x8000
    TRANSPARENT = 1
    SPI_GETNONCLIENTMETRICS, SPI_GETWORKAREA = 0x0029, 0x0030
    ICC_BAR_CLASSES, ICC_TAB_CLASSES, ICC_STANDARD_CLASSES = 0x0004, 0x0008, 0x4000
    CW_USEDEFAULT = c_int(0x80000000).value
    CLSCTX_INPROC_SERVER = 1
    OLEIVERB_INPLACEACTIVATE, OLEIVERB_UIACTIVATE = -5, -4
    OLECLOSE_NOSAVE = 1
    OLECMDID_SHOWSCRIPTERROR, OLECMDID_CLOSE = 40, 45
    DISPID_COMMANDSTATECHANGE, DISPID_TITLECHANGE, DISPID_NEWWINDOW2, DISPID_NAVIGATECOMPLETE2 = 105, 113, 251, 252
    DISPID_DOCUMENTCOMPLETE, DISPID_WINDOWCLOSING, DISPID_FILEDOWNLOAD, DISPID_NEWWINDOW3 = 259, 263, 270, 273
    CSC_NAVIGATEFORWARD, CSC_NAVIGATEBACK = 1, 2
    INTERNET_OPTION_PROXY, INTERNET_OPTION_END_BROWSER_SESSION, INTERNET_OPTION_SUPPRESS_BEHAVIOR = 38, 42, 81
    INTERNET_SUPPRESS_COOKIE_PERSIST, INTERNET_OPEN_TYPE_PROXY = 3, 3
    URLMON_OPTION_USERAGENT = 0x10000001
    VT_EMPTY, VT_NULL, VT_I2, VT_I4, VT_R4, VT_R8, VT_BSTR, VT_DISPATCH = 0, 1, 2, 3, 4, 5, 8, 9
    VT_ERROR, VT_BOOL, VT_VARIANT, VT_UNKNOWN, VT_UI4, VT_I8, VT_INT, VT_UINT = 10, 11, 12, 13, 19, 20, 22, 23
    VT_BYREF = 0x4000
    DISPATCH_METHOD, DISPATCH_PROPERTYGET, DISPATCH_PROPERTYPUT = 1, 2, 4
    DISPID_PROPERTYPUT = -3
    LOCALE_USER_DEFAULT = 0x0400
    # SIZE passed by value to IOleInPlaceSite::Scroll: one 8-byte register on x64, two DWORDs on x86
    SCROLL_ARGS = [ctypes.c_int64] if IS_64BIT else [c_long, c_long]

    def guid(text: str) -> GUID:
        g = GUID()
        if ole32.CLSIDFromString(text, byref(g)) != 0:
            raise ValueError("bad GUID " + text)
        return g

    IID_NULL = GUID()
    IID_IUnknown = guid("{00000000-0000-0000-C000-000000000046}")
    IID_IDispatch = guid("{00020400-0000-0000-C000-000000000046}")
    IID_IOleObject = guid("{00000112-0000-0000-C000-000000000046}")
    IID_IOleInPlaceObject = guid("{00000113-0000-0000-C000-000000000046}")
    IID_IOleWindow = guid("{00000114-0000-0000-C000-000000000046}")
    IID_IOleInPlaceUIWindow = guid("{00000115-0000-0000-C000-000000000046}")
    IID_IOleInPlaceFrame = guid("{00000116-0000-0000-C000-000000000046}")
    IID_IOleClientSite = guid("{00000118-0000-0000-C000-000000000046}")
    IID_IOleInPlaceSite = guid("{00000119-0000-0000-C000-000000000046}")
    IID_IOleCommandTarget = guid("{B722BCCB-4E68-101B-A2BC-00AA00404770}")
    IID_IConnectionPointContainer = guid("{B196B284-BAB4-101A-B69C-00AA00341D07}")
    IID_IWebBrowser2 = guid("{D30C1661-CDAF-11D0-8A3E-00C04FC9E26E}")
    CLSID_WebBrowser = guid(_WEBBROWSER_CLSID)
    DIID_DWebBrowserEvents2 = guid("{34A715A0-6587-11D0-924A-0020AFC7AC4D}")
    CGID_DocHostCommandHandler = guid("{F38BC242-B950-11D1-8918-00C04FC2C836}")

    # ------------------------------------------------------------------ COM calls (vtable / IDispatch)
    protos: dict[Any, Any] = {}

    def vcall(obj: int, index: int, restype: Any, argtypes: Sequence[Any], *args: Any) -> Any:
        """Call method ``index`` of the interface pointer ``obj``."""
        if not obj:
            raise OSError("null COM pointer")
        vtbl = cast(c_void_p(obj), POINTER(c_void_p))[0]
        fnp = cast(c_void_p(vtbl), POINTER(c_void_p))[index]
        key = (restype, tuple(argtypes))
        fn_type = protos.get(key)
        if fn_type is None:
            fn_type = protos[key] = WINFUNCTYPE(restype, c_void_p, *argtypes)
        return fn_type(fnp)(obj, *args)

    def qi(obj: int, iid: GUID) -> int:
        out = c_void_p()
        hr = vcall(obj, 0, HRESULT, [POINTER(GUID), POINTER(c_void_p)], byref(iid), byref(out))
        return int(out.value or 0) if hr == 0 else 0

    def addref(obj: int) -> int:
        return vcall(obj, 1, c_ulong, [])

    def release(obj: int) -> int:
        return vcall(obj, 2, c_ulong, []) if obj else 0

    def same_object(a: Any, b: Any) -> bool:
        if not a or not b:
            return False
        ua, ub = qi(a, IID_IUnknown), qi(b, IID_IUnknown)
        try:
            return bool(ua) and ua == ub
        finally:
            release(ua)
            release(ub)

    def bstr_text(p: Any) -> str:
        return ctypes.wstring_at(p, oleaut32.SysStringLen(p)) if p else ""

    def from_variant(v: Any) -> Any:
        vt = v.vt
        if vt & VT_BYREF:
            base, ref = vt & ~VT_BYREF, v.u.byref
            if not ref:
                return None
            if base == VT_VARIANT:
                return from_variant(cast(c_void_p(ref), POINTER(VARIANT))[0])
            if base == VT_BSTR:
                return bstr_text(cast(c_void_p(ref), POINTER(c_void_p))[0])
            if base == VT_BOOL:
                return cast(c_void_p(ref), POINTER(c_short))[0] != 0
            if base in (VT_I4, VT_UI4, VT_INT, VT_UINT):
                return cast(c_void_p(ref), POINTER(c_long))[0]
            if base in (VT_DISPATCH, VT_UNKNOWN):
                return cast(c_void_p(ref), POINTER(c_void_p))[0]
            return None
        if vt in (VT_EMPTY, VT_NULL):
            return None
        if vt == VT_BSTR:
            return bstr_text(v.u.bstrVal)
        if vt == VT_BOOL:
            return v.u.boolVal != 0
        if vt in (VT_I4, VT_INT, VT_ERROR):
            return v.u.lVal
        if vt in (VT_UI4, VT_UINT):
            return v.u.lVal & 0xFFFFFFFF
        if vt == VT_I2:
            return v.u.iVal
        if vt == VT_I8:
            return v.u.llVal
        if vt == VT_R4:
            return v.u.fltVal
        if vt == VT_R8:
            return v.u.dblVal
        if vt in (VT_DISPATCH, VT_UNKNOWN):
            return v.u.pdispVal  # borrowed
        return None

    def to_variant(v: Any, value: Any, allocated: list) -> None:
        if value is None:
            v.vt = VT_EMPTY
        elif isinstance(value, bool):
            v.vt, v.u.boolVal = VT_BOOL, (-1 if value else 0)
        elif isinstance(value, int):
            v.vt, v.u.lVal = VT_I4, value
        elif isinstance(value, str):
            b = oleaut32.SysAllocString(value)
            allocated.append(b)
            v.vt, v.u.bstrVal = VT_BSTR, b
        else:
            raise TypeError(f"unsupported argument {value!r}")

    def disp_invoke(pdisp: int, name: str, flags: int, args: Sequence[Any] = ()) -> Any:
        """IDispatch call by name; an object result is returned AddRef'd (the caller releases it)."""
        names = (c_wchar_p * 1)(name)
        dispid = c_long()
        hr = vcall(pdisp, 5, HRESULT, [POINTER(GUID), POINTER(c_wchar_p), c_uint, c_ulong, POINTER(c_long)],
                   byref(IID_NULL), names, 1, LOCALE_USER_DEFAULT, byref(dispid))
        if hr != 0:
            raise OSError(f"GetIDsOfNames({name}) failed: 0x{hr & 0xFFFFFFFF:08x}")
        argv = (VARIANT * max(len(args), 1))()
        allocated: list = []
        for i, a in enumerate(reversed(list(args))):
            to_variant(argv[i], a, allocated)
        params = DISPPARAMS()
        if args:
            params.rgvarg = cast(argv, POINTER(VARIANT))
            params.cArgs = len(args)
        named = c_long(DISPID_PROPERTYPUT)
        if flags == DISPATCH_PROPERTYPUT:
            params.rgdispidNamedArgs = pointer(named)
            params.cNamedArgs = 1
        result, excep, argerr = VARIANT(), EXCEPINFO(), c_uint()
        try:
            hr = vcall(pdisp, 6, HRESULT,
                       [c_long, POINTER(GUID), c_ulong, c_ushort, POINTER(DISPPARAMS), POINTER(VARIANT),
                        POINTER(EXCEPINFO), POINTER(c_uint)],
                       dispid.value, byref(IID_NULL), LOCALE_USER_DEFAULT, flags, byref(params), byref(result),
                       byref(excep), byref(argerr))
            if hr != 0:
                raise OSError(f"Invoke({name}) failed: 0x{hr & 0xFFFFFFFF:08x} {bstr_text(excep.bstrDescription)}")
            if result.vt in (VT_DISPATCH, VT_UNKNOWN):
                p = result.u.pdispVal
                if p:
                    addref(p)
                return p or 0
            return from_variant(result)
        finally:
            oleaut32.VariantClear(byref(result))
            for b in allocated + [excep.bstrSource, excep.bstrDescription, excep.bstrHelpFile]:
                if b:
                    oleaut32.SysFreeString(b)

    def disp_get(pdisp: int, name: str) -> Any:
        return disp_invoke(pdisp, name, DISPATCH_PROPERTYGET)

    def disp_call(pdisp: int, name: str, *args: Any) -> Any:
        return disp_invoke(pdisp, name, DISPATCH_METHOD, args)

    # ------------------------------------------------------------------ COM objects implemented in Python
    QI_PROTO = WINFUNCTYPE(HRESULT, c_void_p, POINTER(GUID), POINTER(c_void_p))
    REF_PROTO = WINFUNCTYPE(c_ulong, c_void_p)

    def P(*argtypes: Any) -> Any:
        """Prototype of an HRESULT method (after ``this``)."""
        return WINFUNCTYPE(HRESULT, c_void_p, *argtypes)

    class _Iface(Structure):
        _fields_ = [("lpVtbl", c_void_p)]

    def null_out(pp: Any, hr: int) -> int:
        if pp:
            pp[0] = None
        return hr

    class ComObject:
        """A COM object made in Python: one vtable per interface, one shared reference count.  Kept
        alive by its owner for the lifetime of the process (the engine may call it late)."""

        def __init__(self, label: str, log: Callable[[str], None]) -> None:
            self.label = label
            self.log = log
            self.refs = 0
            self._keep: list = []
            self._by_iid: dict[bytes, int] = {}

        def _guard(self, fn: Callable[..., Any]) -> Callable[..., Any]:
            def call(*args: Any) -> Any:
                try:
                    r = fn(*args)
                    return S_OK if r is None else r
                except Exception:
                    self.log(f"callback error in {self.label}: " + traceback.format_exc().strip().replace("\n", " | "))
                    return E_FAIL
            return call

        def implement(self, iids: Sequence[GUID], methods: Sequence[tuple[Any, Callable[..., Any]]]) -> None:
            funcs = [QI_PROTO(self._qi), REF_PROTO(self._addref), REF_PROTO(self._release)]
            funcs += [fn_type(self._guard(fn)) for fn_type, fn in methods]
            vtbl = (c_void_p * len(funcs))(*[cast(f, c_void_p).value for f in funcs])
            iface = _Iface(addressof(vtbl))
            self._keep += [funcs, vtbl, iface]
            if not self._by_iid:
                self._by_iid[bytes(IID_IUnknown)] = addressof(iface)  # COM identity: the first interface
            for iid in iids:
                self._by_iid[bytes(iid)] = addressof(iface)

        def ptr(self, iid: GUID) -> int:
            return self._by_iid[bytes(iid)]

        def _qi(self, this: Any, riid: Any, ppv: Any) -> int:
            if not ppv:
                return E_POINTER
            p = self._by_iid.get(bytes(riid[0]))
            if p is None:
                ppv[0] = None
                return E_NOINTERFACE
            ppv[0] = p
            self.refs += 1
            return S_OK

        def _addref(self, this: Any) -> int:
            self.refs += 1
            return self.refs

        def _release(self, this: Any) -> int:
            self.refs = max(self.refs - 1, 0)
            return self.refs

    return types.SimpleNamespace(**{k: v for k, v in locals().items() if not k.startswith("__")})


# --------------------------------------------------------------------------- the recording browser window

class _RecLog:
    """``--log`` file of the recording browser: ``HH:MM:SS.mmm text`` lines (UTF-8).  Never raises."""

    def __init__(self, path: Optional[str]) -> None:
        self._lock = threading.Lock()
        self._fh: Any = None
        if path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
                self._fh = open(path, "a", encoding="utf-8")
            except OSError:
                self._fh = None

    def write(self, text: str) -> None:
        t = time.time()
        line = time.strftime("%H:%M:%S", time.localtime(t)) + f".{int((t % 1) * 1000):03d} {text}\n"
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.write(line)
                    self._fh.flush()
                except (OSError, ValueError):
                    pass

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None


class _RecBrowserTab:
    """One tab: a container window with one WebBrowser control, its client site and its event sink."""

    def __init__(self, app: "RecBrowserApp", popup: bool) -> None:
        W = app.W
        app.counter += 1
        self.app, self.W, self.popup, self.name = app, W, popup, f"tab{app.counter}"
        self.closed = False
        self.ole = self.wb = self.inplace = self.cp = 0
        self.cookie = 0
        self.title = ""
        self.can_back = self.can_forward = False
        self.title_announced = not popup
        rc = app.page_rect()
        self.hwnd = W.user32.CreateWindowExW(
            0, app.PAGE_CLASS, "", W.WS_CHILD | W.WS_CLIPCHILDREN | W.WS_CLIPSIBLINGS,
            rc.left, rc.top, max(rc.right - rc.left, 1), max(rc.bottom - rc.top, 1), app.hwnd, None, app.hinst, None)
        if not self.hwnd:
            raise RecorderError(f"記録用ブラウザのタブを作れません (エラー {ctypes_last_error()})")
        app.pages[self.hwnd] = self
        self.site = self._make_site()
        self.sink = self._make_sink()
        ole = W.c_void_p()
        hr = W.ole32.CoCreateInstance(W.byref(W.CLSID_WebBrowser), None, W.CLSCTX_INPROC_SERVER, W.byref(W.IID_IOleObject), W.byref(ole))
        if hr != 0:
            raise RecorderError(f"IE エンジンを開けません (0x{hr & 0xFFFFFFFF:08x})")
        self.ole = int(ole.value)
        site = self.site.ptr(W.IID_IOleClientSite)
        W.vcall(self.ole, 3, W.HRESULT, [W.c_void_p], site)  # IOleObject::SetClientSite
        W.ole32.OleSetContainedObject(self.ole, True)
        crc = self.client_rect()
        hr = W.vcall(self.ole, 11, W.HRESULT, [W.c_long, W.c_void_p, W.c_void_p, W.c_long, W.wt.HWND, W.POINTER(W.wt.RECT)],
                     W.OLEIVERB_INPLACEACTIVATE, None, site, 0, self.hwnd, W.byref(crc))  # IOleObject::DoVerb
        if hr < 0:
            raise RecorderError(f"IE エンジンを表示できません (0x{hr & 0xFFFFFFFF:08x})")
        self.wb = W.qi(self.ole, W.IID_IWebBrowser2)
        self.inplace = W.qi(self.ole, W.IID_IOleInPlaceObject)
        cpc = W.qi(self.ole, W.IID_IConnectionPointContainer)
        cp = W.c_void_p()
        hr = W.vcall(cpc, 4, W.HRESULT, [W.POINTER(W.GUID), W.POINTER(W.c_void_p)], W.byref(W.DIID_DWebBrowserEvents2), W.byref(cp))
        W.release(cpc)
        if hr != 0 or not cp.value:
            raise RecorderError(f"IE エンジンのイベントを受け取れません (0x{hr & 0xFFFFFFFF:08x})")
        self.cp = int(cp.value)
        cookie = W.wt.DWORD()
        hr = W.vcall(self.cp, 5, W.HRESULT, [W.c_void_p, W.POINTER(W.wt.DWORD)], self.sink.ptr(W.IID_IDispatch), W.byref(cookie))
        if hr != 0:
            raise RecorderError(f"IE エンジンのイベントを受け取れません (0x{hr & 0xFFFFFFFF:08x})")
        self.cookie = int(cookie.value)

    # ------------------------------------------------------------------ helpers
    def client_rect(self) -> Any:
        rc = self.W.wt.RECT()
        self.W.user32.GetClientRect(self.hwnd, self.W.byref(rc))
        return rc

    def resize(self) -> None:
        if self.inplace and not self.closed:
            rc = self.client_rect()
            self.W.vcall(self.inplace, 7, self.W.HRESULT, [self.W.POINTER(self.W.wt.RECT)] * 2, self.W.byref(rc), self.W.byref(rc))

    def ui_activate(self) -> None:
        if self.ole and not self.closed:
            W = self.W
            crc = self.client_rect()
            try:
                W.vcall(self.ole, 11, W.HRESULT, [W.c_long, W.c_void_p, W.c_void_p, W.c_long, W.wt.HWND, W.POINTER(W.wt.RECT)],
                        W.OLEIVERB_UIACTIVATE, None, self.site.ptr(W.IID_IOleClientSite), 0, self.hwnd, W.byref(crc))
            except OSError:
                pass

    def navigate(self, url: str) -> None:
        self.W.disp_call(self.wb, "Navigate", url)

    def location(self) -> str:
        try:
            return str(self.W.disp_get(self.wb, "LocationURL") or "")
        except OSError:
            return ""

    def command(self, name: str, *args: Any) -> None:
        try:
            self.W.disp_call(self.wb, name, *args)
        except OSError as exc:
            self.app.log(f"{name} failed in {self.name}: {exc}")

    def eval(self, expression: str) -> str:
        """``eval`` in the page (the --selftest report); never raises."""
        W = self.W
        doc = script = 0
        try:
            doc = W.disp_get(self.wb, "Document")
            if not doc:
                return "(no document)"
            script = W.disp_get(doc, "Script")
            r = W.disp_call(script, "eval", expression)
            if isinstance(r, float) and r.is_integer():
                r = int(r)
            return "" if r is None else str(r)
        except Exception as exc:
            return f"(error {exc})"
        finally:
            W.release(script)
            W.release(doc)

    def call_page(self, function: str) -> Any:
        W = self.W
        doc = script = 0
        try:
            doc = W.disp_get(self.wb, "Document")
            script = W.disp_get(doc, "Script")
            return W.disp_call(script, function)
        finally:
            W.release(script)
            W.release(doc)

    def destroy(self) -> None:
        """Deactivate and release the control, then destroy the container window."""
        if self.closed:
            return
        self.closed = True
        W = self.W
        steps = (
            lambda: W.vcall(self.cp, 6, W.HRESULT, [W.wt.DWORD], self.cookie),       # Unadvise
            lambda: W.vcall(self.inplace, 5, W.HRESULT, []),                         # InPlaceDeactivate
            lambda: W.vcall(self.ole, 6, W.HRESULT, [W.wt.DWORD], W.OLECLOSE_NOSAVE),  # IOleObject::Close
            lambda: W.vcall(self.ole, 3, W.HRESULT, [W.c_void_p], None),             # SetClientSite(NULL)
        )
        for step in steps:
            try:
                step()
            except Exception as exc:
                self.app.log(f"destroy {self.name}: {exc}")
        for p in (self.cp, self.inplace, self.wb, self.ole):
            try:
                W.release(p)
            except Exception:
                pass
        self.cp = self.inplace = self.wb = self.ole = 0
        self.app.pages.pop(self.hwnd, None)
        W.user32.DestroyWindow(self.hwnd)

    # ------------------------------------------------------------------ the client site
    def _make_site(self) -> Any:
        W, app = self.W, self.app

        def get_window(this: Any, phwnd: Any) -> int:
            phwnd[0] = self.hwnd
            return W.S_OK

        def get_window_context(this: Any, pp_frame: Any, pp_doc: Any, prc_pos: Any, prc_clip: Any, frame_info: Any) -> int:
            pp_frame[0] = app.frame.ptr(W.IID_IOleInPlaceFrame)
            app.frame.refs += 1
            pp_doc[0] = None
            rc = self.client_rect()
            prc_pos[0] = rc
            prc_clip[0] = rc
            fi = frame_info.contents
            fi.fMDIApp, fi.hwndFrame, fi.haccel, fi.cAccelEntries = False, app.hwnd, None, 0
            return W.S_OK

        def on_ui_activate(this: Any) -> int:
            app.on_ui_activate(self)
            return W.S_OK

        def query_status(this: Any, pguid: Any, count: Any, cmds: Any, text: Any) -> int:
            return W.OLECMDERR_E_UNKNOWNGROUP if pguid else W.OLECMDERR_E_NOTSUPPORTED

        def exec_(this: Any, pguid: Any, cmd: int, opt: int, pva_in: Any, pva_out: Any) -> int:
            if pguid:
                group = bytes(W.cast(W.c_void_p(pguid), W.POINTER(W.GUID))[0])
                if group == bytes(W.CGID_DocHostCommandHandler) and cmd == W.OLECMDID_SHOWSCRIPTERROR:
                    # a script error on a legacy page: no dialog, the page's scripts keep running
                    if pva_out:
                        v = W.cast(W.c_void_p(pva_out), W.POINTER(W.VARIANT))[0]
                        v.vt, v.u.boolVal = W.VT_BOOL, -1
                    app.log("script error suppressed in " + self.name)
                    return W.S_OK
                return W.OLECMDERR_E_NOTSUPPORTED if group == bytes(W.CGID_DocHostCommandHandler) else W.OLECMDERR_E_UNKNOWNGROUP
            if cmd == W.OLECMDID_CLOSE:
                # window.close(): deferred, the engine is still inside the call
                app.log(f"OLECMDID_CLOSE {self.name} (window.close)")
                W.user32.PostMessageW(app.hwnd, W.WM_APP_CLOSE_TAB, self.hwnd, 0)
                return W.S_OK
            return W.OLECMDERR_E_NOTSUPPORTED

        P = W.P
        site = W.ComObject(self.name + ".site", app.log)
        site.implement([W.IID_IOleClientSite], [
            (P(), lambda this: W.E_NOTIMPL),                                                       # SaveObject
            (P(W.wt.DWORD, W.wt.DWORD, W.POINTER(W.c_void_p)), lambda this, a, w, pp: W.null_out(pp, W.E_NOTIMPL)),  # GetMoniker
            (P(W.POINTER(W.c_void_p)), lambda this, pp: W.null_out(pp, W.E_NOINTERFACE)),          # GetContainer
            (P(), lambda this: W.S_OK),                                                            # ShowObject
            (P(W.wt.BOOL), lambda this, show: W.S_OK),                                             # OnShowWindow
            (P(), lambda this: W.E_NOTIMPL),                                                       # RequestNewObjectLayout
        ])
        site.implement([W.IID_IOleInPlaceSite, W.IID_IOleWindow], [
            (P(W.POINTER(W.wt.HWND)), get_window),                                                 # GetWindow
            (P(W.wt.BOOL), lambda this, mode: W.E_NOTIMPL),                                        # ContextSensitiveHelp
            (P(), lambda this: W.S_OK),                                                            # CanInPlaceActivate
            (P(), lambda this: W.S_OK),                                                            # OnInPlaceActivate
            (P(), on_ui_activate),                                                                 # OnUIActivate
            (P(W.POINTER(W.c_void_p), W.POINTER(W.c_void_p), W.POINTER(W.wt.RECT), W.POINTER(W.wt.RECT),
               W.POINTER(W.OLEINPLACEFRAMEINFO)), get_window_context),                             # GetWindowContext
            (P(*W.SCROLL_ARGS), lambda this, *size: W.E_NOTIMPL),                                  # Scroll
            (P(W.wt.BOOL), lambda this, undoable: W.S_OK),                                         # OnUIDeactivate
            (P(), lambda this: W.S_OK),                                                            # OnInPlaceDeactivate
            (P(), lambda this: W.E_NOTIMPL),                                                       # DiscardUndoState
            (P(), lambda this: W.E_NOTIMPL),                                                       # DeactivateAndUndo
            (P(W.POINTER(W.wt.RECT)), lambda this, rc: W.S_OK),                                    # OnPosRectChange
        ])
        site.implement([W.IID_IOleCommandTarget], [
            (P(W.c_void_p, W.c_ulong, W.c_void_p, W.c_void_p), query_status),                      # QueryStatus
            (P(W.c_void_p, W.wt.DWORD, W.wt.DWORD, W.c_void_p, W.c_void_p), exec_),                # Exec
        ])
        return site

    # ------------------------------------------------------------------ DWebBrowserEvents2 (IDispatch)
    def _make_sink(self) -> Any:
        W = self.W

        def get_type_info_count(this: Any, pct: Any) -> int:
            pct[0] = 0
            return W.S_OK

        P = W.P
        sink = W.ComObject(self.name + ".events", self.app.log)
        sink.implement([W.IID_IDispatch, W.DIID_DWebBrowserEvents2], [
            (P(W.POINTER(W.c_uint)), get_type_info_count),                                         # GetTypeInfoCount
            (P(W.c_uint, W.c_ulong, W.POINTER(W.c_void_p)), lambda this, i, lcid, pp: W.null_out(pp, W.E_NOTIMPL)),
            (P(W.POINTER(W.GUID), W.c_void_p, W.c_uint, W.c_ulong, W.POINTER(W.c_long)), lambda *a: W.E_NOTIMPL),
            (P(W.c_long, W.POINTER(W.GUID), W.c_ulong, W.c_ushort, W.POINTER(W.DISPPARAMS), W.c_void_p, W.c_void_p,
               W.c_void_p), self._invoke),                                                         # Invoke
        ])
        return sink

    def _invoke(self, this: Any, dispid: int, riid: Any, lcid: Any, flags: Any, pparams: Any, *rest: Any) -> int:
        W, app = self.W, self.app
        if self.closed:
            return W.S_OK
        params = pparams[0] if pparams else None
        n = params.cArgs if params else 0
        args = [params.rgvarg[n - 1 - i] for i in range(n)]  # declaration order
        top = lambda: same_object_safe(W, W.from_variant(args[0]), self.ole)  # noqa: E731
        if dispid == W.DISPID_NEWWINDOW3 and n >= 5:
            url = W.from_variant(args[4]) or ""
            app.log(f"NewWindow3 from {self.name} flags=0x{(W.from_variant(args[2]) or 0) & 0xFFFFFFFF:x} url={url}")
            app.host_popup(args[0], args[1], url)
        elif dispid == W.DISPID_NEWWINDOW2 and n >= 2:
            app.log("NewWindow2 from " + self.name)
            app.host_popup(args[0], args[1], "")
        elif dispid == W.DISPID_WINDOWCLOSING:
            app.log("WindowClosing " + self.name)
            W.user32.PostMessageW(app.hwnd, W.WM_APP_CLOSE_TAB, self.hwnd, 0)
        elif dispid == W.DISPID_FILEDOWNLOAD and n >= 1 and not W.from_variant(args[0]):
            app.log(f"FileDownload {self.name} (file download)")
            app.status("このダウンロード (https://) は記録されません" if self.location().lower().startswith("https:") else "ダウンロードを記録しました")
        elif dispid == W.DISPID_TITLECHANGE and n >= 1:
            title = str(W.from_variant(args[0]) or "")
            self.title = title
            app.set_tab_text(self)
            if not self.title_announced and title.strip() and not title.lower().startswith(("http://", "https://", "about:")):
                self.title_announced = True
                app.status("新しいタブ: " + _shorten(title.strip(), app.MAX_TAB_TEXT))
        elif dispid == W.DISPID_COMMANDSTATECHANGE and n >= 2:
            command, enabled = W.from_variant(args[0]), bool(W.from_variant(args[1]))
            if command == W.CSC_NAVIGATEBACK:
                self.can_back = enabled
            elif command == W.CSC_NAVIGATEFORWARD:
                self.can_forward = enabled
            if app.active is self:
                app.update_toolbar()
        elif dispid == W.DISPID_NAVIGATECOMPLETE2 and n >= 2 and top():
            url = str(W.from_variant(args[1]) or "")
            app.log(f"Navigated {self.name} -> {url}")
            if url.lower().startswith("https:"):
                app.status("このページ (https://) は記録されません。http:// のページで操作してください")
            if app.active is self:
                app.update_toolbar()
        elif dispid == W.DISPID_DOCUMENTCOMPLETE and n >= 2 and top():
            url = str(W.from_variant(args[1]) or "")
            app.log(f"DocumentComplete {self.name} {url}")
            app.set_tab_text(self)
            if app.active is self:
                app.update_toolbar()
            app.document_complete(self, url)
        return W.S_OK


def same_object_safe(W: Any, a: Any, b: Any) -> bool:
    try:
        return W.same_object(a, b)
    except Exception:
        return False


def ctypes_last_error() -> int:
    import ctypes

    return int(ctypes.get_last_error())


def _shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class RecBrowserApp:
    """The recording browser window: toolbar, tabs (one WebBrowser control each), status bar.

    ``run()`` sets the per-process proxy (and the 表示モード User-Agent), opens the window at ``url``,
    calls ``ready()`` and runs the message loop until the window closes; it returns the exit code.
    ``stop()`` may be called from any thread (stdin control): the window closes like [記録をおわる].
    """

    MAIN_CLASS = "ReqrecRecBrowser"
    PAGE_CLASS = "ReqrecRecBrowserPage"
    RECORDING_TEXT = "● 記録中 — このウィンドウで開いた http:// のページの通信を記録しています（https:// は記録されません）"
    MAX_TAB_TEXT = 40
    #: Page functions ``--selftest`` calls on the first page, in this order (tests/ie_support.py's site).
    SELFTEST_FUNCTIONS = ("doOpen", "doBlankPost", "doBlankLink", "doModeless", "doModal", "doClosePopup")
    ID_BACK, ID_FORWARD, ID_RELOAD, ID_CLOSE_TAB, ID_STOP, ID_ADDRESS, ID_TABS, ID_STATUS = range(101, 109)
    TIMER_SELFTEST, TIMER_GUARD, TIMER_CLOSE_RETRY = 1, 2, 3

    def __init__(
        self,
        proxy_address: str,
        url: Optional[str] = None,
        title: str = BROWSER_TITLE,
        emulation: str = "default",
        bypass: str = "",
        log: Optional[_RecLog] = None,
        ready: Optional[Callable[[], None]] = None,
        selftest: bool = False,
        seconds: int = 30,
        functions: Optional[Sequence[str]] = None,
        force_exit: Optional[Callable[[int], None]] = None,
    ) -> None:
        self.W = _rb_win32()
        #: Last resort when a modal dialog will not let the window close: end the process (the
        #: recording is on disk; ``run_recorder`` passes a function that writes it once more first).
        self._force_exit: Callable[[int], None] = force_exit or os._exit
        self.proxy_address = proxy_address
        self.start_url = (url or "").strip() or "about:blank"
        self.title = title or BROWSER_TITLE
        self.emulation = emulation if emulation in EMULATION_MODES else "default"
        self.bypass = bypass or ""
        self._log = log or _RecLog(None)
        self._ready = ready
        self.selftest = bool(selftest)
        self.seconds = max(1, int(seconds))
        self.functions = tuple(functions) if functions else self.SELFTEST_FUNCTIONS
        self.hwnd = 0
        self.hinst = self.W.kernel32.GetModuleHandleW(None)
        self.tabs: list[_RecBrowserTab] = []
        self.pages: dict[int, _RecBrowserTab] = {}
        self.retired: list[_RecBrowserTab] = []  # closed tabs: their COM objects stay alive (late calls)
        self.active: Optional[_RecBrowserTab] = None
        self.ui_active: Optional[_RecBrowserTab] = None
        self.active_object = 0
        self.counter = 0
        self.exit_code = RECORD_EXIT_OK
        self.quitting = False
        self.selftest_started = False
        self.busy = False
        self.steps: list[Callable[[], None]] = []
        self.close_retries = 0
        self.stop_requested = False
        self._keep: list = []
        self.controls: dict[str, int] = {}
        self.font = self.bold_font = 0
        self.status_text = ""

    # ------------------------------------------------------------------ logging / status
    def log(self, text: str) -> None:
        self._log.write(text)

    def status(self, text: str) -> None:
        self.status_text = text
        self.log("status: " + text)
        bar = self.controls.get("status")
        if bar:
            self.W.user32.SendMessageW(bar, self.W.SB_SETTEXTW, 1, self._wide(text))

    def _wide(self, text: str) -> int:
        buf = self.W.ctypes.create_unicode_buffer(text)
        self._keep.append(buf)
        if len(self._keep) > 200:
            del self._keep[:100]
        return self.W.addressof(buf)

    # ------------------------------------------------------------------ process-wide options (this process only)
    def _set_process_options(self) -> bool:
        W = self.W

        def option(opt: int, buf: Any = None, size: int = 0) -> tuple[bool, int]:
            ok = W.wininet.InternetSetOptionA(None, opt, buf, size)
            return bool(ok), (0 if ok else ctypes_last_error())

        ok, err = option(W.INTERNET_OPTION_END_BROWSER_SESSION)
        self.log("end browser session -> " + ("ok" if ok else f"FAILED (error {err})"))
        suppress = W.wt.DWORD(W.INTERNET_SUPPRESS_COOKIE_PERSIST)
        ok, err = option(W.INTERNET_OPTION_SUPPRESS_BEHAVIOR, W.byref(suppress), W.sizeof(suppress))
        self.log("suppress cookie persist -> " + ("ok" if ok else f"FAILED (error {err})"))
        info = W.INTERNET_PROXY_INFO(W.INTERNET_OPEN_TYPE_PROXY, self.proxy_address.encode("ascii"), self.bypass.encode("ascii"))
        self._keep_forever = [info]  # WinINet may keep pointing at these strings
        ok, err = option(W.INTERNET_OPTION_PROXY, W.byref(info), W.sizeof(info))
        self.log(f"proxy {self.proxy_address} -> " + ("ok" if ok else f"FAILED (error {err})"))
        if not ok:
            self.proxy_error = err
            return False
        self.log(f'proxy bypass="{self.bypass}"')
        info2 = W.INTERNET_PROXY_INFO(W.INTERNET_OPEN_TYPE_PROXY, self.proxy_address.encode("ascii"), self.bypass.encode("ascii"))
        self._keep_forever.append(info2)
        hr = W.urlmon.UrlMkSetSessionOption(W.INTERNET_OPTION_PROXY, W.byref(info2), W.sizeof(info2), 0)
        self.log(f"urlmon proxy -> hr=0x{hr & 0xFFFFFFFF:x}")
        if self.emulation != "default":
            buf = W.ctypes.create_string_buffer(512)
            size = W.wt.DWORD(512)
            default_ua = buf.value.decode("latin-1") if W.urlmon.ObtainUserAgentString(0, buf, W.byref(size)) == 0 else ""
            ua = emulation_user_agent(default_ua, self.emulation)
            if ua:
                ua_buf = W.ctypes.create_string_buffer(ua.encode("latin-1"))
                self._keep_forever.append(ua_buf)
                hr = W.urlmon.UrlMkSetSessionOption(W.URLMON_OPTION_USERAGENT, ua_buf, len(ua), 0)
                self.log(f"user agent ({self.emulation}) {ua} -> hr=0x{hr & 0xFFFFFFFF:x}")
            self.log(f"表示モード {self.emulation}: X-UA-Compatible {EMULATION_MODES[self.emulation]}")
        return True

    # ------------------------------------------------------------------ window, controls, fonts
    def _visual_styles(self) -> None:
        """Common controls 6 (themed buttons / tabs) for this thread: an activation context made from a
        temporary manifest (the same thing ``Application.EnableVisualStyles`` does).  Optional."""
        W = self.W
        manifest = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><dependency><dependentAssembly>'
                    '<assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" '
                    'processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>'
                    '</dependentAssembly></dependency></assembly>')
        path = ""
        try:
            fd, path = tempfile.mkstemp(prefix="reqrec-", suffix=".manifest")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(manifest)
            ctx = W.ACTCTXW()
            ctx.cbSize = W.sizeof(W.ACTCTXW)
            ctx.lpSource = path
            handle = W.kernel32.CreateActCtxW(W.byref(ctx))
            if handle and handle != W.c_void_p(-1).value:
                cookie = W.c_size_t()
                ok = W.kernel32.ActivateActCtx(handle, W.byref(cookie))
                self.log("visual styles -> " + ("ok" if ok else "FAILED"))
        except Exception as exc:
            self.log(f"visual styles -> FAILED ({exc})")
        finally:
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        try:
            comctl32 = W.ctypes.WinDLL("comctl32")
            icc = W.INITCOMMONCONTROLSEX(W.sizeof(W.INITCOMMONCONTROLSEX), W.ICC_BAR_CLASSES | W.ICC_TAB_CLASSES | W.ICC_STANDARD_CLASSES)
            comctl32.InitCommonControlsEx.argtypes = [W.POINTER(W.INITCOMMONCONTROLSEX)]
            comctl32.InitCommonControlsEx(W.byref(icc))
        except Exception as exc:
            self.log(f"common controls -> FAILED ({exc})")

    def _fonts(self) -> None:
        W = self.W
        ncm = W.NONCLIENTMETRICSW()
        ncm.cbSize = W.sizeof(W.NONCLIENTMETRICSW)
        lf = W.LOGFONTW()
        if W.user32.SystemParametersInfoW(W.SPI_GETNONCLIENTMETRICS, ncm.cbSize, W.byref(ncm), 0):
            lf = ncm.lfMessageFont
        else:
            lf.lfFaceName = "Meiryo UI"
        lf.lfHeight = min(int(lf.lfHeight) if lf.lfHeight else -13, -13)  # at least 10 pt
        self.font = W.gdi32.CreateFontIndirectW(W.byref(lf))
        bold = W.LOGFONTW.from_buffer_copy(lf)
        bold.lfWeight = 700
        bold.lfHeight = lf.lfHeight - 3
        self.bold_font = W.gdi32.CreateFontIndirectW(W.byref(bold))
        self.font_height = abs(int(lf.lfHeight))

    def _text_width(self, text: str, font: int) -> int:
        W = self.W
        dc = W.user32.GetDC(self.hwnd)
        try:
            old = W.gdi32.SelectObject(dc, font)
            size = W.wt.SIZE()
            W.gdi32.GetTextExtentPoint32W(dc, text, len(text), W.byref(size))
            W.gdi32.SelectObject(dc, old)
            return int(size.cx)
        finally:
            W.user32.ReleaseDC(self.hwnd, dc)

    def _register_classes(self) -> None:
        W = self.W
        self.main_proc = W.WNDPROC(self._main_proc)
        self.page_proc = W.WNDPROC(self._page_proc)
        icon = W.user32.LoadIconW(None, W.c_void_p(32512))  # IDI_APPLICATION
        cursor = W.user32.LoadCursorW(None, W.c_void_p(32512))  # IDC_ARROW
        for name, proc, brush in ((self.MAIN_CLASS, self.main_proc, 16), (self.PAGE_CLASS, self.page_proc, 6)):
            wc = W.WNDCLASSEXW()
            wc.cbSize = W.sizeof(W.WNDCLASSEXW)
            wc.lpfnWndProc = proc
            wc.hInstance = self.hinst
            wc.hIcon = icon
            wc.hCursor = cursor
            wc.hbrBackground = brush  # COLOR_BTNFACE + 1 / COLOR_WINDOW + 1
            wc.lpszClassName = name
            if not W.user32.RegisterClassExW(W.byref(wc)) and ctypes_last_error() != 1410:  # 1410 = already registered
                raise RecorderError(f"記録用ブラウザの窓を登録できません (エラー {ctypes_last_error()})")
            self._keep.append(wc)

    def _create_window(self) -> None:
        W = self.W
        work = W.wt.RECT()
        if not W.user32.SystemParametersInfoW(W.SPI_GETWORKAREA, 0, W.byref(work), 0):
            work = W.wt.RECT(0, 0, 1280, 800)
        width = min(1100, work.right - work.left - 20)
        height = min(800, work.bottom - work.top - 20)
        x = work.left + (work.right - work.left - width) // 2
        y = work.top + (work.bottom - work.top - height) // 2
        self.hwnd = W.user32.CreateWindowExW(0, self.MAIN_CLASS, f"{self.title} — 記録中", W.WS_OVERLAPPEDWINDOW | W.WS_CLIPCHILDREN,
                                             x, y, width, height, None, None, self.hinst, None)
        if not self.hwnd:
            raise RecorderError(f"記録用ブラウザの窓を作れません (エラー {ctypes_last_error()})")
        self._fonts()

        def child(key: str, cls: str, text: str, style: int, ident: int, ex: int = 0) -> int:
            h = W.user32.CreateWindowExW(ex, cls, text, W.WS_CHILD | W.WS_VISIBLE | style, 0, 0, 10, 10, self.hwnd, ident, self.hinst, None)
            if not h:
                raise RecorderError(f"記録用ブラウザの部品を作れません: {cls} (エラー {ctypes_last_error()})")
            W.user32.SendMessageW(h, W.WM_SETFONT, self.bold_font if key == "stop" else self.font, 1)
            self.controls[key] = h
            return h

        child("back", "BUTTON", "← 戻る", W.BS_PUSHBUTTON | W.WS_TABSTOP, self.ID_BACK)
        child("forward", "BUTTON", "→ 進む", W.BS_PUSHBUTTON | W.WS_TABSTOP, self.ID_FORWARD)
        child("reload", "BUTTON", "更新", W.BS_PUSHBUTTON | W.WS_TABSTOP, self.ID_RELOAD)
        child("address", "EDIT", "", W.ES_AUTOHSCROLL | W.WS_TABSTOP, self.ID_ADDRESS, W.WS_EX_CLIENTEDGE)
        child("close_tab", "BUTTON", "タブを閉じる", W.BS_PUSHBUTTON | W.WS_TABSTOP, self.ID_CLOSE_TAB)
        child("stop", "BUTTON", "■ 記録をおわる", W.BS_OWNERDRAW | W.WS_TABSTOP, self.ID_STOP)
        child("tabs", "SysTabControl32", "", W.WS_CLIPSIBLINGS, self.ID_TABS)
        child("status", "msctls_statusbar32", "", 0, self.ID_STATUS)
        # Enter in the address box opens the address: the EDIT's own window procedure is wrapped
        self.edit_proc = W.WNDPROC(self._address_proc)
        self.edit_old = W.set_window_long(self.controls["address"], W.GWLP_WNDPROC, W.cast(self.edit_proc, W.c_void_p))
        W.user32.SendMessageW(self.controls["status"], W.SB_SETTEXTW, W.SBT_OWNERDRAW, 0)  # part 0: drawn in red
        self.layout()
        W.user32.ShowWindow(self.hwnd, W.SW_SHOW)
        W.user32.SetForegroundWindow(self.hwnd)  # may be refused by Windows' foreground rules: harmless

    def layout(self) -> None:
        W = self.W
        if not self.hwnd or not self.controls:
            return
        rc = W.wt.RECT()
        W.user32.GetClientRect(self.hwnd, W.byref(rc))
        width = rc.right - rc.left
        pad = 6
        row = max(self.font_height + 16, 30)
        x = pad
        for key, text in (("back", "← 戻る"), ("forward", "→ 進む"), ("reload", "更新")):
            w = self._text_width(text, self.font) + 26
            W.user32.MoveWindow(self.controls[key], x, pad, w, row, True)
            x += w + 4
        stop_w = self._text_width("■ 記録をおわる", self.bold_font) + 40
        close_w = self._text_width("タブを閉じる", self.font) + 26
        stop_x = width - pad - stop_w
        close_x = stop_x - 8 - close_w
        W.user32.MoveWindow(self.controls["stop"], stop_x, pad, stop_w, row, True)
        W.user32.MoveWindow(self.controls["close_tab"], close_x, pad, close_w, row, True)
        edit_h = self.font_height + 10
        W.user32.MoveWindow(self.controls["address"], x + 4, pad + (row - edit_h) // 2, max(close_x - 8 - (x + 4), 40), edit_h, True)
        top = pad * 2 + row
        status = self.controls["status"]
        W.user32.SendMessageW(status, W.WM_SIZE, 0, 0)
        src = W.wt.RECT()
        W.user32.GetWindowRect(status, W.byref(src))
        status_h = src.bottom - src.top
        parts = (W.c_int * 2)(max(width - 340, 100), -1)
        W.user32.SendMessageW(status, W.SB_SETPARTS, 2, W.addressof(parts))
        W.user32.SendMessageW(status, W.SB_SETTEXTW, W.SBT_OWNERDRAW, 0)
        W.user32.SendMessageW(status, W.SB_SETTEXTW, 1, self._wide(self.status_text))
        W.user32.MoveWindow(self.controls["tabs"], 0, top, width, max(rc.bottom - top - status_h, 50), True)
        page = self.page_rect()
        for tab in self.tabs:
            W.user32.MoveWindow(tab.hwnd, page.left, page.top, max(page.right - page.left, 1), max(page.bottom - page.top, 1), True)

    def page_rect(self) -> Any:
        """Client coordinates (of the main window) of the area a tab's page fills."""
        W = self.W
        tabs = self.controls.get("tabs")
        rc = W.wt.RECT()
        if not tabs:
            W.user32.GetClientRect(self.hwnd, W.byref(rc))
            return rc
        W.user32.GetWindowRect(tabs, W.byref(rc))
        W.user32.MapWindowPoints(None, self.hwnd, W.byref(rc), 2)
        W.user32.SendMessageW(tabs, W.TCM_ADJUSTRECT, 0, W.addressof(rc))
        return rc

    # ------------------------------------------------------------------ tabs
    def new_tab(self, popup: bool) -> _RecBrowserTab:
        W = self.W
        tab = _RecBrowserTab(self, popup)
        self.tabs.append(tab)
        item = W.TCITEMW()
        item.mask = W.TCIF_TEXT | W.TCIF_PARAM
        item.pszText = "新しいタブ"
        item.lParam = tab.hwnd
        W.user32.SendMessageW(self.controls["tabs"], W.TCM_INSERTITEMW, len(self.tabs) - 1, W.addressof(item))
        self.layout()  # the first item gives the tab control its strip: the pages move below it
        self.select(tab)
        tab.resize()
        if popup:
            self.status("新しいタブを開きました")
        self.log(f"new tab {tab.name}{' (popup)' if popup else ''} handle=0x{tab.hwnd:x}")
        return tab

    def select(self, tab: _RecBrowserTab) -> None:
        W = self.W
        if tab not in self.tabs:
            return
        self.active = tab
        W.user32.SendMessageW(self.controls["tabs"], W.TCM_SETCURSEL, self.tabs.index(tab), 0)
        for other in self.tabs:
            if other is not tab:
                W.user32.ShowWindow(other.hwnd, W.SW_HIDE)
        W.user32.SetWindowPos(tab.hwnd, W.HWND_TOP, 0, 0, 0, 0, W.SWP_NOMOVE | W.SWP_NOSIZE)
        W.user32.ShowWindow(tab.hwnd, W.SW_SHOW)
        self.update_toolbar()

    def set_tab_text(self, tab: _RecBrowserTab) -> None:
        W = self.W
        if tab not in self.tabs:
            return
        text = (tab.title or "").strip()
        if not text or text.lower().startswith(("http://", "https://")):
            host = urlsplit(tab.location()).hostname or ""
            text = text or host
        text = _shorten(text or "新しいタブ", self.MAX_TAB_TEXT)
        item = W.TCITEMW()
        item.mask = W.TCIF_TEXT
        item.pszText = text
        W.user32.SendMessageW(self.controls["tabs"], W.TCM_SETITEMW, self.tabs.index(tab), W.addressof(item))

    def close_tab(self, tab: _RecBrowserTab) -> None:
        W = self.W
        if tab not in self.tabs:
            return
        self.log("close tab " + tab.name)
        index = self.tabs.index(tab)
        W.user32.SendMessageW(self.controls["tabs"], W.TCM_DELETEITEM, index, 0)
        self.tabs.remove(tab)
        if self.ui_active is tab:
            self.ui_active = None
        tab.destroy()
        self.retired.append(tab)
        if self.quitting:
            return
        if not self.tabs:  # never leave the window without a tab
            fresh = self.new_tab(popup=False)
            fresh.navigate("about:blank")
        else:
            self.select(self.tabs[min(index, len(self.tabs) - 1)])

    def host_popup(self, ppdisp_var: Any, cancel_var: Any, url: str) -> None:
        """Answer NewWindow2/3 with a fresh control in a new tab: the engine navigates it itself, so
        opener, window name, session and POST body survive."""
        W = self.W
        slot = W.cast(W.c_void_p(ppdisp_var.u.byref), W.POINTER(W.c_void_p))
        if slot[0]:
            self.log("  -> already hosted")
            return
        try:
            target = self.new_tab(popup=True)
            if url.lower().startswith(("http://", "https://")):
                # Without this a window.open(url) popup of a page in IE9+ mode comes up in quirks
                # mode (see the section comment); the engine's own navigation replaces about:blank.
                target.navigate("about:blank")
            disp = W.qi(target.ole, W.IID_IDispatch)  # this reference passes to the engine
            if not disp:
                raise RecorderError("no IDispatch")
        except Exception as exc:
            self.log(f"  -> new tab FAILED: {exc}")
            W.cast(W.c_void_p(cancel_var.u.byref), W.POINTER(W.c_short))[0] = -1
            return
        slot[0] = disp
        self.log("  -> hosted in " + target.name)

    def on_ui_activate(self, tab: _RecBrowserTab) -> None:
        W = self.W
        previous = self.ui_active
        self.ui_active = tab
        if previous is not None and previous is not tab and previous.inplace and not previous.closed:
            try:
                W.vcall(previous.inplace, 6, W.HRESULT, [])  # IOleInPlaceObject::UIDeactivate
            except OSError:
                pass

    # ------------------------------------------------------------------ toolbar
    def update_toolbar(self) -> None:
        W = self.W
        tab = self.active
        url = tab.location() if tab is not None else ""
        if url == "about:blank":
            url = ""
        address = self.controls.get("address")
        if address and (W.user32.GetFocus() != address or W.user32.GetWindowTextLengthW(address) == 0):
            W.user32.SetWindowTextW(address, url)
        W.user32.EnableWindow(self.controls["back"], bool(tab and tab.can_back))
        W.user32.EnableWindow(self.controls["forward"], bool(tab and tab.can_forward))

    def address_text(self) -> str:
        W = self.W
        address = self.controls["address"]
        n = W.user32.GetWindowTextLengthW(address)
        buf = W.ctypes.create_unicode_buffer(n + 1)
        W.user32.GetWindowTextW(address, buf, n + 1)
        return buf.value

    def open_address(self, text: str) -> None:
        target = (text or "").strip()
        if not target or self.active is None:
            return
        if "://" not in target and not target.lower().startswith("about:"):
            target = "http://" + target
        try:
            self.active.navigate(target)
        except OSError as exc:
            self.log(f"navigate failed: {exc}")
            self.status("このアドレスは開けません")

    # ------------------------------------------------------------------ window procedures
    def _address_proc(self, hwnd: Any, msg: int, wparam: int, lparam: int) -> int:
        W = self.W
        try:
            if msg == W.WM_KEYDOWN and wparam == W.VK_RETURN:
                self.open_address(self.address_text())
                return 0
            if msg == W.WM_CHAR and wparam in (13, 10):
                return 0  # no beep
        except Exception:
            self.log("address box error: " + traceback.format_exc().strip().replace("\n", " | "))
        return W.user32.CallWindowProcW(self.edit_old, hwnd, msg, wparam, lparam)

    def _page_proc(self, hwnd: Any, msg: int, wparam: int, lparam: int) -> int:
        W = self.W
        try:
            tab = self.pages.get(hwnd)
            if tab is not None:
                if msg == W.WM_SIZE:
                    tab.resize()
                    return 0
                if msg == W.WM_SETFOCUS:
                    tab.ui_activate()
                    return 0
        except Exception:
            self.log("page error: " + traceback.format_exc().strip().replace("\n", " | "))
        return W.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _main_proc(self, hwnd: Any, msg: int, wparam: int, lparam: int) -> int:  # noqa: C901 - a message switch
        W = self.W
        try:
            if msg == W.WM_SIZE:
                self.layout()
                return 0
            if msg == W.WM_GETMINMAXINFO:
                info = W.cast(W.c_void_p(lparam), W.POINTER(W.MINMAXINFO))[0]
                info.ptMinTrackSize.x, info.ptMinTrackSize.y = 640, 400
                return 0
            if msg == W.WM_COMMAND:
                self._command(wparam & 0xFFFF, (wparam >> 16) & 0xFFFF)
                return 0
            if msg == W.WM_NOTIFY:
                hdr = W.cast(W.c_void_p(lparam), W.POINTER(W.NMHDR))[0]
                if hdr.hwndFrom == self.controls.get("tabs") and hdr.code == W.TCN_SELCHANGE:
                    index = W.user32.SendMessageW(self.controls["tabs"], W.TCM_GETCURSEL, 0, 0)
                    if 0 <= index < len(self.tabs):
                        self.select(self.tabs[index])
                        self.tabs[index].ui_activate()
                return 0
            if msg == W.WM_DRAWITEM:
                self._draw(W.cast(W.c_void_p(lparam), W.POINTER(W.DRAWITEMSTRUCT))[0])
                return 1
            if msg == W.WM_SETFOCUS:
                if self.active is not None:
                    self.active.ui_activate()
                return 0
            if msg == W.WM_TIMER:
                self._timer(int(wparam))
                return 0
            if msg == W.WM_APP_CLOSE_TAB:
                tab = self.pages.get(int(wparam))
                if tab is not None:
                    self.close_tab(tab)
                return 0
            if msg in (W.WM_CLOSE, W.WM_APP_STOP):
                self.request_quit(self.exit_code)
                return 0
            if msg == W.WM_DESTROY:
                W.user32.PostQuitMessage(self.exit_code)
                return 0
        except Exception:
            self.log("window error: " + traceback.format_exc().strip().replace("\n", " | "))
        return W.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _command(self, ident: int, code: int) -> None:
        tab = self.active
        if ident == self.ID_BACK and tab is not None and tab.can_back:
            tab.command("GoBack")
        elif ident == self.ID_FORWARD and tab is not None and tab.can_forward:
            tab.command("GoForward")
        elif ident == self.ID_RELOAD and tab is not None:
            tab.command("Refresh")
        elif ident == self.ID_CLOSE_TAB and tab is not None:
            self.close_tab(tab)
        elif ident == self.ID_STOP:
            self.log("stop button")
            self.request_quit(RECORD_EXIT_OK)

    def _draw(self, item: Any) -> None:
        W = self.W
        if item.hwndItem == self.controls.get("stop"):
            pressed = bool(item.itemState & W.ODS_SELECTED)
            brush = W.gdi32.CreateSolidBrush(0x001E1EA0 if pressed else 0x001E1EC4)  # COLORREF = 0x00BBGGRR
            rc = W.wt.RECT(item.rcItem.left, item.rcItem.top, item.rcItem.right, item.rcItem.bottom)
            W.user32.FillRect(item.hDC, W.byref(rc), brush)
            W.gdi32.DeleteObject(brush)
            old = W.gdi32.SelectObject(item.hDC, self.bold_font)
            W.gdi32.SetBkMode(item.hDC, W.TRANSPARENT)
            W.gdi32.SetTextColor(item.hDC, 0x00FFFFFF)
            W.user32.DrawTextW(item.hDC, "■ 記録をおわる", -1, W.byref(rc), W.DT_CENTER | W.DT_VCENTER | W.DT_SINGLELINE)
            W.gdi32.SelectObject(item.hDC, old)
            if item.itemState & W.ODS_FOCUS:
                inner = W.wt.RECT(rc.left + 3, rc.top + 3, rc.right - 3, rc.bottom - 3)
                W.user32.DrawFocusRect(item.hDC, W.byref(inner))
        elif item.hwndItem == self.controls.get("status"):
            rc = W.wt.RECT(item.rcItem.left + 4, item.rcItem.top, item.rcItem.right - 2, item.rcItem.bottom)
            old = W.gdi32.SelectObject(item.hDC, self.font)
            W.gdi32.SetBkMode(item.hDC, W.TRANSPARENT)
            W.gdi32.SetTextColor(item.hDC, 0x000000AA)  # dark red
            W.user32.DrawTextW(item.hDC, self.RECORDING_TEXT, -1, W.byref(rc), W.DT_LEFT | W.DT_VCENTER | W.DT_SINGLELINE | W.DT_END_ELLIPSIS)
            W.gdi32.SelectObject(item.hDC, old)

    # ------------------------------------------------------------------ closing
    def stop(self) -> None:
        """Close the browser like its [記録をおわる] button (any thread; before the window exists, it
        closes as soon as it is open)."""
        self.stop_requested = True
        if self.hwnd:
            self.W.user32.PostMessageW(self.hwnd, self.W.WM_APP_STOP, 0, 0)

    def request_quit(self, code: int) -> None:
        """Close every tab and the window.  While a modal dialog (alert, showModalDialog, the download
        dialog) is open the window is disabled: the dialogs are asked to close first and closing is
        retried; after about 5 seconds the process ends anyway (the recording is on disk)."""
        W = self.W
        self.exit_code = code
        if self.quitting:
            return
        if not W.user32.IsWindowEnabled(self.hwnd) and self.close_retries < 20:
            self.close_retries += 1
            self._close_dialogs()
            W.user32.SetTimer(self.hwnd, self.TIMER_CLOSE_RETRY, 250, None)
            return
        if not W.user32.IsWindowEnabled(self.hwnd):
            self.log("modal dialog did not close -> exit anyway")
            self._force_exit(code)
            return
        self.quitting = True
        for tab in list(self.tabs):
            self.close_tab(tab)
        W.user32.DestroyWindow(self.hwnd)

    def _close_dialogs(self) -> None:
        W = self.W

        def each(hwnd: Any, lparam: Any) -> bool:
            buf = W.ctypes.create_unicode_buffer(64)
            W.user32.GetClassNameW(hwnd, buf, 64)
            if buf.value in ("#32770", "Internet Explorer_TridentDlgFrame") and W.user32.IsWindowVisible(hwnd):
                W.user32.PostMessageW(hwnd, W.WM_CLOSE, 0, 0)
            return True

        callback = W.ENUMWINDOWSPROC(each)
        W.user32.EnumThreadWindows(W.kernel32.GetCurrentThreadId(), callback, 0)

    # ------------------------------------------------------------------ timers / --selftest
    def _timer(self, ident: int) -> None:
        W = self.W
        if ident == self.TIMER_CLOSE_RETRY:
            W.user32.KillTimer(self.hwnd, self.TIMER_CLOSE_RETRY)
            self.request_quit(self.exit_code)
        elif ident == self.TIMER_GUARD:
            W.user32.KillTimer(self.hwnd, self.TIMER_GUARD)
            self.log(f"selftest: guard timeout after {self.seconds} s -> exit {RECORD_EXIT_TIMEOUT}")
            self.request_quit(RECORD_EXIT_TIMEOUT)
        elif ident == self.TIMER_SELFTEST and not self.busy:  # busy: a modal dialog's loop re-entered
            if not self.steps:
                W.user32.KillTimer(self.hwnd, self.TIMER_SELFTEST)
                return
            self.busy = True
            try:
                self.steps.pop(0)()
            except Exception as exc:
                self.log(f"selftest: step error: {exc}")
            finally:
                self.busy = False

    def document_complete(self, tab: _RecBrowserTab, url: str) -> None:
        if not self.selftest or self.selftest_started or tab is not (self.tabs[0] if self.tabs else None):
            return
        if not url or url == "about:blank":
            return
        self.selftest_started = True
        self.log("selftest: first page completed " + url)
        for fn in self.functions:
            self.steps.append(lambda fn=fn: self._selftest_call(tab, fn))
        self.steps.append(self._selftest_tabs)
        self.steps.append(self._selftest_done)
        self.W.user32.SetTimer(self.hwnd, self.TIMER_SELFTEST, 1500, None)

    def _selftest_call(self, tab: _RecBrowserTab, fn: str) -> None:
        if tab.eval("typeof " + fn) != "function":
            self.log(f"selftest: {fn} not present, skipped")
            return
        try:
            r = tab.call_page(fn)
            self.log(f"selftest: {fn} -> {'(null)' if r is None else r}")
        except Exception as exc:
            self.log(f"selftest: {fn} error: {exc}")

    def _selftest_tabs(self) -> None:
        self.log(f"selftest: tabs={len(self.tabs)}")
        for tab in self.tabs:
            url = tab.location() or "(none)"
            mode = tab.eval("document.documentMode")
            opener = tab.eval("window.opener ? 'yes' : 'no'")
            name = tab.eval("window.name")
            self.log(f"tab: {url} mode={mode} opener={opener} name={name}")

    def _selftest_done(self) -> None:
        self.log(f"selftest: done -> exit {RECORD_EXIT_OK}")
        self.request_quit(RECORD_EXIT_OK)

    # ------------------------------------------------------------------ run
    def run(self) -> int:
        W = self.W
        if not self._set_process_options():
            _record_error(f"記録用の中継設定に失敗したため、記録できません (エラー {getattr(self, 'proxy_error', '?')})。"
                          "もう一度 [記録をはじめる] を押してください。")
            return RECORD_EXIT_PROXY
        hr = W.ole32.OleInitialize(None)
        self.log(f"OleInitialize -> hr=0x{hr & 0xFFFFFFFF:x}")
        self._visual_styles()
        self._register_classes()
        self.frame = self._make_frame()
        self._create_window()
        self.log(f"title {self.title} — 記録中")
        first = self.new_tab(popup=False)
        if self.selftest:
            W.user32.SetTimer(self.hwnd, self.TIMER_GUARD, self.seconds * 1000, None)
        target = self.start_url
        if "://" not in target and not target.lower().startswith("about:"):
            target = "http://" + target
        first.navigate(target)
        first.ui_activate()
        if self._ready is not None:
            self._ready()
        if self.stop_requested:  # ``stop`` arrived while the window was being made
            W.user32.PostMessageW(self.hwnd, W.WM_APP_STOP, 0, 0)
        msg = W.wt.MSG()
        while True:
            r = W.user32.GetMessageW(W.byref(msg), None, 0, 0)
            if r == 0 or r == -1:
                break
            if W.WM_KEYFIRST <= msg.message <= W.WM_KEYLAST and self._pretranslate(msg):
                continue
            W.user32.TranslateMessage(W.byref(msg))
            W.user32.DispatchMessageW(W.byref(msg))
        self.log(f"window closed -> exit {self.exit_code}")
        return self.exit_code

    def _pretranslate(self, msg: Any) -> bool:
        """Keyboard messages for the page go to its active object first (Tab, Enter, Delete, Ctrl+C ...)."""
        W = self.W
        tab = self.ui_active or self.active
        if not self.active_object or tab is None or tab.closed:
            return False
        if msg.hWnd != tab.hwnd and not W.user32.IsChild(tab.hwnd, msg.hWnd):
            return False
        try:
            return W.vcall(self.active_object, 5, W.HRESULT, [W.POINTER(W.wt.MSG)], W.byref(msg)) == W.S_OK
        except OSError:
            return False

    def _make_frame(self) -> Any:
        W = self.W

        def get_window(this: Any, phwnd: Any) -> int:
            phwnd[0] = self.hwnd
            return W.S_OK

        def set_active_object(this: Any, active: Any, name: Any) -> int:
            old = self.active_object
            if active:
                W.addref(active)
            self.active_object = int(active or 0)
            if old:
                W.release(old)
            return W.S_OK

        P = W.P
        frame = W.ComObject("frame", self.log)
        frame.implement([W.IID_IOleInPlaceFrame, W.IID_IOleInPlaceUIWindow, W.IID_IOleWindow], [
            (P(W.POINTER(W.wt.HWND)), get_window),                                    # GetWindow
            (P(W.wt.BOOL), lambda this, mode: W.E_NOTIMPL),                           # ContextSensitiveHelp
            (P(W.POINTER(W.wt.RECT)), lambda this, rc: W.E_NOTIMPL),                  # GetBorder
            (P(W.c_void_p), lambda this, widths: W.E_NOTIMPL),                        # RequestBorderSpace
            (P(W.c_void_p), lambda this, widths: W.E_NOTIMPL),                        # SetBorderSpace
            (P(W.c_void_p, W.c_wchar_p), set_active_object),                          # SetActiveObject
            (P(W.c_void_p, W.c_void_p), lambda this, menu, widths: W.E_NOTIMPL),      # InsertMenus
            (P(W.c_void_p, W.c_void_p, W.wt.HWND), lambda this, m, o, h: W.S_OK),     # SetMenu
            (P(W.c_void_p), lambda this, menu: W.E_NOTIMPL),                          # RemoveMenus
            (P(W.c_wchar_p), lambda this, text: W.S_OK),                              # SetStatusText
            (P(W.wt.BOOL), lambda this, enable: W.S_OK),                              # EnableModeless
            (P(W.c_void_p, W.wt.WORD), lambda this, msg, ident: W.S_FALSE),           # TranslateAccelerator
        ])
        return frame


def _record_error(message: str) -> None:
    """A Japanese error line on stderr (the GUI shows the last one)."""
    try:
        print(message, file=sys.stderr, flush=True)
    except Exception:
        pass


# --------------------------------------------------------------------------- reqrec record (the child process)

def run_recorder(
    out: str,
    url: Optional[str] = None,
    title: str = BROWSER_TITLE,
    emulation: str = "default",
    log_path: Optional[str] = None,
    bypass: str = "",
    control: str = "none",
    selftest: bool = False,
    seconds: int = 30,
    headless: bool = False,
    functions: Optional[Sequence[str]] = None,
    ready: Optional[Callable[[int], None]] = None,
    browser: str = "ie",
) -> int:
    """Record until the recording browser is closed; returns an exit code (``RECORD_EXIT_*``).

    ``headless`` runs only the proxy (no window; tests and non-Windows checks): it stops on ``stop`` /
    the end of stdin (``control="stdin"``) or Ctrl+C.  ``ready(port)`` defaults to printing
    ``READY <port>`` on stdout.  ``browser``: ``ie`` (the recording browser) or ``edge`` (Microsoft Edge
    with a profile of its own, :func:`edge_command`; 表示モード does not apply).
    """
    if emulation not in EMULATION_MODES:
        _record_error(f"表示モードは {' / '.join(EMULATION_MODES)} のいずれかで指定してください: {emulation}")
        return RECORD_EXIT_USAGE
    if browser not in RECORD_BROWSERS:
        _record_error(f"記録に使うブラウザは {' / '.join(RECORD_BROWSERS)} のいずれかで指定してください: {browser}")
        return RECORD_EXIT_USAGE
    edge = browser == "edge"
    if not headless:
        availability = edge_availability() if edge else recorder_availability()
        if not availability["available"]:
            _record_error(str(availability["reason"]))
            return RECORD_EXIT_START
    log = _RecLog(log_path)
    log.write(f"reqrec record start (python {sys.version.split()[0]}, {struct.calcsize('P') * 8}-bit, pid {os.getpid()},"
              f" browser {browser})")
    try:
        meta = {"source": "edge", "browser": "edge"} if edge else {"emulation": emulation}
        store = RecordingStore(out, meta=meta).start()
    except OSError as exc:
        _record_error(f"記録ファイルを作成できません: {exc}")
        log.close()
        return RECORD_EXIT_START

    def on_flow(count: int, flow: Flow) -> None:
        status: Any = flow.response.status if flow.response is not None else "ERR"
        log.write(f"flow #{count} {flow.request.method} {truncate(flow.request.url, 160)} -> {status}")

    try:
        proxy = RecordingProxy(store, compat=None if edge else EMULATION_MODES[emulation], on_flow=on_flow)
    except OSError as exc:
        _record_error(f"記録用の中継を開始できません: {exc}")
        store.close()
        log.close()
        return RECORD_EXIT_PROXY
    proxy.start()
    address = f"{RECORD_LISTEN_HOST}:{proxy.port}"
    log.write(f"recording proxy listening on {address}")

    def announce() -> None:
        if ready is not None:
            ready(proxy.port)
            return
        try:
            # the pid too: a venv's python.exe is a launcher that runs the real interpreter as its child
            print(f"READY {proxy.port} {os.getpid()}", flush=True)
        except (OSError, ValueError, AttributeError):  # no stdout (pythonw without a pipe)
            pass

    finished: list[int] = []

    def finish(code: int) -> int:
        """Stop the proxy, write the recording one last time, close the log (once)."""
        if finished:
            return finished[0]
        finished.append(code)
        try:
            proxy.shutdown()
            proxy.server_close()
        except Exception:
            pass
        try:
            path = store.close()
            log.write(f"recording: {len(store)} flows -> {path}")
        except OSError as exc:
            _record_error(f"記録ファイルを書き込めません: {exc}")
        log.write(f"exit {code}")
        log.close()
        return code

    def force_exit(code: int) -> None:  # a modal dialog would not let the window close
        finish(code)
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(code)

    code = RECORD_EXIT_OK
    try:
        if headless:
            announce()
            _wait_for_stop(control)
        elif edge:
            code = _run_edge(proxy.port, url, log, control, announce)
        else:
            app = RecBrowserApp(address, url=url, title=title, emulation=emulation, bypass=bypass, log=log,
                                ready=announce, selftest=selftest, seconds=seconds, functions=functions,
                                force_exit=force_exit)
            if control == "stdin":
                threading.Thread(target=_stdin_control, args=(app,), name="reqrec-stdin", daemon=True).start()
            try:
                code = app.run()
            except Exception as exc:  # RecorderError (Japanese) or anything the engine raised
                _record_error(f"記録用ブラウザを開けませんでした: {exc}")
                log.write("fatal: " + traceback.format_exc().strip().replace("\n", " | "))
                code = RECORD_EXIT_START
    except KeyboardInterrupt:
        code = RECORD_EXIT_OK
    finally:
        code = finish(code)
    return code


def _run_edge(port: int, url: Optional[str], log: "_RecLog", control: str, announce: Callable[[], None],
              edge: Optional[str] = None) -> int:
    """Record with Microsoft Edge until its window is closed (all of our Edge processes ended) or ``stop``
    arrives (``--control stdin``: the GUI's [記録をおわる]); then our Edge is closed and its profile folder
    deleted.  ``READY`` is announced once Edge's window process runs."""
    edge = edge or find_edge()
    if edge is None:
        _record_error("この PC には Microsoft Edge (msedge.exe) が見つかりません。")
        return RECORD_EXIT_START
    profile = tempfile.mkdtemp(prefix="reqrec-edge-")
    stop = threading.Event()
    if control == "stdin":
        threading.Thread(target=_stdin_event, args=(stop,), name="reqrec-stdin", daemon=True).start()
    try:
        launcher = subprocess.Popen(edge_command(edge, port, url, profile), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        _record_error(f"Edge を起動できません: {exc}")
        _remove_profile(profile)
        return RECORD_EXIT_START
    log.write(f"edge started: {edge} (pid {launcher.pid}, profile {profile})")
    code = RECORD_EXIT_OK
    deadline = time.time() + EDGE_START_TIMEOUT
    seen = False
    try:
        while True:
            alive = _edge_processes(launcher.pid)
            if alive and not seen:
                seen = True
                announce()
            if seen and not alive:
                log.write("edge closed")
                break
            if not seen and time.time() > deadline:
                _record_error("Edge の窓が開きませんでした。もう一度 [記録をはじめる] を押してください。")
                code = RECORD_EXIT_START
                break
            if stop.wait(0.5):
                log.write("stop requested: closing edge")
                break
    finally:
        _stop_edge(launcher.pid)
        _remove_profile(profile)
    return code


def _stdin_event(stop: threading.Event) -> None:
    """``--control stdin`` for Edge: ``stop`` (or the end of stdin: the GUI went away) sets ``stop``."""
    try:
        for line in sys.stdin:
            if line.strip().lower() == "stop":
                break
    except (OSError, ValueError):
        pass
    stop.set()


def _wait_for_stop(control: str) -> None:
    """Headless mode: block until ``stop`` / the end of stdin (``control="stdin"``) or Ctrl+C."""
    if control == "stdin":
        for line in sys.stdin:
            if line.strip().lower() == "stop":
                return
        return
    while True:
        time.sleep(3600)


def _stdin_control(app: RecBrowserApp) -> None:
    """``--control stdin``: ``stop`` (or the end of stdin: the GUI went away) closes the browser."""
    try:
        for line in sys.stdin:
            if line.strip().lower() == "stop":
                break
    except (OSError, ValueError):
        pass
    app.stop()


# --------------------------------------------------------------------------- RecorderManager (the GUI's side)

#: Reading a very large recording with ``json.loads`` every second would hurt; above this size a
#: regular expression counts the flow ids instead.
_JSON_COUNT_MAX_BYTES = 24 * 1024 * 1024
_RECORDER_FLOW_ID_RE = re.compile(rb'"id":\s*"f\d{4,}"')
_READER_JOIN_TIMEOUT = 2.0

CommandBuilder = Callable[..., Sequence[str]]


def recorder_command(
    out: str,
    url: Optional[str] = None,
    emulation: str = "default",
    title: str = BROWSER_TITLE,
    log_path: Optional[str] = None,
    python: Optional[str] = None,
    browser: str = "ie",
) -> list[str]:
    """``python reqrec.py record ...`` for one recording, stopped through stdin."""
    cmd = [python or sys.executable or "python", SCRIPT_PATH, "record", "--out", os.path.abspath(out),
           "--control", "stdin", "--title", title, "--emulation", emulation]
    if browser != "ie":
        cmd += ["--browser", browser]
    if url:
        cmd += ["--url", str(url)]
    if log_path:
        cmd += ["--log", log_path]
    return cmd


def count_flows_in_file(path: str, default: int = 0) -> int:
    """Number of flows in a recording JSON file (``default`` when it cannot be read yet)."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return default
    if not raw:
        return default
    if size > _JSON_COUNT_MAX_BYTES:
        return len(_RECORDER_FLOW_ID_RE.findall(raw))
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        return default
    if not isinstance(data, dict):
        return default
    flows = data.get("flows")
    return len(flows) if isinstance(flows, list) else default


def _wait(proc: Any, timeout: float) -> Optional[int]:
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


class RecorderManager:
    """The GUI's recording: one ``reqrec record`` child process (recording browser + proxy).

    ``start`` spawns it (``command_builder`` / ``popen`` are injectable), ``wait_until_ready`` waits for
    its ``READY <port>`` line, ``status`` reports the live flow count read from the recording file,
    ``stop`` ends it gracefully (``stop`` on stdin = the browser's own [記録をおわる]; then WM_CLOSE
    via ``taskkill /PID``; then terminate / kill) and ``load_recording`` parses the result.  stdout /
    stderr are drained by reader threads into bounded buffers so the child never blocks.
    """

    def __init__(
        self,
        command_builder: Optional[CommandBuilder] = None,
        popen: Optional[Callable[..., Any]] = None,
        max_lines: int = 500,
        stop_timeout: float = 8.0,
        run: Optional[Callable[..., Any]] = None,
        job: Optional[Callable[[Any], Optional[int]]] = None,
    ) -> None:
        self.command_builder: CommandBuilder = command_builder or recorder_command
        self._popen = popen or subprocess.Popen
        self._run = run or subprocess.run
        self._job = job if job is not None else (_kill_on_close_job if popen is None else None)
        self.max_lines = int(max_lines)
        self.stop_timeout = float(stop_timeout)
        self._lock = threading.RLock()
        self._proc: Any = None
        self._threads: list[threading.Thread] = []
        self._stdout: deque[str] = deque(maxlen=self.max_lines)
        self._stderr: deque[str] = deque(maxlen=self.max_lines)
        self._ready = threading.Event()
        self._last_count = 0
        self._stop_requested = False
        self.job_handle: Optional[int] = None
        self.command: list[str] = []
        self.out: Optional[str] = None
        self.log_path: Optional[str] = None
        self.port: Optional[int] = None
        #: pid of the process that shows the window (``READY``); differs from ``pid`` when python.exe
        #: is a venv's launcher
        self.browser_pid: Optional[int] = None
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self.exit_code: Optional[int] = None
        #: the browser of the current / last recording (``RECORD_BROWSERS``)
        self.browser = "ie"

    @property
    def running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    # ------------------------------------------------------------------ start
    def start(self, out: str, url: Optional[str] = None, emulation: str = "default", title: str = BROWSER_TITLE,
              log_path: Optional[str] = None, browser: str = "ie") -> dict[str, Any]:
        """Spawn the recording process; returns :meth:`status`.  :class:`RecorderError` when a session
        is already running, the output folder cannot be made or the process cannot be started.
        ``browser``: ``ie`` (the recording browser) or ``edge`` (Microsoft Edge)."""
        with self._lock:
            if self.running:
                raise RecorderError("すでに記録中です。先に記録を停止してください。")
            out_abs = os.path.abspath(out)
            try:
                os.makedirs(os.path.dirname(out_abs) or ".", exist_ok=True)
            except OSError as exc:
                raise RecorderError(f"出力先フォルダを作成できません: {exc}") from exc
            extra = {"browser": browser} if browser != "ie" else {}
            cmd = [str(c) for c in self.command_builder(out_abs, url=url, emulation=emulation, title=title,
                                                        log_path=log_path, **extra)]
            env = dict(os.environ)
            env["PYTHONIOENCODING"] = "utf-8"
            popen_kwargs: dict[str, Any] = dict(
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1, env=env,
            )
            if os.name == "nt":
                popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                proc = self._popen(cmd, **popen_kwargs)
            except OSError as exc:
                raise RecorderError(f"記録用ブラウザを起動できません: {exc}") from exc
            if self.job_handle:
                _close_handle(self.job_handle)
            self.job_handle = self._job(proc) if self._job is not None else None
            self._proc = proc
            self.command = cmd
            self.out = out_abs
            self.log_path = log_path
            self.browser = browser
            self.port = None
            self.browser_pid = None
            self.started_at = time.time()
            self.stopped_at = None
            self.exit_code = None
            self._stop_requested = False
            self._last_count = 0
            self._ready = threading.Event()
            self._stdout = deque(maxlen=self.max_lines)
            self._stderr = deque(maxlen=self.max_lines)
            self._threads = []
            for stream, buf, label in ((proc.stdout, self._stdout, "stdout"), (proc.stderr, self._stderr, "stderr")):
                if stream is None:
                    continue
                t = threading.Thread(target=self._drain, args=(stream, buf, label == "stdout"), name=f"reqrec-recorder-{label}", daemon=True)
                t.start()
                self._threads.append(t)
            return self.status()

    def _drain(self, stream: Any, buf: deque, parse_ready: bool) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                text = line.rstrip("\r\n")
                buf.append(text)
                if parse_ready and text.startswith("READY "):
                    fields = text.split()
                    try:
                        self.port = int(fields[1])
                        self.browser_pid = int(fields[2]) if len(fields) > 2 else None
                    except (IndexError, ValueError):
                        pass
                    self._ready.set()
        except (ValueError, OSError):  # stream closed while reading
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def wait_until_ready(self, timeout: float = RECORD_READY_TIMEOUT, interval: float = 0.1) -> bool:
        """Block until the child printed ``READY`` (proxy listening, window open).  ``False`` when it
        exited first or ``timeout`` passed.  Does not hold the lock while waiting."""
        deadline = time.time() + max(0.0, float(timeout))
        ready = self._ready
        while True:
            if ready.wait(interval):
                return True
            if not self.running:
                return ready.is_set()
            if time.time() >= deadline:
                return False

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    # ------------------------------------------------------------------ stop
    def stop(self, timeout: Optional[float] = None) -> Optional[int]:
        """End the child gracefully and return its exit code (``None`` when nothing ran)."""
        grace = self.stop_timeout if timeout is None else float(timeout)
        with self._lock:
            proc = self._proc
            if proc is None:
                return self.exit_code
            self._stop_requested = True
            rc = proc.poll()
            if rc is None:
                rc = self._shutdown(proc, grace)
            try:
                if proc.stdin is not None:
                    proc.stdin.close()
            except (OSError, ValueError):
                pass
            for t in self._threads:
                t.join(_READER_JOIN_TIMEOUT)
            self._threads = []
            if self.job_handle:
                _close_handle(self.job_handle)
                self.job_handle = None
            self.exit_code = rc
            self.stopped_at = time.time()
            self._proc = None
            return rc

    def _shutdown(self, proc: Any, grace: float) -> int:
        try:  # 1. like the browser's own [記録をおわる]: the window closes, the file is written
            if proc.stdin is not None:
                proc.stdin.write("stop\n")
                proc.stdin.flush()
        except (OSError, ValueError):
            pass
        rc = _wait(proc, grace)
        if rc is not None:
            return rc
        if os.name == "nt" and getattr(proc, "pid", None):  # 2. WM_CLOSE to its windows (and a venv launcher's child)
            try:
                self._run(["taskkill", "/PID", str(proc.pid), "/T"], capture_output=True, text=True, errors="replace", timeout=10.0)
            except Exception:
                pass
            rc = _wait(proc, 3.0)
            if rc is not None:
                return rc
        try:  # 3. the file written so far stays (it is rewritten every half second)
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass
        rc = _wait(proc, 3.0)
        if rc is not None:
            return rc
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
        return proc.wait()

    def forget(self) -> bool:
        """Drop the output file of a **stopped** session ([やめる], or a start that failed): afterwards
        ``out`` is ``None``.  ``False`` (and nothing changes) while the child still runs."""
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return False
            self.out = None
            self._last_count = 0
            return True

    def close(self) -> None:
        """``stop()`` that never raises (app shutdown)."""
        try:
            self.stop()
        except Exception:
            pass

    # ------------------------------------------------------------------ inspection
    def flow_count(self) -> int:
        out = self.out
        if not out:
            return 0
        count = count_flows_in_file(out, default=-1)
        if count < 0:
            return self._last_count
        self._last_count = count
        return count

    def status(self) -> dict[str, Any]:
        """``{running, ready, flows, out, out_name, pid, exit_code, started_at, stopped_at, port, log,
        stdout_tail, stderr_tail, error, command}`` for the GUI."""
        with self._lock:
            proc = self._proc
            running = proc is not None and proc.poll() is None
            exit_code = self.exit_code
            if proc is not None and not running:
                exit_code = proc.returncode
                self.exit_code = exit_code
            stderr_tail = "\n".join(self._stderr)
            stdout_tail = "\n".join(self._stdout)
            error: Optional[str] = None
            if (not running and not self._stop_requested and self.out is not None
                    and exit_code not in (None, 0) and self.started_at is not None):
                detail = [line for line in stderr_tail.strip().splitlines() if line.strip()]
                error = detail[-1] if detail else f"記録用ブラウザが終了コード {exit_code} で終了しました"
            return {
                "running": running,
                "ready": self._ready.is_set(),
                "flows": self.flow_count(),
                "out": self.out,
                "out_name": os.path.basename(self.out) if self.out else None,
                "pid": getattr(proc, "pid", None) if proc is not None else None,
                "browser_pid": self.browser_pid,
                "browser": self.browser,
                "exit_code": exit_code,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "port": self.port,
                "log": self.log_path,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "error": error,
                "command": list(self.command),
            }

    def load_recording(self) -> Recording:
        """Parse the recording written by the last / current session."""
        if not self.out:
            raise RecorderError("記録ファイルがありません。先に記録を開始してください。")
        if not os.path.exists(self.out):
            raise RecorderError("記録ファイルが作成されませんでした。記録用ブラウザで http:// のページを 1 つ以上開いてください。")
        try:
            return Recording.load(self.out)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RecorderError(f"記録ファイルを読み込めません: {exc}") from exc


# ===== former reqrec/gui.py: Flask GUI (reqrec gui) =====
# Flask based no-code GUI for reqrec (``reqrec gui``).  Contract: DESIGN.md §13.6, §13.11, §13.12.
#
# ``create_app(workdir)`` builds the Flask application; ``run_gui`` starts it (and opens a browser).
# The page is ``GUI_HTML`` (right after this section): one Jinja template with the CSS and the
# JavaScript inlined (vanilla JS, no CDN, no build step; the GUI works offline).
#
# Sections (each one a former module, in dependency order):
#
# * launchers (former ``reqrec/webapp/launch.py``) - check the recording browser's first address,
#   open a folder;
# * state (former ``reqrec/webapp/state.py``) - ``AppState`` and the helpers the routes build on;
# * routes (former ``reqrec/webapp/routes.py``) - the JSON API and the page (blueprint ``bp``);
# * app (former ``reqrec/webapp/__init__.py``) - ``create_app`` / ``run_gui`` and the security hook.


# ===== former reqrec/webapp/launch.py: the recording browser's first address / open a folder =====
# Contract: DESIGN.md §13.11.  The only browser reqrec opens for recording is its own IE-engine
# recording browser (recorder section); this section checks the address it starts with and opens the
# 保存先フォルダ.  Every function takes injectable callables so the logic is unit tested on any OS
# without launching anything.

#: ``scheme:`` prefix (RFC 3986); anything with one that is not http(s) is rejected, never patched.
_GUI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
#: ``host:port[/...]`` typed without a scheme (``kanri:8080/app``): the part before ``:`` is a host, not a scheme.
_HOST_PORT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]*:\d{1,5}(?:[/?#]|$)")


def validate_url(url: Any) -> str:
    """``http(s)://...``; an address without a scheme gets ``http://``.

    Raises ``ValueError`` with a Japanese message for an empty address and for anything else
    (``javascript:``, ``edge://`` and friends must never reach the browser from an API call).
    """
    text = str(url or "").strip()
    if not text:
        raise ValueError("サイトのアドレスを入力してください (例: http://kanri/)")
    if not _GUI_SCHEME_RE.match(text) or _HOST_PORT_RE.match(text):  # "kanri/top", "kanri:8080/top" -> http://...
        text = "http://" + text
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("サイトのアドレスは http:// で始まる形で入力してください (例: http://kanri/)")
    if any(ch in text for ch in "\r\n\x00"):
        raise ValueError("サイトのアドレスに使えない文字が含まれています")
    return text


def open_folder(
    path: str,
    startfile: Optional[Callable[[str], Any]] = None,
    popen: Optional[Callable[..., Any]] = None,
    platform: Optional[str] = None,
) -> dict[str, Any]:
    """Show ``path`` in the OS file manager (Explorer / Finder / xdg-open).

    Raises ``FileNotFoundError`` when the folder does not exist and ``RuntimeError`` when the OS
    has no opener.
    """
    if not os.path.isdir(path):
        raise FileNotFoundError(f"フォルダがありません: {path}")
    plat = platform or sys.platform
    if plat == "win32":
        opener = startfile or getattr(os, "startfile", None)
        if opener is None:  # pragma: no cover - os.startfile always exists on Windows
            raise RuntimeError("この OS ではフォルダを開けません")
        opener(path)
        return {"path": path, "opener": "explorer"}
    spawn = popen or subprocess.Popen
    command = ["open", path] if plat == "darwin" else ["xdg-open", path]
    try:
        spawn(command, close_fds=True)
    except OSError as exc:
        raise RuntimeError(f"フォルダを開けませんでした: {exc}") from exc
    return {"path": path, "opener": command[0]}


# ===== former reqrec/webapp/state.py: per-process state and the helpers the routes build on =====
# Per-process state of the GUI and the helpers the routes build on.  Contract: DESIGN.md §13.6.
#
# * :class:`AppState` - the loaded recording, the current plan / options, the recorder, the script
#   runner and the recording browser, guarded by one re-entrant lock.
# * :func:`safe_name` / :meth:`AppState.path_in` - the **only** way a client-supplied name becomes a
#   path (always inside the right ``workdir`` sub-folder).
# * :func:`plan_options_from_json` / :func:`gen_options_from_json` - whitelist + coerce the option
#   objects the browser sends.
# * :class:`ScriptRunner` - runs a saved script in a subprocess with live stdout / stderr buffers.
# * :func:`load_sources` / :func:`exclude_netlocs` - load & merge recordings, drop the GUI's own traffic.
#
# Everything user-facing raises :class:`ApiError` with a Japanese message and an HTTP status.

#: Sub-folders of ``workdir`` (created on start-up).
SUBDIRS = ("recordings", "uploads", "scripts", "outputs")

#: Environment variable with the GUI password (``reqrec gui`` / ``flask --app reqrec run``).  It is not
#: ``REQREC_PASSWORD``: generated scripts read that name for the site's own password.
GUI_PASSWORD_ENV = "REQREC_GUI_PASSWORD"
#: Environment variable with the work folder when the app is built without arguments (Flask CLI).
WORKDIR_ENV = "REQREC_WORKDIR"


def _gui_password() -> str:
    """The GUI password in effect: ``REQREC_GUI_PASSWORD`` when set (``""`` included), else :data:`GUI_PASSWORD`."""
    env = os.environ.get(GUI_PASSWORD_ENV)
    return str(env if env is not None else (GUI_PASSWORD or ""))

#: What the upload / open endpoints accept (``importers.load_recording`` dispatches on these).
RECORDING_EXTENSIONS = frozenset({".har", ".json"})

#: File names coming from the browser must match this after basename reduction.
_NAME_RE = re.compile(r"^[\w.\-]+$", re.UNICODE)
#: Characters that are replaced by ``_`` when *sanitising* an uploaded file name.
_UNSAFE_CHAR_RE = re.compile(r"[^\w.\-]", re.UNICODE)
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_HTML_PARSERS = ("html.parser", "lxml")
_TRUE_WORDS = {"1", "true", "yes", "on", "y", "t"}
_FALSE_WORDS = {"0", "false", "no", "off", "n", "f", ""}


class ApiError(Exception):
    """An error reported to the browser as ``{"error": message}`` with ``status``."""

    def __init__(self, message: str, status: int = 400, **extra: Any) -> None:
        super().__init__(message)
        self.message = message
        self.status = int(status)
        self.extra = extra

    def to_dict(self) -> dict[str, Any]:
        data = {"error": self.message}
        data.update(self.extra)
        return data


# --------------------------------------------------------------------------- names & paths

def safe_name(name: Any, what: str = "ファイル名") -> str:
    """Validate a client-supplied file name.

    Accepts only a bare name made of word characters, ``.`` and ``-`` (``^[\\w.\\-]+$``); rejects
    empty names, ``.``/``..``, hidden names (leading ``.``), anything containing a path separator
    (``/``, ``\\``) or a drive / NUL character.  Returns the name unchanged.
    """
    if not isinstance(name, str):
        raise ApiError(f"{what}が指定されていません")
    candidate = name.strip()
    if not candidate:
        raise ApiError(f"{what}が指定されていません")
    if len(candidate) > 200:
        raise ApiError(f"{what}が長すぎます (200 文字まで)")
    if "/" in candidate or "\\" in candidate or "\x00" in candidate or ":" in candidate:
        raise ApiError(f"{what}にフォルダ区切りやドライブ名は使えません: {candidate}")
    if candidate in (".", "..") or candidate.startswith("."):
        raise ApiError(f"{what}が不正です: {candidate}")
    if not _NAME_RE.match(candidate):
        raise ApiError(f"{what}に使えない文字が含まれています (英数字 . - _ のみ): {candidate}")
    return candidate


def sanitise_upload_name(filename: Any, default: str = "upload") -> str:
    """Reduce an uploaded file's name to something :func:`safe_name` accepts (never raises)."""
    base = os.path.basename(str(filename or "").replace("\\", "/")).strip()
    base = re.sub(r"_+", "_", _UNSAFE_CHAR_RE.sub("_", base)).strip("._ ") or default
    if base in (".", ".."):
        base = default
    try:
        return safe_name(base)
    except ApiError:  # pragma: no cover - the substitutions above make this unreachable
        return default


def _ensure_within(path: str, root: str) -> str:
    """``path`` resolved, guaranteed to be inside ``root`` (defence in depth after ``safe_name``)."""
    real_root = os.path.realpath(root)
    real_path = os.path.realpath(path)
    if real_path != real_root and not real_path.startswith(real_root + os.sep):
        raise ApiError("作業フォルダの外は参照できません", status=403)
    return real_path


def unique_path(path: str) -> str:
    """``x.har`` -> ``x_2.har`` ... when the file already exists."""
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    for n in range(2, 10000):
        candidate = f"{stem}_{n}{ext}"
        if not os.path.exists(candidate):
            return candidate
    raise ApiError("同名のファイルが多すぎます", status=409)


# --------------------------------------------------------------------------- option coercion

def _to_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _TRUE_WORDS:
            return True
        if v in _FALSE_WORDS:
            return False
    if value is None:
        return False
    raise ApiError(f"オプション {name} は true / false で指定してください")


def _gui_to_int(value: Any, name: str, minimum: Optional[int] = None) -> int:
    if isinstance(value, bool):
        value = int(value)
    try:
        if isinstance(value, str):
            value = value.strip()
        n = int(value)
    except (TypeError, ValueError):
        raise ApiError(f"オプション {name} は整数で指定してください") from None
    if minimum is not None and n < minimum:
        raise ApiError(f"オプション {name} は {minimum} 以上で指定してください")
    return n


def _to_float(value: Any, name: str, minimum: Optional[float] = None) -> float:
    try:
        if isinstance(value, str):
            value = value.strip()
        f = float(value)
    except (TypeError, ValueError):
        raise ApiError(f"オプション {name} は数値で指定してください") from None
    if f != f or f in (float("inf"), float("-inf")):
        raise ApiError(f"オプション {name} は数値で指定してください")
    if minimum is not None and f < minimum:
        raise ApiError(f"オプション {name} は {minimum:g} 以上で指定してください")
    return f


def _to_str_list(value: Any, name: str) -> list[str]:
    """``["a", "b"]`` / ``"a, b"`` / ``None`` -> stripped, de-duplicated list."""
    if value is None:
        return []
    if isinstance(value, str):
        items: Iterable[Any] = re.split(r"[,\s;]+", value)
    elif isinstance(value, (list, tuple, set)):
        items = value
    else:
        raise ApiError(f"オプション {name} は文字列の配列で指定してください")
    out: list[str] = []
    for item in items:
        if item is None:
            continue
        s = str(item).strip()
        if s and s not in out:
            out.append(s)
    return out


def _is_empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip()) or (isinstance(value, (list, tuple)) and not value)


def _coerce_field(field: dataclasses.Field, value: Any, hints: dict[str, Any]) -> Any:
    name = field.name
    hint = hints.get(name)
    origin = typing.get_origin(hint)
    args = typing.get_args(hint)
    optional = origin in (typing.Union, types.UnionType) and type(None) in args
    inner = next((a for a in args if a is not type(None)), hint) if optional else hint
    inner_origin = typing.get_origin(inner)

    if inner is bool:
        return _to_bool(value, name)
    if inner_origin is list or inner is list:
        items = _to_str_list(value, name)
        if optional and not items:
            return None
        return items
    if optional and _is_empty(value):
        return None
    if inner is int:
        return _gui_to_int(value, name, minimum=1 if name in ("min_value_length", "max_steps") else None)
    if inner is float:
        return _to_float(value, name, minimum=0.0)
    if inner is str:
        s = str(value).strip()
        if name == "html_parser":
            if s not in _HTML_PARSERS:
                raise ApiError(f"HTML パーサーは {' / '.join(_HTML_PARSERS)} のどちらかを指定してください")
        return s
    return value  # pragma: no cover - no other field types exist in core.py


def _options_from_json(cls: type, data: Any, what: str):
    if data is None:
        return cls()
    if not isinstance(data, dict):
        raise ApiError(f"{what} はオブジェクトで指定してください")
    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for field in dataclasses.fields(cls):
        if field.name in data:
            kwargs[field.name] = _coerce_field(field, data[field.name], hints)
    return cls(**kwargs)


def plan_options_from_json(data: Any) -> PlanOptions:
    """``PlanOptions`` from the JSON the browser sends (unknown keys ignored, types coerced)."""
    return _options_from_json(PlanOptions, data, "plan_options")


def gen_options_from_json(data: Any) -> GenOptions:
    """``GenOptions`` from the JSON the browser sends (unknown keys ignored, types coerced)."""
    return _options_from_json(GenOptions, data, "gen_options")


def options_to_plain(opts: Any) -> dict[str, Any]:
    return dataclasses.asdict(opts)


# --------------------------------------------------------------------------- recordings

def normalise_netloc(netloc: str, scheme: str = "http") -> str:
    """``LOCALHOST:80`` -> ``localhost`` (default ports dropped, lower-case, IPv6 brackets kept)."""
    n = (netloc or "").strip().lower()
    if not n:
        return ""
    default = {"http": ":80", "https": ":443"}.get((scheme or "http").lower())
    if default and n.endswith(default):
        n = n[: -len(default)]
    return n


def gui_netlocs(host: str, port: int, request_host: Optional[str] = None) -> set[str]:
    """Every ``host[:port]`` spelling a browser could use to reach this GUI."""
    out: set[str] = set()
    hosts = {"127.0.0.1", "localhost", "[::1]"}
    h = (host or "").strip().lower()
    if h and h not in ("0.0.0.0", "::", "*", "[::]"):
        hosts.add(h if ":" not in h or h.startswith("[") else f"[{h}]")
    for name in hosts:
        out.add(normalise_netloc(f"{name}:{int(port)}"))
    if request_host:
        out.add(normalise_netloc(request_host))
    return {n for n in out if n}


def exclude_netlocs(recording: Recording, netlocs: set[str]) -> tuple[Recording, int]:
    """Drop every flow whose request host[:port] is one of ``netlocs`` (the GUI itself) and
    re-number the rest.  Returns ``(recording, removed_count)``; untouched when nothing matched."""
    if not netlocs or not recording.flows:
        return recording, 0
    keep = []
    removed = 0
    for flow in recording.flows:
        parts = urlsplit(flow.request.url)
        if normalise_netloc(parts.netloc, parts.scheme) in netlocs:
            removed += 1
        else:
            keep.append(flow)
    if not removed:
        return recording, 0
    trimmed = Recording.merge([Recording(flows=keep, meta=dict(recording.meta))])
    trimmed.meta = dict(recording.meta)
    trimmed.meta["excluded_self_flows"] = int(trimmed.meta.get("excluded_self_flows", 0)) + removed
    return trimmed, removed


def _load_recordings(paths: list[str]) -> Recording:
    """``load_recordings`` (importers section): one file as it is, several merged by time stamp."""
    return load_recordings(list(paths))


def load_sources(paths: list[str]) -> Recording:
    """Load one or more recording files into a single ``Recording`` (merged when several).

    Import problems become :class:`ApiError` (400) with the importer's Japanese message.
    """
    if not paths:
        raise ApiError("読み込むファイルが指定されていません")
    try:
        return _load_recordings(paths)
    except (ValueError, KeyError, TypeError) as exc:
        raise ApiError(f"記録ファイルを読み込めません: {exc}") from exc
    except OSError as exc:
        raise ApiError(f"ファイルを開けません: {exc}") from exc


# --------------------------------------------------------------------------- script runner

#: A progress line of a generated script on stderr: ``[2/9] OK  POST /Login.aspx ...``,
#: ``[3/9] ERROR  ...`` or ``[完了] すべての手順が終わりました（9 手順）`` (codegen ``_emit_progress_helpers``).
#: With REQREC_DEBUG the dependency lines ``[3/9]   ...`` match too, so they stay in the run console.
_PROGRESS_LINE_RE = re.compile(r"^\[(?:\d+/\d+|完了)\] ")


class ScriptRunner:
    """Run one generated script at a time in a subprocess.

    stdout / stderr are read by daemon threads into line ring buffers (``tail``) and, for
    stdout, additionally kept in full up to ``max_output_bytes`` so the user can save the result.
    ``output_tail`` interleaves stdout with the script's progress lines (stderr) in arrival order -
    what the run panel shows - and ``errors_tail`` is stderr without them.
    Secrets arrive as environment variables for the child only; they are never stored or logged.
    """

    def __init__(self, max_lines: int = 2000, max_output_bytes: int = 32 * 1024 * 1024, popen=None) -> None:
        self.max_lines = int(max_lines)
        self.max_output_bytes = int(max_output_bytes)
        self._popen = popen or subprocess.Popen
        self._lock = threading.RLock()
        self._proc: Optional[subprocess.Popen] = None
        self._threads: list[threading.Thread] = []
        self._stdout_tail: deque[str] = deque(maxlen=self.max_lines)
        self._stderr_tail: deque[str] = deque(maxlen=self.max_lines)
        self._output_tail: deque[str] = deque(maxlen=self.max_lines)
        self._errors_tail: deque[str] = deque(maxlen=self.max_lines)
        self._stdout_full: list[str] = []
        self._stdout_bytes = 0
        self._stdout_truncated = False
        self.name: Optional[str] = None
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.exit_code: Optional[int] = None
        self._stop_requested = False

    @property
    def running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def start(self, script_path: str, env: Optional[dict[str, str]] = None, cwd: Optional[str] = None) -> dict[str, Any]:
        with self._lock:
            if self.running:
                raise ApiError("すでにスクリプトを実行中です。終了を待つか [停止] を押してください。", status=409)
            if not os.path.isfile(script_path):
                raise ApiError(f"スクリプトが見つかりません: {os.path.basename(script_path)}", status=404)
            child_env = dict(os.environ)
            child_env.pop(GUI_PASSWORD_ENV, None)  # the GUI's own password never reaches a script
            child_env["PYTHONIOENCODING"] = "utf-8"
            child_env["PYTHONUNBUFFERED"] = "1"
            for key, value in (env or {}).items():
                if not isinstance(key, str) or not _ENV_NAME_RE.match(key):
                    raise ApiError(f"環境変数名が不正です: {key!r}")
                if value is None:
                    continue
                child_env[key] = str(value)
            cmd = [sys.executable, "-X", "utf8", script_path]
            try:
                proc = self._popen(
                    cmd,
                    cwd=cwd or os.path.dirname(script_path) or None,
                    env=child_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
            except OSError as exc:
                raise ApiError(f"スクリプトを起動できません: {exc}", status=500) from exc
            self._proc = proc
            self.name = os.path.basename(script_path)
            self.started_at = time.time()
            self.finished_at = None
            self.exit_code = None
            self._stop_requested = False
            self._stdout_tail = deque(maxlen=self.max_lines)
            self._stderr_tail = deque(maxlen=self.max_lines)
            self._output_tail = deque(maxlen=self.max_lines)
            self._errors_tail = deque(maxlen=self.max_lines)
            self._stdout_full = []
            self._stdout_bytes = 0
            self._stdout_truncated = False
            self._threads = [
                threading.Thread(target=self._drain_stdout, args=(proc.stdout,), name="reqrec-run-stdout", daemon=True),
                threading.Thread(target=self._drain_stderr, args=(proc.stderr,), name="reqrec-run-stderr", daemon=True),
            ]
            for t in self._threads:
                t.start()
            return self.status()

    def _drain_stdout(self, stream: Any) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                text = line.rstrip("\r\n")
                self._stdout_tail.append(text)
                self._output_tail.append(text)
                if not self._stdout_truncated:
                    size = len(line.encode("utf-8", "replace"))
                    if self._stdout_bytes + size > self.max_output_bytes:
                        self._stdout_truncated = True
                    else:
                        self._stdout_full.append(line)
                        self._stdout_bytes += size
        except (ValueError, OSError):
            pass
        finally:
            self._finish_if_done()

    def _drain_stderr(self, stream: Any) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                text = line.rstrip("\r\n")
                self._stderr_tail.append(text)
                if _PROGRESS_LINE_RE.match(text):
                    self._output_tail.append(text)
                else:
                    self._errors_tail.append(text)
        except (ValueError, OSError):
            pass
        finally:
            self._finish_if_done()

    def _finish_if_done(self) -> None:
        proc = self._proc
        if proc is None:
            return
        rc = proc.poll()
        if rc is None:
            return
        with self._lock:
            if self.exit_code is None and self._proc is proc:
                self.exit_code = rc
                self.finished_at = time.time()

    def stop(self, timeout: float = 5.0) -> dict[str, Any]:
        with self._lock:
            proc = self._proc
            if proc is None or proc.poll() is not None:
                return self.status()
            self._stop_requested = True
            try:
                proc.terminate()
            except (ProcessLookupError, OSError):
                pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass
                proc.wait()
            self.exit_code = proc.returncode
            self.finished_at = time.time()
            return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            proc = self._proc
            running = proc is not None and proc.poll() is None
            if proc is not None and not running:
                self.exit_code = proc.returncode
                if self.finished_at is None:
                    self.finished_at = time.time()
            return {
                "running": running,
                "exit_code": None if running else self.exit_code,
                "stdout_tail": "\n".join(self._stdout_tail),
                "stderr_tail": "\n".join(self._stderr_tail),
                "output_tail": "\n".join(self._output_tail),
                "errors_tail": "\n".join(self._errors_tail),
                "started_at": self.started_at,
                "finished_at": None if running else self.finished_at,
                "name": self.name,
                "pid": proc.pid if proc is not None else None,
                "stopped_by_user": self._stop_requested,
                "stdout_truncated": self._stdout_truncated,
                "stdout_bytes": self._stdout_bytes,
            }

    def wait(self, timeout: Optional[float] = None) -> Optional[int]:
        """Block until the child exits (tests / shutdown)."""
        proc = self._proc
        if proc is None:
            return self.exit_code
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        for t in self._threads:
            t.join(2.0)
        with self._lock:
            self.exit_code = rc
            if self.finished_at is None:
                self.finished_at = time.time()
        return rc

    def last_stdout(self) -> str:
        """Everything the last run printed to stdout (bounded by ``max_output_bytes``)."""
        with self._lock:
            return "".join(self._stdout_full)

    def close(self) -> None:
        try:
            self.stop(timeout=2.0)
        except Exception:
            pass


# --------------------------------------------------------------------------- app state

class AppState:
    """Everything the GUI remembers between requests (one instance per Flask app)."""

    def __init__(
        self,
        workdir: str,
        host: str = "127.0.0.1",
        port: int = 8765,
        token: Optional[str] = None,
        recorder: Optional[RecorderManager] = None,
        runner: Optional[ScriptRunner] = None,
    ) -> None:
        self.workdir = os.path.abspath(workdir)
        self.host = host
        self.port = int(port)
        self.token = token or secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.recording: Optional[Recording] = None
        self.sources: list[str] = []
        self.plan: Optional[Plan] = None
        self.plan_options = PlanOptions()
        self.gen_options = GenOptions()
        self.last_code: Optional[str] = None
        self.last_secrets: list[dict[str, Any]] = []
        self.last_script_name: Optional[str] = None
        #: The recording browser + proxy child process (``reqrec record``) of the current / last recording.
        self.recorder = recorder or RecorderManager()
        self.runner = runner or ScriptRunner()
        #: Why the recording browser could not be opened the last time in this GUI session (for the page).
        self.record_error: Optional[str] = None
        self.ensure_dirs()

    # ------------------------------------------------------------------ folders & paths

    def ensure_dirs(self) -> None:
        try:
            for sub in SUBDIRS:
                os.makedirs(os.path.join(self.workdir, sub), exist_ok=True)
        except OSError as exc:
            raise RuntimeError(f"作業フォルダを作成できません: {self.workdir} ({exc})") from exc

    def subdir(self, sub: str) -> str:
        if sub not in SUBDIRS:
            raise ApiError(f"不正なフォルダです: {sub}")
        path = os.path.join(self.workdir, sub)
        os.makedirs(path, exist_ok=True)
        return path

    def path_in(self, sub: str, name: Any, what: str = "ファイル名") -> str:
        """Absolute path of ``workdir/<sub>/<name>`` for a validated client name (never outside)."""
        folder = self.subdir(sub)
        clean = safe_name(name, what)
        return _ensure_within(os.path.join(folder, clean), folder)

    def list_files(self, sub: str, extensions: Optional[Iterable[str]] = None) -> list[dict[str, Any]]:
        folder = self.subdir(sub)
        exts = {e.lower() for e in extensions} if extensions else None
        out: list[dict[str, Any]] = []
        try:
            names = os.listdir(folder)
        except OSError:
            return out
        for name in sorted(names):
            if name.startswith("."):
                continue
            path = os.path.join(folder, name)
            if not os.path.isfile(path):
                continue
            if exts is not None and os.path.splitext(name)[1].lower() not in exts:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            out.append({"name": name, "folder": sub, "size": st.st_size, "mtime": st.st_mtime, "path": path})
        out.sort(key=lambda d: d["mtime"], reverse=True)
        return out

    # ------------------------------------------------------------------ recording

    def set_recording(self, recording: Recording, sources: list[str]) -> Recording:
        """Replace the current recording.  A new recording starts over: the plan, the options of
        詳細設定 (flow ids belong to one recording) and the current script are forgotten."""
        with self.lock:
            self.recording = recording
            self.sources = list(sources)
            self.plan = None
            self.plan_options = PlanOptions()
            self.gen_options = GenOptions()
            self.last_code = None
            self.last_secrets = []
            self.last_script_name = None
            return self.recording

    def require_recording(self) -> Recording:
        with self.lock:
            if self.recording is None or not self.recording.flows:
                raise ApiError("記録が読み込まれていません。かんたん画面で記録するか、HAR ファイルを読み込んでください。", status=409)
            return self.recording

    def recording_summary(self) -> dict[str, Any]:
        with self.lock:
            rec = self.recording
            hosts: list[str] = []
            if rec is not None:
                for flow in rec.flows:
                    h = flow.request.host
                    if h and h not in hosts:
                        hosts.append(h)
            return {
                "loaded": rec is not None,
                "sources": list(self.sources),
                "flows": len(rec.flows) if rec is not None else 0,
                "hosts": hosts[:50],
                "meta": _plain_meta(rec.meta) if rec is not None else None,
                "excluded_self_flows": int(rec.meta.get("excluded_self_flows", 0)) if rec is not None else 0,
            }

    # ------------------------------------------------------------------ shutdown

    def close(self) -> None:
        self.recorder.close()
        self.runner.close()


def _plain_meta(meta: dict[str, Any]) -> dict[str, Any]:
    """Recording meta reduced to JSON-safe scalars (nested ``sources`` of a merge included)."""
    out: dict[str, Any] = {}
    for k, v in meta.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, list):
            out[k] = [_plain_meta(x) if isinstance(x, dict) else str(x) for x in v]
        elif isinstance(v, dict):
            out[k] = _plain_meta(v)
        else:
            out[k] = str(v)
    return out


# ===== former reqrec/webapp/routes.py: JSON API + page (blueprint bp) =====
# JSON API + page of the GUI.  Contract: DESIGN.md §13.6.
#
# All endpoints return JSON (errors as ``{"error": "<日本語>"}`` with a 4xx / 5xx status) except
# ``GET /`` (the page) and ``GET /api/scripts/<name>/download`` (a file).  Security rules (token,
# Host, Origin) live in :func:`create_app`'s ``before_request`` hook (app section below), so every route
# here can assume the caller is the page served by this process.
#
# Analysis is delegated to the existing pipeline (``load_sources`` → ``build_plan`` → ``generate`` and
# ``build_inspect_report`` / ``format_plan_summary`` of the cli section); the routes only map HTTP to
# those calls.

bp = Blueprint("reqrec", __name__, root_path=os.path.dirname(os.path.abspath(__file__)))

#: Response / request bodies returned by ``/api/flow/<id>`` are cut here (characters).
BODY_LIMIT = 200 * 1024
_GUI_FLOW_ID_RE = re.compile(r"^f\d{4,}$")


# --------------------------------------------------------------------------- helpers

def get_state() -> AppState:
    return current_app.extensions["reqrec"]


def _json_body(required: bool = True) -> dict[str, Any]:
    """Parsed JSON object body (``{}`` for an empty body when not required)."""
    raw = flask_request.get_data(cache=True)
    if not raw or not raw.strip():
        if required:
            raise ApiError("JSON のリクエスト本文が必要です")
        return {}
    data = flask_request.get_json(silent=True, force=True)
    if data is None:
        raise ApiError("リクエスト本文を JSON として解析できません")
    if not isinstance(data, dict):
        raise ApiError("リクエスト本文は JSON オブジェクトである必要があります")
    return data


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off", ""):
            return False
    raise ApiError("true / false で指定してください")


def _ok(**data: Any) -> Response:
    data.setdefault("ok", True)
    return jsonify(data)


def _options_from_body(body: dict[str, Any]) -> tuple[PlanOptions, GenOptions]:
    """``{"plan_options": {...}, "gen_options": {...}}``; a body without those keys is taken as the
    plan options themselves; missing parts keep the current state."""
    state = get_state()
    if "plan_options" in body or "gen_options" in body:
        plan_src = body.get("plan_options")
        gen_src = body.get("gen_options")
    else:
        plan_src = body if body else None
        gen_src = None
    plan_opts = plan_options_from_json(plan_src) if plan_src is not None else state.plan_options
    gen_opts = gen_options_from_json(gen_src) if gen_src is not None else state.gen_options
    return plan_opts, gen_opts


def _rebuild_plan(state: AppState, plan_opts: PlanOptions) -> Plan:
    recording = state.require_recording()
    try:
        plan = build_plan(recording, plan_opts)
    except Exception as exc:  # the analysis must never take the GUI down
        current_app.logger.exception("build_plan failed")
        raise ApiError(f"解析に失敗しました: {exc.__class__.__name__}: {exc}", status=500) from exc
    with state.lock:
        state.plan = plan
        state.plan_options = plan_opts
    return plan


def _flow_rows(recording: Recording, plan: Plan) -> list[dict[str, Any]]:
    """One row per recorded flow: kept / step index or drop reason (sorted by time, then id)."""
    step_of: dict[str, int] = {}
    for step in plan.steps:
        for fid in step.source_flow_ids:
            step_of.setdefault(fid, step.index)
    reason_of = {d.flow_id: d.reason for d in plan.dropped}
    rows = []
    for flow in recording.flows:
        resp = flow.response
        step_index = step_of.get(flow.id)
        kept = step_index is not None
        if kept:
            reason = None
        else:
            reason = reason_of.get(flow.id) or "not used (folded into another step or beyond --max-steps)"
        rows.append({
            "id": flow.id,
            "started_at": flow.started_at,
            "method": flow.request.method,
            "status": resp.status if resp is not None else None,
            "mime": resp.mime_type if resp is not None else None,
            "url": flow.request.url,
            "host": flow.request.host,
            "referer": flow.request.header("referer"),
            "resource_type": flow.resource_type,
            "page_ref": flow.page_ref,
            "kept": kept,
            "reason": reason,
            "step_index": step_index,
            "has_body": flow.request.body is not None and len(flow.request.body) > 0,
            "response_size": len(resp.body) if resp is not None and resp.body is not None else 0,
            "is_final": plan.final_step_index is not None and step_index == plan.final_step_index,
        })
    rows.sort(key=lambda r: (r["started_at"] is None, r["started_at"] if r["started_at"] is not None else 0.0, r["id"]))
    return rows


def _plan_payload(state: AppState, plan: Plan) -> dict[str, Any]:
    recording = state.require_recording()
    report = build_inspect_report(recording, plan, source=", ".join(state.sources))
    report["flows"] = _flow_rows(recording, plan)
    report["auth"] = to_plain(plan.auth) if plan.auth is not None else None
    report["final_step_index"] = plan.final_step_index
    report["loops"] = [
        {"step_index": s.index, "var": s.loop.var, "count": len(s.loop.values), "numeric_range": list(s.loop.numeric_range) if s.loop.numeric_range else None}
        for s in plan.steps if s.loop is not None
    ]
    report["summary"] = format_plan_summary(plan, flows_total=len(recording.flows))
    report["plan_options"] = options_to_plain(state.plan_options)
    report["sources"] = list(state.sources)
    report["excluded_self_flows"] = int(recording.meta.get("excluded_self_flows", 0) or 0)
    # plain Japanese for 詳細設定, split like the easy screen: 確認してください / お知らせ
    actionable, notes = _split_warnings(list(plan.warnings))
    report["warning_details"] = _warning_details(actionable)
    report["note_details"] = _warning_details(notes)
    return report


def _secrets_of(plan: Plan) -> list[dict[str, Any]]:
    """Environment variables the generated script reads: secret constants plus, for NTLM /
    Negotiate (DESIGN.md §13.2), ``REQREC_NTLM_USER`` / ``REQREC_NTLM_PASSWORD`` which the script
    uses when ``requests_negotiate_sspi`` is unavailable (not a Windows box / another user)."""
    out = []
    seen: set[str] = set()
    for c in plan.constants:
        if c.secret and c.env_var and c.env_var not in seen:
            seen.add(c.env_var)
            out.append({"name": c.name, "env_var": c.env_var, "comment": c.comment})
    auth = plan.auth
    if auth is not None and str(auth.kind or "").lower() in ("ntlm", "negotiate"):
        # ``auth`` marks the Windows-authentication entries: the easy screen keeps their own
        # instruction (the logged-in Windows user via requests_negotiate_sspi needs neither value) instead of
        # 「記録したときと同じ値を入れてください」, and does not count the user name (written into the
        # script as its default) among the values 「スクリプトに書き込まれていません」.
        kind = str(auth.kind).lower()
        label = "NTLM" if kind == "ntlm" else "Negotiate"
        who = f"記録時のユーザー: {auth.username}" if auth.username else "記録からユーザー名は特定できませんでした"
        if "REQREC_NTLM_USER" not in seen:
            seen.add("REQREC_NTLM_USER")
            out.append({
                "name": f"{label} 認証のユーザー名 (DOMAIN\\user)", "env_var": "REQREC_NTLM_USER", "secret": False,
                "default": auth.username or "", "auth": kind,
                "comment": f"{who}。Windows で今ログインしているユーザーのまま認証する場合 "
                           "(requests_negotiate_sspi を入れた PC) は空欄のまま (使われません)",
            })
        if "REQREC_NTLM_PASSWORD" not in seen:
            seen.add("REQREC_NTLM_PASSWORD")
            out.append({
                "name": f"{label} 認証のパスワード", "env_var": "REQREC_NTLM_PASSWORD", "secret": True, "auth": kind,
                "comment": "Windows 以外 / 別のユーザーで実行する場合 (requests_ntlm を入れた PC) に必要。"
                           "Windows で今ログインしているユーザーのまま認証する場合 (requests_negotiate_sspi を入れた PC) は空欄のまま",
            })
    return out


def _body_view(body: Optional[bytes], content_type: Optional[str], mime: Optional[str]) -> dict[str, Any]:
    """Decoded body for the detail drawer (JSON pretty-printed, binary summarised, long bodies cut)."""
    if body is None or len(body) == 0:
        return {"kind": "none", "size": 0, "text": "", "truncated": False, "mime": mime}
    size = len(body)
    mime = (mime or parse_content_type(content_type)[0] or "").lower() or None
    textual = is_textual_mime(mime) or mime is None or mime in ("application/octet-stream",)
    text: Optional[str] = None
    if textual:
        decoded = decode_body(body, content_type)
        if "\x00" in decoded[:4096] or (mime in (None, "application/octet-stream") and _looks_binary(body)):
            textual = False
        else:
            text = decoded
    if not textual or text is None:
        return {"kind": "binary", "size": size, "text": None, "truncated": False, "mime": mime}
    kind = "text"
    stripped = text.lstrip()
    if is_json_mime(mime) or (stripped[:1] in ("{", "[") and len(stripped) < 4 * 1024 * 1024):
        try:
            parsed = json.loads(text)
            text = json.dumps(parsed, ensure_ascii=False, indent=2)
            kind = "json"
        except ValueError:
            pass
    elif mime == "application/x-www-form-urlencoded":
        kind = "form"
    elif is_html_mime(mime):
        kind = "html"
    truncated = len(text) > BODY_LIMIT
    if truncated:
        text = text[:BODY_LIMIT]
    view: dict[str, Any] = {"kind": kind, "size": size, "text": text, "truncated": truncated, "mime": mime}
    if kind == "form":
        # byte level: a Shift_JIS form keeps its percent-encoded spelling (never U+FFFD)
        declared = detect_charset(b"", content_type) if content_type and parse_content_type(content_type)[1].get("charset") else None
        view["pairs"] = [list(p) for p in parse_form_bytes(body, declared)]
    return view


def _looks_binary(body: bytes) -> bool:
    sample = body[:2048]
    if not sample:
        return False
    control = sum(1 for b in sample if b < 9 or 13 < b < 32)
    return control > len(sample) * 0.05


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts)).isoformat(timespec="milliseconds")
    except (OverflowError, OSError, ValueError):
        return None


def _timestamp_name(prefix: str, ext: str) -> str:
    return f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"


def _script_name(raw: Any) -> str:
    """``scrape`` / ``scrape.py`` -> ``scrape.py`` (validated)."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raw = _timestamp_name("scrape", "")
    name = safe_name(raw, "スクリプト名")
    if not name.lower().endswith(".py"):
        name += ".py"
    if name.lower() == ".py":
        raise ApiError("スクリプト名が指定されていません")
    return name


def _record_info(state: AppState) -> dict[str, Any]:
    """``{"available", "reason", "last_error", "browsers"}``: can this PC record (with the recording
    browser = the IE engine, or with Microsoft Edge: ``browsers`` has each one's availability), and why
    the recording could not be started the last time in this GUI session."""
    browsers = {"ie": recorder_availability(), "edge": edge_availability()}
    info = dict(browsers["ie"])
    if not info.get("available") and browsers["edge"].get("available"):
        info = dict(browsers["edge"])
    info["browsers"] = browsers
    info["last_error"] = state.record_error
    return info


def _require_recording_browser(browser: str = "ie") -> None:
    """400 unless ``browser`` (the recording browser / Edge) can be used on this PC and the page is opened
    on it."""
    if not _is_loopback_addr(flask_request.remote_addr):
        raise ApiError("記録は、reqrec を動かしている PC の画面からだけ始められます。"
                       "他の PC では HAR ファイルを読み込んでください。", status=400)
    info = edge_availability() if browser == "edge" else recorder_availability()
    if not info.get("available"):
        raise ApiError(info.get("reason") or "記録用ブラウザ (IE エンジン) はこの PC では使えません。", status=400)


def _start_url(raw: Any) -> Optional[str]:
    """The optional first page of the recording browser: ``None`` when blank, else a validated
    ``http(s)://`` URL (a bare host name gets ``http://``; ``edge://`` and other schemes are refused)."""
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return validate_url(text)
    except ValueError as exc:
        raise ApiError(str(exc)) from exc


#: ``kind`` of the 500 errors of ``record_start`` (the easy screen explains each one differently):
#: ``proxy`` = the recording browser could not set its per-process proxy (exit code
#: :data:`RECORD_EXIT_PROXY`), ``iehost`` = the recording browser could not be started or opened.
ERROR_KIND_PROXY = "proxy"
ERROR_KIND_IEHOST = "iehost"
#: ``edge`` = Microsoft Edge (記録に使うブラウザ「Edge」) could not be started or its window did not appear.
ERROR_KIND_EDGE = "edge"


def _remove_quietly(path: Optional[str]) -> bool:
    """Delete ``path`` if it is a file; ``True`` when something was removed.  Never raises."""
    if not path or not os.path.isfile(path):
        return False
    try:
        os.remove(path)
        return True
    except OSError:
        return False


def _forget_recording(state: AppState) -> None:
    """Make the recorder forget its output file (``RecorderManager.forget``; tolerated when absent)."""
    forget = getattr(state.recorder, "forget", None)
    if callable(forget):
        try:
            forget()
        except Exception:
            current_app.logger.exception("recorder.forget failed")


def _abandon_start(state: AppState, out: str) -> None:
    """Undo a ``record_start`` whose recording browser never got ready: stop the child, delete the
    (empty) recording file and forget it.  Does nothing when another recording owns the recorder by now."""
    with state.lock:
        current = getattr(state.recorder, "out", out)
        if current and os.path.abspath(current) != os.path.abspath(out):
            return
        state.recorder.stop()
        _remove_quietly(out)
        _forget_recording(state)


def _apply_loaded(state: AppState, recording: Recording, sources: list[str], from_gui_recorder: bool) -> dict[str, Any]:
    """Load ``recording`` as the new current one; the summary also carries the (reset) options."""
    excluded = 0
    if from_gui_recorder:
        recording, excluded = exclude_netlocs(recording, gui_netlocs(state.host, state.port, flask_request.host))
    state.set_recording(recording, sources)
    summary = state.recording_summary()
    summary["excluded_self"] = excluded
    summary["plan_options"] = options_to_plain(state.plan_options)
    summary["gen_options"] = options_to_plain(state.gen_options)
    return summary


# --------------------------------------------------------------------------- page

@bp.get("/")
def index() -> str:
    state = get_state()
    # Recording opens the recording browser (or Edge) on the PC that runs reqrec, for the person in front
    # of it: a page opened from another PC makes scripts from HAR files only (no recording controls).
    local = _is_loopback_addr(flask_request.remote_addr)
    can_record_ie = bool(local and recorder_availability().get("available"))
    can_record_edge = bool(local and edge_availability().get("available"))
    return render_template(
        _GUI_TEMPLATE,
        token=state.token,
        version=__version__,
        workdir=state.workdir,
        can_record=can_record_ie or can_record_edge,
        can_record_ie=can_record_ie,
        can_record_edge=can_record_edge,
        logged_in=bool(flask_session.get(_SESSION_AUTH_KEY)),
    )


@bp.get("/api/state")
def api_state() -> Response:
    state = get_state()
    return jsonify({
        "version": __version__,
        "workdir": state.workdir,
        "gui_address": flask_request.host,
        "recorder": state.recorder.status(),
        "record": _record_info(state),
        "recording": state.recording_summary(),
        "plan_loaded": state.plan is not None,
        "plan_options": options_to_plain(state.plan_options),
        "gen_options": options_to_plain(state.gen_options),
        "run": state.runner.status(),
        "last_script": state.last_script_name,
        "secrets": list(state.last_secrets),
    })


# --------------------------------------------------------------------------- recording (live)

@bp.post("/api/record/start")
def record_start() -> Response:
    """Open the recording browser (``reqrec record`` as a child process: the IE engine plus the
    recording proxy, DESIGN.md §13.12) and wait until it is ready.

    Only ``http://`` is recorded; ``https://`` passes through untouched, no certificate is needed and
    nothing in Windows is changed.  Body (all optional): ``{"start_url": "...", "emulation": <mode>,
    "browser": "ie" | "edge"}`` with a mode of :data:`EMULATION_MODES`; ``edge`` opens Microsoft Edge
    with a profile of its own instead of the recording browser (表示モード does not apply).
    """
    state = get_state()
    body = _json_body(required=False)
    start_url = _start_url(body.get("start_url"))
    emulation = str(body.get("emulation") or "default").strip().lower()
    if emulation not in EMULATION_MODES:
        raise ApiError(f"表示モード (emulation) は {' / '.join(EMULATION_MODES)} のいずれかで指定してください")
    browser = str(body.get("browser") or "ie").strip().lower()
    if browser not in RECORD_BROWSERS:
        raise ApiError(f"記録に使うブラウザ (browser) は {' / '.join(RECORD_BROWSERS)} のいずれかで指定してください")
    if state.recorder.running:
        raise ApiError("すでに記録中です。先に [記録をおわる] を押してください。", status=409)
    _require_recording_browser(browser)

    edge = browser == "edge"
    label = "Edge" if edge else "記録用ブラウザ"
    start_kind = ERROR_KIND_EDGE if edge else ERROR_KIND_IEHOST
    out = os.path.join(state.subdir("recordings"), _timestamp_name("rec", ".json"))
    log_path = os.path.join(state.workdir, "logs", _timestamp_name("edge" if edge else "recbrowser", ".log"))
    with state.lock:
        try:
            state.recorder.start(out, url=start_url, emulation=emulation, title=BROWSER_TITLE, log_path=log_path,
                                 browser=browser)
        except RecorderError as exc:
            state.record_error = str(exc)
            raise ApiError(f"{label}を起動できませんでした: {exc}", status=500, kind=start_kind) from exc
    # A first start imports Flask in the child and loads the IE engine: wait without the lock.
    if not state.recorder.wait_until_ready(timeout=RECORD_READY_TIMEOUT):
        failed = state.recorder.status()
        _abandon_start(state, out)
        code = failed.get("exit_code")
        tail = [line for line in (failed.get("stderr_tail") or "").strip().splitlines() if line.strip()]
        detail = failed.get("error") or (tail[-1] if tail else "時間内に開きませんでした")
        state.record_error = detail
        kind = ERROR_KIND_PROXY if code == RECORD_EXIT_PROXY else start_kind
        raise ApiError(f"{label}を開けませんでした: {detail}", status=500, kind=kind, exit_code=code)
    state.record_error = None
    return _ok(
        out=os.path.basename(out),
        out_path=out,
        status=state.recorder.status(),
        emulation=emulation,
        browser=browser,
        self_excluded_hosts=sorted(gui_netlocs(state.host, state.port, flask_request.host)),
    )


@bp.get("/api/record/status")
def record_status() -> Response:
    return jsonify(get_state().recorder.status())


@bp.post("/api/record/stop")
def record_stop() -> Response:
    """Close the recording browser (it writes the recording) and load the recording; ``{"discard":
    true}`` ([やめる]) deletes it instead.  Also called after the browser was closed by the user."""
    state = get_state()
    body = _json_body(required=False)
    discard = _bool(body.get("discard"), False)
    with state.lock:
        was_running = state.recorder.running
        if not was_running and state.recorder.out is None:
            raise ApiError("記録は開始されていません", status=409)
        exit_code = state.recorder.stop()
        if discard:
            # [やめる]: nothing is loaded (the recording already loaded stays as it was), the
            # file is removed and the recorder forgets it.
            removed = _remove_quietly(state.recorder.out)
            _forget_recording(state)
            return _ok(discarded=True, removed=removed, exit_code=exit_code, recording=state.recording_summary())
        out_path = state.recorder.out
        try:
            recording = state.recorder.load_recording()
        except RecorderError as exc:
            if not (out_path and not os.path.exists(out_path) and exit_code is not None):
                raise ApiError(str(exc), status=400, exit_code=exit_code,
                               stderr_tail=state.recorder.status()["stderr_tail"]) from exc
            recording = Recording(flows=[], meta={})  # the browser never got going: nothing was recorded
        if not recording.flows:
            raise ApiError(
                "何も記録されませんでした。記録用ブラウザでページを開く前にブラウザが閉じられたか、"
                "https:// のページ（記録されません）だけを開いた可能性があります。"
                "もう一度 [記録をはじめる] を押し、http:// のページを開いて操作してください。",
                status=400, exit_code=exit_code, out=os.path.basename(state.recorder.out or ""), empty=True,
            )
        summary = _apply_loaded(state, recording, [f"recordings/{os.path.basename(state.recorder.out or '')}"], from_gui_recorder=True)
    summary.update(out=os.path.basename(state.recorder.out or ""), out_path=state.recorder.out, exit_code=exit_code)
    return _ok(**summary)


# --------------------------------------------------------------------------- recordings (files)

@bp.post("/api/recordings/upload")
def recordings_upload() -> Response:
    state = get_state()
    files = flask_request.files.getlist("files") or flask_request.files.getlist("file")
    files = [f for f in files if f and f.filename]
    if not files:
        raise ApiError("ファイルが選択されていません (.har / .json)")
    saved: list[str] = []
    display: list[str] = []
    for storage in files:
        name = sanitise_upload_name(storage.filename)
        ext = os.path.splitext(name)[1].lower()
        if ext not in RECORDING_EXTENSIONS:
            raise ApiError(f"対応していないファイル形式です: {storage.filename} (対応: .har / .json)")
        target = unique_path(state.path_in("uploads", name, "アップロードファイル名"))
        try:
            storage.save(target)
        except OSError as exc:
            raise ApiError(f"ファイルを保存できません: {exc}", status=500) from exc
        saved.append(target)
        display.append(f"uploads/{os.path.basename(target)}")
    recording = load_sources(saved)  # several files (one HAR per tab) are merged by time stamp
    with state.lock:
        summary = _apply_loaded(state, recording, display, from_gui_recorder=False)
    summary["saved"] = [os.path.basename(p) for p in saved]
    return _ok(**summary)


# --------------------------------------------------------------------------- analysis

@bp.post("/api/plan")
def api_plan() -> Response:
    state = get_state()
    body = _json_body(required=False)
    plan_opts, _gen = _options_from_body(body)
    with state.lock:
        plan = _rebuild_plan(state, plan_opts)
        payload = _plan_payload(state, plan)
    return jsonify(payload)


@bp.get("/api/flow/<flow_id>")
def api_flow(flow_id: str) -> Response:
    state = get_state()
    if not _GUI_FLOW_ID_RE.match(flow_id or ""):
        raise ApiError(f"フロー ID が不正です: {flow_id}", status=404)
    with state.lock:
        recording = state.require_recording()
        flow = recording.flow_by_id(flow_id)
        if flow is None:
            raise ApiError(f"フロー {flow_id} はありません", status=404)
        plan = state.plan
        step_index = None
        reason = None
        if plan is not None:
            for step in plan.steps:
                if flow_id in step.source_flow_ids:
                    step_index = step.index
                    break
            if step_index is None:
                reason = next((d.reason for d in plan.dropped if d.flow_id == flow_id), None)
        req = flow.request
        resp = flow.response
        payload = {
            "id": flow.id,
            "started_at": flow.started_at,
            "started_at_iso": _iso(flow.started_at),
            "resource_type": flow.resource_type,
            "page_ref": flow.page_ref,
            "step_index": step_index,
            "reason": reason,
            "request": {
                "method": req.method,
                "url": req.url,
                "host": req.host,
                "path": req.path,
                "query": [list(p) for p in req.query_pairs],
                "headers": [list(h) for h in req.headers],
                "body": _body_view(req.body, req.header("content-type"), req.content_type),
            },
            "response": None if resp is None else {
                "status": resp.status,
                "headers": [list(h) for h in resp.headers],
                "mime": resp.mime_type,
                "body": _body_view(resp.body, resp.header("content-type"), resp.mime_type),
            },
        }
    return jsonify(payload)


# --------------------------------------------------------------------------- generation

def _suggest_script_name(plan: Plan) -> str:
    host = ""
    for step in plan.steps:
        url = step.literal_url()
        if url:
            host = RecordedRequest("GET", url).host
            break
    slug = safe_identifier(host.replace(".", "_"), default="site").strip("_") if host else "site"
    return f"scrape_{slug or 'site'}"[:60]


#: Plan / codegen notes that describe what the script does for the user rather than a risk
#: (Shift_JIS form bodies are re-encoded faithfully): shown as information, not under 「確認してください」.
_INFO_NOTE_MARKERS = ("UTF-8 以外の文字コード", "looks like a credential", "セッション切替を検出しました", "手順に含めました")


def _split_warnings(warnings: list[str]) -> tuple[list[str], list[str]]:
    actionable: list[str] = []
    notes: list[str] = []
    for w in warnings:
        bucket = notes if any(m in w for m in _INFO_NOTE_MARKERS) else actionable
        if w not in bucket:
            bucket.append(w)
    return actionable, notes


def _path_part(label: str) -> str:
    """``path segment 2`` (0-based index from deps.request_params) -> 「URL の / で区切った 3 番目の部分」,
    any other parameter name -> 「「name」の値」."""
    m = re.fullmatch(r"path segment (\d+)", label)
    if m:
        return f"URL の / で区切った {int(m.group(1)) + 1} 番目の部分"
    return f"「{label}」の値"


#: The English plan warnings (analysis section, former plan.py) in plain Japanese for the easy screen.  The patterns
#: follow the plan section's wording exactly; tests/test_gui.py (easy-mode section) runs build_plan + generate on every
#: fixture and checks that each produced warning comes out in Japanese.
_WARNING_TRANSLATIONS: tuple[tuple[Any, Any], ...] = (
    (re.compile(r"step (\d+): value of `(.+)` looks dynamic but could not be traced to any earlier "
                r"response; replaying the recorded literal may fail", re.S),
     lambda m: (f"手順 {m.group(1)}: {_path_part(m.group(2))}は毎回変わるもののようですが、それより前の画面の"
                f"どこから来たのか分かりませんでした。記録したときの値をそのまま送るため、実行すると失敗することがあります。")),
    (re.compile(r"step (\d+): `(.+)` looks like a credential; the script reads it from the environment "
                r"variable (\S+) \(set it before running\)", re.S),
     lambda m: (f"手順 {m.group(1)}: 「{m.group(2)}」はパスワードなどの秘密の値と思われるため、スクリプトには"
                f"書き込まず、実行するときに入力します (環境変数 {m.group(3)})。")),
    (re.compile(r"recording has (\d+) steps; truncated to --max-steps (\d+) \((\d+) step\(s\) ignored\)", re.S),
     lambda m: (f"記録には {m.group(1)} 手順ありましたが、上限の {m.group(2)} 手順で打ち切りました "
                f"(残りの {m.group(3)} 手順は使っていません)。詳細設定の「手順の数の上限」で変えられます。")),
    (re.compile(r"(\d+) cookie\(s\) existed before the recording started \((.*)\); they are replayed as "
                r"INITIAL_COOKIES and may have expired", re.S),
     lambda m: (f"記録を始める前からあった Cookie が {m.group(1)} 個あります ({m.group(2)})。スクリプトは"
                f"これを最初からそのまま送るため、期限が切れていると失敗することがあります。"
                f"そのときは、ブラウザを開き直してからもう一度記録してください。")),
    # Japanese warnings keep their text; only the step prefix is made readable
    (re.compile(r"step (\d+): (.*)", re.S), lambda m: f"手順 {m.group(1)}: {m.group(2)}"),
    (re.compile(r"step_(\d+)_\w*: (.*)", re.S), lambda m: f"手順 {int(m.group(1))}: {m.group(2)}"),
)


def warning_message(text: str) -> str:
    """Plain-Japanese version of one plan / codegen warning (unchanged when it is not recognised)."""
    raw = str(text or "")
    for pattern, render in _WARNING_TRANSLATIONS:
        m = pattern.fullmatch(raw.strip())
        if m:
            return render(m)
    return raw


def _warning_details(warnings: list[str]) -> list[dict[str, str]]:
    """``[{"text": <original>, "message": <plain Japanese>}]`` for the easy screen."""
    return [{"text": w, "message": warning_message(w)} for w in warnings]


def _is_attachment(content_disposition: Optional[str]) -> bool:
    """Shared download rule (1): ``Content-Disposition`` starting with ``attachment``, or naming a
    ``filename`` without being ``inline`` (:func:`is_attachment_disposition`, the same
    rule as the generated scripts' ``_is_attachment``)."""
    return is_attachment_disposition(content_disposition)


def _downloads_of(recording: Recording, plan: Plan) -> list[dict[str, Any]]:
    """What the generated script will save, shown on the easy screen as 「保存されるファイル」.

    Shared download rule (5): every step whose **recorded** response is binary
    (``response_kind == "binary"``) or an attachment per :func:`_is_attachment` (html / text steps
    included); loop steps too, marked ``loop: true`` (one file per iteration).  ``filename`` comes
    from :func:`download_filename` (``None`` when the header names no file).
    """
    by_id = {f.id: f for f in recording.flows}
    out: list[dict[str, Any]] = []
    for step in plan.steps:
        if not step.source_flow_ids:
            continue
        flow = by_id.get(step.source_flow_ids[-1])
        resp = flow.response if flow is not None else None
        disposition = resp.header("content-disposition") if resp is not None else None
        if step.response_kind != "binary" and not _is_attachment(disposition):
            continue
        out.append({
            "index": step.index,
            "method": step.method,
            "url": step.literal_url() or (flow.request.url_without_query if flow is not None else ""),
            "filename": download_filename(disposition),
            "mime": resp.mime_type if resp is not None else None,
            "loop": step.loop is not None,
        })
    return out


@bp.post("/api/scripts/save")
def scripts_save() -> Response:
    state = get_state()
    body = _json_body()
    code = body.get("code")
    if code is None:
        code = state.last_code
    if not isinstance(code, str) or not code.strip():
        raise ApiError("保存するコードがありません。")
    name = _script_name(body.get("name"))
    path = state.path_in("scripts", name, "スクリプト名")
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code if code.endswith("\n") else code + "\n")
    except OSError as exc:
        raise ApiError(f"スクリプトを保存できません: {exc}", status=500) from exc
    state.last_script_name = name
    return _ok(name=name, path=path, size=os.path.getsize(path), download_url=f"/api/scripts/{name}/download")


@bp.get("/api/scripts/<name>/download")
def scripts_download(name: str) -> Response:
    state = get_state()
    clean = _script_name(name)
    path = state.path_in("scripts", clean, "スクリプト名")
    if not os.path.isfile(path):
        raise ApiError(f"スクリプトが見つかりません: {clean}", status=404)
    return send_from_directory(state.subdir("scripts"), clean, as_attachment=True, download_name=clean, mimetype="text/x-python")


# --------------------------------------------------------------------------- run

@bp.post("/api/run")
def run_start() -> Response:
    state = get_state()
    body = _json_body()
    name = _script_name(body.get("name") or state.last_script_name)
    env = body.get("env") or {}
    if not isinstance(env, dict):
        raise ApiError("env はオブジェクト {\"VAR\": \"value\"} で指定してください")
    path = state.path_in("scripts", name, "スクリプト名")
    child_env = {str(k): v for k, v in env.items()}
    # downloaded files (Excel / CSV export ...) land in <workdir>/outputs unless the user chose otherwise
    child_env.setdefault("REQREC_OUTPUT_DIR", state.subdir("outputs"))
    status = state.runner.start(path, env=child_env, cwd=state.subdir("scripts"))
    state.last_script_name = name
    return _ok(**status)


@bp.get("/api/run/status")
def run_status() -> Response:
    return jsonify(get_state().runner.status())


@bp.post("/api/run/stop")
def run_stop() -> Response:
    state = get_state()
    if not state.runner.running:
        return _ok(**state.runner.status(), stopped=False)
    status = state.runner.stop()
    return _ok(**status, stopped=True)


@bp.post("/api/run/save_output")
def run_save_output() -> Response:
    state = get_state()
    body = _json_body(required=False)
    raw = body.get("name") or _timestamp_name("output", ".txt")
    name = safe_name(raw, "出力ファイル名")
    if "." not in name:
        name += ".txt"
    output = state.runner.last_stdout()
    if not output and state.runner.started_at is None:
        raise ApiError("保存できる出力がありません。先にスクリプトを実行してください。", status=409)
    path = state.path_in("outputs", name, "出力ファイル名")
    try:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(output)
    except OSError as exc:
        raise ApiError(f"出力を保存できません: {exc}", status=500) from exc
    return _ok(name=name, path=path, size=len(output.encode("utf-8")), truncated=state.runner.status()["stdout_truncated"])


# --------------------------------------------------------------------------- かんたんモード (DESIGN.md §13.11)

#: Folders of the work directory the easy mode may open in the file manager.
_OPENABLE_FOLDERS = ("workdir", "scripts", "outputs", "recordings", "uploads")


@bp.post("/api/folder/open")
def folder_open() -> Response:
    """Show one of the work folders in Explorer / Finder: ``{"folder": "scripts"}``."""
    state = get_state()
    body = _json_body(required=False)
    folder = str(body.get("folder") or "scripts").strip().lower()
    if folder not in _OPENABLE_FOLDERS:
        raise ApiError(f"開けるフォルダは {', '.join(_OPENABLE_FOLDERS)} のいずれかです")
    path = state.workdir if folder == "workdir" else state.subdir(folder)
    try:
        result = open_folder(path)
    except FileNotFoundError as exc:
        raise ApiError(str(exc), status=404) from exc
    except RuntimeError as exc:
        raise ApiError(str(exc), status=500) from exc
    return _ok(**result)


@bp.post("/api/easy/build")
def easy_build() -> Response:
    """Analyse the loaded recording with the current (or given) options, generate the script and
    save it under ``scripts/``: the easy screen after a recording, and 詳細設定 [設定から作り直す]
    (which passes the current script's ``name`` and its options, so the file is replaced).

    Body (all optional): ``{"name": "...", "plan_options": {...}, "gen_options": {...}}``.
    Returns what both screens show: file name / path / download URL, step count, the final
    step's URL, warnings, the secrets the user must type before running, the options used and the
    code itself.
    """
    state = get_state()
    body = _json_body(required=False)
    plan_opts, gen_opts = _options_from_body(body)
    with state.lock:
        plan = _rebuild_plan(state, plan_opts)
        if not plan.steps:
            raise ApiError(
                "スクリプトにできる通信が記録にありませんでした。サイトの画面を開いた操作が記録（HAR ファイル）に"
                "入っているかを確認してください（HAR ファイルは、F12 の「Preserve log」にチェックを入れて操作してから保存します）。",
                status=400,
            )
        try:
            code = generate(plan, gen_opts)
        except Exception as exc:
            current_app.logger.exception("generate failed")
            raise ApiError(f"コード生成に失敗しました: {exc}", status=500) from exc
        state.gen_options = gen_opts
        state.last_code = code
        secrets = _secrets_of(plan)
        state.last_secrets = secrets
        raw_name = body.get("name")
        if raw_name is None or not str(raw_name).strip():
            raw_name = f"{_suggest_script_name(plan)}_{datetime.now().strftime('%Y%m%d_%H%M')}"
        name = _script_name(raw_name)
        path = state.path_in("scripts", name, "スクリプト名")
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(code if code.endswith("\n") else code + "\n")
        except OSError as exc:
            raise ApiError(f"スクリプトを保存できません: {exc}", status=500) from exc
        state.last_script_name = name
        recording = state.require_recording()
        final_index = plan.final_step_index or (plan.steps[-1].index if plan.steps else None)
        final_step = next((s for s in plan.steps if s.index == final_index), None)
        actionable, notes = _split_warnings(list(plan.warnings))
        steps_view = [
            {
                "index": s.index,
                "method": s.method,
                "url": s.literal_url() or "".join(r.value if r.is_literal else "{…}" for r in s.url),
                "loop": s.loop is not None,
                "extracts": len(s.extractors),
            }
            for s in plan.steps
        ]
        payload = {
            "name": name,
            "path": path,
            "download_url": f"/api/scripts/{name}/download",
            "steps": len(plan.steps),
            "steps_view": steps_view,
            "final_step_index": final_index,
            "final_url": final_step.literal_url() if final_step is not None else None,
            "final_method": final_step.method if final_step is not None else None,
            "flows_total": len(recording.flows),
            "warnings": actionable,
            "notes": notes,
            # the same lists with a plain-Japanese ``message`` per entry (what the easy screen shows)
            "warning_details": _warning_details(actionable),
            "note_details": _warning_details(notes),
            "downloads": _downloads_of(recording, plan),
            "secrets": secrets,
            "auth": to_plain(plan.auth) if plan.auth is not None else None,
            "summary": format_plan_summary(plan, flows_total=len(recording.flows)),
            "code": code,
            "sources": list(state.sources),
            "plan_options": options_to_plain(plan_opts),
            "gen_options": options_to_plain(gen_opts),
        }
    return _ok(**payload)


# ===== former reqrec/webapp/__init__.py: app factory (create_app / run_gui) and the security hook =====
# Flask based no-code GUI for reqrec.  Contract: DESIGN.md §13.6.
#
# ``create_app(workdir)`` builds the Flask application; ``run_gui`` starts it (and opens a browser):
# ``python reqrec.py``.  ``create_app()`` without arguments is the factory ``python -m flask --app
# reqrec run`` finds.
#
# Security model (the user's browser visits arbitrary sites while this GUI runs):
#
# * requests from this PC itself need no login; their ``Host`` must be the bound address /
#   ``127.0.0.1`` / ``localhost`` / ``::1`` (DNS-rebinding guard);
# * requests from other PCs need a login session (``/login`` with :data:`GUI_PASSWORD` or the
#   environment variable ``REQREC_GUI_PASSWORD``: a signed HttpOnly, SameSite=Strict cookie; wrong
#   passwords in a row lock the address out for a while); with an empty password they are refused;
# * every ``POST`` / ``PUT`` / ``DELETE`` must carry ``X-Reqrec-Token`` equal to a per-process random
#   token the page receives through the template (``<body data-token>``), and a state-changing request
#   with an ``Origin`` header must come from the page itself;
# * file names from the browser only ever map to files inside ``workdir`` (``safe_name``).

TOKEN_HEADER = "X-Reqrec-Token"
#: Template name of the page (``GUI_HTML``); the ``.html`` suffix turns Jinja autoescaping on.
_GUI_TEMPLATE = "gui.html"

_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_WILDCARD_HOSTS = frozenset({"0.0.0.0", "::", "[::]", "*", ""})
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Uploads (HAR files can be large). 1 GiB by default; override with ``create_app(..., MAX_CONTENT_LENGTH=...)``.
_DEFAULT_MAX_UPLOAD = 1024 * 1024 * 1024

_BROWSER_OPEN_DELAY = 0.8

#: Template name of the login page (:data:`LOGIN_HTML`), shown only when a GUI password is set.
_LOGIN_TEMPLATE = "login.html"
#: Session key that marks a logged-in browser.
_SESSION_AUTH_KEY = "reqrec_auth"
#: Wrong passwords in a row from one address before it is locked out, and for how long (seconds).
_LOGIN_MAX_FAILURES = 5
_LOGIN_LOCK_SECONDS = 60.0
#: Pause after a wrong password (slows down guessing); tests pass ``LOGIN_FAIL_DELAY=0``.
_LOGIN_FAIL_DELAY = 1.0
#: How long a login lasts (seconds): one work shift.
_LOGIN_LIFETIME = 12 * 60 * 60
#: Printed at start-up while the initial password is still in use.
_DEFAULT_PASSWORD_WARNING = (f"注意: GUI のパスワードが初期値 ({_DEFAULT_GUI_PASSWORD}) のままです。他の PC から使う前に、"
                             "reqrec.py の GUI_PASSWORD を書き換えてください。")

#: The login page (Jinja template; plain HTML and CSS, no script, so it also works in the IE engine).
LOGIN_HTML = r'''<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>reqrec — ログイン</title>
<style>
body { margin: 0; background: #f4f6f9; color: #1f2933; font-family: "Segoe UI", "Yu Gothic UI", Meiryo, sans-serif; }
main { max-width: 22rem; margin: 12vh auto 0; padding: 1.6rem 1.8rem; background: #fff; border: 1px solid #d9dee5; border-radius: 10px; }
h1 { margin: 0 0 .3rem; font-size: 1.25rem; }
p { margin: .2rem 0 1rem; color: #52606d; font-size: .9rem; }
label { display: block; margin-bottom: .35rem; font-weight: 600; }
input { box-sizing: border-box; width: 100%; padding: .55rem .6rem; font-size: 1rem; border: 1px solid #b8c2cc; border-radius: 6px; }
button { width: 100%; margin-top: 1rem; padding: .6rem; color: #fff; background: #2563eb; border: 0; border-radius: 6px; font-size: 1rem; font-weight: 600; cursor: pointer; }
.error { margin-bottom: 1rem; padding: .5rem .7rem; color: #9b1c1c; background: #fdecec; border: 1px solid #f5c2c2; border-radius: 6px; font-size: .9rem; }
</style>
</head>
<body>
<main>
  <h1>reqrec</h1>
  <p>パスワードを入力してください。</p>
  {% if error %}<div class="error" id="login-error" role="alert">{{ error }}</div>{% endif %}
  <form method="post" action="/login">
    <label for="password">パスワード</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
    <button type="submit">ログイン</button>
  </form>
</main>
</body>
</html>
'''


def _is_loopback_addr(addr: Optional[str]) -> bool:
    """``127.x.x.x`` / ``::1`` (also as an IPv4-mapped IPv6 address): a request from this PC itself."""
    try:
        ip = ipaddress.ip_address((addr or "").split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(ip.is_loopback or (mapped is not None and mapped.is_loopback))


# --------------------------------------------------------------------------- host / origin checks

def _split_host(value: str) -> str:
    """``[::1]:8765`` -> ``[::1]``, ``LocalHost:80`` -> ``localhost`` (port removed, lower-case)."""
    v = (value or "").strip().lower()
    if not v:
        return ""
    if v.startswith("["):
        end = v.find("]")
        return v[: end + 1] if end != -1 else v
    if v.count(":") == 1:
        v = v.split(":", 1)[0]
    return v


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def host_allowed(host_header: str, bind_host: str) -> bool:
    """Is this ``Host`` header one of ours?  (bound host, loopback names; any IP literal for a
    wildcard bind, because DNS rebinding needs a *name*)."""
    host = _split_host(host_header)
    if not host:
        return False
    if host in _LOCAL_HOSTS:
        return True
    bind = (bind_host or "").strip().lower()
    if bind and bind not in _WILDCARD_HOSTS:
        bind_norm = bind if not (":" in bind and not bind.startswith("[")) else f"[{bind}]"
        if host == bind_norm:
            return True
        if _is_ip_literal(host) and _is_ip_literal(bind_norm) and ipaddress.ip_address(host.strip("[]")) == ipaddress.ip_address(bind_norm.strip("[]")):
            return True
        return False
    return _is_ip_literal(host)


def origin_allowed(origin: Optional[str], host_header: str, scheme: str = "http") -> bool:
    """A browser ``Origin`` is accepted only when it names this very page (scheme + host[:port])."""
    if origin is None:
        return True  # non-browser client; the token still protects the endpoint
    o = origin.strip()
    if not o or o.lower() == "null":
        return False
    parts = urlsplit(o)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return False
    return _normalise_netloc(parts.netloc, parts.scheme) == _normalise_netloc(host_header, scheme)


def _normalise_netloc(netloc: str, scheme: str) -> str:
    n = (netloc or "").strip().lower()
    default = {"http": ":80", "https": ":443"}.get(scheme or "http")
    if default and n.endswith(default):
        n = n[: -len(default)]
    return n


# --------------------------------------------------------------------------- factory

def create_app(workdir: Optional[str] = None, **config: Any) -> Flask:
    """Build the Flask app.

    ``workdir`` defaults to the environment variable ``REQREC_WORKDIR`` or ``reqrec_work``; called
    without arguments this is the factory ``flask --app reqrec run`` finds, and the children it starts
    (the recording browser, a script run) are then stopped at exit.  ``config`` may hold
    ``host`` / ``port`` (what the server binds; used for the Host check and for excluding the GUI's
    own traffic from recordings), ``token`` (per-process CSRF token; generated when omitted),
    ``password`` (the login password for other PCs; defaults to the environment variable
    ``REQREC_GUI_PASSWORD``, else :data:`GUI_PASSWORD`; empty = other PCs are refused), ``recorder`` /
    ``runner`` (test doubles) and any upper-case Flask config key (``MAX_CONTENT_LENGTH``, ``TESTING``,
    ``LOGIN_FAIL_DELAY`` ...).  Requests from this PC itself never need a login.
    """
    from_cli = workdir is None
    if workdir is None:
        workdir = os.environ.get(WORKDIR_ENV) or "reqrec_work"
    host = str(config.pop("host", "127.0.0.1") or "127.0.0.1")
    port = int(config.pop("port", 8765) or 8765)
    token = config.pop("token", None)
    password = config.pop("password", None)
    if password is None:
        password = _gui_password()
    password = str(password or "")
    recorder = config.pop("recorder", None)
    runner = config.pop("runner", None)

    # The page is the single template ``GUI_HTML`` (CSS / JS inlined): no templates/ or static/ folder
    # and no static route.  ``root_path`` is given so Flask never searches for the import name.  The
    # template is served by name from memory, so Jinja compiles it once per app and caches it
    # (``render_template_string`` would compile the 140 KB page again on every ``GET /``).
    app = Flask("reqrec.gui", root_path=os.path.dirname(os.path.abspath(__file__)), template_folder=None, static_folder=None)
    app.jinja_loader = DictLoader({_GUI_TEMPLATE: GUI_HTML, _LOGIN_TEMPLATE: LOGIN_HTML})
    app.config.update(
        MAX_CONTENT_LENGTH=_DEFAULT_MAX_UPLOAD,
        JSON_SORT_KEYS=False,
        SEND_FILE_MAX_AGE_DEFAULT=0,
        TEMPLATES_AUTO_RELOAD=False,
        LOGIN_FAIL_DELAY=_LOGIN_FAIL_DELAY,
    )
    for key, value in config.items():
        app.config[key.upper()] = value
    app.json.ensure_ascii = False  # Japanese stays readable in responses / logs
    app.json.sort_keys = False

    state = AppState(workdir, host=host, port=port, token=token, recorder=recorder, runner=runner)
    app.extensions["reqrec"] = state
    app.config.update(REQREC_WORKDIR=state.workdir, REQREC_TOKEN=state.token, REQREC_HOST=host, REQREC_PORT=port,
                      REQREC_LOGIN_ENABLED=bool(password))
    # Login sessions: a signed cookie that is valid for this process only (a restart logs everyone
    # out).  Its name carries the work folder, so another web app on the same server never overwrites
    # it (browsers keep cookies per host, not per port).
    app.secret_key = secrets.token_bytes(32)
    app.config.update(
        SESSION_COOKIE_NAME="reqrec_session_" + hashlib.sha256(state.workdir.encode("utf-8")).hexdigest()[:8],
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=_LOGIN_LIFETIME,
    )

    app.register_blueprint(bp)

    # ---------------------------------------------------------------- login (only with a password)
    failures: dict[str, tuple[int, float]] = {}  # address -> (wrong passwords in a row, locked until)
    failures_lock = threading.Lock()

    def _login():  # type: ignore[no-untyped-def]
        error: Optional[str] = None
        status = 200
        if flask_request.method == "POST":
            addr = flask_request.remote_addr or "?"
            now = time.time()
            with failures_lock:
                count, locked_until = failures.get(addr, (0, 0.0))
            if locked_until > now:
                error = f"パスワードを続けて間違えたため、あと {int(locked_until - now) + 1} 秒はログインできません。"
                status = 429
            elif hmac.compare_digest(flask_request.form.get("password", "").encode("utf-8"), password.encode("utf-8")):
                with failures_lock:
                    failures.pop(addr, None)
                flask_session.clear()
                flask_session.permanent = True
                flask_session[_SESSION_AUTH_KEY] = True
                return redirect("/")
            else:
                delay = float(app.config.get("LOGIN_FAIL_DELAY") or 0)
                if delay > 0:
                    time.sleep(delay)
                count += 1
                if count >= _LOGIN_MAX_FAILURES:
                    with failures_lock:
                        failures[addr] = (0, now + _LOGIN_LOCK_SECONDS)
                    error = (f"パスワードを {_LOGIN_MAX_FAILURES} 回続けて間違えたため、"
                             f"{int(_LOGIN_LOCK_SECONDS)} 秒間ログインできません。")
                    status = 429
                else:
                    with failures_lock:
                        failures[addr] = (count, 0.0)
                    error = "パスワードが違います。"
                    status = 401
        elif flask_session.get(_SESSION_AUTH_KEY):
            return redirect("/")
        # ``same-origin``, not the GUI's ``no-referrer``: under ``no-referrer`` browsers send
        # ``Origin: null`` with the form post, which the CSRF check rejects.
        return render_template(_LOGIN_TEMPLATE, error=error), status, {"Referrer-Policy": "same-origin"}

    def _logout():  # type: ignore[no-untyped-def]
        flask_session.clear()
        return redirect("/login")

    if password:
        app.add_url_rule("/login", "login", _login, methods=["GET", "POST"])
        app.add_url_rule("/logout", "logout", _logout, methods=["GET"])

    # ---------------------------------------------------------------- security hook
    @app.before_request
    def _guard():  # type: ignore[no-untyped-def]
        api_like = flask_request.path.startswith("/api/") or flask_request.method in _UNSAFE_METHODS
        local = _is_loopback_addr(flask_request.remote_addr)
        if local:
            # this PC itself: no login (the easy screen stays "記録をはじめる → 操作 → おわる"), but
            # the DNS-rebinding guard applies
            if not host_allowed(flask_request.host, host):
                return jsonify({"error": f"この Host ヘッダーからのアクセスは許可されていません: {flask_request.host}"}), 403
        elif not password:
            message = ("この PC 以外から使うにはパスワードが必要ですが、設定されていません。"
                       f"reqrec.py の GUI_PASSWORD か環境変数 {GUI_PASSWORD_ENV} にパスワードを設定して起動し直してください。")
            if api_like:
                return jsonify({"error": message}), 403
            return Response(message, status=403, mimetype="text/plain")
        if password and flask_request.path == "/login":
            if flask_request.method in _UNSAFE_METHODS and not origin_allowed(
                    flask_request.headers.get("Origin"), flask_request.host, flask_request.scheme):
                return jsonify({"error": "別のオリジンからのリクエストは拒否しました (CSRF 対策)"}), 403
            return None
        if not local and not flask_session.get(_SESSION_AUTH_KEY):
            if api_like:
                return jsonify({"error": "ログインしていません。ページを再読み込みしてログインしてください。", "login": True}), 401
            return redirect("/login")
        if flask_request.method in _UNSAFE_METHODS:
            if not origin_allowed(flask_request.headers.get("Origin"), flask_request.host, flask_request.scheme):
                return jsonify({"error": "別のオリジンからのリクエストは拒否しました (CSRF 対策)"}), 403
            sent = flask_request.headers.get(TOKEN_HEADER, "")
            if not sent or not hmac.compare_digest(sent, state.token):
                return jsonify({"error": "認証トークンが一致しません。GUI のページを再読み込みしてください。"}), 403
        return None

    @app.after_request
    def _headers(resp):  # type: ignore[no-untyped-def]
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        if flask_request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------------------------------------------------------------- errors -> JSON
    @app.errorhandler(ApiError)
    def _api_error(exc: ApiError):  # type: ignore[no-untyped-def]
        return jsonify(exc.to_dict()), exc.status

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):  # type: ignore[no-untyped-def]
        if flask_request.path.startswith("/api/") or flask_request.method in _UNSAFE_METHODS:
            messages = {
                404: "指定された API はありません",
                405: "この HTTP メソッドは使えません",
                413: "ファイルが大きすぎます (上限を超えました)",
                400: "リクエストが不正です",
            }
            msg = messages.get(exc.code or 0, exc.name)
            return jsonify({"error": msg, "status": exc.code}), exc.code or 500
        return exc

    @app.errorhandler(Exception)
    def _unexpected(exc: Exception):  # type: ignore[no-untyped-def]
        if app.testing or app.debug:
            raise exc
        app.logger.exception("unhandled error")
        return jsonify({"error": f"内部エラーが発生しました: {exc.__class__.__name__}: {exc}"}), 500

    if from_cli:
        # ``flask --app reqrec run``: nobody calls run_gui, so stop the children at exit and say where
        # the files go and whether a login is needed.
        import atexit

        atexit.register(_shutdown, state)
        login = ("他の PC からはパスワードでログインして使います" if password else
                 "パスワードが未設定のため、この PC の中からだけ使えます")
        print(f"reqrec: 作業フォルダ: {state.workdir} / {login}", file=sys.stderr, flush=True)
        if password == _DEFAULT_GUI_PASSWORD:
            print(_DEFAULT_PASSWORD_WARNING, file=sys.stderr, flush=True)
    return app


# --------------------------------------------------------------------------- running

def _display_host(host: str) -> str:
    return "127.0.0.1" if host in _WILDCARD_HOSTS else host


def _port_free(host: str, port: int) -> Optional[str]:
    """None when ``host:port`` can be bound, else a Japanese explanation."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            if os.name != "nt":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", 10048)):
            return f"ポート {port} は既に使われています。別のポートを --port で指定するか、起動中の reqrec gui を終了してください。"
        if exc.errno in (errno.EACCES, getattr(errno, "WSAEACCES", 10013)):
            return f"ポート {port} を開く権限がありません。--port で 1024 以上のポートを指定してください。"
        if exc.errno == errno.EADDRNOTAVAIL:
            return f"アドレス {host} はこの PC に存在しません。--host を確認してください。"
        return f"{host}:{port} で待ち受けできません: {exc}"
    return None


def _open_browser_later(url: str, host: str, port: int, delay: float = _BROWSER_OPEN_DELAY) -> threading.Thread:
    """Open the browser once the server answers (so a failed start never pops an error page)."""

    def _worker() -> None:
        deadline = time.time() + 10.0
        time.sleep(delay)
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            return
        try:
            webbrowser.open(url)
        except Exception:
            pass

    t = threading.Thread(target=_worker, name="reqrec-open-browser", daemon=True)
    t.start()
    return t


def run_gui(host: str = "127.0.0.1", port: int = 8765, workdir: str = "reqrec_work", open_browser: bool = True) -> int:
    """Start the GUI server (blocking) and return a process exit code (``0`` after Ctrl+C)."""
    port = int(port)
    password = _gui_password()
    exposed = (host or "").strip().lower() not in _LOCAL_HOSTS
    if exposed and not password:
        print(f"GUI を起動できません: --host {host} で他の PC から使えるようにするときは、パスワードが必要です。"
              f"reqrec.py の GUI_PASSWORD か環境変数 {GUI_PASSWORD_ENV} にパスワードを設定してから起動してください。",
              file=sys.stderr)
        return 1
    try:
        app = create_app(workdir, host=host, port=port)
    except (RuntimeError, OSError) as exc:
        print(f"GUI を起動できません: {exc}", file=sys.stderr)
        return 1
    url = f"http://{_display_host(host)}:{port}"
    problem = _port_free(host, port)
    if problem:
        print(f"GUI を起動できません: {problem}", file=sys.stderr)
        return 1
    print(f"GUI を起動しました: {url}  (Ctrl+C で終了)", flush=True)
    print(f"作業フォルダ: {app.extensions['reqrec'].workdir}", flush=True)
    if exposed:
        print("他の PC からはパスワードでログインして使います", flush=True)
        if password == _DEFAULT_GUI_PASSWORD:
            print(_DEFAULT_PASSWORD_WARNING, flush=True)
    if open_browser:
        _open_browser_later(url, _display_host(host), port)
    state: AppState = app.extensions["reqrec"]
    try:
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        print("\nGUI を終了します", flush=True)
        return 0
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", 10048)):
            print(f"GUI を起動できません: ポート {port} は既に使われています。--port で別のポートを指定してください。", file=sys.stderr)
        else:
            print(f"GUI を起動できません: {exc}", file=sys.stderr)
        return 1
    finally:
        _shutdown(state)
    return 0


def _shutdown(state: AppState) -> None:
    """Stop the children (the recording browser, a script run)."""
    try:
        state.close()
    except Exception:
        pass


# ===== former reqrec/gui.html: the GUI page (GUI_HTML) =====
# The single page of the GUI: a Jinja template (name ``_GUI_TEMPLATE``, served from memory by
# ``create_app``'s loader) rendered by the ``/`` route, the CSS and the JavaScript inlined in
# ``{% raw %}`` blocks (vanilla JS, no CDN, no build step: the GUI works offline).  Started as the
# former file; on 2026-10-12 the inputs of the removed recording modes were taken out (port, listen
# address, recording method, system proxy, certificate, https recording, legacy TLS).

#: The GUI page (Jinja template).
GUI_HTML = r'''<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>reqrec — HTTP 記録からスクレイピングスクリプトを自動生成</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%231f5fbf'/%3E%3Ccircle cx='16' cy='16' r='7' fill='%23fff'/%3E%3Ccircle cx='16' cy='16' r='3.5' fill='%23c0392b'/%3E%3C/svg%3E">
{# reqrec GUI page, rendered by the index route (reqrec.py, gui section).  Former reqrec/webapp/templates/index.html
   with reqrec/webapp/static/app.css and app.js inlined below (same origin, no external resources;
   Jinja raw blocks keep the CSS / JS verbatim).  Every piece of recorded content is inserted with
   textContent, never innerHTML. -#}
<style>
{% raw %}
/* ===== former reqrec/webapp/static/app.css ===== */
/* reqrec GUI — plain CSS, no frameworks, no external resources. Light theme, system fonts. */

:root {
  --bg: #f4f6f9;
  --surface: #ffffff;
  --surface-2: #f8fafc;
  --border: #d9dee7;
  --border-strong: #b9c2d0;
  --text: #1c2430;
  --text-muted: #5b6676;
  --text-faint: #8a94a6;
  --primary: #1f5fbf;
  --primary-hover: #174c99;
  --primary-soft: #e6effc;
  --danger: #c0392b;
  --danger-soft: #fbeae8;
  --ok: #1e8e4b;
  --ok-soft: #e4f5ea;
  --warn: #b26a00;
  --warn-soft: #fff4e0;
  --info-soft: #eef3fb;
  --dropped-bg: #f6f7f9;
  --dropped-text: #8a94a6;
  --radius: 10px;
  --shadow: 0 1px 2px rgba(16, 24, 40, .06), 0 1px 3px rgba(16, 24, 40, .08);
  --mono: ui-monospace, "SFMono-Regular", Menlo, Consolas, "BIZ UDGothic", "MS Gothic", monospace;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", "Hiragino Sans", "Hiragino Kaku Gothic ProN", "Yu Gothic UI", "Meiryo", Roboto, "Noto Sans JP", sans-serif;
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  font-family: var(--font);
  font-size: 14.5px;
  line-height: 1.55;
  color: var(--text);
  background: var(--bg);
  -webkit-font-smoothing: antialiased;
}
a { color: var(--primary); }
code { font-family: var(--mono); font-size: .92em; background: var(--surface-2); border: 1px solid var(--border); border-radius: 4px; padding: 0 .3em; word-break: break-all; }
h1 { font-size: 1.45rem; margin: 0 0 .35rem; letter-spacing: -.01em; }
h2 { font-size: 1.05rem; margin: 0 0 .75rem; color: var(--text); }
h3 { font-size: .95rem; margin: 1rem 0 .4rem; color: var(--text-muted); font-weight: 600; }
p { margin: .4rem 0; }
button, input, select { font: inherit; color: inherit; }
[hidden] { display: none !important; }

/* ------------------------------------------------------------------ top bar */
.topbar {
  position: sticky; top: 0; z-index: 50;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  box-shadow: 0 1px 0 rgba(16,24,40,.03);
}
.topbar-row {
  display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  padding: .55rem 1.25rem .35rem;
}
.brand { display: flex; align-items: baseline; gap: .75rem; min-width: 0; }
.brand-name { font-weight: 800; font-size: 1.25rem; color: var(--primary); letter-spacing: -.02em; }
.brand-tagline { color: var(--text-muted); font-size: .85rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.status-bar {
  display: flex; align-items: center; gap: .5rem;
  max-width: 48%; min-width: 0;
  padding: .35rem .75rem; border-radius: 999px;
  background: var(--surface-2); border: 1px solid var(--border);
  font-size: .85rem; color: var(--text-muted);
}
.status-bar span:last-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.status-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--text-faint); flex: none; }
.status-bar.ok .status-dot { background: var(--ok); }
.status-bar.error { color: var(--danger); border-color: #f0b8b1; background: var(--danger-soft); }
.status-bar.error .status-dot { background: var(--danger); }
.status-bar.busy .status-dot { background: var(--primary); animation: pulse 1s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .3; } }

/* ------------------------------------------------------------------ layout */
.content { max-width: 1400px; margin: 0 auto; padding: 1.25rem 1.25rem 3rem; }
@keyframes fade { from { opacity: 0; transform: translateY(2px); } to { opacity: 1; transform: none; } }
.panel-head { margin-bottom: 1rem; }
.lead { color: var(--text-muted); margin: 0; max-width: 1100px; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; align-items: start; }
.card {
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  box-shadow: var(--shadow); padding: 1rem 1.15rem; margin-bottom: 1rem;
}
.grid-2 > .card { margin-bottom: 0; }
.grid-2 { margin-bottom: 1rem; }
.footer { text-align: center; color: var(--text-faint); font-size: .8rem; padding: 1rem; }

.notice { padding: .7rem .9rem; border-radius: 8px; border: 1px solid var(--border); background: var(--info-soft); margin-bottom: 1rem; }
.notice.warn { background: var(--warn-soft); border-color: #f1d49a; color: #5c3a00; }
.notice.error { background: var(--danger-soft); border-color: #f0b8b1; color: #7a1e14; white-space: pre-wrap; }
.notice.info { background: var(--info-soft); border-color: #c7d9f6; }

/* ------------------------------------------------------------------ forms */
.form-grid { display: grid; grid-template-columns: minmax(140px, max-content) 1fr; gap: .6rem 1rem; align-items: start; }
.form-grid > label { padding-top: .35rem; color: var(--text-muted); font-weight: 600; font-size: .9rem; }
.form-grid.compact { gap: .45rem .9rem; }
input[type=text], input[type=number], input[type=search], input[type=password], select {
  padding: .4rem .55rem; border: 1px solid var(--border-strong); border-radius: 6px; background: #fff;
  min-height: 2.1rem;
}
input:focus, select:focus, button:focus-visible { outline: 2px solid #8fb4f2; outline-offset: 1px; }
.w-s { width: 7rem; } .w-m { width: 16rem; max-width: 100%; } .w-l { width: 22rem; max-width: 100%; } .w-full { width: 100%; }
.hint { color: var(--text-muted); font-size: .84rem; }
.check { display: flex; align-items: flex-start; gap: .5rem; cursor: pointer; margin: .25rem 0; }
.check input { margin-top: .3rem; flex: none; }
.check > span { flex: 1; min-width: 0; }
.opts { display: flex; flex-direction: column; margin-bottom: .75rem; }
.actions { display: flex; flex-wrap: wrap; align-items: center; gap: .6rem; margin-top: .9rem; }
.input-suffix { display: inline-flex; align-items: center; gap: .3rem; }
.input-suffix span { color: var(--text-muted); }

.btn {
  display: inline-flex; align-items: center; gap: .35rem;
  padding: .5rem 1rem; border-radius: 8px; border: 1px solid var(--border-strong);
  background: var(--surface); color: var(--text); font-weight: 600; cursor: pointer; text-decoration: none;
  transition: background .12s, border-color .12s;
}
.btn:hover { background: var(--surface-2); }
.btn.primary { background: var(--primary); border-color: var(--primary); color: #fff; }
.btn.primary:hover { background: var(--primary-hover); }
.btn.danger { background: var(--danger); border-color: var(--danger); color: #fff; }
.btn.danger:hover { background: #a93226; }
.btn.ghost { background: transparent; border-color: var(--border); color: var(--text-muted); }
.btn.ghost:hover { color: var(--text); background: var(--surface-2); }
.btn.tiny { padding: .15rem .55rem; font-size: .8rem; font-weight: 500; }
.btn:disabled, .btn.disabled { opacity: .5; cursor: not-allowed; pointer-events: none; }

.kv { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; margin: .5rem 0; }
.kv dt { color: var(--text-muted); font-weight: 600; font-size: .88rem; }
.kv dd { margin: 0; word-break: break-all; }

details summary { cursor: pointer; color: var(--text-muted); font-size: .9rem; margin-top: .5rem; }

/* ------------------------------------------------------------------ tables */
.table-wrap { overflow: auto; max-height: 62vh; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); }
table.data { width: 100%; border-collapse: separate; border-spacing: 0; font-size: .86rem; }
table.data th, table.data td { padding: .42rem .55rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
table.data thead th {
  position: sticky; top: 0; z-index: 2;
  background: var(--surface-2); color: var(--text-muted); font-weight: 600; font-size: .8rem;
  border-bottom: 1px solid var(--border-strong); white-space: nowrap;
}
table.data tbody tr:last-child td { border-bottom: 0; }
table.data td.empty { text-align: center; color: var(--text-faint); padding: 1.5rem; }
table.data .num, table.data th.num { text-align: right; font-variant-numeric: tabular-nums; }
table.flows tbody tr { cursor: pointer; }
table.flows tbody tr:hover td { background: var(--primary-soft); }
table.flows tbody tr.dropped td { background: var(--dropped-bg); color: var(--dropped-text); }
table.flows tbody tr.dropped:hover td { background: #eef1f6; }
table.flows tbody tr.final td { background: var(--ok-soft); }
table.flows tbody tr.final td.col-step .step-no { background: var(--ok); }
.col-check, .col-radio { width: 2.6rem; text-align: center !important; }
.col-step { width: 4.5rem; white-space: nowrap; }
.col-method { width: 5rem; }
.col-status { width: 4.5rem; }
.col-type { width: 7rem; }
.col-url { min-width: 22rem; max-width: 42rem; }
.col-ref { max-width: 18rem; }
.col-reason { min-width: 10rem; }
td.col-url, td.col-ref { word-break: break-all; font-family: var(--mono); font-size: .8rem; }
.step-no { display: inline-block; min-width: 1.7em; text-align: center; padding: 0 .35em; border-radius: 999px; background: var(--primary); color: #fff; font-weight: 700; font-size: .78rem; }
.method { font-family: var(--mono); font-weight: 700; font-size: .8rem; }
.method.POST, .method.PUT, .method.PATCH, .method.DELETE { color: #8a3b00; }
.status-pill { display: inline-block; padding: 0 .45em; border-radius: 999px; font-size: .78rem; font-weight: 700; background: var(--surface-2); border: 1px solid var(--border); font-variant-numeric: tabular-nums; }
.status-pill.s2 { background: var(--ok-soft); color: var(--ok); border-color: #b5e2c5; }
.status-pill.s3 { background: var(--info-soft); color: var(--primary); border-color: #c7d9f6; }
.status-pill.s4, .status-pill.s5 { background: var(--danger-soft); color: var(--danger); border-color: #f0b8b1; }
.status-pill.s0 { color: var(--text-faint); }
.reason { font-size: .8rem; }
.reason.user { color: var(--warn); font-weight: 600; }
.url-host { color: var(--text-muted); }
.table-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; margin-bottom: .4rem; }
.table-toolbar h2 { margin: 0; }
.toolbar-right { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }

table.kv-table td:first-child { color: var(--text-muted); font-weight: 600; white-space: nowrap; width: 30%; max-width: 18rem; word-break: break-all; white-space: normal; }
table.kv-table td { font-family: var(--mono); font-size: .8rem; word-break: break-all; }

/* ------------------------------------------------------------------ steps summary */
.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: .5rem; margin-bottom: .5rem; }
.stat { background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: .5rem .6rem; text-align: center; }
.stat-num { display: block; font-size: 1.5rem; font-weight: 800; color: var(--primary); font-variant-numeric: tabular-nums; }
.stat-label { font-size: .78rem; color: var(--text-muted); }
.warnings { margin: .25rem 0 0; padding-left: 1.2rem; color: #5c3a00; font-size: .85rem; }
.warnings li { margin-bottom: .2rem; }
.auth-pill { display: inline-block; padding: .05em .5em; border-radius: 999px; background: var(--warn-soft); color: #5c3a00; border: 1px solid #f1d49a; font-weight: 700; font-size: .8rem; }

/* ------------------------------------------------------------------ code / console */
pre.code, pre.console {
  margin: 0; padding: .75rem .9rem; border-radius: 8px; overflow: auto;
  font-family: var(--mono); font-size: .8rem; line-height: 1.5; tab-size: 4;
  background: #0f172a; color: #e2e8f0; max-height: 70vh; white-space: pre;
}
pre.console { background: #111827; color: #d1d5db; min-height: 8rem; max-height: 40vh; white-space: pre-wrap; word-break: break-all; }
pre.console.stderr { color: #fecaca; }
pre.code.body { max-height: 45vh; white-space: pre-wrap; word-break: break-all; background: var(--surface-2); color: var(--text); border: 1px solid var(--border); }
.run-state { font-weight: 700; color: var(--text-muted); }
.run-state.running { color: var(--primary); }
.run-state.ok { color: var(--ok); }
.run-state.fail { color: var(--danger); }

/* ------------------------------------------------------------------ drawer */
.drawer-backdrop { position: fixed; inset: 0; background: rgba(15, 23, 42, .35); z-index: 90; }
.drawer {
  position: fixed; top: 0; right: 0; bottom: 0; z-index: 100;
  width: min(820px, 94vw); background: var(--surface); box-shadow: -8px 0 30px rgba(0,0,0,.18);
  display: flex; flex-direction: column; padding: 1rem 1.15rem; overflow: hidden;
  animation: slide .18s ease-out;
}
@keyframes slide { from { transform: translateX(30px); opacity: 0; } to { transform: none; opacity: 1; } }
.drawer-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: .5rem; }
.drawer-title { font-size: 1.05rem; font-weight: 700; display: flex; align-items: center; gap: .5rem; }
.drawer-url { font-family: var(--mono); font-size: .82rem; word-break: break-all; color: var(--text-muted); }
.tabs { display: flex; gap: .25rem; border-bottom: 1px solid var(--border); margin-bottom: .5rem; }
.tab { padding: .45rem .9rem; border: 0; background: transparent; cursor: pointer; color: var(--text-muted); font-weight: 600; border-bottom: 2px solid transparent; margin-bottom: -1px; }
.tab.active { color: var(--primary); border-bottom-color: var(--primary); }
.tab-body { display: none; overflow: auto; flex: 1; padding-right: .25rem; }
.tab-body.active { display: block; }
.tab-body h3:first-child { margin-top: .25rem; }

/* ------------------------------------------------------------------ responsive */
@media (max-width: 1000px) {
  .grid-2 { grid-template-columns: 1fr; }
  .brand-tagline { display: none; }
  .status-bar { max-width: 60%; }
  .stats { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 640px) {
  .topbar-row { flex-direction: column; align-items: stretch; gap: .4rem; }
  .status-bar { max-width: none; }
  .content { padding: .75rem .75rem 2rem; }
  .form-grid { grid-template-columns: 1fr; }
  .form-grid > label { padding-top: 0; }
  .col-ref, th.col-ref { display: none; }
  .drawer { width: 100vw; }
}

/* ------------------------------------------------------------------ かんたん画面 (既定) */
.mode-toggle { flex: none; white-space: nowrap; }
#panel-easy, #panel-detail { animation: fade .15s ease-out; }
body.easy-mode #panel-detail, body:not(.easy-mode) #panel-easy { display: none; }
body.easy-mode .content { max-width: 960px; }

.easy-hero { text-align: center; margin: 1.25rem 0 1.5rem; }
.easy-hero h1 { font-size: 1.6rem; }
.easy-hero .lead { margin: .25rem auto .75rem; }
.easy-flow {
  list-style: none; padding: 0; margin: 1.25rem auto 0;
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; max-width: 900px; text-align: left;
}
.easy-flow li {
  display: flex; gap: .75rem; align-items: flex-start;
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  padding: .9rem 1rem; box-shadow: var(--shadow);
}
.easy-flow-num {
  flex: none; display: inline-flex; align-items: center; justify-content: center;
  width: 30px; height: 30px; border-radius: 50%;
  background: var(--primary); color: #fff; font-weight: 800; font-size: 1rem;
}
.easy-card { padding: 1.4rem 1.6rem; }
.easy-actions { display: flex; flex-wrap: wrap; gap: .75rem; align-items: center; justify-content: center; margin: 1.1rem 0 .5rem; }
.btn.xl { font-size: 1.25rem; padding: .9rem 2.4rem; border-radius: 14px; font-weight: 800; letter-spacing: .01em; }
.easy-ready { list-style: none; padding: 0; margin: .75rem 0 0; display: flex; flex-wrap: wrap; gap: .4rem 1.25rem; justify-content: center; color: var(--text-muted); font-size: .9rem; }
.easy-ready li::before { content: "●"; margin-right: .4em; color: var(--text-faint); }
.easy-ready li.ok::before { color: var(--ok); }
.easy-ready li.warn::before { color: var(--warn); }
.easy-ready li.bad::before { color: var(--danger); }

.easy-live-card { text-align: center; border-color: #f0b8b1; }
.easy-live { display: inline-flex; align-items: center; gap: .5rem; color: var(--danger); font-weight: 800; font-size: 1.3rem; }
.easy-live .rec-light { width: 14px; height: 14px; border-radius: 50%; background: var(--danger); animation: pulse 1.2s infinite; display: inline-block; }
.easy-count { margin: .5rem 0 .75rem; }
.easy-count-num { font-size: 3rem; font-weight: 800; color: var(--primary); font-variant-numeric: tabular-nums; margin-right: .35rem; }
.easy-count-label { color: var(--text-muted); }
.easy-guide { font-size: 1.05rem; margin: .5rem 0 1rem; }
.easy-live-card .notice { text-align: left; }

.easy-center { text-align: center; padding: 2.5rem 1.5rem; }
.spinner {
  width: 42px; height: 42px; margin: 0 auto 1rem; border-radius: 50%;
  border: 4px solid var(--border); border-top-color: var(--primary);
  animation: spin .9s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.easy-processing-text { font-size: 1.1rem; color: var(--text-muted); margin: 0; }

.easy-done-title { color: var(--ok); font-size: 1.5rem; margin-bottom: .75rem; }
.easy-kv dd { word-break: break-all; }
.easy-details { margin: .75rem 0; }
.easy-details summary { cursor: pointer; color: var(--primary); font-weight: 600; }
.easy-steplist { margin: .5rem 0 0; padding-left: 1.5rem; }
.easy-steplist li { margin: .2rem 0; word-break: break-all; }
.easy-steplist .method { margin-right: .4em; }
.easy-steplist .loop-tag { font-size: .78rem; color: var(--warn); margin-left: .4em; }
#easy-run h2 { margin-bottom: .5rem; }

@media (max-width: 760px) {
  .easy-flow { grid-template-columns: 1fr; }
  .mode-toggle { display: none; }
}
.easy-loaded { display: flex; flex-wrap: wrap; gap: .5rem .75rem; align-items: center; justify-content: center; margin-top: 1rem; padding-top: .75rem; border-top: 1px dashed var(--border); }

.easy-ready li.bad { color: #7a1e14; }
#easy-emulation + .hint { margin-top: .25rem; }
.easy-har-hint { text-align: center; margin-top: 0; }
.easy-har-help { margin-top: .75rem; text-align: left; }
.easy-har-help summary { cursor: pointer; text-align: center; }
.easy-har-help ol { margin: .4rem 0 .4rem 1.4rem; padding: 0; }
.easy-har-help p { margin: .4rem 0; }

/* ------------------------------------------------------------------ 詳細設定 (スクリプトの詳細と変更) */
.detail-settings h3:first-child { margin-top: 0; }
textarea.code-editor {
  display: block; width: 100%; height: 60vh; min-height: 18rem; resize: vertical; margin: .5rem 0 0;
  padding: .75rem .9rem; border-radius: 8px; border: 1px solid #0f172a; overflow: auto;
  font-family: var(--mono); font-size: .8rem; line-height: 1.5; tab-size: 4; white-space: pre;
  background: #0f172a; color: #e2e8f0;
}
textarea.code-editor:focus { outline: 2px solid #8fb4f2; outline-offset: 1px; }
textarea.code-editor[readonly] { opacity: .7; }
.dirty-badge { color: var(--warn); font-weight: 700; font-size: .85rem; }
#sum-notes-wrap { margin-bottom: 1rem; }
.notes { margin: .25rem 0 0; padding-left: 1.2rem; font-size: .85rem; color: var(--text-muted); }
{% endraw %}
</style>
</head>
<body class="easy-mode" data-token="{{ token }}" data-can-record="{{ 'true' if can_record else 'false' }}" data-can-ie="{{ 'true' if can_record_ie else 'false' }}" data-can-edge="{{ 'true' if can_record_edge else 'false' }}">

<header class="topbar">
  <div class="topbar-row">
    <div class="brand">
      <span class="brand-name">reqrec</span>
      <span class="brand-tagline">ブラウザ操作の HTTP 通信を記録して、Python のスクレイピングスクリプトを自動生成します</span>
    </div>
    <div class="status-bar" id="status-bar" role="status" aria-live="polite">
      <span class="status-dot"></span>
      <span id="status-text">準備完了。</span>
    </div>
    <button type="button" id="mode-toggle" class="btn tiny ghost mode-toggle" title="かんたん画面で作ったスクリプトの中身を確認して、細かく変更します">詳細設定を表示</button>
    {% if logged_in %}<a href="/logout" id="logout-link" class="btn tiny ghost" title="ログアウトします">ログアウト</a>{% endif %}
  </div>
</header>

<main class="content">

<!-- ===================================================== かんたん画面 (既定) -->
<section id="panel-easy" class="easy" aria-labelledby="h-easy">

  <!-- 待機中: 記録できる PC では記録 (HAR も可)、それ以外 (サーバーを別の PC から開いたときなど) は HAR ファイルから -->
  <div class="easy-stage" id="easy-idle">
    {% if can_record %}
    <div class="easy-hero">
      <h1 id="h-easy">サイトの操作を記録して、自動取得スクリプトを作ります</h1>
      <p class="lead">やることは 3 つだけです。ポートやプロキシなどの設定はすべて自動で行います。Windows の設定や証明書は変更しません。</p>
      <ol class="easy-flow">
        <li><span class="easy-flow-num">1</span><div><strong>記録をはじめる</strong> を押す<br><span class="hint">記録用のブラウザが開きます (IE モード、または記録専用の Edge)</span></div></li>
        <li><span class="easy-flow-num">2</span><div><strong>いつもどおりサイトを操作する</strong><br><span class="hint">ログイン → 一覧を開く → 欲しいデータの画面まで</span></div></li>
        <li><span class="easy-flow-num">3</span><div><strong>記録をおわる</strong> を押す<br><span class="hint">ブラウザを閉じるだけでスクリプトが自動でできあがります</span></div></li>
      </ol>
    </div>
    {% else %}
    <div class="easy-hero">
      <h1 id="h-easy">HAR ファイルから、自動取得スクリプトを作ります</h1>
      <p class="lead">サイトを操作したときの通信をブラウザの F12 開発者ツールで HAR ファイルに保存して、ここで選ぶだけです。https:// のサイトにも使えます。</p>
      <ol class="easy-flow">
        <li><span class="easy-flow-num">1</span><div><strong>F12 開発者ツールを開く</strong><br><span class="hint">ふだんの Edge は F12 を押して「Network」を開き、「Preserve log」にチェックを入れます。IE モードのサイトは IEChooser.exe でそのタブを選んで「ネットワーク」の記録を始めます</span></div></li>
        <li><span class="easy-flow-num">2</span><div><strong>いつもどおりサイトを操作する</strong><br><span class="hint">ログイン → 欲しいデータの画面まで。終わったら HAR ファイルに保存します (ふだんの Edge は機密データを含む形で。下の「HAR ファイルの保存のしかた」)</span></div></li>
        <li><span class="easy-flow-num">3</span><div><strong>HAR ファイルを選ぶ</strong> を押す<br><span class="hint">保存したファイルを選ぶと、スクリプトが自動でできあがります</span></div></li>
      </ol>
    </div>
    {% endif %}
    <div class="card easy-card">
      <div id="easy-record-ui"{% if not can_record %} hidden{% endif %}>
      <div class="form-grid compact">
        <label for="easy-url">開くサイトのアドレス <span class="hint">(任意)</span></label>
        <div><input id="easy-url" type="text" class="w-full" placeholder="例: http://kanri/  または  http://192.168.1.10/seisan/" autocomplete="url">
          <div class="hint">空欄のままでも構いません。開いたブラウザのアドレス欄にサイトのアドレスを入れて開けます。</div></div>
        <label for="easy-browser">記録に使うブラウザ</label>
        <div><select id="easy-browser" class="w-m">
            <option value="ie"{% if not can_record_ie %} disabled{% endif %}>IE モード (記録用ブラウザ)</option>
            <option value="edge"{% if not can_record_edge %} disabled{% endif %}>Edge</option>
          </select>
          <div class="hint">Edge の IE モードで開くサイトは「IE モード」、ふだんの Edge で開くサイトは「Edge」を選びます。「Edge」では記録専用の Edge の窓が開きます (ふだんの Edge の設定やログイン状態には触れません)。どちらも http:// のサイトだけを記録します (https:// のサイトは、下の「HAR ファイルから作る」を使います)。選んだブラウザは次回も使われます。</div></div>
        <label for="easy-emulation" data-ie-only>表示モード</label>
        <div data-ie-only><select id="easy-emulation" class="w-m">
            <option value="default">既定 (IE7 互換表示)</option>
            <option value="ie8">IE8 相当</option>
            <option value="ie11">IE11 相当 (ページの指定に従う)</option>
            <option value="ie11_force">IE11 強制</option>
          </select>
          <div class="hint">ふだんは「既定」のままで構いません。記録用ブラウザで画面が崩れるときだけ変えてください。表示モードは記録用ブラウザの中だけで切り替わります (Windows の設定やレジストリは変更しません)。選んだモードは次回も使われます。</div></div>
      </div>
      <div class="easy-actions">
        <button type="button" id="easy-start" class="btn primary xl"{% if not can_record %} disabled{% endif %}>● 記録をはじめる</button>
      </div>
      <ul class="easy-ready" id="easy-ready" aria-live="polite"></ul>
      </div>
      {% if not can_record %}
      <div class="easy-actions">
        <button type="button" id="easy-har-pick" class="btn primary xl">HAR ファイルを選ぶ…</button>
      </div>
      <p class="hint easy-har-hint">.har ファイルを選びます。別のタブで開いた画面の HAR は、まとめて選べます。<br>
        IEChooser.exe は <code>C:\Windows\System32\F12</code> にあります。</p>
      {% endif %}
      <div class="easy-loaded" id="easy-loaded" hidden>
        <span class="hint">すでに読み込まれている記録があります:</span>
        <button type="button" id="easy-build-loaded" class="btn">読み込み済みの記録 (<span id="easy-loaded-count">0</span> 件) からスクリプトを作る</button>
      </div>
      {% if can_record %}
      <div class="easy-loaded" id="easy-har">
        <span class="hint">F12 開発者ツールで保存した HAR ファイルからも作れます (https:// のサイトはこちら):</span>
        <button type="button" id="easy-har-pick" class="btn">HAR ファイルから作る…</button>
      </div>
      {% endif %}
      <details class="hint easy-har-help" id="easy-har-help">
        <summary>HAR ファイルの保存のしかた (https:// のサイトも、この方法で作れます)</summary>
        <p><strong>ふだんの Edge</strong> (F12 の表示は英語のことがあります。名前は Edge の版で少し違うことがあります)</p>
        <ol>
          <li>InPrivate ウィンドウ (Ctrl+Shift+N) でサイトを開きます (ログインしていない状態から始めるため)。</li>
          <li>F12 を押し、「Network」(ネットワーク) で「Preserve log」(ログを保持) にチェックを入れます。入れないと、画面が変わるたびに記録が消えます。</li>
          <li>最初の 1 回だけ: F12 の設定 (歯車) の「Preferences」→「Network」で「Allow to generate HAR with sensitive data」をオンにします。オフのままだと Cookie が消えた HAR になり、スクリプトが動きません。</li>
          <li>ログイン画面から、いつもどおり操作します。</li>
          <li>「Network」の書き出しボタン (下向きの矢印) で「Export HAR (with sensitive data)」を選んで保存します。</li>
        </ol>
        <p>別ウィンドウ (ポップアップ) で開く画面があるときは、手順 3 の設定の「Preferences」→「Global」で「Auto-open DevTools for popups」もオンにします。ポップアップが開いたら、その窓で F5 を押して読み直してから操作を続け、両方の窓の HAR を保存して、まとめて選びます。</p>
        <p><strong>Edge の IE モード</strong>: <code>C:\Windows\System32\F12\IEChooser.exe</code> でそのタブを選び、「ネットワーク」で ▶ を押して記録を始めて操作し、「HAR としてエクスポート」で保存します。</p>
      </details>
      <input id="easy-har-input" type="file" multiple accept=".har,.json" hidden>
    </div>
  </div>

  <!-- 記録中 -->
  <div class="easy-stage" id="easy-recording" hidden>
    <div class="card easy-card easy-live-card">
      <div class="easy-live"><span class="rec-light"></span><span>記録中</span></div>
      <div class="easy-count"><span class="easy-count-num" id="easy-count">0</span><span class="easy-count-label">件の通信を記録しました</span></div>
      <p class="easy-guide" data-for-browser="ie">記録用のブラウザが開きました。そのウィンドウでいつもどおりサイトを操作してください。<br>終わったら、ブラウザの赤い <strong>[記録をおわる]</strong> か、この画面の <strong>[記録をおわる]</strong> を押します。</p>
      <p class="easy-guide" data-for-browser="edge" hidden>記録用の Edge の窓が開きました。その窓でいつもどおりサイトを操作してください。<br>終わったら、その Edge の窓を閉じるか、この画面の <strong>[記録をおわる]</strong> を押します。</p>
      <div class="notice error" id="easy-rec-error" hidden></div>
      <div class="easy-actions">
        <button type="button" id="easy-stop" class="btn danger xl">■ 記録をおわる</button>
        <button type="button" id="easy-cancel" class="btn ghost">やめる (記録を破棄)</button>
      </div>
      <p class="hint" data-for-browser="ie">件数が増えないときは、記録用のブラウザ (タイトルに「記録中」と付いた窓) でサイトを開いているか確認してください。https:// のページは記録されません (https:// のサイトは HAR ファイルから作れます)。</p>
      <p class="hint" data-for-browser="edge" hidden>件数が増えないときは、記録用に開いた Edge の窓 (ふだんの Edge とは別の窓) でサイトを開いているか確認してください。https:// のページは記録されません (https:// のサイトは HAR ファイルから作れます)。Edge で開いても IE モードに切り替わるサイトは記録されないので、「IE モード」で記録してください。</p>
    </div>
  </div>

  <!-- 処理中 -->
  <div class="easy-stage" id="easy-processing" hidden>
    <div class="card easy-card easy-center">
      <div class="spinner" aria-hidden="true"></div>
      <p class="easy-processing-text" id="easy-processing-text">処理しています…</p>
    </div>
  </div>

  <!-- 完了 -->
  <div class="easy-stage" id="easy-done" hidden>
    <div class="card easy-card">
      <h1 class="easy-done-title">✔ スクリプトができました</h1>
      <dl class="kv easy-kv">
        <dt>ファイル名</dt><dd><code id="easy-done-name"></code></dd>
        <dt>保存先</dt><dd><code id="easy-done-path"></code></dd>
        <dt>手順の数</dt><dd id="easy-done-steps"></dd>
        <dt id="easy-done-files-label" hidden>保存されるファイル</dt><dd id="easy-done-files" hidden></dd>
        <dt>最後に取得する画面</dt><dd id="easy-done-final" class="url-cell"></dd>
      </dl>
      <details class="easy-details">
        <summary>スクリプトがする手順を見る</summary>
        <ol class="easy-steplist" id="easy-steplist"></ol>
      </details>
      <div class="notice warn" id="easy-done-warnings" hidden>
        <strong>確認してください</strong>
        <ul class="warnings" id="easy-done-warning-list"></ul>
      </div>
      <div class="notice info" id="easy-done-secrets" hidden></div>
      <div class="easy-actions">
        <a id="easy-download" class="btn primary" href="#" download>⬇ スクリプトをダウンロード</a>
        <button type="button" id="easy-open-folder" class="btn">保存先フォルダを開く</button>
        <button type="button" id="easy-test-run" class="btn">▶ 試しに実行する</button>
        <button type="button" id="easy-open-detail" class="btn">詳細を見る・変更する</button>
        <button type="button" id="easy-again" class="btn ghost">もう一度記録する</button>
      </div>
    </div>

    <div class="card easy-card" id="easy-run" hidden>
      <h2>試しに実行する</h2>
      <div id="easy-env" class="form-grid compact"></div>
      <div class="easy-actions">
        <button type="button" id="easy-run-btn" class="btn primary">▶ 実行</button>
        <button type="button" id="easy-run-stop" class="btn danger" disabled>■ 停止</button>
        <span id="easy-run-state" class="run-state">待機中</span>
        <button type="button" id="easy-save-output" class="btn" disabled>結果をファイルに保存</button>
      </div>
      <p class="hint" id="easy-save-output-result"></p>
      <div class="notice error" id="easy-run-hint" hidden></div>
      <h3>結果 (スクリプトの出力)</h3>
      <pre class="console" id="easy-run-out"></pre>
      <details id="easy-run-err-wrap" hidden>
        <summary>エラーメッセージを表示</summary>
        <pre class="console stderr" id="easy-run-err"></pre>
      </details>
    </div>
  </div>

  <div class="notice error" id="easy-error" hidden></div>
</section>

<!-- ===================================================== 詳細設定 (かんたん画面で作ったスクリプトの詳細と変更) -->
<section id="panel-detail" aria-labelledby="h-detail">
  <div class="panel-head">
    <h1 id="h-detail">スクリプトの詳細と変更</h1>
    <p class="lead">かんたん画面で作ったスクリプトの中身を確認して、細かく変更できます。手順を使う・使わないや待ち時間などを変えて [設定から作り直す] を押すか、下のコードを直接書き換えて [保存] します。どちらも [試しに実行する] ですぐに確かめられます。新しく記録すると、ここの設定は最初の状態に戻ります。</p>
  </div>

  <div id="detail-empty" class="notice info">まだ記録がありません。右上の [かんたん画面に戻る] を押して HAR ファイルを読み込む（または記録する）と、ここでスクリプトの中身を確認・変更できます。</div>

  <div id="detail-body" hidden>
  <div class="card">
    <dl class="kv">
      <dt>スクリプト</dt><dd><code id="detail-script">(まだありません)</code></dd>
      <dt>もとの記録</dt><dd id="detail-source">—</dd>
    </dl>
  </div>

  <div class="card">
    <div class="table-toolbar">
      <h2>1. 手順の一覧 <span class="hint" id="table-count"></span></h2>
      <div class="toolbar-right">
        <input id="table-filter" type="search" placeholder="URL / ホスト / メソッドで絞り込み" class="w-l">
        <label class="check"><input id="show-dropped" type="checkbox"><span>使わない通信も表示</span></label>
      </div>
    </div>
    <p class="hint">☑ = スクリプトに入れる　/　◉ 結果 = スクリプトの最後に表示する画面 (データ)　/　灰色の行 = 使わない通信 (理由は「判定」の列)　/　行をクリック = 送ったデータと受け取ったデータを表示</p>
    <div class="stats">
      <div class="stat"><span class="stat-num" id="sum-steps">0</span><span class="stat-label">手順</span></div>
      <div class="stat"><span class="stat-num" id="sum-kept">0</span><span class="stat-label">使う通信</span></div>
      <div class="stat"><span class="stat-num" id="sum-dropped">0</span><span class="stat-label">使わない通信</span></div>
      <div class="stat"><span class="stat-num" id="sum-vars">0</span><span class="stat-label">自動で取り出す値</span></div>
    </div>
    <dl class="kv">
      <dt>結果にする手順</dt><dd id="sum-final">最後の手順 (既定)　<button type="button" id="btn-final-clear" class="btn tiny ghost" hidden>指定を解除</button></dd>
      <dt>HTTP 認証</dt><dd id="sum-auth">見つかりませんでした</dd>
      <dt>定数 / 秘密情報</dt><dd id="sum-constants">なし</dd>
      <dt>繰り返し</dt><dd id="sum-loops">なし</dd>
      <dt>自動で外したもの</dt><dd id="sum-self">—</dd>
    </dl>
    <div id="sum-warnings-wrap" class="notice warn" hidden>
      <strong>確認してください</strong>
      <ul class="warnings" id="sum-warnings"></ul>
    </div>
    <details id="sum-notes-wrap" hidden>
      <summary>お知らせ (スクリプトが自動で行うこと)</summary>
      <ul class="notes" id="sum-notes"></ul>
    </details>
    <div class="table-wrap">
      <table class="data flows">
        <thead>
          <tr>
            <th class="col-check" title="チェック = スクリプトに入れる">使う</th>
            <th class="col-radio" title="スクリプトの最後に結果を表示する通信">結果</th>
            <th class="col-step">手順</th>
            <th class="col-method">メソッド</th>
            <th class="col-status">ステータス</th>
            <th class="col-type">種類</th>
            <th class="col-url">URL</th>
            <th class="col-ref">参照元 (Referer)</th>
            <th class="col-reason">判定</th>
          </tr>
        </thead>
        <tbody id="flow-tbody"><tr><td colspan="9" class="empty">解析中…</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2>2. 設定</h2>
    <div class="grid-2 detail-settings">
      <div>
        <h3>手順の選び方 <span class="hint">(変えると上の一覧にすぐ反映されます)</span></h3>
        <div class="opts">
          <label class="check"><input type="checkbox" class="opt" data-opt="keep_static"><span>画像・CSS・JavaScript・フォントの通信も入れる</span></label>
          <label class="check"><input type="checkbox" class="opt" data-opt="keep_trackers"><span>アクセス解析などの通信も入れる</span></label>
          <label class="check"><input type="checkbox" class="opt" data-opt="keep_all"><span>自動で外すのをやめて、すべての通信を入れる</span></label>
          <label class="check"><input type="checkbox" class="opt" data-opt="collapse_redirects" checked><span>転送 (リダイレクト) は 1 つの手順にまとめる</span></label>
          <label class="check"><input type="checkbox" class="opt" data-opt="detect_loops" checked><span>同じ形の繰り返し (ページ送りなど) を見つけてまとめる</span></label>
          <label class="check"><input type="checkbox" class="opt" data-opt="redact_secrets"><span>パスワードなどをスクリプトに書き込まず、実行するときに入力する (環境変数から読む)</span></label>
          <label class="check"><input type="checkbox" class="opt" data-opt="detect_auth" checked><span>HTTP 認証 (Windows 統合認証 NTLM / Basic / Digest) のやり取りを見つけてまとめる</span></label>
        </div>
        <div class="form-grid compact">
          <label for="opt-include-hosts">このホストだけ使う</label>
          <div><input id="opt-include-hosts" type="text" class="opt-text w-full" data-opt="include_hosts" placeholder="例: kanri (空欄 = 制限なし)"></div>
          <label for="opt-exclude-hosts">このホストは使わない</label>
          <div><input id="opt-exclude-hosts" type="text" class="opt-text w-full" data-opt="exclude_hosts" placeholder="例: cdn.example.com, fonts.googleapis.com"></div>
          <label for="opt-min-len">値を探す最小の文字数</label>
          <div><input id="opt-min-len" type="number" min="1" value="4" class="opt-num w-s" data-opt="min_value_length"> <span class="hint">前の画面から受け取った値かどうかを調べる長さ</span></div>
          <label for="opt-max-steps">手順の数の上限</label>
          <div><input id="opt-max-steps" type="number" min="1" class="opt-num w-s" data-opt="max_steps" placeholder="なし"></div>
        </div>
      </div>
      <div>
        <h3>スクリプトの書き方</h3>
        <div class="form-grid compact">
          <label for="gopt-parser">HTML の読み取り方</label>
          <div><select id="gopt-parser" class="gopt" data-gopt="html_parser"><option value="html.parser" selected>html.parser (標準・追加インストール不要)</option><option value="lxml">lxml (高速・pip install lxml が必要)</option></select></div>
          <label for="gopt-delay">手順の間の待ち時間 (秒)</label>
          <div><input id="gopt-delay" type="number" min="0" step="0.1" value="0" class="gopt w-s" data-gopt="delay"> <span class="hint">サーバーに負荷をかけないための間隔</span></div>
          <label for="gopt-timeout">タイムアウト (秒)</label>
          <div><input id="gopt-timeout" type="number" min="1" step="1" value="30" class="gopt w-s" data-gopt="timeout"></div>
        </div>
        <div class="opts">
          <label class="check"><input type="checkbox" class="gopt" data-gopt="print_final" checked><span>最後の手順の結果を表示する (print)</span></label>
          <label class="check"><input type="checkbox" class="gopt" data-gopt="comments" checked><span>日本語の説明コメントを入れる</span></label>
          <label class="check"><input type="checkbox" class="gopt" data-gopt="strict_status"><span>記録したときと違うステータスコードが返ったらエラーにする (厳格モード)</span></label>
        </div>
      </div>
    </div>
    <div class="notice info" id="regen-note" hidden>設定を変えました。[設定から作り直す] を押すと、コードに反映されます。</div>
    <div class="actions">
      <button type="button" id="btn-regenerate" class="btn primary" disabled>⚙ 設定から作り直す</button>
      <span class="hint" id="regen-hint"></span>
    </div>
  </div>

  <div class="card">
    <div class="table-toolbar">
      <h2>3. コード <span class="hint" id="code-lines"></span></h2>
      <span class="dirty-badge" id="code-dirty" hidden>● 保存していない変更があります</span>
    </div>
    <p class="hint">ここで直接書き換えられます (Tab キーで空白 4 つ、Ctrl+S で保存)。</p>
    <textarea id="code-editor" class="code-editor" spellcheck="false" wrap="off" autocomplete="off" autocapitalize="off" aria-label="スクリプトのコード" readonly placeholder="(スクリプトを作ると、ここにコードが表示されます)"></textarea>
    <div class="actions">
      <label for="script-name" class="hint">ファイル名</label>
      <div class="input-suffix"><input id="script-name" type="text" class="w-m" placeholder="scrape_example" disabled><span>.py</span></div>
      <button type="button" id="btn-save" class="btn primary" disabled>保存</button>
      <button type="button" id="btn-revert" class="btn ghost" disabled>保存した内容に戻す</button>
      <button type="button" id="btn-download" class="btn" disabled>⬇ ダウンロード</button>
    </div>
    <p class="hint" id="save-result">保存先: <code>{{ workdir }}/scripts/</code></p>
  </div>

  <div class="card" id="detail-run">
    <h2>4. 試しに実行する</h2>
    <div id="detail-env" class="form-grid compact"></div>
    <label class="check"><input type="checkbox" id="detail-run-debug"><span>詳しい情報も表示する（送る値をどこから取ったか、使った Cookie の domain / path。値そのものは表示しません）</span></label>
    <div class="actions">
      <button type="button" id="detail-run-btn" class="btn primary" disabled>▶ 試しに実行する</button>
      <button type="button" id="detail-run-stop" class="btn danger" disabled>■ 停止</button>
      <span id="detail-run-state" class="run-state">待機中</span>
      <button type="button" id="detail-save-output" class="btn" disabled>結果をファイルに保存</button>
    </div>
    <p class="hint">保存していない変更があるときは、保存してから実行します。</p>
    <p class="hint" id="detail-save-output-result"></p>
    <div class="notice error" id="detail-run-hint" hidden></div>
    <h3>結果 (スクリプトの出力)</h3>
    <pre class="console" id="detail-run-out"></pre>
    <details id="detail-run-err-wrap" hidden>
      <summary>エラーメッセージを表示</summary>
      <pre class="console stderr" id="detail-run-err"></pre>
    </details>
  </div>
  </div>
</section>

</main>

<!-- ===================================================== 詳細ドロワー -->
<div id="drawer-backdrop" class="drawer-backdrop" hidden></div>
<aside id="drawer" class="drawer" hidden aria-label="リクエストの詳細">
  <div class="drawer-head">
    <div>
      <div class="drawer-title"><span class="method" id="dr-method"></span> <span id="dr-status" class="status-pill"></span> <span id="dr-flow-id" class="hint"></span></div>
      <div class="drawer-url" id="dr-url"></div>
      <div class="hint" id="dr-meta"></div>
    </div>
    <button type="button" id="drawer-close" class="btn ghost" aria-label="閉じる">✕ 閉じる</button>
  </div>
  <div class="tabs" role="tablist">
    <button type="button" class="tab active" data-tab="req" role="tab">リクエスト</button>
    <button type="button" class="tab" data-tab="resp" role="tab">レスポンス</button>
  </div>
  <div class="tab-body active" id="tab-req">
    <h3>クエリパラメータ</h3>
    <table class="data kv-table" id="dr-req-query"><tbody></tbody></table>
    <h3>ヘッダー</h3>
    <table class="data kv-table" id="dr-req-headers"><tbody></tbody></table>
    <h3>本文 <span class="hint" id="dr-req-body-info"></span></h3>
    <table class="data kv-table" id="dr-req-form" hidden><tbody></tbody></table>
    <pre class="code body" id="dr-req-body"></pre>
  </div>
  <div class="tab-body" id="tab-resp">
    <h3>ヘッダー</h3>
    <table class="data kv-table" id="dr-resp-headers"><tbody></tbody></table>
    <h3>本文 <span class="hint" id="dr-resp-body-info"></span></h3>
    <pre class="code body" id="dr-resp-body"></pre>
  </div>
</aside>

<footer class="footer">reqrec {{ version }} — 作業フォルダ: <code>{{ workdir }}</code></footer>

<script>
{% raw %}
// ===== former reqrec/webapp/static/app.js =====
/* reqrec GUI — vanilla JS, no build step, no external resources.
 *
 * Structure:  api()  ->  modules (Steps / Drawer / Run / Detail = 詳細設定 / Easy = かんたん画面)  ->  render functions.
 * Every piece of recorded content is inserted with textContent (never innerHTML): recordings are
 * attacker-controlled data.
 */
(() => {
  'use strict';

  // ------------------------------------------------------------------ basics
  const body = document.body;
  const TOKEN = body.dataset.token;
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  class ApiError extends Error {
    constructor(message, status, data) { super(message); this.status = status; this.data = data || {}; }
  }

  async function api(path, { method = 'GET', json, form } = {}) {
    const headers = {};
    if (method !== 'GET') headers['X-Reqrec-Token'] = TOKEN;
    let reqBody;
    if (json !== undefined) { headers['Content-Type'] = 'application/json'; reqBody = JSON.stringify(json); }
    else if (form) reqBody = form;
    let resp;
    try {
      resp = await fetch(path, { method, headers, body: reqBody, credentials: 'same-origin', cache: 'no-store' });
    } catch (e) {
      throw new ApiError('GUI のサーバーに接続できません。reqrec gui が終了していないか確認してください。', 0, {});
    }
    const text = await resp.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { error: text.slice(0, 300) || resp.statusText }; }
    if (resp.status === 401 && data.login) window.location.href = '/login';  // the login session ended
    if (!resp.ok) throw new ApiError(data.error || `エラー (HTTP ${resp.status})`, resp.status, data);
    return data;
  }

  const statusBar = $('#status-bar');
  const statusText = $('#status-text');
  function setStatus(message, kind = 'info') {
    statusText.textContent = message;
    statusBar.className = 'status-bar ' + kind;
    statusBar.title = message;
  }
  function fail(err, prefix) {
    const msg = (prefix ? prefix + ': ' : '') + (err && err.message ? err.message : String(err));
    setStatus(msg, 'error');
    console.error(err);
  }

  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k === 'dataset') Object.assign(node.dataset, v);
      else node.setAttribute(k, v);
    }
    for (const c of [].concat(children)) {
      if (c === null || c === undefined) continue;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
  function fmtBytes(n) {
    if (n === null || n === undefined) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }
  function debounce(fn, ms) {
    let timer = null;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
  }
  function splitHosts(text) {
    return (text || '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
  }

  // ------------------------------------------------------------------ shared state
  const S = {
    recording: null,      // summary of the loaded recording (from the server)
    plan: null,           // last /api/plan payload
    flows: [],
    exclude: new Set(),
    include: new Set(),
    finalFlowId: null,
    secrets: [],          // values the current script reads from environment variables
    script: null,         // the current script (a file in scripts/): made on the easy screen, changed in 詳細設定
    savedCode: null,      // its content as saved
    generatedCode: null,  // the code as last generated; the editor differs = changed by hand (null = unknown)
    runPoll: null,
    recPoll: null,
  };
  const scriptUrl = (name) => '/api/scripts/' + encodeURIComponent(name) + '/download';
  // The plain-Japanese text of each plan warning comes from the server (routes.warning_message,
  // tested against the warnings build_plan really produces); the raw text is the fallback.
  function warningTexts(details, raw) {
    if (Array.isArray(details)) return details.map((d) => d.message || d.text);
    return raw || [];
  }

  // ------------------------------------------------------------------ screens
  // かんたん画面 (既定) と 詳細設定 (かんたん画面で作ったスクリプトの中身を確認して、細かく変更する画面)
  const toggleBtn = $('#mode-toggle');
  function setMode(mode, persist = true) {
    const easy = mode !== 'advanced';
    body.classList.toggle('easy-mode', easy);
    toggleBtn.textContent = easy ? '詳細設定を表示' : 'かんたん画面に戻る';
    if (persist) { try { localStorage.setItem('reqrec.mode', easy ? 'easy' : 'advanced'); } catch (e) { /* ignore */ } }
    window.scrollTo({ top: 0 });
  }
  toggleBtn.addEventListener('click', () => setMode(body.classList.contains('easy-mode') ? 'advanced' : 'easy'));

  // ================================================================== 詳細設定: 手順の一覧と設定
  const Steps = (() => {
    const tbody = $('#flow-tbody');
    const REASONS = [
      ['excluded by user', '手動で除外'],
      ['static asset', '静的ファイル'],
      ['tracker/analytics host', 'トラッカー / 解析サービス'],
      ['no response recorded', 'レスポンスなし (未完了)'],
      ['CORS preflight', 'CORS プリフライト'],
      ['304 not modified', '304 (ブラウザキャッシュ)'],
      ['websocket', 'WebSocket'],
      ['server-sent events', 'SSE ストリーム'],
      ['host excluded', '除外ホスト'],
      ['host not in', '対象ホスト外'],
      ['auth', '認証ハンドシェイク (統合済み)'],
      ['not used', '使用されず (他の手順に統合 / 上限超過)'],
    ];
    function reasonLabel(reason) {
      if (!reason) return '';
      const hit = REASONS.find(([k]) => reason.toLowerCase().startsWith(k) || reason.toLowerCase().includes(k));
      if (!hit) return reason;
      const m = /\((.*)\)$/.exec(reason);
      return hit[1] + (m && hit[0] === 'static asset' ? ` (${m[1]})` : '');
    }
    function shortMime(mime, rtype) {
      if (!mime) return rtype || '—';
      const map = { 'text/html': 'HTML', 'application/json': 'JSON', 'text/css': 'CSS', 'application/javascript': 'JS', 'text/javascript': 'JS', 'application/x-javascript': 'JS', 'text/plain': 'テキスト', 'text/csv': 'CSV', 'application/pdf': 'PDF', 'application/xml': 'XML', 'text/xml': 'XML', 'application/xhtml+xml': 'XHTML' };
      if (map[mime]) return map[mime];
      if (mime.startsWith('image/')) return '画像';
      if (mime.startsWith('font/')) return 'フォント';
      if (mime.endsWith('+json')) return 'JSON';
      if (mime.endsWith('+xml')) return 'XML';
      return mime.split('/').pop().slice(0, 14);
    }

    function collectPlanOptions() {
      const o = {};
      $$('input.opt[type=checkbox]').forEach((cb) => { o[cb.dataset.opt] = cb.checked; });
      o.include_hosts = splitHosts($('#opt-include-hosts').value);
      if (!o.include_hosts.length) o.include_hosts = null;
      o.exclude_hosts = splitHosts($('#opt-exclude-hosts').value);
      const minLen = parseInt($('#opt-min-len').value, 10);
      if (minLen >= 1) o.min_value_length = minLen;
      const maxSteps = parseInt($('#opt-max-steps').value, 10);
      o.max_steps = maxSteps >= 1 ? maxSteps : null;
      o.exclude_flow_ids = Array.from(S.exclude);
      o.include_flow_ids = Array.from(S.include);
      o.final_flow_id = S.finalFlowId;
      return o;
    }
    function collectGenOptions() {
      const g = {};
      $$('.gopt').forEach((n) => {
        const key = n.dataset.gopt;
        if (n.type === 'checkbox') g[key] = n.checked;
        else if (n.type === 'number') { const v = parseFloat(n.value); if (!Number.isNaN(v)) g[key] = v; }
        else g[key] = n.value;
      });
      return g;
    }
    // the form shows the options the server used (a new recording starts again from the defaults)
    function fillOptions(planOpts, genOpts) {
      const p = planOpts || {};
      $$('input.opt[type=checkbox]').forEach((cb) => { if (typeof p[cb.dataset.opt] === 'boolean') cb.checked = p[cb.dataset.opt]; });
      $('#opt-include-hosts').value = (p.include_hosts || []).join(', ');
      $('#opt-exclude-hosts').value = (p.exclude_hosts || []).join(', ');
      if (p.min_value_length) $('#opt-min-len').value = p.min_value_length;
      $('#opt-max-steps').value = p.max_steps || '';
      S.exclude = new Set(p.exclude_flow_ids || []);
      S.include = new Set(p.include_flow_ids || []);
      S.finalFlowId = p.final_flow_id || null;
      const g = genOpts || {};
      $$('.gopt').forEach((n) => {
        const v = g[n.dataset.gopt];
        if (v === undefined || v === null) return;
        if (n.type === 'checkbox') n.checked = !!v; else n.value = String(v);
      });
      setChanged(false);
    }
    // The code is rebuilt only by [設定から作り直す]: rebuilding on every change would throw away hand edits.
    function setChanged(on) { $('#regen-note').hidden = !(on && S.script); }

    let inflight = 0;
    async function replan(quiet = false) {
      if (!S.recording || !S.recording.loaded) return;
      const my = ++inflight;
      if (!quiet) setStatus('解析しています…', 'busy');
      tbody.classList.add('loading');
      try {
        const res = await api('/api/plan', { method: 'POST', json: { plan_options: collectPlanOptions() } });
        if (my !== inflight) return; // a newer request superseded this one
        S.plan = res;
        S.flows = res.flows || [];
        render(res);
        if (!quiet) setStatus(`解析しました: 手順 ${res.steps_kept} 個 / 使う通信 ${res.flows_kept} 件 / 使わない通信 ${res.dropped} 件`, 'ok');
      } catch (e) {
        if (my === inflight) fail(e, '解析に失敗しました');
      } finally {
        tbody.classList.remove('loading');
      }
    }
    const replanDebounced = debounce(() => replan(), 250);
    const replanTyped = debounce(() => replan(), 600);

    function render(plan) {
      // summary
      $('#sum-steps').textContent = plan.steps_kept;
      $('#sum-kept').textContent = plan.flows_kept;
      $('#sum-dropped').textContent = plan.dropped;
      $('#sum-vars').textContent = (plan.steps || []).reduce((n, s) => n + (s.extractors || []).length, 0);
      const finalEl = $('#sum-final');
      const finalBtn = $('#btn-final-clear');
      clear(finalEl);
      if (plan.final_step_index) {
        const st = (plan.steps || []).find((s) => s.index === plan.final_step_index);
        finalEl.appendChild(el('span', { text: `手順 ${plan.final_step_index}${st ? ` (${st.method} ${st.url})` : ''} ` }));
        finalEl.appendChild(finalBtn); finalBtn.hidden = false;
      } else if (S.finalFlowId) {
        finalEl.appendChild(el('span', { class: 'hint', text: `指定した ${S.finalFlowId} は使わない通信になっているため、最後の手順を結果にします ` }));
        finalEl.appendChild(finalBtn); finalBtn.hidden = false;
      } else {
        finalEl.appendChild(el('span', { text: '最後の手順 (既定) ' }));
        finalEl.appendChild(finalBtn); finalBtn.hidden = true;
      }
      const authEl = clear($('#sum-auth'));
      if (plan.auth) {
        const a = plan.auth;
        const kind = { ntlm: 'NTLM (Windows 統合認証)', negotiate: 'Negotiate / Kerberos (Windows 統合認証)', basic: 'Basic 認証', digest: 'Digest 認証' }[a.kind] || a.kind;
        authEl.appendChild(el('span', { class: 'auth-pill', text: kind }));
        authEl.appendChild(document.createTextNode(` ${(a.hosts || []).join(', ')}${a.username ? ` / 記録時のユーザー: ${a.username}` : ''} — スクリプトでは session.auth で認証します`));
      } else authEl.textContent = '見つかりませんでした';
      const constEl = clear($('#sum-constants'));
      if (plan.constants && plan.constants.length) {
        plan.constants.forEach((c, i) => {
          if (i) constEl.appendChild(document.createTextNode(', '));
          constEl.appendChild(el('code', { text: c.name + (c.secret ? ` (秘密: 環境変数 ${c.env_var})` : c.value !== null && c.value !== undefined ? ` = ${String(c.value).slice(0, 40)}` : '') }));
        });
      } else constEl.textContent = 'なし';
      const loopEl = clear($('#sum-loops'));
      if (plan.loops && plan.loops.length) {
        loopEl.textContent = plan.loops.map((l) => `手順 ${l.step_index}: ${l.var} を ${l.count} 回${l.numeric_range ? ` (${l.numeric_range[0]}〜${l.numeric_range[1]})` : ''}`).join(' / ');
      } else loopEl.textContent = 'なし';
      $('#sum-self').textContent = plan.excluded_self_flows ? `GUI 自身への通信 ${plan.excluded_self_flows} 件を記録から除外済み` : 'なし';
      const warnings = warningTexts(plan.warning_details, plan.warnings);
      const warnList = clear($('#sum-warnings'));
      warnings.forEach((w) => warnList.appendChild(el('li', { text: w })));
      $('#sum-warnings-wrap').hidden = !warnings.length;
      const notes = warningTexts(plan.note_details, []);  // informational (Shift_JIS bodies, passwords read at run time)
      const noteList = clear($('#sum-notes'));
      notes.forEach((w) => noteList.appendChild(el('li', { text: w })));
      $('#sum-notes-wrap').hidden = !notes.length;
      renderTable();
    }

    function renderTable() {
      const filter = ($('#table-filter').value || '').toLowerCase();
      const showDropped = $('#show-dropped').checked;
      clear(tbody);
      let shown = 0;
      S.flows.forEach((f) => {
        if (!showDropped && !f.kept) return;
        if (filter && !(`${f.method} ${f.url} ${f.host} ${f.reason || ''}`.toLowerCase().includes(filter))) return;
        shown++;
        const tr = el('tr', { class: (f.kept ? 'kept' : 'dropped') + (f.is_final ? ' final' : ''), dataset: { flowId: f.id } });
        const cb = el('input', { type: 'checkbox', title: f.kept ? 'チェックを外すと、この通信をスクリプトから外します' : 'チェックを入れると、この通信をスクリプトに入れます' });
        cb.checked = f.kept;
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', () => toggleFlow(f, cb.checked));
        const radio = el('input', { type: 'radio', name: 'final-flow', title: 'この通信の結果をスクリプトの最後に表示します' });
        radio.checked = S.finalFlowId === f.id || (!S.finalFlowId && f.is_final);
        radio.disabled = !f.kept;
        radio.addEventListener('click', (e) => e.stopPropagation());
        radio.addEventListener('change', () => { if (radio.checked) { S.finalFlowId = f.id; setChanged(true); replanDebounced(); } });
        let urlNode;
        try {
          const u = new URL(f.url);
          urlNode = el('span', {}, [el('span', { class: 'url-host', text: u.protocol + '//' + u.host }), document.createTextNode(u.pathname + u.search + u.hash)]);
        } catch (e) { urlNode = document.createTextNode(f.url); }
        const statusClass = f.status === null || f.status === undefined ? 's0' : 's' + String(f.status)[0];
        tr.append(
          el('td', { class: 'col-check' }, cb),
          el('td', { class: 'col-radio' }, radio),
          el('td', { class: 'col-step' }, f.step_index ? el('span', { class: 'step-no', text: String(f.step_index) }) : el('span', { class: 'hint', text: f.id })),
          el('td', { class: 'col-method' }, el('span', { class: 'method ' + f.method, text: f.method })),
          el('td', { class: 'col-status' }, el('span', { class: 'status-pill ' + statusClass, text: f.status === null || f.status === undefined ? '—' : String(f.status) })),
          el('td', { class: 'col-type', text: shortMime(f.mime, f.resource_type) }),
          el('td', { class: 'col-url', title: f.url }, urlNode),
          el('td', { class: 'col-ref', title: f.referer || '', text: f.referer ? f.referer.replace(/^https?:\/\//, '') : '' }),
          el('td', { class: 'col-reason' }, el('span', { class: 'reason' + (f.reason === 'excluded by user' ? ' user' : ''), text: f.kept ? (f.is_final ? '使う（結果）' : '使う') : reasonLabel(f.reason) })),
        );
        tr.addEventListener('click', () => Drawer.open(f.id));
        tbody.appendChild(tr);
      });
      if (!shown) {
        tbody.appendChild(el('tr', {}, el('td', { colspan: 9, class: 'empty', text: S.flows.length
          ? '条件に合う行がありません (「使わない通信も表示」にチェックを入れると、すべての通信が出ます)' : '通信がありません' })));
      }
      $('#table-count').textContent = `(${shown} / ${S.flows.length} 件を表示)`;
    }

    function toggleFlow(flow, checked) {
      if (checked) {
        S.exclude.delete(flow.id);
        if (!flow.kept) S.include.add(flow.id);
      } else {
        S.include.delete(flow.id);
        S.exclude.add(flow.id);
        if (S.finalFlowId === flow.id) S.finalFlowId = null;
      }
      setChanged(true);
      replanDebounced();
    }

    $$('input.opt, .opt-num').forEach((n) => n.addEventListener('change', () => { setChanged(true); replanDebounced(); }));
    $$('.opt-text').forEach((n) => n.addEventListener('input', () => { setChanged(true); replanTyped(); }));
    $$('.gopt').forEach((n) => n.addEventListener('change', () => setChanged(true)));
    $('#table-filter').addEventListener('input', debounce(renderTable, 120));
    $('#show-dropped').addEventListener('change', renderTable);
    $('#btn-final-clear').addEventListener('click', () => { S.finalFlowId = null; setChanged(true); replan(); });

    return { replan, collectPlanOptions, collectGenOptions, fillOptions, setChanged };
  })();

  // ================================================================== 詳細ドロワー
  const Drawer = (() => {
    const drawer = $('#drawer');
    const backdrop = $('#drawer-backdrop');
    function close() { drawer.hidden = true; backdrop.hidden = true; }
    $('#drawer-close').addEventListener('click', close);
    backdrop.addEventListener('click', close);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !drawer.hidden) close(); });
    $$('.tab', drawer).forEach((t) => t.addEventListener('click', () => {
      $$('.tab', drawer).forEach((x) => x.classList.toggle('active', x === t));
      $$('.tab-body', drawer).forEach((b) => b.classList.toggle('active', b.id === 'tab-' + t.dataset.tab));
    }));
    function fillPairs(table, pairs, emptyText) {
      const tb = clear(table.querySelector('tbody'));
      if (!pairs || !pairs.length) { tb.appendChild(el('tr', {}, el('td', { colspan: 2, class: 'empty', text: emptyText }))); return; }
      pairs.forEach(([k, v]) => tb.appendChild(el('tr', {}, [el('td', { text: k }), el('td', { text: v })])));
    }
    function bodyInfo(b) {
      if (!b || b.kind === 'none') return '(なし)';
      const kind = { json: 'JSON', html: 'HTML', form: 'フォーム', text: 'テキスト', binary: 'バイナリ' }[b.kind] || b.kind;
      return `${kind} / ${fmtBytes(b.size)}${b.mime ? ` / ${b.mime}` : ''}${b.truncated ? ' / 先頭 200 KB のみ表示' : ''}`;
    }
    function bodyText(b) {
      if (!b || b.kind === 'none') return '';
      if (b.kind === 'binary') return `(バイナリデータ ${fmtBytes(b.size)} — 表示できません)`;
      return b.text || '';
    }
    async function open(flowId) {
      try {
        const d = await api('/api/flow/' + encodeURIComponent(flowId));
        $('#dr-method').textContent = d.request.method;
        $('#dr-method').className = 'method ' + d.request.method;
        const st = d.response ? d.response.status : null;
        const pill = $('#dr-status');
        pill.textContent = st === null ? 'レスポンスなし' : String(st);
        pill.className = 'status-pill ' + (st === null ? 's0' : 's' + String(st)[0]);
        $('#dr-flow-id').textContent = `${d.id}${d.step_index ? ` / 手順 ${d.step_index}` : d.reason ? ` / 使わない理由: ${d.reason}` : ''}`;
        $('#dr-url').textContent = d.request.url;
        $('#dr-meta').textContent = [d.started_at_iso ? `時刻 ${d.started_at_iso}` : null, d.resource_type ? `種類 ${d.resource_type}` : null, d.page_ref ? `ページ ${d.page_ref}` : null].filter(Boolean).join(' / ');
        fillPairs($('#dr-req-query'), d.request.query, 'クエリパラメータなし');
        fillPairs($('#dr-req-headers'), d.request.headers, 'ヘッダーなし');
        const rb = d.request.body;
        $('#dr-req-body-info').textContent = bodyInfo(rb);
        const formTable = $('#dr-req-form');
        if (rb && rb.kind === 'form' && rb.pairs) { fillPairs(formTable, rb.pairs, ''); formTable.hidden = false; } else formTable.hidden = true;
        $('#dr-req-body').textContent = bodyText(rb);
        if (d.response) {
          fillPairs($('#dr-resp-headers'), d.response.headers, 'ヘッダーなし');
          $('#dr-resp-body-info').textContent = bodyInfo(d.response.body);
          $('#dr-resp-body').textContent = bodyText(d.response.body);
        } else {
          fillPairs($('#dr-resp-headers'), [], 'レスポンスは記録されていません');
          $('#dr-resp-body-info').textContent = '';
          $('#dr-resp-body').textContent = '(レスポンスなし)';
        }
        drawer.hidden = false; backdrop.hidden = false;
      } catch (e) { fail(e, '詳細を取得できません'); }
    }
    return { open };
  })();

  // ================================================================== 試しに実行 (かんたん画面と詳細設定)
  const Run = (() => {
    let last = {};  // the last /api/run/status (one script runs at a time; both screens show it)
    function authLabel(s) {  // Windows authentication entries (REQREC_NTLM_USER / _PASSWORD) carry ``auth``
      return `Windows 認証 (${s.auth === 'negotiate' ? 'Negotiate' : 'NTLM'})`;
    }
    function friendlySecretLabel(s) {
      if (s.auth) return `${authLabel(s)} の${s.secret === false ? 'ユーザー名' : 'パスワード'}`;
      const name = String(s.name || s.env_var || '');
      const field = /form `([^`]+)`/.exec(String(s.comment || ''));
      let kind = '入力が必要な値';
      if (/pass|pwd/i.test(name) || /パスワード/.test(name)) kind = 'パスワード';
      else if (/user|login|account/i.test(name) || /ユーザー/.test(name)) kind = 'ユーザー名';
      else if (/token|key|secret/i.test(name)) kind = '秘密の値 (トークンなど)';
      return field ? `${kind} (入力欄: ${field[1]})` : kind;
    }
    function friendlySecretHint(s) {
      // Windows authentication keeps its own instruction: with requests_negotiate_sspi the logged-in Windows user
      // is used and both fields stay blank; 「記録したときと同じ値」 would be wrong advice there.
      if (s.auth) return s.comment || '';
      return '記録したときと同じ値を入れてください。実行するときだけ使われ、どこにも保存されません。';
    }
    // input fields for the values the current script reads from environment variables (S.secrets)
    function renderEnvInputsInto(container, idPrefix, runLabel, showEnvName = false) {
      clear(container);
      if (!S.secrets.length) {
        container.appendChild(el('p', { class: 'hint', text: `入力するものはありません。[${runLabel}] を押すだけで動きます。` }));
        return;
      }
      S.secrets.forEach((s) => {
        const id = idPrefix + s.env_var;
        container.appendChild(el('label', { for: id, text: friendlySecretLabel(s) }));
        const isSecret = s.secret !== false;
        container.appendChild(el('div', {}, [
          el('input', { type: isSecret ? 'password' : 'text', id, class: 'env-input w-m', dataset: { env: s.env_var }, autocomplete: 'off', placeholder: s.name, value: !isSecret && s.default ? s.default : undefined }),
          el('div', { class: 'hint', text: friendlySecretHint(s) + (showEnvName ? `（環境変数 ${s.env_var}）` : '') }),
        ]));
      });
    }
    function collectEnvFrom(container) {
      const env = {};
      $$('.env-input', container).forEach((i) => { if (i.value !== '') env[i.dataset.env] = i.value; });
      return env;
    }
    const listeners = [];
    function subscribe(fn) { listeners.push(fn); }
    function render(st) {
      last = st || {};
      listeners.forEach((fn) => { try { fn(last); } catch (e) { console.error(e); } });
      const running = !!last.running;
      if (running && !S.runPoll) S.runPoll = setInterval(poll, 1000);
      if (!running && S.runPoll) { clearInterval(S.runPoll); S.runPoll = null; }
    }
    function refresh() { render(last); }  // e.g. the current script changed: the run buttons follow
    async function poll() {
      try {
        const st = await api('/api/run/status');
        render(st);
        if (!st.running && st.exit_code !== null && st.exit_code !== undefined) {
          if (st.exit_code === 0) setStatus('スクリプトは正常に終わりました', 'ok');
          else if (st.stopped_by_user) setStatus('スクリプトを停止しました', 'info');
          else setStatus(`スクリプトはエラーで終わりました (終了コード ${st.exit_code})`, 'error');
        }
      } catch (e) { /* transient */ }
    }
    async function start(name, env) {
      if (!name) { setStatus('実行するスクリプトがありません', 'error'); return false; }
      setStatus(`${name} を実行しています…`, 'busy');
      try {
        render(await api('/api/run', { method: 'POST', json: { name, env } }));
        return true;
      } catch (e) { fail(e, '実行できません'); return false; }
    }
    async function stop() {
      try { render(await api('/api/run/stop', { method: 'POST', json: {} })); setStatus('スクリプトを停止しました', 'info'); } catch (e) { fail(e); }
    }
    async function saveOutput(resultEl) {
      try {
        const res = await api('/api/run/save_output', { method: 'POST', json: {} });
        resultEl.textContent = `保存しました: ${res.path}${res.truncated ? ' ※出力が大きすぎたため途中までです' : ''}`;
        setStatus(`結果を保存しました: ${res.name}`, 'ok');
      } catch (e) { fail(e, '結果を保存できません'); }
    }
    // plain-language hint for the most common failures of a generated script (the raw traceback stays available below)
    const ERROR_HINTS = [
      [/getaddrinfo failed|Name or service not known|NameResolutionError|nodename nor servname/i, 'サイトに接続できません (アドレスが見つかりません)。LAN環境内のネットワークに接続しているか、VPN が必要なサイトではないか確認してください。'],
      [/ConnectTimeout|Read timed out|timed out/i, 'サイトの応答がありません (タイムアウト)。しばらくしてからもう一度実行してください。'],
      [/CERTIFICATE_VERIFY_FAILED|SSLCertVerificationError/i, 'https:// のサイトの証明書を確認できませんでした (Windows にも入っていない、自己署名などの証明書です)。サイトの管理者から証明書のファイル (Base64 形式の .cer / .pem) をもらい、コマンドプロンプトで「set REQUESTS_CA_BUNDLE=そのファイルの場所」を入力してから、同じコマンドプロンプトで python reqrec.py を起動し直してください。'],
      [/SSLError/i, 'https:// のサイトと暗号化した接続を始められませんでした。サイトが古い方式 (TLS 1.0 / 1.1 など) にしか対応していない可能性があります。サイトの管理者に確認してください。'],
      [/ConnectionRefused|Connection refused|WinError 10061/i, 'サイトに接続できません (接続が拒否されました)。サイトが動いているか確認してください。'],
      [/\b(401|403) Client Error|Unauthorized for url|Forbidden for url|: HTTP (401|403) /, 'ログインに失敗したか、権限がありません。パスワードなどの入力値を確認してください。'],
      [/REQREC_[A-Z_]+ (が|is) /, '実行に必要な入力 (パスワードなど) が足りません。上の入力欄をすべて埋めてください。'],
      [/が選んだ値の行が(ありません|複数あります)/, '記録したときに一覧から選んだ行 (名前などが同じ行) が、今回の一覧に無いか、複数あります。入力値を確認してください。一覧の内容が変わった場合は、もう一度記録してください。'],
      [/要素が見つかりません|パターンに一致しませんでした|JSON にパス/, '画面の内容が記録したときと違うため、続きの値を取り出せませんでした。パスワードが正しいか、ログインが拒否されていないかを確認してください。サイトの画面が変わった場合は、もう一度記録してください。'],
      [/ModuleNotFoundError: No module named '(requests_negotiate_sspi|requests_ntlm)'|統合 Windows 認証には追加パッケージが必要です/, 'Windows 統合認証用の部品が入っていません。管理者に python -m pip install requests_negotiate_sspi の実行を依頼してください (別のユーザーで認証する場合は、代わりに python -m pip install requests_ntlm)。'],
      [/ModuleNotFoundError: No module named '([\w.]+)'/, '必要な部品 ($1) が入っていません。管理者に pip install の実行を依頼してください。'],
      [/status (\d{3}) .*expected|想定外のステータス|unexpected status/i, 'サイトの応答が記録したときと違います。サイト側が変わったか、ログインが切れている可能性があります。'],
      [/SyntaxError|IndentationError|TabError/, 'スクリプトの書き方に誤りがあります。詳細設定でコードを書き換えた場合は、エラーメッセージの行を確認してください。'],
    ];
    function errorHint(text) {
      if (!text) return '';
      for (const [re, msg] of ERROR_HINTS) {
        const m = re.exec(text);
        if (m) return msg.replace('$1', m[1] || '');
      }
      const lastLine = text.trim().split('\n').pop();
      return lastLine ? `エラー: ${lastLine.slice(0, 200)}` : '';
    }
    // one run card (#easy-run-… / #detail-run-…): buttons, state, result (with the progress lines),
    // error details and the plain-language hint
    function bindView(p, opts) {
      const btn = $(`#${p}-run-btn`);
      const stopBtn = $(`#${p}-run-stop`);
      const saveBtn = $(`#${p}-save-output`);
      const out = $(`#${p}-run-out`);
      const err = $(`#${p}-run-err`);
      const errWrap = $(`#${p}-run-err-wrap`);
      const state = $(`#${p}-run-state`);
      const hint = $(`#${p}-run-hint`);
      btn.addEventListener('click', async () => {
        btn.disabled = true;  // no second start while the first one is on its way
        try { await opts.onRun(); } finally { refresh(); }
      });
      stopBtn.addEventListener('click', stop);
      saveBtn.addEventListener('click', () => saveOutput($(`#${p}-save-output-result`)));
      subscribe((st) => {
        const running = !!st.running;
        btn.disabled = running || !opts.canRun();
        stopBtn.disabled = !running;
        saveBtn.disabled = running || !st.started_at;
        out.textContent = (st.output_tail ?? st.stdout_tail) || (running ? '(実行中… 出力を待っています)' : '');
        if (running) out.scrollTop = out.scrollHeight;
        const errors = (st.errors_tail ?? st.stderr_tail) || '';  // stderr without the progress lines
        err.textContent = errors;
        errWrap.hidden = !errors;
        hint.hidden = true;
        if (running) { state.textContent = '実行中…'; state.className = 'run-state running'; }
        else if (st.exit_code === null || st.exit_code === undefined) { state.textContent = '待機中'; state.className = 'run-state'; }
        else if (st.exit_code === 0) { state.textContent = '正常に終わりました'; state.className = 'run-state ok'; }
        else {
          state.textContent = st.stopped_by_user ? '停止しました' : 'エラーで終わりました';
          state.className = 'run-state fail';
          if (!st.stopped_by_user) {
            const h = errorHint(st.stderr_tail);
            if (h) { hint.textContent = h; hint.hidden = false; }
            errWrap.open = true;
          }
        }
      });
    }
    return { start, render, refresh, bindView, renderEnvInputsInto, collectEnvFrom, friendlySecretLabel, authLabel };
  })();

  // ================================================================== 詳細設定: スクリプトの中身を確認・変更する
  // 手順と設定を変えて [設定から作り直す] (= /api/easy/build で同じファイルを作り直す) か、コードを直接
  // 書き換えて [保存] する。どちらも [試しに実行する] ですぐに確かめられる。
  const Detail = (() => {
    const editor = $('#code-editor');
    const nameInput = $('#script-name');
    const btnSave = $('#btn-save');
    const btnRevert = $('#btn-revert');
    const btnDownload = $('#btn-download');
    const btnRegen = $('#btn-regenerate');
    const RUN_LABEL = '▶ 試しに実行する';

    function typedName() {
      const n = nameInput.value.trim();
      return n && !/\.py$/i.test(n) ? n + '.py' : n;
    }
    function dirty() { return !!S.script && S.savedCode !== null && editor.value !== S.savedCode; }
    function refreshButtons() {
      const changed = dirty();
      $('#code-dirty').hidden = !changed;
      btnSave.disabled = !S.script || (!changed && typedName() === S.script);
      btnRevert.disabled = !changed;
      btnDownload.disabled = !S.script;
      $('#code-lines').textContent = editor.value ? `(${editor.value.split('\n').length} 行)` : '';
    }
    // steps and settings need a loaded recording, the code a script
    function refresh() {
      const loaded = !!(S.recording && S.recording.loaded && S.recording.flows);
      $('#detail-empty').hidden = loaded || !!S.script;
      $('#detail-body').hidden = !(loaded || S.script);
      $('#detail-source').textContent = loaded
        ? `${(S.recording.sources || []).join(', ') || '—'}（${S.recording.flows} 件の通信）`
        : '(記録は読み込まれていません)';
      btnRegen.disabled = !loaded;
      btnRegen.textContent = S.script ? '⚙ 設定から作り直す' : '⚙ この設定でスクリプトを作る';
      $('#regen-hint').textContent = S.script
        ? '今のスクリプトを、この設定で作ったコードに置きかえて保存します (コードを直接書き換えた部分は消えます)。'
        : 'この設定でスクリプトを作って保存します。';
    }
    // The current script, shown on both screens.  ``code`` is its saved content; the editor is only
    // refilled when ``fillEditor`` (a save keeps whatever was typed meanwhile).
    function setScript(name, code, path, fillEditor = true) {
      S.script = name || null;
      S.savedCode = name ? (code || '') : null;
      if (!name) S.generatedCode = null;
      if (fillEditor && editor.value !== (code || '')) editor.value = code || '';
      editor.readOnly = !name;
      nameInput.value = name ? name.replace(/\.py$/i, '') : '';
      nameInput.disabled = !name;
      $('#detail-script').textContent = name || '(まだありません)';
      if (path) $('#save-result').textContent = `保存先: ${path}`;
      Run.renderEnvInputsInto($('#detail-env'), 'detail-env-', RUN_LABEL, true);
      Easy.showScript(name, path);
      refreshButtons();
      refresh();
      Run.refresh();
    }
    async function loadScript(name) {  // after a page reload: the saved file goes into the editor
      try {
        const resp = await fetch(scriptUrl(name), { credentials: 'same-origin', cache: 'no-store' });
        if (resp.ok) setScript(name, await resp.text(), null);
      } catch (e) { /* the editor stays empty */ }
    }
    async function save() {
      if (!S.script) return false;
      const name = typedName();
      if (!name) { setStatus('ファイル名を入力してください', 'error'); nameInput.focus(); return false; }
      const code = editor.value;
      setStatus('保存しています…', 'busy');
      try {
        const res = await api('/api/scripts/save', { method: 'POST', json: { name, code } });
        setScript(res.name, code, res.path, false);
        $('#save-result').textContent = `保存しました: ${res.path}`;
        setStatus(`保存しました: ${res.name}`, 'ok');
        return true;
      } catch (e) { fail(e, '保存できませんでした'); return false; }
    }
    function revert() {
      if (!dirty() || !window.confirm('保存していない変更を消して、保存した内容に戻しますか？')) return;
      editor.value = S.savedCode;
      refreshButtons();
    }
    async function download() {
      if (!S.script || (dirty() && !(await save()))) return;
      const a = el('a', { href: scriptUrl(S.script), download: S.script });
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
    async function regenerate() {
      if (!S.recording || !S.recording.loaded) return;
      const edited = !!S.script && (S.generatedCode === null || editor.value !== S.generatedCode);
      if (edited && !window.confirm('コードを直接書き換えた部分は消えて、この設定で作ったコードに置きかわります。よろしいですか？')) return;
      const had = !!S.script;
      btnRegen.disabled = true;
      setStatus('設定からスクリプトを作っています…', 'busy');
      try {
        const b = await api('/api/easy/build', { method: 'POST', json: {
          name: S.script || undefined,  // the same file is replaced; a new one gets the automatic name
          plan_options: Steps.collectPlanOptions(),
          gen_options: Steps.collectGenOptions(),
        } });
        applyBuild(b);
        setStatus(had ? `作り直して保存しました: ${b.name}` : `スクリプトを作りました: ${b.name}`, 'ok');
      } catch (e) { fail(e, 'スクリプトを作れませんでした'); }
      finally { refresh(); }
    }

    editor.addEventListener('input', refreshButtons);
    editor.addEventListener('keydown', (e) => {
      if (e.key === 'Tab' && !e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey && !editor.readOnly) {
        e.preventDefault();  // 4 spaces (Python indentation) instead of moving the focus
        if (!document.execCommand('insertText', false, '    ')) editor.setRangeText('    ', editor.selectionStart, editor.selectionEnd, 'end');
        refreshButtons();
      } else if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
        e.preventDefault();
        if (!btnSave.disabled) save();
      }
    });
    nameInput.addEventListener('input', refreshButtons);
    nameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !btnSave.disabled) save(); });
    btnSave.addEventListener('click', save);
    btnRevert.addEventListener('click', revert);
    btnDownload.addEventListener('click', download);
    btnRegen.addEventListener('click', regenerate);
    window.addEventListener('beforeunload', (e) => { if (dirty()) { e.preventDefault(); e.returnValue = ''; } });
    Run.bindView('detail', {
      canRun: () => !!S.script,
      onRun: async () => {  // unsaved edits are saved first: the run uses the file
        if (!dirty() || await save()) {
          const env = Run.collectEnvFrom($('#detail-env'));
          if ($('#detail-run-debug').checked) env.REQREC_DEBUG = '1';  // the script's dependency debug lines
          await Run.start(S.script, env);
        }
      },
    });
    return { setScript, loadScript, refresh, dirty };
  })();

  // ================================================================== かんたん画面 (既定)
  // 「記録をはじめる」→ 記録用ブラウザでサイトを操作 → 「記録をおわる」(または記録用ブラウザを閉じる) だけで、
  // 記録用ブラウザの起動・解析・生成・保存をすべて自動で行う。HAR ファイルからも同じように作れる。
  // できたスクリプトの中身の確認と細かい変更は「詳細設定を表示」(Detail) で行う。
  const Easy = (() => {
    // 記録できるのは、記録用ブラウザ (IE エンジン) が使える Windows の PC で、その PC から開いたときだけ
    // (サーバー側の判断: data-can-record)。それ以外の画面は HAR ファイルから作る (記録用の項目は出さない)。
    const CAN_RECORD = body.dataset.canRecord === 'true';
    const CAN_IE = body.dataset.canIe === 'true';      // the recording browser (IE engine) can be used here
    const CAN_EDGE = body.dataset.canEdge === 'true';  // Microsoft Edge can be used here
    const EMULATION_KEY = 'reqrec.emulation';  // 表示モード: remembered in this browser, sent with every start
    const BROWSER_KEY = 'reqrec.browser';      // 記録に使うブラウザ (ie / edge): remembered the same way
    const stages = { idle: $('#easy-idle'), recording: $('#easy-recording'), processing: $('#easy-processing'), done: $('#easy-done') };
    const errEl = $('#easy-error');
    const btnStart = $('#easy-start');
    const btnStop = $('#easy-stop');
    const emuSel = $('#easy-emulation');
    const browserSel = $('#easy-browser');
    let current = 'idle';
    let autoStopped = false;    // the recording browser was closed: stop + build already fired for this recording
    let lastIEError = null;     // last failure to open the recording browser in this GUI session
    let recBrowser = 'ie';      // the browser of the current recording
    const browserName = () => (recBrowser === 'edge' ? 'Edge' : '記録用ブラウザ');

    // ---------------------------------------------------------------- stages
    function stage(name, text) {
      current = name;
      Object.entries(stages).forEach(([k, node]) => { node.hidden = k !== name; });
      if (name === 'processing' && text) $('#easy-processing-text').textContent = text;
      toggleBtn.disabled = name === 'recording' || name === 'processing';  // 詳細設定 waits for the script
      if (name === 'idle') { btnStart.disabled = !CAN_RECORD; readiness(); }
      window.scrollTo({ top: 0 });
    }
    function showError(message) { errEl.textContent = message || ''; errEl.hidden = !message; }

    // ---------------------------------------------------------------- readiness (idle)
    function readiness() {
      refreshLoaded();
      if (!CAN_RECORD) return;  // HAR files only: the recording controls are not shown
      const list = clear($('#easy-ready'));
      const add = (cls, text) => list.appendChild(el('li', { class: cls, text }));
      if (lastIEError) add('bad', '前回、記録用のブラウザを開けませんでした: ' + lastIEError);
      add(CAN_IE ? 'ok' : 'bad', CAN_IE ? 'IE モード (記録用ブラウザ): 使えます (Windows の設定や証明書は変更しません)'
        : 'IE モード (記録用ブラウザ): この PC では使えません');
      add(CAN_EDGE ? 'ok' : 'bad', CAN_EDGE ? 'Edge: 使えます (記録専用の窓で開きます。ふだんの Edge の設定は変更しません)'
        : 'Edge: この PC では見つかりません');
    }
    // a recording loaded earlier (before a page reload, or one that could not be turned into a script)
    function refreshLoaded() {
      const loaded = !!(S.recording && S.recording.loaded && S.recording.flows);
      $('#easy-loaded').hidden = !loaded;
      if (loaded) $('#easy-loaded-count').textContent = S.recording.flows;
    }

    // ---------------------------------------------------------------- 表示モード (this browser remembers it)
    function loadEmulation() {
      let name = 'default';
      try { name = localStorage.getItem(EMULATION_KEY) || 'default'; } catch (e) { /* ignore */ }
      if (!emuSel.querySelector(`option[value="${name}"]`)) name = 'default';
      emuSel.value = name;
    }
    emuSel.addEventListener('change', () => {
      try { localStorage.setItem(EMULATION_KEY, emuSel.value); } catch (e) { /* ignore */ }
    });

    // ---------------------------------------------------------------- 記録に使うブラウザ (this browser remembers it)
    function showBrowser(name) {  // 表示モード only for IE mode; the guide texts of the recording stage
      $$('[data-ie-only]').forEach((node) => { node.hidden = name !== 'ie'; });
      $$('[data-for-browser]').forEach((node) => { node.hidden = node.dataset.forBrowser !== name; });
    }
    function loadBrowser() {
      let name = 'ie';
      try { name = localStorage.getItem(BROWSER_KEY) || 'ie'; } catch (e) { /* ignore */ }
      if (name === 'edge' ? !CAN_EDGE : !CAN_IE) name = CAN_IE ? 'ie' : 'edge';  // the one this PC has
      browserSel.value = name;
      showBrowser(name);
    }
    browserSel.addEventListener('change', () => {
      try { localStorage.setItem(BROWSER_KEY, browserSel.value); } catch (e) { /* ignore */ }
      showBrowser(browserSel.value);
    });

    // ---------------------------------------------------------------- live count (polled every second)
    function renderLive(st) {
      $('#easy-count').textContent = st.flows ?? 0;
      const err = $('#easy-rec-error');
      err.textContent = st.error ? browserName() + 'が終了しました: ' + st.error : '';
      err.hidden = !st.error;
    }
    function onRecordStatus(st) {
      if (current !== 'recording') return;
      renderLive(st);
      if (st.running || autoStopped) return;
      // The recording browser was closed (its own [記録をおわる] or the window's ×): stop + build once.
      autoStopped = true;
      if (st.exit_code === 4) {  // the per-process proxy could not be set: nothing was recorded
        discardSilently('記録用ブラウザの中継設定に失敗したため、記録できませんでした。もう一度 [記録をはじめる] を押してください。');
        return;
      }
      setStatus((recBrowser === 'edge' ? 'Edge の窓' : '記録用ブラウザ') + 'が閉じられました。スクリプトを作成します…', 'busy');
      stop();
    }
    async function pollRecord() {
      let st;
      try { st = await api('/api/record/status'); } catch (e) { return; }  // transient
      onRecordStatus(st);
      if (!st.running) stopPolling();
    }
    function startPolling() { if (!S.recPoll) S.recPoll = setInterval(pollRecord, 1000); }
    function stopPolling() { clearInterval(S.recPoll); S.recPoll = null; }

    // ---------------------------------------------------------------- start / stop / cancel
    function okToStartOver() {  // a new recording replaces the current script of 詳細設定
      return !Detail.dirty() || window.confirm('詳細設定で書き換えたコードが、まだ保存されていません。保存しないで新しく作りますか？');
    }
    async function start() {
      if (!CAN_RECORD || !okToStartOver()) return;
      showError('');
      btnStart.disabled = true;
      $('#easy-rec-error').hidden = true;
      $('#easy-count').textContent = '0';
      autoStopped = false;
      recBrowser = browserSel.value === 'edge' ? 'edge' : 'ie';
      showBrowser(recBrowser);
      stage('processing', recBrowser === 'edge' ? '記録の準備をしています… (記録用の Edge の窓を開きます。数秒かかります)'
        : '記録の準備をしています… (記録用ブラウザを開きます。数秒かかります)');
      let res;
      try {
        res = await api('/api/record/start', { method: 'POST', json: {
          start_url: $('#easy-url').value.trim(),
          emulation: emuSel.value,
          browser: recBrowser,
        } });
      } catch (e) {
        stage('idle');
        const kind = e.data && e.data.kind;
        if (kind === 'iehost' || kind === 'edge') {
          lastIEError = e.message;
          readiness();
          showError(e.message + '　もう一度 [記録をはじめる] を押してください。何度やっても同じときは、パソコンを再起動してから試してください。');
        } else if (kind === 'proxy') {
          showError(e.message + '　記録用の中継を設定できませんでした。もう一度 [記録をはじめる] を押してください。');
        } else {
          showError('記録を始められませんでした: ' + e.message);
        }
        setStatus('記録を始められませんでした', 'error');
        return;
      }
      lastIEError = null;
      stage('recording');
      renderLive(res.status || { running: true, flows: 0 });
      startPolling();
      setStatus(recBrowser === 'edge' ? '記録中です。開いた Edge の窓でサイトを操作してください。'
        : '記録中です。開いた記録用ブラウザでサイトを操作してください。', 'ok');
    }

    async function stop() {
      btnStop.disabled = true;
      stage('processing', '記録を保存しています…');
      let res;
      try {
        res = await api('/api/record/stop', { method: 'POST', json: {} });
      } catch (e) {
        btnStop.disabled = false;
        stopPolling();
        stage('idle');
        const empty = !!(e.data && e.data.empty);
        // Edge: a site switched to IE mode, or a proxy fixed by the PC's settings, leaves nothing to record
        const edgeHint = empty && recBrowser === 'edge'
          ? '　Edge で開いても IE モードに切り替わるサイトや、PC の設定で中継が固定されている場合は記録できません。「IE モード」で記録してください。' : '';
        showError((empty ? '' : '記録を保存できませんでした: ') + e.message + edgeHint);
        setStatus(empty ? '何も記録されませんでした' : '記録を保存できませんでした', 'error');
        return;
      }
      btnStop.disabled = false;
      stopPolling();
      setRecording(res);
      stage('processing', `記録した ${res.flows} 件の通信を解析して、スクリプトを作成しています…`);
      await build();
    }

    // HAR files (one per tab are merged by time stamp) or reqrec's own .json, the same way as a recording
    async function buildFromFiles(files) {
      if (!files.length || !okToStartOver()) return;
      showError('');
      stage('processing', `${files.length} 個のファイルを読み込んでいます…`);
      const form = new FormData();
      files.forEach((f) => form.append('files', f, f.name));
      let res;
      try {
        res = await api('/api/recordings/upload', { method: 'POST', form });
      } catch (e) {
        stage('idle');
        showError('ファイルを読み込めませんでした: ' + e.message);
        setStatus('ファイルを読み込めませんでした', 'error');
        return;
      }
      setRecording(res);
      stage('processing', `読み込んだ ${res.flows} 件の通信を解析して、スクリプトを作成しています…`);
      await build();
    }

    async function build() {
      let b;
      try {
        b = await api('/api/easy/build', { method: 'POST', json: {} });
      } catch (e) {
        stage('idle');
        showError('スクリプトを作成できませんでした: ' + e.message + '　記録は読み込まれているので、右上の「詳細設定を表示」で通信の一覧を確認できます。');
        setStatus('スクリプトを作成できませんでした', 'error');
        Steps.replan(true);
        return;
      }
      applyBuild(b);
      Steps.replan(true);  // the table of 詳細設定 (not awaited)
      stage('done');
      setStatus(`スクリプトができました: ${b.name}`, 'ok');
    }

    async function discardSilently(message) {
      stage('processing', '記録を止めています…');
      try { await api('/api/record/stop', { method: 'POST', json: { discard: true } }); } catch (e) { /* already stopped */ }
      stopPolling();
      stage('idle');
      showError(message);
      setStatus('記録できませんでした', 'error');
    }

    async function cancel() {
      if (!window.confirm('記録をやめて破棄しますか？')) return;
      stage('processing', '記録を止めています…');
      try { await api('/api/record/stop', { method: 'POST', json: { discard: true } }); } catch (e) { /* already stopped: nothing to discard */ }
      stopPolling();
      stage('idle');
      setStatus('記録をやめました', 'info');
    }

    // ---------------------------------------------------------------- done screen
    function showScript(name, path) {  // the current script (saved under another name in 詳細設定, too)
      $('#easy-done-name').textContent = name || '';
      if (path) $('#easy-done-path').textContent = path;
      const dl = $('#easy-download');
      if (name) { dl.href = scriptUrl(name); dl.setAttribute('download', name); }
    }
    function renderDone(b) {
      showScript(b.name, b.path);
      $('#easy-done-steps').textContent = `${b.steps} 手順 (記録した ${b.flows_total} 件の通信から、画像や広告などを除いて作りました)`;
      $('#easy-done-final').textContent = b.final_url ? `${b.final_method || ''} ${b.final_url}` : '最後の手順の結果';
      const files = clear($('#easy-done-files'));
      (b.downloads || []).forEach((d, i) => {
        if (i) files.appendChild(el('br'));
        files.appendChild(el('strong', { text: d.filename || '(アドレスなどから自動で付けた名前)' }));
        files.appendChild(el('span', { class: 'hint', text: d.loop
          ? `　手順 ${d.index} (繰り返し) のダウンロード。繰り返しのたびに保存され、同じ名前のときは「名前 (2)」のように番号が付きます`
          : `　手順 ${d.index} のダウンロード。実行すると保存されます` }));
      });
      $('#easy-done-files').hidden = $('#easy-done-files-label').hidden = !(b.downloads && b.downloads.length);
      const list = clear($('#easy-steplist'));
      (b.steps_view || []).forEach((s) => list.appendChild(el('li', {}, [
        el('span', { class: 'method ' + s.method, text: s.method }),
        document.createTextNode(s.url),
        s.loop ? el('span', { class: 'loop-tag', text: '(繰り返し)' }) : null,
        s.extracts ? el('span', { class: 'hint', text: ` — この画面から ${s.extracts} 個の値を取り出します` }) : null,
      ])));
      const wl = clear($('#easy-done-warning-list'));
      const warnings = warningTexts(b.warning_details, b.warnings);
      warnings.forEach((w) => wl.appendChild(el('li', { text: w })));
      $('#easy-done-warnings').hidden = !warnings.length;
      const sec = $('#easy-done-secrets');
      // Only real secrets are kept out of the script: the Windows-authentication user name (secret: false)
      // is written into it as the default, so it is not listed here.
      const hidden = (b.secrets || []).filter((s) => s.secret !== false);
      if (hidden.length) {
        let text = `${hidden.map((s) => Run.friendlySecretLabel(s)).join('、')} はスクリプトに書き込まれていません。実行するときに入力します。`;
        const auth = hidden.find((s) => s.auth);
        if (auth) text += `（${Run.authLabel(auth)} は、Windows に今ログインしているユーザーのまま実行するなら入力不要です）`;
        sec.textContent = text;
        sec.hidden = false;
      } else sec.hidden = true;
      $('#easy-run').hidden = true;
      $('#easy-save-output-result').textContent = '';
    }

    $('#easy-open-folder').addEventListener('click', async () => {
      try { await api('/api/folder/open', { method: 'POST', json: { folder: 'scripts' } }); }
      catch (e) { fail(e, 'フォルダを開けません'); }
    });
    $('#easy-open-detail').addEventListener('click', () => setMode('advanced'));
    $('#easy-again').addEventListener('click', () => { stage('idle'); showError(''); });
    $('#easy-build-loaded').addEventListener('click', async () => {
      if (!(S.recording && S.recording.loaded) || !okToStartOver()) return;
      showError('');
      stage('processing', `読み込み済みの ${S.recording.flows} 件の通信を解析して、スクリプトを作成しています…`);
      await build();
    });
    $('#easy-har-pick').addEventListener('click', () => $('#easy-har-input').click());
    $('#easy-har-input').addEventListener('change', (e) => {
      const files = Array.from(e.target.files || []);
      e.target.value = '';  // the same file can be chosen again
      buildFromFiles(files);
    });
    $('#easy-test-run').addEventListener('click', () => {
      Run.renderEnvInputsInto($('#easy-env'), 'easy-env-', '▶ 実行');
      $('#easy-run').hidden = false;
      $('#easy-run').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    Run.bindView('easy', { canRun: () => !!S.script, onRun: () => Run.start(S.script, Run.collectEnvFrom($('#easy-env'))) });

    btnStart.addEventListener('click', start);
    btnStop.addEventListener('click', stop);
    $('#easy-cancel').addEventListener('click', cancel);
    $('#easy-url').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !btnStart.disabled) start(); });

    function initFromState(st) {
      lastIEError = (st.record && st.record.last_error) || null;
      loadEmulation();
      loadBrowser();
      if (st.recorder && st.recorder.running) {
        // a page reload during a recording: it is finished here (closing the browser still stops it)
        setMode('easy', false);
        autoStopped = false;
        recBrowser = st.recorder.browser === 'edge' ? 'edge' : 'ie';
        showBrowser(recBrowser);
        stage('recording');
        renderLive(st.recorder);
        startPolling();
        return;
      }
      let mode = 'easy';
      try { mode = localStorage.getItem('reqrec.mode') || 'easy'; } catch (e) { /* ignore */ }
      setMode(mode, false);
      stage('idle');
    }
    return { initFromState, renderDone, showScript, refreshLoaded };
  })();

  // ================================================================== shared by the two screens
  // A recording was loaded (recorded or HAR): the server starts over with the default options and no script.
  function setRecording(sum) {
    S.recording = sum;
    S.plan = null;
    S.flows = [];
    S.secrets = [];
    Steps.fillOptions(sum.plan_options, sum.gen_options);
    Detail.setScript(null, null, null);
    Easy.refreshLoaded();
  }
  // A script was made (かんたん画面) or rebuilt (詳細設定 [設定から作り直す]) and saved: /api/easy/build.
  function applyBuild(b) {
    S.secrets = b.secrets || [];
    S.generatedCode = b.code;
    Steps.fillOptions(b.plan_options, b.gen_options);
    Detail.setScript(b.name, b.code, b.path);
    Easy.renderDone(b);
  }

  // ================================================================== 起動
  async function init() {
    try {
      const st = await api('/api/state');
      S.recording = st.recording || { loaded: false };
      S.secrets = st.secrets || [];
      Steps.fillOptions(st.plan_options, st.gen_options);
      Run.render(st.run || {});
      Easy.initFromState(st);
      Detail.refresh();
      if (st.last_script) await Detail.loadScript(st.last_script);
      if (S.recording.loaded) Steps.replan(true);
    } catch (e) { fail(e, '初期化に失敗しました'); }
  }
  init();
})();
{% endraw %}
</script>
</body>
</html>
'''


# ===== former reqrec/cli.py: argparse CLI (reqrec import / inspect / generate / gui / record) =====
# argparse CLI.  Contract: DESIGN.md §9.  Recording itself is done in the GUI (``reqrec gui``).
#
# Sub-commands::
#
#     reqrec import   INPUT... -o rec.json
#     reqrec inspect  INPUT... [filter options] [override options] [--json]
#     reqrec generate INPUT... -o scrape.py [filter options] [override options] [codegen options]
#                     [--dump-plan plan.json] [--run]
#     reqrec gui      [--host 127.0.0.1] [--port 8765] [--workdir DIR] [--no-browser]
#     reqrec browser  build | status   (prebuild the recording browser next to reqrec.py; Windows)
#
# ``python -m reqrec ...`` is the same.  Several ``INPUT`` files (one HAR per browser tab, say) are merged by time stamp (DESIGN.md §13.5).
# Override options (§13.1): ``--exclude-flow`` / ``--include-flow`` / ``--final-flow`` take the flow
# ids ``inspect`` shows (``f0008``, comma separated / repeatable); ``--exclude-step N`` /
# ``--final-step N`` take step numbers of the plan built *without* overrides and are resolved to flow
# ids by building the plan once more.
#
# All user-facing messages are Japanese (the end user is Japanese); identifiers and comments are
# English.  Exit codes: ``0`` success, ``1`` runtime error (missing / unsupported input file, ...),
# ``2`` usage error.
#
# This module only parses arguments, maps them onto ``PlanOptions`` / ``GenOptions`` and formats
# results.  The pipeline functions are bound to module-level names (``load_recording``,
# ``load_recordings``, ``build_plan``, ``generate``) so tests can monkeypatch them.


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

#: Defaults are read from the dataclasses so the CLI never drifts from ``core.py``.
_PLAN_DEFAULTS = PlanOptions()
_GEN_DEFAULTS = GenOptions()

HTML_PARSERS = ("html.parser", "lxml")

#: How many example URLs ``inspect`` shows per drop reason.
INSPECT_EXAMPLES_PER_REASON = 5
#: Column truncation widths for the ``inspect`` table.
INSPECT_URL_WIDTH = 72
INSPECT_EXTRACT_WIDTH = 60


# --------------------------------------------------------------------------- output helpers

def _info(message: str) -> None:
    """Informational message (never part of machine-readable output) -> stderr."""
    print(message, file=sys.stderr, flush=True)


def _error(message: str) -> None:
    print(f"エラー: {message}", file=sys.stderr, flush=True)


def _display_width(text: str) -> int:
    """Terminal column width of ``text`` (CJK characters take two columns)."""
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _display_width(text))


def _format_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    """Plain-text table (two-space column gap, CJK-aware padding)."""
    columns = len(headers)
    widths = [_display_width(h) for h in headers]
    for row in rows:
        for i in range(columns):
            widths[i] = max(widths[i], _display_width(row[i]))
    lines = ["  ".join(_pad(h, widths[i]) for i, h in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(_pad(row[i], widths[i]) for i in range(columns)).rstrip())
    return lines


# --------------------------------------------------------------------------- argparse plumbing (Japanese)

_ARGPARSE_TRANSLATIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^the following arguments are required: (.*)$"), "次の引数が必要です: {0}"),
    (re.compile(r"^unrecognized arguments: (.*)$"), "不明な引数です: {0}"),
    (re.compile(r"^argument (.+?): invalid choice: (.*) \(choose from (.*)\)$"),
     "引数 {0}: 無効な選択です: {1}（選択肢: {2}）"),
    (re.compile(r"^argument (.+?): invalid (\S+) value: (.*)$"), "引数 {0}: {1} として解釈できない値です: {2}"),
    (re.compile(r"^argument (.+?): expected one argument$"), "引数 {0}: 値が 1 つ必要です"),
    (re.compile(r"^argument (.+?): expected at least one argument$"), "引数 {0}: 値が 1 つ以上必要です"),
    (re.compile(r"^argument (.+?): expected (\d+) arguments?$"), "引数 {0}: 値が {1} 個必要です"),
    (re.compile(r"^argument (.+?): not allowed with argument (.*)$"), "引数 {0}: {1} と同時には指定できません"),
    (re.compile(r"^argument (.+?): ignored explicit argument (.*)$"), "引数 {0}: 余分な値が指定されました: {1}"),
    (re.compile(r"^ambiguous option: (.*)$"), "オプションが曖昧です: {0}"),
    # ``argparse.ArgumentTypeError`` raised by our own converters: the text is already Japanese.
    (re.compile(r"^argument (.+?): (.*)$"), "引数 {0}: {1}"),
]


def translate_argparse_message(message: str) -> str:
    """Translate argparse's English error text to Japanese where we know the phrase."""
    for pattern, template in _ARGPARSE_TRANSLATIONS:
        m = pattern.match(message)
        if m:
            return template.format(*m.groups())
    return message


class _JapaneseHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """``usage:`` -> ``使い方:``; keeps description/epilog line breaks."""

    def add_usage(self, usage, actions, groups, prefix=None):  # type: ignore[override]
        if prefix is None:
            prefix = "使い方: "
        return super().add_usage(usage, actions, groups, prefix)


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser whose generated text (group titles, usage, errors) is Japanese.

    ``error`` still exits with ``SystemExit(2)`` like argparse does; ``main`` converts that into a
    return code so the function can be used from tests without catching ``SystemExit``.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", _JapaneseHelpFormatter)
        kwargs.setdefault("allow_abbrev", False)
        add_help = kwargs.pop("add_help", True)
        kwargs["add_help"] = False  # we add our own -h with Japanese help text
        super().__init__(*args, **kwargs)
        # Group titles are not reachable through the public API.
        self._positionals.title = "引数"
        self._optionals.title = "オプション"
        if add_help:
            self.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="このヘルプを表示して終了する")

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: エラー: {translate_argparse_message(message)}\n")


# --------------------------------------------------------------------------- value converters

def _int_value(text: str) -> int:
    try:
        return int(text, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"整数を指定してください: {text!r}") from None


def _float_value(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"数値を指定してください: {text!r}") from None
    if value != value or value in (float("inf"), float("-inf")):
        raise argparse.ArgumentTypeError(f"有限の数値を指定してください: {text!r}")
    return value


def _port(text: str) -> int:
    n = _int_value(text)
    if not 1 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"ポート番号は 1〜65535 の範囲で指定してください: {n}")
    return n


def _positive_int(text: str) -> int:
    n = _int_value(text)
    if n < 1:
        raise argparse.ArgumentTypeError(f"1 以上の整数を指定してください: {n}")
    return n


def _non_negative_float(text: str) -> float:
    value = _float_value(text)
    if value < 0:
        raise argparse.ArgumentTypeError(f"0 以上の数値を指定してください: {text}")
    return value


def _positive_float(text: str) -> float:
    value = _float_value(text)
    if value <= 0:
        raise argparse.ArgumentTypeError(f"0 より大きい数値を指定してください: {text}")
    return value


_CLI_FLOW_ID_RE = re.compile(r"^f?(\d+)$", re.I)
_FLOW_TOKEN_RE = re.compile(r"^[\w.\-]+$")


def cli_normalise_flow_id(text: Optional[str]) -> Optional[str]:
    """``"f0008"`` / ``"F8"`` / ``"8"`` -> ``"f0008"``.  Other non-empty tokens are returned as typed
    (they are checked against the recording later); an empty token gives ``None``."""
    token = str(text or "").strip()
    if not token:
        return None
    m = _CLI_FLOW_ID_RE.match(token)
    if m:
        return f"f{int(m.group(1)):04d}"
    return token


def split_flow_ids(values: Optional[Iterable[str]]) -> list[str]:
    """Repeated ``--exclude-flow`` values (each may be comma / semicolon / space separated) ->
    normalised, de-duplicated flow ids in order."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values or ():
        for item in re.split(r"[,;\s]+", str(value)):
            fid = cli_normalise_flow_id(item)
            if fid and fid not in seen:
                seen.add(fid)
                out.append(fid)
    return out


def _flow_id_list(text: str) -> str:
    """argparse type for repeatable flow-id options: validates every token, returns the raw text
    (``split_flow_ids`` flattens the repeated values later)."""
    ids = split_flow_ids([text])
    if not ids:
        raise argparse.ArgumentTypeError(f"フロー ID を指定してください（例: f0008）: {text!r}")
    for fid in ids:
        if not _FLOW_TOKEN_RE.match(fid):
            raise argparse.ArgumentTypeError(f"フロー ID として解釈できません: {fid!r}（例: f0008。inspect で確認できます）")
    return text


def _flow_id(text: str) -> str:
    ids = split_flow_ids([text])
    if len(ids) != 1 or not _FLOW_TOKEN_RE.match(ids[0]):
        raise argparse.ArgumentTypeError(f"フロー ID を 1 つ指定してください（例: f0008）: {text!r}")
    return ids[0]


def _step_numbers(text: str) -> list[int]:
    """argparse type for ``--exclude-step``: ``"2,3"`` -> ``[2, 3]`` (positive integers)."""
    out: list[int] = []
    for item in re.split(r"[,;\s]+", str(text)):
        if item:
            out.append(_positive_int(item))
    if not out:
        raise argparse.ArgumentTypeError(f"ステップ番号を指定してください（例: 3）: {text!r}")
    return out


def split_hosts(values: Optional[Iterable[str]]) -> list[str]:
    """``["a.com, B.com", "c.com"]`` -> ``["a.com", "b.com", "c.com"]`` (lower-case, de-duplicated).

    Accepts the repeated ``--include-host`` values; each may itself be a comma / semicolon /
    whitespace separated list.  ``None`` / empty -> ``[]``.
    """
    out: list[str] = []
    seen: set[str] = set()
    for value in values or ():
        for item in re.split(r"[,;\s]+", str(value)):
            host = item.strip().lower().rstrip(".")
            if host and host not in seen:
                seen.add(host)
                out.append(host)
    return out


# --------------------------------------------------------------------------- option groups -> dataclasses


def add_filter_options(parser: argparse.ArgumentParser) -> None:
    """Add the filter / analysis options shared by ``inspect`` and ``generate``."""
    group = parser.add_argument_group(
        "フィルタ / 解析オプション",
        "記録のどのリクエストをステップとして残すか、どう解析するかを調整します。",
    )
    group.add_argument(
        "--include-host", action="append", metavar="HOST", default=None,
        help="このホスト（とそのサブドメイン）へのリクエストだけを残す。繰り返し指定・カンマ区切り可",
    )
    group.add_argument(
        "--exclude-host", action="append", metavar="HOST", default=None,
        help="このホスト（とそのサブドメイン）へのリクエストを除外する。繰り返し指定・カンマ区切り可",
    )
    group.add_argument("--keep-static", action="store_true", help="画像・CSS・JS・フォントなどの静的ファイルも残す")
    group.add_argument("--keep-trackers", action="store_true", help="アクセス解析・広告などのトラッカーへのリクエストも残す")
    group.add_argument("--keep-all", action="store_true", help="ノイズ除去をすべて無効にする（ホストの指定だけ適用）")
    group.add_argument("--no-collapse-redirects", action="store_true", help="リダイレクトの連鎖を 1 ステップにまとめない")
    group.add_argument("--no-loops", action="store_true", help="ページ送りなどの繰り返しをループとして折りたたまない")
    group.add_argument(
        "--min-value-length", type=_positive_int, metavar="N", default=_PLAN_DEFAULTS.min_value_length,
        help=f"依存関係の検出対象にする値の最小文字数（既定: {_PLAN_DEFAULTS.min_value_length}）",
    )
    group.add_argument(
        "--max-steps", type=_positive_int, metavar="N", default=None,
        help="ステップ数の上限（巨大な記録の安全弁。超えた分は警告付きで切り捨て）",
    )
    group.add_argument(
        "--redact", action="store_true",
        help="パスワード等をスクリプトに書き込まず、実行時に環境変数から読む（既定は記録した値をそのまま書き込む）",
    )
    group.add_argument(
        "--no-detect-auth", action="store_true",
        help="NTLM / Negotiate / Basic / Digest 認証のやり取り（401 → Authorization）を検出して session.auth にまとめる処理を行わない",
    )

    manual = parser.add_argument_group(
        "手動の取捨選択",
        "inspect が表示するフロー ID（f0008 など。カンマ区切り・繰り返し指定可）やステップ番号で、"
        "除外する / 必ず残す / 結果にするリクエストを指定します。",
    )
    manual.add_argument(
        "--exclude-flow", action="append", metavar="ID", default=None, type=_flow_id_list,
        help="このフローを必ず除外する（除外理由: excluded by user）",
    )
    manual.add_argument(
        "--include-flow", action="append", metavar="ID", default=None, type=_flow_id_list,
        help="ノイズ判定に関わらずこのフローをステップとして残す（レスポンスが記録されていないものは残せない）",
    )
    manual.add_argument(
        "--final-flow", metavar="ID", default=None, type=_flow_id,
        help="このフローを含むステップの結果を、生成コードの main() が最後に表示する（既定: 最後のステップ）",
    )
    manual.add_argument(
        "--exclude-step", action="append", metavar="N", default=None, type=_step_numbers,
        help="inspect（オーバーライド指定なし）で表示されたステップ番号 N のリクエストを除外する。カンマ区切り・繰り返し指定可",
    )
    manual.add_argument(
        "--final-step", metavar="N", default=None, type=_positive_int,
        help="inspect（オーバーライド指定なし）で表示されたステップ番号 N の結果を表示する（--final-flow のステップ番号版）",
    )


def plan_options_from_args(args: argparse.Namespace) -> PlanOptions:
    """Map the parsed filter options onto a ``PlanOptions`` (missing attributes -> defaults).

    ``--exclude-step`` / ``--final-step`` are *not* mapped here (they need the recording); see
    :func:`resolve_overrides`.
    """
    include = split_hosts(getattr(args, "include_host", None))
    final_flow = getattr(args, "final_flow", None)
    return PlanOptions(
        include_hosts=include or None,
        exclude_hosts=split_hosts(getattr(args, "exclude_host", None)),
        keep_static=bool(getattr(args, "keep_static", False)),
        keep_trackers=bool(getattr(args, "keep_trackers", False)),
        keep_all=bool(getattr(args, "keep_all", False)),
        collapse_redirects=not getattr(args, "no_collapse_redirects", False),
        detect_loops=not getattr(args, "no_loops", False),
        redact_secrets=bool(getattr(args, "redact", False)),
        min_value_length=getattr(args, "min_value_length", None) or _PLAN_DEFAULTS.min_value_length,
        max_steps=getattr(args, "max_steps", None),
        exclude_flow_ids=split_flow_ids(getattr(args, "exclude_flow", None)),
        include_flow_ids=split_flow_ids(getattr(args, "include_flow", None)),
        final_flow_id=cli_normalise_flow_id(final_flow) if final_flow else None,
        detect_auth=not getattr(args, "no_detect_auth", False),
    )


def _flatten_steps(values: Any) -> list[int]:
    """``--exclude-step`` values (``[[2, 3], [5]]`` or ``[2]``) -> sorted unique step numbers."""
    out: set[int] = set()
    for value in values or ():
        if isinstance(value, (list, tuple)):
            out.update(int(v) for v in value)
        elif value is not None:
            out.add(int(value))
    return sorted(out)


def resolve_overrides(recording: Recording, opts: PlanOptions, exclude_steps: Any = None,
                      final_step: Optional[int] = None) -> PlanOptions:
    """Check the flow-id overrides against the recording and turn step numbers into flow ids.

    Step numbers refer to the plan built **without** overrides (what a plain ``inspect`` shows),
    so when any is given the plan is built once more here and the step's ``source_flow_ids`` are
    used.  Raises ``ValueError`` (Japanese) for unknown ids, out-of-range steps and contradictions.
    """
    known = {flow.id for flow in recording.flows}

    def check(ids: Iterable[str], flag: str) -> None:
        for fid in ids:
            if fid not in known:
                raise ValueError(f"{flag} {fid}: 記録にそのフロー ID はありません（inspect でフロー ID を確認してください）")

    check(opts.exclude_flow_ids, "--exclude-flow")
    check(opts.include_flow_ids, "--include-flow")
    if opts.final_flow_id:
        check([opts.final_flow_id], "--final-flow")

    exclude_ids = list(opts.exclude_flow_ids)
    final_id = opts.final_flow_id or None
    steps = _flatten_steps(exclude_steps)
    if steps or final_step is not None:
        base = replace(opts, exclude_flow_ids=[], include_flow_ids=[], final_flow_id=None)
        base_plan: Plan = build_plan(recording, base)
        by_index = {step.index: step for step in base_plan.steps}

        def lookup(n: int, flag: str) -> Step:
            step = by_index.get(n)
            if step is None:
                if not by_index:
                    raise ValueError(f"{flag} {n}: ステップが 1 つもありません（inspect でフィルタ設定を確認してください）")
                raise ValueError(
                    f"{flag} {n}: ステップ番号は {min(by_index)}〜{max(by_index)} の範囲で指定してください（inspect で確認できます）"
                )
            return step

        for n in steps:
            for fid in lookup(n, "--exclude-step").source_flow_ids:
                if fid not in exclude_ids:
                    exclude_ids.append(fid)
        if final_step is not None:
            step = lookup(final_step, "--final-step")
            if not step.source_flow_ids:
                raise ValueError(f"--final-step {final_step}: このステップにはフロー ID がありません")
            if final_id and final_id not in step.source_flow_ids:
                raise ValueError("--final-step と --final-flow が別のステップを指しています。どちらか一方だけ指定してください")
            final_id = step.source_flow_ids[-1]

    overlap = sorted(set(exclude_ids) & set(opts.include_flow_ids))
    if overlap:
        raise ValueError(f"同じフローを --include-flow と --exclude-flow の両方に指定しています: {', '.join(overlap)}")
    if final_id and final_id in exclude_ids:
        raise ValueError(f"結果にするフロー {final_id} が除外の対象になっています（--exclude-flow / --exclude-step を確認してください）")
    return replace(opts, exclude_flow_ids=exclude_ids, final_flow_id=final_id)


def add_generate_options(parser: argparse.ArgumentParser) -> None:
    """Add the code-generation options of ``generate``."""
    group = parser.add_argument_group("コード生成オプション")
    group.add_argument(
        "--html-parser", choices=HTML_PARSERS, default=_GEN_DEFAULTS.html_parser, metavar="PARSER",
        help=f"生成コードが BeautifulSoup に渡すパーサー: {' / '.join(HTML_PARSERS)}（既定: {_GEN_DEFAULTS.html_parser}）",
    )
    group.add_argument("--no-comments", action="store_true", help="生成コードに説明コメントを入れない")
    group.add_argument(
        "--delay", type=_non_negative_float, metavar="SEC", default=_GEN_DEFAULTS.delay,
        help=f"ステップ間の待ち時間（秒）。サーバーへの負荷を抑えるため（既定: {_GEN_DEFAULTS.delay:g}）",
    )
    group.add_argument(
        "--timeout", type=_positive_float, metavar="SEC", default=_GEN_DEFAULTS.timeout,
        help=f"各リクエストのタイムアウト（秒）（既定: {_GEN_DEFAULTS.timeout:g}）",
    )
    group.add_argument(
        "--strict-status", action="store_true",
        help="記録時と同じステータスコードでなければエラーにする（既定は 4xx/5xx のみエラー）",
    )


def gen_options_from_args(args: argparse.Namespace) -> GenOptions:
    """Map the parsed code-generation options onto a ``GenOptions``."""
    return GenOptions(
        html_parser=getattr(args, "html_parser", None) or _GEN_DEFAULTS.html_parser,
        comments=not getattr(args, "no_comments", False),
        delay=getattr(args, "delay", _GEN_DEFAULTS.delay),
        timeout=getattr(args, "timeout", _GEN_DEFAULTS.timeout),
        print_final=_GEN_DEFAULTS.print_final,
        strict_status=bool(getattr(args, "strict_status", False)),
    )


# --------------------------------------------------------------------------- parser

_DESCRIPTION = """\
reqrec - Web サイトの HTTP 通信を記録して、同じ操作を再現する Python スクレイピングスクリプトを生成します。
画面の要素をつかむのではなく、ブラウザが実際に送受信した HTTP リクエスト/レスポンスを元に
「HTTP レベルのマクロ記録」を行います。"""

_EPILOG = """\
ふだんは引数なしで起動します:  python reqrec.py   （GUI が開きます。記録・スクリプト作成・実行をボタンで行えます）

コマンドで使う場合の典型的な流れ:
  1. 記録する   python reqrec.py record --out rec.json --url http://kanri/   （記録用ブラウザを閉じると保存）
  2. 確認する   python reqrec.py inspect rec.json
  3. 生成する   python reqrec.py generate rec.json -o scrape.py
  4. 実行する   python scrape.py

IE の F12 で保存した HAR も使えます。別タブの HAR は複数指定して結合できます:
  python reqrec.py generate tab1.har tab2.har -o scrape.py
手動で取捨選択:  python reqrec.py generate rec.json -o scrape.py --exclude-flow f0012 --final-step 3

各コマンドの詳細: python reqrec.py <コマンド> -h"""


_INPUT_HELP = ("入力ファイル（.har / .json）。複数指定すると時刻順に結合して 1 つの記録として扱います"
               "（別タブで開いた画面の HAR など）")


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level parser with its sub-commands (import / inspect / generate / gui / record)."""
    parser = _ArgumentParser(prog="reqrec", description=_DESCRIPTION, epilog=_EPILOG)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}", help="バージョンを表示して終了する")

    subparsers = parser.add_subparsers(dest="command", title="コマンド")

    # -- import -----------------------------------------------------------------------------------
    p_import = subparsers.add_parser(
        "import",
        help="HAR を reqrec の記録形式（JSON）に変換する",
        description="開発者ツールの HAR（.har）または reqrec の記録（.json）を\n"
                    "読み込み、reqrec の記録形式（JSON）で保存します。inspect / generate は HAR を直接読めるので、\n"
                    "変換は必須ではありません（記録を 1 つの形式でまとめて保管したい場合などに使います）。",
    )
    p_import.add_argument("input", metavar="INPUT", nargs="+", help=_INPUT_HELP)
    p_import.add_argument("-o", "--out", required=True, metavar="FILE", help="保存先（JSON）")
    p_import.set_defaults(func=cmd_import)

    # -- inspect ----------------------------------------------------------------------------------
    p_inspect = subparsers.add_parser(
        "inspect",
        help="記録を解析し、どのリクエストがステップとして残り、どれが捨てられたかを表示する",
        description="記録を解析して、生成されるステップの一覧（メソッド・ステータス・URL・抽出される変数・ループ）と、\n"
                    "ノイズとして捨てられたリクエストを理由ごとに表示します。generate の前に必ず確認してください。",
    )
    p_inspect.add_argument("input", metavar="INPUT", nargs="+", help=_INPUT_HELP)
    add_filter_options(p_inspect)
    p_inspect.add_argument("--json", action="store_true", help="人が読む表の代わりに JSON で出力する")
    p_inspect.set_defaults(func=cmd_inspect)

    # -- generate ---------------------------------------------------------------------------------
    p_generate = subparsers.add_parser(
        "generate",
        help="記録から Python スクレイピングスクリプト（requests + BeautifulSoup）を生成する",
        description="記録を解析し、同じ HTTP の会話を再現する単体で動く Python スクリプトを生成します。\n"
                    "解析結果の要約と警告は標準エラー出力に、スクリプトは -o で指定したファイル（- で標準出力）に書きます。",
    )
    p_generate.add_argument("input", metavar="INPUT", nargs="+", help=_INPUT_HELP)
    p_generate.add_argument("-o", "--out", required=True, metavar="FILE", help="生成するスクリプトのパス（- で標準出力）")
    add_filter_options(p_generate)
    add_generate_options(p_generate)
    p_generate.add_argument("--dump-plan", metavar="FILE", default=None,
                            help="解析結果（Plan）を JSON で書き出す（デバッグ・検証用）")
    p_generate.add_argument("--run", action="store_true",
                            help="生成したスクリプトをすぐに実行する（同じ Python で実行し、その終了コードを返す）")
    p_generate.set_defaults(func=cmd_generate)

    # -- gui --------------------------------------------------------------------------------------
    p_gui = subparsers.add_parser(
        "gui",
        help="ブラウザで操作する GUI（Flask）を起動する。記録・読み込み・ステップ選択・コード生成・実行をボタンで行える",
        description="ローカルの Web GUI（Flask）を起動し、既定ではブラウザを自動で開きます。\n"
                    "記録の開始/停止、HAR 等の読み込み（複数可）、ステップの取捨選択、コード生成、生成コードの実行を\n"
                    "コードを書かずに行えます。",
    )
    p_gui.add_argument("--host", default="127.0.0.1", metavar="HOST", help="待ち受けアドレス（既定: 127.0.0.1。他の PC から使わせるときは 0.0.0.0 などにし、"
                            "環境変数 REQREC_GUI_PASSWORD でパスワードを設定する）")
    p_gui.add_argument("--port", type=_port, default=8765, metavar="PORT", help="待ち受けポート（既定: 8765）")
    p_gui.add_argument("--workdir", default="reqrec_work", metavar="DIR",
                       help="記録ファイルや生成スクリプトを保存する作業フォルダ（既定: ./reqrec_work）")
    p_gui.add_argument("--no-browser", action="store_true", help="ブラウザを自動で開かない")
    p_gui.set_defaults(func=cmd_gui)

    # -- record ---------------------------------------------------------------------------------
    p_record = subparsers.add_parser(
        "record",
        help="記録用ブラウザ（IE エンジン・Windows）を開いて、操作した http:// の通信を記録する（GUI が使います）",
        description="記録用ブラウザ（Edge の IE モードと同じエンジン）を開き、閉じるまでに開いた http:// のページの通信を\n"
                    "記録して --out のファイル（reqrec の記録形式）に保存します。GUI の [記録をはじめる] はこのコマンドを使います。\n"
                    "Windows の設定・レジストリ・証明書は変更しません（中継はこの記録用ブラウザだけに設定します）。",
    )
    p_record.add_argument("--out", required=True, metavar="FILE", help="記録の保存先（JSON）")
    p_record.add_argument("--url", default=None, metavar="URL", help="最初に開くアドレス（省略すると空白のページ）")
    p_record.add_argument("--title", default=BROWSER_TITLE, metavar="TEXT", help="窓のタイトル（「— 記録中」が付きます）")
    p_record.add_argument("--emulation", default="default", choices=list(EMULATION_MODES),
                          help="表示モード（既定: default = IE7 互換表示。--browser ie のときだけ）")
    p_record.add_argument("--browser", default="ie", choices=list(RECORD_BROWSERS),
                          help="記録に使うブラウザ（既定: ie = 記録用ブラウザ・IE モードと同じエンジン / edge = Microsoft Edge を"
                               "記録専用のプロファイルで開く）")
    p_record.add_argument("--log", default=None, metavar="FILE", help="記録用ブラウザのログの保存先")
    p_record.add_argument("--bypass", default="", metavar="LIST", help=argparse.SUPPRESS)
    p_record.add_argument("--control", default="none", choices=("none", "stdin"),
                          help="stdin: 標準入力の stop（または入力の終わり）で記録を終える（GUI 用）")
    p_record.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    p_record.add_argument("--seconds", type=int, default=30, help=argparse.SUPPRESS)
    p_record.add_argument("--functions", default=None, help=argparse.SUPPRESS)
    p_record.add_argument("--headless", action="store_true", help=argparse.SUPPRESS)
    p_record.set_defaults(func=cmd_record)

    return parser


# --------------------------------------------------------------------------- shared file helpers

def _check_output_path(path: str, what: str) -> None:
    """Fail early (``ValueError``) when an output path can not be written to."""
    if os.path.isdir(path):
        raise ValueError(f"{what}にディレクトリは指定できません: {path}")
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        raise ValueError(f"{what}のディレクトリがありません: {parent}")


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _describe_source(meta: dict[str, Any]) -> str:
    """``"har, WebInspector/537.36"`` style one-liner from ``Recording.meta`` (may be empty).

    A merged recording (``{"source": "merged", "sources": [...]}``) lists every part.
    """
    if not isinstance(meta, dict):
        return ""
    parts = []
    source = meta.get("source")
    if isinstance(source, dict):  # Plan.meta["source"] holds the recording meta
        return _describe_source(source)
    if source == "merged" and isinstance(meta.get("sources"), list):
        inner = [_describe_source(m) for m in meta["sources"] if isinstance(m, dict)]
        inner = [d for d in inner if d]
        label = f"結合 {len(meta['sources'])} 件"
        return label + (f": {' / '.join(inner)}" if inner else "")
    if source:
        parts.append(str(source))
    creator = meta.get("creator")
    if creator:
        parts.append(str(creator))
    return ", ".join(parts)


def load_inputs(paths: Sequence[str]) -> Recording:
    """Load the ``INPUT`` arguments: one file -> ``load_recording`` (unchanged meta), several ->
    ``load_recordings`` (merged by time stamp, re-numbered flow ids; DESIGN.md §13.5)."""
    unique: list[str] = []
    for path in paths or ():
        if path not in unique:
            unique.append(path)
    if not unique:
        raise ValueError("入力ファイルが指定されていません")
    if len(unique) == 1:
        return load_recording(unique[0])
    return load_recordings(unique)


def _input_label(paths: Sequence[str]) -> str:
    return ", ".join(str(p) for p in paths)


# --------------------------------------------------------------------------- record / gui / import

def cmd_record(args: argparse.Namespace) -> int:
    """``reqrec record``: the recording browser (the GUI starts it as a child process)."""
    code = run_recorder(
        args.out, url=args.url, title=args.title, emulation=args.emulation, log_path=args.log, bypass=args.bypass,
        control=args.control, selftest=args.selftest, seconds=args.seconds, headless=args.headless,
        functions=[f for f in (args.functions or "").split(",") if f.strip()] or None, browser=args.browser,
    )
    if not args.headless and is_windows() and args.browser == "ie":
        # The IE engine's COM objects must not be torn down by the interpreter's exit: the
        # recording is written already, so the process ends here.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(code)
    return code


def cmd_gui(args: argparse.Namespace) -> int:
    """``reqrec gui``: start the Flask GUI (gui section)."""
    return int(run_gui(host=args.host, port=args.port, workdir=args.workdir, open_browser=not args.no_browser))


def cmd_import(args: argparse.Namespace) -> int:
    """``reqrec import``: any supported input -> reqrec recording JSON."""
    _check_output_path(args.out, "保存先")
    inputs = list(args.input)
    recording: Recording = load_inputs(inputs)
    recording.save(args.out)
    source = _describe_source(recording.meta)
    detail = f"（{source}）" if source else ""
    merged = f"{len(inputs)} ファイルを結合して " if len(inputs) > 1 else ""
    print(f"{merged}{len(recording.flows)} 件のフローを取り込みました{detail} → {args.out}")
    return EXIT_OK


# --------------------------------------------------------------------------- inspect

def _json_path_label(path: Optional[list[Any]]) -> str:
    """``["data", "items", 0, "id"]`` -> ``data.items[0].id``."""
    if not path:
        return ""
    out = ""
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += ("." if out else "") + str(part)
    return out


def _extractor_label(e: dict[str, Any]) -> str:
    """``csrf_token←html_input[_token]`` from an extractor entry of the inspect report."""
    kind = e.get("kind") or "?"
    path, row = list(e.get("path") or []), e.get("row")
    if kind == "json" and e.get("row_key") and isinstance(row, int) and 0 <= row < len(path):
        # one row of a list the user chose, found by its label: ``d[name=…].code``
        detail = (_json_path_label(path[:row]) + f"[{_json_path_label(e['row_key'])}=…]"
                  + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in path[row + 1:]))
    elif kind == "json":
        detail = _json_path_label(e.get("path"))
    elif e.get("name"):
        detail = str(e["name"])
    elif e.get("selector"):
        detail = str(e["selector"]) + (f"@{e['attr']}" if e.get("attr") else "")
    elif e.get("pattern"):
        detail = truncate(str(e["pattern"]), 24)
    else:
        detail = ""
    return f"{e.get('var')}←{kind}" + (f"[{detail}]" if detail else "")


def _loop_label(loop: dict[str, Any]) -> str:
    """``ループ page=1..3 (3回)`` from a loop entry of the inspect report."""
    count = int(loop.get("count") or 0)
    rng = loop.get("numeric_range")
    if rng:
        return f"ループ {loop['var']}={rng[0]}..{rng[1]} ({count}回)"
    values = list(loop.get("values") or [])
    preview = ", ".join(truncate(str(v), 12) for v in values[:3])
    if count > 3:
        preview += ", …"
    return f"ループ {loop['var']} ({count}回: {preview})"


def _url_label(step: Step) -> str:
    """Display form of the step URL; non-literal pieces are shown as ``{expr}``."""
    literal = step.literal_url()
    if literal is not None:
        return literal
    return "".join(ref.value if ref.is_literal else "{" + ref.value + "}" for ref in step.url)


def _status_chain(step: Step, flows_by_id: dict[str, Flow]) -> list[int]:
    """Recorded statuses of a collapsed redirect chain, e.g. ``[302, 200]`` (empty for loops)."""
    if step.loop is not None or len(step.source_flow_ids) < 2:
        return []
    statuses: list[int] = []
    for flow_id in step.source_flow_ids:
        flow = flows_by_id.get(flow_id)
        if flow is not None and flow.response is not None:
            statuses.append(flow.response.status)
    return statuses if len(statuses) > 1 else []


def _flow_ids_label(ids: Sequence[str]) -> str:
    """``["f0008", "f0009"]`` -> ``"f0008+f0009"``; long loops -> ``"f0011+…+f0015 (5)"``."""
    ids = [str(i) for i in ids]
    if not ids:
        return "-"
    if len(ids) <= 3:
        return "+".join(ids)
    return f"{ids[0]}+…+{ids[-1]} ({len(ids)})"


def _auth_label(auth: Optional[dict[str, Any]], constants: Sequence[dict[str, Any]] = ()) -> Optional[str]:
    """``認証: NTLM (記録時のユーザー: EXAMPLE\\taro) → 生成コードは session.auth を設定します``."""
    if not auth:
        return None
    kind = str(auth.get("kind") or "").lower()
    label = {"ntlm": "NTLM", "negotiate": "Negotiate", "basic": "Basic", "digest": "Digest"}.get(kind, kind or "?")
    text = f"認証: {label}"
    if auth.get("username"):
        text += f" (記録時のユーザー: {auth['username']})"
    text += " → 生成コードは session.auth を設定します"
    pw_const = auth.get("password_const")
    if pw_const:
        for c in constants:
            if c.get("name") == pw_const and c.get("secret") and c.get("env_var"):
                text += f"（パスワードは環境変数 {c['env_var']}）"
                break
    if kind in ("ntlm", "negotiate"):
        text += "（追加パッケージが必要: python -m pip install requests_negotiate_sspi または requests_ntlm）"
    return text


def _constant_display(value: Any) -> Any:
    """A constant's value for reports: the text of a legacy-charset (bytes) value, decoded as cp932 /
    EUC-JP when possible, else its percent-encoded spelling."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        for enc in ("cp932", "euc_jp"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return quote_from_bytes(raw, safe="")
    return value


def build_inspect_report(recording: Recording, plan: Plan, source: str = "",
                         inputs: Optional[Sequence[str]] = None) -> dict[str, Any]:
    """Machine-readable summary of a plan (what ``inspect --json`` prints).

    Secret constant values and cookie values are deliberately *not* included.  ``inputs`` lists
    the input files (``source`` is their display form); every step carries its ``source_flow_ids``
    and a ``flow_ids`` label (``"f0008+f0009"``) so users can refer to flows in the override options.
    """
    flows_by_id = {flow.id: flow for flow in recording.flows}
    flows_kept = sum(len(step.source_flow_ids) for step in plan.steps)
    if not flows_kept and plan.meta.get("flows_kept") is not None:
        flows_kept = int(plan.meta["flows_kept"])

    steps: list[dict[str, Any]] = []
    for step in plan.steps:
        loop = None
        if step.loop is not None:
            loop = {
                "var": step.loop.var,
                "count": len(step.loop.values),
                "values": [_constant_display(v) for v in step.loop.values],
                "numeric_range": list(step.loop.numeric_range) if step.loop.numeric_range is not None else None,
            }
        steps.append({
            "index": step.index,
            "func_name": step.func_name,
            "method": step.method,
            "status": step.expected_status,
            "status_chain": _status_chain(step, flows_by_id),
            "url": _url_label(step),
            "params": [name for name, _ref in step.params],
            "body_kind": step.body_kind,
            "response_kind": step.response_kind,
            "extractors": [
                {
                    "var": e.var,
                    "kind": e.kind,
                    "name": e.name,
                    "path": e.path,
                    "row": e.row,
                    "row_key": e.row_key,
                    "selector": e.selector,
                    "attr": e.attr,
                    "pattern": e.pattern,
                    "sample": e.sample,
                    "note": e.note,
                }
                for e in step.extractors
            ],
            "loop": loop,
            "source_flow_ids": list(step.source_flow_ids),
            "flow_ids": _flow_ids_label(step.source_flow_ids),
            "is_final": plan.final_step_index is not None and step.index == plan.final_step_index,
            "comment": step.comment,
        })

    by_reason: dict[str, list[Dropped]] = {}
    for dropped in plan.dropped:
        by_reason.setdefault(dropped.reason, []).append(dropped)
    dropped_by_reason = [
        {
            "reason": reason,
            "count": len(items),
            "examples": [d.url for d in items[:INSPECT_EXAMPLES_PER_REASON]],
            "example_ids": [d.flow_id for d in items[:INSPECT_EXAMPLES_PER_REASON]],
        }
        for reason, items in sorted(by_reason.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ]

    constants = [
        {
            "name": c.name,
            "secret": bool(c.secret),
            "env_var": c.env_var,
            # passwords are never shown (the script holds them as the user decided)
            "value": None if c.secret or getattr(c, "sensitive", False) else _constant_display(c.value),
            "comment": c.comment,
            "kind": getattr(c, "kind", "shared"),
            "sensitive": bool(getattr(c, "sensitive", False)),
        }
        for c in plan.constants
    ]

    return {
        "input": source,
        "inputs": [str(p) for p in inputs] if inputs is not None else ([source] if source else []),
        "source": _describe_source(recording.meta),
        "auth": to_plain(plan.auth) if plan.auth is not None else None,
        "final_step_index": plan.final_step_index,
        "flows_total": len(recording.flows),
        "flows_kept": flows_kept,
        "steps_kept": len(plan.steps),
        "dropped": len(plan.dropped),
        "steps": steps,
        "dropped_by_reason": dropped_by_reason,
        "dropped_flows": [
            {"flow_id": d.flow_id, "method": d.method, "url": d.url, "reason": d.reason} for d in plan.dropped
        ],
        "constants": constants,
        "env_vars": sorted({c.env_var for c in plan.constants if c.secret and c.env_var}),
        "initial_cookies": [{"name": c.name, "domain": c.domain, "path": c.path} for c in plan.initial_cookies],
        "base_headers": [[name, value] for name, value in plan.base_headers],
        "warnings": list(plan.warnings),
    }


def format_inspect_report(report: dict[str, Any]) -> str:
    """Human-readable rendering of ``build_inspect_report``'s output."""
    lines: list[str] = []
    header = f"入力: {report.get('input') or '-'}"
    if report.get("source"):
        header += f"  ({report['source']})"
    lines.append(header)
    lines.append(
        f"フロー合計 {report['flows_total']} 件 / 採用 {report['flows_kept']} 件 → "
        f"ステップ {report['steps_kept']} 件 / 除外 {report['dropped']} 件"
    )
    steps = report["steps"]
    auth_line = _auth_label(report.get("auth"), report.get("constants") or [])
    if auth_line:
        lines.append(auth_line)
    final_index = report.get("final_step_index")
    if final_index is not None:
        final_step = next((s for s in steps if s["index"] == final_index), None)
        detail = f" ({final_step['method']} {truncate(final_step['url'], INSPECT_URL_WIDTH)})" if final_step else ""
        lines.append(f"結果にするステップ: {final_index}{detail}")
    lines.append("")

    if steps:
        lines.append(f"ステップ ({len(steps)} 件):")
        rows: list[list[str]] = []
        for step in steps:
            method = step["method"]
            if step["loop"]:
                method += f" ×{step['loop']['count']}"
            chain = step.get("status_chain") or []
            status = "→".join(str(s) for s in chain) if chain else str(step["status"])
            extras = [_extractor_label(e) for e in step["extractors"]]
            if step["loop"]:
                extras.append(_loop_label(step["loop"]))
            if step.get("is_final"):
                extras.insert(0, "★ 結果として表示")
            # One extractor / loop per line: the first shares the step row, the rest get
            # continuation rows so nothing is hidden behind a truncation.
            rows.append([
                f"{step['index']:02d}",
                step.get("flow_ids") or _flow_ids_label(step.get("source_flow_ids") or []),
                method,
                status,
                truncate(step["url"], INSPECT_URL_WIDTH),
                truncate(extras[0], INSPECT_EXTRACT_WIDTH) if extras else "-",
            ])
            for extra in extras[1:]:
                rows.append(["", "", "", "", "", truncate(extra, INSPECT_EXTRACT_WIDTH)])
        lines.extend(_format_table(["#", "FLOW", "METHOD", "STATUS", "URL", "抽出する変数 / ループ"], rows))
        lines.append("  （FLOW はフロー ID。--exclude-flow / --include-flow / --final-flow で指定できます）")
    else:
        lines.append("ステップ: なし（残ったリクエストがありません。--include-host や --keep-all などのフィルタオプションを確認してください）")
    lines.append("")

    dropped_groups = report["dropped_by_reason"]
    if dropped_groups:
        lines.append(f"除外されたリクエスト ({report['dropped']} 件):")
        for group in dropped_groups:
            lines.append(f"  {group['reason']} — {group['count']} 件")
            ids = list(group.get("example_ids") or [])
            for i, url in enumerate(group["examples"]):
                fid = ids[i] if i < len(ids) else ""
                lines.append(f"      {fid + '  ' if fid else ''}{truncate(url, 100)}")
            if group["count"] > len(group["examples"]):
                lines.append(f"      … 他 {group['count'] - len(group['examples'])} 件（--json で全件表示）")
    else:
        lines.append("除外されたリクエスト: なし")
    lines.append("")

    constants = report.get("constants") or []
    if constants:
        lines.append(f"定数 ({len(constants)} 件):")
        for c in constants:
            label = "入力値 " if c.get("kind") == "input" else ""
            if c["secret"]:
                env = c["env_var"] or "(環境変数名なし)"
                lines.append(f"  {label}{c['name']}  ← 環境変数 {env}（秘密情報: 実行前に設定してください）")
            elif c.get("sensitive"):
                lines.append(f"  {label}{c['name']} = （パスワードなどのため表示しません）")
            else:
                lines.append(f"  {label}{c['name']} = {truncate(repr(c['value']), 60)}")
        lines.append("")

    cookies = report.get("initial_cookies") or []
    if cookies:
        names = ", ".join(f"{c['name']}@{c['domain']}" for c in cookies[:8])
        if len(cookies) > 8:
            names += ", …"
        lines.append(f"記録開始前からブラウザにあった Cookie ({len(cookies)} 件): {names}")
        lines.append("  （値は生成コードに埋め込まれます。期限切れになったら記録し直してください）")
        lines.append("")

    warnings = report.get("warnings") or []
    if warnings:
        lines.append(f"警告 ({len(warnings)} 件):")
        for w in warnings:
            lines.append(f"  - {w}")
    else:
        lines.append("警告: なし")
    return "\n".join(lines) + "\n"


def cmd_inspect(args: argparse.Namespace) -> int:
    """``reqrec inspect``: analyse and print what would be generated."""
    inputs = list(args.input)
    recording: Recording = load_inputs(inputs)
    opts = resolve_overrides(recording, plan_options_from_args(args),
                             getattr(args, "exclude_step", None), getattr(args, "final_step", None))
    plan: Plan = build_plan(recording, opts)
    report = build_inspect_report(recording, plan, source=_input_label(inputs), inputs=inputs)
    if args.json:
        sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
    else:
        sys.stdout.write(format_inspect_report(report))
    sys.stdout.flush()
    return EXIT_OK


# --------------------------------------------------------------------------- generate

def format_plan_summary(plan: Plan, flows_total: Optional[int] = None) -> str:
    """Short summary + warnings that ``generate`` prints to stderr."""
    if flows_total is None:
        flows_total = plan.meta.get("flows_total")
    total = f"フロー合計 {flows_total} 件 / " if flows_total is not None else ""
    loops = sum(1 for s in plan.steps if s.loop is not None)
    extracted = sum(len(s.extractors) for s in plan.steps)
    lines = [
        f"ステップ {len(plan.steps)} 件を生成します（{total}除外 {len(plan.dropped)} 件 / "
        f"抽出する変数 {extracted} 個 / ループ {loops} 個）"
    ]
    if plan.auth is not None:
        constants = [{"name": c.name, "secret": c.secret, "env_var": c.env_var} for c in plan.constants]
        auth_line = _auth_label(to_plain(plan.auth), constants)
        if auth_line:
            lines.append(auth_line)
    if plan.final_step_index is not None:
        final_step = next((s for s in plan.steps if s.index == plan.final_step_index), None)
        detail = f"（{final_step.method} {truncate(_url_label(final_step), INSPECT_URL_WIDTH)}）" if final_step else ""
        lines.append(f"結果にするステップ: {plan.final_step_index}{detail}")
    env_vars = sorted({c.env_var for c in plan.constants if c.secret and c.env_var})
    if env_vars:
        lines.append("秘密情報は環境変数から読み込みます。実行前に設定してください: " + ", ".join(env_vars))
    if plan.warnings:
        lines.append(f"警告 ({len(plan.warnings)} 件):")
        lines.extend(f"  - {w}" for w in plan.warnings)
    return "\n".join(lines)


def run_script(path: str) -> int:
    """Execute a generated script with the current interpreter; returns its exit code."""
    command = [sys.executable, os.path.abspath(path)]
    _info("生成したスクリプトを実行します: " + " ".join(shlex.quote(c) for c in command))
    sys.stdout.flush()
    try:
        # The child inherits our environment (REQREC_* secrets) and working directory.
        returncode = subprocess.call(command)
    except OSError as exc:
        raise OSError(f"スクリプトを実行できません: {exc}") from exc
    if returncode != 0:
        _info(f"スクリプトは終了コード {returncode} で終了しました")
    return returncode if 0 <= returncode <= 255 else EXIT_ERROR


def _plan_dump(plan: Plan) -> dict:
    """``--dump-plan`` JSON: ``core.to_plain(plan)`` with the recorded value of every *secret*
    constant removed (the generated script reads it from the environment; the dump must not keep it)."""
    data = to_plain(plan)
    for const, plain in zip(plan.constants, data.get("constants", [])):
        if const.secret:
            plain["value"] = None
    return data


def cmd_generate(args: argparse.Namespace) -> int:
    """``reqrec generate``: recording -> plan -> script (-> optional run)."""
    to_stdout = args.out == "-"
    if args.run and to_stdout:
        raise ValueError("--run を使う場合は -o にファイル名を指定してください（- は使えません）")
    if not to_stdout:
        _check_output_path(args.out, "出力先")
    if args.dump_plan:
        _check_output_path(args.dump_plan, "--dump-plan の出力先")

    inputs = list(args.input)
    recording: Recording = load_inputs(inputs)
    opts = resolve_overrides(recording, plan_options_from_args(args),
                             getattr(args, "exclude_step", None), getattr(args, "final_step", None))
    plan: Plan = build_plan(recording, opts)

    if args.dump_plan:
        _write_text(args.dump_plan, json.dumps(_plan_dump(plan), ensure_ascii=False, indent=2, default=str) + "\n")
        _info(f"解析結果 (Plan) を書き出しました: {args.dump_plan}")

    source = generate(plan, gen_options_from_args(args))
    if not isinstance(source, str):
        raise ValueError("コード生成器が文字列を返しませんでした")
    if not source.endswith("\n"):
        source += "\n"

    _info(format_plan_summary(plan, flows_total=len(recording.flows)))
    if not plan.steps:
        _info("注意: ステップが 1 つもありません。inspect で除外理由を確認し、--include-host / --keep-all などを調整してください。")

    if to_stdout:
        sys.stdout.write(source)
        sys.stdout.flush()
    else:
        _write_text(args.out, source)
        _info(f"スクリプトを書き出しました: {args.out}")

    if args.run:
        return run_script(args.out)
    return EXIT_OK


# ===== entry point: main() (``python reqrec.py``, console script ``reqrec``, ``python -m reqrec``) =====
# Former end of reqrec/cli.py.  ``python reqrec.py`` runs :func:`main` (the guard at the very end):
# without arguments the GUI, with a command the CLI (``record`` is the GUI's recording browser).


def _exit_code_from_system_exit(code: Any) -> int:
    """Normalise ``SystemExit.code`` (argparse uses ints; ``None`` means success)."""
    if code is None:
        return EXIT_OK
    if isinstance(code, bool):
        return int(code)
    if isinstance(code, int):
        return code
    print(str(code), file=sys.stderr)
    return EXIT_USAGE


def default_workdir() -> str:
    """``python reqrec.py``'s work folder: ``REQREC_WORKDIR``, else ``reqrec_work`` next to reqrec.py."""
    return os.environ.get(WORKDIR_ENV) or os.path.join(os.path.dirname(SCRIPT_PATH), "reqrec_work")


def first_free_port(host: str = "127.0.0.1", preferred: int = 8765, attempts: int = 20) -> int:
    """``preferred`` or the next port that can be bound (``preferred`` when none: the GUI explains)."""
    for port in range(int(preferred), int(preferred) + max(1, int(attempts))):
        if 1 <= port <= 65535 and _port_free(host, port) is None:
            return port
    return int(preferred)


def run_default_gui() -> int:
    """``python reqrec.py`` without arguments: the GUI on this PC (``127.0.0.1``, port 8765 or the next
    free one), opened in the browser; recordings and scripts go to :func:`default_workdir`."""
    return run_gui(host="127.0.0.1", port=first_free_port("127.0.0.1", 8765), workdir=default_workdir(), open_browser=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return the process exit code (0 ok, 1 error, 2 usage).  Without arguments
    (``python reqrec.py``) the GUI starts (:func:`run_default_gui`)."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        return run_default_gui()
    parser = build_parser()
    try:
        args = parser.parse_args(arguments)
    except SystemExit as exc:  # argparse: --help / --version (0) or usage error (2)
        return _exit_code_from_system_exit(exc.code)

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    try:
        return int(func(args))
    except FileNotFoundError as exc:
        missing = exc.filename if getattr(exc, "filename", None) else str(exc)
        _error(f"ファイルが見つかりません: {missing}")
        return EXIT_ERROR
    except (ValueError, ImportError, OSError) as exc:
        _error(str(exc) or exc.__class__.__name__)
        return EXIT_ERROR
    except KeyboardInterrupt:
        _error("中断されました")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
