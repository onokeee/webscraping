"""reqrec - record a website's HTTP traffic and generate a standalone Python scraping script from it.

Pipeline:  record (GUI) / import  ->  Recording  ->  build_plan  ->  Plan  ->  generate  ->  script.py

Target: legacy intranet sites used in Edge's IE mode, over plain ``http://``.  Recording is done
only through the GUI's own IE-engine recording browser (no Windows proxy change, no certificate).

The whole application is this one file (DESIGN.md "Module layout"):

* ``reqrec ...`` / ``python -m reqrec ...`` - the command line (:func:`main`): ``import`` /
  ``inspect`` / ``generate`` / ``gui`` / ``browser build|status``;
* ``mitmdump -s reqrec.py`` - the recording proxy loads this very file as its addon (:data:`addons`,
  :data:`ADDON_PATH`);
* ``import reqrec`` - the library (``load_recording``, ``build_plan``, ``generate``, ``create_app`` ...).

Sections, in this order, each one a former module (search for ``# ===== former reqrec/``): core,
importers, analysis, codegen, recorder, iehost (followed by the C# source ``RECBROWSER_CS``), gui
(followed by the page ``GUI_HTML``), cli and the entry point (:func:`main`).  Every top-level name is
defined once; names that clashed between former modules carry a section prefix, and the recording
browser keeps its former module as the namespace class ``iehost`` (``iehost.launch(...)``).

Importing has no side effects (nothing is started, written or read); bs4, winreg and ctypes are
imported only where they are used, so the proxy (``mitmdump -s reqrec.py``) starts quickly.
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
import importlib.util
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
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tokenize
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
    render_template,
    send_from_directory,
)
# mitmdump registers this module itself as an addon (``mitmdump -s reqrec.py``) and calls every
# top-level attribute named like one of its event hooks (``request``, ``response``, ``error``,
# ``load``, ``running``, ``done`` ...), so no top-level name may be a hook name: Flask's ``request``
# proxy is bound as ``flask_request`` (tests/test_recorder.py checks the names against mitmproxy's hooks).
from flask import request as flask_request
from jinja2 import DictLoader
from werkzeug.exceptions import HTTPException

__version__ = "0.1.0"

__all__ = [
    # core
    "RECORDING_FORMAT_VERSION", "Headers", "header_get", "header_get_all", "RecordedRequest",
    "RecordedResponse", "Flow", "Recording", "Ref", "RefKind", "Extractor", "ExtractorKind", "MultipartPart",
    "Loop", "Step", "Constant", "InitialCookie", "Dropped", "AuthInfo", "Plan", "PlanOptions", "GenOptions",
    "BodyKind", "ResponseKind", "to_plain", "NOT_WINDOWS_MESSAGE", "is_windows",
    # importers
    "load_recording", "load_recordings", "load_har", "recording_from_har", "HAR_EXTENSIONS",
    "parse_har_timestamp", "flow_from_mitm",
    "decode_header_fields", "infer_resource_type",
    # analysis
    "TRACKER_HOSTS", "STATIC_EXTENSIONS", "STATIC_RESOURCE_TYPES", "DROP_REQUEST_HEADERS",
    "SESSION_AUTH_SCHEMES", "AUTH_FAMILIES", "classify_noise", "filter_flows", "collapse_redirects",
    "classify_cookies", "compute_base_headers", "clean_request_headers", "parse_cookie_header",
    "parse_set_cookie", "normalise_flow_id", "collapse_auth_handshakes", "auth_family",
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
    "ReqRecAddon", "addons", "parse_hosts", "write_recording_atomic", "OPT_OUT", "OPT_HOSTS", "DEFAULT_OUT",
    "ADDON_PATH", "MITMDUMP_PYTHON_STUB", "RECORD_LISTEN_HOST", "mitmproxy_available", "mitmdump_launcher",
    "build_command", "RecorderError", "RecorderManager", "count_flows_in_file",
    # iehost
    "iehost", "IEHostError", "BrowserProcess", "RECBROWSER_CS",
    # gui
    "open_folder", "validate_url", "ApiError", "AppState", "ScriptRunner", "SUBDIRS", "safe_name",
    "plan_options_from_json", "gen_options_from_json", "options_to_plain", "load_sources", "exclude_netlocs",
    "normalise_netloc", "RECORDING_EXTENSIONS", "bp", "get_state", "create_app", "run_gui", "TOKEN_HEADER",
    "GUI_HTML",
    # cli
    "EXIT_OK", "EXIT_ERROR", "EXIT_USAGE", "main", "build_parser", "add_filter_options",
    "add_generate_options", "plan_options_from_args", "gen_options_from_args", "split_hosts",
    "split_flow_ids", "cli_normalise_flow_id", "load_inputs", "resolve_overrides", "build_inspect_report",
    "format_inspect_report", "format_plan_summary", "run_script",
]


def _register_script_module() -> None:
    """Put this module into ``sys.modules`` when it is executed without being registered there.

    ``mitmdump -s reqrec.py`` (mitmproxy's script loader) executes this file as
    ``__mitmproxy_script__.reqrec`` without registering it, but ``dataclasses`` looks the defining
    module up in ``sys.modules`` (the annotations are strings, see the ``__future__`` import) and
    fails without it.  The module object is the one holding this namespace, registered under its own
    name exactly as a normal import does.
    """
    import gc

    namespace = globals()
    module = next((m for m in gc.get_referrers(namespace) if isinstance(m, types.ModuleType) and m.__dict__ is namespace), None)
    if module is not None:
        sys.modules[__name__] = module


if __name__ not in sys.modules:
    _register_script_module()


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
        return parse_query(self.query)

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
    "cookie",      # session.cookies.get(name)                        -> name
    "header",      # resp.headers.get(name)                           -> name
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


@dataclass
class InitialCookie:
    """A cookie the browser already had when recording started (never seen in Set-Cookie)."""

    name: str
    value: str
    domain: str
    path: str = "/"


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
    redact_secrets: bool = True
    min_value_length: int = 4  # shortest request value considered for dependency detection
    max_steps: Optional[int] = None  # truncate (with a warning) - safety valve for huge recordings
    # --- manual overrides (GUI / CLI) ---
    exclude_flow_ids: list[str] = field(default_factory=list)  # always dropped, reason "excluded by user"
    include_flow_ids: list[str] = field(default_factory=list)  # kept even if a noise rule would drop them
    final_flow_id: Optional[str] = None  # the flow whose step becomes Plan.final_step_index
    detect_auth: bool = True  # detect NTLM / Negotiate / Basic / Digest handshakes -> Plan.auth


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
# (formerly in reqrec/winsupport.py; used by the iehost section)

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
# * mitmproxy -> Flow conversion (former ``reqrec/importers/mitm.py``) - ``flow_from_mitm`` (used by
#   the recorder addon).


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


# ===== former reqrec/importers/mitm.py: mitmproxy HTTPFlow -> Flow conversion (recorder addon) =====
# mitmproxy -> Flow conversion.  Contract: DESIGN.md §2.
#
# ``flow_from_mitm`` is used by the live recorder addon (recorder section).  It only touches public
# attributes of ``mitmproxy.http.HTTPFlow`` so it also works on duck-typed objects and does not
# itself need mitmproxy importable.

# ``Sec-Fetch-Dest`` request header -> HAR-style resource type, used when present (Chromium / Firefox
# HARs).  The IE-engine recording browser never sends it: its flows get no resource type and are
# classified by URL extension and MIME type instead.
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

    Equivalent to ``core.parse_form`` for UTF-8 bodies (blank values kept, repeated names kept,
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
    if not ct or not parse_content_type(ct)[1].get("charset"):
        return None
    return detect_charset(b"", ct)


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
    for name, value in parse_query(req.query):
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

    It stays a trace candidate - an all-uppercase key such as ``/s/QZVBNMWRTYPXSDFKHJ/items`` can
    be a JSON leaf of an earlier response - but the plan section never traces it through markup
    (``html_attr`` / ``html_text`` / ``regex`` / ``url``): tracing ``Login.aspx`` to
    ``action="Login.aspx"`` would only make the script depend on that markup for a constant."""
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
    tokens (tests/test_analysis.py, review3 section)."""
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
        from bs4 import NavigableString, Tag  # imported on first use: importing reqrec stays cheap

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
    others = sorted(v for v in value_variants(value) if v != value)
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
    variants = set(value_variants(value))
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
            # counter-like / word-like values are folded.
            if location in _LOOPABLE_LOCATIONS and not any(is_dynamic_looking(v) for v in values):
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
#: What a route-like path segment may still be traced to: exact structural matches (an all-uppercase
#: session key ``/s/QZVBNMWRTYPXSDFKHJ/`` can be a JSON leaf or a header of an earlier response).
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
    this step, so the header never carries a stale session value.

    Only whole tokens are replaced: a whole path segment (or the value of a ``;name=value`` path
    parameter such as ``;jsessionid=``) and a whole query value (or a query item without ``=``),
    each either verbatim or in its percent-encoded spelling.  ``scheme://host`` and the fragment
    stay literal, and a value is never replaced inside a longer token.  Only non-literal refs of
    this step whose recorded value has at least ``_REFERER_MIN_VALUE`` characters are used;
    anything else stays literal.

    ``secrets`` (recorded value -> Ref of a secret constant) is used, whatever the value's length,
    for query items whose name looks like a credential (``Login.aspx?pw=abc`` as the previous
    page), so a password never reaches the script through the Referer."""
    swaps: dict[str, Ref] = {}
    for (_loc, _name, raw), ref in refs.items():
        if ref is None or ref.is_literal or not isinstance(raw, str) or len(raw) < _REFERER_MIN_VALUE:
            continue
        swaps.setdefault(raw, ref)
    secrets = {raw: ref for raw, ref in (secrets or {}).items() if raw and ref is not None and not ref.is_literal}
    m = _ABS_URL_RE.match(value) if swaps or secrets else None
    if m is None:
        return Ref.lit(value)
    head, path, query, fragment = m.groups()
    pieces: list[tuple[bool, str]] = [(False, head)]  # (is_expr, text)

    def token(text: str, plus: bool, name: str = "") -> None:
        expr = _referer_token(text, swaps, plus) if text else None
        if expr is None and text and secrets and looks_like_secret_name(unquote(name.replace("+", " "))):
            expr = _referer_token(text, secrets, plus)
        pieces.append((True, expr) if expr is not None else (False, text))

    for i, segment in enumerate(path.split("/")):
        if i:
            pieces.append((False, "/"))
        first, *params = segment.split(";")
        token(first, False)
        for param in params:
            pieces.append((False, ";"))
            pname, eq, pvalue = param.partition("=")
            if eq:
                pieces.append((False, pname + "="))
                token(pvalue, False)
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
                token(qvalue, True, qname)
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
        self.value_units: dict[str, set[int]] = {}
        self.base_headers = []
        self.base_set: set[tuple[str, str]] = set()
        # --- phase 2 (DESIGN.md §13) ---
        self.auth: Optional[AuthInfo] = None
        self.auth_hops: dict[int, list[Flow]] = {}  # id(final attempt) -> its 401 hops
        self.auth_credentials: Optional[tuple[str, str]] = None  # Basic: (user, password) behind Plan.auth
        self.auth_token_units: dict[str, set[int]] = {}  # session-auth tokens sent by several steps
        self.auth_header_warned: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ naming

    def _cand_base_name(self, cand: Candidate, flow: Flow) -> str:
        if cand.location == "json":
            return _json_leaf_name(cand.json_path)
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
        segments = _path_segments(flow.request.url)
        parts = [s for i, s in enumerate(segments) if s and i not in dynamic_segments and not s.isdigit()]
        slug_src = "_".join(parts[-2:]) if parts else flow.request.host
        slug = safe_identifier(slug_src, default="root")[:_MAX_SLUG_LEN].strip("_") or "root"
        base = f"step_{index:02d}_{flow.request.method.lower()}_{slug}"
        return unique_name(base, self.func_names)

    # ------------------------------------------------------------------ constants

    def _secret_field(self, name: str) -> bool:
        """Is ``name`` a field whose value must be read from the environment (DESIGN.md §7)?"""
        return bool(self.opts.redact_secrets and looks_like_secret_name(name))

    def _constant(self, cand: Candidate, value: str, flow: Flow, step_no: int, force_secret: bool = False) -> Ref:
        """The shared ``Constant`` for ``value`` (created on first use).

        A secret use (``force_secret`` or a credential-like name, when ``redact_secrets``) only ever
        reuses a *secret* constant: a password equal to the user id gets its own environment variable
        instead of turning the user id's constant into one.  A plain use reuses any constant of the
        value (a form field carrying the Basic password reuses ``AUTH_PASSWORD`` rather than leaking it)."""
        secret = self.opts.redact_secrets and (force_secret or looks_like_secret_name(cand.name))
        const = self.secret_by_value.get(value) if secret else self.const_by_value.get(value)
        if const is None:
            base = safe_identifier(self._cand_base_name(cand, flow), default="value").upper()
            name = unique_name(base, self.taken)
            const = Constant(name=name, value=value, secret=secret, env_var=f"REQREC_{name}" if secret else None)
            self.constants.append(const)
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

    @staticmethod
    def _legacy_form_hint(body: Optional[bytes], form: list[tuple[str, Ref]]) -> list[tuple[str, Ref]]:
        """``form`` pairs for a body replayed as raw bytes: traced values keep their Ref, values
        that are not UTF-8 become bytes literals (``requests`` percent-encodes bytes verbatim)."""
        raw_pairs = form_pairs_bytes(body)
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

    def _trace(self, value: str, cand: Candidate, flow: Flow, step_no: int) -> Optional[Ref]:
        """Search earlier steps' responses, latest first."""
        route_segment = is_structural_path_segment(cand)
        for built in reversed(self.built):
            chain = built.unit.response_chain
            if route_segment:
                ext = self._accept(locate_value_kinds(value, chain[-1], _ROUTE_SEGMENT_KINDS), value, cand)
            else:
                ext = self._accept(locate_value(value, chain[-1]), value, cand)
            note = None
            if ext is None:
                for k in range(len(chain) - 2, -1, -1):
                    kinds = frozenset({"header", "url"}) if k == len(chain) - 2 else frozenset({"header"})
                    if route_segment:
                        kinds = kinds & _ROUTE_SEGMENT_KINDS
                    ext = self._accept(locate_value_kinds(value, chain[k], kinds), value, cand)
                    if ext is not None:
                        if ext.kind == "header":
                            note = f"from an intermediate redirect response ({chain[k].id}); check resp.history"
                        break
            if ext is None:
                continue
            ext = self._register(built, ext, cand, flow, step_no, note)
            return self._adapt(ext, value)
        return None

    def _resolve(self, cand: Candidate, unit: _Unit, step_no: int, cache: dict[tuple[str, bool], Ref]) -> Ref:
        value = cand.value
        secret_name = self._secret_field(cand.name)
        # keyed by secrecy too: ``txtUserId=tanaka01&txtPassword=tanaka01`` must not hand the user
        # id's literal to the password
        cache_key = (value, secret_name)
        if cache_key in cache:
            return cache[cache_key]
        flow = unit.first_flow
        ref: Optional[Ref] = None
        ts = looks_like_timestamp(value, around=flow.started_at)
        if ts:
            expr = "int(time.time()*1000)" if ts == "ms" else "int(time.time())"
            ref = Ref.expr(expr if cand.numeric else f"str({expr})")
        if ref is None:
            hit = find_cookie(value, self.earlier_flows)
            if hit:
                ref = self._cookie_ref(hit[0], hit[1], value)
        if ref is None:
            ref = self._trace(value, cand, flow, step_no)
        route_segment = is_structural_path_segment(cand)
        if ref is None and len(self.value_units.get(value, ())) >= 2 and not route_segment:
            # a repeated literal becomes a shared Constant - except route names in the path
            # (``GET /Default.aspx`` then ``POST /Default.aspx``), which stay part of the URL
            ref = self._constant(cand, value, flow, step_no)
        if ref is None and value in self.const_by_value and not route_segment:
            # the same value already has a Constant (e.g. AUTH_USERNAME from the Basic handshake)
            ref = self._constant(cand, value, flow, step_no)
        if ref is None and secret_name:
            ref = self._constant(cand, value, flow, step_no, force_secret=True)
        if ref is None:
            if is_dynamic_looking(value):
                label = f"path segment {cand.name}" if cand.location == "path" else cand.name
                self.warnings.append(
                    f"step {step_no}: value of `{label}` looks dynamic but could not be traced to any earlier "
                    f"response; replaying the recorded literal may fail"
                )
            ref = Ref.lit(value)
        cache[cache_key] = ref
        return ref

    # ------------------------------------------------------------------ step construction

    def _build_step(self, unit: _Unit, index: int) -> Step:
        flow = unit.first_flow
        req = flow.request
        last = unit.last_flow
        resp = last.response
        step_no = index
        cands = find_candidates(flow, self.opts)
        loop: Optional[Loop] = None
        loop_key: Optional[tuple[str, str, int]] = None
        loop_first_value: Optional[tuple[str, str, str]] = None
        if unit.loop is not None:
            lg = unit.loop
            var = self._loop_var(lg, flow)
            loop = Loop(var=var, values=list(lg.values), numeric_range=lg.numeric_range,
                        note=f"{len(lg.groups)} iterations of {lg.location} `{lg.name}`: {truncate(', '.join(lg.values), 60)}")
            loop_key = (lg.location, lg.name, lg.occurrence)
            loop_first_value = (lg.location, lg.name, lg.values[0] if lg.values else "")

        refs: dict[tuple[str, str, str], Ref] = {}
        cand_by_key: dict[tuple[str, str, str], Candidate] = {}
        cache: dict[tuple[str, bool], Ref] = {}
        for cand in cands:
            key = (cand.location, cand.name, cand.value)
            cand_by_key.setdefault(key, cand)
            if key in refs or key == loop_first_value:
                continue
            refs[key] = self._resolve(cand, unit, step_no, cache)

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
                return Ref.var(loop.var)
            ref = refs.get((location, name, value))
            if ref is None:
                ref = secret_ref(location, name, value) or Ref.lit(value)
            return ref

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

        params = [(name, ref_for("query", name, value)) for name, value in parse_query(req.query)]

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
                dynamic = [name for name, ref in form if not ref.is_literal]
                form = self._legacy_form_hint(req.body, form)
                raw_body = req.body
                body_kind = "raw"
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
        header_cands: dict[str, list[Candidate]] = {}
        for cand in cands:
            if cand.location == "header":
                header_cands.setdefault(cand.name, []).append(cand)
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
                ref = _referer_with_fresh_values(value, refs, secrets)
            headers.append((name, ref))

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
            allow_redirects=True,
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

        if initial_cookies:
            names = ", ".join(sorted({c.name for c in initial_cookies})[:8])
            self.warnings.append(
                f"{len(initial_cookies)} cookie(s) existed before the recording started ({names}); they are replayed "
                f"as INITIAL_COOKIES and may have expired"
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
        )


def build_plan(recording: Recording, opts: Optional[PlanOptions] = None) -> Plan:
    """Analyse a ``Recording`` and return the ``Plan`` the code generator turns into a script.

    See DESIGN.md §7 for the algorithm.  Never raises on odd recordings (binary bodies, missing
    responses, broken encodings); problems surface as ``Plan.warnings`` / ``Plan.dropped``.
    """
    clear_cache()
    try:
        return _Builder(recording, opts or PlanOptions()).build()
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
        reserved = set(self.constant_names) | {
            "main", "session", "resp", "soup", "data", "ctx", "results", "out", "requests", "re", "json",
            "os", "sys", "time", "unquote", "urlencode", "urljoin", "BeautifulSoup",
            "TIMEOUT", "DELAY", "BASE_HEADERS", "INITIAL_COOKIES",
            "_soup", "_check", "_regex", "_json_path", "_select", "_attr", "_elem_text", "_text", "_charset",
            "_normalise_charset", "final_resp", "final_results", "final_saved",
            "HttpNegotiateAuth", "HttpNtlmAuth",
        } | _DOWNLOAD_HELPER_NAMES
        for step in self.plan.steps:
            base = _check_identifier(step.func_name or f"step_{step.index:02d}", "step function name")
            self.func_names.append(unique_name(base, reserved))
        for step, fname in zip(self.plan.steps, self.func_names):
            for ext in step.extractors:
                self.producer.setdefault(ext.var, fname)
                self.producer_kind.setdefault(ext.var, ext.kind)
                self.helpers_needed.update(_helpers_for_extractor(ext))
            if self._raw_form(step) is not None:
                self.needs_urlencode = True
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
            if ref.value in self.producer:
                return f"{self.producer[ref.value]} で取得"
            if ref.value in self.loop_vars:
                return "ループ変数"
            return None
        if ref.kind == "expr":
            names = [n for n in _expr_names(_check_expr(ref.value)) if n in self.producer]
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
        """Every Ref of a step in the order the request is assembled (URL, params, headers, body)."""
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
        params: list[str] = []
        loop_var = step.loop.var if step.loop is not None else None
        if loop_var:
            params.append(loop_var)
        for ref in self._iter_refs(step):
            if not isinstance(ref, Ref):
                continue
            if ref.kind == "var":
                name = _check_identifier(ref.value, "Ref.var")
                if name in self.constant_names or name == loop_var or name in params:
                    continue
                if name not in known:
                    self._note(f"{step.func_name}: 変数 {name!r} はどのステップでも取得されていません（実行時に KeyError になります）")
                params.append(name)
            elif ref.kind == "expr":
                for name in _expr_names(_check_expr(ref.value)):
                    if name in known and name not in self.constant_names and name != loop_var and name not in params:
                        params.append(name)
        return params

    # ------------------------------------------------------------------ sections

    def _render(self, extra: Optional[list[str]] = None) -> str:
        self.w = _Writer()
        self._emit_docstring(extra=extra)
        self._emit_imports()
        self._emit_settings()
        self._emit_helpers()
        self._emit_steps()
        self._emit_main()
        self.w.blank(2)
        self.w.line('if __name__ == "__main__":')
        with self.w.indent():
            self.w.line("main()")
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
        label = {"har": "HAR ファイル", "mitmproxy": "mitmproxy 録画"}.get(kind.lower(), kind)
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
                '統合 Windows 認証には追加パッケージが必要です。Windows: pip install "reqrec[sspi]"'
                "（今ログインしているユーザーで認証します）",
                'Windows 以外 / 別のユーザーで実行する場合: pip install "reqrec[ntlm]" のうえ、環境変数 '
                f"REQREC_NTLM_USER（例: {default_user}）と REQREC_NTLM_PASSWORD を設定してください",
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
        w.line("import json")
        w.line("import os")
        w.line("import re")
        w.line("import sys")
        w.line("import time")
        names = ["unquote", "urljoin"] + (["urlencode"] if self.needs_urlencode else [])
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

        constants = self._all_constants()
        if constants:
            w.blank()
            self._c("===== 定数（必要に応じて書き換えてください） =====")
            for const in constants:
                self._emit_constant(const)

        w.blank()
        self._c("全てのリクエストに共通して送るヘッダー")
        items = [([f"{_lit(k)}: {_lit(v)}"], None) for k, v in (self.plan.base_headers or [])]
        w.block(_container("{", "}", items, inline_ok=False), prefix="BASE_HEADERS = ")

        w.blank()
        self._c("記録開始時点でブラウザが既に持っていた Cookie（ログイン済みセッションなど）")
        if self.plan.initial_cookies:
            self._c("期限切れになっている場合は、再度ブラウザから値を取得して書き換えてください")
        items = []
        for ck in self.plan.initial_cookies or []:
            items.append(([
                "{" + ", ".join([
                    f"'name': {_lit(ck.name)}",
                    f"'value': {_lit(ck.value)}",
                    f"'domain': {_lit(ck.domain)}",
                    f"'path': {_lit(ck.path or '/')}",
                ]) + "}"
            ], None))
        w.block(_container("[", "]", items, inline_ok=False), prefix="INITIAL_COOKIES = ")

    def _emit_constant(self, const: Constant) -> None:
        w = self.w
        name = _check_identifier(const.name, "constant name")
        if const.comment:
            self._c(const.comment)
        if const.secret:
            env = _env_name(const)
            self._c(f"記録時の値は安全のため出力していません。環境変数 {env} で指定してください（下の行の '' に直接書いても動きます）")
            w.line(f"{name} = os.environ.get({_lit(env)}, '')")
        else:
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
                w.line('"""ステータスコードが記録時と一致することを確認する。"""')
                w.line("if resp.status_code != expected:")
                with w.indent():
                    w.line("raise RuntimeError(")
                    with w.indent():
                        w.line('f"{step}: 想定外のステータスコード {resp.status_code} "')
                        w.line('f"(記録時: {expected}) {resp.request.method} {resp.url}"')
                    w.line(")")
            else:
                w.line('"""エラー応答（4xx/5xx）なら例外にし、記録時と違うステータスなら警告を出す。"""')
                w.line("if resp.status_code != expected:")
                with w.indent():
                    w.line("print(")
                    with w.indent():
                        w.line('f"[警告] {step}: ステータスコード {resp.status_code} (記録時: {expected}) {resp.url}",')
                        w.line("file=sys.stderr,")
                    w.line(")")
                w.line("resp.raise_for_status()")

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
            w.line("文字化けする。ヘッダーの charset → 本文先頭の <meta charset> / <?xml encoding> → JSON なら UTF-8 →")
            w.line("本文からの推定、の順に文字コードを決め、resp.encoding に設定したうえで resp.text を返す。")
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
            for ln in _docstring_lines(doc):
                w.line(ln)
            self._emit_request(step)
            try:
                expected = int(step.expected_status)
            except (TypeError, ValueError):
                expected = 200
            w.line(f"_check(resp, {expected}, {_lit(fname)})")
            outputs = self._emit_extractors(step, fname)
            items = [([f"{_lit(v)}: {v}"], None) for v in outputs]
            w.block(_container("{", "}", items), prefix="return resp, ")
        w.blank(2)

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
        if self._raw_form(step) is not None:
            self._note(
                f"{step.func_name}: UTF-8 以外の文字コードで送られたフォーム本文は、各フィールドの値から URL エンコードして"
                f"組み直します（取得した値は差し替え、Shift_JIS などの値は記録時のバイト列のまま）"
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
                if ext.sample is not None:
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
            return f"session.cookies.get({_lit(ext.name)})", f"Cookie {_lit(ext.name)} の値"
        if kind == "header":
            if ext.name is None:
                return self._todo(ext, fname, "ヘッダー名がありません")
            return f"resp.headers.get({_lit(ext.name)})", f"レスポンスヘッダー {_lit(ext.name)}"
        if kind == "json":
            if ext.path is None:
                return self._todo(ext, fname, "JSON パスがありません")
            path_src = "[" + ", ".join(_num_lit(p) if isinstance(p, int) and not isinstance(p, bool) else _lit(p) for p in ext.path) + "]"
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
            w.line("session = requests.Session()")
            self._emit_session_auth()
            w.line("session.headers.update(BASE_HEADERS)")
            w.line("for c in INITIAL_COOKIES:")
            with w.indent():
                w.line("session.cookies.set(c['name'], c['value'], domain=c['domain'], path=c['path'])")
            w.line("ctx = {}")
            if not steps:
                w.line('print("記録に再現できるリクエストがありませんでした", file=sys.stderr)')
                w.line("return ctx")
                return
            sleep = (self.opts.delay or 0) > 0
            for i, (step, fname) in enumerate(zip(steps, self.func_names)):
                last = i == len(steps) - 1
                w.blank()
                self._emit_main_step(
                    step, fname,
                    sleep=sleep and (not last or step.loop is not None),
                    final=self.opts.print_final and step is self.final_step,
                )
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
                         'Windows: 今ログインしているユーザーで認証（pip install "reqrec[sspi]"）')
                w.line("session.auth = HttpNegotiateAuth()")
            w.line("except ImportError:")
            with w.indent():
                w.line("try:")
                with w.indent():
                    self._cl("from requests_ntlm import HttpNtlmAuth",
                             '他の OS / 別ユーザーで認証する場合（pip install "reqrec[ntlm]"）')
                w.line("except ImportError:")
                with w.indent():
                    w.line("raise SystemExit(")
                    with w.indent():
                        w.line(_lit('統合 Windows 認証には追加パッケージが必要です: pip install "reqrec[sspi]"（Windows）'
                                    ' または pip install "reqrec[ntlm]"（他の OS。環境変数 REQREC_NTLM_USER / REQREC_NTLM_PASSWORD も設定）'))
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

    def _emit_main_step(self, step: Step, fname: str, *, sleep: bool, final: bool = False) -> None:
        w = self.w
        desc = step.comment or f"{str(step.method).upper()} {self._url_display(step.url)}"
        if step.loop is None:
            self._c(f"ステップ {step.index}: {desc}")
            w.block(self._call(step, fname))
            w.line("ctx.update(out)")
            if final:
                self._cl("final_resp = resp", "このステップの結果を最後に表示する")
            # a file is saved right after its own request, so a later failing step cannot lose it
            self._emit_save(step, target="final_saved = " if final and self._final_needs_saved(step) else "")
            if sleep:
                w.line("time.sleep(DELAY)")
            return
        loop = step.loop
        var = _check_identifier(loop.var, "loop variable")
        iterable = self._loop_iterable(loop)
        self._c(f"ステップ {step.index}: {desc}")
        if loop.note and str(loop.note) not in desc:
            self._c(f"繰り返し: {loop.note}")
        w.line("results = []")
        if iterable == "[]":
            w.line("out = {}")
        w.line(f"for {var} in {iterable}:")
        with w.indent():
            w.block(self._call(step, fname))
            if step.response_kind == "binary":
                self._cl("results.append(_save_download(resp))", "ファイルを保存し、保存先のパスを結果に入れる")
            else:
                self._emit_save(step)
                w.line("results.append(" + ("resp.json()" if step.response_kind == "json" else "_text(resp)") + ")")
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
        w.line("if not final_saved:")
        with w.indent():
            if kind == "html":
                w.line("soup = _soup(final_resp)")
                w.line("print(soup.title.get_text(strip=True) if soup.title else final_resp.url)")
                self._c("TODO: 必要なデータを soup から取り出してください（例: soup.select('table tr')）")
            else:  # empty
                w.line("print(final_resp.status_code, final_resp.url)")


# =========================================================================== module-level helpers

#: Emitted verbatim (top level) whenever the plan has steps: the DESIGN.md §13.13 download rule.
#:
#: * ``_is_attachment``: ``Content-Disposition`` (stripped, lower-cased) starts with ``attachment``,
#:   or contains ``filename`` and does not start with ``inline`` (``inline; filename=f.txt`` is
#:   Spring's RFD protection on every JSON response, not a download).  ``core.is_attachment_disposition``
#:   is the same rule for the GUI.
#: * ``_download_name``: RFC 6266 ``filename*=``, RFC 2047 encoded words (``=?UTF-8?B?...?=`` from
#:   .NET), IE-style percent-encoded UTF-8, or raw UTF-8 / Shift_JIS bytes that http.client decoded
#:   as Latin-1; else the URL's last segment; else ``output`` + an extension from the MIME type.
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
    """保存するファイル名: Content-Disposition のファイル名 → URL の末尾 → output + 拡張子。

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
        last = _unquote(urlsplit(resp.url).path.rsplit("/", 1)[-1], "utf-8")
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


def _helpers_for_extractor(ext: Extractor) -> set[str]:
    kind = ext.kind
    need: set[str] = set()
    if kind in ("html_input", "html_meta", "html_attr"):
        need |= {"_soup", "_attr"}
    elif kind == "html_text":
        need |= {"_soup", "_elem_text"}
    elif kind == "json":
        need.add("_json_path")
    if kind in ("regex", "url") or (kind in ("html_attr", "html_text") and ext.pattern):
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


# ===== former reqrec/recorder.py: proxy recording (mitmproxy addon, mitmdump launcher, GUI manager) =====
# Live recording through a mitmproxy-based proxy.  Contract: DESIGN.md §3 and §13.6.
#
# reqrec.py itself is the addon script mitmdump loads (``mitmdump -s reqrec.py --set
# reqrec_out=rec.json``, see :data:`ADDON_PATH`); it has no imports of its own to resolve, so script
# mode needs no special handling beyond ``_register_script_module`` at the top.  Importing reqrec never
# requires mitmproxy itself (the addon only needs it at run time).
#
# Sections (each one a former module, in dependency order):
#
# * addon (former ``reqrec/recorder/addon.py``) - the mitmproxy addon ``ReqRecAddon`` / ``addons``;
# * command line (former ``reqrec/recorder/run.py``) - ``build_command``: the ``mitmdump`` argument
#   vector with this file as its addon;
# * manager (former ``reqrec/recorder/manager.py``) - ``RecorderManager``: start / stop / watch a
#   recording from the GUI (the only way reqrec records: the GUI's recording browser).


# ===== former reqrec/recorder/addon.py: the mitmproxy addon (ReqRecAddon) =====
# mitmproxy addon that writes a reqrec Recording.  Run by the GUI's recorder as
# ``mitmdump -s reqrec.py --set reqrec_out=rec.json``.  Contract: DESIGN.md §3.
#
# Options (declared in :meth:`ReqRecAddon.load`):
#
# ``reqrec_out``
#     Path of the recording JSON file.  Rewritten **atomically after every response** (temp file in
#     the same directory + ``os.replace``) so a killed session still leaves a valid file.
# ``reqrec_hosts``
#     Comma-separated host names to record; a host matches itself and its sub-domains
#     (``host_matches``).  Empty = record everything.
#
# The addon works both when reqrec is imported normally and when mitmproxy exec's reqrec.py directly
# (script mode).

try:  # mitmproxy is only needed for type checks / option access; the addon stays importable without it
    from mitmproxy import ctx as _mitm_ctx
    from mitmproxy import http as _mitm_http
except ImportError:  # pragma: no cover - exercised only when mitmproxy is absent
    _mitm_ctx = None
    _mitm_http = None

log = logging.getLogger("reqrec.recorder")

OPT_OUT = "reqrec_out"
OPT_HOSTS = "reqrec_hosts"
DEFAULT_OUT = "reqrec_recording.json"

HostsSpec = Union[None, str, Iterable[str]]


def parse_hosts(spec: HostsSpec) -> list[str]:
    """``"a.com, B.com;c.com"`` / ``["a.com", ...]`` -> ``["a.com", "b.com", "c.com"]`` (lower-case,
    de-duplicated, order kept).  ``None`` / ``""`` -> ``[]`` (= record every host)."""
    if spec is None:
        return []
    if isinstance(spec, str):
        items: Iterable[str] = spec.replace(";", ",").replace("\n", ",").split(",")
    else:
        items = []
        for item in spec:
            items.extend(str(item).replace(";", ",").split(","))
    out: list[str] = []
    for item in items:
        for token in item.split():
            host = token.strip().lower().rstrip(".")
            if host and host not in out:
                out.append(host)
    return out


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


class ReqRecAddon:
    """Collect completed HTTP flows and keep ``reqrec_out`` up to date on disk.

    The addon can also be used programmatically without mitmproxy's option machinery::

        addon = ReqRecAddon(out="rec.json", hosts=["example.com"])
        addon.response(flow)      # flow: mitmproxy.http.HTTPFlow
        addon.done()

    Options set through mitmproxy (``--set reqrec_out=...``) take precedence once ``configure`` runs.
    """

    def __init__(self, out: Optional[str] = None, hosts: HostsSpec = None) -> None:
        # Constructor arguments are the baseline; mitmproxy options set to a non-default value
        # override them in ``configure`` (and fall back to these when reset to the default).
        self._init_out: Optional[str] = out
        self._init_hosts: list[str] = parse_hosts(hosts)
        self.out: Optional[str] = out
        self.hosts: list[str] = list(self._init_hosts)
        self.started_at: str = now_iso()
        self.errors: int = 0  # flows recorded through the error hook (no response)
        self.flush_count: int = 0
        self.last_flush_error: Optional[str] = None
        self._flows: list[Flow] = []
        self._seen: set[Any] = set()  # mitmproxy flow ids already recorded (response/error both fire)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ mitmproxy option hooks

    def load(self, loader: Any) -> None:
        """Declare the ``reqrec_out`` / ``reqrec_hosts`` options."""
        loader.add_option(
            name=OPT_OUT,
            typespec=str,
            default=DEFAULT_OUT,
            help="reqrec: path of the recording JSON file (rewritten atomically after every response)",
        )
        loader.add_option(
            name=OPT_HOSTS,
            typespec=str,
            default="",
            help="reqrec: comma-separated hosts to record (sub-domains included); empty = every host",
        )

    def configure(self, updated: Iterable[str]) -> None:
        """Pick up option changes (mitmproxy calls this at start-up with every option name)."""
        updated = set(updated)
        if OPT_OUT in updated:
            value = self._option(OPT_OUT)
            if isinstance(value, str) and value.strip() and value.strip() != DEFAULT_OUT:
                self.out = value.strip()
            else:
                self.out = self._init_out  # option at its default -> constructor value / DEFAULT_OUT
        if OPT_HOSTS in updated:
            value = self._option(OPT_HOSTS)
            self.hosts = parse_hosts(str(value)) if value is not None else []
            if not self.hosts:
                self.hosts = list(self._init_hosts)
        if updated & {OPT_OUT, OPT_HOSTS}:
            scope = ", ".join(self.hosts) if self.hosts else "all hosts"
            log.info("[reqrec] recording %s -> %s", scope, self.output_path)

    def _option(self, name: str) -> Any:
        """Read a mitmproxy option, or ``None`` when no master is running (plain Python use)."""
        if _mitm_ctx is None:
            return None
        try:
            options = _mitm_ctx.options
        except AttributeError:
            return None
        try:
            return getattr(options, name)
        except (AttributeError, KeyError):
            return None

    @property
    def output_path(self) -> str:
        """Absolute output path: explicit ``out`` > mitmproxy option > ``DEFAULT_OUT``."""
        out = self.out
        if not out:
            value = self._option(OPT_OUT)
            out = value if isinstance(value, str) and value.strip() else DEFAULT_OUT
        return os.path.abspath(out)

    # ------------------------------------------------------------------ mitmproxy event hooks

    def response(self, flow: Any) -> None:
        """A full response has arrived: record the flow and flush the file."""
        self._record(flow, errored=False)

    def error(self, flow: Any) -> None:
        """The flow failed (connection refused, TLS failure, client abort, ...).

        The request is still worth keeping (``response=None``) so the user sees what the browser
        attempted; ``filters`` drops such flows from the generated script.
        """
        self._record(flow, errored=True)

    def done(self) -> None:
        """mitmproxy is shutting down: final flush (also when nothing was recorded)."""
        try:
            path = self.flush()
        except Exception as exc:  # never let shutdown blow up
            log.error("[reqrec] final flush failed: %s", exc)
            return
        log.info("[reqrec] %d flow(s) saved to %s", len(self._flows), path)

    # ------------------------------------------------------------------ core

    def wants(self, flow: Any) -> bool:
        """Should this flow be recorded?  HTTP only, host filter applied."""
        if _mitm_http is not None and not isinstance(flow, _mitm_http.HTTPFlow):
            return False
        request = getattr(flow, "request", None)
        if request is None or not hasattr(request, "method"):
            return False
        if not self.hosts:
            return True
        return host_matches(_host_of(request), self.hosts)

    def _record(self, flow: Any, errored: bool) -> None:
        if not self.wants(flow):
            return
        key = getattr(flow, "id", None) or id(flow)
        with self._lock:
            if key in self._seen:
                return
            try:
                recorded = flow_from_mitm(flow, "f0000")  # real id assigned when sorted at flush time
            except Exception as exc:
                log.warning("[reqrec] could not convert flow: %s", exc)
                return
            self._seen.add(key)
            self._flows.append(recorded)
            if errored:
                self.errors += 1
            try:
                self.flush()
            except Exception as exc:
                self.last_flush_error = str(exc)
                log.error("[reqrec] could not write %s: %s", self.output_path, exc)
        status: Any = recorded.response.status if recorded.response is not None else "ERR"
        log.info("[reqrec] #%04d %s %s -> %s", len(self._flows), recorded.request.method, truncate(recorded.request.url, 100), status)

    def recording(self) -> Recording:
        """Snapshot of everything recorded so far, chronologically ordered with fresh ids."""
        with self._lock:
            ordered = self._sorted_flows()
            for n, flow in enumerate(ordered, start=1):
                flow.id = f"f{n:04d}"
            meta: dict[str, Any] = {
                "source": "mitmproxy",
                "started_at": self.started_at,
                "updated_at": now_iso(),
                "hosts": list(self.hosts),
                "flows_total": len(ordered),
                "errors": self.errors,
            }
            return Recording(flows=list(ordered), meta=meta)

    def _sorted_flows(self) -> list[Flow]:
        """Stable sort by ``started_at``; flows without a timestamp keep their arrival position."""
        keyed: list[tuple[float, int, Flow]] = []
        last = float("-inf")
        for index, flow in enumerate(self._flows):
            if flow.started_at is None:
                key = last
            else:
                key = last = float(flow.started_at)
            keyed.append((key, index, flow))
        keyed.sort(key=lambda t: (t[0], t[1]))
        return [f for _, _, f in keyed]

    def flush(self) -> str:
        """Write the current recording atomically; returns the path written."""
        with self._lock:
            path = write_recording_atomic(self.recording(), self.output_path)
            self.flush_count += 1
            self.last_flush_error = None
            return path

    def __len__(self) -> int:
        return len(self._flows)


def _host_of(request: Any) -> str:
    for attr in ("pretty_host", "host"):
        try:
            host = getattr(request, attr)
        except Exception:
            continue
        if host:
            return str(host)
    return ""


addons = [ReqRecAddon()]


# ===== former reqrec/recorder/run.py: the mitmdump command line =====
# ``mitmdump -s reqrec.py --set reqrec_out=... [--set reqrec_hosts=...] -p PORT --listen-host 127.0.0.1``.
# Contract: DESIGN.md §3.  The proxy only ever listens on this PC (:data:`RECORD_LISTEN_HOST`): its
# only client is the recording browser started by the GUI.

#: Absolute path of the addon file passed to ``mitmdump -s``: this very file (its addon section defines ``addons``).
ADDON_PATH = os.path.abspath(__file__)

#: ``mitmproxy.tools.main`` has no ``__main__`` guard, so ``python -m mitmproxy.tools.main`` does
#: nothing; the documented programmatic entry point is the ``mitmdump()`` function.
MITMDUMP_PYTHON_STUB = "import sys; from mitmproxy.tools.main import mitmdump; sys.exit(mitmdump())"

#: The recording proxy's listen address: this PC only.
RECORD_LISTEN_HOST = "127.0.0.1"


# --------------------------------------------------------------------------- discovery

def mitmproxy_available() -> bool:
    """True when either a ``mitmdump`` executable or the ``mitmproxy`` package can be found."""
    if shutil.which("mitmdump"):
        return True
    try:
        return importlib.util.find_spec("mitmproxy") is not None
    except (ImportError, ValueError):  # pragma: no cover - broken sys.modules entry
        return False


def mitmdump_launcher() -> list[str]:
    """Command prefix that runs mitmdump: the ``mitmdump`` executable when on PATH, otherwise the
    current interpreter calling ``mitmproxy.tools.main.mitmdump()``."""
    exe = shutil.which("mitmdump")
    if exe:
        return [exe]
    return [sys.executable, "-c", MITMDUMP_PYTHON_STUB]


# --------------------------------------------------------------------------- command line

def build_command(
    out: str,
    port: int = 8080,
    hosts: Union[None, str, Iterable[str]] = None,
    extra_args: Sequence[str] = (),
) -> list[str]:
    """Full ``mitmdump`` argument vector for a recording session.

    * ``out`` is made absolute (mitmdump's cwd is ours, but absolute paths survive ``--set`` quoting).
    * ``hosts`` (list or comma-separated string) becomes ``--set reqrec_hosts=a,b``; omitted when empty
      (= record every host).
    * mitmdump's own per-flow dump is off (``flow_detail=0``); the addon's one-line-per-recorded-flow
      log and mitmproxy warnings stay visible.
    * ``extra_args`` are appended verbatim (the GUI passes :data:`HTTPS_PASSTHROUGH_ARGS`).
    """
    cmd = mitmdump_launcher()
    cmd += ["-s", ADDON_PATH, "--set", f"reqrec_out={os.path.abspath(out)}"]
    host_list = parse_hosts(hosts)
    if host_list:
        cmd += ["--set", "reqrec_hosts=" + ",".join(host_list)]
    cmd += ["-p", str(int(port)), "--listen-host", RECORD_LISTEN_HOST]
    cmd += ["--set", "flow_detail=0"]
    cmd += [str(a) for a in extra_args]
    return cmd


# --------------------------------------------------------------------------- waiting

def _wait(proc: subprocess.Popen, timeout: float) -> Optional[int]:
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


# ===== former reqrec/recorder/manager.py: RecorderManager for the GUI =====
# Start / stop / watch a mitmdump recording from the GUI.  Contract: DESIGN.md §13.6 (RecorderManager).
#
# ``RecorderManager`` owns at most one child process.  The command line comes from an injectable
# ``command_builder`` (default :func:`build_command`) so tests can substitute a
# small Python stub for mitmdump.  The child's stdout / stderr are drained by reader threads into
# bounded ring buffers (``status()["stdout_tail"]`` / ``["stderr_tail"]``) so a child that logs a
# lot can never block, and the addon's atomically flushed recording file is read to count flows while
# the session runs.
#
# Stopping: SIGINT (``CTRL_BREAK_EVENT`` on Windows, where the child is started in its own process
# group) -> ``terminate()`` -> ``kill()``.

#: Reading a very large recording with ``json.loads`` every second would hurt; above this size a
#: regular expression counts the flow ids instead.
_JSON_COUNT_MAX_BYTES = 24 * 1024 * 1024
_RECORDER_FLOW_ID_RE = re.compile(rb'"id":\s*"f\d{4,}"')

_MANAGER_GRACE_AFTER_TERMINATE = 5.0
_READER_JOIN_TIMEOUT = 2.0

CommandBuilder = Callable[..., Sequence[str]]


class RecorderError(RuntimeError):
    """Raised by :class:`RecorderManager` with a Japanese, user-facing message."""


def count_flows_in_file(path: str, default: int = 0) -> int:
    """Number of flows in a recording JSON file.

    Tolerates a missing or not yet written file (before the addon's first flush): returns
    ``default`` whenever the file cannot be parsed.  Large files are counted with a regular
    expression on the raw bytes.
    """
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
    if isinstance(flows, list):
        return len(flows)
    return default


class RecorderManager:
    """Lifecycle of one recording child process (see module docstring).

    ``command_builder(out, port=..., hosts=[...])`` must return the argument
    vector to run; it is called with the absolute output path.  ``popen`` is injectable too.
    """

    def __init__(
        self,
        command_builder: Optional[CommandBuilder] = None,
        popen: Optional[Callable[..., subprocess.Popen]] = None,
        max_lines: int = 500,
        stop_timeout: float = 10.0,
    ) -> None:
        self.command_builder: CommandBuilder = command_builder or build_command
        self._popen = popen or subprocess.Popen
        self.max_lines = int(max_lines)
        self.stop_timeout = float(stop_timeout)
        self._lock = threading.RLock()
        self._proc: Optional[subprocess.Popen] = None
        self._threads: list[threading.Thread] = []
        self._stdout: deque[str] = deque(maxlen=self.max_lines)
        self._stderr: deque[str] = deque(maxlen=self.max_lines)
        self._last_count = 0
        self._stop_requested = False
        self.command: list[str] = []
        self.out: Optional[str] = None
        self.port: Optional[int] = None
        self.hosts: list[str] = []
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self.exit_code: Optional[int] = None

    # ------------------------------------------------------------------ properties

    @property
    def running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    # ------------------------------------------------------------------ start

    def start(
        self,
        out: str,
        port: int = 8080,
        hosts: Union[None, str, Iterable[str]] = None,
        extra_args: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Spawn the recording process; returns :meth:`status`.

        Raises :class:`RecorderError` when a session is already running, the output directory
        cannot be created or the process fails to start.
        """
        with self._lock:
            if self.running:
                raise RecorderError("すでに記録中です。先に記録を停止してください。")
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                raise RecorderError(f"ポート番号が不正です: {port!r}") from None
            if not 1 <= port_int <= 65535:
                raise RecorderError(f"ポート番号は 1〜65535 で指定してください: {port_int}")
            host_list = parse_hosts(hosts)
            out_abs = os.path.abspath(out)
            try:
                os.makedirs(os.path.dirname(out_abs) or ".", exist_ok=True)
            except OSError as exc:
                raise RecorderError(f"出力先フォルダを作成できません: {exc}") from exc
            kwargs: dict[str, Any] = {}
            if extra_args:
                kwargs["extra_args"] = list(extra_args)
            cmd = [str(c) for c in self.command_builder(out_abs, port=port_int, hosts=host_list, **kwargs)]
            popen_kwargs: dict[str, Any] = dict(
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            if os.name == "nt":  # own process group so CTRL_BREAK_EVENT reaches only the child
                popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            try:
                proc = self._popen(cmd, **popen_kwargs)
            except OSError as exc:
                raise RecorderError(f"記録プロセスを起動できません: {exc}") from exc
            self._proc = proc
            self.command = cmd
            self.out = out_abs
            self.port = port_int
            self.hosts = host_list
            self.started_at = time.time()
            self.stopped_at = None
            self.exit_code = None
            self._stop_requested = False
            self._last_count = 0
            self._stdout = deque(maxlen=self.max_lines)
            self._stderr = deque(maxlen=self.max_lines)
            self._threads = []
            for stream, buf, label in ((proc.stdout, self._stdout, "stdout"), (proc.stderr, self._stderr, "stderr")):
                if stream is None:
                    continue
                t = threading.Thread(target=self._drain, args=(stream, buf), name=f"reqrec-recorder-{label}", daemon=True)
                t.start()
                self._threads.append(t)
            return self.status()

    def wait_until_listening(
        self,
        timeout: float = 20.0,
        connect: Optional[Callable[..., Any]] = None,
        interval: float = 0.2,
    ) -> bool:
        """Block until the proxy accepts TCP connections on ``127.0.0.1:port``.

        mitmdump needs a second or two to import before it binds; a client that is pointed at the
        proxy earlier (the in-app recording browser, DESIGN.md §13.12) gets 「ページを表示できません」.
        Returns ``False`` when the child exits first or ``timeout`` passes.  Does not hold the lock
        while waiting.  ``connect`` is injectable (default :func:`socket.create_connection`).
        """
        dial = connect or socket.create_connection
        with self._lock:
            port = self.port
            out = self.out
        if not port:
            return False
        host = RECORD_LISTEN_HOST
        deadline = time.time() + max(0.0, float(timeout))
        while True:
            if not self.running or self.out != out:
                return False
            try:
                conn = dial((host, int(port)), timeout=0.5)
            except OSError:
                conn = None
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                return True
            if time.time() >= deadline:
                return False
            time.sleep(interval)

    @staticmethod
    def _drain(stream: Any, buf: deque) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                buf.append(line.rstrip("\r\n"))
        except (ValueError, OSError):  # stream closed while reading
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ stop

    def stop(self, timeout: Optional[float] = None) -> Optional[int]:
        """Stop the child gracefully and return its exit code (``None`` when nothing was running).

        Order: SIGINT / CTRL_BREAK_EVENT (lets the addon flush) -> wait ``timeout`` ->
        ``terminate()`` -> wait -> ``kill()``.
        """
        grace = self.stop_timeout if timeout is None else float(timeout)
        with self._lock:
            proc = self._proc
            if proc is None:
                return self.exit_code
            self._stop_requested = True
            rc = proc.poll()
            if rc is None:
                rc = self._shutdown(proc, grace)
            for t in self._threads:
                t.join(_READER_JOIN_TIMEOUT)
            self._threads = []
            self.exit_code = rc
            self.stopped_at = time.time()
            self._proc = None
            return rc

    @staticmethod
    def _shutdown(proc: subprocess.Popen, grace: float) -> int:
        try:
            if os.name == "nt":
                sig = getattr(signal, "CTRL_BREAK_EVENT", None)
                if sig is not None:
                    proc.send_signal(sig)
                else:  # pragma: no cover - very old Python on Windows
                    proc.terminate()
            else:
                proc.send_signal(signal.SIGINT)
        except (ProcessLookupError, OSError, ValueError):
            pass
        rc = _wait(proc, grace)
        if rc is not None:
            return rc
        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass
        rc = _wait(proc, _MANAGER_GRACE_AFTER_TERMINATE)
        if rc is not None:
            return rc
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
        return proc.wait()

    def forget(self) -> bool:
        """Drop the output file of a **stopped** session so :meth:`status` no longer reports it.

        Used when the recording was thrown away ([やめる] in the GUI, which deletes the file) or never
        really started (the recording browser could not be opened): afterwards ``out`` is ``None``, so
        the GUI does not claim 「記録は保存されました」 and :meth:`load_recording` refuses.  The exit
        code and the output tails stay for diagnostics.  Returns ``False`` (and changes nothing)
        while the child is still running.
        """
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return False
            self.out = None
            self._last_count = 0
            return True

    def close(self) -> None:
        """``stop()`` that never raises (for ``atexit`` / app shutdown)."""
        try:
            self.stop()
        except Exception:
            pass

    # ------------------------------------------------------------------ inspection

    def flow_count(self) -> int:
        """Flows written so far (``0`` before the first flush).  While the file is being replaced
        the previous good count is returned."""
        out = self.out
        if not out:
            return 0
        count = count_flows_in_file(out, default=-1)
        if count < 0:
            return self._last_count
        self._last_count = count
        return count

    def status(self) -> dict[str, Any]:
        """Snapshot for the GUI: ``{running, flows, out, pid, exit_code, started_at, stopped_at,
        port, hosts, stdout_tail, stderr_tail, error, command}``."""
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
                # The child died on its own (port in use, missing dependency, ...): surface why.
                detail = stderr_tail.strip().splitlines()
                last = detail[-1] if detail else ""
                error = f"記録プロセスが終了コード {exit_code} で終了しました" + (f": {last}" if last else "")
            return {
                "running": running,
                "flows": self.flow_count(),
                "out": self.out,
                "out_name": os.path.basename(self.out) if self.out else None,
                "pid": proc.pid if proc is not None else None,
                "exit_code": exit_code,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "port": self.port,
                "hosts": list(self.hosts),
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "error": error,
                "command": list(self.command),
            }

    def load_recording(self) -> Recording:
        """Parse the recording written by the last / current session (``Recording.load``)."""
        if not self.out:
            raise RecorderError("記録ファイルがありません。先に記録を開始してください。")
        if not os.path.exists(self.out):
            raise RecorderError(
                "記録ファイルが作成されませんでした。記録用ブラウザで http:// のページを"
                " 1 つ以上開いてください。"
            )
        try:
            return Recording.load(self.out)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RecorderError(f"記録ファイルを読み込めません: {exc}") from exc


# ===== former reqrec/iehost.py: recording browser (build / launch / document mode) =====
# Recording browser for legacy intranet sites: a hosted IE engine routed through the local proxy.
# Contract: DESIGN.md §13.12.  Importable on every OS; everything Windows-specific is guarded and
# takes injectable dependencies (``exists`` / ``run`` / ``popen`` / ``winreg``) so the logic is unit
# tested anywhere without compiling, starting processes or touching the registry.
#
# Why a separate process
# ----------------------
# Edge's IE mode can only be pointed at a proxy by changing the Windows (system) proxy, which many
# factory PCs forbid.  ``RecBrowser.exe`` (C# source:
# :data:`RECBROWSER_CS` right after this section, compiled on first use with the ``csc.exe`` that
# ships with the inbox .NET Framework 4.x) hosts the very same Trident / MSHTML engine (``WebBrowser``
# control) and sets the proxy **for its own process only**::
#
#     InternetSetOptionA(NULL, INTERNET_OPTION_PROXY, {dwAccessType=3, "127.0.0.1:PORT", bypass=""})
#
# Nothing is written to the registry or Internet Options, no certificate is needed (the recorder is
# started with a catch-all ``--ignore-hosts`` pattern so HTTPS on every port passes through untouched
# and only plain ``http://``, the normal case for a LAN intranet site, is recorded).  The exe is always
# built 32-bit (``-platform:x86``) so the 32-bit ActiveX controls of legacy pages load, as in IE mode.  The bypass list is deliberately **empty**:
# ``<local>`` would exclude dotless host names such as ``http://kanri/`` from the recording.  Popups
# (``window.open``, ``target=_blank``, ``showModalDialog`` ...) open as tabs inside the same process,
# so their traffic is recorded too.
#
# Build cache
# -----------
# ``iehost.ensure_built(workdir)`` writes :data:`RECBROWSER_CS` to ``<workdir>/bin/RecBrowser.cs``,
# compiles it to ``<workdir>/bin/RecBrowser.exe`` and stores the SHA-256 of the source (and of the
# build settings) in ``<workdir>/bin/RecBrowser.cs.sha256``; it recompiles only when the exe is
# missing, the hash differs (reqrec was updated) or ``force=True``.  Without ``csc.exe`` a prebuilt
# ``RecBrowser.exe`` next to reqrec.py (``reqrec browser build``) is copied instead.
#
# Document mode
# -------------
# Without a ``FEATURE_BROWSER_EMULATION`` entry the hosted control runs in IE7 mode (what IE mode
# does for Compatibility-View intranet sites).  ``iehost.set_emulation`` writes the per-user value
# ``HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION\RecBrowser.exe``
# (``11000`` = IE11 mode); this is the only registry value this section ever touches and it affects
# nothing but ``RecBrowser.exe``.
#
# Command line (former ``reqrec/iehost/__main__.py``, now the CLI's ``browser`` sub-command)::
#
#     reqrec browser build    # prebuild RecBrowser.exe next to reqrec.py (distribution folder)
#     reqrec browser status   # is there a prebuilt exe?
#
# Namespace
# ---------
# The functions and constants live in the class ``iehost`` and are called as before
# (``iehost.launch(...)``, ``iehost.availability(...)``, ``iehost.EXE_NAME``): several of their names
# (``build_command``, ``_wait``, ``_write_text``) exist in
# other sections too.  Inside, they refer to each other through ``iehost.``, so replacing one attribute
# (tests ``monkeypatch`` ``iehost.csc_path`` / ``iehost.launch``) affects every caller, exactly as
# replacing an attribute of the former module did.  ``IEHostError`` and ``BrowserProcess`` are
# top-level classes (``BrowserProcess`` is also reachable as ``iehost.BrowserProcess``).


class IEHostError(RuntimeError):
    """Raised with a Japanese, user-facing message when the recording browser cannot be built or started."""


class BrowserProcess:
    """A running ``RecBrowser.exe``: ``pid`` / ``exe`` / ``log_path`` / ``started_at`` plus ``poll`` / ``close``.

    ``close()`` is graceful first: on Windows ``taskkill /PID <pid>`` (no ``/F``) posts ``WM_CLOSE``
    so the browser window closes like a user clicking the X; then ``terminate()``, then ``kill()``.
    ``run`` / ``windows`` are injectable for tests.
    """

    def __init__(
        self,
        proc: Any,
        exe: str,
        log_path: str,
        run: Callable[..., Any] = subprocess.run,
        started_at: Optional[float] = None,
        windows: Optional[bool] = None,
    ) -> None:
        self._proc = proc
        self._run = run
        self._windows = iehost.is_windows() if windows is None else bool(windows)
        self.pid: int = int(getattr(proc, "pid", 0) or 0)
        self.exe = exe
        self.log_path = log_path
        #: Windows job handle that ends the browser if this process dies (see ``iehost.kill_on_close_job``).
        self.job_handle: Optional[int] = None
        self.started_at: float = time.time() if started_at is None else float(started_at)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "running" if self.running else f"exited({self.poll()})"
        return f"<BrowserProcess pid={self.pid} {state} exe={self.exe!r}>"

    @property
    def running(self) -> bool:
        """True while the browser process is alive."""
        return self.poll() is None

    @property
    def returncode(self) -> Optional[int]:
        return self.poll()

    def poll(self) -> Optional[int]:
        """Exit code, or ``None`` while running."""
        return self._proc.poll()

    def wait(self, timeout: Optional[float] = None) -> Optional[int]:
        """Wait for the browser to exit; ``None`` on timeout."""
        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def close(self, timeout: float = 5.0) -> Optional[int]:
        """Close the browser window and return its exit code (``None`` if it would not die).

        Order: ``taskkill /PID`` (WM_CLOSE, Windows only) -> wait ``timeout`` -> ``terminate()`` ->
        wait -> ``kill()`` -> wait.  The job handle is released once the process is gone.
        """
        rc = self._close(timeout)
        if rc is not None and self.job_handle:
            iehost._close_handle(self.job_handle)
            self.job_handle = None
        return rc

    def _close(self, timeout: float) -> Optional[int]:
        rc = self.poll()
        if rc is not None:
            return rc
        if self._windows and self.pid:
            try:
                self._run(
                    ["taskkill", "/PID", str(self.pid)],
                    capture_output=True, text=True, errors="replace", timeout=iehost._TASKKILL_TIMEOUT,
                )
            except Exception:  # taskkill missing / refused: fall through to terminate()
                pass
            rc = iehost._wait(self._proc, timeout)
            if rc is not None:
                return rc
        try:
            self._proc.terminate()
        except (ProcessLookupError, OSError):
            pass
        rc = iehost._wait(self._proc, iehost._GRACE_AFTER_TERMINATE)
        if rc is not None:
            return rc
        try:
            self._proc.kill()
        except (ProcessLookupError, OSError):
            pass
        return iehost._wait(self._proc, timeout)


class iehost:  # noqa: N801 - a namespace, named like the former module its callers use
    """The recording browser host (former ``reqrec/iehost.py``): build, launch, document mode.

    Used as a namespace only (never instantiated): ``iehost.launch(...)``, ``iehost.EXE_NAME`` ...
    """

    BrowserProcess = BrowserProcess
    #: The platform check this section uses (replaceable on its own, as in the former module).
    is_windows = staticmethod(is_windows)

    #: Name of the compiled host; also the value name FEATURE_BROWSER_EMULATION looks up.
    EXE_NAME = "RecBrowser.exe"

    #: File next to the exe holding the SHA-256 of the source it was built from.
    HASH_NAME = "RecBrowser.cs.sha256"

    #: Name of the C# source file csc compiles: :data:`RECBROWSER_CS` written to ``<workdir>/bin/``.
    SOURCE_NAME = "RecBrowser.cs"

    #: Distribution folder of a prebuilt exe (``reqrec browser build``): the folder of reqrec.py.
    SHIPPED_DIR = os.path.dirname(os.path.abspath(__file__))

    #: Registry path (under HKEY_CURRENT_USER) of the per-executable document-mode override.
    FEATURE_BROWSER_EMULATION_KEY = r"Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION"

    #: Document-mode presets for ``set_emulation`` (``None`` = no override = IE7 mode in the hosted control).
    EMULATION_LEVELS: dict[str, Optional[int]] = {
        "default": None,
        "ie8": 8000,
        "ie11": 11000,
        "ie11_force": 11001,
    }

    #: ``%WINDIR%``-relative locations of the inbox C# compiler, preferred first (either one builds the
    #: 32-bit exe, see :data:`BUILD_PLATFORM`).
    _CSC_RELATIVE = (
        os.path.join("Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe"),
        os.path.join("Microsoft.NET", "Framework", "v4.0.30319", "csc.exe"),
    )

    _CSC_TIMEOUT = 120.0
    _TASKKILL_TIMEOUT = 10.0
    _GRACE_AFTER_TERMINATE = 3.0

    _NO_CSC_MESSAGE = (
        "記録用ブラウザを作成するためのコンパイラ (csc.exe) が見つかりません。"
        "Windows 標準の .NET Framework 4.x が入っているパソコンで実行してください。"
    )

    # ----------------------------------------------------------------------- discovery

    @staticmethod
    def csc_path(exists: Callable[[str], bool] = os.path.isfile, env: Optional[dict] = None) -> Optional[str]:
        """Path of the inbox C# compiler: ``%WINDIR%\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe``
        (then the 32-bit ``Framework`` directory), or ``None`` when neither exists."""
        environ = os.environ if env is None else env
        windir = environ.get("WINDIR") or environ.get("SystemRoot") or environ.get("windir") or r"C:\Windows"
        for rel in iehost._CSC_RELATIVE:
            candidate = os.path.join(windir, rel)
            if exists(candidate):
                return candidate
        return None

    @staticmethod
    def _prebuilt_exe(folder: Optional[str] = None) -> str:
        """A ready-made ``RecBrowser.exe`` in the distribution folder (default: next to reqrec.py;
        ``reqrec browser build``)."""
        return os.path.join(folder or iehost.SHIPPED_DIR, iehost.EXE_NAME)

    @staticmethod
    def shipped_exe(
        folder: Optional[str] = None,
        exists: Callable[[str], bool] = os.path.isfile,
        source: Optional[str] = None,
    ) -> Optional[str]:
        """The prebuilt exe in the distribution folder when it was built from **this** source, else ``None``.

        Run in place (not copied into the work folder): locked-down PCs often allow executables only in
        the folder IT approved (where reqrec / the portable Python lives), not under the user profile.
        A shipped exe without a hash file, or one built from another version, is not used directly.
        ``source`` is the C# source text (default :data:`RECBROWSER_CS`).
        """
        exe = iehost._prebuilt_exe(folder)
        if not exists(exe):
            return None
        recorded = iehost._read_text(exe + ".sha256")
        if recorded and recorded == iehost._build_digest(source):
            return exe
        return None

    @staticmethod
    def build_shipped(
        run: Callable[..., Any] = subprocess.run,
        csc: Optional[str] = None,
        folder: Optional[str] = None,
        source: Optional[str] = None,
    ) -> str:
        """Compile ``RecBrowser.exe`` into the distribution folder (default: next to reqrec.py) and
        record its source hash.

        ``reqrec browser build`` calls this; afterwards every PC that uses this folder runs the exe
        from there and nothing is compiled or written under the user's profile.  The C# source
        (default :data:`RECBROWSER_CS`) goes to a temporary file for ``csc``.
        """
        text = RECBROWSER_CS if source is None else source
        compiler = csc or iehost.csc_path()
        if compiler is None:
            raise IEHostError(iehost._NO_CSC_MESSAGE)
        exe = iehost._prebuilt_exe(folder)
        kwargs: dict[str, Any] = {"capture_output": True, "text": True, "errors": "replace", "timeout": iehost._CSC_TIMEOUT}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with tempfile.TemporaryDirectory(prefix="reqrec_recbrowser_") as tmp:
            src = os.path.join(tmp, iehost.SOURCE_NAME)
            iehost._write_source(src, text)
            try:
                result = run(iehost.build_command(compiler, src, exe), **kwargs)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise IEHostError(f"記録用ブラウザの作成 (コンパイル) に失敗しました。\n{exc}") from exc
        if getattr(result, "returncode", 1) != 0 or not os.path.isfile(exe):
            output = iehost._run_output(result)
            raise IEHostError("記録用ブラウザの作成 (コンパイル) に失敗しました。" + ("\n" + output if output else ""))
        iehost._write_text(exe + ".sha256", iehost._build_digest(text))
        return exe

    @staticmethod
    def exe_path(workdir: str) -> str:
        """``<workdir>/bin/RecBrowser.exe`` (the compiled host lives in the work directory)."""
        return os.path.join(workdir, "bin", iehost.EXE_NAME)

    @staticmethod
    def source_path(workdir: str) -> str:
        """``<workdir>/bin/RecBrowser.cs``: where :data:`RECBROWSER_CS` is written for ``csc``."""
        return os.path.join(workdir, "bin", iehost.SOURCE_NAME)

    @staticmethod
    def _hash_path(workdir: str) -> str:
        return os.path.join(workdir, "bin", iehost.HASH_NAME)

    @staticmethod
    def availability(
        workdir: str,
        platform: Optional[str] = None,
        exists: Callable[[str], bool] = os.path.isfile,
        env: Optional[dict] = None,
        folder: Optional[str] = None,
        source: Optional[str] = None,
    ) -> dict:
        """``{"available": bool, "reason": str|None, "exe": str|None, "built": bool, ...}`` for the GUI.

        ``reason`` is a Japanese sentence explaining why the recording browser cannot be used (``None``
        when it can); ``exe`` is the path ``iehost.launch`` will run (``None`` when unavailable); ``built``
        tells whether that exe already exists (otherwise the first launch compiles it, a few seconds).
        Also reports ``source`` (where the C# source is written for compiling), ``csc`` and
        ``prebuilt`` for diagnostics.  Never raises.
        """
        exe = iehost.exe_path(workdir)
        info: dict[str, Any] = {
            "available": False,
            "reason": None,
            "exe": None,
            "built": False,
            "source": iehost.source_path(workdir),
            "csc": None,
            "prebuilt": None,
        }
        if (platform or sys.platform) != "win32":
            info["reason"] = "記録用ブラウザ (IE エンジン) は Windows でのみ使えます。"
            return info
        csc = iehost.csc_path(exists=exists, env=env)
        prebuilt = iehost._prebuilt_exe(folder)
        info["csc"] = csc
        info["prebuilt"] = prebuilt if exists(prebuilt) else None
        shipped = iehost.shipped_exe(folder, exists=exists, source=source) if info["prebuilt"] else None
        if shipped:
            info.update(available=True, exe=shipped, built=True, shipped=True)
            return info
        info["built"] = bool(exists(exe))
        if info["built"] or info["prebuilt"] or csc:  # the C# source is part of reqrec.py: always there
            info["available"] = True
            info["exe"] = exe
            return info
        info["reason"] = iehost._NO_CSC_MESSAGE
        return info

    # ----------------------------------------------------------------------- build

    #: Target platform of ``RecBrowser.exe``: always 32-bit, whichever compiler builds it.  Legacy intranet
    #: pages load in-process ActiveX controls (report viewers, barcode / printing controls, ...) that
    #: mostly exist only as 32-bit DLLs; Edge's IE mode hosts them in a 32-bit content process, and a
    #: 64-bit host could not load them at all.  An x86 exe runs on 32- and 64-bit Windows alike (WOW64).
    BUILD_PLATFORM = "x86"

    @staticmethod
    def build_command(csc: str, source: str, exe: str) -> list[str]:
        """Exact ``csc`` argv (``source`` is the path of the ``.cs`` file): a 32-bit (``-platform:x86``,
        see :data:`BUILD_PLATFORM`) GUI executable (``winexe``: no console window) with WinForms references.

        The platform does not depend on the compiler ``iehost.csc_path`` picked: the ``Framework64`` and
        the 32-bit ``Framework`` csc.exe both emit x86 executables.  The P/Invoke structs use ``IntPtr``
        fields with sequential layout, which is correct for either bitness.
        """
        return [
            csc,
            "-nologo",
            "-target:winexe",
            f"-platform:{iehost.BUILD_PLATFORM}",
            "-optimize+",
            f"-out:{exe}",
            "-r:System.dll",
            "-r:System.Windows.Forms.dll",
            "-r:System.Drawing.dll",
            source,
        ]

    @staticmethod
    def _build_digest(source: Optional[str] = None) -> str:
        """What a built exe is checked against: the C# source (default :data:`RECBROWSER_CS`, as UTF-8)
        **and** the build settings (platform), so a new source or a change of build options alone
        (x64 -> x86) rebuilds an exe that is already there, once.  For the same source text this is the
        hash the former ``RecBrowser.cs`` file gave, so existing work folders are not rebuilt."""
        text = RECBROWSER_CS if source is None else source
        return hashlib.sha256(text.encode("utf-8") + f"\0platform={iehost.BUILD_PLATFORM}".encode("ascii")).hexdigest()

    @staticmethod
    def _write_source(path: str, text: str) -> None:
        """Write the C# source for ``csc``: its UTF-8 bytes as they are (no BOM, no newline translation)."""
        try:
            with open(path, "wb") as fh:
                fh.write(text.encode("utf-8"))
        except OSError as exc:
            raise IEHostError(f"記録用ブラウザのソースファイルを書き込めません: {path}\n{exc}") from exc

    @staticmethod
    def _read_text(path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return None

    @staticmethod
    def _write_text(path: str, text: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    @staticmethod
    def _run_output(result: Any) -> str:
        return f"{getattr(result, 'stdout', '') or ''}\n{getattr(result, 'stderr', '') or ''}".strip()

    @staticmethod
    def ensure_built(
        workdir: str,
        run: Callable[..., Any] = subprocess.run,
        csc: Optional[str] = None,
        force: bool = False,
        folder: Optional[str] = None,
        source: Optional[str] = None,
    ) -> str:
        """Compile the C# source into ``<workdir>/bin/RecBrowser.exe`` when needed and return the exe path.

        A prebuilt exe for this source in the distribution folder (``folder``, default next to reqrec.py)
        is returned as it is (unless ``force``).  Otherwise compiles when the exe is missing, when
        ``<workdir>/bin/RecBrowser.cs.sha256`` differs from the current source hash, or when ``force`` is
        set: the source (``source``, default :data:`RECBROWSER_CS`) is written to
        ``<workdir>/bin/RecBrowser.cs`` and the hash is written after a successful build.  ``csc``
        defaults to ``iehost.csc_path``; without a compiler a prebuilt exe in the distribution folder is
        copied instead.  ``run`` is called like ``subprocess.run`` (``capture_output`` / ``text`` /
        ``timeout`` keywords).  Raises :class:`IEHostError` (Japanese prefix + the compiler's output) on
        failure.  Never prints.
        """
        if not force:
            shipped = iehost.shipped_exe(folder, source=source)
            if shipped is not None:
                return shipped  # prebuilt for this version in the distribution folder: run it in place
        exe = iehost.exe_path(workdir)
        hash_file = iehost._hash_path(workdir)
        bin_dir = os.path.dirname(exe)
        current_hash = iehost._build_digest(source)
        exe_exists = os.path.isfile(exe)

        if not force and exe_exists and iehost._read_text(hash_file) == current_hash:
            return exe  # up to date

        compiler = csc or iehost.csc_path()
        if compiler is None:
            prebuilt = iehost._prebuilt_exe(folder)
            if os.path.isfile(prebuilt):
                return iehost._copy_prebuilt(prebuilt, exe, hash_file, current_hash)
            raise IEHostError(iehost._NO_CSC_MESSAGE)

        os.makedirs(bin_dir, exist_ok=True)
        src = iehost.source_path(workdir)
        iehost._write_source(src, RECBROWSER_CS if source is None else source)
        cmd = iehost.build_command(compiler, src, exe)
        kwargs: dict[str, Any] = {"capture_output": True, "text": True, "errors": "replace", "timeout": iehost._CSC_TIMEOUT}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            result = run(cmd, **kwargs)
        except FileNotFoundError:
            raise IEHostError(f"コンパイラが見つかりません: {compiler}") from None
        except subprocess.TimeoutExpired:
            raise IEHostError("記録用ブラウザの作成 (コンパイル) がタイムアウトしました。") from None
        except OSError as exc:
            raise IEHostError(f"コンパイラを実行できません: {exc}") from exc

        output = iehost._run_output(result)
        if getattr(result, "returncode", 1) != 0 or not os.path.isfile(exe):
            hint = ""
            if exe_exists:
                hint = "\n記録用ブラウザが開いたままの場合は、閉じてからもう一度お試しください。"
            raise IEHostError("記録用ブラウザの作成 (コンパイル) に失敗しました。" + hint + ("\n" + output if output else ""))
        iehost._write_text(hash_file, current_hash)
        return exe

    @staticmethod
    def _copy_prebuilt(prebuilt: str, exe: str, hash_file: str, digest: str) -> str:
        os.makedirs(os.path.dirname(exe), exist_ok=True)
        try:
            shutil.copyfile(prebuilt, exe)
        except OSError as exc:
            raise IEHostError(f"記録用ブラウザをコピーできません: {exc}") from exc
        iehost._write_text(hash_file, digest)
        return exe

    # ----------------------------------------------------------------------- process

    @staticmethod
    def _wait(proc: Any, timeout: float) -> Optional[int]:
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    @staticmethod
    def kill_on_close_job(proc: Any) -> Optional[int]:
        """Put ``proc`` in a Windows job object with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` and return the
        job handle (``None`` when unsupported or it failed — never raises).

        The handle stays open in this (GUI) process; if the GUI dies without cleaning up (console
        window closed, ended from Task Manager), Windows closes the handle and ends the recording browser
        too, so no orphaned window keeps sending traffic to a proxy port the next session may reuse.
        No setting, file or registry value is involved.
        """
        if not iehost.is_windows():
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
            # KILL_ON_JOB_CLOSE | SILENT_BREAKAWAY_OK: only RecBrowser.exe is tied to the GUI; programs it
            # starts (Excel opened from a download, a mail client ...) stay outside the job and survive.
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

    @staticmethod
    def _close_handle(handle: Optional[int]) -> None:
        if not handle or not iehost.is_windows():
            return
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle(wintypes.HANDLE(handle))
        except Exception:
            pass

    @staticmethod
    def _log_file(log_dir: str, now: float) -> str:
        stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(now))
        path = os.path.join(log_dir, f"recbrowser_{stamp}.log")
        n = 2
        while os.path.exists(path):  # two launches within one second
            path = os.path.join(log_dir, f"recbrowser_{stamp}_{n}.log")
            n += 1
        return path

    @staticmethod
    def launch(
        workdir: str,
        proxy_address: str,
        url: Optional[str] = None,
        title: Optional[str] = None,
        popen: Callable[..., Any] = subprocess.Popen,
        run: Callable[..., Any] = subprocess.run,
        log_dir: Optional[str] = None,
        job: Optional[Callable[[Any], Optional[int]]] = None,
    ) -> BrowserProcess:
        """Build if needed, then start the recording browser routed through ``proxy_address`` (``host:port``).

        argv: ``RecBrowser.exe --proxy <addr> --bypass "" --log <workdir>/logs/recbrowser_<timestamp>.log
        [--url <url>] [--title <title>]``.  The bypass list is empty on purpose (see the section comment).
        ``run`` is used for the compiler and later for ``taskkill`` in :meth:`BrowserProcess.close`.
        Raises :class:`IEHostError` when the exe cannot be built or started.
        """
        proxy_address = (proxy_address or "").strip()
        if not proxy_address:
            raise ValueError("プロキシのアドレス (host:port) を指定してください")
        exe = iehost.ensure_built(workdir, run=run)
        logs = log_dir or os.path.join(workdir, "logs")
        try:
            os.makedirs(logs, exist_ok=True)
        except OSError as exc:
            raise IEHostError(f"ログ用フォルダを作成できません: {exc}") from exc
        started_at = time.time()
        log_path = iehost._log_file(logs, started_at)
        argv = [exe, "--proxy", proxy_address, "--bypass", "", "--log", log_path]
        if url:
            argv += ["--url", str(url)]
        if title:
            argv += ["--title", str(title)]
        try:
            proc = popen(
                argv,
                cwd=os.path.dirname(exe),
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise IEHostError(f"記録用ブラウザを起動できません: {exc}") from exc
        binder = job if job is not None else (iehost.kill_on_close_job if popen is subprocess.Popen else None)
        job_handle = binder(proc) if binder is not None else None
        browser = iehost.BrowserProcess(proc, exe, log_path, run=run, started_at=started_at)
        browser.job_handle = job_handle
        return browser

    # ----------------------------------------------------------------------- document mode (registry)

    @staticmethod
    def _winreg(injected: Any) -> Any:
        """The injected fake or the real ``winreg`` module; :class:`IEHostError` on other OSes."""
        if injected is not None:
            return injected
        if not iehost.is_windows():
            raise IEHostError(NOT_WINDOWS_MESSAGE)
        import winreg  # noqa: WPS433 - Windows only

        return winreg

    @staticmethod
    def resolve_emulation(level: Any) -> Optional[int]:
        """Accept a preset name (``"ie11"``), an int (``11000``) or ``None`` and return the DWORD (or ``None``)."""
        if level is None:
            return None
        if isinstance(level, str):
            key = level.strip().lower()
            if key in iehost.EMULATION_LEVELS:
                return iehost.EMULATION_LEVELS[key]
            if not key or not key.isdigit():
                raise ValueError(f"表示モードの指定が不正です: {level!r}")
            level = int(key)
        if isinstance(level, bool) or not isinstance(level, int) or level < 0:
            raise ValueError(f"表示モードの指定が不正です: {level!r}")
        return level

    @staticmethod
    def set_emulation(level: Optional[int], exe_name: str = EXE_NAME, winreg: Any = None) -> None:
        """Write (or, for ``None``, delete) the ``FEATURE_BROWSER_EMULATION`` DWORD for ``exe_name`` under HKCU.

        Only this one per-user value is touched; it affects nothing but the named executable.
        """
        value = iehost.resolve_emulation(level)
        reg = iehost._winreg(winreg)
        access = reg.KEY_READ | reg.KEY_SET_VALUE
        if value is None:
            # read-only first: on the default path nothing is opened for writing unless a value exists
            # (some security products guard this key and refuse write access)
            if iehost.get_emulation(exe_name, winreg=reg) is None:
                return
            try:
                key = reg.OpenKey(reg.HKEY_CURRENT_USER, iehost.FEATURE_BROWSER_EMULATION_KEY, 0, access)
            except FileNotFoundError:
                return  # key absent: nothing to delete
            with key:
                try:
                    reg.DeleteValue(key, exe_name)
                except FileNotFoundError:
                    pass
                except OSError as exc:  # pragma: no cover - other registry errors
                    if getattr(exc, "winerror", None) != 2:
                        raise
            return
        with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, iehost.FEATURE_BROWSER_EMULATION_KEY, 0, access) as key:
            reg.SetValueEx(key, exe_name, 0, reg.REG_DWORD, int(value))

    @staticmethod
    def get_emulation(exe_name: str = EXE_NAME, winreg: Any = None) -> Optional[int]:
        """Current ``FEATURE_BROWSER_EMULATION`` DWORD for ``exe_name`` (``None`` when not set)."""
        reg = iehost._winreg(winreg)
        try:
            key = reg.OpenKey(reg.HKEY_CURRENT_USER, iehost.FEATURE_BROWSER_EMULATION_KEY, 0, reg.KEY_READ)
        except FileNotFoundError:
            return None
        with key:
            try:
                value, _type = reg.QueryValueEx(key, exe_name)
            except FileNotFoundError:
                return None
            except OSError as exc:  # pragma: no cover - other registry errors
                if getattr(exc, "winerror", None) == 2:
                    return None
                raise
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


# ===== former reqrec/RecBrowser.cs: C# source of the recording browser (RECBROWSER_CS) =====
# Compiled by ``iehost.ensure_built`` (written to ``<workdir>/bin/RecBrowser.cs`` first) and by
# ``reqrec browser build`` (written to a temporary file).  Started as the former file and was cut
# down on 2026-10-12 for the http-only scope (no ``--https`` option, no ``Options.HttpsRecorded``).
# UTF-8 without BOM (csc reads it as UTF-8), LF line ends; the build hash is taken over these bytes.

#: C# source of ``RecBrowser.exe``, the recording browser (see the iehost section).
RECBROWSER_CS = r'''// RecBrowser.cs -- reqrec "recording browser" for legacy intranet sites (DESIGN.md: IE host mode).
//
// Hosts the Internet Explorer engine (WebBrowser control = Shell.Explorer.2 / MSHTML, the same Trident
// engine Edge's IE mode uses) in this small process and routes ONLY THIS PROCESS's HTTP through the
// local reqrec recorder (mitmproxy).  Nothing in Windows is changed: no Internet Options proxy, no
// registry value, no CA certificate (the recorder is started with a catch-all --ignore-hosts pattern,
// so HTTPS on every port is tunnelled untouched and only plain http:// is recorded).
//
// Proven facts this file relies on (do not "modernise" them away):
//   * The per-process proxy must be set with InternetSetOptionA(NULL, INTERNET_OPTION_PROXY) and an
//     INTERNET_PROXY_INFO holding ANSI strings, BEFORE the first WebBrowser control is created.  The
//     Unicode (W) variant does not work.  INTERNET_OPTION_PER_CONNECTION_OPTION with a NULL handle
//     writes the registry and is never used here.
//   * The proxy bypass list must stay EMPTY: "<local>" would exclude dotless intranet names such as
//     http://kanri/ from the recording.
//   * Popups (window.open, target=_blank, form target=_blank, showModelessDialog, showModalDialog)
//     are hosted as new tabs by answering DWebBrowserEvents2.NewWindow3 / NewWindow2 with the
//     ActiveXInstance of a fresh control, so window.opener, the window name, the session and POST
//     bodies survive and all of their HTTP goes through the proxy.
//   * window.close() never raises DWebBrowserEvents2.WindowClosing on this engine build (verified with a
//     catch-all event sink, with and without RegisterAsBrowser).  MSHTML instead sends OLECMDID_CLOSE to
//     the control's site (IOleCommandTarget), so the site implements that interface and closes the tab.
//
// Build (inbox .NET Framework 4.8, C# 5 compiler, no installation needed):
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -nologo -target:winexe -platform:x86
//       -out:RecBrowser.exe -r:System.Windows.Forms.dll -r:System.Drawing.dll RecBrowser.cs
// Always 32-bit (-platform:x86), also on 64-bit Windows: legacy intranet pages use in-process ActiveX
// controls that mostly exist only as 32-bit DLLs, which Edge's IE mode loads in a 32-bit process; a
// 64-bit host cannot load them.
// Run:
//   RecBrowser.exe --proxy 127.0.0.1:PORT [--bypass ""] [--url http://...] [--title "..."]
//                  [--log path] [--selftest] [--seconds N]
// Exit codes: 0 = window closed normally, 2 = usage error, 3 = --selftest guard timeout.
//
// The language level is C# 5 (no string interpolation, nameof, expression-bodied members or ?.).
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace Reqrec.IeHost
{
    /// <summary>Subset of DWebBrowserEvents2 (dispatch ids from exdisp.idl) that the host needs.</summary>
    [ComImport, Guid("34A715A0-6587-11D0-924A-0020AFC7AC4D"), InterfaceType(ComInterfaceType.InterfaceIsIDispatch), TypeLibType(TypeLibTypeFlags.FHidden)]
    public interface DWebBrowserEvents2
    {
        [DispId(251)] void NewWindow2([In, Out, MarshalAs(UnmanagedType.IDispatch)] ref object ppDisp, [In, Out] ref bool Cancel);
        [DispId(263)] void WindowClosing([In] bool IsChildWindow, [In, Out] ref bool Cancel);
        [DispId(270)] void FileDownload([In] bool ActiveDocument, [In, Out] ref bool Cancel);
        [DispId(273)] void NewWindow3([In, Out, MarshalAs(UnmanagedType.IDispatch)] ref object ppDisp, [In, Out] ref bool Cancel, [In] uint dwFlags, [In, MarshalAs(UnmanagedType.BStr)] string bstrUrlContext, [In, MarshalAs(UnmanagedType.BStr)] string bstrUrl);
    }

    /// <summary>IOleCommandTarget (docobj.h), implemented by the control's site so MSHTML can ask the
    /// host to close a window.  Group ids are passed as raw pointers because the standard group is NULL.</summary>
    [ComImport, Guid("B722BCCB-4E68-101B-A2BC-00AA00404770"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IOleCommandTarget
    {
        [PreserveSig] int QueryStatus(IntPtr pguidCmdGroup, uint cCmds, IntPtr prgCmds, IntPtr pCmdText);
        [PreserveSig] int Exec(IntPtr pguidCmdGroup, uint nCmdID, uint nCmdexecopt, IntPtr pvaIn, IntPtr pvaOut);
    }

    /// <summary>Append-only diagnostics log ("HH:mm:ss.fff text", UTF-8 without BOM).  The process has
    /// no console (winexe), so this file is the only place diagnostics go.  Never throws.</summary>
    internal static class Log
    {
        static StreamWriter writer;
        static readonly object gate = new object();

        public static void Open(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(path));
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                writer = new StreamWriter(path, true, new UTF8Encoding(false));
                writer.AutoFlush = true;
            }
            catch (Exception) { writer = null; }
        }

        public static void Write(string text)
        {
            lock (gate)
            {
                if (writer == null) return;
                try { writer.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " " + text); }
                catch (Exception) { }
            }
        }

        public static void Close()
        {
            lock (gate)
            {
                if (writer == null) return;
                try { writer.Flush(); writer.Dispose(); } catch (Exception) { }
                writer = null;
            }
        }
    }

    /// <summary>WinINet / urlmon per-process options.  Every call here affects this process only.</summary>
    internal static class WinInet
    {
        const int INTERNET_OPTION_PROXY = 38;
        const int INTERNET_OPTION_END_BROWSER_SESSION = 42;
        const int INTERNET_OPTION_SUPPRESS_BEHAVIOR = 81;
        const int INTERNET_SUPPRESS_COOKIE_PERSIST = 3;
        const int INTERNET_OPEN_TYPE_PROXY = 3;

        // DWORD + two pointers; Sequential + IntPtr gives the right layout for -platform:x86 (the
        // production build, see the header) and would for x64 as well.
        [StructLayout(LayoutKind.Sequential)]
        struct INTERNET_PROXY_INFO
        {
            public int dwAccessType;
            public IntPtr lpszProxy;
            public IntPtr lpszProxyBypass;
        }

        [DllImport("wininet.dll", SetLastError = true, EntryPoint = "InternetSetOptionA")]
        static extern bool InternetSetOptionA(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        [DllImport("urlmon.dll")]
        static extern int UrlMkSetSessionOption(int dwOption, IntPtr pBuffer, int dwBufferLength, int dwReserved);

        // Kept alive for the lifetime of the process: WinINet may keep pointing at these strings.
        static IntPtr proxyInfoBuffer = IntPtr.Zero;

        static IntPtr BuildProxyInfo(string server, string bypass, out int size)
        {
            INTERNET_PROXY_INFO info = new INTERNET_PROXY_INFO();
            info.dwAccessType = INTERNET_OPEN_TYPE_PROXY;
            info.lpszProxy = Marshal.StringToHGlobalAnsi(server);            // ANSI: the W variant breaks WinINet
            info.lpszProxyBypass = Marshal.StringToHGlobalAnsi(bypass ?? "");
            size = Marshal.SizeOf(typeof(INTERNET_PROXY_INFO));
            IntPtr buf = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(info, buf, false);
            return buf;
        }

        /// <summary>InternetSetOptionA(NULL, INTERNET_OPTION_PROXY): proxy for every WinINet handle of this
        /// process that uses the pre-configured settings (which is what MSHTML / urlmon do).</summary>
        public static bool SetProcessProxy(string server, string bypass, out int lastError)
        {
            int size;
            proxyInfoBuffer = BuildProxyInfo(server, bypass, out size);
            bool ok = InternetSetOptionA(IntPtr.Zero, INTERNET_OPTION_PROXY, proxyInfoBuffer, size);
            lastError = ok ? 0 : Marshal.GetLastWin32Error();
            return ok;
        }

        /// <summary>Belt and braces: the same proxy on urlmon's own session (UrlMkSetSessionOption).</summary>
        public static int SetUrlmonProxy(string server, string bypass)
        {
            int size;
            IntPtr buf = BuildProxyInfo(server, bypass, out size);
            try { return UrlMkSetSessionOption(INTERNET_OPTION_PROXY, buf, size, 0); }
            catch (Exception) { return -1; }
        }

        /// <summary>Do not persist cookies received by this process (the recording starts from a clean
        /// session every time, so the login itself gets recorded).</summary>
        public static bool SuppressCookiePersist(out int lastError)
        {
            IntPtr buf = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(buf, INTERNET_SUPPRESS_COOKIE_PERSIST);
            bool ok = InternetSetOptionA(IntPtr.Zero, INTERNET_OPTION_SUPPRESS_BEHAVIOR, buf, 4);
            lastError = ok ? 0 : Marshal.GetLastWin32Error();
            return ok;
        }

        /// <summary>Flush session cookies / cached credentials of the browser session.</summary>
        public static bool EndBrowserSession(out int lastError)
        {
            bool ok = InternetSetOptionA(IntPtr.Zero, INTERNET_OPTION_END_BROWSER_SESSION, IntPtr.Zero, 0);
            lastError = ok ? 0 : Marshal.GetLastWin32Error();
            return ok;
        }
    }

    /// <summary>WebBrowser with the DWebBrowserEvents2 events the stock control does not expose:
    /// NewWindow2/NewWindow3 (popups hosted by a control we supply), WindowClosing and FileDownload.</summary>
    public class ExtWebBrowser : WebBrowser
    {
        /// <summary>Short name used in the log ("tab1", "tab2", ...).</summary>
        public string Name2 = "";
        /// <summary>Returns the (already created) control that will host a popup; null cancels the popup.</summary>
        public Func<ExtWebBrowser, string, uint, ExtWebBrowser> NewWindowFactory;
        /// <summary>window.close() was called on this tab's document.</summary>
        public Action<ExtWebBrowser> CloseRequested;
        /// <summary>A real file download (FileDownload with ActiveDocument == false) started.</summary>
        public Action<ExtWebBrowser> DownloadDetected;

        AxHost.ConnectionPointCookie cookie;
        Sink sink;

        protected override void CreateSink()
        {
            base.CreateSink();
            try
            {
                sink = new Sink(this);
                cookie = new AxHost.ConnectionPointCookie(ActiveXInstance, sink, typeof(DWebBrowserEvents2));
            }
            catch (Exception ex) { Log.Write("event sink FAILED for " + Name2 + ": " + ex.Message); }
        }

        protected override void DetachSink()
        {
            if (cookie != null)
            {
                try { cookie.Disconnect(); } catch (Exception) { }
                cookie = null;
            }
            base.DetachSink();
        }

        protected override WebBrowserSiteBase CreateWebBrowserSiteBase()
        {
            return new CommandSite(this);
        }

        /// <summary>The control's site with an IOleCommandTarget.  When script calls window.close() MSHTML
        /// sends OLECMDID_CLOSE (standard group) to the site, for script-opened popups directly and for the
        /// top-level page after IE's own "close this window?" confirmation.  (DWebBrowserEvents2.WindowClosing
        /// is never raised by this engine build, so the command is the reliable signal.)  Every other command
        /// is declined so the control keeps its default behaviour.</summary>
        protected class CommandSite : WebBrowserSite, IOleCommandTarget
        {
            const int S_OK = 0;
            const int OLECMDERR_E_NOTSUPPORTED = unchecked((int)0x80040100);
            const int OLECMDERR_E_UNKNOWNGROUP = unchecked((int)0x80040104);
            const uint OLECMDID_CLOSE = 45;
            const uint OLECMDID_SHOWSCRIPTERROR = 40;
            static readonly Guid CGID_DocHostCommandHandler = new Guid("F38BC242-B950-11D1-8918-00C04FC2C836");

            readonly ExtWebBrowser owner;
            public CommandSite(ExtWebBrowser host) : base(host) { owner = host; }

            public int QueryStatus(IntPtr pguidCmdGroup, uint cCmds, IntPtr prgCmds, IntPtr pCmdText)
            {
                return pguidCmdGroup == IntPtr.Zero ? OLECMDERR_E_NOTSUPPORTED : OLECMDERR_E_UNKNOWNGROUP;
            }

            public int Exec(IntPtr pguidCmdGroup, uint nCmdID, uint nCmdexecopt, IntPtr pvaIn, IntPtr pvaOut)
            {
                if (pguidCmdGroup != IntPtr.Zero)
                {
                    Guid group;
                    try { group = (Guid)Marshal.PtrToStructure(pguidCmdGroup, typeof(Guid)); }
                    catch (Exception) { return OLECMDERR_E_UNKNOWNGROUP; }
                    if (group == CGID_DocHostCommandHandler && nCmdID == OLECMDID_SHOWSCRIPTERROR)
                    {
                        // A script error on a legacy page: no dialog, keep running the page's scripts
                        // (pvaOut = TRUE).  Only this prompt is suppressed; login / security prompts still show.
                        try { if (pvaOut != IntPtr.Zero) Marshal.GetNativeVariantForObject(true, pvaOut); }
                        catch (Exception) { }
                        Log.Write("script error suppressed in " + owner.Name2);
                        return S_OK;
                    }
                    return group == CGID_DocHostCommandHandler ? OLECMDERR_E_NOTSUPPORTED : OLECMDERR_E_UNKNOWNGROUP;
                }
                if (nCmdID == OLECMDID_CLOSE)
                {
                    Log.Write("OLECMDID_CLOSE " + owner.Name2 + " (window.close)");
                    try { if (owner.CloseRequested != null) owner.CloseRequested(owner); }
                    catch (Exception ex) { Log.Write("close request failed: " + ex.Message); }
                    return S_OK;
                }
                return pguidCmdGroup == IntPtr.Zero ? OLECMDERR_E_NOTSUPPORTED : OLECMDERR_E_UNKNOWNGROUP;
            }
        }

        class Sink : DWebBrowserEvents2
        {
            readonly ExtWebBrowser owner;
            public Sink(ExtWebBrowser o) { owner = o; }

            public void NewWindow2(ref object ppDisp, ref bool Cancel)
            {
                Log.Write("NewWindow2 from " + owner.Name2);
                Host(ref ppDisp, ref Cancel, 0, "");
            }

            public void NewWindow3(ref object ppDisp, ref bool Cancel, uint dwFlags, string bstrUrlContext, string bstrUrl)
            {
                Log.Write("NewWindow3 from " + owner.Name2 + " flags=0x" + dwFlags.ToString("x") + " url=" + bstrUrl);
                Host(ref ppDisp, ref Cancel, dwFlags, bstrUrl);
            }

            void Host(ref object ppDisp, ref bool Cancel, uint flags, string url)
            {
                ExtWebBrowser target = null;
                try { if (owner.NewWindowFactory != null) target = owner.NewWindowFactory(owner, url, flags); }
                catch (Exception ex) { Log.Write("  -> new tab FAILED: " + ex.Message); }
                if (target == null) { Cancel = true; Log.Write("  -> cancelled (no tab)"); return; }
                object ax = target.ActiveXInstance;
                if (ax == null) { Cancel = true; Log.Write("  -> cancelled (ActiveXInstance null)"); return; }
                ppDisp = ax;   // the engine navigates THIS control itself (keeps opener / name / POST body)
                Log.Write("  -> hosted in " + target.Name2);
            }

            public void WindowClosing(bool IsChildWindow, ref bool Cancel)
            {
                Log.Write("WindowClosing " + owner.Name2 + " child=" + IsChildWindow);
                if (owner.CloseRequested != null) owner.CloseRequested(owner);
            }

            public void FileDownload(bool ActiveDocument, ref bool Cancel)
            {
                // ActiveDocument == true fires for every ordinary page; false is a real file download.
                if (ActiveDocument) return;
                Log.Write("FileDownload " + owner.Name2 + " (file download)");
                if (owner.DownloadDetected != null) owner.DownloadDetected(owner);
            }
        }
    }

    /// <summary>Parsed command line.</summary>
    public class Options
    {
        public string Proxy;
        public string Bypass = "";
        public string Url = "about:blank";
        public string Title = "reqrec 記録用ブラウザ";
        public string LogPath;
        public bool SelfTest;
        public int Seconds = 20;

        public static Options Parse(string[] args)
        {
            Options o = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                bool hasValue = i + 1 < args.Length;
                switch (a)
                {
                    case "--proxy": if (hasValue) o.Proxy = args[++i]; break;
                    case "--bypass": if (hasValue) o.Bypass = args[++i] ?? ""; break;
                    case "--url": if (hasValue) o.Url = args[++i]; break;
                    case "--title": if (hasValue) o.Title = args[++i]; break;
                    case "--log": if (hasValue) o.LogPath = args[++i]; break;
                    case "--selftest": o.SelfTest = true; break;
                    case "--seconds":
                        if (hasValue)
                        {
                            int n;
                            if (int.TryParse(args[++i], out n) && n > 0) o.Seconds = n;
                        }
                        break;
                    default: break;   // unknown arguments are ignored
                }
            }
            if (string.IsNullOrEmpty(o.Url)) o.Url = "about:blank";
            if (string.IsNullOrEmpty(o.Title)) o.Title = "reqrec 記録用ブラウザ";
            return o;
        }
    }

    public class MainForm : Form
    {
        const int MaxTabText = 40;

        readonly Options opt;
        readonly TabControl tabs = new TabControl();
        readonly TextBox addressBox = new TextBox();
        readonly Button backButton = new Button();
        readonly Button forwardButton = new Button();
        readonly Button reloadButton = new Button();
        readonly Button closeTabButton = new Button();
        readonly Button stopButton = new Button();
        readonly ToolStripStatusLabel eventLabel = new ToolStripStatusLabel();
        int tabCounter = 0;
        bool selfTestStarted = false;

        public MainForm(Options options)
        {
            opt = options;
            Text = opt.Title + " — 記録中";
            Font baseFont = SystemFonts.MessageBoxFont ?? SystemFonts.DefaultFont;
            Font = new Font(baseFont.FontFamily, Math.Max(baseFont.Size, 10F));
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = true;
            MinimumSize = new Size(640, 400);
            Rectangle area = Screen.PrimaryScreen.WorkingArea;
            Size = new Size(Math.Min(1100, area.Width - 20), Math.Min(800, area.Height - 20));

            BuildToolbar();
            BuildStatusStrip();

            tabs.Dock = DockStyle.Fill;
            tabs.Padding = new Point(14, 5);
            tabs.SelectedIndexChanged += delegate { UpdateToolbar(); };
            Controls.Add(tabs);
            tabs.BringToFront();

            ExtWebBrowser first = NewTab(false);
            if (opt.SelfTest)
            {
                first.DocumentCompleted += FirstPageCompletedForSelfTest;
                Timer guard = new Timer();
                guard.Interval = opt.Seconds * 1000;
                guard.Tick += delegate
                {
                    guard.Stop();
                    Log.Write("selftest: guard timeout after " + opt.Seconds + " s -> exit 3");
                    Program.ExitCode = 3;
                    Close();
                };
                guard.Start();
            }
            NavigateTab(first, opt.Url);
            UpdateToolbar();
            FormClosed += delegate { Log.Write("window closed -> exit " + Program.ExitCode); };
        }

        // ------------------------------------------------------------------ UI construction

        void BuildToolbar()
        {
            TableLayoutPanel bar = new TableLayoutPanel();
            bar.Dock = DockStyle.Top;
            bar.AutoSize = true;
            bar.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            bar.ColumnCount = 6;
            bar.RowCount = 1;
            bar.Padding = new Padding(6, 4, 6, 4);
            bar.BackColor = SystemColors.Control;
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            SetupToolButton(backButton, "← 戻る");
            SetupToolButton(forwardButton, "→ 進む");
            SetupToolButton(reloadButton, "⟳ 更新");
            SetupToolButton(closeTabButton, "⨯ タブを閉じる");
            backButton.Click += delegate { ExtWebBrowser b = Active; if (b != null && b.CanGoBack) Safe(delegate { b.GoBack(); }); };
            forwardButton.Click += delegate { ExtWebBrowser b = Active; if (b != null && b.CanGoForward) Safe(delegate { b.GoForward(); }); };
            reloadButton.Click += delegate { ExtWebBrowser b = Active; if (b != null) Safe(delegate { b.Refresh(WebBrowserRefreshOption.Normal); }); };
            closeTabButton.Click += delegate { if (tabs.SelectedTab != null) CloseTab(tabs.SelectedTab); };

            addressBox.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            addressBox.Margin = new Padding(6, 3, 6, 3);
            addressBox.KeyDown += AddressKeyDown;

            stopButton.Text = "■ 記録をおわる";
            stopButton.AutoSize = true;
            stopButton.Padding = new Padding(16, 5, 16, 5);
            stopButton.Margin = new Padding(8, 2, 2, 2);
            stopButton.FlatStyle = FlatStyle.Flat;
            stopButton.FlatAppearance.BorderSize = 0;
            stopButton.BackColor = Color.FromArgb(196, 30, 30);
            stopButton.ForeColor = Color.White;
            stopButton.UseVisualStyleBackColor = false;
            stopButton.Font = new Font(Font.FontFamily, Font.Size + 2F, FontStyle.Bold);
            stopButton.Click += delegate { Log.Write("stop button"); Program.ExitCode = 0; Close(); };

            bar.Controls.Add(backButton, 0, 0);
            bar.Controls.Add(forwardButton, 1, 0);
            bar.Controls.Add(reloadButton, 2, 0);
            bar.Controls.Add(addressBox, 3, 0);
            bar.Controls.Add(closeTabButton, 4, 0);
            bar.Controls.Add(stopButton, 5, 0);
            Controls.Add(bar);
        }

        void SetupToolButton(Button b, string text)
        {
            b.Text = text;
            b.AutoSize = true;
            b.Padding = new Padding(8, 4, 8, 4);
            b.Margin = new Padding(2);
            b.UseVisualStyleBackColor = true;
        }

        void BuildStatusStrip()
        {
            StatusStrip strip = new StatusStrip();
            strip.SizingGrip = false;
            ToolStripStatusLabel recording = new ToolStripStatusLabel(
                "● 記録中 — このウィンドウで開いた http:// のページの通信を記録しています（https:// は記録されません）");
            recording.Spring = true;
            recording.TextAlign = ContentAlignment.MiddleLeft;
            recording.ForeColor = Color.FromArgb(170, 0, 0);
            eventLabel.TextAlign = ContentAlignment.MiddleRight;
            strip.Items.Add(recording);
            strip.Items.Add(eventLabel);
            Controls.Add(strip);
        }

        // ------------------------------------------------------------------ tabs

        ExtWebBrowser Active
        {
            get
            {
                TabPage page = tabs.SelectedTab;
                if (page == null || page.Controls.Count == 0) return null;
                return page.Controls[0] as ExtWebBrowser;
            }
        }

        /// <summary>Creates a tab with a fresh control (handle forced so ActiveXInstance exists) and selects it.</summary>
        ExtWebBrowser NewTab(bool isPopup)
        {
            tabCounter++;
            string name = "tab" + tabCounter;
            TabPage page = new TabPage("新しいタブ");
            ExtWebBrowser wb = new ExtWebBrowser();
            wb.Name2 = name;
            wb.Dock = DockStyle.Fill;
            // Not Silent (= ScriptErrorsSuppressed): that would also hide the 「Windows セキュリティ」 login
            // prompt of Basic / Windows authentication.  Script errors are suppressed in CommandSite.Exec.
            wb.ScriptErrorsSuppressed = false;
            wb.IsWebBrowserContextMenuEnabled = true;
            wb.NewWindowFactory = delegate(ExtWebBrowser source, string url, uint flags) { return NewTab(true); };
            wb.CloseRequested = delegate(ExtWebBrowser b)
            {
                // Deferred: the engine is still inside window.close() (OLECMDID_CLOSE / WindowClosing)
                // when this runs, so the control must not be disposed synchronously.
                BeginInvoke(new Action(delegate { CloseTab(page); }));
            };
            wb.DownloadDetected = delegate(ExtWebBrowser b)
            {
                SetStatus(IsUnrecordedHttps(b.Url) ? "このダウンロード (https://) は記録されません" : "ダウンロードを記録しました");
            };
            bool titleAnnounced = !isPopup;
            wb.DocumentTitleChanged += delegate
            {
                string title = "";
                try { title = wb.DocumentTitle ?? ""; } catch (Exception) { }
                page.Text = TabText(title, wb);
                if (!titleAnnounced && title.Trim().Length > 0)
                {
                    titleAnnounced = true;
                    SetStatus("新しいタブ: " + Shorten(title.Trim(), MaxTabText));
                }
            };
            wb.Navigated += delegate(object s, WebBrowserNavigatedEventArgs e)
            {
                Log.Write("Navigated " + name + " -> " + e.Url);
                if (IsUnrecordedHttps(e.Url)) SetStatus("このページ (https://) は記録されません。http:// のページで操作してください");
                if (tabs.SelectedTab == page) UpdateToolbar();
            };
            wb.DocumentCompleted += delegate { if (tabs.SelectedTab == page) UpdateToolbar(); };
            wb.CanGoBackChanged += delegate { if (tabs.SelectedTab == page) UpdateToolbar(); };
            wb.CanGoForwardChanged += delegate { if (tabs.SelectedTab == page) UpdateToolbar(); };
            page.Controls.Add(wb);
            tabs.TabPages.Add(page);
            tabs.SelectedTab = page;
            IntPtr h = wb.Handle;   // force creation: ActiveXInstance must exist before the engine gets it
            if (isPopup) SetStatus("新しいタブを開きました");
            Log.Write("new tab " + name + (isPopup ? " (popup)" : "") + " handle=0x" + h.ToInt64().ToString("x"));
            return wb;
        }

        void CloseTab(TabPage page)
        {
            if (page == null || !tabs.TabPages.Contains(page)) return;
            ExtWebBrowser wb = page.Controls.Count > 0 ? page.Controls[0] as ExtWebBrowser : null;
            Log.Write("close tab " + (wb != null ? wb.Name2 : "?"));
            tabs.TabPages.Remove(page);
            try { if (wb != null) wb.Dispose(); } catch (Exception ex) { Log.Write("dispose failed: " + ex.Message); }
            try { page.Dispose(); } catch (Exception) { }
            if (tabs.TabPages.Count == 0)
            {
                ExtWebBrowser fresh = NewTab(false);   // never leave the window without a tab
                NavigateTab(fresh, "about:blank");
            }
            UpdateToolbar();
        }

        static string TabText(string title, ExtWebBrowser wb)
        {
            string t = (title ?? "").Trim();
            if (t.Length == 0)
            {
                try { if (wb.Url != null && wb.Url.ToString() != "about:blank") t = wb.Url.Host; } catch (Exception) { }
            }
            if (t.Length == 0) t = "新しいタブ";
            return Shorten(t, MaxTabText);
        }

        static string Shorten(string s, int max)
        {
            if (s.Length <= max) return s;
            return s.Substring(0, max - 1) + "…";
        }

        // ------------------------------------------------------------------ navigation / toolbar

        void NavigateTab(ExtWebBrowser wb, string url)
        {
            string target = (url ?? "").Trim();
            if (target.Length == 0) return;
            if (target.IndexOf("://", StringComparison.Ordinal) < 0 && !target.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
                target = "http://" + target;
            try { wb.Navigate(target); }
            catch (Exception ex) { Log.Write("navigate failed: " + ex.Message); SetStatus("このアドレスは開けません"); }
        }

        void AddressKeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode != Keys.Enter) return;
            e.SuppressKeyPress = true;
            e.Handled = true;
            ExtWebBrowser b = Active;
            if (b != null) NavigateTab(b, addressBox.Text);
        }

        void UpdateToolbar()
        {
            ExtWebBrowser b = Active;
            string url = "";
            bool back = false, forward = false;
            if (b != null)
            {
                try { if (b.Url != null) url = b.Url.ToString(); } catch (Exception) { }
                try { back = b.CanGoBack; forward = b.CanGoForward; } catch (Exception) { }
            }
            if (url == "about:blank") url = "";
            if (!addressBox.Focused || addressBox.Text.Length == 0) addressBox.Text = url;
            backButton.Enabled = back;
            forwardButton.Enabled = forward;
        }

        static bool IsUnrecordedHttps(Uri url)
        {
            return url != null && url.Scheme == Uri.UriSchemeHttps;
        }

        void SetStatus(string text)
        {
            eventLabel.Text = text;
            Log.Write("status: " + text);
        }

        static void Safe(Action a)
        {
            try { a(); } catch (Exception ex) { Log.Write("action failed: " + ex.Message); }
        }

        // ------------------------------------------------------------------ --selftest

        void FirstPageCompletedForSelfTest(object sender, WebBrowserDocumentCompletedEventArgs e)
        {
            if (selfTestStarted) return;
            if (e.Url != null && e.Url.ToString() == "about:blank") return;
            selfTestStarted = true;
            ExtWebBrowser main = (ExtWebBrowser)sender;
            Log.Write("selftest: first page completed " + e.Url);
            Queue<Action> steps = new Queue<Action>();
            // doClosePopup (optional) opens a popup that closes itself: exercises the OLECMDID_CLOSE path.
            string[] functions = { "doOpen", "doBlankPost", "doBlankLink", "doModeless", "doModal", "doClosePopup" };
            foreach (string fn in functions)
            {
                string name = fn;
                steps.Enqueue(delegate
                {
                    if (SafeEval(main, "typeof " + name) != "function") { Log.Write("selftest: " + name + " not present, skipped"); return; }
                    object r = null;
                    try { r = main.Document.InvokeScript(name); }
                    catch (Exception ex) { Log.Write("selftest: " + name + " error: " + ex.Message); return; }
                    Log.Write("selftest: " + name + " -> " + (r == null ? "(null)" : r.ToString()));
                });
            }
            steps.Enqueue(delegate
            {
                Log.Write("selftest: tabs=" + tabs.TabPages.Count);
                foreach (TabPage p in tabs.TabPages)
                {
                    ExtWebBrowser b = p.Controls.Count > 0 ? p.Controls[0] as ExtWebBrowser : null;
                    if (b == null) continue;
                    string url = "(none)";
                    try { if (b.Url != null) url = b.Url.ToString(); } catch (Exception) { }
                    Log.Write("tab: " + url + " mode=" + SafeEval(b, "document.documentMode") + " opener=" + SafeEval(b, "window.opener ? 'yes' : 'no'") + " name=" + SafeEval(b, "window.name"));
                }
            });
            steps.Enqueue(delegate { Log.Write("selftest: done -> exit 0"); Program.ExitCode = 0; Close(); });

            Timer timer = new Timer();
            timer.Interval = 1500;
            timer.Tick += delegate
            {
                if (steps.Count == 0) { timer.Stop(); return; }
                try { steps.Dequeue()(); }
                catch (Exception ex) { Log.Write("selftest: step error: " + ex.Message); }
            };
            timer.Start();
        }

        static string SafeEval(ExtWebBrowser b, string expression)
        {
            try
            {
                if (b.Document == null) return "(no document)";
                object r = b.Document.InvokeScript("eval", new object[] { expression });
                return r == null ? "" : r.ToString();
            }
            catch (Exception ex) { return "(error " + ex.Message + ")"; }
        }
    }

    internal static class Program
    {
        public static int ExitCode = 0;

        [STAThread]
        static int Main(string[] args)
        {
            Options opt = Options.Parse(args);
            Log.Open(opt.LogPath);
            Log.Write("RecBrowser start");
            if (string.IsNullOrEmpty(opt.Proxy))
            {
                Log.Write("proxy (none) -> FAILED: --proxy 127.0.0.1:PORT is required");
                Log.Close();
                return 2;
            }

            // All WinINet options are set before the first WebBrowser control exists.  None of them
            // touches the registry or Internet Options; failures are logged and never fatal.
            int err;
            bool ok = WinInet.EndBrowserSession(out err);
            Log.Write("end browser session -> " + (ok ? "ok" : "FAILED (error " + err + ")"));
            ok = WinInet.SuppressCookiePersist(out err);
            Log.Write("suppress cookie persist -> " + (ok ? "ok" : "FAILED (error " + err + ")"));
            ok = WinInet.SetProcessProxy(opt.Proxy, opt.Bypass, out err);
            Log.Write("proxy " + opt.Proxy + " -> " + (ok ? "ok" : "FAILED (error " + err + ")"));
            if (!ok)
            {
                // Without the per-process proxy the window would say 「記録中」 while recording nothing.
                Log.Write("exit 4 (proxy could not be set)");
                Log.Close();
                MessageBox.Show(
                    "記録用の中継設定に失敗したため、記録できません (エラー " + err + ")。\n" +
                    "reqrec の画面でもう一度 [記録をはじめる] を押してください。直らない場合は管理者に連絡してください。",
                    "reqrec 記録用ブラウザ", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 4;
            }
            Log.Write("proxy bypass=\"" + opt.Bypass + "\"");
            int hr = WinInet.SetUrlmonProxy(opt.Proxy, opt.Bypass);
            Log.Write("urlmon proxy -> hr=0x" + hr.ToString("x"));

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object s, System.Threading.ThreadExceptionEventArgs e)
            {
                Log.Write("unhandled: " + e.Exception);
            };
            try
            {
                MainForm form = new MainForm(opt);
                Log.Write("title " + form.Text);
                Application.Run(form);
            }
            catch (Exception ex)
            {
                Log.Write("fatal: " + ex);
                Log.Close();
                return 1;
            }
            Log.Write("exit " + ExitCode);
            Log.Close();
            return ExitCode;
        }
    }
}
'''


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
# recording browser (iehost section); this section checks the address it starts with and opens the
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

class ScriptRunner:
    """Run one generated script at a time in a subprocess.

    stdout / stderr are read by daemon threads into line ring buffers (``tail``) and, for
    stdout, additionally kept in full up to ``max_output_bytes`` so the user can save the result.
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
                self._stdout_tail.append(line.rstrip("\r\n"))
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
                self._stderr_tail.append(line.rstrip("\r\n"))
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
        self.recorder = recorder or RecorderManager()
        self.runner = runner or ScriptRunner()
        self.record_append = False
        #: Screen that started the running recording: ``"easy"`` (かんたん画面) or ``"advanced"``
        #: (詳細設定); ``None`` when idle.  Only an easy-started recording may be stopped automatically
        #: by the easy screen when its recording browser is closed (survives a page reload).
        self.record_origin: Optional[str] = None
        #: Last ``iehost.launch`` failure of this session (e.g. the exe blocked by AppLocker), for the page.
        self.iehost_error: Optional[str] = None
        #: The in-app recording browser (``iehost.BrowserProcess``) of the current / last
        #: recording (DESIGN.md §13.12); ``None`` when none was started.
        self.browser: Optional[Any] = None
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

    def set_recording(self, recording: Recording, sources: list[str], append: bool) -> Recording:
        """Replace or merge the current recording; invalidates the plan."""
        with self.lock:
            if append and self.recording is not None and self.recording.flows:
                merged = Recording.merge([self.recording, recording])
                self.recording = merged
                self.sources = list(self.sources) + [s for s in sources if s not in self.sources]
            else:
                self.recording = recording
                self.sources = list(sources)
            self.plan = None
            return self.recording

    def clear_recording(self) -> None:
        with self.lock:
            self.recording = None
            self.sources = []
            self.plan = None
            self.last_code = None
            self.last_secrets = []

    def require_recording(self) -> Recording:
        with self.lock:
            if self.recording is None or not self.recording.flows:
                raise ApiError("記録が読み込まれていません。先に「記録」または「読み込み」で記録ファイルを読み込んでください。", status=409)
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

    # ------------------------------------------------------------------ recording browser

    def close_browser(self, timeout: float = 5.0) -> Optional[int]:
        """Close the in-app recording browser (if any) and forget it; returns its exit code.

        Never raises: a browser that cannot be closed is still dropped from the state so the GUI
        is not stuck with it.  ``None`` when there was no browser or it did not exit in time.
        """
        browser = self.browser
        if browser is None:
            return None
        self.browser = None
        try:
            return browser.close(timeout=timeout)
        except Exception:
            return None

    # ------------------------------------------------------------------ shutdown

    def close(self) -> None:
        self.close_browser()
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


# --------------------------------------------------------------------------- free port (recording proxy)

def find_free_port(host: str = "127.0.0.1", preferred: int = 8080, avoid: Iterable[int] = (), attempts: int = 40) -> int:
    """A TCP port the recording proxy can bind: ``preferred`` first, then the following ports,
    finally one chosen by the OS.  Ports in ``avoid`` (the GUI's own) are skipped.

    Every recording uses this so the user never has to know what a port is.
    """
    skip = {int(p) for p in avoid}
    for port in range(int(preferred), int(preferred) + max(1, int(attempts))):
        if port in skip or not 1 <= port <= 65535:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((host, port))
            except OSError:
                continue
            return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


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
#: Flow count is only computed for listed files up to this size (it means parsing the file).
CHEAP_COUNT_MAX_BYTES = 3 * 1024 * 1024
_GUI_FLOW_ID_RE = re.compile(r"^f\d{4,}$")

#: Window title of the in-app recording browser (DESIGN.md §13.12); the host appends 「— 記録中」.
BROWSER_TITLE = "reqrec 記録用ブラウザ"
#: Extra mitmdump arguments that tunnel HTTPS untouched (no CA certificate needed; only http:// is recorded).
#: Every recording is started with them.
#: A catch-all pattern: ``:443$`` matched port 443 only, so ``https://kanri:8443/`` was intercepted with
#: the untrusted mitmproxy CA (certificate error) although the status line says HTTPS is not recorded.
#: In regular (explicit proxy) mode mitmproxy applies ``ignore_hosts`` only when deciding the layer of a
#: ``CONNECT`` tunnel; plain ``http://`` requests (absolute-form, what WinINet sends to a proxy) never
#: reach that check and are still recorded.  Measured with mitmdump 12.2.3 (see
#: tests/test_gui.py::TestHttpsPassthroughWithRealMitmdump): http:// recorded, https on a
#: non-443 port tunnelled with the origin server's own certificate and not recorded.
HTTPS_PASSTHROUGH_ARGS = ("--ignore-hosts", ".*")
#: Seconds ``record_start`` waits for mitmdump to accept connections before opening the recording browser.
PROXY_READY_TIMEOUT = 20.0
#: Accepted values of ``origin`` on ``POST /api/record/start``: the screen that started the recording.
_ORIGINS = ("advanced", "easy")


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
        # instruction (the logged-in Windows user via reqrec[sspi] needs neither value) instead of
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
                "comment": f"{who}。Windows で今ログインしているユーザーのまま認証する場合 (reqrec[sspi]) は空欄のまま (使われません)",
            })
        if "REQREC_NTLM_PASSWORD" not in seen:
            seen.add("REQREC_NTLM_PASSWORD")
            out.append({
                "name": f"{label} 認証のパスワード", "env_var": "REQREC_NTLM_PASSWORD", "secret": True, "auth": kind,
                "comment": "Windows 以外 / 別のユーザーで実行する場合 (reqrec[ntlm]) に必要。"
                           "Windows で今ログインしているユーザーのまま認証する場合 (reqrec[sspi]) は空欄のまま",
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
        view["pairs"] = [list(p) for p in parse_form(decode_body(body, content_type))]
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


def _file_entry_with_flows(entry: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in entry.items() if k != "path"}
    out["flows"] = None
    if entry["size"] <= CHEAP_COUNT_MAX_BYTES:  # list_files only returns .har / .json
        try:
            with open(entry["path"], "rb") as fh:
                data = json.loads(fh.read().decode("utf-8-sig", errors="replace"))
            if isinstance(data, dict):
                if isinstance(data.get("flows"), list):
                    out["flows"] = len(data["flows"])
                elif isinstance(data.get("log"), dict) and isinstance(data["log"].get("entries"), list):
                    out["flows"] = len(data["log"]["entries"])
        except (OSError, ValueError):
            out["flows"] = None
    return out


def _resolve_recording_name(state: AppState, item: Any) -> tuple[str, str]:
    """``"x.har"`` / ``{"folder": "uploads", "name": "x.har"}`` -> ``(path, display name)``."""
    folder: Optional[str] = None
    name: Any = item
    if isinstance(item, dict):
        folder = item.get("folder")
        name = item.get("name")
    clean = safe_name(name, "記録ファイル名")
    if os.path.splitext(clean)[1].lower() not in RECORDING_EXTENSIONS:
        raise ApiError(f"対応していないファイル形式です: {clean} (対応: {', '.join(sorted(RECORDING_EXTENSIONS))})")
    folders = [folder] if folder else ["recordings", "uploads"]
    for sub in folders:
        if sub not in ("recordings", "uploads"):
            raise ApiError(f"不正なフォルダです: {sub}")
        path = state.path_in(sub, clean, "記録ファイル名")
        if os.path.isfile(path):
            return path, f"{sub}/{clean}"
    raise ApiError(f"ファイルが見つかりません: {clean}", status=404)


def _iehost_info(state: AppState) -> dict[str, Any]:
    """``iehost.availability`` reduced to what the page / ``/api/state`` expose, plus the
    current 表示モード (preset name of the HKCU value, ``"default"`` when unset) and the last launch
    error of this GUI session (shown on the easy screen so a blocked exe is explained)."""
    info = iehost.availability(state.workdir)
    out = {k: info.get(k) for k in ("available", "reason", "exe", "built", "shipped")}
    out["emulation"] = "default"
    if info.get("available"):
        try:
            value = iehost.get_emulation()
        except Exception:
            value = None
        if value is not None:
            names = [k for k, v in iehost.EMULATION_LEVELS.items() if v == value]
            out["emulation"] = names[0] if names else "custom"
    out["last_error"] = state.iehost_error
    return out


def _require_iehost(state: AppState) -> None:
    """400 unless the in-app recording browser can be used on this PC (Windows + csc.exe or a prebuilt exe)."""
    info = iehost.availability(state.workdir)
    if not info.get("available"):
        raise ApiError(info.get("reason") or "記録用ブラウザ (IE エンジン) はこの PC では使えません。", status=400, iehost=info)


def _iehost_start_url(raw: Any) -> Optional[str]:
    """The optional first page of the recording browser: ``None`` when blank, else a validated
    ``http(s)://`` URL (a bare host name gets ``http://``; ``edge://`` and other schemes are refused)."""
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return validate_url(text)
    except ValueError as exc:
        raise ApiError(str(exc)) from exc


def _browser_payload(proc: Any) -> dict[str, Any]:
    """``{"kind": "iehost", "pid", "running", "log", "exit_code"}`` for a ``BrowserProcess``."""
    code = proc.poll()
    return {
        "kind": "iehost",
        "pid": getattr(proc, "pid", None),
        "running": code is None,
        "exit_code": code,
        "log": getattr(proc, "log_path", None),
    }


def _browser_status(state: AppState) -> dict[str, Any]:
    """``{"kind": "iehost"|None, "running": bool, "pid": ...|None, "exit_code": ...|None}``."""
    proc = state.browser
    if proc is None:
        return {"kind": None, "running": False, "pid": None, "exit_code": None}
    payload = _browser_payload(proc)
    payload.pop("log", None)
    return payload


#: ``kind`` of the 500 errors of ``record_start`` (the easy screen explains each one differently):
#: ``proxy`` = mitmdump never accepted connections, ``emulation`` = 表示モード (HKCU value) could not be
#: written, ``iehost`` = the recording browser could not be built or started (only this one gets the
#: 「RecBrowser.exe が止められた可能性」 guidance and is remembered as ``iehost.last_error``).
ERROR_KIND_PROXY = "proxy"
ERROR_KIND_EMULATION = "emulation"
ERROR_KIND_IEHOST = "iehost"


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
    """Undo a ``record_start`` that failed after mitmdump was spawned (proxy never listened, 表示モード
    or the recording browser failed): stop the recorder, delete the half-made file (normally absent:
    no browser ever used the proxy) and forget it, so 詳細設定 does not report 「記録は保存されました」
    and [記録停止] is not left enabled.  Does nothing when another recording owns the recorder by now."""
    with state.lock:
        current = getattr(state.recorder, "out", out)
        if current and os.path.abspath(current) != os.path.abspath(out):
            return
        state.recorder.stop()
        _remove_quietly(out)
        _forget_recording(state)
        state.record_origin = None


def _proxy_address(port: int) -> str:
    """``127.0.0.1:PORT``: the recording proxy as the recording browser is told to use it."""
    return f"{RECORD_LISTEN_HOST}:{int(port)}"


def _launch_iehost(state: AppState, proxy_address: str, start_url: Optional[str]) -> Any:
    """Start ``RecBrowser.exe`` (building it first when needed) and remember it as ``state.browser``.

    Raises :class:`ApiError` 500 (``kind: "iehost"``) with a Japanese message; the compiler's output
    is part of the message when the build failed (``IEHostError`` carries it).
    """
    try:
        proc = iehost.launch(state.workdir, proxy_address, url=start_url, title=BROWSER_TITLE)
    except Exception as exc:
        current_app.logger.exception("iehost launch failed")
        state.iehost_error = str(exc)
        raise ApiError(f"記録用ブラウザを起動できませんでした: {exc}", status=500, kind=ERROR_KIND_IEHOST) from exc
    state.iehost_error = None
    state.browser = proc
    return proc


def _apply_loaded(state: AppState, recording: Recording, sources: list[str], append: bool, from_gui_recorder: bool) -> dict[str, Any]:
    excluded = 0
    if from_gui_recorder:
        recording, excluded = exclude_netlocs(recording, gui_netlocs(state.host, state.port, flask_request.host))
    state.set_recording(recording, sources, append)
    summary = state.recording_summary()
    summary["excluded_self"] = excluded
    summary["appended"] = bool(append)
    return summary


# --------------------------------------------------------------------------- page

@bp.get("/")
def index() -> str:
    state = get_state()
    return render_template(
        _GUI_TEMPLATE,
        token=state.token,
        version=__version__,
        gui_address=f"{flask_request.host}",
        workdir=state.workdir,
        mitmproxy_available=mitmproxy_available(),
        iehost=_iehost_info(state),
    )


@bp.get("/api/state")
def api_state() -> Response:
    state = get_state()
    return jsonify({
        "version": __version__,
        "workdir": state.workdir,
        "gui_address": flask_request.host,
        "mitmproxy_available": mitmproxy_available(),
        "recorder": state.recorder.status(),
        "recording": state.recording_summary(),
        "plan_loaded": state.plan is not None,
        "plan_options": options_to_plain(state.plan_options),
        "gen_options": options_to_plain(state.gen_options),
        "run": state.runner.status(),
        "iehost": _iehost_info(state),
        "browser": _browser_status(state),
        "record_origin": state.record_origin,
        "last_script": state.last_script_name,
        "secrets": list(state.last_secrets),
    })


# --------------------------------------------------------------------------- recording (live)

@bp.post("/api/record/start")
def record_start() -> Response:
    """Start the recorder and open the recording browser through it (DESIGN.md §13.12).

    The proxy listens on ``127.0.0.1`` on a free port and tunnels every HTTPS connection untouched
    (:data:`HTTPS_PASSTHROUGH_ARGS`), so only ``http://`` is recorded and no certificate is needed.
    Body (all optional): ``{"hosts": [...], "append": bool, "start_url": "...", "emulation": "keep" |
    <preset>, "origin": "easy" | "advanced"}``.
    """
    state = get_state()
    body = _json_body(required=False)
    hosts_raw = body.get("hosts", [])
    if isinstance(hosts_raw, str):
        hosts = [h for h in re.split(r"[,\s;]+", hosts_raw) if h]
    elif isinstance(hosts_raw, list):
        hosts = [str(h).strip() for h in hosts_raw if str(h).strip()]
    else:
        raise ApiError("対象ホストは配列か文字列で指定してください")
    append = _bool(body.get("append"), False)
    start_url = _iehost_start_url(body.get("start_url"))
    emulation = str(body.get("emulation") or "keep").strip().lower()
    if emulation != "keep" and emulation not in iehost.EMULATION_LEVELS:
        raise ApiError(f"表示モード (emulation) は keep / {' / '.join(iehost.EMULATION_LEVELS)} のいずれかで指定してください")
    # which screen started it: only an easy-started recording is stopped automatically by the easy
    # screen when its recording browser closes (kept on the server so a page reload knows it too)
    origin = str(body.get("origin") or "advanced").strip().lower()
    if origin not in _ORIGINS:
        raise ApiError(f"origin は {' / '.join(_ORIGINS)} のどちらかで指定してください")

    if state.recorder.running:
        raise ApiError("すでに記録中です。先に [記録停止] を押してください。", status=409)
    if state.recorder.command_builder is _default_command_builder() and not mitmproxy_available():
        raise ApiError(
            "mitmproxy がインストールされていないため記録できません。コマンドプロンプトで "
            'pip install "reqrec[record]" を実行してから GUI を再起動してください。', status=400,
        )
    _require_iehost(state)
    try:
        port = find_free_port(RECORD_LISTEN_HOST, preferred=8080, avoid=(state.port,))
    except OSError as exc:
        raise ApiError(f"記録用の空きポートが見つかりません: {exc}", status=500) from exc

    out = os.path.join(state.subdir("recordings"), _timestamp_name("rec", ".json"))
    proxy_address = _proxy_address(port)
    with state.lock:
        state.close_browser()  # a browser left over from an earlier session must not record into the new one
        try:
            status = state.recorder.start(out, port=port, hosts=hosts, extra_args=list(HTTPS_PASSTHROUGH_ARGS))
        except RecorderError as exc:
            raise ApiError(str(exc), status=400) from exc
        state.record_append = append
        state.record_origin = origin
    time.sleep(0.15)  # give an immediately failing child (port in use) the chance to report
    status = state.recorder.status()
    browser_result: Optional[dict[str, Any]] = None
    warnings: list[str] = []
    if status.get("running"):
        # mitmdump needs a second or two before it accepts connections; a browser pointed at it
        # earlier shows 「ページを表示できません」 for the first page.  Wait without the lock.
        wait = getattr(state.recorder, "wait_until_listening", None)
        if wait is not None and not wait(timeout=PROXY_READY_TIMEOUT):
            failed = state.recorder.status()
            _abandon_start(state, out)
            tail = (failed.get("stderr_tail") or "").strip().splitlines()
            detail = failed.get("error") or (tail[-1] if tail else "時間内に待ち受けを開始しませんでした")
            raise ApiError(f"記録用プロキシを起動できませんでした: {detail}", status=500, kind=ERROR_KIND_PROXY)
        # The recorder is up: point the recording browser at it.  Document mode first (a per-exe
        # HKCU value read by the engine at start-up), then the process itself.
        with state.lock:
            if not state.recorder.running or os.path.abspath(state.recorder.out or "") != os.path.abspath(out):
                raise ApiError("記録用ブラウザを開く前に記録が止まりました。もう一度 [記録をはじめる] を押してください。", status=409)
            level = iehost.EMULATION_LEVELS.get(emulation)
            if emulation == "keep":
                pass  # かんたん画面: whatever 表示モード was chosen in 詳細設定 stays; the registry is not touched
            elif level is None:
                # 既定 (IE7 相当): nothing to write.  Only a value left by an earlier non-default
                # choice is removed, and failing to remove it never blocks the recording.
                try:
                    if iehost.get_emulation() is not None:
                        iehost.set_emulation(None)
                except Exception as exc:
                    warnings.append(f"表示モードの設定を既定に戻せませんでした（記録は続けます）: {exc}")
            else:
                try:
                    iehost.set_emulation(level)
                except Exception as exc:
                    _abandon_start(state, out)
                    raise ApiError(f"記録用ブラウザの表示モードを設定できませんでした: {exc}", status=500,
                                   kind=ERROR_KIND_EMULATION) from exc
            try:
                proc = _launch_iehost(state, proxy_address, start_url)
            except ApiError:
                _abandon_start(state, out)
                raise
            browser_result = _browser_payload(proc)
    return _ok(
        out=os.path.basename(out),
        out_path=out,
        port=port,
        proxy_address=proxy_address,
        status=status,
        browser=browser_result,
        emulation=emulation,
        origin=origin,
        warnings=warnings,
        self_excluded_hosts=sorted(gui_netlocs(state.host, state.port, flask_request.host)),
    )


def _default_command_builder():
    return build_command


@bp.get("/api/record/status")
def record_status() -> Response:
    state = get_state()
    status = state.recorder.status()
    status["mitmproxy_available"] = mitmproxy_available()
    status["browser"] = _browser_status(state)
    status["origin"] = state.record_origin
    return jsonify(status)


@bp.post("/api/record/stop")
def record_stop() -> Response:
    state = get_state()
    body = _json_body(required=False)
    append = _bool(body.get("append"), state.record_append)
    discard = _bool(body.get("discard"), False)
    with state.lock:
        was_running = state.recorder.running
        if not was_running and state.recorder.out is None:
            raise ApiError("記録は開始されていません", status=409)
        # The recording browser goes first so its in-flight requests reach the proxy before mitmdump
        # flushes and exits; ``close_browser`` never raises and forgets the process either way.
        had_browser = state.browser is not None
        browser_exit_code = state.close_browser(timeout=5.0)
        exit_code = state.recorder.stop()
        state.record_origin = None
        if discard:
            # [やめる]: nothing is loaded (the recording already loaded stays as it was) and the
            # half-made file is removed so it does not show up in 「作業フォルダ内のファイル」; the
            # recorder forgets it so 詳細設定 does not say 「記録は保存されました」 for a deleted file.
            removed = _remove_quietly(state.recorder.out)
            _forget_recording(state)
            return _ok(discarded=True, removed=removed, exit_code=exit_code,
                       browser_exit_code=browser_exit_code, recording=state.recording_summary())
        out_path = state.recorder.out
        try:
            recording = state.recorder.load_recording()
        except RecorderError as exc:
            if not (out_path and not os.path.exists(out_path) and exit_code is not None):
                raise ApiError(str(exc), status=400, exit_code=exit_code,
                               browser_exit_code=browser_exit_code, stderr_tail=state.recorder.status()["stderr_tail"]) from exc
            # The addon writes the file after the first response only, and on Windows the stop
            # (CTRL_BREAK) ends mitmdump before its final flush: no file = nothing was recorded.
            recording = Recording(flows=[], meta={})
        if not recording.flows:
            if had_browser:
                message = (
                    "何も記録されませんでした。記録用ブラウザでページを開く前にブラウザが閉じられたか、"
                    "https:// のページ（記録されません）だけを開いた可能性があります。"
                    "もう一度 [記録をはじめる] を押し、http:// のページを開いて操作してください。"
                )
            else:
                message = (
                    "何も記録されませんでした。記録用ブラウザが開く前に記録が止まった可能性があります。"
                    "もう一度 [記録をはじめる] を押し、http:// のページを開いて操作してください。"
                )
            raise ApiError(
                message,
                status=400, exit_code=exit_code, browser_exit_code=browser_exit_code,
                out=os.path.basename(state.recorder.out or ""), empty=True,
            )
        summary = _apply_loaded(state, recording, [f"recordings/{os.path.basename(state.recorder.out or '')}"], append, from_gui_recorder=True)
    summary.update(out=os.path.basename(state.recorder.out or ""), out_path=state.recorder.out, exit_code=exit_code,
                   browser_exit_code=browser_exit_code)
    return _ok(**summary)


# --------------------------------------------------------------------------- recordings (files)

@bp.post("/api/recordings/upload")
def recordings_upload() -> Response:
    state = get_state()
    files = flask_request.files.getlist("files") or flask_request.files.getlist("file")
    files = [f for f in files if f and f.filename]
    if not files:
        raise ApiError("ファイルが選択されていません (.har / .json)")
    append = _bool(flask_request.form.get("append"), False)
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
    recording = load_sources(saved)
    with state.lock:
        summary = _apply_loaded(state, recording, display, append, from_gui_recorder=False)
    summary["saved"] = [os.path.basename(p) for p in saved]
    return _ok(**summary)


@bp.get("/api/recordings")
def recordings_list() -> Response:
    state = get_state()
    files = [_file_entry_with_flows(e) for sub in ("recordings", "uploads") for e in state.list_files(sub, RECORDING_EXTENSIONS)]
    return jsonify({"files": files, "current": state.recording_summary()})


@bp.post("/api/recordings/open")
def recordings_open() -> Response:
    state = get_state()
    body = _json_body()
    names = body.get("names")
    if isinstance(names, (str, dict)):
        names = [names]
    if not isinstance(names, list) or not names:
        raise ApiError("開くファイルを選択してください")
    append = _bool(body.get("append"), False)
    paths: list[str] = []
    display: list[str] = []
    for item in names:
        path, label = _resolve_recording_name(state, item)
        paths.append(path)
        display.append(label)
    recording = load_sources(paths)
    from_recorder = all(label.startswith("recordings/") for label in display)
    with state.lock:
        summary = _apply_loaded(state, recording, display, append, from_gui_recorder=from_recorder)
    return _ok(**summary)


@bp.post("/api/recordings/clear")
def recordings_clear() -> Response:
    state = get_state()
    state.clear_recording()
    return _ok(recording=state.recording_summary())


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

@bp.post("/api/generate")
def api_generate() -> Response:
    state = get_state()
    body = _json_body(required=False)
    plan_opts, gen_opts = _options_from_body(body)
    with state.lock:
        plan = _rebuild_plan(state, plan_opts)
        try:
            code = generate(plan, gen_opts)
        except Exception as exc:
            current_app.logger.exception("generate failed")
            raise ApiError(f"コード生成に失敗しました: {exc}", status=500) from exc
        state.gen_options = gen_opts
        state.last_code = code
        secrets = _secrets_of(plan)
        state.last_secrets = secrets
        recording = state.require_recording()
        payload = {
            "code": code,
            "summary": format_plan_summary(plan, flows_total=len(recording.flows)),
            "warnings": list(plan.warnings),
            "secrets": secrets,
            "env_vars": [s["env_var"] for s in secrets],
            "steps": len(plan.steps),
            "final_step_index": plan.final_step_index,
            "auth": to_plain(plan.auth) if plan.auth is not None else None,
            "suggested_name": _suggest_script_name(plan),
            "plan_options": options_to_plain(plan_opts),
            "gen_options": options_to_plain(gen_opts),
        }
    return jsonify(payload)


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
_INFO_NOTE_MARKERS = ("UTF-8 以外の文字コード", "looks like a credential")


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
                f"(残りの {m.group(3)} 手順は使っていません)。詳細設定の「ステップ数の上限」で変えられます。")),
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
        raise ApiError("保存するコードがありません。先に [生成] を押してください。")
    name = _script_name(body.get("name"))
    path = state.path_in("scripts", name, "スクリプト名")
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code if code.endswith("\n") else code + "\n")
    except OSError as exc:
        raise ApiError(f"スクリプトを保存できません: {exc}", status=500) from exc
    state.last_script_name = name
    return _ok(name=name, path=path, size=os.path.getsize(path), download_url=f"/api/scripts/{name}/download")


@bp.get("/api/scripts")
def scripts_list() -> Response:
    state = get_state()
    files = [{k: v for k, v in e.items() if k != "path"} for e in state.list_files("scripts", {".py"})]
    return jsonify({"files": files, "last": state.last_script_name})


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


@bp.post("/api/browser/open")
def browser_open() -> Response:
    """(Re)open the in-app recording browser of the running recording at ``{"url": ...}``.

    When it is still running nothing happens (``relaunched: false``); otherwise it is started again
    against the recorder's proxy (``relaunched: true``).  409 when nothing is being recorded.
    """
    body = _json_body(required=False)
    state = get_state()
    start_url = _iehost_start_url(body.get("url"))
    with state.lock:
        proc = state.browser
        if proc is not None and proc.poll() is None:
            return _ok(running=True, relaunched=False, browser=_browser_payload(proc))
        if not state.recorder.running:
            raise ApiError("記録が開始されていません", status=409)
        _require_iehost(state)
        port = getattr(state.recorder, "port", None) or state.recorder.status().get("port")
        if not port:
            raise ApiError("記録用プロキシのポートが分かりません", status=500)
        state.close_browser(timeout=2.0)  # an exited process object is dropped before the new one starts
        proc = _launch_iehost(state, _proxy_address(int(port)), start_url)
    return _ok(running=True, relaunched=True, browser=_browser_payload(proc))


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
    """One shot for the easy mode: analyse the loaded recording with the current (or given)
    options, generate the script and save it under ``scripts/``.

    Body (all optional): ``{"name": "...", "plan_options": {...}, "gen_options": {...}}``.
    Returns what the easy screen shows: file name / path / download URL, step count, the final
    step's URL, warnings, the secrets the user must type before running, and the code itself.
    """
    state = get_state()
    body = _json_body(required=False)
    plan_opts, gen_opts = _options_from_body(body)
    with state.lock:
        plan = _rebuild_plan(state, plan_opts)
        if not plan.steps:
            raise ApiError(
                "スクリプトにできる通信が記録にありませんでした。記録中に記録用ブラウザで"
                " http:// のサイトの画面を開いたかを確認してください。",
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
        }
    return _ok(**payload)


# ===== former reqrec/webapp/__init__.py: app factory (create_app / run_gui) and the security hook =====
# Flask based no-code GUI for reqrec.  Contract: DESIGN.md §13.6.
#
# ``create_app(workdir)`` builds the Flask application; ``run_gui`` starts it (and opens a browser).
#
# Security model (the user's browser visits arbitrary sites while this GUI runs):
#
# * every ``POST`` / ``PUT`` / ``DELETE`` must carry ``X-Reqrec-Token`` equal to a per-process random
#   token the page receives through the template (``<body data-token>``);
# * every request's ``Host`` must be the bound address / ``127.0.0.1`` / ``localhost`` / ``::1``
#   (DNS-rebinding guard), and a state-changing request with an ``Origin`` header must come from the
#   page itself;
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

def create_app(workdir: str, **config: Any) -> Flask:
    """Build the Flask app.

    ``config`` may hold ``host`` / ``port`` (what the server binds; used for the Host check and
    for excluding the GUI's own traffic from recordings), ``token`` (per-process CSRF token;
    generated when omitted), ``recorder`` / ``runner`` (test doubles) and any upper-case Flask
    config key (``MAX_CONTENT_LENGTH``, ``TESTING``, ...).
    """
    host = str(config.pop("host", "127.0.0.1") or "127.0.0.1")
    port = int(config.pop("port", 8765) or 8765)
    token = config.pop("token", None)
    recorder = config.pop("recorder", None)
    runner = config.pop("runner", None)

    # The page is the single template ``GUI_HTML`` (CSS / JS inlined): no templates/ or static/ folder
    # and no static route.  ``root_path`` is given so Flask never searches for the import name.  The
    # template is served by name from memory, so Jinja compiles it once per app and caches it
    # (``render_template_string`` would compile the 140 KB page again on every ``GET /``).
    app = Flask("reqrec.gui", root_path=os.path.dirname(os.path.abspath(__file__)), template_folder=None, static_folder=None)
    app.jinja_loader = DictLoader({_GUI_TEMPLATE: GUI_HTML})
    app.config.update(
        MAX_CONTENT_LENGTH=_DEFAULT_MAX_UPLOAD,
        JSON_SORT_KEYS=False,
        SEND_FILE_MAX_AGE_DEFAULT=0,
        TEMPLATES_AUTO_RELOAD=False,
    )
    for key, value in config.items():
        app.config[key.upper()] = value
    app.json.ensure_ascii = False  # Japanese stays readable in responses / logs
    app.json.sort_keys = False

    state = AppState(workdir, host=host, port=port, token=token, recorder=recorder, runner=runner)
    app.extensions["reqrec"] = state
    app.config.update(REQREC_WORKDIR=state.workdir, REQREC_TOKEN=state.token, REQREC_HOST=host, REQREC_PORT=port)

    app.register_blueprint(bp)

    # ---------------------------------------------------------------- security hook
    @app.before_request
    def _guard():  # type: ignore[no-untyped-def]
        if not host_allowed(flask_request.host, host):
            return jsonify({"error": f"この Host ヘッダーからのアクセスは許可されていません: {flask_request.host}"}), 403
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
    """Stop the children (recorder, recording browser, script run)."""
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

.steps-nav {
  display: flex; align-items: center; gap: .25rem;
  padding: .25rem 1.25rem .6rem; overflow-x: auto;
}
.nav-step {
  display: inline-flex; align-items: center; gap: .5rem;
  padding: .4rem .9rem; border-radius: 999px;
  border: 1px solid transparent; background: transparent; cursor: pointer;
  color: var(--text-muted); font-weight: 600; white-space: nowrap;
}
.nav-step:hover { background: var(--surface-2); color: var(--text); }
.nav-step.active { background: var(--primary-soft); color: var(--primary); border-color: #c7d9f6; }
.nav-step.done .nav-num { background: var(--ok); }
.nav-num {
  display: inline-flex; align-items: center; justify-content: center;
  width: 22px; height: 22px; border-radius: 50%;
  background: var(--text-faint); color: #fff; font-size: .8rem; font-weight: 700;
}
.nav-step.active .nav-num { background: var(--primary); }
.nav-badge { font-size: .75rem; background: var(--surface); border: 1px solid var(--border); border-radius: 999px; padding: 0 .5em; color: var(--text-muted); }
.nav-arrow { color: var(--border-strong); }

/* ------------------------------------------------------------------ layout */
.content { max-width: 1400px; margin: 0 auto; padding: 1.25rem 1.25rem 3rem; }
.panel { display: none; }
.panel.active { display: block; animation: fade .15s ease-out; }
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

/* ------------------------------------------------------------------ record panel */
.rec-status { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: .75rem 1rem; border-radius: 8px; background: var(--surface-2); border: 1px solid var(--border); }
.rec-indicator { display: flex; align-items: center; gap: .5rem; font-weight: 700; }
.rec-light { width: 12px; height: 12px; border-radius: 50%; background: var(--text-faint); }
.rec-indicator.live .rec-light { background: var(--danger); animation: pulse 1.2s infinite; }
.rec-indicator.live { color: var(--danger); }
.rec-count { display: flex; align-items: baseline; gap: .4rem; }
.rec-count-num { font-size: 2rem; font-weight: 800; color: var(--primary); font-variant-numeric: tabular-nums; }
.rec-count-label { color: var(--text-muted); }
details summary { cursor: pointer; color: var(--text-muted); font-size: .9rem; margin-top: .5rem; }

/* ------------------------------------------------------------------ load panel */
.dropzone {
  position: relative; border: 2px dashed var(--border-strong); border-radius: var(--radius);
  padding: 1.5rem 1rem; text-align: center; background: var(--surface-2); color: var(--text-muted);
  margin-bottom: .75rem; transition: border-color .12s, background .12s;
}
.dropzone.over { border-color: var(--primary); background: var(--primary-soft); }
.dropzone input[type=file] { position: absolute; inset: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
.dropzone p { margin: .2rem 0; pointer-events: none; }

/* ------------------------------------------------------------------ tables */
.table-wrap { overflow: auto; max-height: 62vh; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); }
.table-wrap.short { max-height: 40vh; }
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
.env-list { margin: .25rem 0; padding-left: 1.2rem; }
.summary-text { white-space: pre-wrap; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: .6rem .8rem; font-size: .88rem; margin-top: .75rem; }
.auth-pill { display: inline-block; padding: .05em .5em; border-radius: 999px; background: var(--warn-soft); color: #5c3a00; border: 1px solid #f1d49a; font-weight: 700; font-size: .8rem; }

/* ------------------------------------------------------------------ code / console */
pre.code, pre.console {
  margin: 0; padding: .75rem .9rem; border-radius: 8px; overflow: auto;
  font-family: var(--mono); font-size: .8rem; line-height: 1.5; tab-size: 4;
  background: #0f172a; color: #e2e8f0; max-height: 70vh; white-space: pre;
}
pre.code .placeholder { color: #94a3b8; font-style: italic; }
pre.console { background: #111827; color: #d1d5db; min-height: 8rem; max-height: 40vh; white-space: pre-wrap; word-break: break-all; }
pre.console.stderr { color: #fecaca; }
pre.console.small { min-height: 3rem; max-height: 14rem; font-size: .75rem; }
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
  .nav-label { display: none; }
  .nav-step.active .nav-label { display: inline; }
  .col-ref, th.col-ref { display: none; }
  .drawer { width: 100vw; }
}

/* ------------------------------------------------------------------ かんたん画面 (既定) */
.mode-toggle { flex: none; white-space: nowrap; }
#panel-easy { display: none; }
body.easy-mode #panel-easy { display: block; animation: fade .15s ease-out; }
body.easy-mode .steps-nav { display: none; }
body.easy-mode .panel { display: none !important; }
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

/* ------------------------------------------------------------------ 記録用ブラウザ (IE エンジン) */
select.w-full { width: 100%; max-width: 100%; }
#rec-emulation + .hint { margin-top: .25rem; }
.easy-ready li.bad { color: #7a1e14; }
{% endraw %}
</style>
</head>
<body data-token="{{ token }}"
      data-mitm-available="{{ 'true' if mitmproxy_available else 'false' }}"
      data-iehost-available="{{ 'true' if iehost and iehost.available else 'false' }}"
      data-iehost-reason="{{ (iehost.reason if iehost and iehost.reason else '') }}">

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
    <button type="button" id="mode-toggle" class="btn tiny ghost mode-toggle" title="フィルタ設定や通信の一覧など、細かい設定を表示します">詳細設定を表示</button>
  </div>
  <nav class="steps-nav" id="nav" aria-label="作業の流れ">
    <button type="button" class="nav-step active" data-panel="record"><span class="nav-num">1</span><span class="nav-label">記録</span><span class="nav-badge" id="badge-record" hidden></span></button>
    <span class="nav-arrow" aria-hidden="true">→</span>
    <button type="button" class="nav-step" data-panel="load"><span class="nav-num">2</span><span class="nav-label">読み込み</span><span class="nav-badge" id="badge-load" hidden></span></button>
    <span class="nav-arrow" aria-hidden="true">→</span>
    <button type="button" class="nav-step" data-panel="steps"><span class="nav-num">3</span><span class="nav-label">ステップ</span><span class="nav-badge" id="badge-steps" hidden></span></button>
    <span class="nav-arrow" aria-hidden="true">→</span>
    <button type="button" class="nav-step" data-panel="code"><span class="nav-num">4</span><span class="nav-label">コード</span><span class="nav-badge" id="badge-code" hidden></span></button>
    <span class="nav-arrow" aria-hidden="true">→</span>
    <button type="button" class="nav-step" data-panel="run"><span class="nav-num">5</span><span class="nav-label">実行</span><span class="nav-badge" id="badge-run" hidden></span></button>
  </nav>
</header>

<main class="content">

<!-- ===================================================== かんたん画面 (既定) -->
<section id="panel-easy" class="easy" aria-labelledby="h-easy">

  {% if not mitmproxy_available %}
  <div class="notice warn">
    <strong>記録機能の準備ができていません。</strong> 管理者（または IT 担当）に「mitmproxy が入っていない」と伝えてください。
    コマンドプロンプトで <code>pip install "reqrec[record]"</code> を実行してから、この画面を開き直すと使えるようになります。
  </div>
  {% endif %}

  <!-- 待機中 -->
  <div class="easy-stage" id="easy-idle">
    <div class="easy-hero">
      <h1 id="h-easy">サイトの操作を記録して、自動取得スクリプトを作ります</h1>
      <p class="lead">やることは 3 つだけです。ポートやプロキシなどの設定はすべて自動で行います。Windows の設定や証明書は変更しません。</p>
      <ol class="easy-flow">
        <li><span class="easy-flow-num">1</span><div><strong>記録をはじめる</strong> を押す<br><span class="hint">記録用のブラウザが開きます (Edge の IE モードと同じエンジン)</span></div></li>
        <li><span class="easy-flow-num">2</span><div><strong>いつもどおりサイトを操作する</strong><br><span class="hint">ログイン → 一覧を開く → 欲しいデータの画面まで</span></div></li>
        <li><span class="easy-flow-num">3</span><div><strong>記録をおわる</strong> を押す<br><span class="hint">ブラウザを閉じるだけでスクリプトが自動でできあがります</span></div></li>
      </ol>
    </div>
    <div class="card easy-card">
      <div class="form-grid compact">
        <label for="easy-url">開くサイトのアドレス <span class="hint">(任意)</span></label>
        <div><input id="easy-url" type="text" class="w-full" placeholder="例: http://kanri/  または  http://192.168.1.10/seisan/" autocomplete="url">
          <div class="hint">空欄のままでも構いません。開いたブラウザのアドレス欄にサイトのアドレスを入れて開けます。</div></div>
      </div>
      <div class="easy-actions">
        <button type="button" id="easy-start" class="btn primary xl" {% if not (mitmproxy_available and iehost and iehost.available) %}disabled{% endif %}>● 記録をはじめる</button>
      </div>
      <ul class="easy-ready" id="easy-ready" aria-live="polite"></ul>
      <div class="easy-loaded" id="easy-loaded" hidden>
        <span class="hint">すでに読み込まれている記録があります:</span>
        <button type="button" id="easy-build-loaded" class="btn">読み込み済みの記録 (<span id="easy-loaded-count">0</span> 件) からスクリプトを作る</button>
      </div>
    </div>
  </div>

  <!-- 記録中 -->
  <div class="easy-stage" id="easy-recording" hidden>
    <div class="card easy-card easy-live-card">
      <div class="easy-live"><span class="rec-light"></span><span>記録中</span></div>
      <div class="easy-count"><span class="easy-count-num" id="easy-count">0</span><span class="easy-count-label">件の通信を記録しました</span></div>
      <p class="easy-guide">記録用のブラウザが開きました。そのウィンドウでいつもどおりサイトを操作してください。<br>終わったら、ブラウザの赤い <strong>[記録をおわる]</strong> か、この画面の <strong>[記録をおわる]</strong> を押します。</p>
      <div class="notice info" id="easy-browser-note" hidden></div>
      <div class="notice error" id="easy-rec-error" hidden></div>
      <div class="easy-actions">
        <button type="button" id="easy-stop" class="btn danger xl">■ 記録をおわる</button>
        <button type="button" id="easy-open-browser" class="btn">ブラウザをもう一度開く</button>
        <button type="button" id="easy-cancel" class="btn ghost">やめる (記録を破棄)</button>
      </div>
      <p class="hint">件数が増えないときは、記録用のブラウザ (タイトルに「記録中」と付いた窓) でサイトを開いているか確認してください。https:// のページは記録されません。</p>
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

<!-- ===================================================== 1 記録 -->
<section id="panel-record" class="panel active" aria-labelledby="h-record">
  <div class="panel-head">
    <h1 id="h-record">1. ブラウザの通信を記録する</h1>
    <p class="lead">[記録開始] を押すと記録用ブラウザ (Edge の IE モードと同じエンジン) が開きます。その窓で普段どおりにサイトを操作すると、http:// の通信がすべて記録されます (https:// は記録しません)。別窓やダイアログで開いた画面も、記録用ブラウザのタブとして記録されます。操作が終わったら [記録停止して読み込む] を押します。<br>
    すでに HAR ファイル (IE の F12 開発者ツールで保存した通信ログ) がある場合は、この手順を飛ばして「<a href="#" data-goto="load">2 読み込み</a>」へ進んでください。</p>
  </div>

  {% if not mitmproxy_available %}
  <div class="notice warn">
    <strong>mitmproxy が見つかりません。</strong> 記録機能を使うには、コマンドプロンプト (ターミナル) で
    <code>pip install "reqrec[record]"</code> を実行し、GUI を再起動してください。HAR ファイルの読み込みはそのまま使えます。
  </div>
  {% endif %}
  {% if not (iehost and iehost.available) %}
  <div class="notice warn" id="rec-unavailable">
    <strong>記録用ブラウザ (IE エンジン) が使えないため、この PC では記録できません。</strong> {{ iehost.reason if iehost and iehost.reason else '' }}
    HAR ファイルの読み込み以降はそのまま使えます。
  </div>
  {% endif %}

  <div class="grid-2">
    <div class="card">
      <h2>記録の設定</h2>
      <div class="form-grid">
        <label for="rec-hosts">記録するサイト (ホスト名)</label>
        <div><input id="rec-hosts" type="text" placeholder="例: example.co.jp, api.example.co.jp (空欄 = すべて記録)" class="w-full">
          <div class="hint">カンマ区切りで複数指定できます。サブドメインも含めて記録されます。空欄なら開いたサイトをすべて記録します。</div></div>

        <label>追加モード</label>
        <div><label class="check"><input id="rec-append" type="checkbox"><span>停止したとき、すでに読み込んである記録に<strong>追加して結合</strong>する</span></label></div>

        <label for="rec-start-url">最初に開くアドレス</label>
        <div><input id="rec-start-url" type="text" class="w-full" placeholder="例: http://kanri/  (空欄なら空のページで開きます)" autocomplete="url"></div>

        <label for="rec-emulation">表示モード (記録用ブラウザ)</label>
        <div>
          <select id="rec-emulation" class="w-full">
            <option value="keep">変更しない (今の設定のまま)</option>
            <option value="default">既定 (IE7 互換表示、レジストリに書き込まない)</option>
            <option value="ie8">IE8 相当</option>
            <option value="ie11">IE11 相当 (ページの指定に従う)</option>
            <option value="ie11_force">IE11 強制</option>
          </select>
          <div class="hint">Edge の IE モードで表示が崩れないサイトは「既定」のままで構いません。既定以外は、この記録用ブラウザだけに効く設定をユーザーのレジストリ (HKCU) に書き込みます。選んだ表示モードは次回以降も (かんたん画面でも) そのまま使われます。</div>
        </div>

      </div>
      <div class="actions">
        <button type="button" id="btn-rec-start" class="btn primary" {% if not (mitmproxy_available and iehost and iehost.available) %}disabled{% endif %}>● 記録開始</button>
        <button type="button" id="btn-rec-stop" class="btn danger" disabled>■ 記録停止して読み込む</button>
      </div>
      <p class="hint">※ この GUI 自身への通信 (<code>{{ gui_address }}</code>) は記録から自動的に除外されます。</p>
    </div>

    <div class="card">
      <h2>記録の状態</h2>
      <div class="rec-status">
        <div class="rec-indicator" id="rec-indicator"><span class="rec-light"></span><span id="rec-state-text">停止中</span></div>
        <div class="rec-count"><span class="rec-count-num" id="rec-flow-count">0</span><span class="rec-count-label">件のリクエストを記録</span></div>
      </div>
      <dl class="kv">
        <dt>プロキシのアドレス</dt><dd id="rec-proxy-address">—</dd>
        <dt>出力ファイル</dt><dd id="rec-out">—</dd>
        <dt>記録用ブラウザ</dt><dd id="rec-browser-state">—</dd>
      </dl>
      <div id="rec-error" class="notice error" hidden></div>
      <details>
        <summary>プロキシのログを表示</summary>
        <pre class="console small" id="rec-log"></pre>
      </details>
    </div>
  </div>

</section>

<!-- ===================================================== 2 読み込み -->
<section id="panel-load" class="panel" aria-labelledby="h-load">
  <div class="panel-head">
    <h1 id="h-load">2. 記録ファイルを読み込む</h1>
    <p class="lead">「1 記録」で保存したファイルのほか、IE の F12 開発者ツール (IEChooser.exe で IE モードのタブを選ぶ → ネットワーク → 「HAR としてエクスポート」) で保存した <strong>.har</strong> も読み込めます。<br>
    <strong>別タブで開いた画面</strong>を HAR で記録した場合はタブごとに HAR を保存し、複数ファイルをまとめて選ぶか「追加して結合」で読み込むと 1 つの流れとして扱えます。</p>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>ファイルを選んで読み込む</h2>
      <div class="dropzone" id="dropzone">
        <input id="file-input" type="file" multiple accept=".har,.json">
        <p>ここにファイルをドラッグ＆ドロップするか、クリックして選択 (.har / .json、複数可)</p>
        <p class="hint" id="file-chosen">ファイルが選ばれていません</p>
      </div>
      <label class="check"><input id="append-toggle" type="checkbox"><span><strong>追加して結合</strong>する (読み込み済みの記録を置き換えず、時刻順に結合します)</span></label>
      <div class="actions">
        <button type="button" id="btn-upload" class="btn primary" disabled>読み込む</button>
      </div>
    </div>

    <div class="card">
      <h2>現在読み込まれている記録</h2>
      <dl class="kv">
        <dt>ファイル</dt><dd id="cur-sources">(なし)</dd>
        <dt>リクエスト数</dt><dd id="cur-flows">0</dd>
        <dt>ホスト</dt><dd id="cur-hosts">—</dd>
      </dl>
      <div class="actions">
        <button type="button" id="btn-goto-steps" class="btn primary" disabled>3 ステップへ進む →</button>
        <button type="button" id="btn-clear" class="btn ghost" disabled>記録をクリア</button>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>作業フォルダ内のファイルから開く</h2>
    <p class="hint">作業フォルダ: <code>{{ workdir }}</code> — <code>recordings/</code> (この GUI で記録したもの) と <code>uploads/</code> (読み込んだファイル)</p>
    <div class="table-wrap short">
      <table class="data" id="files-table">
        <thead><tr><th class="col-check"></th><th>ファイル名</th><th>フォルダ</th><th class="num">リクエスト数</th><th class="num">サイズ</th><th>更新日時</th></tr></thead>
        <tbody><tr><td colspan="6" class="empty">読み込み中…</td></tr></tbody>
      </table>
    </div>
    <div class="actions">
      <button type="button" id="btn-open-selected" class="btn primary" disabled>選択したファイルを開く</button>
      <button type="button" id="btn-refresh-files" class="btn ghost">一覧を更新</button>
      <span class="hint">複数選ぶと結合して開きます。「追加して結合」にチェックがあれば現在の記録にも追加します。</span>
    </div>
  </div>
</section>

<!-- ===================================================== 3 ステップ -->
<section id="panel-steps" class="panel" aria-labelledby="h-steps">
  <div class="panel-head">
    <h1 id="h-steps">3. スクリプトにするステップを選ぶ</h1>
    <p class="lead">記録したリクエストを自動で解析し、画像や解析サービスなどの不要な通信を除外して「ステップ」にまとめます。表のチェックを外す/付けると採用・除外を手動で変えられます。「結果」の列で<strong>最終的に出力したい画面 (データ) のリクエスト</strong>を選べます。行をクリックすると内容を確認できます。</p>
  </div>

  <div id="steps-empty" class="notice info">記録が読み込まれていません。「<a href="#" data-goto="record">1 記録</a>」または「<a href="#" data-goto="load">2 読み込み</a>」で記録を読み込んでください。</div>

  <div id="steps-body" hidden>
  <div class="grid-2 steps-top">
    <div class="card">
      <h2>フィルタ設定 <span class="hint">(変更すると自動で再計算します)</span></h2>
      <div class="opts">
        <label class="check"><input type="checkbox" class="opt" data-opt="keep_static"><span>静的ファイル (画像 / CSS / JS / フォント) も残す</span></label>
        <label class="check"><input type="checkbox" class="opt" data-opt="keep_trackers"><span>トラッカー / 解析サービスへの通信も残す</span></label>
        <label class="check"><input type="checkbox" class="opt" data-opt="keep_all"><span>すべて残す (自動のノイズ除外を無効にする)</span></label>
        <label class="check"><input type="checkbox" class="opt" data-opt="collapse_redirects" checked><span>リダイレクトを 1 つのステップに統合する</span></label>
        <label class="check"><input type="checkbox" class="opt" data-opt="detect_loops" checked><span>ループ (ページ送りなど) を検出してまとめる</span></label>
        <label class="check"><input type="checkbox" class="opt" data-opt="redact_secrets" checked><span>パスワードなどの秘密情報を環境変数から読む (スクリプトに書き込まない)</span></label>
        <label class="check"><input type="checkbox" class="opt" data-opt="detect_auth" checked><span>HTTP 認証 (Windows 統合認証 NTLM / Basic / Digest) のやり取りを検出して統合する</span></label>
      </div>
      <div class="form-grid compact">
        <label for="opt-include-hosts">このホストだけ採用</label>
        <div><input id="opt-include-hosts" type="text" class="opt-text w-full" data-opt="include_hosts" placeholder="例: example.co.jp (空欄 = 制限なし)"></div>
        <label for="opt-exclude-hosts">このホストは除外</label>
        <div><input id="opt-exclude-hosts" type="text" class="opt-text w-full" data-opt="exclude_hosts" placeholder="例: cdn.example.com, fonts.googleapis.com"></div>
        <label for="opt-min-len">依存検出する値の最小文字数</label>
        <div><input id="opt-min-len" type="number" min="1" value="4" class="opt-num w-s" data-opt="min_value_length"></div>
        <label for="opt-max-steps">ステップ数の上限</label>
        <div><input id="opt-max-steps" type="number" min="1" class="opt-num w-s" data-opt="max_steps" placeholder="なし"></div>
      </div>
    </div>

    <div class="card">
      <h2>解析結果</h2>
      <div class="stats">
        <div class="stat"><span class="stat-num" id="sum-steps">0</span><span class="stat-label">ステップ</span></div>
        <div class="stat"><span class="stat-num" id="sum-kept">0</span><span class="stat-label">採用リクエスト</span></div>
        <div class="stat"><span class="stat-num" id="sum-dropped">0</span><span class="stat-label">除外</span></div>
        <div class="stat"><span class="stat-num" id="sum-vars">0</span><span class="stat-label">自動抽出する値</span></div>
      </div>
      <dl class="kv">
        <dt>結果にするステップ</dt><dd id="sum-final">最後のステップ (既定)　<button type="button" id="btn-final-clear" class="btn tiny ghost" hidden>指定を解除</button></dd>
        <dt>HTTP 認証</dt><dd id="sum-auth">検出されませんでした</dd>
        <dt>定数 / 秘密情報</dt><dd id="sum-constants">なし</dd>
        <dt>ループ</dt><dd id="sum-loops">なし</dd>
        <dt>自動除外</dt><dd id="sum-self">—</dd>
      </dl>
      <div id="sum-warnings-wrap" hidden>
        <h3>警告 <span class="hint">(生成されるスクリプトが期待どおり動かない可能性がある点)</span></h3>
        <ul class="warnings" id="sum-warnings"></ul>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="table-toolbar">
      <h2>リクエスト一覧 <span class="hint" id="table-count"></span></h2>
      <div class="toolbar-right">
        <input id="table-filter" type="search" placeholder="URL / ホスト / メソッドで絞り込み" class="w-l">
        <label class="check"><input id="show-dropped" type="checkbox" checked><span>除外された行も表示</span></label>
        <button type="button" id="btn-replan" class="btn ghost">再計算</button>
        <button type="button" id="btn-goto-code" class="btn primary">4 コードへ進む →</button>
      </div>
    </div>
    <p class="hint">☑ = スクリプトに採用　/　◉ 結果 = スクリプトの最後に出力するデータとして使うリクエスト　/　灰色の行 = 除外 (理由を「判定」列に表示)　/　行をクリック = リクエストとレスポンスの内容を表示</p>
    <div class="table-wrap">
      <table class="data flows">
        <thead>
          <tr>
            <th class="col-check" title="チェック = スクリプトに採用">採用</th>
            <th class="col-radio" title="最終結果として出力するリクエスト">結果</th>
            <th class="col-step">ステップ</th>
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
  </div>
</section>

<!-- ===================================================== 4 コード -->
<section id="panel-code" class="panel" aria-labelledby="h-code">
  <div class="panel-head">
    <h1 id="h-code">4. スクリプトを生成する</h1>
    <p class="lead">選んだステップから、<code>requests</code> と <code>BeautifulSoup</code> だけで動く Python スクリプトを生成します。生成後に保存すると「5 実行」から実行でき、ダウンロードして別の PC で動かすこともできます (必要なもの: Python 3.8 以上と <code>pip install requests beautifulsoup4</code>)。</p>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>生成オプション</h2>
      <div class="form-grid compact">
        <label for="gopt-parser">HTML パーサー</label>
        <div><select id="gopt-parser" class="gopt" data-gopt="html_parser"><option value="html.parser" selected>html.parser (標準・追加インストール不要)</option><option value="lxml">lxml (高速・pip install lxml が必要)</option></select></div>
        <label for="gopt-delay">ステップ間の待ち時間 (秒)</label>
        <div><input id="gopt-delay" type="number" min="0" step="0.1" value="0" class="gopt w-s" data-gopt="delay"> <span class="hint">サーバーに負荷をかけないための間隔</span></div>
        <label for="gopt-timeout">タイムアウト (秒)</label>
        <div><input id="gopt-timeout" type="number" min="1" step="1" value="30" class="gopt w-s" data-gopt="timeout"></div>
      </div>
      <div class="opts">
        <label class="check"><input type="checkbox" class="gopt" data-gopt="comments" checked><span>日本語の説明コメントを入れる</span></label>
        <label class="check"><input type="checkbox" class="gopt" data-gopt="strict_status"><span>記録時と違うステータスコードが返ったらエラーにする (厳格モード)</span></label>
      </div>
      <div class="actions">
        <button type="button" id="btn-generate" class="btn primary">⚙ 生成</button>
      </div>
      <div id="gen-summary" class="summary-text" hidden></div>
      <div id="gen-warnings-wrap" hidden>
        <h3>警告</h3>
        <ul class="warnings" id="gen-warnings"></ul>
      </div>
      <div id="gen-secrets-wrap" hidden>
        <h3>実行時に必要な環境変数</h3>
        <p class="hint">パスワードなどはスクリプトに書き込まれません。「5 実行」で入力するか、実行前に環境変数として設定してください。</p>
        <ul class="env-list" id="gen-secrets"></ul>
      </div>
    </div>

    <div class="card">
      <h2>保存</h2>
      <div class="form-grid compact">
        <label for="script-name">ファイル名</label>
        <div><div class="input-suffix"><input id="script-name" type="text" placeholder="scrape_example" class="w-m"><span>.py</span></div>
          <div class="hint">保存先: <code>{{ workdir }}/scripts/</code></div></div>
      </div>
      <div class="actions">
        <button type="button" id="btn-save" class="btn primary" disabled>保存</button>
        <a id="btn-download" class="btn disabled" href="#" download aria-disabled="true">ダウンロード</a>
        <button type="button" id="btn-goto-run" class="btn ghost" disabled>5 実行へ進む →</button>
      </div>
      <p class="hint" id="save-result"></p>
    </div>
  </div>

  <div class="card">
    <h2>生成されたコード <span class="hint" id="code-lines"></span></h2>
    <pre class="code" id="code-preview"><span class="placeholder">(「生成」を押すとここにスクリプトが表示されます)</span></pre>
  </div>
</section>

<!-- ===================================================== 5 実行 -->
<section id="panel-run" class="panel" aria-labelledby="h-run">
  <div class="panel-head">
    <h1 id="h-run">5. スクリプトを実行する</h1>
    <p class="lead">保存したスクリプトをこの PC の Python で実行し、出力をここに表示します。パスワードなどの秘密情報は入力欄から<strong>実行するプロセスにだけ</strong>渡され、ファイルには保存されません。</p>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>実行するスクリプト</h2>
      <div class="form-grid compact">
        <label for="run-script">スクリプト</label>
        <div><select id="run-script" class="w-full"></select> <button type="button" id="btn-refresh-scripts" class="btn tiny ghost">一覧を更新</button></div>
      </div>
      <h3>環境変数 (秘密情報)</h3>
      <div id="env-inputs" class="form-grid compact"><p class="hint">生成したスクリプトに秘密情報がなければ入力は不要です。</p></div>
      <div class="actions">
        <button type="button" id="btn-run" class="btn primary">▶ 実行</button>
        <button type="button" id="btn-run-stop" class="btn danger" disabled>■ 停止</button>
        <span id="run-state" class="run-state">待機中</span>
      </div>
    </div>

    <div class="card">
      <h2>結果を保存</h2>
      <p class="hint">最後に実行したときの標準出力 (スクリプトが print したもの) をファイルに保存します。保存先: <code>{{ workdir }}/outputs/</code></p>
      <div class="form-grid compact">
        <label for="output-name">ファイル名</label>
        <div><input id="output-name" type="text" placeholder="output.txt" class="w-m"></div>
      </div>
      <div class="actions">
        <button type="button" id="btn-save-output" class="btn" disabled>結果を保存</button>
      </div>
      <p class="hint" id="save-output-result"></p>
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>標準出力</h2>
      <pre class="console" id="run-stdout"></pre>
    </div>
    <div class="card">
      <h2>標準エラー (エラーメッセージ)</h2>
      <pre class="console stderr" id="run-stderr"></pre>
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
 * Structure:  api()  ->  per-panel modules (Record / Load / Steps / Code / Run)  ->  render functions.
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
  function fmtTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    const p = (x) => String(x).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
  function debounce(fn, ms) {
    let timer = null;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
  }
  function splitHosts(text) {
    return (text || '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
  }

  // ------------------------------------------------------------------ navigation
  const panels = {};
  $$('.panel').forEach((p) => { panels[p.id.replace('panel-', '')] = p; });
  function show(name) {
    Object.entries(panels).forEach(([k, p]) => p.classList.toggle('active', k === name));
    $$('.nav-step').forEach((b) => b.classList.toggle('active', b.dataset.panel === name));
    try { localStorage.setItem('reqrec.panel', name); } catch (e) { /* ignore */ }
    window.scrollTo({ top: 0 });
  }
  $$('.nav-step').forEach((b) => b.addEventListener('click', () => show(b.dataset.panel)));
  document.addEventListener('click', (ev) => {
    const link = ev.target.closest('[data-goto]');
    if (link) { ev.preventDefault(); show(link.dataset.goto); }
  });
  function markDone(name, done, badge) {
    const btn = $(`.nav-step[data-panel="${name}"]`);
    if (btn) btn.classList.toggle('done', !!done);
    const b = $(`#badge-${name}`);
    if (b) { if (badge) { b.textContent = badge; b.hidden = false; } else { b.hidden = true; } }
  }

  // ------------------------------------------------------------------ shared state
  const S = {
    recording: null,     // summary from the server
    plan: null,          // last /api/plan payload
    flows: [],
    exclude: new Set(),
    include: new Set(),
    finalFlowId: null,
    code: null,
    secrets: [],
    savedScript: null,
    runPoll: null,
    recPoll: null,
  };

  // ================================================================== 1 記録
  const Record = (() => {
    const btnStart = $('#btn-rec-start');
    const btnStop = $('#btn-rec-stop');
    const indicator = $('#rec-indicator');
    const stateText = $('#rec-state-text');
    const countEl = $('#rec-flow-count');
    const errEl = $('#rec-error');
    const logEl = $('#rec-log');

    // 記録は常にアプリ内の記録用ブラウザ (IE エンジン, DESIGN.md §13.12) で行う
    const IEHOST_AVAILABLE = body.dataset.iehostAvailable === 'true';
    const CAN_RECORD = IEHOST_AVAILABLE && body.dataset.mitmAvailable === 'true';
    function setEmulation(name) {  // the select starts at the 表示モード currently in the registry
      const sel = $('#rec-emulation');
      if (sel && name && sel.querySelector(`option[value="${name}"]`)) sel.value = name;
      else if (sel && name === 'custom') sel.value = 'keep';
    }

    const listeners = [];
    function subscribe(fn) { listeners.push(fn); }
    function renderBrowser(b) {
      const node = $('#rec-browser-state');
      if (!node) return;
      if (!b || !b.kind) node.textContent = '—';
      else if (b.running) node.textContent = `起動中 (PID ${b.pid})`;
      else node.textContent = '閉じられました' + (b.exit_code === null || b.exit_code === undefined ? '' : ` (終了コード ${b.exit_code})`);
    }
    function render(st) {
      listeners.forEach((fn) => { try { fn(st); } catch (e) { console.error(e); } });
      const running = !!st.running;
      indicator.classList.toggle('live', running);
      // ``out`` is cleared by the server when a recording is discarded or never really started
      // (RecorderManager.forget); a child that died on its own keeps ``out`` but reports ``error``.
      stateText.textContent = running ? '記録中…（ブラウザを操作してください）' : (st.out && !st.error ? '停止中（記録は保存されました）' : '停止中');
      countEl.textContent = st.flows ?? 0;
      $('#rec-out').textContent = st.out || '—';
      if (st.browser !== undefined) renderBrowser(st.browser);
      if (st.running && st.browser && st.browser.kind === 'iehost' && !st.browser.running && !body.classList.contains('easy-mode')) {
        setStatus('記録用ブラウザが閉じられました。[記録停止して読み込む] を押すと記録が読み込まれます。', 'info');
      }
      if (st.port) $('#rec-proxy-address').textContent = `127.0.0.1:${st.port}`;
      btnStart.disabled = running || !CAN_RECORD;
      btnStop.disabled = !running && !st.out;
      const log = [st.stdout_tail, st.stderr_tail].filter(Boolean).join('\n');
      logEl.textContent = log;
      if (st.error) { errEl.textContent = st.error; errEl.hidden = false; } else { errEl.hidden = true; }
      markDone('record', !!st.out && !running, running ? `${st.flows ?? 0} 件` : null);
      if (running && !S.recPoll) startPolling();
      if (!running && S.recPoll) stopPolling();
    }
    async function poll() {
      try { render(await api('/api/record/status')); } catch (e) { /* transient */ }
    }
    function startPolling() { if (!S.recPoll) S.recPoll = setInterval(poll, 1000); }
    function stopPolling() { clearInterval(S.recPoll); S.recPoll = null; }

    btnStart.addEventListener('click', async () => {
      btnStart.disabled = true;
      setStatus('記録プロキシと記録用ブラウザを起動しています…（初回は数秒かかります）', 'busy');
      try {
        const res = await api('/api/record/start', { method: 'POST', json: {
          hosts: splitHosts($('#rec-hosts').value),
          append: $('#rec-append').checked,
          start_url: $('#rec-start-url').value.trim(),
          emulation: $('#rec-emulation').value,
          origin: 'advanced',  // never stopped automatically by the easy screen
        } });
        $('#rec-proxy-address').textContent = res.proxy_address || '';
        render(res.status || { running: true, flows: 0, out: res.out });
        renderBrowser(res.browser);
        if (res.status && res.status.error) {
          setStatus('記録プロキシが起動できませんでした: ' + res.status.error, 'error');
        } else {
          setStatus('記録を開始しました。開いた記録用ブラウザでサイトを操作してください (http:// のページだけが記録されます)。', 'ok');
        }
      } catch (e) {
        btnStart.disabled = !CAN_RECORD;
        fail(e, '記録を開始できません');
      }
    });

    btnStop.addEventListener('click', async () => {
      btnStop.disabled = true;
      setStatus('記録を停止して読み込んでいます…', 'busy');
      try {
        const res = await api('/api/record/stop', { method: 'POST', json: { append: $('#rec-append').checked } });
        stopPolling();
        await poll();
        Load.applySummary(res);
        let msg = `記録を読み込みました: ${res.flows} 件のリクエスト (${res.out})`;
        if (res.excluded_self) msg += `。GUI 自身への通信 ${res.excluded_self} 件は自動的に除外しました`;
        setStatus(msg, 'ok');
        Load.refreshFiles();
        show('steps');
        Steps.resetOverrides();
        Steps.replan();
      } catch (e) {
        stopPolling();
        await poll();
        fail(e, '記録を停止できません');
      }
    });

    return { render, poll, startPolling, subscribe, setEmulation };
  })();

  // ================================================================== 2 読み込み
  const Load = (() => {
    const fileInput = $('#file-input');
    const dropzone = $('#dropzone');
    const btnUpload = $('#btn-upload');
    const filesTbody = $('#files-table tbody');
    const btnOpen = $('#btn-open-selected');

    function describeFiles() {
      const files = Array.from(fileInput.files || []);
      $('#file-chosen').textContent = files.length ? files.map((f) => `${f.name} (${fmtBytes(f.size)})`).join(', ') : 'ファイルが選ばれていません';
      btnUpload.disabled = files.length === 0;
    }
    fileInput.addEventListener('change', describeFiles);
    ['dragenter', 'dragover'].forEach((t) => dropzone.addEventListener(t, (e) => { e.preventDefault(); dropzone.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((t) => dropzone.addEventListener(t, (e) => { e.preventDefault(); dropzone.classList.remove('over'); }));
    dropzone.addEventListener('drop', (e) => {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        describeFiles();
      }
    });

    function applySummary(sum) {
      S.recording = sum;
      const loaded = !!(sum && sum.loaded && sum.flows);
      $('#cur-sources').textContent = loaded && sum.sources && sum.sources.length ? sum.sources.join(', ') : '(なし)';
      $('#cur-flows').textContent = loaded ? `${sum.flows} 件` : '0';
      $('#cur-hosts').textContent = loaded && sum.hosts && sum.hosts.length ? sum.hosts.join(', ') : '—';
      $('#btn-goto-steps').disabled = !loaded;
      $('#btn-clear').disabled = !loaded;
      $('#steps-empty').hidden = loaded;
      $('#steps-body').hidden = !loaded;
      markDone('load', loaded, loaded ? `${sum.flows} 件` : null);
      if (!loaded) { Steps.clearTable(); markDone('steps', false, null); }
      if (typeof Easy !== 'undefined' && Easy.refreshLoaded) Easy.refreshLoaded();
    }

    async function upload() {
      const files = Array.from(fileInput.files || []);
      if (!files.length) return;
      const form = new FormData();
      files.forEach((f) => form.append('files', f, f.name));
      form.append('append', $('#append-toggle').checked ? 'true' : 'false');
      btnUpload.disabled = true;
      setStatus(`${files.length} 個のファイルを読み込んでいます…`, 'busy');
      try {
        const res = await api('/api/recordings/upload', { method: 'POST', form });
        applySummary(res);
        setStatus(`読み込みました: ${res.flows} 件のリクエスト` + (res.appended ? '（結合済み）' : ''), 'ok');
        fileInput.value = '';
        describeFiles();
        refreshFiles();
        show('steps');
        Steps.resetOverrides();
        Steps.replan();
      } catch (e) {
        btnUpload.disabled = false;
        fail(e, '読み込みに失敗しました');
      }
    }
    btnUpload.addEventListener('click', upload);

    async function refreshFiles() {
      try {
        const res = await api('/api/recordings');
        clear(filesTbody);
        if (!res.files.length) {
          filesTbody.appendChild(el('tr', {}, el('td', { colspan: 6, class: 'empty', text: '作業フォルダに記録ファイルはまだありません' })));
        }
        res.files.forEach((f) => {
          const cb = el('input', { type: 'checkbox', dataset: { folder: f.folder, name: f.name } });
          cb.addEventListener('change', updateOpenButton);
          filesTbody.appendChild(el('tr', {}, [
            el('td', { class: 'col-check' }, cb),
            el('td', { text: f.name }),
            el('td', { text: f.folder === 'recordings' ? 'recordings (この GUI で記録)' : 'uploads (読み込み)' }),
            el('td', { class: 'num', text: f.flows === null || f.flows === undefined ? '—' : String(f.flows) }),
            el('td', { class: 'num', text: fmtBytes(f.size) }),
            el('td', { text: fmtTime(f.mtime) }),
          ]));
        });
        updateOpenButton();
      } catch (e) { fail(e, 'ファイル一覧を取得できません'); }
    }
    function selectedFiles() {
      return $$('input[type=checkbox]:checked', filesTbody).map((cb) => ({ folder: cb.dataset.folder, name: cb.dataset.name }));
    }
    function updateOpenButton() { btnOpen.disabled = selectedFiles().length === 0; }
    btnOpen.addEventListener('click', async () => {
      const names = selectedFiles();
      if (!names.length) return;
      setStatus('ファイルを開いています…', 'busy');
      try {
        const res = await api('/api/recordings/open', { method: 'POST', json: { names, append: $('#append-toggle').checked } });
        applySummary(res);
        let msg = `開きました: ${res.flows} 件のリクエスト`;
        if (res.excluded_self) msg += `（GUI 自身への通信 ${res.excluded_self} 件を自動除外）`;
        setStatus(msg, 'ok');
        show('steps');
        Steps.resetOverrides();
        Steps.replan();
      } catch (e) { fail(e, 'ファイルを開けません'); }
    });
    $('#btn-refresh-files').addEventListener('click', refreshFiles);
    $('#btn-goto-steps').addEventListener('click', () => { show('steps'); if (!S.plan) Steps.replan(); });
    $('#btn-clear').addEventListener('click', async () => {
      try {
        const res = await api('/api/recordings/clear', { method: 'POST', json: {} });
        applySummary(res.recording);
        S.plan = null;
        Steps.resetOverrides();
        setStatus('記録をクリアしました', 'ok');
      } catch (e) { fail(e); }
    });

    return { applySummary, refreshFiles };
  })();

  // ================================================================== 3 ステップ
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
      ['not used', '使用されず (他ステップに統合 / 上限超過)'],
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

    let inflight = 0;
    async function replan() {
      if (!S.recording || !S.recording.loaded) return;
      const my = ++inflight;
      setStatus('解析しています…', 'busy');
      tbody.classList.add('loading');
      try {
        const res = await api('/api/plan', { method: 'POST', json: { plan_options: collectPlanOptions() } });
        if (my !== inflight) return; // a newer request superseded this one
        S.plan = res;
        S.flows = res.flows || [];
        render(res);
        setStatus(`解析完了: ステップ ${res.steps_kept} 件 / 採用 ${res.flows_kept} 件 / 除外 ${res.dropped} 件`, 'ok');
      } catch (e) {
        if (my === inflight) fail(e, '解析に失敗しました');
      } finally {
        tbody.classList.remove('loading');
      }
    }
    const replanDebounced = debounce(replan, 250);

    function resetOverrides() {
      S.exclude = new Set();
      S.include = new Set();
      S.finalFlowId = null;
    }
    function clearTable() {
      clear(tbody).appendChild(el('tr', {}, el('td', { colspan: 9, class: 'empty', text: '記録が読み込まれていません' })));
    }

    function render(plan) {
      // summary card
      $('#sum-steps').textContent = plan.steps_kept;
      $('#sum-kept').textContent = plan.flows_kept;
      $('#sum-dropped').textContent = plan.dropped;
      $('#sum-vars').textContent = (plan.steps || []).reduce((n, s) => n + (s.extractors || []).length, 0);
      const finalEl = $('#sum-final');
      const finalBtn = $('#btn-final-clear');
      clear(finalEl);
      if (plan.final_step_index) {
        const st = (plan.steps || []).find((s) => s.index === plan.final_step_index);
        finalEl.appendChild(el('span', { text: `ステップ ${plan.final_step_index}${st ? ` (${st.method} ${st.url})` : ''} ` }));
        finalEl.appendChild(finalBtn); finalBtn.hidden = false;
      } else if (S.finalFlowId) {
        finalEl.appendChild(el('span', { class: 'hint', text: `指定した ${S.finalFlowId} は除外されているため、最後のステップを結果にします `}));
        finalEl.appendChild(finalBtn); finalBtn.hidden = false;
      } else {
        finalEl.appendChild(el('span', { text: '最後のステップ (既定) ' }));
        finalEl.appendChild(finalBtn); finalBtn.hidden = true;
      }
      const authEl = clear($('#sum-auth'));
      if (plan.auth) {
        const a = plan.auth;
        const kind = { ntlm: 'NTLM (Windows 統合認証)', negotiate: 'Negotiate / Kerberos (Windows 統合認証)', basic: 'Basic 認証', digest: 'Digest 認証' }[a.kind] || a.kind;
        authEl.appendChild(el('span', { class: 'auth-pill', text: kind }));
        authEl.appendChild(document.createTextNode(` ${(a.hosts || []).join(', ')}${a.username ? ` / 記録時のユーザー: ${a.username}` : ''} — 生成コードでは session.auth で認証します`));
      } else authEl.textContent = '検出されませんでした';
      const constEl = clear($('#sum-constants'));
      if (plan.constants && plan.constants.length) {
        plan.constants.forEach((c, i) => {
          if (i) constEl.appendChild(document.createTextNode(', '));
          constEl.appendChild(el('code', { text: c.name + (c.secret ? ` (秘密: 環境変数 ${c.env_var})` : c.value !== null && c.value !== undefined ? ` = ${String(c.value).slice(0, 40)}` : '') }));
        });
      } else constEl.textContent = 'なし';
      const loopEl = clear($('#sum-loops'));
      if (plan.loops && plan.loops.length) {
        loopEl.textContent = plan.loops.map((l) => `ステップ ${l.step_index}: ${l.var} を ${l.count} 回${l.numeric_range ? ` (${l.numeric_range[0]}〜${l.numeric_range[1]})` : ''}`).join(' / ');
      } else loopEl.textContent = 'なし';
      $('#sum-self').textContent = plan.excluded_self_flows ? `GUI 自身への通信 ${plan.excluded_self_flows} 件を記録から除外済み` : 'なし';
      const warnWrap = $('#sum-warnings-wrap');
      const warnList = clear($('#sum-warnings'));
      (plan.warnings || []).forEach((w) => warnList.appendChild(el('li', { text: w })));
      warnWrap.hidden = !(plan.warnings && plan.warnings.length);
      markDone('steps', plan.steps_kept > 0, `${plan.steps_kept} ステップ`);

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
        const cb = el('input', { type: 'checkbox', title: f.kept ? 'チェックを外すとこのリクエストを除外します' : 'チェックを入れるとこのリクエストを採用します' });
        cb.checked = f.kept;
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', () => toggleFlow(f, cb.checked));
        const radio = el('input', { type: 'radio', name: 'final-flow', title: 'このリクエストの結果をスクリプトの出力にします' });
        radio.checked = S.finalFlowId === f.id || (!S.finalFlowId && f.is_final);
        radio.disabled = !f.kept;
        radio.addEventListener('click', (e) => e.stopPropagation());
        radio.addEventListener('change', () => { if (radio.checked) { S.finalFlowId = f.id; replanDebounced(); } });
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
          el('td', { class: 'col-reason' }, el('span', { class: 'reason' + (f.reason === 'excluded by user' ? ' user' : ''), text: f.kept ? (f.is_final ? '採用（結果）' : '採用') : reasonLabel(f.reason) })),
        );
        tr.addEventListener('click', () => Drawer.open(f.id));
        tbody.appendChild(tr);
      });
      if (!shown) tbody.appendChild(el('tr', {}, el('td', { colspan: 9, class: 'empty', text: S.flows.length ? '条件に合う行がありません' : 'リクエストがありません' })));
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
      replanDebounced();
    }

    $$('input.opt, .opt-num').forEach((n) => n.addEventListener('change', replanDebounced));
    $$('.opt-text').forEach((n) => n.addEventListener('input', debounce(replan, 600)));
    $('#table-filter').addEventListener('input', debounce(renderTable, 120));
    $('#show-dropped').addEventListener('change', renderTable);
    $('#btn-replan').addEventListener('click', replan);
    $('#btn-final-clear').addEventListener('click', () => { S.finalFlowId = null; replan(); });
    $('#btn-goto-code').addEventListener('click', () => show('code'));

    return { replan, resetOverrides, clearTable, collectPlanOptions, collectGenOptions };
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
        $('#dr-flow-id').textContent = `${d.id}${d.step_index ? ` / ステップ ${d.step_index}` : d.reason ? ` / 除外: ${d.reason}` : ''}`;
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

  // ================================================================== 4 コード
  const Code = (() => {
    const preview = $('#code-preview');
    const btnSave = $('#btn-save');
    const btnDownload = $('#btn-download');
    const nameInput = $('#script-name');

    function renderSecrets(secrets) {
      S.secrets = secrets || [];
      const wrap = $('#gen-secrets-wrap');
      const list = clear($('#gen-secrets'));
      S.secrets.forEach((s) => list.appendChild(el('li', {}, [el('code', { text: s.env_var }), document.createTextNode(` — ${/^[A-Za-z_][A-Za-z0-9_]*$/.test(s.name) ? '定数 ' : ''}${s.name}${s.comment ? ` (${s.comment})` : ''}`)])));
      wrap.hidden = !S.secrets.length;
      Run.renderEnvInputs();
    }

    $('#btn-generate').addEventListener('click', async () => {
      if (!S.recording || !S.recording.loaded) { setStatus('先に記録を読み込んでください', 'error'); show('load'); return; }
      setStatus('スクリプトを生成しています…', 'busy');
      try {
        const res = await api('/api/generate', { method: 'POST', json: { plan_options: Steps.collectPlanOptions(), gen_options: Steps.collectGenOptions() } });
        S.code = res.code;
        preview.textContent = res.code;
        $('#code-lines').textContent = `(${res.code.split('\n').length} 行 / ${res.steps} ステップ)`;
        $('#gen-summary').textContent = res.summary || '';
        $('#gen-summary').hidden = !res.summary;
        const wl = clear($('#gen-warnings'));
        (res.warnings || []).forEach((w) => wl.appendChild(el('li', { text: w })));
        $('#gen-warnings-wrap').hidden = !(res.warnings && res.warnings.length);
        renderSecrets(res.secrets);
        if (!nameInput.value.trim() && res.suggested_name) nameInput.value = res.suggested_name;
        btnSave.disabled = false;
        markDone('code', true, `${res.steps} ステップ`);
        setStatus(`スクリプトを生成しました (${res.steps} ステップ)。ファイル名を確認して [保存] してください。`, 'ok');
      } catch (e) { fail(e, '生成に失敗しました'); }
    });

    btnSave.addEventListener('click', async () => {
      if (!S.code) return;
      let name = nameInput.value.trim();
      if (!name) { setStatus('ファイル名を入力してください', 'error'); nameInput.focus(); return; }
      setStatus('保存しています…', 'busy');
      try {
        const res = await api('/api/scripts/save', { method: 'POST', json: { name, code: S.code } });
        S.savedScript = res.name;
        $('#save-result').textContent = `保存しました: ${res.path}`;
        btnDownload.href = res.download_url;
        btnDownload.setAttribute('download', res.name);
        btnDownload.classList.remove('disabled');
        btnDownload.removeAttribute('aria-disabled');
        $('#btn-goto-run').disabled = false;
        setStatus(`保存しました: ${res.name}`, 'ok');
        await Run.refreshScripts(res.name);
      } catch (e) { fail(e, '保存に失敗しました'); }
    });
    $('#btn-goto-run').addEventListener('click', () => show('run'));

    return { renderSecrets };
  })();

  // ================================================================== 5 実行
  const Run = (() => {
    const select = $('#run-script');
    const envWrap = $('#env-inputs');
    const btnRun = $('#btn-run');
    const btnStop = $('#btn-run-stop');
    const stateEl = $('#run-state');
    const outEl = $('#run-stdout');
    const errEl = $('#run-stderr');

    async function refreshScripts(selectName) {
      try {
        const res = await api('/api/scripts');
        clear(select);
        if (!res.files.length) select.appendChild(el('option', { value: '', text: '(保存されたスクリプトはありません — 「4 コード」で保存してください)' }));
        res.files.forEach((f) => select.appendChild(el('option', { value: f.name, text: `${f.name}  (${fmtBytes(f.size)}, ${fmtTime(f.mtime)})` })));
        const want = selectName || S.savedScript || res.last;
        if (want && res.files.some((f) => f.name === want)) select.value = want;
      } catch (e) { fail(e, 'スクリプト一覧を取得できません'); }
    }
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
      // Windows authentication keeps its own instruction: with reqrec[sspi] the logged-in Windows user
      // is used and both fields stay blank; 「記録したときと同じ値」 would be wrong advice there.
      if (s.auth) return s.comment || '';
      return '記録したときと同じ値を入れてください。実行するときだけ使われ、どこにも保存されません。';
    }
    function renderEnvInputsInto(container, idPrefix = 'env-', friendly = false) {
      clear(container);
      if (!S.secrets.length) {
        container.appendChild(el('p', { class: 'hint', text: '生成したスクリプトに秘密情報がなければ入力は不要です。' }));
        return;
      }
      S.secrets.forEach((s) => {
        const id = idPrefix + s.env_var;
        container.appendChild(el('label', { for: id, text: friendly ? friendlySecretLabel(s) : s.env_var }));
        const isSecret = s.secret !== false;
        container.appendChild(el('div', {}, [
          el('input', { type: isSecret ? 'password' : 'text', id, class: 'env-input w-m', dataset: { env: s.env_var }, autocomplete: 'off', placeholder: s.name, value: !isSecret && s.default ? s.default : undefined }),
          el('div', { class: 'hint', text: friendly
            ? friendlySecretHint(s)
            : `${s.name}${s.comment ? ' — ' + s.comment : ''}（実行プロセスにだけ渡され、保存されません）` }),
        ]));
      });
    }
    function renderEnvInputs() { renderEnvInputsInto(envWrap); }
    function collectEnvFrom(container) {
      const env = {};
      $$('.env-input', container).forEach((i) => { if (i.value !== '') env[i.dataset.env] = i.value; });
      return env;
    }
    function collectEnv() { return collectEnvFrom(envWrap); }
    const listeners = [];
    function subscribe(fn) { listeners.push(fn); }
    function render(st) {
      listeners.forEach((fn) => { try { fn(st); } catch (e) { console.error(e); } });
      const running = !!st.running;
      btnRun.disabled = running;
      btnStop.disabled = !running;
      outEl.textContent = st.stdout_tail || '';
      errEl.textContent = st.stderr_tail || '';
      if (running) { stateEl.textContent = `実行中… (${st.name || ''})`; stateEl.className = 'run-state running'; }
      else if (st.exit_code === null || st.exit_code === undefined) { stateEl.textContent = '待機中'; stateEl.className = 'run-state'; }
      else if (st.exit_code === 0) { stateEl.textContent = `正常終了 (${st.name || ''})`; stateEl.className = 'run-state ok'; }
      else { stateEl.textContent = st.stopped_by_user ? '停止しました' : `エラー終了 (終了コード ${st.exit_code})`; stateEl.className = 'run-state fail'; }
      $('#btn-save-output').disabled = running || !st.started_at;
      if (running) outEl.scrollTop = outEl.scrollHeight;
      markDone('run', !running && st.exit_code === 0, null);
      if (running && !S.runPoll) S.runPoll = setInterval(poll, 1000);
      if (!running && S.runPoll) { clearInterval(S.runPoll); S.runPoll = null; }
    }
    async function poll() {
      try {
        const st = await api('/api/run/status');
        render(st);
        if (!st.running && st.exit_code !== null && st.exit_code !== undefined) {
          setStatus(st.exit_code === 0 ? 'スクリプトは正常に終了しました' : `スクリプトは終了コード ${st.exit_code} で終了しました（標準エラーを確認してください）`, st.exit_code === 0 ? 'ok' : 'error');
        }
      } catch (e) { /* transient */ }
    }
    async function start(name, env) {
      if (!name) { setStatus('実行するスクリプトを選んでください（「4 コード」で保存できます）', 'error'); return false; }
      btnRun.disabled = true;
      setStatus(`${name} を実行しています…`, 'busy');
      try {
        const st = await api('/api/run', { method: 'POST', json: { name, env } });
        render(st);
        return true;
      } catch (e) { btnRun.disabled = false; fail(e, '実行できません'); return false; }
    }
    async function stop() {
      try { render(await api('/api/run/stop', { method: 'POST', json: {} })); setStatus('スクリプトを停止しました', 'info'); } catch (e) { fail(e); }
    }
    btnRun.addEventListener('click', () => start(select.value, collectEnv()));
    btnStop.addEventListener('click', stop);
    $('#btn-refresh-scripts').addEventListener('click', () => refreshScripts());
    $('#btn-save-output').addEventListener('click', async () => {
      const name = $('#output-name').value.trim();
      try {
        const res = await api('/api/run/save_output', { method: 'POST', json: name ? { name } : {} });
        $('#save-output-result').textContent = `保存しました: ${res.path} (${fmtBytes(res.size)})${res.truncated ? ' ※出力が大きすぎたため途中までです' : ''}`;
        setStatus(`結果を保存しました: ${res.name}`, 'ok');
      } catch (e) { fail(e, '結果を保存できません'); }
    });
    return { refreshScripts, renderEnvInputs, renderEnvInputsInto, collectEnvFrom, render, start, stop, subscribe, friendlySecretLabel, authLabel };
  })();

  // ================================================================== かんたん画面 (既定)
  // 「記録をはじめる」→ 記録用ブラウザでサイトを操作 → 「記録をおわる」だけで、ポート選択・記録用ブラウザの
  // 起動・解析・生成・保存をすべて自動で行う。細かい設定は「詳細設定を表示」で既存の 5 画面に切り替える。
  const Easy = (() => {
    const MITM_AVAILABLE = body.dataset.mitmAvailable === 'true';
    // アプリ内の記録用ブラウザ (IE エンジン, DESIGN.md §13.12): Windows でコンパイラか exe があるときだけ使える。
    // Windows の設定や証明書は変更しない。使えない PC では記録できない (HAR の読み込み以降は使える)。
    const IEHOST = body.dataset.iehostAvailable === 'true';
    const IEHOST_REASON = body.dataset.iehostReason || '';
    const toggleBtn = $('#mode-toggle');
    const stages = { idle: $('#easy-idle'), recording: $('#easy-recording'), processing: $('#easy-processing'), done: $('#easy-done') };
    const errEl = $('#easy-error');
    const btnStart = $('#easy-start');
    const btnStop = $('#easy-stop');
    let current = 'idle';
    let lastBuild = null;
    let browserSeen = false;   // the recording browser was seen running during this recording (guards the auto-stop against racing the launch)
    let autoStopped = false;   // the auto-stop already fired for this recording
    let recOrigin = null;      // 'easy' / 'advanced': which screen started the recording in progress (from the server)
    let lastIEError = null;    // last failure to start the recording browser in this GUI session
    function canStart() { return MITM_AVAILABLE && IEHOST; }

    // ---------------------------------------------------------------- mode
    function setMode(mode, persist = true) {
      const easy = mode !== 'advanced';
      body.classList.toggle('easy-mode', easy);
      toggleBtn.textContent = easy ? '詳細設定を表示' : 'かんたん画面に戻る';
      if (persist) { try { localStorage.setItem('reqrec.mode', easy ? 'easy' : 'advanced'); } catch (e) { /* ignore */ } }
      if (!easy) {
        // show the panel that matches what the easy screen just did
        let panel = null;
        try { panel = localStorage.getItem('reqrec.panel'); } catch (e) { /* ignore */ }
        if (current === 'recording') panel = 'record';
        else if (current === 'done') panel = 'code';
        else if (!panel && S.recording && S.recording.loaded) panel = 'steps';
        if (panel && panels[panel]) show(panel);
      }
      window.scrollTo({ top: 0 });
    }
    toggleBtn.addEventListener('click', async () => {
      const toEasy = !body.classList.contains('easy-mode');
      setMode(toEasy ? 'easy' : 'advanced');
      if (!toEasy) return;
      try {  // a recording started or stopped in 詳細設定 is reflected here
        const st = await api('/api/record/status');
        if (st.running) recOrigin = st.origin || null;
        if (st.running && current !== 'recording') {
          browserSeen = !!(st.browser && st.browser.running);
          autoStopped = false;
          stage('recording');
          renderLive(st);
          Record.startPolling();
        } else if (!st.running && current === 'recording') {
          stage('idle'); btnStart.disabled = !canStart(); readiness();
        }
      } catch (e) { /* the regular poll will catch up */ }
    });

    // ---------------------------------------------------------------- stages
    function stage(name, text) {
      current = name;
      Object.entries(stages).forEach(([k, node]) => { node.hidden = k !== name; });
      if (name === 'processing' && text) $('#easy-processing-text').textContent = text;
      window.scrollTo({ top: 0 });
    }
    function showError(message) { errEl.textContent = message || ''; errEl.hidden = !message; }

    // ---------------------------------------------------------------- readiness (idle)
    async function readiness() {
      refreshLoaded();
      const list = clear($('#easy-ready'));
      const add = (cls, text) => list.appendChild(el('li', { class: cls, text }));
      if (!MITM_AVAILABLE) { add('bad', '記録機能: 準備できていません (mitmproxy が未インストール)'); return; }
      add('ok', '記録機能: 使えます');
      if (IEHOST) {
        if (lastIEError) add('bad', '記録用ブラウザ (IE エンジン): 前回、起動できませんでした: ' + lastIEError);
        else add('ok', '記録用ブラウザ (IE エンジン): 使えます (Windows の設定や証明書は変更しません)');
        return;
      }
      add('bad', '記録用ブラウザ (IE エンジン): 準備できていません: ' + (IEHOST_REASON || '理由不明'));
      add('warn', 'この PC では記録できません。管理者に連絡してください (HAR ファイルを読み込んでスクリプトを作ることはできます)。');
    }

    // ---------------------------------------------------------------- live count
    function renderLive(st) {
      $('#easy-count').textContent = st.flows ?? 0;
      const err = $('#easy-rec-error');
      if (st.error) { err.textContent = '記録用の中継サーバーが止まりました: ' + st.error; err.hidden = false; }
      else err.hidden = true;
      if (st.running === false && current === 'recording' && !st.error) {
        err.textContent = '記録用の中継サーバーが終了しています。[記録をおわる] を押して保存するか、[やめる] で破棄してください。';
        err.hidden = false;
      }
    }
    Record.subscribe((st) => {  // Record polls /api/record/status every second
      if (current !== 'recording') return;
      renderLive(st);
      if (st.running) recOrigin = st.origin || null;
      if (!st.browser || st.browser.kind !== 'iehost') return;
      if (st.browser.running) { browserSeen = true; return; }
      // Closing the recording browser is the natural "I'm done" of the in-app flow: stop + build once.
      // Only while this screen is shown, and only for a recording started from this screen: one started
      // in 詳細設定 (also after a page reload) is only pointed out; its own stop keeps its 追加モード.
      if (!browserSeen || autoStopped || !body.classList.contains('easy-mode')) return;
      autoStopped = true;  // handled once per recording ([ブラウザをもう一度開く] re-arms it)
      if (recOrigin !== 'easy') {
        setStatus('記録用ブラウザが閉じられました。[記録をおわる] を押すと記録を保存します。', 'info');
        return;
      }
      if (st.browser.exit_code === 4) {  // RecBrowser could not set its per-process proxy: nothing was recorded
        discardSilently('記録用ブラウザの中継設定に失敗したため、記録できませんでした。もう一度 [記録をはじめる] を押してください。直らない場合は管理者に連絡してください。');
        return;
      }
      setStatus('記録用ブラウザが閉じられました。スクリプトを作成します…', 'busy');
      stop();
    });
    const pollOnce = () => Record.poll();

    // ---------------------------------------------------------------- browser
    async function openBrowser() {
      const url = $('#easy-url').value.trim();
      try {
        const res = await api('/api/browser/open', { method: 'POST', json: { url } });
        if (res.browser && res.browser.running) { browserSeen = true; autoStopped = false; }
        setStatus(res.relaunched ? '記録用ブラウザを開き直しました。' : '記録用ブラウザはすでに開いています。', 'ok');
        return res;
      } catch (e) {
        if (e.data && e.data.kind === 'iehost') lastIEError = e.message;  // the exe itself could not be started
        $('#easy-browser-note').textContent = '記録用ブラウザを開けませんでした (' + e.message + ')。';
        $('#easy-browser-note').hidden = false;
        return null;
      }
    }

    // ---------------------------------------------------------------- start / stop / cancel
    async function start() {
      if (!canStart()) {
        showError(!MITM_AVAILABLE
          ? '記録機能の準備ができていません (mitmproxy が未インストール)。'
          : '記録用ブラウザが使えないため記録できません: ' + (IEHOST_REASON || '理由不明') + '　管理者に連絡してください。');
        return;
      }
      showError('');
      btnStart.disabled = true;
      $('#easy-browser-note').hidden = true;
      $('#easy-rec-error').hidden = true;
      $('#easy-count').textContent = '0';
      browserSeen = false;
      autoStopped = false;
      stage('processing', '記録の準備をしています… (記録用ブラウザを開きます。初回は数秒かかります)');
      let res;
      try {
        res = await api('/api/record/start', { method: 'POST', json: {
          hosts: [], append: false,
          start_url: $('#easy-url').value.trim(),
          emulation: 'keep',  // 表示モード is only changed from 詳細設定
          origin: 'easy',     // only easy-started recordings are stopped automatically when the browser closes
        } });
      } catch (e) {
        stage('idle'); btnStart.disabled = !canStart();
        const kind = e.data && e.data.kind;
        if (kind === 'iehost') {
          // RecBrowser.exe could not be built or started: typically blocked by a security policy (AppLocker)
          lastIEError = e.message;
          showError(e.message + '　パソコンのセキュリティ設定で記録用ブラウザ (RecBrowser.exe) が止められた可能性があります。'
            + '管理者に「reqrec のフォルダで python -m reqrec browser build を実行し、そのフォルダの RecBrowser.exe の実行を許可する」よう依頼してください。');
          readiness();
        } else if (kind === 'proxy') {
          // the recording proxy (mitmdump) did not start listening: not a security-policy problem
          showError(e.message + '　記録用の中継サーバーが動きませんでした。もう一度 [記録をはじめる] を押してください。'
            + '何度やっても同じときは、パソコンを再起動してから試すか、管理者に連絡してください。');
        } else if (kind === 'emulation') {
          showError(e.message + '　右上の「詳細設定を表示」→「1 記録」の「表示モード」を「変更しない」にして、もう一度記録してください。');
        } else {
          showError('記録を始められませんでした: ' + e.message);
        }
        setStatus('記録を始められませんでした', 'error');
        return;
      }
      Record.render(res.status || { running: true, flows: 0, out: res.out });
      if (res.status && res.status.error) {
        stage('idle'); btnStart.disabled = !canStart();
        showError('記録用の中継サーバーを起動できませんでした: ' + res.status.error);
        setStatus('記録を始められませんでした', 'error');
        return;
      }
      recOrigin = res.origin || 'easy';
      stage('recording');
      Record.startPolling();
      // the server already opened the recording browser
      browserSeen = !!(res.browser && res.browser.running);
      (res.warnings || []).forEach((w) => setStatus(w, 'info'));
      setStatus('記録中です。開いた記録用ブラウザでサイトを操作してください。', 'ok');
    }

    async function stop() {
      btnStop.disabled = true;
      stage('processing', '記録を保存しています…');
      let res;
      try {
        // no ``append``: the server uses the one the recording was started with (always false for an
        // easy-started recording, the 追加モード checkbox for one started in 詳細設定)
        res = await api('/api/record/stop', { method: 'POST', json: {} });
      } catch (e) {
        btnStop.disabled = false;
        await pollOnce();
        stage('idle'); btnStart.disabled = !canStart();
        const empty = !!(e.data && e.data.empty);
        showError((empty ? '' : '記録を保存できませんでした: ') + e.message);
        setStatus(empty ? '何も記録されませんでした' : '記録を保存できませんでした', 'error');
        readiness();
        return;
      }
      btnStop.disabled = false;
      recOrigin = null;
      Load.applySummary(res);
      Load.refreshFiles();
      Steps.resetOverrides();
      stage('processing', `記録した ${res.flows} 件の通信を解析して、スクリプトを作成しています…`);
      await build();
    }

    async function build() {
      let b;
      try {
        b = await api('/api/easy/build', { method: 'POST', json: {} });
      } catch (e) {
        stage('idle'); btnStart.disabled = !canStart();
        showError('スクリプトを作成できませんでした: ' + e.message + '　記録は読み込まれているので、「詳細設定を表示」から通信の一覧を確認できます。');
        setStatus('スクリプトを作成できませんでした', 'error');
        Steps.replan();
        readiness();
        return;
      }
      lastBuild = b;
      S.code = b.code;
      S.savedScript = b.name;
      Code.renderSecrets(b.secrets);
      $('#code-preview').textContent = b.code;
      $('#script-name').value = b.name.replace(/\.py$/i, '');
      $('#btn-save').disabled = false;
      markDone('code', true, `${b.steps} ステップ`);
      Run.refreshScripts(b.name);
      Steps.replan();  // keep the advanced table in sync (not awaited)
      renderDone(b);
      stage('done');
      setStatus(`スクリプトができました: ${b.name}`, 'ok');
    }

    async function discardSilently(message) {
      stage('processing', '記録を止めています…');
      try { await api('/api/record/stop', { method: 'POST', json: { discard: true } }); } catch (e) { /* already stopped */ }
      recOrigin = null;
      await pollOnce();
      stage('idle'); btnStart.disabled = !canStart();
      showError(message);
      setStatus('記録できませんでした', 'error');
      readiness();
    }

    async function cancel() {
      if (!window.confirm('記録をやめて破棄しますか？')) return;
      stage('processing', '記録を止めています…');
      try {
        const res = await api('/api/record/stop', { method: 'POST', json: { discard: true } });
        if (res.recording) Load.applySummary(res.recording);  // unchanged: the discarded recording is never loaded
      } catch (e) { /* already stopped: nothing to discard */ }
      recOrigin = null;
      await pollOnce();
      stage('idle'); btnStart.disabled = !canStart();
      setStatus('記録をやめました', 'info');
      readiness();
    }

    // ---------------------------------------------------------------- done screen
    // The plain-Japanese text of each plan warning comes from the server (routes.warning_message,
    // tested against the warnings build_plan really produces); the raw text is the fallback.
    function warningTexts(details, raw) {
      if (Array.isArray(details)) return details.map((d) => d.message || d.text);
      return raw || [];
    }
    function renderDone(b) {
      $('#easy-done-name').textContent = b.name;
      $('#easy-done-path').textContent = b.path;
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
      const dl = $('#easy-download');
      dl.href = b.download_url;
      dl.setAttribute('download', b.name);
      $('#easy-run').hidden = true;
      $('#easy-run-out').textContent = '';
      $('#easy-run-err').textContent = '';
      $('#easy-run-err-wrap').hidden = true;
      $('#easy-save-output-result').textContent = '';
    }

    $('#easy-open-folder').addEventListener('click', async () => {
      try { await api('/api/folder/open', { method: 'POST', json: { folder: 'scripts' } }); }
      catch (e) { fail(e, 'フォルダを開けません'); }
    });
    $('#easy-again').addEventListener('click', () => { stage('idle'); btnStart.disabled = !canStart(); showError(''); readiness(); });
    // a recording loaded elsewhere (詳細設定 / HAR from DevTools) can be turned into a script from here too
    function refreshLoaded() {
      const loaded = !!(S.recording && S.recording.loaded && S.recording.flows);
      $('#easy-loaded').hidden = !loaded;
      if (loaded) $('#easy-loaded-count').textContent = S.recording.flows;
    }
    $('#easy-build-loaded').addEventListener('click', async () => {
      if (!(S.recording && S.recording.loaded)) return;
      showError('');
      stage('processing', `読み込み済みの ${S.recording.flows} 件の通信を解析して、スクリプトを作成しています…`);
      await build();
    });
    $('#easy-test-run').addEventListener('click', () => {
      Run.renderEnvInputsInto($('#easy-env'), 'easy-env-', true);
      $('#easy-run').hidden = false;
      $('#easy-run').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    $('#easy-run-btn').addEventListener('click', () => { if (lastBuild) Run.start(lastBuild.name, Run.collectEnvFrom($('#easy-env'))); });
    $('#easy-run-stop').addEventListener('click', () => Run.stop());
    $('#easy-save-output').addEventListener('click', async () => {
      try {
        const res = await api('/api/run/save_output', { method: 'POST', json: {} });
        $('#easy-save-output-result').textContent = `保存しました: ${res.path}`;
        setStatus(`結果を保存しました: ${res.name}`, 'ok');
      } catch (e) { fail(e, '結果を保存できません'); }
    });
    // plain-language hint for the most common failures of a generated script (the raw traceback stays available below)
    const ERROR_HINTS = [
      [/getaddrinfo failed|Name or service not known|NameResolutionError|nodename nor servname/i, 'サイトに接続できません (アドレスが見つかりません)。社内ネットワークに接続しているか、VPN が必要なサイトではないか確認してください。'],
      [/ConnectTimeout|Read timed out|timed out/i, 'サイトの応答がありません (タイムアウト)。しばらくしてからもう一度実行してください。'],
      [/CERTIFICATE_VERIFY_FAILED|SSLError|SSLCertVerificationError/i, 'https:// のサイトの証明書を確認できませんでした。このツールが対象とするのは http:// のサイトです。'],
      [/ConnectionRefused|Connection refused|WinError 10061/i, 'サイトに接続できません (接続が拒否されました)。サイトが動いているか確認してください。'],
      [/\b(401|403) Client Error|Unauthorized for url|Forbidden for url/, 'ログインに失敗したか、権限がありません。パスワードなどの入力値を確認してください。'],
      [/REQREC_[A-Z_]+ (が|is) /, '実行に必要な入力 (パスワードなど) が足りません。上の入力欄をすべて埋めてください。'],
      [/要素が見つかりません|パターンに一致しませんでした|JSON にパス/, '画面の内容が記録したときと違うため、続きの値を取り出せませんでした。パスワードが正しいか、ログインが拒否されていないかを確認してください。サイトの画面が変わった場合は、もう一度記録してください。'],
      [/ModuleNotFoundError: No module named '(requests_negotiate_sspi|requests_ntlm)'/, 'Windows 統合認証用の部品が入っていません。管理者に pip install "reqrec[sspi]" の実行を依頼してください。'],
      [/ModuleNotFoundError: No module named '([\w.]+)'/, '必要な部品 ($1) が入っていません。管理者に pip install の実行を依頼してください。'],
      [/status (\d{3}) .*expected|想定外のステータス|unexpected status/i, 'サイトの応答が記録したときと違います。サイト側が変わったか、ログインが切れている可能性があります。'],
    ];
    function errorHint(text) {
      if (!text) return '';
      for (const [re, msg] of ERROR_HINTS) {
        const m = re.exec(text);
        if (m) return msg.replace('$1', m[1] || '');
      }
      const last = text.trim().split('\n').pop();
      return last ? `エラー: ${last.slice(0, 200)}` : '';
    }
    Run.subscribe((st) => {
      const running = !!st.running;
      $('#easy-run-btn').disabled = running;
      $('#easy-run-stop').disabled = !running;
      $('#easy-save-output').disabled = running || !st.started_at;
      const out = $('#easy-run-out');
      out.textContent = st.stdout_tail || (running ? '(実行中… 出力を待っています)' : '');
      if (running) out.scrollTop = out.scrollHeight;
      $('#easy-run-err').textContent = st.stderr_tail || '';
      $('#easy-run-err-wrap').hidden = !st.stderr_tail;
      const s = $('#easy-run-state');
      const hint = $('#easy-run-hint');
      hint.hidden = true;
      if (running) { s.textContent = '実行中…'; s.className = 'run-state running'; }
      else if (st.exit_code === null || st.exit_code === undefined) { s.textContent = '待機中'; s.className = 'run-state'; }
      else if (st.exit_code === 0) { s.textContent = '正常に終わりました'; s.className = 'run-state ok'; }
      else {
        s.textContent = st.stopped_by_user ? '停止しました' : 'エラーで終わりました';
        s.className = 'run-state fail';
        if (!st.stopped_by_user) {
          const h = errorHint(st.stderr_tail);
          if (h) { hint.textContent = h; hint.hidden = false; }
          $('#easy-run-err-wrap').open = true;
        }
      }
    });

    btnStart.addEventListener('click', start);
    btnStop.addEventListener('click', stop);
    $('#easy-cancel').addEventListener('click', cancel);
    $('#easy-open-browser').addEventListener('click', openBrowser);
    $('#easy-url').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !btnStart.disabled) start(); });

    function initFromState(st) {
      lastIEError = (st.iehost && st.iehost.last_error) || null;
      let mode = 'easy';
      try { mode = localStorage.getItem('reqrec.mode') || 'easy'; } catch (e) { /* ignore */ }
      setMode(mode, false);
      if (st.recorder && st.recorder.running) {
        // a page reload during an in-app-browser recording keeps the auto-stop working, but only for a
        // recording that was started from the easy screen (record_origin is kept by the server)
        const b = st.browser || null;
        recOrigin = st.record_origin || null;
        browserSeen = !!(b && b.kind === 'iehost' && b.running);
        autoStopped = false;
        stage('recording');
        renderLive(st.recorder);
        Record.startPolling();
      } else {
        stage('idle');
        btnStart.disabled = !canStart();
        readiness();
      }
    }
    return { initFromState, refreshLoaded };
  })();

  // ================================================================== 起動
  async function init() {
    try {
      const st = await api('/api/state');
      Record.render(st.recorder || {});
      Load.applySummary(st.recording || { loaded: false });
      Run.render(st.run || {});
      if (st.secrets && st.secrets.length) Code.renderSecrets(st.secrets);
      if (st.last_script) S.savedScript = st.last_script;
      if (st.recording && st.recording.loaded) Steps.replan();
      Load.refreshFiles();
      Run.refreshScripts();
      let panel = null;
      try { panel = localStorage.getItem('reqrec.panel'); } catch (e) { /* ignore */ }
      if (st.recorder && st.recorder.running) panel = 'record';
      else if (!panel && st.recording && st.recording.loaded) panel = 'steps';
      if (panel && panels[panel]) show(panel);
      if (st.iehost && st.iehost.emulation) Record.setEmulation(st.iehost.emulation);
      Easy.initFromState(st);
    } catch (e) { fail(e, '初期化に失敗しました'); }
  }
  init();
})();
{% endraw %}
</script>
</body>
</html>
'''


# ===== former reqrec/cli.py: argparse CLI (reqrec import / inspect / generate / gui / browser) =====
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
        "--no-redact", action="store_true",
        help="パスワード等を環境変数に置き換えず、記録した値をそのままコードに埋め込む（取り扱い注意）",
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
        redact_secrets=not getattr(args, "no_redact", False),
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
典型的な流れ:
  1. 記録する   reqrec gui                           （記録用ブラウザで操作。IE の F12 で保存した HAR も可）
  2. 確認する   reqrec inspect rec.json
  3. 生成する   reqrec generate rec.json -o scrape.py
  4. 実行する   REQREC_PASSWORD=... python scrape.py

別タブで開いた画面の HAR は複数指定して結合できます:  reqrec generate tab1.har tab2.har -o scrape.py
手動で取捨選択:  reqrec generate rec.json -o scrape.py --exclude-flow f0012 --final-step 3
コードを書かずに使う GUI:  reqrec gui

各コマンドの詳細: reqrec <コマンド> -h"""


_INPUT_HELP = ("入力ファイル（.har / .json）。複数指定すると時刻順に結合して 1 つの記録として扱います"
               "（別タブで開いた画面の HAR など）")


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level parser with its sub-commands (import / inspect / generate / gui / browser)."""
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
    p_gui.add_argument("--host", default="127.0.0.1", metavar="HOST", help="待ち受けアドレス（既定: 127.0.0.1。他の端末からは使わせない）")
    p_gui.add_argument("--port", type=_port, default=8765, metavar="PORT", help="待ち受けポート（既定: 8765）")
    p_gui.add_argument("--workdir", default="reqrec_work", metavar="DIR",
                       help="記録ファイルや生成スクリプトを保存する作業フォルダ（既定: ./reqrec_work）")
    p_gui.add_argument("--no-browser", action="store_true", help="ブラウザを自動で開かない")
    p_gui.set_defaults(func=cmd_gui)

    # -- browser ----------------------------------------------------------------------------------
    p_browser = subparsers.add_parser(
        "browser",
        help="記録用ブラウザ（IE エンジン・Windows）を reqrec.py と同じフォルダに事前に作成する / 作成済みか確認する",
        description="記録用ブラウザ（RecBrowser.exe）を reqrec.py と同じフォルダ（配布フォルダ）に事前に作成します。\n"
                    "作成しておくと、そのフォルダを使うどの PC でもその exe をそのまま使い、各 PC の作業フォルダでの\n"
                    "コンパイルは行いません（IT 担当者が配布フォルダを用意するとき用。Windows 標準の csc.exe が必要）。",
    )
    browser_actions = p_browser.add_subparsers(dest="browser_action", title="操作")
    p_browser_build = browser_actions.add_parser(
        "build",
        help="記録用ブラウザを reqrec.py と同じフォルダに作成する（32 ビット版）",
        description="記録用ブラウザ（RecBrowser.exe）と、元にしたソースのハッシュ（RecBrowser.exe.sha256）を\n"
                    "reqrec.py と同じフォルダに作成します。",
    )
    p_browser_build.set_defaults(func=cmd_browser_build)
    p_browser_status = browser_actions.add_parser(
        "status",
        help="このバージョン用の記録用ブラウザが reqrec.py と同じフォルダに作成済みか確認する",
        description="reqrec.py と同じフォルダに、このバージョンのソースから作った記録用ブラウザがあるか表示します。",
    )
    p_browser_status.set_defaults(func=cmd_browser_status)
    p_browser.set_defaults(func=cmd_browser_usage)

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


# --------------------------------------------------------------------------- browser / gui / import

#: ``reqrec browser`` without ``build`` / ``status`` (the former ``python -m reqrec.iehost`` usage text).
_BROWSER_USAGE = (
    "使い方: reqrec browser build   （記録用ブラウザを reqrec.py と同じフォルダに作成）\n"
    "        reqrec browser status  （作成済みか確認）"
)


def cmd_browser_build(args: argparse.Namespace) -> int:
    """``reqrec browser build``: prebuild the recording browser into the distribution folder (former
    ``python -m reqrec.iehost build``)."""
    try:
        exe = iehost.build_shipped()
    except IEHostError as exc:
        _error(str(exc))
        return EXIT_ERROR
    # always 32-bit, so the 32-bit ActiveX controls of legacy intranet pages load (as in IE mode)
    print(f"記録用ブラウザを作成しました (32 ビット版): {exe}")
    return EXIT_OK


def cmd_browser_status(args: argparse.Namespace) -> int:
    """``reqrec browser status``: is there a prebuilt recording browser for this version?"""
    exe = iehost.shipped_exe()
    print(f"配布フォルダの記録用ブラウザ: {exe}" if exe else "配布フォルダの記録用ブラウザ: なし（各 PC の作業フォルダで初回にコンパイルします）")
    return EXIT_OK


def cmd_browser_usage(args: argparse.Namespace) -> int:
    """``reqrec browser`` alone: print the usage and return the usage exit code."""
    print(_BROWSER_USAGE, file=sys.stderr)
    return EXIT_USAGE


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
    if kind == "json":
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
        text += '（pip install "reqrec[sspi]" / "reqrec[ntlm]"）'
    return text


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
                "values": list(step.loop.values),
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
            "value": None if c.secret else c.value,
            "comment": c.comment,
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
            if c["secret"]:
                env = c["env_var"] or "(環境変数名なし)"
                lines.append(f"  {c['name']}  ← 環境変数 {env}（秘密情報: 実行前に設定してください）")
            else:
                lines.append(f"  {c['name']} = {truncate(repr(c['value']), 60)}")
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


# ===== entry point: main() (console script ``reqrec``, ``python -m reqrec``) =====
# Former end of reqrec/cli.py.  ``python -m reqrec`` runs :func:`main` (the guard at the very end);
# ``mitmdump -s reqrec.py`` loads this file as a script and only uses ``addons`` (recorder section).


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


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return the process exit code (0 ok, 1 error, 2 usage)."""
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
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
