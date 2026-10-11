"""Core data model for reqrec.

Two layers:

1. **Recording layer** - what was captured on the wire.
   ``Recording`` -> ``Flow`` -> ``RecordedRequest`` / ``RecordedResponse``
   Serialised to a JSON file (``Recording.save`` / ``Recording.load``); bodies are base64.

2. **Plan layer** - what the generated script should do.
   ``Plan`` -> ``Step`` (one HTTP call) with ``Ref`` values (literal / variable / expression),
   ``Extractor`` (how a later step gets a value out of this step's response), ``Loop``
   (pagination), plus ``Constant`` (user-supplied literals lifted to the top of the script),
   ``InitialCookie`` (cookies that pre-dated the recording) and ``Dropped`` (noise, with reason).

Every other module speaks in these types. Keep this file dependency-free (stdlib only).
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from typing import Any, Literal, Optional
from urllib.parse import urlsplit

from . import util

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
        return util.strip_query(self.url)

    @property
    def query_pairs(self) -> list[tuple[str, str]]:
        return util.parse_query(self.query)

    def header(self, name: str) -> Optional[str]:
        return header_get(self.headers, name)

    @property
    def content_type(self) -> Optional[str]:
        """Lower-cased MIME type of the request body without parameters, or None."""
        ct = self.header("content-type")
        return util.parse_content_type(ct)[0] if ct else None

    def text(self) -> Optional[str]:
        """Request body decoded to str (None when there is no body)."""
        if self.body is None:
            return None
        return util.decode_body(self.body, self.header("content-type"))


@dataclass
class RecordedResponse:
    status: int
    headers: Headers = field(default_factory=list)
    body: Optional[bytes] = None
    mime_type: Optional[str] = None  # lower-case, no parameters; derived from Content-Type if absent

    def __post_init__(self) -> None:
        if not self.mime_type:
            ct = self.header("content-type")
            self.mime_type = util.parse_content_type(ct)[0] if ct else None
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
        return util.decode_body(self.body, self.header("content-type"))

    @property
    def is_textual(self) -> bool:
        return util.is_textual_mime(self.mime_type)


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

    def save(self, path: str, atomic: bool = True) -> None:
        """Write the recording as JSON.  ``atomic`` writes a temp file in the same directory and
        ``os.replace``s it so a crash never leaves a half-written file."""
        data = self.to_json(indent=1)
        if not atomic:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
            return
        import os
        import tempfile

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
    """Knobs for ``plan.build_plan``.  All host matching is case-insensitive and also matches
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
    legacy_tls: bool = False  # mount an HTTPS adapter that accepts TLS 1.0/1.1 and SECLEVEL=1 ciphers (old intranet servers)


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


__all__ = [
    "RECORDING_FORMAT_VERSION", "Headers", "header_get", "header_get_all",
    "RecordedRequest", "RecordedResponse", "Flow", "Recording",
    "Ref", "RefKind", "Extractor", "ExtractorKind", "MultipartPart", "Loop", "Step", "Constant",
    "InitialCookie", "Dropped", "AuthInfo", "Plan", "PlanOptions", "GenOptions", "BodyKind", "ResponseKind",
    "to_plain",
]
