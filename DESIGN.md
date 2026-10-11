# reqrec — design & module contracts

`reqrec` records a website's HTTP traffic (via a mitmproxy-based recording proxy, a HAR file
exported from browser DevTools, or a saved mitmproxy flow file) and generates a **standalone
Python script** (`requests` + `BeautifulSoup`) that replays the same conversation — like a macro
recorder, but at the HTTP request/response level instead of screen elements.

```
 browser ──proxy──▶ mitmproxy addon ─┐
 DevTools ──"Save all as HAR"────────┼──▶ Recording (JSON) ──▶ build_plan ──▶ Plan ──▶ generate ──▶ scrape.py
 mitmdump -w flows.mitm ─────────────┘
```

The three stages are deliberately separated so each can be tested alone:

| stage | input → output | module |
|---|---|---|
| import / record | HAR / .mitm / live proxy → `Recording` | `reqrec/importers/*`, `reqrec/recorder/*` |
| analyse | `Recording` → `Plan` | `reqrec/filters.py`, `reqrec/deps.py`, `reqrec/loops.py`, `reqrec/plan.py` |
| generate | `Plan` → Python source | `reqrec/codegen.py` |
| UI | argparse CLI | `reqrec/cli.py` |

All shared types live in **`reqrec/model.py`**; shared helpers in **`reqrec/util.py`**.  Both are
finished and are the single source of truth — read them first. If you believe a field is missing,
do **not** edit `model.py`; add a module-local workaround and report the request.

## 1. Recording layer (`model.py`)

`Recording{flows, meta}` → `Flow{id, request, response, started_at, page_ref, resource_type}`.
Flow ids are `f0001, f0002, …` in **chronological order** (sorted by `started_at`). Bodies are
`bytes | None`; `.text()` decodes using charset detection (`util.decode_body`). Request headers are
stored **exactly as captured** (including HTTP/2 pseudo-headers such as `:authority` from Chrome
HARs) — cleaning happens in `filters.clean_request_headers`.

## 2. Importers (`reqrec/importers/`)

```python
# reqrec/importers/__init__.py
def load_recording(path: str) -> Recording
```
Dispatch: `.har` → HAR; `.mitm` / `.flows` / `.flow` → mitmproxy; `.json` → sniff: a dict with
`"log"` is HAR, a dict with `"flows"` is our Recording. Unknown → `ValueError` with a clear message.

```python
# reqrec/importers/har.py
def load_har(path: str) -> Recording
def recording_from_har(har: dict, source: str = "") -> Recording
```
* Sort entries by `startedDateTime` (ISO-8601, may have `Z` or `+09:00`; parse to epoch float).
* request: `method`, `url`, `headers[{name,value}]`, body from `postData.text`
  (if absent but `postData.params` present → urlencode them). If `postData.mimeType` is set and no
  `Content-Type` header exists, add one.  If `request.cookies` is present and there is no `Cookie`
  header, synthesise `Cookie: a=1; b=2`.
* response: `status` (0 / missing → `response=None`), `headers`, body from `content.text`;
  `content.encoding == "base64"` → b64decode, else encode the text with the charset from
  `content.mimeType` / `Content-Type` (fallback utf-8). If `response.cookies` is present but no
  `Set-Cookie` header, synthesise `Set-Cookie` headers (`name=value; Path=…; Domain=…; …`).
  `mime_type` from `content.mimeType` or the header.
* `_resourceType` → `resource_type` (lower-case), `pageref` → `page_ref`.
* `meta = {"source": "har", "file": source, "creator": log.creator.name/version, "imported_at": util.now_iso()}`.
* Tolerate missing/odd fields (never crash on a real-world HAR; skip an entry only if it has no URL).

```python
# reqrec/importers/mitm.py
def load_mitm(path: str) -> Recording           # mitmproxy.io.FlowReader; ImportError → friendly message
def flow_from_mitm(flow, flow_id: str) -> Flow   # shared with the recorder addon (HTTPFlow only)
```
Use `flow.request.pretty_url`, `headers.fields` (bytes pairs → str, latin-1/utf-8 tolerant),
`flow.request.content` / `flow.response.content` (**decoded** of Content-Encoding; fall back to
`raw_content` when decoding fails), `flow.request.timestamp_start`.

## 3. Recorder (`reqrec/recorder/`)

```python
# reqrec/recorder/addon.py   — a mitmproxy addon (importable without mitmproxy *installed* at module
#                              import time only if guarded; it's fine to require mitmproxy here)
class ReqRecAddon:   options: reqrec_out (str path), reqrec_hosts (str, comma-separated, "" = all)
    load(loader) / response(flow) / error(flow) / done()
addons = [ReqRecAddon()]
```
Append every completed HTTP flow (optionally only for the given hosts and their sub-domains) and
**flush the JSON file atomically after every response** (write temp file + `os.replace`) so a
killed session still leaves a valid recording. `meta = {"source": "mitmproxy", "started_at": …}`.

```python
# reqrec/recorder/run.py
def run_record(out: str, port: int = 8080, hosts: list[str] | None = None,
               listen_host: str = "127.0.0.1", quiet: bool = True, extra_args: list[str] = ()) -> int
```
Spawn `mitmdump` (via `sys.executable -m mitmproxy.tools.main mitmdump` or the `mitmdump` binary,
whichever exists) with `-s <path to addon.py> --set reqrec_out=… --set reqrec_hosts=… -p PORT
--listen-host HOST`. Before starting, print **Japanese** instructions: how to point the browser at
`http://HOST:PORT`, that the CA certificate must be installed once (`~/.mitmproxy/mitmproxy-ca-cert.pem`
or visit `http://mitm.it` through the proxy), and that `Ctrl+C` stops recording. Forward
`KeyboardInterrupt` to the child gracefully; return its exit code. If mitmproxy is missing, print
`pip install "reqrec[record]"` and return 1.

## 4. Filters (`reqrec/filters.py`)

```python
TRACKER_HOSTS: list[str]                 # analytics/ads/monitoring domains (conservative; never a real content host)
STATIC_EXTENSIONS: frozenset[str]        # .png .jpg .jpeg .gif .webp .svg .ico .css .js .mjs .map .woff .woff2 .ttf .otf .eot .mp4 .webm .mp3 .wasm …
STATIC_RESOURCE_TYPES: frozenset[str]    # image stylesheet script font media manifest texttrack ping beacon csp_report prefetch preflight signedexchange other
DROP_REQUEST_HEADERS: frozenset[str]     # host cookie content-length connection accept-encoding transfer-encoding te trailer keep-alive upgrade proxy-* if-none-match if-modified-since if-range range? (keep range) expect
                                         # + any header starting with ':'  + 'content-type' is handled by plan.py (dropped for form/json/multipart bodies)

def classify_noise(flow: Flow, opts: PlanOptions) -> str | None    # reason to drop, or None to keep
def filter_flows(recording: Recording, opts: PlanOptions) -> tuple[list[Flow], list[Dropped]]
def collapse_redirects(flows: list[Flow]) -> list[list[Flow]]
def classify_cookies(flows: list[Flow]) -> tuple[list[InitialCookie], set[str]]
def compute_base_headers(flows: list[Flow]) -> Headers
def clean_request_headers(headers: Headers) -> Headers
```
`classify_noise` rules, in order (first hit wins; `keep_all` skips rules 4–9, host rules always apply):
1. `include_hosts` set and host not in it → `"host not in --include-host"`
2. host in `exclude_hosts` → `"host excluded"`
3. no response → `"no response recorded"`
4. `method == OPTIONS` → `"CORS preflight"`
5. tracker host (unless `keep_trackers`) → `"tracker/analytics host"`
6. static (unless `keep_static`): resource_type in STATIC_RESOURCE_TYPES, or response mime is
   `image/*`, `font/*`, `audio/*`, `video/*`, `text/css`, `*javascript*`, `application/wasm`,
   `application/octet-stream` **only when** the URL extension is static, or URL extension static and
   mime unknown/`text/plain`, or path ends with `/favicon.ico` → `"static asset (<why>)"`
7. status 304 → `"304 not modified (browser cache)"`
8. websocket upgrade (`Upgrade: websocket` or status 101) → `"websocket"`
9. `text/event-stream` → `"server-sent events stream"`
Everything else is kept, including HTML documents, JSON/XML APIs, text, redirects, downloads
(e.g. a CSV / PDF the user clicked — not matched by rule 6 because extension/mime are not static).

`collapse_redirects`: walk kept flows in order; when flow *i* has a 3xx response with `Location`
and the **next kept flow** *i+1* is a `GET`/same-method request whose URL equals
`urljoin(flow_i.url, location)` (compare ignoring fragment), chain them; continue while the chain's
last hop is itself a redirect. Each group is `[first, …, final]`; everything else is a singleton.

`classify_cookies`: scan flows in order; collect names from every `Set-Cookie` seen so far
(managed). A cookie in a request `Cookie` header whose name has **not** been set by any earlier
response is *pre-existing*: emit `InitialCookie(name, value, domain=request host, path="/")` once
per (name, host). Return `(initial_cookies, managed_names)`.

`compute_base_headers`: after `clean_request_headers`, the (name, value) pairs present with the
*same value* in **every** kept request (case-insensitive names; keep the first spelling). Never
includes `referer`, `content-type`, `origin`, `authorization`, or any `x-*` header (those stay
per-step so dependency detection can replace them).

## 5. Dependency detection (`reqrec/deps.py`)

The "intelligence": for each request, find which of its values were produced by an earlier response.

```python
@dataclass
class Candidate:
    location: str           # "path" | "query" | "form" | "json" | "header" | "multipart"
    name: str               # param / header / multipart field name; for "path" the 0-based segment index as str; for "json" a dotted path "a.b[0].c"
    value: str              # the recorded value (str; numbers stringified)
    json_path: list | None  # for location == "json"

def find_candidates(flow: Flow, opts: PlanOptions) -> list[Candidate]
def locate_value(value: str, source: Flow) -> Extractor | None      # var left as "" ; caller names it
def locate_in_cookies(value: str, earlier: list[Flow]) -> str | None  # returns the cookie *name* if value equals (any variant of) a Set-Cookie value from an earlier response
def is_dynamic_looking(value: str) -> bool                          # long random-ish token heuristic (for warnings)
```
* Candidates: every query value, form value, JSON leaf (str/int/float, via recursive walk),
  multipart text field, path segment, and header value **except** headers in
  `filters.DROP_REQUEST_HEADERS`, `user-agent`, `accept*`, `sec-*`, `referer`, `origin`,
  `cache-control`, `pragma`, `dnt`, `priority`, `content-type`. Skip values shorter than
  `opts.min_value_length`, and values that are purely alphabetic common words ≤ 6 chars
  (e.g. `true`, `json`, `ja`, `asc`) — keep digits-only values of ≥ 4 chars (ids).
* `locate_value(value, source)` searches `source.response` in this priority and returns the first hit,
  trying every spelling in `util.value_variants(value)`:
  1. response header equal to the value → `header`
  2. JSON body (if `util.is_json_mime` or body parses as JSON) → exact leaf match → `json` with `path`
  3. HTML (`util.is_html_mime` or body starts with `<`) — parse with BeautifulSoup(`html.parser`):
     a. `<input name=X value=V>` → `html_input(name=X)`
     b. `<meta name=X content=V>` → `html_meta(name=X)`
     c. any element attribute == V, element locatable by `#id`, `[name=…]`, `tag[data-*=…]`, or a
        unique `tag.class` selector (verify uniqueness with `select`) → `html_attr(selector, attr)`;
        if V is a *substring* of the attribute (e.g. a token inside an href), add `pattern` with
        escaped context around the match and one capture group.
     d. element whose stripped text == V and which is locatable as in (c) → `html_text(selector)`
     e. inline `<script>` / anywhere in text: `regex` with ≤ 24 chars of escaped context on each side
        and a capture group that matches `[^"'&<>\s]+?` style tokens: `re.escape(prefix) + r'([^"\'&<>\s]+?)' + re.escape(suffix)`
        — then **verify** the pattern re-matches the original value in the recorded text.
  4. Any other textual body → `regex` as in 3e.
  5. `Location` header containing the value (final URL) → `url` with a verified pattern.
  Never return a locator keyed by the dynamic value itself (that would break on the next run).
  Patterns must have exactly **one** capturing group and be verified against the recorded text.
* `locate_in_cookies`: compare against cookie values parsed from earlier `Set-Cookie` headers (first
  `name=value` segment), including URL-decoded/encoded variants (Laravel's `XSRF-TOKEN` is sent
  URL-encoded in the cookie and decoded in the `X-XSRF-TOKEN` header).

## 6. Loop detection (`reqrec/loops.py`)

```python
@dataclass
class LoopGroup:
    groups: list[list[Flow]]   # the redirect-chains that fold into one looped step, in order
    location: str              # "query" | "form" | "json" | "path"
    name: str                  # param name / json dotted path / path segment index
    values: list[str]
    numeric_range: tuple[int, int] | None

def detect_loops(groups: list[list[Flow]], opts: PlanOptions) -> list[LoopGroup]
```
Fold **≥ 3 consecutive** kept groups with identical method, URL-without-query, parameter *names*
(query / form / json leaf paths), body kind and headers (ignoring `referer`), where **exactly one**
value differs across all of them. `numeric_range` is set when the values are consecutive integers
(step ±1). Groups that belong to a loop must not be referenced by `Extractor`s of later steps other
than through the last iteration (plan.py enforces this by running loop detection *before*
dependency detection and treating the last flow of the loop as the step's response).

## 7. Plan builder (`reqrec/plan.py`)

```python
def build_plan(recording: Recording, opts: PlanOptions | None = None) -> Plan
```
1. `filter_flows` → kept / dropped.
2. `collapse_redirects` → groups. `detect_loops` (if enabled) → fold groups into looped steps.
3. `classify_cookies` → `Plan.initial_cookies` (only cookies for hosts that appear in kept flows).
4. `compute_base_headers` → `Plan.base_headers`.
5. For each step in order, build a `Step` from the **first** flow of its group (request) and the
   **last** flow (response → `response_kind`, `expected_status`). Then for every `Candidate`:
   * `util.looks_like_timestamp(value, around=flow.started_at)` → `Ref.expr("str(int(time.time()*1000))")` / `"str(int(time.time()))"`.
   * `locate_in_cookies` → `Ref.expr('session.cookies.get("NAME")')` (or `unquote(session.cookies.get("NAME"))` when the header value is the URL-decoded cookie).
   * search earlier steps' responses, **latest first**, with `locate_value` (for a collapsed chain,
     search the final response first, then intermediate hops only for `header`/`url` kinds) →
     add/reuse an `Extractor` on that step (de-duplicate by (step, kind, locator)); value → `Ref.var`.
   * else if the same value was already sent in an **earlier request** (same literal, not traced to a
     response) → one `Constant` (UPPER_SNAKE from the param name) reused everywhere; if
     `util.looks_like_secret_name(name)` and `opts.redact_secrets` → `secret=True, env_var="REQREC_<NAME>"`.
   * else if `util.looks_like_secret_name(name)` and `opts.redact_secrets` → secret `Constant`.
   * else literal `Ref.lit`. If `deps.is_dynamic_looking(value)` add a `Plan.warnings` entry
     ("step N: value of `X` looks dynamic but could not be traced to any earlier response; replaying the recorded literal may fail").
   The very first step can only have constants / literals.
6. Per-step headers = `clean_request_headers(request.headers)` minus `base_headers`; drop
   `content-type` when `body_kind in {form, json, multipart}`.
7. Body: `application/x-www-form-urlencoded` → `form`; JSON mime (or body parses as JSON object/array)
   → `json_body` with `Ref` leaves; `multipart/form-data` → parse parts (stdlib `email.parser` /
   manual boundary split) → `multipart`; other → `raw_body`.
8. `func_name = f"step_{index:02d}_{method.lower()}_{slug}"` where slug = `util.safe_identifier` of the
   last 1–2 non-empty path segments (or host when path is `/`), made unique.
   Extractor `var` names: `util.safe_identifier(param_name)` made unique across the whole plan
   (e.g. `token`, `csrf_token`, `authorization` → for `Authorization: Bearer X` the candidate value is
   `X` and the header Ref becomes `Ref.expr('"Bearer " + access_token')` — handle the `Bearer `/`Basic `
   prefix explicitly).
9. `Plan.meta = {"source": recording.meta, "generated_at": util.now_iso(), "flows_total": …, "flows_kept": …}`.
10. `opts.max_steps` truncates with a warning.

## 8. Code generator (`reqrec/codegen.py`)

```python
def generate(plan: Plan, opts: GenOptions | None = None) -> str
```
Output is a self-contained script, **valid Python 3.8+**, that:
* starts with a module docstring (generated-by, source, step count, warnings) and the fixed import
  block `json, os, re, sys, time`, `from urllib.parse import unquote, urljoin`, `requests`,
  `from bs4 import BeautifulSoup`;
* defines `TIMEOUT`, `DELAY`, constants (secrets as `os.environ.get("ENV", "")` with a comment),
  `BASE_HEADERS`, `INITIAL_COOKIES`, and helpers `_soup(resp)`, `_check(resp, expected)`,
  `_regex(text, pattern)` (raises a clear `RuntimeError` naming the pattern on miss),
  `_json_path(data, path)` (clear error naming the path), `_attr(soup, selector, attr)`, `_text(soup, selector)`;
* one function per `Step`: `def step_NN_xxx(session, <needed vars…>): -> (resp, dict_of_extracted)`;
  looped steps take the loop var as a parameter and `main()` calls them inside `for VAR in …:`,
  collecting `results`;
* `main()` builds the `Session`, applies base headers and initial cookies, runs steps in order with
  `ctx` threading, sleeps `DELAY` between steps, and finally prints the last result (JSON pretty-printed
  with `ensure_ascii=False`; HTML → title + hint comment; text → first 2000 chars; binary → saves
  `output.bin`). `if __name__ == "__main__": main()`.
* **Every literal that came from the recording is emitted with `repr()`** (or `json.dumps` for JSON
  bodies) — never by string concatenation into source. This is a security boundary: recorded content
  is attacker-controlled. `Ref.expr` is emitted verbatim, `Ref.var` as the identifier.
* query/form pairs: a `dict` when names are unique, else a `list` of tuples. JSON bodies: a Python
  literal with `Ref`s substituted (`True/False/None`, nested). Multipart: `files={name: (filename,
  content_bytes, content_type)}` + `data={…}`; file content > 64 KiB → `b""  # TODO` + warning.
* Non-literal URL pieces: `"https://h/users/" + str(user_id) + "/x"`.
* `allow_redirects=step.allow_redirects` only when False.
* Comments in **Japanese** (the end user is Japanese), identifiers in English. `GenOptions.comments=False` suppresses them.

The output must `compile()` for every Plan; tests must also *execute* generated scripts against a
local server (see §10).

## 9. CLI (`reqrec/cli.py`)

```
reqrec record   -o rec.json [-p 8080] [--listen-host 127.0.0.1] [--hosts a.com,b.com]
reqrec import   INPUT(.har|.mitm|.json) -o rec.json
reqrec inspect  INPUT [filter options] [--json]
reqrec generate INPUT -o scrape.py [filter options] [--html-parser html.parser|lxml] [--no-redact]
                [--delay SEC] [--timeout SEC] [--no-comments] [--strict-status] [--dump-plan plan.json] [--run]
filter options: --include-host H (repeatable, comma ok) --exclude-host H --keep-static --keep-trackers
                --keep-all --no-collapse-redirects --no-loops --min-value-length N --max-steps N
```
`main(argv=None) -> int`. Messages in Japanese. `inspect` prints a table: kept steps (index, method,
status, url, extracted vars) then dropped flows with reasons, then warnings. `generate` prints the
plan summary + warnings to stderr and writes the script (or `-` for stdout). Exit codes: 0 / 1 (error) / 2 (usage).
`--run` executes the generated script right away with `sys.executable`.

## 10. Tests (`tests/`)

* `tests/fixtures/*.har` — hand-written realistic Chrome/Firefox HARs (login with CSRF hidden input,
  JSON API with bearer token from a login JSON, pagination, static noise, trackers, a redirect chain).
* unit tests per module.
* `tests/e2e/server.py` — a stdlib `ThreadingHTTPServer` "site": `/login` (HTML form with random
  per-session `_token` hidden input + `Set-Cookie`), `POST /login` (validates token+cookie, 302 →
  `/dashboard`), `/dashboard` (HTML with `<meta name="csrf-token">`, an inline `window.API_TOKEN="…"`
  script, a link containing a token), `/api/items?page=N` (JSON, requires `X-CSRF-Token` or
  `Authorization: Bearer`), `POST /api/items` (JSON body), static noise (`/static/app.css`,
  `/static/logo.png`, `/favicon.ico`). Tokens are **random per run** so a replayed literal fails.
* `tests/e2e/capture.py` — drives the site with `requests` and builds a `Recording` (use
  `resp.raw.headers.getlist("Set-Cookie")`, include `resp.history`).
* `tests/e2e/test_e2e.py` — capture → `build_plan` → `generate` → run the script in a **subprocess**
  (`sys.executable`, env with `REQREC_PASSWORD`) against a fresh server → assert the output contains
  the items and the server saw fresh tokens.
* `tests/e2e/mock_adapter.py` — a `requests` transport adapter that serves scripted responses, so
  HAR-fixture-generated scripts can be executed in-process against fake hosts.

## 11. Non-goals / known limits (document in README)

JavaScript-computed signatures (HMAC in JS, Akamai/Cloudflare challenges), captchas, TLS/HTTP2
fingerprinting, WebSocket flows. The tool makes the first 80% mechanical; the generated script is a
readable starting point to edit.

## 12. File ownership for parallel implementation

| owner | files |
|---|---|
| A importers/recorder | `reqrec/importers/__init__.py`, `reqrec/importers/har.py`, `reqrec/importers/mitm.py`, `reqrec/recorder/*`, `tests/test_importers.py`, `tests/test_recorder.py`, `tests/fixtures/*.har` |
| B filters | `reqrec/filters.py`, `tests/test_filters.py` |
| C deps/loops/plan | `reqrec/deps.py`, `reqrec/loops.py`, `reqrec/plan.py`, `tests/test_deps.py`, `tests/test_loops.py`, `tests/test_plan.py` |
| D codegen | `reqrec/codegen.py`, `tests/test_codegen.py`, `tests/e2e/mock_adapter.py` |
| E cli/docs | `reqrec/cli.py`, `README.md`, `examples/*`, `tests/test_cli.py` |
| F e2e | `tests/e2e/server.py`, `tests/e2e/capture.py`, `tests/e2e/test_e2e.py`, `tests/e2e/__init__.py` |

Nobody edits `model.py`, `util.py`, `pyproject.toml` or another owner's files. No `git` commands.

---

# Phase 2 — no-code GUI (Flask), Edge IE-mode support, multi-tab recordings

User requirements added after v0.1: (1) a **no-code** tool — a **Flask web app** — rather than CLI only;
(2) first-class session / cookie handling (already in v0.1, exposed in the GUI); (3) **Edge IE mode**
support: recording through the Windows system proxy, Windows integrated auth (NTLM / Negotiate),
legacy TLS servers, Shift_JIS pages, ASP.NET WebForms; (4) screens that open in a **new tab**
(`target=_blank` / `window.open`) — natively covered by proxy recording, and for the HAR path by
**merging several recordings**.

`model.py` already carries the new fields (do not edit it): `PlanOptions.exclude_flow_ids /
include_flow_ids / final_flow_id / detect_auth`, `GenOptions.legacy_tls`, `Plan.auth: AuthInfo`,
`Plan.final_step_index`, `Recording.merge(list)`, `Recording.save(path, atomic=True)`.
`cli.py` already has the `gui` sub-command calling `reqrec.webapp.run_gui(host, port, workdir, open_browser)`.

## 13.1 Manual overrides and the "result" step  (filters.py, plan.py, codegen.py, cli.py)

* `filters.classify_noise`: a flow whose id is in `opts.exclude_flow_ids` → reason
  `"excluded by user"` (checked **first**, before host rules). A flow in `opts.include_flow_ids`
  is kept regardless of rules 3–9 (but still needs a response: a response-less flow cannot be a
  step → reason `"no response recorded"`).
* `plan.build_plan`: when `opts.final_flow_id` names a flow that ended up in a step (as any of its
  `source_flow_ids`), set `Plan.final_step_index = that step's index`; if the flow was dropped,
  add a warning and leave `None`.
* `codegen`: `main()` still runs every step in order; the printed result is the step named by
  `Plan.final_step_index` (fall back to the last step). Implementation: after that step's call,
  `final_resp = resp`; the final print block uses `final_resp` and that step's `response_kind`.
* `cli`: `inspect` / `generate` gain `--exclude-flow ID` (repeatable, comma ok), `--include-flow ID`,
  `--final-flow ID`, plus conveniences `--exclude-step N` / `--final-step N` that resolve step
  numbers to flow ids by building the plan once without overrides, then rebuilding. `inspect` shows
  the flow id(s) of every step (`f0008+f0009`) and of every dropped flow so users can refer to them.

## 13.2 HTTP authentication handshakes  (filters.py, plan.py, codegen.py)

Intranet sites used through IE mode typically use **Integrated Windows Authentication**. On the wire:

```
GET /            → 401  WWW-Authenticate: Negotiate, NTLM
GET /  Authorization: NTLM TlRMTVNTUAAB…   → 401  WWW-Authenticate: NTLM TlRMTVNTUAAC…
GET /  Authorization: NTLM TlRMTVNTUAAD…   → 200
```
(Basic: one 401 then the same request with `Authorization: Basic …`; Digest similar with a nonce.)

* `filters.collapse_auth_handshakes(flows) -> tuple[list[list[Flow]], Optional[AuthInfo]]` (new):
  detect, **before** `collapse_redirects`, a run of flows with the same method + URL (ignoring
  fragment) where every hop but the last is a 401 whose `WWW-Authenticate` names a scheme and the
  next hop carries `Authorization:` with that scheme; fold the run into one group whose *request* is
  the **last** attempt (the one that got through) and whose response chain is the final response
  only. Return `AuthInfo(kind, hosts, realm, username)` for the first scheme seen (`negotiate` when
  the client answered with Negotiate, `ntlm` when with NTLM, else `basic` / `digest`). For NTLM,
  parse the Type-3 message (base64 NTLMSSP, message type 3) to recover `DOMAIN\user` when possible
  (fields are UTF-16LE when the Unicode flag is set) — informational only, never a secret. For
  Basic, decode `user:password` and expose `username`; the password goes into a **secret**
  `Constant` (`AUTH_PASSWORD`, env `REQREC_AUTH_PASSWORD`) and the username into a plain
  `Constant` (`AUTH_USERNAME`); set `AuthInfo.username_const / password_const` accordingly.
  Any later request carrying `Authorization` with the same scheme (NTLM is connection-oriented,
  Basic is repeated on every request) has that header **removed** from the step headers.
* `plan.build_plan` runs it when `opts.detect_auth`; sets `Plan.auth`; the 401 hops never become
  steps. `deps.header_candidates` must not treat NTLM/Negotiate/Basic/Digest `Authorization` values
  as traceable candidates once `Plan.auth` exists (Bearer tokens are unaffected).
* `codegen` (when `plan.auth` is set), right after `session = requests.Session()`:
  * basic → `session.auth = (AUTH_USERNAME, AUTH_PASSWORD)`;
  * digest → `session.auth = requests.auth.HTTPDigestAuth(AUTH_USERNAME, AUTH_PASSWORD)` (constants as for basic);
  * ntlm / negotiate →
    ```python
    # 統合 Windows 認証（NTLM / Negotiate）: 記録時のユーザー: DOMAIN\user
    try:
        from requests_negotiate_sspi import HttpNegotiateAuth  # Windows: 今ログインしているユーザーで認証（pip install "reqrec[sspi]"）
        session.auth = HttpNegotiateAuth()
    except ImportError:
        from requests_ntlm import HttpNtlmAuth  # 他の OS / 別ユーザーで認証する場合（pip install "reqrec[ntlm]"）
        session.auth = HttpNtlmAuth(os.environ.get("REQREC_NTLM_USER", r"DOMAIN\user"), os.environ.get("REQREC_NTLM_PASSWORD", ""))
    ```
    The docstring "注意" lists the required package and env vars. No `Authorization` header of that
    scheme appears anywhere in the emitted steps.

## 13.3 Legacy TLS and certificate verification  (codegen.py, cli.py)

* Always emit `VERIFY_TLS = True  # 自己署名証明書のサイトなら False か CA 証明書 (.pem) のパスに` in the
  settings block and `session.verify = VERIFY_TLS` in `main()`.
* `GenOptions.legacy_tls` (`generate --legacy-tls`; GUI checkbox「古いTLS/暗号しか使えないサーバー」):
  emit a `_LegacyTLSAdapter(requests.adapters.HTTPAdapter)` whose `init_poolmanager` /
  `proxy_manager_for` build an `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` with
  `minimum_version = ssl.TLSVersion.TLSv1` (guarded `try`), `set_ciphers("DEFAULT:@SECLEVEL=1")`,
  `options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)`, `check_hostname`/`verify_mode` left to
  requests (honour `VERIFY_TLS`), and `session.mount("https://", _LegacyTLSAdapter())`. Comment in
  Japanese why this exists (IE モードで使っている古い社内サーバー向け).

## 13.4 Character encoding of responses  (codegen.py)

`requests` falls back to ISO-8859-1 for `text/*` without a charset — Shift_JIS pages become mojibake.
* `_soup(resp)` must parse **bytes**: `BeautifulSoup(resp.content, PARSER)` (bs4 sniffs `<meta charset>` /
  BOM / falls back to chardet-like detection).
* New helper `_text(resp)`: if the `Content-Type` has a charset → `resp.text`; else sniff
  `<meta charset=…>` / `<meta http-equiv content=…charset=…>` / `<?xml encoding=…>` in the first 4 KiB
  of `resp.content` (set `resp.encoding`), else `resp.encoding = resp.apparent_encoding`; return `resp.text`.
  Normalise `shift_jis`/`sjis`/`x-sjis`/`windows-31j` to `cp932`, `euc-jp` stays. Every `_regex(resp.text …)`,
  the final print of text/html and `results.append(resp.text)` use `_text(resp)` instead.
* Form bodies that were recorded percent-encoded in a legacy charset (e.g. `%93%FA%96%7B` = cp932
  「日本」) must round-trip: when a form field value is not valid UTF-8 after unquoting, plan keeps the
  **raw percent-encoded body** (`body_kind = "raw"` with the original `Content-Type`) and warns.
  (Check `util.parse_form` / `deps.classify_body`; add a test with a cp932-encoded form.)

## 13.5 Multi-recording merge  (importers/__init__.py, cli.py)

* `importers.load_recordings(paths: list[str]) -> Recording`: `load_recording` each, then
  `Recording.merge`. One path → identical to `load_recording` (same meta).
* CLI: `import`, `inspect`, `generate` accept one or more `INPUT` (`nargs="+"`). `inspect` header
  names every source. README explains the new-tab case (see §13.9).

## 13.6 Flask GUI  (reqrec/webapp/, reqrec/recorder/manager.py)

```python
# reqrec/webapp/__init__.py
def create_app(workdir: str, **config) -> flask.Flask
def run_gui(host="127.0.0.1", port=8765, workdir="reqrec_work", open_browser=True) -> int
```
Layout: `reqrec/webapp/__init__.py` (factory + run), `routes.py` (blueprint), `state.py` (per-process
session state: loaded recording, current plan/options, recorder, runner), `templates/index.html`,
`static/app.js`, `static/app.css` (vanilla JS, **no CDN / no external resources**; the GUI must work
offline). UI language: **Japanese**. Served only on the bind address; default `127.0.0.1`.

**Security (the user's browser visits arbitrary sites while this GUI runs):**
* every state-changing request (`POST`) must carry header `X-Reqrec-Token` equal to a per-process
  random token (`secrets.token_urlsafe(32)`) that the page receives via the template; missing/wrong
  token → 403 JSON `{"error": "..."}`.
* reject requests whose `Host` header is not `127.0.0.1[:port]` / `localhost[:port]` / the bound
  host (DNS-rebinding guard) → 403; reject cross-origin `Origin` on POST.
* file names from the client are reduced to a basename and must match `^[\w.\-]+$`; everything is
  read/written **inside `workdir`** (resolve + check prefix). Uploaded files are stored under
  `workdir/uploads/`. Generated scripts under `workdir/scripts/`. Recordings under `workdir/recordings/`.
* secrets typed in the 実行 panel (env values) are passed to the subprocess only; never written to disk, never logged.
* `debug=False`; no `flask run` reloader.

**JSON API** (all return JSON; errors `{"error": "<日本語>"}` with 4xx):
* `GET /` → page. `GET /api/state` → `{recorder: {...}, recording: {loaded: bool, sources: [...], flows: n},
  plan_options, gen_options, windows: {is_windows, proxy, cert}}`.
* Recording: `POST /api/record/start {port, hosts: [...], listen_host, set_system_proxy: bool}` → starts
  `RecorderManager` (below); output `workdir/recordings/rec_YYYYmmdd_HHMMSS.json`; when
  `set_system_proxy` and Windows → `winsupport.set_system_proxy` (backup saved; restored on stop /
  app exit). Returns `{instructions: "<日本語>", out, proxy_address}`. `GET /api/record/status` →
  `{running, flows, out, stderr_tail, error}` (counts flows by reading the flushed JSON, tolerant of a
  file mid-write). `POST /api/record/stop` → stops, restores proxy, **loads the recording** as current
  (merging with already loaded ones only when `{"append": true}`), returns `{out, flows}`.
* Loading: `POST /api/recordings/upload` (multipart, field `files`, several allowed: .har/.json/.mitm;
  `append` form field) → saves to `uploads/`, `load_recordings`, sets/merges current; returns summary.
  `GET /api/recordings` lists files in `recordings/` and `uploads/` (name, size, mtime, flows if cheap).
  `POST /api/recordings/open {names: [...], append}` opens server-side files by name.
  `POST /api/recordings/clear`.
* Analysis: `POST /api/plan {plan_options}` → runs `build_plan`, stores plan+options, returns
  `cli.build_inspect_report(...)` **plus** `flows: [{id, started_at, method, status, mime, url, referer,
  kept, reason, step_index, resource_type}]` for *every* flow, `constants`, `auth`, `warnings`,
  `final_step_index`. `GET /api/flow/<id>` → request/response headers and decoded bodies (bodies
  truncated to 200 KiB with a flag; JSON pretty-printed; binary → size + mime only).
* Generation: `POST /api/generate {plan_options, gen_options}` → `{code, summary, warnings, secrets:
  [{name, env_var}]}`; `POST /api/scripts/save {name, code}` → writes `scripts/<name>.py`, returns path;
  `GET /api/scripts/<name>/download`; `GET /api/scripts` list.
* Run: `POST /api/run {name, env: {VAR: value}}` → starts `sys.executable scripts/<name>.py` in a
  thread (cwd `workdir/scripts/`, env = os.environ + given), max one at a time; `GET /api/run/status`
  → `{running, exit_code, stdout_tail, stderr_tail, started_at}`; `POST /api/run/stop`.
  `POST /api/run/save_output {name}` writes the last stdout to `workdir/outputs/<name>`.
* Windows: `GET /api/win/status` → `{is_windows, proxy: {enabled, server, override}, cert: {installed:
  bool|null, path}}`; `POST /api/win/proxy {enable, server}`; `POST /api/win/proxy/restore`;
  `POST /api/win/cert/install` (runs `certutil -user -addstore Root <cert>`; returns output). On other
  OSes → 400 with 「Windows 以外では使えません」.

**RecorderManager** (`reqrec/recorder/manager.py`): wraps `recorder.run.build_command` + `subprocess.Popen`
(`stdout/stderr` to a bounded ring buffer in a reader thread), `start(out, port, hosts, listen_host)`,
`stop(timeout) -> exit_code` (SIGINT/CTRL_BREAK on Windows → terminate → kill; mirrors `run.stop_child`),
`status()`, `flow_count()` (reads the JSON file; returns last good count while the file is mid-write).
Must be testable with a fake command (inject `command_builder`).

**UI** (single page, sections as tabs or a vertical flow):
1. 記録 — ポート・対象ホスト入力、[記録開始]/[記録停止]、進行中はフロー件数をライブ表示、手順カード
   (プロキシ設定 `127.0.0.1:8080`、CA 証明書 `~/.mitmproxy/mitmproxy-ca-cert.pem` / `http://mitm.it`、
   Edge IE モードは Windows の「インターネット オプション」のプロキシを使う旨)。Windows では
   [システムプロキシを設定する] チェックと [CA 証明書をインストール] ボタン、状態表示。
2. 読み込み — ファイル選択(複数: .har/.json/.mitm)、作業フォルダ内ファイル一覧から開く、「追加して結合」トグル。
3. ステップ — フィルタ設定(静的ファイル/トラッカー/全て残す、リダイレクト統合、ループ検出、秘密情報の環境変数化、
   ホスト include/exclude、認証検出、レガシーTLS)、全フローの表(チェック=採用、判定理由、ステップ番号、メソッド、
   ステータス、種類、URL、参照元)、「結果として使う」ラジオ、クリックで詳細ドロワー(リクエスト/レスポンスのヘッダー・本文)。
   表の変更は即 `/api/plan` 再計算。
4. コード — [生成] → プレビュー(`<pre>` + 行番号は任意)、ファイル名入力、[保存]、[ダウンロード]、警告と環境変数の一覧。
5. 実行 — 検出された秘密情報の環境変数ごとの入力欄(type=password)、[実行]/[停止]、標準出力/標準エラーのコンソール、
   [結果を保存]。
Status bar with the last message. Keep the JS modular (`api()`, render functions); no build step.

**Tests**: `tests/test_webapp.py` (Flask test client; every endpoint; token/Host/Origin enforcement;
path traversal attempts; plan/generate on `tests/fixtures/login_flow_chrome.har`; run endpoint with a
tiny script; Windows endpoints → 400 off-Windows; RecorderManager with a fake "mitmdump" python stub
that writes a recording file and exits on SIGINT/terminate), `tests/test_winsupport.py` (pure logic with
injected fakes for winreg / subprocess), `tests/test_webapp_browser.py` (Playwright, Chromium at
`/opt/pw-browsers/chromium` with fallback to default; skipped when unavailable): start the app on a
free port in a thread, upload the fixture HAR, wait for the steps table, uncheck one flow and see the
plan refresh, pick a final step, click 生成, assert the code preview contains `def step_01_`, save,
and run against `tests/e2e/mock_adapter.py`? — no: run is tested with a trivial script; the fixture
script can't reach the fake hosts.

## 13.7 Windows support module  (reqrec/winsupport.py)

```python
def is_windows() -> bool
def get_system_proxy() -> dict            # {"enabled": bool, "server": str, "override": str}  (HKCU\…\Internet Settings)
def set_system_proxy(server: str, enable: bool = True, override: str = "<local>;localhost;127.0.0.1") -> dict   # returns backup of previous values
def restore_system_proxy(backup: dict) -> None
def refresh_proxy_settings() -> None      # ctypes wininet InternetSetOptionW(None, 39, None, 0) and (None, 37, None, 0)
def mitmproxy_ca_cert_path() -> Optional[str]   # ~/.mitmproxy/mitmproxy-ca-cert.cer or .pem, whichever exists
def cert_installed() -> Optional[bool]    # certutil -user -store Root, look for "mitmproxy"; None when certutil unavailable
def install_ca_cert(path: Optional[str] = None) -> tuple[bool, str]   # certutil -user -addstore Root <path>
```
All functions accept injected `winreg` / `run` callables for tests and raise `RuntimeError("Windows 以外では使えません")`
when called for real on other OSes (except `is_windows`, `mitmproxy_ca_cert_path`).

## 13.8 Legacy fixture  (tests/fixtures/legacy_webforms_ntlm.har)

An IE-mode style intranet recording for `http://intra.example.local/`: the NTLM 3-leg handshake on
`GET /Default.aspx`, a **Shift_JIS** WebForms page (`Content-Type: text/html` **without** charset,
`<meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS">`, hidden `__VIEWSTATE`,
`__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`), a `POST /Default.aspx` postback (`__EVENTTARGET`,
`ctl00$txtKeyword=%93%FA%96%7B` (cp932 日本), `ctl00$btnSearch=%8C%9F%8D%F5`), a results page with
`<a href="Report.aspx?id=1234">`, then `GET /Report.aspx?id=1234` (`1234` traced to that href), and a
static `GET /WebResource.axd?d=…` (script) to drop. HAR content for Shift_JIS pages is stored as
base64 (`"encoding": "base64"`) so bytes survive. Expected plan: `auth.kind == "ntlm"`, 4 steps, no
`Authorization` headers, `__VIEWSTATE` etc. as `html_input` extractors, raw percent-encoded form body
kept, `id` traced via `html_attr` + pattern, generated script compiles and replays against the mock
adapter with fresh `__VIEWSTATE` values.

## 13.9 Documentation additions  (README.md, examples/)

New sections: GUI (`reqrec gui`) walkthrough with the five panels; 「Edge IE モードで記録する」 (why the
proxy path works for IE mode, Windows プロキシ設定とCA証明書, IE11 F12 の HAR 保存も可能だがプロキシ記録を推奨,
統合 Windows 認証 → 生成コードの `session.auth`, `pip install "reqrec[sspi]"` / `"reqrec[ntlm]"`,
レガシー TLS オプション, Shift_JIS, WebForms の `__VIEWSTATE`); 「別タブで開く画面」 (proxy records all tabs;
HAR: DevTools 設定「ポップアップに対して DevTools を自動的に開く」→ タブごとに保存 → 複数ファイルを指定して結合);
手動の取捨選択 (`--exclude-flow` 等 / GUI のチェック) と「結果にするステップ」; Windows での配布
(`pip install .` と `reqrec gui`、PyInstaller での exe 化の例 `pyinstaller --onefile --name reqrec --collect-all reqrec --collect-all mitmproxy -m reqrec.cli` は検証していない旨を明記);
更新したオプション表・FAQ (文字化け, 401 が続く, 証明書エラー, IE モードのサイトで TLS エラー).

## 13.10 File ownership for phase 2

| owner | files |
|---|---|
| G gui | `reqrec/webapp/**`, `reqrec/recorder/manager.py`, `reqrec/winsupport.py`, `tests/test_webapp.py`, `tests/test_webapp_browser.py`, `tests/test_winsupport.py` |
| H1 analysis | `reqrec/filters.py`, `reqrec/plan.py`, `reqrec/deps.py`, `reqrec/importers/__init__.py`, `tests/test_filters.py`, `tests/test_plan.py`, `tests/test_deps.py`, `tests/test_auth.py`, `tests/test_overrides.py`, `tests/test_merge.py`, `tests/fixtures/legacy_webforms_ntlm.har`, `tests/test_integration_legacy.py` |
| H2 codegen+cli | `reqrec/codegen.py`, `reqrec/cli.py`, `tests/test_codegen.py`, `tests/test_cli.py`, `tests/test_codegen_phase2.py` |
| I docs | `README.md`, `examples/**` |

Nobody edits `model.py`, `util.py`, `pyproject.toml` or another owner's files. No `git` commands.
`tests/test_integration.py` and `tests/e2e/**` belong to the integrator.
