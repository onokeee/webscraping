"""Tests for reqrec.plan (DESIGN.md §7)."""

from __future__ import annotations

import json
from urllib.parse import unquote

import pytest

from reqrec.model import Flow, PlanOptions, RecordedRequest, RecordedResponse, Recording, Ref
from reqrec.plan import build_plan

T0 = 1_700_000_000.0
BASE = [("User-Agent", "UA/1.0"), ("Accept-Language", "ja"), ("Accept-Encoding", "gzip"), ("Connection", "keep-alive")]
HTML = [("Content-Type", "text/html; charset=utf-8")]
JSON = [("Content-Type", "application/json")]
FORM = ("Content-Type", "application/x-www-form-urlencoded")


class Site:
    """Tiny helper that builds Flows quickly (ids and timestamps are sequential)."""

    def __init__(self, host="https://site.example"):
        self.host = host
        self.flows: list[Flow] = []

    def add(self, method, path, req_headers=(), body=None, status=200, resp_headers=HTML, resp_body=b"", rtype=None,
            no_response=False, base=True):
        url = path if path.startswith("http") else self.host + path
        headers = (list(BASE) if base else []) + list(req_headers)
        resp = None if no_response else RecordedResponse(status, list(resp_headers), resp_body)
        f = Flow(f"f{len(self.flows) + 1:04d}", RecordedRequest(method, url, headers, body), resp,
                 started_at=T0 + len(self.flows), resource_type=rtype)
        self.flows.append(f)
        return f

    def recording(self, **meta):
        return Recording(flows=list(self.flows), meta=meta or {"source": "test"})

    def plan(self, opts=None, **meta):
        return build_plan(self.recording(**meta), opts)


def step_by_func(plan, needle):
    return next(s for s in plan.steps if needle in s.func_name)


def hdr(step, name):
    return next(r for n, r in step.headers if n.lower() == name.lower())


def form(step, name):
    return dict(step.form)[name]


def params(step):
    return dict(step.params)


# --------------------------------------------------------------------------- scenarios

LOGIN_HTML = (b'<html><body><form method="post" action="/login"><input type="hidden" name="_token" value="CSRFhidden123456">'
              b'<input name="username"><input name="password"></form></body></html>')
DASH_HTML = (b'<html><head><meta name="csrf-token" content="METAcsrf7890"></head><body>'
             b'<a class="export" href="/api/export?token=LINKtok44556&amp;f=csv">x</a>'
             b'<script>window.API_TOKEN="APIt0k3n99887766";</script></body></html>')


def login_site():
    s = Site()
    s.add("GET", "/login", [("Accept", "text/html")], resp_headers=HTML + [("Set-Cookie", "sess=S3SS10N; Path=/; HttpOnly"),
                                                                           ("Set-Cookie", "XSRF-TOKEN=xsrf%3D%3Dabc; Path=/")], resp_body=LOGIN_HTML)
    s.add("POST", "/login", [("Accept", "text/html"), FORM, ("Cookie", "sess=S3SS10N"), ("Origin", "https://site.example")],
          body=b"_token=CSRFhidden123456&username=alice_w&password=Secr3tPass%21", status=302, resp_headers=[("Location", "/dashboard")])
    s.add("GET", "/dashboard", [("Accept", "text/html"), ("Cookie", "sess=S3SS10N")], resp_body=DASH_HTML)
    return s


def test_login_csrf_hidden_input_and_redirect_chain():
    plan = login_site().plan()
    assert [s.func_name for s in plan.steps] == ["step_01_get_login", "step_02_post_login"]
    get_login, post_login = plan.steps
    assert get_login.index == 1 and get_login.response_kind == "html" and get_login.expected_status == 200
    (ext,) = get_login.extractors
    assert (ext.kind, ext.name, ext.var, ext.sample) == ("html_input", "_token", "token", "CSRFhidden123456")
    assert "step 2" in ext.note
    assert form(post_login, "_token") == Ref.var("token")
    assert post_login.body_kind == "form"
    # collapsed chain: final response of the chain describes the step
    assert post_login.source_flow_ids == ["f0002", "f0003"]
    assert post_login.expected_status == 200 and post_login.response_kind == "html" and post_login.allow_redirects is True
    assert "redirect chain" in post_login.comment
    # content-type dropped for form bodies, cookie never emitted, base headers removed
    names = [n.lower() for n, _ in post_login.headers]
    assert "content-type" not in names and "cookie" not in names and "user-agent" not in names
    assert hdr(post_login, "Origin") == Ref.lit("https://site.example")


def test_password_secret_constant_and_literal_username():
    plan = login_site().plan()
    post_login = plan.steps[1]
    assert form(post_login, "username") == Ref.lit("alice_w")
    (pw,) = plan.constants
    assert pw.name == "PASSWORD" and pw.secret is True and pw.env_var == "REQREC_PASSWORD" and pw.value == "Secr3tPass!"
    assert form(post_login, "password") == Ref.var("PASSWORD")
    assert "step 2" in pw.comment
    assert any("REQREC_PASSWORD" in w for w in plan.warnings)
    # --no-redact keeps the literal
    plan2 = login_site().plan(PlanOptions(redact_secrets=False))
    assert form(plan2.steps[1], "password") == Ref.lit("Secr3tPass!") and plan2.constants == []


def test_username_repeated_in_two_requests_becomes_constant():
    s = login_site()
    s.add("POST", "/api/profile", [("Accept", "application/json"), ("Content-Type", "application/json")],
          body=json.dumps({"username": "alice_w", "display": "Alice W."}).encode(), resp_headers=JSON, resp_body=b'{"ok": true}')
    plan = s.plan()
    const = {c.name: c for c in plan.constants}
    assert set(const) == {"PASSWORD", "USERNAME"}
    assert const["USERNAME"].value == "alice_w" and const["USERNAME"].secret is False and const["USERNAME"].env_var is None
    assert "step 2" in const["USERNAME"].comment and "step 3" in const["USERNAME"].comment
    assert form(plan.steps[1], "username") == Ref.var("USERNAME")
    assert plan.steps[2].json_body == {"username": Ref.var("USERNAME"), "display": "Alice W."}


def test_meta_csrf_header_and_xsrf_cookie_header():
    s = login_site()
    s.add("GET", "/api/items?page=1", [("Accept", "application/json"), ("X-CSRF-Token", "METAcsrf7890"), ("X-XSRF-TOKEN", "xsrf==abc"),
                                        ("Cookie", "sess=S3SS10N; XSRF-TOKEN=xsrf%3D%3Dabc")], resp_headers=JSON, resp_body=b'{"items": []}')
    plan = s.plan()
    api = plan.steps[2]
    assert hdr(api, "X-CSRF-Token") == Ref.var("x_csrf_token")
    meta_ext = next(e for e in plan.steps[1].extractors if e.kind == "html_meta")
    assert meta_ext.name == "csrf-token" and meta_ext.var == "x_csrf_token"
    assert hdr(api, "X-XSRF-TOKEN") == Ref.expr('unquote(session.cookies.get("XSRF-TOKEN"))')
    assert hdr(api, "Accept") == Ref.lit("application/json")
    assert params(api) == {"page": Ref.lit("1")}
    assert api.response_kind == "json"


def test_plain_cookie_value_reference():
    s = login_site()
    s.add("GET", "/api/me?sid=S3SS10N", [("Accept", "application/json")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert params(plan.steps[2])["sid"] == Ref.expr('session.cookies.get("sess")')


def test_bearer_token_from_json_login_response():
    s = Site()
    s.add("POST", "/api/login", [("Content-Type", "application/json")], body=json.dumps({"user": "bob", "password": "pw123456"}).encode(),
          resp_headers=JSON, resp_body=json.dumps({"access_token": "ACC3SSt0ken.abc.def", "expires": 3600}).encode())
    s.add("GET", "/api/me", [("Authorization", "Bearer ACC3SSt0ken.abc.def"), ("Accept", "application/json")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    (ext,) = plan.steps[0].extractors
    assert (ext.kind, ext.path, ext.var) == ("json", ["access_token"], "access_token")
    assert hdr(plan.steps[1], "Authorization") == Ref.expr('"Bearer " + access_token')
    assert plan.steps[0].body_kind == "json" and plan.steps[0].json_body["password"] == Ref.var("PASSWORD")
    assert plan.steps[0].json_body["user"] == "bob"
    names = [n.lower() for n, _ in plan.steps[0].headers]
    assert "content-type" not in names


def test_untraced_bearer_token_becomes_secret_constant_with_prefix():
    s = Site()
    s.add("GET", "/api/me", [("Authorization", "Bearer STATICtoken0001")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    (const,) = plan.constants
    assert const.name == "AUTHORIZATION" and const.secret and const.env_var == "REQREC_AUTHORIZATION" and const.value == "STATICtoken0001"
    assert hdr(plan.steps[0], "Authorization") == Ref.expr('"Bearer " + AUTHORIZATION')
    plan2 = s.plan(PlanOptions(redact_secrets=False))
    assert hdr(plan2.steps[0], "Authorization") == Ref.lit("Bearer STATICtoken0001")


def test_inline_script_token_via_regex_and_href_token_via_attr_pattern():
    s = login_site()
    s.add("POST", "/api/items", [("Accept", "application/json"), ("Authorization", "Bearer APIt0k3n99887766"), ("Content-Type", "application/json")],
          body=b'{"name": "widget"}', status=201, resp_headers=JSON, resp_body=b'{"id": 1}')
    s.add("GET", "/api/export?token=LINKtok44556&f=csv", [("Accept", "text/csv")], resp_headers=[("Content-Type", "text/csv")], resp_body=b"a,b\n1,2\n")
    plan = s.plan()
    dash_exts = {e.kind: e for e in plan.steps[1].extractors}
    assert dash_exts["regex"].var == "api_token" and "APIt0k3n99887766" not in dash_exts["regex"].pattern
    assert hdr(plan.steps[2], "Authorization") == Ref.expr('"Bearer " + api_token')
    assert plan.steps[2].expected_status == 201
    href = dash_exts["html_attr"]
    assert href.selector == "a.export" and href.attr == "href" and href.pattern and "LINKtok44556" not in href.pattern
    assert params(plan.steps[3])["token"] == Ref.var(href.var) and href.var == "token_2"  # "token" taken by _token
    assert params(plan.steps[3])["f"] == Ref.lit("csv")
    assert plan.steps[3].response_kind == "text"


def test_path_segment_from_json_response_splits_url():
    s = Site()
    s.add("GET", "/api/orgs", [("Accept", "application/json")], resp_headers=JSON, resp_body=b'{"orgs": [{"id": 7701, "name": "acme"}]}')
    s.add("GET", "/api/orgs/7701/items?limit=50", [("Accept", "application/json")], resp_headers=JSON, resp_body=b"[]")
    plan = s.plan()
    (ext,) = plan.steps[0].extractors
    assert (ext.kind, ext.path, ext.var) == ("json", ["orgs", 0, "id"], "org_id")
    step = plan.steps[1]
    assert step.url == [Ref.lit("https://site.example/api/orgs/"), Ref.var("org_id"), Ref.lit("/items")]
    assert step.literal_url() is None
    assert step.func_name == "step_02_get_orgs_items"
    assert params(step)["limit"] == Ref.lit("50")


def test_url_percent_encoding_preserved_and_trailing_slash():
    s = Site()
    s.add("GET", "/api/ids", resp_headers=JSON, resp_body=b'{"id": "ID0001"}')
    s.add("GET", "/p/%E3%81%82/ID0001/", resp_headers=HTML, resp_body=b"<html></html>")
    plan = s.plan()
    # previous segment is not a word -> generic name path_seg_N
    assert plan.steps[1].url == [Ref.lit("https://site.example/p/%E3%81%82/"), Ref.var("path_seg_2"), Ref.lit("/")]


def test_pagination_loop_numeric_range():
    s = login_site()
    for page in (1, 2, 3):
        s.add("GET", f"/api/items?page={page}&_=1700000000{page:03d}", [("Accept", "application/json"), ("X-CSRF-Token", "METAcsrf7890"),
                                                                         ("Referer", f"https://site.example/dashboard?p={page}")],
              resp_headers=JSON, resp_body=json.dumps({"items": [{"id": 1000 + page}], "next": f"NEXTcursor{page}000"}).encode())
    s.add("GET", "/api/items/1003", [("Accept", "application/json"), ("X-CSRF-Token", "METAcsrf7890")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert len(plan.steps) == 4
    loop_step = plan.steps[2]
    assert loop_step.loop is not None
    assert loop_step.loop.var == "page" and loop_step.loop.values == ["1", "2", "3"] and loop_step.loop.numeric_range == (1, 3)
    assert params(loop_step)["page"] == Ref.var("page")
    assert params(loop_step)["_"] == Ref.expr("str(int(time.time()*1000))")
    assert loop_step.source_flow_ids == ["f0004", "f0005", "f0006"]
    assert hdr(loop_step, "X-CSRF-Token") == Ref.var("x_csrf_token")
    # the response of the looped step is the LAST iteration's: 1003 is traced to it
    (ext,) = loop_step.extractors
    assert ext.path == ["items", 0, "id"] and ext.sample == "1003"
    assert plan.steps[3].url == [Ref.lit("https://site.example/api/items/"), Ref.var(ext.var)]
    assert "x3" in loop_step.comment
    plan_noloop = s.plan(PlanOptions(detect_loops=False))
    assert len(plan_noloop.steps) == 6 and all(st.loop is None for st in plan_noloop.steps)


def test_timestamp_cache_buster_expr_in_first_step_and_json_numeric():
    s = Site()
    s.add("GET", "/api/x?_=1700000000123&t=1700000000", resp_headers=JSON, resp_body=b"{}")
    s.add("POST", "/api/y", [("Content-Type", "application/json")], body=b'{"ts": 1700000000456, "s": "1700000000"}', resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert params(plan.steps[0]) == {"_": Ref.expr("str(int(time.time()*1000))"), "t": Ref.expr("str(int(time.time()))")}
    assert plan.steps[1].json_body == {"ts": Ref.expr("int(time.time()*1000)"), "s": Ref.expr("str(int(time.time()))")}


def test_initial_cookies_only_for_kept_hosts_and_base_headers():
    s = Site()
    s.add("GET", "/a", [("Cookie", "theme=dark; sess=OLD"), ("Accept", "text/html")], resp_headers=HTML + [("Set-Cookie", "sess=NEW; Path=/")])
    s.add("GET", "https://tracker.doubleclick.net/pixel", [("Cookie", "IDE=trackme")], resp_headers=[("Content-Type", "image/gif")])
    s.add("GET", "/b", [("Cookie", "theme=dark; sess=NEW"), ("Accept", "application/json")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert [(c.name, c.value, c.domain) for c in plan.initial_cookies] == [("theme", "dark", "site.example"), ("sess", "OLD", "site.example")]
    assert plan.base_headers == [("User-Agent", "UA/1.0"), ("Accept-Language", "ja")]
    for step in plan.steps:
        names = [n.lower() for n, _ in step.headers]
        assert names == ["accept"]
    assert any("INITIAL_COOKIES" in w for w in plan.warnings)


def test_noise_dropped_with_reasons_and_meta():
    s = Site()
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/static/app.css", resp_headers=[("Content-Type", "text/css")], rtype="stylesheet")
    s.add("GET", "https://www.googletagmanager.com/gtm.js", resp_headers=[("Content-Type", "application/javascript")])
    s.add("OPTIONS", "/api", status=204)
    s.add("GET", "/api/data", resp_headers=JSON, resp_body=b"{}", no_response=True)
    s.add("GET", "/api/data", resp_headers=JSON, resp_body=b"{}")
    plan = s.plan(source="har", file="x.har")
    assert [(d.flow_id, d.reason) for d in plan.dropped] == [
        ("f0002", "static asset (resource type stylesheet)"),
        ("f0003", "tracker/analytics host"),
        ("f0004", "CORS preflight"),
        ("f0005", "no response recorded"),
    ]
    assert [st.source_flow_ids for st in plan.steps] == [["f0001"], ["f0006"]]
    assert plan.meta["source"] == {"source": "har", "file": "x.har"}
    assert plan.meta["flows_total"] == 6 and plan.meta["flows_kept"] == 2 and plan.meta["steps"] == 2
    assert "generated_at" in plan.meta


def test_keep_all_keep_static_include_hosts():
    s = Site()
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/static/app.css", resp_headers=[("Content-Type", "text/css")])
    s.add("GET", "https://www.googletagmanager.com/gtm.js", resp_headers=[("Content-Type", "application/javascript")])
    s.add("GET", "https://cdn.other.net/lib.json", resp_headers=JSON, resp_body=b"{}")
    assert len(s.plan().steps) == 2
    assert len(s.plan(PlanOptions(keep_static=True)).steps) == 3
    assert len(s.plan(PlanOptions(keep_all=True)).steps) == 4
    inc = s.plan(PlanOptions(include_hosts=["site.example"], keep_all=True))
    assert len(inc.steps) == 2 and {d.reason for d in inc.dropped} == {"host not in --include-host"}
    exc = s.plan(PlanOptions(exclude_hosts=["other.net"]))
    assert [d.reason for d in exc.dropped if d.flow_id == "f0004"] == ["host excluded"]


def test_max_steps_truncates_with_warning():
    s = Site()
    for i in range(5):
        s.add("GET", f"/p{i}", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(max_steps=2, detect_loops=False))  # /p0../p4 would otherwise fold into a path loop
    assert len(plan.steps) == 2
    assert any("max-steps" in w for w in plan.warnings)
    assert [d.flow_id for d in plan.dropped] == ["f0003", "f0004", "f0005"]
    assert plan.meta["flows_kept"] == 2


def test_dynamic_untraced_literal_warns():
    s = Site()
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/api?sig=8f3a9c2d1e4b5a6f7a8b&sort=name", resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert params(plan.steps[1])["sig"] == Ref.lit("8f3a9c2d1e4b5a6f7a8b")
    assert any("step 2" in w and "`sig`" in w and "looks dynamic" in w for w in plan.warnings)
    assert not any("`sort`" in w for w in plan.warnings)


def test_first_step_only_has_literals_and_constants():
    s = Site()
    s.add("POST", "/login", [FORM], body=b"user=someone_long&password=pw12345678&tok=8f3a9c2d1e4b5a6f", resp_body=b"<html></html>")
    plan = s.plan()
    (step,) = plan.steps
    assert step.extractors == []
    assert form(step, "user") == Ref.lit("someone_long") and form(step, "password") == Ref.var("PASSWORD")
    assert form(step, "tok") == Ref.lit("8f3a9c2d1e4b5a6f")


def test_multipart_body():
    boundary = "----WebKitFormBoundaryX1"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nTitle 0001\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\nCSRFmp12345\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
            f"--{boundary}--\r\n").encode()
    s = Site()
    s.add("GET", "/form", resp_body=b'<html><input type="hidden" name="csrf" value="CSRFmp12345"></html>')
    s.add("POST", "/upload", [("Content-Type", f"multipart/form-data; boundary={boundary}")], body=body, resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    step = plan.steps[1]
    assert step.body_kind == "multipart"
    parts = {p.name: p for p in step.multipart}
    assert parts["title"].value == Ref.lit("Title 0001") and parts["csrf"].value == Ref.var("csrf")
    assert parts["file"].filename == "a.txt" and parts["file"].content == b"hello" and parts["file"].content_type == "text/plain"
    assert "content-type" not in [n.lower() for n, _ in step.headers]


def test_raw_body_and_binary_response_and_no_crash_on_garbage():
    s = Site()
    s.add("POST", "/soap", [("Content-Type", "text/xml")], body=b"<x>\xff\xfe</x>", resp_headers=[("Content-Type", "application/xml")], resp_body=b"<r/>")
    s.add("POST", "/bin", [("Content-Type", "application/octet-stream")], body=b"\x00\x01\x02", resp_headers=[("Content-Type", "application/pdf")], resp_body=b"%PDF\x00")
    s.add("GET", "/nothing", status=204, resp_headers=[], resp_body=None)
    s.add("GET", "/weird", resp_headers=[("Content-Type", "text/html; charset=bogus-charset")], resp_body=b"\xff\xfe\x00bad")
    s.add("GET", "/plainjson", resp_headers=[("Content-Type", "text/plain")], resp_body=b'{"a": 1}')
    s.add("GET", "/noct", resp_headers=[], resp_body=b"\x89PNG\x00\x00")
    plan = s.plan(PlanOptions(detect_loops=False))  # four "GET /<word>" requests would fold into a path loop
    kinds = [(st.body_kind, st.response_kind) for st in plan.steps]
    assert kinds == [("raw", "xml"), ("raw", "binary"), ("none", "empty"), ("none", "html"), ("none", "json"), ("none", "binary")]
    assert plan.steps[0].raw_body == b"<x>\xff\xfe</x>" and plan.steps[1].raw_body == b"\x00\x01\x02"
    assert plan.steps[2].expected_status == 204


def test_empty_recording_and_missing_responses():
    plan = build_plan(Recording(flows=[], meta={}))
    assert plan.steps == [] and plan.constants == [] and plan.base_headers == [] and plan.meta["flows_total"] == 0
    s = Site()
    s.add("GET", "/a", no_response=True)
    plan = s.plan()
    assert plan.steps == [] and plan.dropped[0].reason == "no response recorded"


def test_same_value_in_same_request_gets_same_ref_and_extractor_dedupe():
    s = Site()
    s.add("GET", "/form", resp_body=b'<html><input type="hidden" name="t" value="SAMEtoken00001"></html>')
    s.add("POST", "/a?t=SAMEtoken00001", [FORM, ("X-Token", "SAMEtoken00001")], body=b"t=SAMEtoken00001", resp_body=b"<html></html>")
    s.add("POST", "/b", [FORM], body=b"t=SAMEtoken00001", resp_body=b"<html></html>")
    plan = s.plan()
    assert len(plan.steps[0].extractors) == 1
    ext = plan.steps[0].extractors[0]
    assert "step 2" in ext.note and "step 3" in ext.note
    st = plan.steps[1]
    assert params(st)["t"] == form(st, "t") == hdr(st, "X-Token") == Ref.var(ext.var)
    assert form(plan.steps[2], "t") == Ref.var(ext.var)


def test_redirect_chain_location_value_via_url_kind():
    s = Site()
    s.add("GET", "/auth", status=302, resp_headers=[("Location", "/cb?code=AUTHcode123456&state=xyz")])
    s.add("GET", "/cb?code=AUTHcode123456&state=xyz", resp_body=b"<html>done</html>")
    s.add("POST", "/token", [FORM], body=b"code=AUTHcode123456&grant=authorization_code", resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert len(plan.steps) == 2 and plan.steps[0].source_flow_ids == ["f0001", "f0002"]
    (ext,) = plan.steps[0].extractors
    assert ext.kind == "url" and "AUTHcode123456" not in ext.pattern
    assert form(plan.steps[1], "code") == Ref.var(ext.var) and ext.var == "code"
    plan2 = s.plan(PlanOptions(collapse_redirects=False))
    assert len(plan2.steps) == 3 and plan2.steps[0].expected_status == 302


def test_variable_names_are_unique_and_not_reserved():
    s = Site()
    s.add("GET", "/a", resp_body=b'<html><input name="type" value="TYPEval0001"><input name="session" value="SESSval0001"><input name="data" value="DATAval0001"></html>')
    s.add("GET", "/b?type=TYPEval0001&session=SESSval0001&data=DATAval0001&data2=DATAval0001&timeout=TIMEOUTval01", resp_headers=JSON, resp_body=b"{}")
    s.add("GET", "/c?timeout=TIMEOUTval01", resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    names = [e.var for e in plan.steps[0].extractors]
    assert len(set(names)) == len(names) and all(n not in ("type", "session", "data") for n in names)
    assert plan.constants[0].name not in ("TIMEOUT",) and plan.constants[0].value == "TIMEOUTval01"


def test_json_response_value_in_header_uses_adapted_ref_for_encoded_variant():
    s = Site()
    s.add("GET", "/a", resp_body=b'<html><a id="next" href="/go?u=a%2Fb%2Fc12345">n</a></html>')
    s.add("GET", "/go?u=a/b/c12345", resp_body=b"<html></html>")
    plan = s.plan()
    ref = params(plan.steps[1])["u"]
    (ext,) = plan.steps[0].extractors
    assert ext.kind == "html_attr" and ext.selector == "#next"
    assert ref == Ref.expr(f"unquote({ext.var})")
    assert unquote(ext.sample) == "a/b/c12345"


def test_slug_and_func_name_edge_cases():
    s = Site()
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/very/deep/path/items.json?x=1", resp_headers=JSON, resp_body=b"{}")
    s.add("DELETE", "/items/12345", status=204, resp_headers=[], resp_body=b"")
    plan = s.plan()
    assert [st.func_name for st in plan.steps] == [
        "step_01_get_site_example", "step_02_get_site_example", "step_03_get_path_items_json", "step_04_delete_items",
    ]


# --------------------------------------------------------------------------- short ids and plain words

def test_short_numeric_path_segment_traced_to_json_leaf():
    """``/orgs/77/items`` after ``GET /me`` -> ``{"org": {"id": 77}}``: traced although 77 is short."""
    s = Site()
    s.add("GET", "/api/me", [("Accept", "application/json")], resp_headers=JSON,
          resp_body=b'{"id": 4821, "name": "Alice", "org": {"id": 77, "name": "Example Org"}}')
    s.add("GET", "/api/orgs/77/items?page=1", [("Accept", "application/json")], resp_headers=JSON, resp_body=b"[]")
    plan = s.plan()
    ext = plan.steps[0].extractors[0]
    assert (ext.kind, ext.path, ext.var, ext.sample) == ("json", ["org", "id"], "org_id", "77")
    assert plan.steps[1].url == [Ref.lit("https://site.example/api/orgs/"), Ref.var("org_id"), Ref.lit("/items")]
    assert plan.steps[1].func_name == "step_02_get_orgs_items"
    assert plan.warnings == []


def test_short_numeric_path_segment_is_never_pattern_traced():
    """A two-digit id occurs in prose by coincidence: only exact structural matches count."""
    s = Site()
    s.add("GET", "/page", resp_body=b'<html><body><p class="o">Order 77 of 1977 shipped</p><a href="/x?n=77">x</a></body></html>')
    s.add("GET", "/orders/77")
    plan = s.plan()
    assert plan.steps[0].extractors == []
    assert plan.steps[1].url == [Ref.lit("https://site.example/orders/77")]


def test_plain_word_path_segment_is_not_traced_through_patterns():
    """``dashboard`` is a path name, not a token: neither the redirect Location nor an href is used."""
    s = Site()
    s.add("POST", "/login", [FORM], body=b"username=alice_w&password=Secr3tPass%21", status=302,
          resp_headers=[("Location", "/dashboard")])
    s.add("GET", "/dashboard", resp_body=b'<html><body><a href="/dashboard" class="active">Home</a></body></html>')
    s.add("GET", "/dashboard", resp_body=b"<html><body>again</body></html>")  # explicit navigation
    plan = s.plan()
    assert [st.func_name for st in plan.steps] == ["step_01_post_login", "step_02_get_dashboard"]
    assert plan.steps[1].url == [Ref.lit("https://site.example/dashboard")]
    assert all(not e.pattern for st in plan.steps for e in st.extractors)


def test_func_name_slug_from_numeric_host_has_no_leading_underscore():
    s = Site(host="http://127.0.0.1:8000")
    s.add("GET", "/")
    assert s.plan().steps[0].func_name == "step_01_get_127_0_0_1"


# --------------------------------------------------------------------------- phase 2: legacy-charset forms (DESIGN.md §13.4)

SJIS_PAGE = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"></head><body>'
             '<form method="post" action="./Default.aspx" id="form1">'
             '<input type="hidden" name="__VIEWSTATE" value="dDwtMTI3NjU0ODE4Nzs7Pg5QcVUGkTdF" />'
             '<input type="hidden" name="__EVENTVALIDATION" value="/wEWAwLcx6TQBwKU7LvkBgLs0bLrBg==" />'
             '<input name="ctl00$txtKeyword" type="text" /><input type="submit" name="ctl00$btnSearch" value="検索" />'
             '</form></body></html>').encode("cp932")
SJIS_POST = (b"__EVENTTARGET=&__VIEWSTATE=dDwtMTI3NjU0ODE4Nzs7Pg5QcVUGkTdF&__EVENTVALIDATION=%2FwEWAwLcx6TQBwKU7LvkBgLs0bLrBg%3D%3D"
             b"&ctl00%24txtKeyword=%93%FA%96%7B&ctl00%24btnSearch=%8C%9F%8D%F5")


def test_cp932_percent_encoded_form_is_replayed_raw_with_content_type():
    s = Site()
    s.add("GET", "/Default.aspx", resp_headers=[("Content-Type", "text/html")], resp_body=SJIS_PAGE)
    s.add("POST", "/Default.aspx", [FORM, ("Referer", "https://site.example/Default.aspx")], body=SJIS_POST,
          resp_headers=[("Content-Type", "text/html")], resp_body=SJIS_PAGE)
    plan = s.plan()
    get_page, post = plan.steps
    assert post.body_kind == "raw" and post.raw_body == SJIS_POST
    assert hdr(post, "Content-Type") == Ref.lit("application/x-www-form-urlencoded")
    # dependency detection still works on the form fields ...
    exts = {e.name: e for e in get_page.extractors}
    assert set(exts) == {"__VIEWSTATE", "__EVENTVALIDATION"} and all(e.kind == "html_input" for e in exts.values())
    # ... and the form hint keeps the traced Refs plus bytes literals for the cp932 values
    form_hint = dict(post.form)
    assert form_hint["__VIEWSTATE"] == Ref.var("viewstate") and form_hint["__EVENTVALIDATION"] == Ref.var("eventvalidation")
    assert form_hint["ctl00$txtKeyword"] == Ref.expr(repr("日本".encode("cp932")))
    assert form_hint["ctl00$btnSearch"] == Ref.expr(repr("検索".encode("cp932")))
    assert form_hint["__EVENTTARGET"] == Ref.lit("")
    assert [name for name, _ in post.form] == ["__EVENTTARGET", "__VIEWSTATE", "__EVENTVALIDATION", "ctl00$txtKeyword", "ctl00$btnSearch"]
    (warning,) = [w for w in plan.warnings if "step 2" in w]
    assert "Shift_JIS" in warning and "__VIEWSTATE" in warning
    assert not any("looks dynamic" in w for w in plan.warnings)
    assert post.func_name == "step_02_post_default_aspx" and get_page.func_name == "step_01_get_default_aspx"


def test_utf8_form_with_japanese_stays_a_normal_form():
    s = Site()
    s.add("GET", "/search", resp_body=b'<html><input type="hidden" name="csrf" value="CSRFutf8abc123"></html>')
    s.add("POST", "/search", [FORM], body=b"csrf=CSRFutf8abc123&q=%E6%97%A5%E6%9C%AC&submit=%E6%A4%9C%E7%B4%A2", resp_body=b"<html></html>")
    plan = s.plan()
    post = plan.steps[1]
    assert post.body_kind == "form" and post.raw_body is None
    assert form(post, "q") == Ref.lit("日本") and form(post, "csrf") == Ref.var("csrf")
    assert "content-type" not in [n.lower() for n, _ in post.headers]
    assert not any("Shift_JIS" in w for w in plan.warnings)


def test_declared_legacy_charset_on_the_request_decodes_values_but_still_replays_raw():
    s = Site()
    s.add("GET", "/f", resp_body=b"<html></html>")
    s.add("POST", "/f", [("Content-Type", "application/x-www-form-urlencoded; charset=Shift_JIS")],
          body=b"q=%93%FA%96%7B&n=12345678", resp_body=b"<html></html>")
    plan = s.plan()
    post = plan.steps[1]
    assert post.body_kind == "raw" and hdr(post, "Content-Type") == Ref.lit("application/x-www-form-urlencoded; charset=Shift_JIS")
    assert dict(post.form)["q"] == Ref.expr(repr("日本".encode("cp932"))) and dict(post.form)["n"] == Ref.lit("12345678")


# --------------------------------------------------------------------------- phase 2: route names and reserved parameter names

def test_route_like_path_segments_are_never_constants_or_pattern_traced():
    s = Site()
    s.add("GET", "/Default.aspx", resp_body=b'<html><a id="self" href="Default.aspx?x=1">self</a><a id="next" href="Report.aspx?id=4321">r</a></html>')
    s.add("POST", "/Default.aspx", [FORM], body=b"q=hello_world", resp_body=b"<html></html>")
    s.add("GET", "/Default.aspx", resp_body=b"<html></html>")
    s.add("GET", "/Report.aspx?id=4321", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(detect_loops=False))
    assert plan.constants == []
    assert all(st.literal_url() for st in plan.steps)
    assert plan.steps[3].literal_url() == "https://site.example/Report.aspx"
    (ext,) = plan.steps[0].extractors
    assert ext.selector == "#next" and ext.var == "report_id" and params(plan.steps[3])["id"] == Ref.var("report_id")
    assert [st.func_name for st in plan.steps] == [
        "step_01_get_default_aspx", "step_02_post_default_aspx", "step_03_get_default_aspx", "step_04_get_report_aspx",
    ]


def test_reserved_parameter_names_are_qualified_with_the_route():
    s = Site()
    s.add("GET", "/api/items", resp_headers=JSON, resp_body=b'{"items": [{"id": 9001, "type": "WIDGET_X1"}]}')
    s.add("GET", "/api/items/detail?id=9001&type=WIDGET_X1", resp_headers=JSON, resp_body=b"{}")
    s.add("GET", "/?id=9001", resp_body=b"<html></html>")
    plan = s.plan()
    names = {e.var for e in plan.steps[0].extractors}
    assert names == {"detail_id", "detail_type"}
    assert params(plan.steps[1]) == {"id": Ref.var("detail_id"), "type": Ref.var("detail_type")}
    assert params(plan.steps[2]) == {"id": Ref.var("detail_id")}  # reused extractor, named after its first consumer


def test_plan_without_auth_has_no_auth_fields():
    plan = login_site().plan()
    assert plan.auth is None and plan.final_step_index is None and "auth" not in plan.meta


# --------------------------------------------------------------------------- review 3: route-like path segments

def test_all_uppercase_path_key_is_traced_to_an_exact_json_leaf():
    """Regression: letters-only path segments were removed from the candidates, so a base32 session
    key in the path (traceable to a JSON leaf) stayed a stale literal."""
    s = Site()
    s.add("GET", "/api/session", resp_headers=JSON, resp_body=b'{"session": {"key": "QZVBNMWRTYPXSDFKHJ"}}')
    s.add("GET", "/s/QZVBNMWRTYPXSDFKHJ/items", resp_headers=JSON, resp_body=b"[]")
    plan = s.plan()
    (ext,) = plan.steps[0].extractors
    assert (ext.kind, ext.path) == ("json", ["session", "key"])
    assert plan.steps[1].url == [Ref.lit("https://site.example/s/"), Ref.var(ext.var), Ref.lit("/items")]


def test_route_like_path_segment_keeps_exact_header_and_input_traces_but_never_markup():
    s = Site()
    s.add("GET", "/start", resp_headers=HTML + [("X-Next-Page", "SC0020.aspx")],
          resp_body=b'<html><a id="nx" href="SC0020.aspx">next</a><span id="pg">SC0030.aspx</span>'
                    b'<form action="KJ010Search.aspx"><input type="hidden" name="hdnNext" value="Menu01.aspx"></form></html>')
    s.add("GET", "/SC0020.aspx")        # equal to a response header -> traced (exact)
    s.add("GET", "/start", resp_headers=HTML + [("X-Next-Page", "SC0020.aspx")],
          resp_body=b'<html><form><input type="hidden" name="hdnNext" value="Menu01.aspx"></form></html>')
    s.add("GET", "/Menu01.aspx")        # equal to an <input> value -> traced (exact)
    s.add("GET", "/start", resp_body=b'<html><span id="pg">SC0030.aspx</span><form action="KJ010Search.aspx"></form></html>')
    s.add("GET", "/SC0030.aspx")        # only element text -> literal
    s.add("GET", "/start", resp_body=b'<html><span id="pg">SC0030.aspx</span><form action="KJ010Search.aspx"></form></html>')
    s.add("POST", "/KJ010Search.aspx", [FORM], body=b"q=hello_world")  # only a form action -> literal
    plan = s.plan(PlanOptions(detect_loops=False))
    steps = {st.index: st for st in plan.steps}
    assert [(e.kind, e.name) for st in plan.steps for e in st.extractors] == [("header", "X-Next-Page"), ("html_input", "hdnNext")]
    header_ext, input_ext = plan.steps[0].extractors[0], plan.steps[2].extractors[0]
    assert steps[2].url == [Ref.lit("https://site.example/"), Ref.var(header_ext.var)]
    assert steps[4].url == [Ref.lit("https://site.example/"), Ref.var(input_ext.var)]
    assert steps[6].literal_url() == "https://site.example/SC0030.aspx"
    assert steps[8].literal_url() == "https://site.example/KJ010Search.aspx"
    assert plan.constants == [] and not any("looks dynamic" in w for w in plan.warnings)


def test_screen_id_pages_are_literal_in_urls_and_referers():
    """``SC0010.aspx`` / ``KJ010Search.aspx`` / ``Menu01.aspx`` used to be traced to markup (the digits
    made them non-structural) and the Referer rewrite spread that dependency."""
    s = Site("http://intra.example")
    page = (b'<html><a id="m" href="Menu01.aspx">menu</a><form id="f" action="KJ010Search.aspx">'
            b'<input type="hidden" name="__VIEWSTATE" value="VS0123456789abc"></form></html>')
    s.add("GET", "/SC0010.aspx", resp_body=page)
    s.add("POST", "/KJ010Search.aspx", [FORM, ("Referer", "http://intra.example/SC0010.aspx")],
          body=b"__VIEWSTATE=VS0123456789abc&q=x", resp_body=page)
    s.add("GET", "/Menu01.aspx", [("Referer", "http://intra.example/KJ010Search.aspx")], resp_body=page)
    s.add("GET", "/SC0010.aspx", [("Referer", "http://intra.example/Menu01.aspx")], resp_body=page)
    plan = s.plan(PlanOptions(detect_loops=False))
    assert [st.literal_url() for st in plan.steps] == [
        "http://intra.example/SC0010.aspx", "http://intra.example/KJ010Search.aspx",
        "http://intra.example/Menu01.aspx", "http://intra.example/SC0010.aspx"]
    assert [(e.kind, e.name) for st in plan.steps for e in st.extractors] == [("html_input", "__VIEWSTATE")]
    assert all(r.is_literal for st in plan.steps for n, r in st.headers if n.lower() == "referer")
    assert plan.constants == []


def test_mvc_route_words_with_acronyms_are_not_traced_through_markup():
    s = Site()
    s.add("GET", "/Production/Index", resp_body=b'<html><a id="x" href="/Production/ProductionResultCSV">csv</a>'
                                                 b'<script>var a = "/Production/OrderDateDESC";</script></html>')
    s.add("GET", "/Production/ProductionResultCSV", resp_headers=[("Content-Type", "text/csv")], resp_body=b"a,b\n")
    s.add("GET", "/Production/OrderDateDESC", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(detect_loops=False))
    assert plan.steps[0].extractors == []
    assert [st.literal_url() for st in plan.steps[1:]] == [
        "https://site.example/Production/ProductionResultCSV", "https://site.example/Production/OrderDateDESC"]
    assert not any("looks dynamic" in w for w in plan.warnings)


def test_digit_free_base64url_key_is_a_token():
    """``xBBHOH-pXYZgFKyNZpuWy`` is not a route word: traced by pattern, and warned about otherwise."""
    s = Site()
    s.add("GET", "/menu", resp_body=b"<html><a id=\"s\" onclick=\"window.open('Search.aspx?key=xBBHOH-pXYZgFKyNZpuWy','s')\">s</a></html>")
    s.add("GET", "/Search.aspx?key=xBBHOH-pXYZgFKyNZpuWy")
    s.add("GET", "/r/pXYZgFKy_NZpuWyxBBHOH/view")
    plan = s.plan(PlanOptions(detect_loops=False))
    (ext,) = plan.steps[0].extractors
    assert ext.pattern and params(plan.steps[1])["key"] == Ref.var(ext.var)
    assert plan.constants == []
    # an untraced random path key is not a route name: the stale literal is warned about
    assert any("path segment 1" in w and "looks dynamic" in w for w in plan.warnings)
    # repeated and untraced: a shared constant (not kept in the URL like a route name), still warned about
    s.add("GET", "/r/pXYZgFKy_NZpuWyxBBHOH/view?x=1")
    plan = s.plan(PlanOptions(detect_loops=False))
    assert [c.value for c in plan.constants] == ["pXYZgFKy_NZpuWyxBBHOH"]


# --------------------------------------------------------------------------- review 3: Referer substitution

from reqrec.plan import _referer_with_fresh_values  # noqa: E402


def _eval_ref(ref, **names):
    import requests

    return eval(ref.value, {"requests": requests, "unquote": unquote, "str": str}, names)  # noqa: S307


def test_referer_replaces_whole_tokens_only():
    refs = {("query", "key", "ABCDEFGH1234"): Ref.var("key")}
    referer = ("http://ABCDEFGH1234.example/x/ABCDEFGH1234/y?key=ABCDEFGH1234&long=ABCDEFGH12345"
               "&pre=xABCDEFGH1234&ABCDEFGH1234#ABCDEFGH1234")
    ref = _referer_with_fresh_values(referer, refs)
    assert ref.kind == "expr"
    assert _eval_ref(ref, key="NEW") == ("http://ABCDEFGH1234.example/x/NEW/y?key=NEW&long=ABCDEFGH12345"
                                          "&pre=xABCDEFGH1234&NEW#ABCDEFGH1234")
    # in the host, or inside longer tokens only -> nothing to replace
    assert _referer_with_fresh_values("http://ABCDEFGH1234.example/a?k=ABCDEFGH12345", refs) == \
        Ref.lit("http://ABCDEFGH1234.example/a?k=ABCDEFGH12345")
    # path parameters (``;jsessionid=``) are whole tokens too
    ref = _referer_with_fresh_values("http://h/app/list.do;jsessionid=ABCDEFGH1234?p=1", refs)
    assert _eval_ref(ref, key="NEW") == "http://h/app/list.do;jsessionid=NEW?p=1"
    # short values, literal refs and non-URL headers stay literal
    assert _referer_with_fresh_values("http://h/a?k=1234567", {("query", "k", "1234567"): Ref.var("k")}).is_literal
    assert _referer_with_fresh_values("http://h/a?k=ABCDEFGH1234", {("query", "k", "ABCDEFGH1234"): Ref.lit("x")}).is_literal
    assert _referer_with_fresh_values("about:blank ABCDEFGH1234", refs).is_literal


def test_referer_handles_the_percent_encoded_spelling():
    """A key with ``+ / =`` appears percent-encoded in the Referer and used to stay stale."""
    raw = "Qk+9/zR8vT=="
    referer = "http://h/Search.aspx?key=Qk%2B9%2FzR8vT%3D%3D&x=1"
    # value decoded from an encoded source (``unquote(X)``): X is the fresh encoded spelling
    ref = _referer_with_fresh_values(referer, {("query", "key", raw): Ref.expr("unquote(key)")})
    assert ref.value == "'http://h/Search.aspx?key=' + str(key) + '&x=1'"
    assert _eval_ref(ref, key="Zz%2B1%2FyY2xX%3D%3D") == "http://h/Search.aspx?key=Zz%2B1%2FyY2xX%3D%3D&x=1"
    # any other ref: quoted with requests.utils.quote (the generated script always imports requests)
    ref = _referer_with_fresh_values(referer, {("query", "key", raw): Ref.var("key")})
    assert "requests.utils.quote(str(key), safe='')" in ref.value
    assert _eval_ref(ref, key="Zz+1/yY2xX==") == "http://h/Search.aspx?key=Zz%2B1%2FyY2xX%3D%3D&x=1"
    # the verbatim spelling still wins, also for an unquote(X) ref
    ref = _referer_with_fresh_values("http://h/S.aspx?key=" + raw, {("query", "key", raw): Ref.expr("unquote(key)")})
    assert _eval_ref(ref, key="Zz%2B1") == "http://h/S.aspx?key=Zz+1"
    # '+' for a space in a query value
    ref = _referer_with_fresh_values("http://h/s?q=hello+big+world", {("query", "q", "hello big world"): Ref.var("q")})
    assert _eval_ref(ref, q="a b") == "http://h/s?q=a%20b"


def test_referer_rewrite_in_a_plan_keeps_host_and_unrelated_tokens():
    s = Site("http://kanri01")
    s.add("GET", "/Menu.aspx", resp_body=b"<html><a id=\"s\" onclick=\"window.open('Search.aspx?key=kanri01KEYxyz9','s')\">s</a></html>")
    s.add("GET", "/Search.aspx?key=kanri01KEYxyz9", [("Referer", "http://kanri01/Menu.aspx?from=kanri01KEYxyz9X")],
          resp_body=b'<html><form id="form1" action="Search.aspx?key=kanri01KEYxyz9"></form></html>')
    s.add("POST", "/Search.aspx?key=kanri01KEYxyz9", [FORM, ("Referer", "http://kanri01/Search.aspx?key=kanri01KEYxyz9")],
          body=b"q=1", resp_body=b"<html></html>")
    plan = s.plan()
    get_search, post_search = plan.steps[1], plan.steps[2]
    assert hdr(get_search, "Referer") == Ref.lit("http://kanri01/Menu.aspx?from=kanri01KEYxyz9X")
    key_var = params(post_search)["key"].value
    assert hdr(post_search, "Referer") == Ref.expr(f"'http://kanri01/Search.aspx?key=' + str({key_var})")


# --------------------------------------------------------------------------- review 3: secrets that are not trace candidates

@pytest.mark.parametrize("password", ["admin", "guest", "abc", "123", "x"])
def test_short_or_plain_word_passwords_are_still_secret(password):
    s = Site()
    s.add("GET", "/login", resp_body=b"<html></html>")
    s.add("POST", "/login", [FORM], body=f"user=taro&password={password}".encode(), resp_body=b"<html></html>")
    plan = s.plan()
    (const,) = plan.constants
    assert (const.name, const.value, const.secret, const.env_var) == ("PASSWORD", password, True, "REQREC_PASSWORD")
    assert form(plan.steps[1], "password") == Ref.var("PASSWORD") and form(plan.steps[1], "user") == Ref.lit("taro")
    assert any("REQREC_PASSWORD" in w for w in plan.warnings)
    no_redact = s.plan(PlanOptions(redact_secrets=False))
    assert form(no_redact.steps[1], "password") == Ref.lit(password) and no_redact.constants == []


def test_password_equal_to_the_user_id_is_still_secret():
    """Regression: the per-step value cache handed the user id's literal Ref to the password."""
    s = Site()
    s.add("POST", "/Login.aspx", [FORM], body=b"txtUserId=tanaka01&txtPassword=tanaka01&btnLogin=Login", resp_body=b"<html></html>")
    plan = s.plan()
    assert form(plan.steps[0], "txtUserId") == Ref.lit("tanaka01")
    assert form(plan.steps[0], "txtPassword") == Ref.var("TXT_PASSWORD")
    (const,) = plan.constants
    assert (const.value, const.secret, const.env_var) == ("tanaka01", True, "REQREC_TXT_PASSWORD")


def test_repeated_user_id_constant_is_not_turned_into_the_password():
    """The user id's shared constant stays plain; the password gets its own environment variable."""
    s = Site()
    for _ in range(2):
        s.add("POST", "/Login.aspx", [FORM], body=b"txtUserId=tanaka01&txtPassword=tanaka01", resp_body=b"<html></html>")
        s.add("GET", "/Logout.aspx", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(detect_loops=False))
    consts = {c.name: c for c in plan.constants}
    assert (consts["TXT_USER_ID"].secret, consts["TXT_USER_ID"].env_var) == (False, None)
    assert (consts["TXT_PASSWORD"].secret, consts["TXT_PASSWORD"].env_var) == (True, "REQREC_TXT_PASSWORD")
    for st in (plan.steps[0], plan.steps[2]):
        assert form(st, "txtUserId") == Ref.var("TXT_USER_ID") and form(st, "txtPassword") == Ref.var("TXT_PASSWORD")


def test_secret_fields_outside_forms_are_redacted_too():
    s = Site()
    s.add("POST", "/api/login?pwd=987", [("Content-Type", "application/json"), ("Authorization", "Bearer abc"), ("X-Api-Key", "k1")],
          body=json.dumps({"user": "taro", "pin": 123, "auth": {"password": "admin"}}).encode(), resp_headers=JSON, resp_body=b"{}")
    s.add("POST", "/upload", [("Content-Type", "multipart/form-data; boundary=XyZ")],
          body=b'--XyZ\r\nContent-Disposition: form-data; name="passwd"\r\n\r\nxyz\r\n--XyZ--\r\n', resp_body=b"<html></html>")
    plan = s.plan()
    api, upload = plan.steps
    consts = {c.name: c for c in plan.constants}
    assert all(c.secret and c.env_var == f"REQREC_{c.name}" for c in consts.values())
    assert params(api)["pwd"] == Ref.var("PWD") and consts["PWD"].value == "987"
    # a numeric leaf stays a number: int() of the environment variable
    assert api.json_body == {"user": "taro", "pin": Ref.expr("int(PIN)"), "auth": {"password": Ref.var("PASSWORD")}}
    assert (consts["PIN"].value, consts["PASSWORD"].value) == ("123", "admin")
    assert hdr(api, "Authorization") == Ref.expr('"Bearer " + AUTHORIZATION') and consts["AUTHORIZATION"].value == "abc"
    assert hdr(api, "X-Api-Key") == Ref.var("X_API_KEY") and consts["X_API_KEY"].value == "k1"
    (part,) = upload.multipart
    assert part.value == Ref.var("PASSWD") and consts["PASSWD"].value == "xyz"
    assert not any(f"'{v}'" in repr(plan.steps) for v in ("admin", "abc", "xyz", "k1", "987"))


def test_referer_never_carries_a_short_password():
    """``Login.aspx?pwd=abc`` as the previous page: the Referer of the next request reuses the secret."""
    s = Site("http://kanri01")
    s.add("GET", "/Login.aspx?user=taro&pwd=abc", resp_body=b"<html></html>")
    s.add("GET", "/Menu.aspx", [("Referer", "http://kanri01/Login.aspx?user=taro&pwd=abc&x=abc")], resp_body=b"<html></html>")
    plan = s.plan()
    assert params(plan.steps[0])["pwd"] == Ref.var("PWD")
    referer = hdr(plan.steps[1], "Referer")
    assert referer == Ref.expr("'http://kanri01/Login.aspx?user=taro&pwd=' + str(PWD) + '&x=abc'")


def test_route_like_path_segments_do_not_turn_other_values_into_constants():
    s = Site()
    s.add("GET", "/Menu.aspx", resp_body=b"<html></html>")
    s.add("POST", "/Logout.aspx", [FORM], body=b"ReturnUrl=Menu.aspx", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(detect_loops=False))
    assert plan.constants == [] and form(plan.steps[1], "ReturnUrl") == Ref.lit("Menu.aspx")
