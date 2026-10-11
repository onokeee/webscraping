"""Tests for ``reqrec.codegen`` (DESIGN.md §8) and the ``tests/e2e/mock_adapter`` transport.

Plans are built by hand from ``reqrec.model`` so this file does not depend on the plan builder.
Every generated script is compiled; most are also *executed* against ``MockAdapter`` and the
sequence of HTTP calls (methods, URLs, headers, bodies) is asserted.
"""

from __future__ import annotations

import ast
import io
import json
import re
import subprocess
import sys
import tokenize
from urllib.parse import parse_qsl, urlsplit

import pytest
import requests

from reqrec.codegen import MAX_INLINE_BODY, CodegenError, generate
from reqrec.model import (
    Constant,
    Extractor,
    GenOptions,
    InitialCookie,
    Loop,
    MultipartPart,
    Plan,
    Ref,
    Step,
)
from tests.e2e.mock_adapter import Call, MockAdapter, Rule, install, run_generated

H = "https://example.test"

LOGIN_HTML = """<!doctype html>
<html><head><title>ログイン</title>
<meta name="csrf-token" content="M1-meta">
</head><body>
<form method="post" action="/submit"><input type="hidden" name="_token" value="T1-input"></form>
<a id="next" href="/next?tok=A1-link&amp;x=1">next</a>
<span class="user">alice</span>
<script>window.API="S1-script";</script>
</body></html>"""


# =========================================================================== helpers

def compiles(src: str) -> str:
    compile(src, "<gen>", "exec")
    return src


def check_format(src: str) -> None:
    """Formatting contract: trailing newline, no trailing whitespace, parses as Python 3.8."""
    assert src.endswith("\n")
    assert not src.endswith("\n\n")
    for i, line in enumerate(src.split("\n"), 1):
        assert line == line.rstrip(), f"trailing whitespace on line {i}: {line!r}"
    ast.parse(src, feature_version=(3, 8))
    compiles(src)


def comment_tokens(src: str) -> list[str]:
    toks = tokenize.generate_tokens(io.StringIO(src).readline)
    return [t.string for t in toks if t.type == tokenize.COMMENT]


def name_tokens(src: str) -> set[str]:
    toks = tokenize.generate_tokens(io.StringIO(src).readline)
    return {t.string for t in toks if t.type == tokenize.NAME}


def func_params(src: str, name: str) -> list[str]:
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return [a.arg for a in node.args.args]
    raise AssertionError(f"function {name} not found")


def step(index: int, method: str, path: str, func: str | None = None, **kw) -> Step:
    url = kw.pop("url", None) or [Ref.lit(H + path)]
    kw.setdefault("response_kind", "json")
    return Step(index=index, func_name=func or f"step_{index:02d}_{method.lower()}_{path.strip('/').replace('/', '_') or 'root'}",
                method=method, url=url, **kw)


def meta() -> dict:
    return {
        "generated_at": "2026-10-07T01:02:03+00:00",
        "source": {"source": "har", "file": "login_flow.har", "creator": "WebInspector 537.36"},
        "flows_total": 57,
        "flows_kept": 3,
    }


# =========================================================================== fixtures: plans + adapters

def login_plan() -> Plan:
    """Every Extractor kind in step 1, every Ref kind in step 2, a JSON->header/URL flow in step 3."""
    s1 = step(
        1, "GET", "/login",
        headers=[("Referer", Ref.lit(H + "/"))],
        response_kind="html",
        comment="GET https://example.test/login -> 200 text/html",
        extractors=[
            Extractor("token", "html_input", name="_token", sample="T1-input", note="step 2 のフォームで使用"),
            Extractor("csrf", "html_meta", name="csrf-token", sample="M1-meta"),
            Extractor("link_tok", "html_attr", selector="a#next", attr="href", pattern=r"tok=([^&]+)", sample="A1-link"),
            Extractor("user", "html_text", selector="span.user", sample="alice"),
            Extractor("api_key", "regex", pattern=r'window\.API="([^"]+)"', sample="S1-script"),
            Extractor("req_id", "header", name="X-Request-Id", sample="R1-header"),
            Extractor("sid", "cookie", name="sid", sample="C1-cookie"),
            Extractor("page_name", "url", pattern=r"/(login)$", sample="login"),
        ],
    )
    s2 = step(
        2, "POST", "/submit",
        body_kind="form",
        form=[
            ("_token", Ref.var("token")),
            ("csrf", Ref.var("csrf")),
            ("link_tok", Ref.var("link_tok")),
            ("user", Ref.var("user")),
            ("api_key", Ref.var("api_key")),
            ("req_id", Ref.var("req_id")),
            ("sid", Ref.var("sid")),
            ("page_name", Ref.var("page_name")),
            ("username", Ref.var("USERNAME")),
            ("password", Ref.var("PASSWORD")),
            ("ts", Ref.expr("str(int(time.time()))")),
            ("mode", Ref.lit("full")),
        ],
        headers=[("X-CSRF-Token", Ref.var("csrf")), ("X-Sid", Ref.expr('session.cookies.get("sid")'))],
        extractors=[
            Extractor("access_token", "json", path=["data", "token"], sample="T2-json"),
            Extractor("user_id", "json", path=["data", "ids", 0], sample="42"),
        ],
    )
    s3 = step(
        3, "GET", "/users/42/me", func="step_03_get_me",
        url=[Ref.lit(H + "/users/"), Ref.var("user_id"), Ref.lit("/me")],
        headers=[("Authorization", Ref.expr('"Bearer " + access_token')), ("X-User-Id", Ref.var("user_id"))],
        params=[("fields", Ref.lit("a,b")), ("fields", Ref.lit("c"))],  # repeated name -> list of tuples
    )
    return Plan(
        steps=[s1, s2, s3],
        constants=[
            Constant("USERNAME", "alice", comment="ログイン ID"),
            Constant("PASSWORD", "hunter2-recorded", secret=True, env_var="REQREC_PASSWORD"),
        ],
        base_headers=[("User-Agent", "Mozilla/5.0 (test)"), ("Accept-Language", "ja,en;q=0.8")],
        initial_cookies=[InitialCookie("pref", "dark", "example.test", "/")],
        warnings=["step 2: value of `mode` looks dynamic but could not be traced"],
        meta=meta(),
    )


def login_adapter() -> MockAdapter:
    def submit(req):
        form = dict(parse_qsl(req.body if isinstance(req.body, str) else req.body.decode(), keep_blank_values=True))
        if form.get("_token") != "T1-input":
            return 403, None, {"error": "bad token"}
        return 200, None, {"data": {"token": "T2-json", "ids": [42, 43]}}

    return MockAdapter([
        Rule(H + "/login", method="GET", body=LOGIN_HTML, content_type="text/html; charset=utf-8",
             headers=[("Set-Cookie", "sid=C1-cookie; Path=/"), ("Set-Cookie", "other=zzz; Path=/"), ("X-Request-Id", "R1-header")]),
        Rule(H + "/submit", method="POST", handler=submit),
        Rule(re.compile(r"/users/\d+/me"), method="GET", body={"ok": True, "name": "太郎"}),
    ])


def loop_plan(numeric: bool = True, with_follow_up: bool = False) -> Plan:
    values = ["1", "2", "3"] if numeric else ["spring", "summer", "autumn"]
    s1 = step(
        1, "GET", "/api/items",
        params=[("page", Ref.var("page")), ("per_page", Ref.lit("20"))],
        loop=Loop(var="page", values=values, numeric_range=(1, 3) if numeric else None, note="3 回 (query `page`)"),
        extractors=[Extractor("last_id", "json", path=["last"], sample="x3")],
        comment="GET https://example.test/api/items -> 200 application/json x3",
    )
    steps = [s1]
    if with_follow_up:
        steps.append(step(2, "GET", "/api/after", params=[("after", Ref.var("last_id"))]))
    return Plan(steps=steps, meta=meta())


def loop_adapter() -> MockAdapter:
    def items(req):
        q = dict(parse_qsl(urlsplit(req.url).query))
        return 200, None, {"page": q.get("page"), "last": "x" + q.get("page", "")}

    return MockAdapter([
        Rule(H + "/api/items", handler=items),
        Rule(H + "/api/after", body={"after": "ok"}),
    ])


def json_body_plan() -> Plan:
    s1 = step(1, "GET", "/api/seed", extractors=[Extractor("item_id", "json", path=["item", "id"], sample="7"),
                                                  Extractor("tag", "json", path=["item", "tag"], sample="t")])
    s2 = step(
        2, "POST", "/api/graphql",
        body_kind="json",
        json_body={
            "query": "mutation { x }",
            "variables": {
                "id": Ref.var("item_id"),
                "tag": Ref.var("tag"),
                "flags": [True, False, None],
                "ratio": 1.5,
                "count": 3,
                "nested": [{"k": Ref.lit("v"), "ts": Ref.expr("int(time.time())")}],
                "日本語": "値",
            },
        },
        headers=[("X-Item", Ref.var("item_id"))],  # json-derived var in a header -> str()
    )
    return Plan(steps=[s1, s2], meta=meta())


def multipart_plan(big: bool = False) -> Plan:
    content = b"x" * (MAX_INLINE_BODY + 1) if big else b"hello\x00\xff world"
    s1 = step(
        1, "POST", "/upload",
        body_kind="multipart",
        multipart=[
            MultipartPart(name="title", value=Ref.lit("タイトル")),
            MultipartPart(name="file", filename="a.bin", content_type="application/octet-stream", content=content),
            MultipartPart(name="note", value=Ref.lit("n")),
        ],
    )
    return Plan(steps=[s1], meta=meta())


def raw_plan(body: bytes) -> Plan:
    s1 = step(1, "PUT", "/raw", body_kind="raw", raw_body=body,
              headers=[("Content-Type", Ref.lit("application/octet-stream"))], response_kind="empty", expected_status=204)
    return Plan(steps=[s1], meta=meta())


def redirect_plan(follow: bool = True) -> Plan:
    s1 = step(1, "GET", "/start", response_kind="html" if follow else "empty",
              allow_redirects=follow, expected_status=200 if follow else 302)
    s2 = step(2, "GET", "/next", headers=[("X-Sess", Ref.expr('session.cookies.get("sess")'))])
    return Plan(steps=[s1, s2], meta=meta())


def redirect_adapter() -> MockAdapter:
    return MockAdapter([
        Rule(H + "/start", status=302, headers=[("Location", "/landing"), ("Set-Cookie", "sess=S9; Path=/")]),
        Rule(H + "/landing", body="<html><title>Landing</title></html>", content_type="text/html"),
        Rule(H + "/next", body={"next": True}),
    ])


# =========================================================================== end-to-end: every kind flows through

class TestLoginFlow:
    def test_compiles_and_format(self):
        src = generate(login_plan())
        check_format(src)

    def test_calls_headers_bodies_and_value_flow(self, capsys):
        plan = login_plan()
        src = compiles(generate(plan))
        adapter = login_adapter()
        out = run_generated(src, adapter, env={"REQREC_PASSWORD": "from-env"})

        assert [c.method for c in adapter.calls] == ["GET", "POST", "GET"]
        assert adapter.unmatched == []
        c1, c2, c3 = adapter.calls

        # step 1: base headers, per-step header, initial cookie
        assert c1.url == H + "/login"
        assert c1.header("User-Agent") == "Mozilla/5.0 (test)"
        assert c1.header("Accept-Language") == "ja,en;q=0.8"
        assert c1.header("Referer") == H + "/"
        assert c1.cookies == {"pref": "dark"}

        # step 2: every extractor kind arrived in the form body
        form = c2.form
        assert form["_token"] == "T1-input"      # html_input
        assert form["csrf"] == "M1-meta"         # html_meta
        assert form["link_tok"] == "A1-link"     # html_attr + pattern
        assert form["user"] == "alice"           # html_text
        assert form["api_key"] == "S1-script"    # regex
        assert form["req_id"] == "R1-header"     # header
        assert form["sid"] == "C1-cookie"        # cookie
        assert form["page_name"] == "login"      # url
        assert form["username"] == "alice"       # constant
        assert form["password"] == "from-env"    # secret constant from env
        assert form["ts"].isdigit() and len(form["ts"]) == 10  # expr
        assert form["mode"] == "full"            # literal
        assert c2.header("X-CSRF-Token") == "M1-meta"
        assert c2.header("X-Sid") == "C1-cookie"
        assert c2.header("Content-Type") == "application/x-www-form-urlencoded"
        assert c2.cookies["sid"] == "C1-cookie" and c2.cookies["other"] == "zzz" and c2.cookies["pref"] == "dark"

        # step 3: JSON path -> Bearer header, JSON int -> URL piece and str() header, repeated params
        assert c3.url == H + "/users/42/me?fields=a%2Cb&fields=c"
        assert c3.header("Authorization") == "Bearer T2-json"
        assert c3.header("X-User-Id") == "42"

        # final output: pretty JSON with ensure_ascii=False
        assert json.loads(out) == {"ok": True, "name": "太郎"}
        assert "太郎" in out
        assert capsys.readouterr().err == ""

    def test_secret_value_never_in_source(self):
        src = generate(login_plan())
        assert "hunter2-recorded" not in src
        assert "PASSWORD = os.environ.get('REQREC_PASSWORD', '')" in src
        assert "USERNAME = 'alice'" in src
        assert "REQREC_PASSWORD" in src.split('"""')[1]  # mentioned in the module docstring

    def test_function_signatures(self):
        src = generate(login_plan())
        assert func_params(src, "step_01_get_login") == ["session"]
        # sorted by first use (headers come after params/url, form after headers), constants excluded
        assert func_params(src, "step_02_post_submit") == [
            "session", "csrf", "token", "link_tok", "user", "api_key", "req_id", "sid", "page_name",
        ]
        assert func_params(src, "step_03_get_me") == ["session", "user_id", "access_token"]
        assert "resp, out = step_02_post_submit(" in src
        assert "token=ctx['token']" in src

    def test_extractor_rendering(self):
        src = generate(login_plan())
        assert "soup = _soup(resp)" in src
        assert src.count("soup = _soup(resp)") == 1  # once per function (final step is JSON)
        assert "token = _attr(soup, 'input[name=\"_token\"]', 'value')" in src
        assert "csrf = _attr(soup, 'meta[name=\"csrf-token\"]', 'content')" in src
        assert "link_tok = _regex(_attr(soup, 'a#next', 'href'), 'tok=([^&]+)')" in src
        assert "user = _elem_text(soup, 'span.user')" in src  # §13.4: _text(resp) is the encoding helper
        assert "api_key = _regex(_text(resp), 'window\\\\.API=\"([^\"]+)\"')" in src  # text read through _text(resp)
        assert "req_id = resp.headers.get('X-Request-Id')" in src
        assert "sid = session.cookies.get('sid')" in src
        assert "page_name = _regex(resp.url, '/(login)$')" in src
        assert "data = resp.json()" in src
        assert "access_token = _json_path(data, ['data', 'token'])" in src
        assert "user_id = _json_path(data, ['data', 'ids', 0])" in src
        assert "return resp, {'access_token': access_token, 'user_id': user_id}" in src
        # japanese explanation with the recorded sample, via repr
        assert "# token: <input name='_token'> の value（記録時の値: 'T1-input'） — step 2 のフォームで使用" in src
        assert "'_token': token,  # step_01_get_login で取得" in src

    def test_url_and_headers_rendering(self):
        src = generate(login_plan())
        assert "'https://example.test/users/' + str(user_id) + '/me'" in src
        assert "'Authorization': \"Bearer \" + access_token" in src
        assert "'X-User-Id': str(user_id)" in src
        assert "params=[('fields', 'a,b'), ('fields', 'c')]" in src
        assert "allow_redirects" not in src  # only emitted when False

    def test_module_docstring(self):
        plan = login_plan()
        src = generate(plan)
        ns: dict = {}
        exec(compile(src, "<gen>", "exec"), ns)
        doc = ns["__doc__"]
        assert "reqrec 0.1.0" in doc and "2026-10-07T01:02:03+00:00" in doc
        assert "HAR ファイル (login_flow.har)" in doc and "WebInspector 537.36" in doc
        assert "ステップ数: 3（記録 57 リクエストのうち 3 件を使用）" in doc
        assert "注意:" in doc and "  - step 2: value of `mode` looks dynamic" in doc
        assert src.startswith('"""')

    def test_main_structure(self):
        src = generate(login_plan())
        assert "session = requests.Session()" in src
        assert "session.headers.update(BASE_HEADERS)" in src
        assert "for c in INITIAL_COOKIES:" in src
        assert "session.cookies.set(c['name'], c['value'], domain=c['domain'], path=c['path'])" in src
        assert "ctx = {}" in src and "ctx.update(out)" in src
        assert src.rstrip().endswith('if __name__ == "__main__":\n    main()')
        assert "time.sleep" not in src  # delay 0 -> no sleeps


# =========================================================================== loops

class TestLoops:
    def test_numeric_range_issues_three_calls(self):
        plan = loop_plan(numeric=True)
        src = compiles(generate(plan))
        assert "for page in range(1, 4):" in src
        assert "results = []" in src and "results.append(resp.json())" in src
        assert func_params(src, "step_01_get_api_items") == ["session", "page"]
        adapter = loop_adapter()
        out = run_generated(src, adapter)
        assert [c.query_dict for c in adapter.calls] == [
            {"page": "1", "per_page": "20"}, {"page": "2", "per_page": "20"}, {"page": "3", "per_page": "20"},
        ]
        assert json.loads(out) == [{"page": "1", "last": "x1"}, {"page": "2", "last": "x2"}, {"page": "3", "last": "x3"}]

    def test_explicit_values(self):
        src = compiles(generate(loop_plan(numeric=False)))
        assert "for page in ['spring', 'summer', 'autumn']:" in src
        adapter = loop_adapter()
        run_generated(src, adapter)
        assert [c.query_dict["page"] for c in adapter.calls] == ["spring", "summer", "autumn"]

    def test_last_iteration_feeds_following_step(self):
        src = compiles(generate(loop_plan(numeric=True, with_follow_up=True), GenOptions(delay=0.5)))
        adapter = loop_adapter()
        run_generated(src, adapter)
        assert adapter.calls[-1].url == H + "/api/after?after=x3"
        # sleeps: inside the loop body and (none needed) after the last step
        assert src.count("time.sleep(DELAY)") == 1
        assert "DELAY = 0.5" in src

    def test_descending_range(self):
        plan = loop_plan()
        plan.steps[0].loop.numeric_range = (5, 3)
        plan.steps[0].loop.values = ["5", "4", "3"]
        src = compiles(generate(plan))
        assert "for page in range(5, 2, -1):" in src

    def test_loop_var_passed_positionally_in_main(self):
        src = generate(loop_plan(with_follow_up=True))
        assert "resp, out = step_01_get_api_items(session, page)" in src
        assert "resp, out = step_02_get_api_after(session, last_id=ctx['last_id'])" in src


# =========================================================================== bodies

class TestBodies:
    def test_json_body_with_refs(self):
        src = compiles(generate(json_body_plan()))
        adapter = MockAdapter([
            Rule(H + "/api/seed", body={"item": {"id": 7, "tag": "t"}}),
            Rule(H + "/api/graphql", body={"done": 1}),
        ])
        run_generated(src, adapter)
        sent = adapter.calls[1].json()
        assert sent["query"] == "mutation { x }"
        v = sent["variables"]
        assert v["id"] == 7 and v["tag"] == "t"
        assert v["flags"] == [True, False, None]
        assert v["ratio"] == 1.5 and v["count"] == 3
        assert v["nested"][0]["k"] == "v" and isinstance(v["nested"][0]["ts"], int)
        assert v["日本語"] == "値"
        assert adapter.calls[1].header("Content-Type") == "application/json"
        assert adapter.calls[1].header("X-Item") == "7"
        assert "'flags': [True, False, None]," in src
        assert "'id': item_id,  # step_01_get_api_seed で取得" in src

    def test_json_nan_inf_render_as_valid_python(self):
        plan = Plan(steps=[step(1, "POST", "/x", body_kind="json", json_body={"a": float("nan"), "b": float("inf"), "c": -float("inf")})])
        src = compiles(generate(plan))
        assert "float('nan')" in src and "float('inf')" in src and "float('-inf')" in src

    def test_multipart(self):
        src = compiles(generate(multipart_plan()))
        assert "files={" in src and "'file': ('a.bin', b'hello\\x00\\xff world', 'application/octet-stream')," in src
        assert "data={'title': 'タイトル', 'note': 'n'}" in src
        adapter = MockAdapter([Rule(H + "/upload", body={"ok": 1})])
        run_generated(src, adapter)
        call = adapter.calls[0]
        assert call.header("Content-Type").startswith("multipart/form-data; boundary=")
        assert b'name="file"; filename="a.bin"' in call.body
        assert b"hello\x00\xff world" in call.body
        assert "タイトル".encode("utf-8") in call.body
        assert b'name="note"\r\n\r\nn\r\n' in call.body

    def test_multipart_huge_file_is_omitted_with_todo_and_warning(self):
        plan = multipart_plan(big=True)
        src = compiles(generate(plan))
        assert "'file': ('a.bin', b'', 'application/octet-stream'),  # TODO" in src
        assert "x" * 1000 not in src
        assert any("アップロードファイル" in w for w in plan.warnings)
        assert "注意:" in src and "アップロードファイル 'file'" in src.split('"""')[1]

    def test_raw_body_exact_bytes(self):
        body = bytes(range(256)) + "日本語 'quote' \"dq\" \\ \n#".encode("utf-8")
        src = compiles(generate(raw_plan(body)))
        assert "data=" + repr(body) in src
        adapter = MockAdapter([Rule(H + "/raw", status=204)])
        out = run_generated(src, adapter)
        call = adapter.calls[0]
        assert call.method == "PUT" and call.body == body
        assert call.header("Content-Type") == "application/octet-stream"
        assert out.strip() == f"204 {H}/raw"

    def test_raw_body_huge_is_omitted(self):
        plan = raw_plan(b"z" * (MAX_INLINE_BODY + 10))
        src = compiles(generate(plan))
        assert "data=b'',  # TODO" in src
        assert any("リクエスト本文" in w for w in plan.warnings)

    def test_empty_form_and_none_body(self):
        plan = Plan(steps=[step(1, "POST", "/f", body_kind="form", form=[]), step(2, "DELETE", "/d", response_kind="empty")])
        src = compiles(generate(plan))
        assert "resp = session.post('https://example.test/f', data={}, timeout=TIMEOUT)" in src
        assert "resp = session.delete('https://example.test/d', timeout=TIMEOUT)" in src

    def test_duplicate_form_names_use_list_of_tuples(self):
        plan = Plan(steps=[step(1, "POST", "/f", body_kind="form", form=[("a", Ref.lit("1")), ("a", Ref.lit("2"))])])
        src = compiles(generate(plan))
        assert "data=[('a', '1'), ('a', '2')]" in src
        adapter = MockAdapter([Rule(H + "/f", body={})])
        run_generated(src, adapter)
        assert adapter.calls[0].form_pairs == [("a", "1"), ("a", "2")]

    def test_unusual_method_uses_session_request(self):
        plan = Plan(steps=[step(1, "PROPFIND", "/dav", response_kind="xml"), step(2, "HEAD", "/h", response_kind="empty")])
        src = compiles(generate(plan))
        assert "session.request('PROPFIND', 'https://example.test/dav', timeout=TIMEOUT)" in src
        assert "session.request('HEAD', 'https://example.test/h', timeout=TIMEOUT)" in src


# =========================================================================== redirects / status handling

class TestRedirectsAndStatus:
    def test_redirect_followed_and_cookie_from_hop_used(self):
        src = compiles(generate(redirect_plan(follow=True)))
        assert "allow_redirects" not in src
        adapter = redirect_adapter()
        run_generated(src, adapter)
        assert [c.url for c in adapter.calls] == [H + "/start", H + "/landing", H + "/next"]
        assert adapter.calls[2].header("X-Sess") == "S9"
        assert adapter.calls[2].cookies == {"sess": "S9"}

    def test_allow_redirects_false(self):
        src = compiles(generate(redirect_plan(follow=False)))
        assert "allow_redirects=False," in src
        assert "_check(resp, 302, 'step_01_get_start')" in src
        adapter = redirect_adapter()
        run_generated(src, adapter)
        assert [c.url for c in adapter.calls] == [H + "/start", H + "/next"]

    def test_non_strict_warns_on_mismatch_but_raises_on_4xx(self, capsys):
        plan = Plan(steps=[step(1, "GET", "/a", response_kind="empty")])
        src = compiles(generate(plan, GenOptions(strict_status=False)))
        assert "resp.raise_for_status()" in src
        adapter = MockAdapter([Rule(H + "/a", status=201)])
        run_generated(src, adapter)
        assert "[警告] step_01_get_a: ステータスコード 201 (記録時: 200)" in capsys.readouterr().err
        adapter = MockAdapter([Rule(H + "/a", status=404)])
        with pytest.raises(requests.HTTPError):
            run_generated(src, adapter)

    def test_strict_status_raises_runtime_error(self):
        plan = Plan(steps=[step(1, "GET", "/a", response_kind="empty")])
        src = compiles(generate(plan, GenOptions(strict_status=True)))
        assert "raise_for_status" not in src
        adapter = MockAdapter([Rule(H + "/a", status=201)])
        with pytest.raises(RuntimeError) as exc:
            run_generated(src, adapter)
        msg = str(exc.value)
        assert "step_01_get_a" in msg and "201" in msg and "200" in msg and H + "/a" in msg
        adapter = MockAdapter([Rule(H + "/a", status=200)])
        run_generated(src, adapter)  # exact match passes

    def test_runtime_helper_errors_are_clear(self):
        plan = Plan(steps=[
            step(1, "GET", "/p", response_kind="html", extractors=[Extractor("tok", "html_input", name="missing")]),
        ])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/p", body="<html></html>", content_type="text/html")])
        with pytest.raises(RuntimeError, match=r"要素が見つかりません: 'input\[name=\"missing\"\]'"):
            run_generated(src, adapter)
        plan = Plan(steps=[step(1, "GET", "/p", extractors=[Extractor("tok", "regex", pattern="nomatch-(\\d+)")])])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/p", body="zzz")])
        with pytest.raises(RuntimeError, match=r"パターンに一致しませんでした: 'nomatch-\(\\\\d\+\)'"):
            run_generated(src, adapter)
        plan = Plan(steps=[step(1, "GET", "/p", extractors=[Extractor("tok", "json", path=["a", 2, "b"])])])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/p", body={"a": [1]})])
        with pytest.raises(RuntimeError, match=r"JSON にパス \['a', 2, 'b'\] が見つかりません"):
            run_generated(src, adapter)


# =========================================================================== options

class TestOptions:
    def test_comments_off_has_no_comment_tokens_but_keeps_docstrings(self):
        plan = login_plan()
        on = generate(plan, GenOptions(comments=True))
        off = generate(plan, GenOptions(comments=False))
        check_format(off)
        assert comment_tokens(on)
        assert comment_tokens(off) == []
        assert '"""GET https://example.test/login' in off
        adapter = login_adapter()
        run_generated(off, adapter, env={"REQREC_PASSWORD": "p"})
        assert len(adapter.calls) == 3

    def test_delay_and_timeout_and_parser(self):
        src = compiles(generate(login_plan(), GenOptions(delay=2.5, timeout=7, html_parser="lxml")))
        assert "TIMEOUT = 7.0" in src and "DELAY = 2.5" in src
        assert "BeautifulSoup(resp.content, 'lxml', from_encoding=_charset(resp))" in src  # §13.4: parse bytes
        assert src.count("time.sleep(DELAY)") == 2  # between 3 steps
        assert "timeout=TIMEOUT" in src

    def test_print_final_off(self):
        src = compiles(generate(login_plan(), GenOptions(print_final=False)))
        assert "json.dumps(resp.json()" not in src
        adapter = login_adapter()
        assert run_generated(src, adapter, env={"REQREC_PASSWORD": "p"}) == ""

    @pytest.mark.parametrize("kind,body,ct,expected", [
        ("html", "<html><head><title> 結果 </title></head></html>", "text/html; charset=utf-8", "結果\n"),
        ("text", "plain text " * 3, "text/plain", "plain text " * 3 + "\n"),
        ("xml", "<a>1</a>", "application/xml", "<a>1</a>\n"),
        ("empty", b"", None, f"200 {H}/x\n"),
    ])
    def test_print_final_kinds(self, kind, body, ct, expected):
        plan = Plan(steps=[step(1, "GET", "/x", response_kind=kind)])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/x", body=body, content_type=ct)])
        assert run_generated(src, adapter) == expected

    def test_print_final_binary_saves_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("REQREC_OUTPUT_DIR", raising=False)  # this test checks the cwd default
        plan = Plan(steps=[step(1, "GET", "/x", response_kind="binary")])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/x", body=b"\x00\x01\x02", content_type="application/octet-stream")])
        out = run_generated(src, adapter)
        assert (tmp_path / "output.bin").read_bytes() == b"\x00\x01\x02"
        assert "output.bin" in out and "3 バイト" in out

    XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    @pytest.mark.parametrize("disposition,expected", [
        # RFC 6266 / 5987
        ("attachment; filename*=UTF-8''%E7%94%9F%E7%94%A3%E5%AE%9F%E7%B8%BE.xlsx", "生産実績.xlsx"),
        ("attachment; filename=\"fallback.xlsx\"; filename*=UTF-8''%E5%AE%9F%E7%B8%BE.xlsx", "実績.xlsx"),
        # IE-style percent-encoded UTF-8 in plain filename=
        ("attachment; filename=%E7%94%9F%E7%94%A3.xlsx", "生産.xlsx"),
        # raw Shift_JIS bytes (legacy IIS) – http.client hands them over as Latin-1
        ("attachment; filename=\"" + "生産実績.xlsx".encode("cp932").decode("latin-1") + "\"", "生産実績.xlsx"),
        # raw UTF-8 bytes
        ("attachment; filename=" + "日報.xlsx".encode("utf-8").decode("latin-1"), "日報.xlsx"),
        # path tricks are neutralised
        ("attachment; filename=\"..\\\\..\\\\evil.xlsx\"", "evil.xlsx"),
        ("attachment; filename=\"a:b?.xlsx\"", "a_b_.xlsx"),
        # no name at all -> output + extension from the MIME type
        ("attachment", "output.xlsx"),
    ])
    def test_final_download_uses_server_file_name(self, tmp_path, monkeypatch, disposition, expected):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("REQREC_OUTPUT_DIR", raising=False)  # this test checks the cwd default
        plan = Plan(steps=[step(1, "POST", "/Search.aspx", "step_01_search", response_kind="binary")])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/Search.aspx", body=b"PK\x03\x04xlsx", content_type=self.XLSX,
                                    headers={"Content-Disposition": disposition})])
        out = run_generated(src, adapter)
        assert (tmp_path / expected).read_bytes() == b"PK\x03\x04xlsx"
        assert expected in out and "に保存しました" in out
        assert not (tmp_path / "output.bin").exists() or expected == "output.bin"

    def test_final_download_name_from_url_and_output_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("REQREC_OUTPUT_DIR", raising=False)  # this test checks the cwd default
        outdir = tmp_path / "outputs"
        plan = Plan(steps=[step(1, "GET", "/files/report.xlsx", "step_01_report", response_kind="binary")])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/files/report.xlsx", body=b"PK", content_type=self.XLSX)])
        run_generated(src, adapter, env={"REQREC_OUTPUT_DIR": str(outdir)})
        assert (outdir / "report.xlsx").read_bytes() == b"PK"

    def test_text_attachment_is_saved_and_previewed(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("REQREC_OUTPUT_DIR", raising=False)  # this test checks the cwd default
        csv = "品番,数量\nA-1001,12\n".encode("cp932")
        plan = Plan(steps=[step(1, "POST", "/Export.aspx", "step_01_export", response_kind="text")])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/Export.aspx", body=csv, content_type="text/csv; charset=Shift_JIS",
                                    headers={"Content-Disposition": "attachment; filename=export.csv"})])
        out = run_generated(src, adapter)
        assert (tmp_path / "export.csv").read_bytes() == csv
        assert "export.csv に保存しました" in out and "A-1001,12" in out

    def test_text_without_attachment_is_only_printed(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("REQREC_OUTPUT_DIR", raising=False)  # this test checks the cwd default
        plan = Plan(steps=[step(1, "GET", "/x.txt", "step_01_x", response_kind="text")])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/x.txt", body="hello", content_type="text/plain")])
        assert run_generated(src, adapter) == "hello\n"
        assert list(tmp_path.iterdir()) == []

    def test_download_helpers_without_comments(self):
        src = generate(Plan(steps=[step(1, "GET", "/x", response_kind="binary")]), GenOptions(comments=False))
        check_format(src)
        assert comment_tokens(src) == []
        assert "def _save_download(resp):" in src

    def test_json_final_falls_back_to_text(self):
        plan = Plan(steps=[step(1, "GET", "/x", response_kind="json")])
        src = compiles(generate(plan))
        adapter = MockAdapter([Rule(H + "/x", body="not json", content_type="text/plain")])
        assert run_generated(src, adapter) == "not json\n"

    def test_looped_text_final(self):
        plan = loop_plan()
        plan.steps[0].response_kind = "text"
        plan.steps[0].extractors = []
        src = compiles(generate(plan))
        assert "results.append(_text(resp))" in src  # §13.4
        adapter = MockAdapter([Rule(H + "/api/items", body="page body")])
        assert run_generated(src, adapter) == "page body\n" * 3

    def test_default_options(self):
        src = generate(login_plan(), None)
        assert "TIMEOUT = 30.0" in src and "DELAY = 0.0" in src and "'html.parser'" in src


# =========================================================================== robustness

class TestRobustness:
    def test_empty_plan(self, capsys):
        src = compiles(generate(Plan()))
        check_format(src)
        assert run_generated(src, MockAdapter()) == ""
        assert "再現できるリクエストがありません" in capsys.readouterr().err

    def test_unknown_extractor_kind_and_missing_fields_become_todos(self):
        plan = Plan(steps=[
            step(1, "GET", "/x", extractors=[
                Extractor("weird", "telepathy", sample="?"),
                Extractor("nopath", "json"),
                Extractor("nosel", "html_attr", attr="href"),
            ]),
            step(2, "GET", "/y", params=[("w", Ref.var("weird")), ("n", Ref.var("nopath")), ("s", Ref.var("nosel"))]),
        ])
        src = compiles(generate(plan))
        assert src.count("= None  # TODO") == 3
        assert len([w for w in plan.warnings if "抽出できません" in w]) == 3
        assert "未対応の抽出方法 'telepathy'" in src
        adapter = MockAdapter([Rule(H + "/x", body={}), Rule(H + "/y", body={})])
        run_generated(src, adapter)  # None params are dropped by requests; must not crash
        assert adapter.calls[1].url == H + "/y"

    def test_unknown_body_kind_and_bad_status(self):
        plan = Plan(steps=[step(1, "POST", "/x", body_kind="telegram", expected_status="abc")])
        src = compiles(generate(plan))
        assert "_check(resp, 200, " in src
        assert any("未対応のボディ種別" in w for w in plan.warnings)

    def test_var_from_nowhere_is_reported(self):
        plan = Plan(steps=[step(1, "GET", "/x", params=[("q", Ref.var("ghost"))])])
        src = compiles(generate(plan))
        assert func_params(src, "step_01_get_x") == ["session", "ghost"]
        assert any("ghost" in w for w in plan.warnings)

    def test_duplicate_function_names_are_made_unique(self):
        plan = Plan(steps=[step(1, "GET", "/a", func="dup"), step(2, "GET", "/b", func="dup")])
        src = compiles(generate(plan))
        assert "def dup(session):" in src and "def dup_2(session):" in src

    @pytest.mark.parametrize("ref", [
        Ref.var("1bad"), Ref.var("has space"), Ref.var("class"), Ref.var("x\ny"),
        Ref.expr("a +"), Ref.expr("a  # comment"), Ref.expr("a\nb"), Ref.expr("import os"), Ref.expr(""),
    ])
    def test_invalid_identifiers_and_expressions_raise(self, ref):
        plan = Plan(steps=[step(1, "GET", "/x", params=[("q", ref)])])
        with pytest.raises(CodegenError):
            generate(plan)
        plan = Plan(steps=[step(1, "GET", "/x", extractors=[Extractor("1bad", "header", name="x")])])
        with pytest.raises(CodegenError):
            generate(plan)

    def test_generate_is_idempotent_with_warnings(self):
        plan = multipart_plan(big=True)
        a = generate(plan)
        n = len(plan.warnings)
        b = generate(plan)
        assert a == b and len(plan.warnings) == n

    def test_meta_variants_do_not_crash(self):
        for m in ({}, {"source": "weird"}, {"source": None}, {"source": {"source": "mitmproxy", "started_at": "x"}}, {"generated_at": 5}):
            check_format(generate(Plan(steps=[step(1, "GET", "/x")], meta=m)))


# =========================================================================== security: recorded content is data, never code

NASTY = (
    "a'b\"c\\d\ne\rf\"\"\"g'''h#i日本語  \x00\x7f\x1bj\\n\\x41 \t k"
    "\nINJECTED = 1\n"
    "'); import os; os.system('x'); ('"
    "\"\"\"\nINJECTED2 = 2\n\"\"\""
)
HEADER_SAFE_NASTY = "a'b\"c\\d\"\"\"g'''h#i日本語 INJECTED3 = 3 '); import os; ('"


def nasty_plan() -> Plan:
    """Recorded text everywhere a value can appear (compile-only: not every value is sendable)."""
    s1 = step(
        1, "GET", "/n1", func="step_01_nasty",
        url=[Ref.lit(H + "/" + NASTY), Ref.var("v"), Ref.lit(NASTY)],
        params=[(NASTY, Ref.lit(NASTY)), (NASTY, Ref.var("v"))],
        headers=[(NASTY, Ref.lit(NASTY)), ("X-" + NASTY, Ref.var("K"))],
        body_kind="form", form=[(NASTY, Ref.lit(NASTY)), ("b", Ref.lit(NASTY))],
        extractors=[
            Extractor("e1", "html_input", name=NASTY, sample=NASTY, note=NASTY),
            Extractor("e2", "html_meta", name=NASTY, sample=NASTY),
            Extractor("e3", "html_attr", selector=NASTY, attr=NASTY, pattern=NASTY, sample=NASTY),
            Extractor("e4", "html_text", selector=NASTY, pattern=NASTY),
            Extractor("e5", "regex", pattern=NASTY),
            Extractor("e6", "url", pattern=NASTY),
            Extractor("e7", "cookie", name=NASTY),
            Extractor("e8", "header", name=NASTY),
            Extractor("e9", "json", path=[NASTY, 0, NASTY]),
            Extractor("e10", "nonsense" + NASTY),
        ],
        response_kind="html", comment=NASTY,
        loop=Loop(var="v", values=[NASTY, NASTY + "2", "3"], note=NASTY),
    )
    s2 = step(2, "POST", "/n2", func="step_02_nasty", body_kind="json",
              json_body={NASTY: [NASTY, {NASTY: Ref.var("e1")}, 1, None, True]}, comment=NASTY)
    s3 = step(3, "POST", "/n3", func="step_03_nasty", body_kind="multipart", multipart=[
        MultipartPart(name=NASTY, value=Ref.lit(NASTY)),
        MultipartPart(name=NASTY, filename=NASTY, content_type=NASTY, content=NASTY.encode("utf-8")),
    ])
    s4 = step(4, "POST", "/n4", func="step_04_nasty", body_kind="raw", raw_body=NASTY.encode("utf-8") + bytes(range(256)))
    return Plan(
        steps=[s1, s2, s3, s4],
        constants=[Constant("K", NASTY, comment=NASTY), Constant("S", NASTY, secret=True, env_var=NASTY, comment=NASTY)],
        base_headers=[(NASTY, NASTY)],
        initial_cookies=[InitialCookie(NASTY, NASTY, NASTY, NASTY)],
        warnings=[NASTY, "plain"],
        meta={"generated_at": NASTY, "source": {"source": NASTY, "file": NASTY, "creator": NASTY, "started_at": NASTY}},
    )


class TestInjection:
    @pytest.mark.parametrize("comments", [True, False])
    def test_nasty_plan_compiles_and_recorded_text_stays_data(self, comments):
        plan = nasty_plan()
        src = generate(plan, GenOptions(comments=comments))
        check_format(src)
        names = name_tokens(src)
        assert not {"INJECTED", "INJECTED2", "INJECTED3", "system"} & names
        # the recorded text survives intact inside string literals
        ns: dict = {}
        exec(compile(src, "<gen>", "exec"), ns)
        assert ns["K"] == NASTY
        assert ns["BASE_HEADERS"] == {NASTY: NASTY}
        assert ns["INITIAL_COOKIES"] == [{"name": NASTY, "value": NASTY, "domain": NASTY, "path": NASTY}]
        assert "INJECTED" in ns["__doc__"] and "\nINJECTED" not in ns["__doc__"]  # newlines flattened
        assert NASTY not in src.split("\n")  # never a raw line of its own
        # the secret constant reads an environment variable named safely
        assert re.search(r"^S = os\.environ\.get\('[A-Z0-9_]+', ''\)$", src, re.M)
        assert "S = " + repr(NASTY) not in src

    def test_nasty_values_are_sent_byte_exact(self):
        raw = NASTY.encode("utf-8") + bytes(range(256))
        s1 = step(1, "POST", "/form", body_kind="form", form=[(NASTY, Ref.lit(NASTY)), ("plain", Ref.lit(NASTY))],
                  params=[("q", Ref.lit(NASTY)), (NASTY, Ref.lit("v"))],
                  headers=[("X-Nasty", Ref.lit(HEADER_SAFE_NASTY))], comment=NASTY,
                  extractors=[Extractor("tok", "json", path=["tok"], sample=NASTY)])
        s2 = step(2, "POST", "/json", body_kind="json", json_body={NASTY: Ref.var("tok"), "list": [NASTY, 1]})
        s3 = step(3, "PUT", "/raw", body_kind="raw", raw_body=raw, response_kind="empty")
        plan = Plan(steps=[s1, s2, s3], constants=[Constant("C", NASTY, comment=NASTY)], warnings=[NASTY])
        src = generate(plan)
        check_format(src)
        adapter = MockAdapter([
            Rule(H + "/form", body={"tok": NASTY}),
            Rule(H + "/json", body={}),
            Rule(H + "/raw", status=200),
        ])
        run_generated(src, adapter)
        c1, c2, c3 = adapter.calls
        assert c1.form_pairs == [(NASTY, NASTY), ("plain", NASTY)]
        assert c1.query == [("q", NASTY), (NASTY, "v")]
        assert c1.header("X-Nasty") == HEADER_SAFE_NASTY
        assert c2.json() == {NASTY: NASTY, "list": [NASTY, 1]}
        assert c3.body == raw
        assert not {"INJECTED", "INJECTED2", "INJECTED3", "system"} & name_tokens(src)

    def test_docstring_escaper_round_trips(self):
        from reqrec.codegen import _docstring_lines
        samples = ['"""', 'a"', '\\', 'x\\"""y', "tab\there", "nul\x00", "日本語", "", "trail ", " ", 'ends with \\']
        for s in samples:
            lines = _docstring_lines([s, s + "2"])
            value = ast.literal_eval("\n".join(lines))
            assert value.split("\n")[0] == s.rstrip().replace(" ", " ").rstrip() or s.strip() == ""
        assert _docstring_lines([]) == ['""""""']
        assert _docstring_lines(["one"]) == ['"""one"""']

    def test_comment_sanitiser(self):
        from reqrec.codegen import _comment_text
        out = _comment_text("a\nb\rc d\x00e\x1b\tf  ")
        assert "\n" not in out and "\r" not in out and " " not in out
        assert out == "a b c d\\x00e\\x1b\tf"


# =========================================================================== syntax check with -W error, across the board

ALL_PLANS = {
    "login": lambda: generate(login_plan()),
    "login_nocomments": lambda: generate(login_plan(), GenOptions(comments=False, strict_status=True, delay=1)),
    "loop_numeric": lambda: generate(loop_plan(True, True)),
    "loop_values": lambda: generate(loop_plan(False)),
    "json": lambda: generate(json_body_plan()),
    "multipart": lambda: generate(multipart_plan()),
    "multipart_big": lambda: generate(multipart_plan(True)),
    "raw": lambda: generate(raw_plan(bytes(range(256)))),
    "redirect": lambda: generate(redirect_plan(True)),
    "noredirect": lambda: generate(redirect_plan(False)),
    "nasty": lambda: generate(nasty_plan()),
    "nasty_nocomments": lambda: generate(nasty_plan(), GenOptions(comments=False)),
    "empty": lambda: generate(Plan()),
}


@pytest.mark.parametrize("name", sorted(ALL_PLANS))
def test_every_plan_compiles_and_is_well_formatted(name):
    check_format(ALL_PLANS[name]())


def test_every_script_compiles_with_warnings_as_errors(tmp_path):
    paths = []
    for name, fn in ALL_PLANS.items():
        p = tmp_path / f"{name}.py"
        p.write_text(fn(), encoding="utf-8")
        paths.append(str(p))
    checker = (
        "import sys\n"
        "for p in sys.argv[1:]:\n"
        "    with open(p, encoding='utf-8') as fh:\n"
        "        compile(fh.read(), p, 'exec')\n"
        "print('ok', len(sys.argv) - 1)\n"
    )
    proc = subprocess.run([sys.executable, "-W", "error", "-c", checker, *paths], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == f"ok {len(paths)}"


# =========================================================================== the mock adapter itself

class TestMockAdapter:
    def test_multiple_set_cookie_and_history(self):
        adapter = redirect_adapter()
        s = install(requests.Session(), adapter)
        r = s.get(H + "/start")
        assert r.status_code == 200 and len(r.history) == 1 and r.history[0].status_code == 302
        assert s.cookies.get("sess") == "S9"
        assert r.text.startswith("<html>")

    def test_handler_rules_and_unmatched(self):
        adapter = MockAdapter([{"method": "GET", "url": H + "/h", "body": lambda req: (201, {"X-A": "1"}, b"raw")}])
        s = install(requests.Session(), adapter)
        r = s.get(H + "/h?x=1")
        assert (r.status_code, r.headers["X-A"], r.content) == (201, "1", b"raw")
        r = s.post(H + "/h")  # method mismatch -> unmatched 404
        assert r.status_code == 404 and "no rule matches POST" in r.text
        assert len(adapter.unmatched) == 1 and len(adapter.calls) == 2
        assert isinstance(adapter.calls[0], Call) and adapter.calls[0].query_dict == {"x": "1"}

    def test_run_generated_patches_session_env_and_namespace(self):
        script = (
            "import os, requests, time\n"
            "def main():\n"
            "    time.sleep(100)\n"
            "    s = requests.Session()\n"
            "    r = s.get('https://example.test/e')\n"
            "    print(r.json()['v'], os.environ.get('REQREC_T'))\n"
        )
        adapter = MockAdapter([Rule(H + "/e", body={"v": 1})])
        ns: dict = {}
        out = run_generated(script, adapter, env={"REQREC_T": "tv"}, namespace=ns)
        assert out == "1 tv\n"
        assert callable(ns["main"]) and requests.Session is not None
        import os
        assert "REQREC_T" not in os.environ

    def test_body_kinds(self):
        adapter = MockAdapter([Rule(H + "/b", body="テキスト"), Rule(H + "/j", body=[1, 2]), Rule(H + "/n", body=None)])
        s = install(requests.Session(), adapter)
        assert s.get(H + "/b").text == "テキスト"
        assert s.get(H + "/j").json() == [1, 2]
        assert s.get(H + "/n").content == b""
