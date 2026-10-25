"""Tests for the codegen section of ``reqrec.py`` (DESIGN.md §8) and the ``tests/support.py`` mock transport.

One section per former test module (headed ``# ===== former tests/<name>.py ... =====``).  Helpers
that existed in several of them under the same name but with different contents carry a section
prefix (``phase2_step`` / ``phase2_check_format``, ``review3_step`` / ``review3_check_format`` /
``review3_fake_response`` / ``review3_login_adapter``); identical ones are defined once.
"""

from __future__ import annotations

import ast
import base64
import io
import json
import os
import re
import subprocess
import sys
import tokenize
import types
import warnings
from pathlib import Path
from urllib.parse import parse_qsl, quote_from_bytes, unquote_to_bytes, urlsplit

import pytest
import requests
from requests.utils import get_encoding_from_headers

import reqrec as util
from reqrec import build_plan
from reqrec import CodegenError, MAX_INLINE_BODY, generate
from reqrec import (
    AuthInfo, Constant, Extractor, GenOptions, InitialCookie, Loop, MultipartPart, Plan, PlanOptions, Ref,
    Step,
)
from reqrec import load_recording
from tests.support import Call, MockAdapter, Rule, install, run_generated


# ===== former tests/test_codegen.py: code generation and the MockAdapter transport =====
# Tests for ``reqrec.codegen`` (DESIGN.md §8) and the ``tests/support.py`` mock transport.
#
# Plans are built by hand from ``reqrec.core`` so this file does not depend on the plan builder.
# Every generated script is compiled; most are also *executed* against ``MockAdapter`` and the
# sequence of HTTP calls (methods, URLs, headers, bodies) is asserted.

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
        assert json.loads(out) == {"ok": True, "name": "太郎"}  # stdout carries only the result
        assert "太郎" in out
        # progress goes to stderr: one line per step (with the title of an HTML page) and a final line
        assert capsys.readouterr().err.splitlines() == [
            "[1/3] OK  GET /login (200)  「ログイン」",
            "[2/3] OK  POST /submit (200)",
            "[3/3] OK  GET /users/{user_id}/me (200)",
            "[完了] すべての手順が終わりました（3 手順）",
        ]

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
        assert "_step_start(1, 3, 'GET /login')" in src and "_step_start(3, 3, 'GET /users/{user_id}/me')" in src
        assert src.count("\n    _step_ok(resp)\n") == 3  # one call per step in main()
        assert 'print("[完了] すべての手順が終わりました（3 手順）", file=sys.stderr, flush=True)' in src
        # the __main__ block names the step that failed, then lets the error through (traceback kept)
        assert src.rstrip().endswith(
            'if __name__ == "__main__":\n    try:\n        main()\n    except Exception:\n'
            '        # どの手順で止まったかを表示してから、エラーの詳細を出す\n'
            '        if _STEP["no"] and not _STEP["ok"]:\n'
            '            print("[{}/{}] 失敗  {}".format(_STEP["no"], _STEP["total"], _STEP["label"]), file=sys.stderr, flush=True)\n'
            '        raise')
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
        from reqrec import _docstring_lines
        samples = ['"""', 'a"', '\\', 'x\\"""y', "tab\there", "nul\x00", "日本語", "", "trail ", " ", 'ends with \\']
        for s in samples:
            lines = _docstring_lines([s, s + "2"])
            value = ast.literal_eval("\n".join(lines))
            assert value.split("\n")[0] == s.rstrip().replace(" ", " ").rstrip() or s.strip() == ""
        assert _docstring_lines([]) == ['""""""']
        assert _docstring_lines(["one"]) == ['"""one"""']

    def test_comment_sanitiser(self):
        from reqrec import _comment_text
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


# ===== former tests/test_codegen_phase2.py: phase-2 code generation (auth, encodings, forms) =====
# Phase-2 tests for ``reqrec.codegen`` (DESIGN.md §13.1-§13.4).
#
# * §13.1 the printed result follows ``Plan.final_step_index`` (``final_resp`` / ``final_results``);
# * §13.2 ``Plan.auth`` -> ``session.auth`` (Basic tuple, ``HTTPDigestAuth``, SSPI -> ``requests_ntlm``
#   fallback) and no ``Authorization`` header of that scheme survives in the script;
# * §13.3 (TLS) is gone: reqrec targets http:// sites only, so no ``VERIFY_TLS`` / ``_LegacyTLSAdapter``
#   is emitted and requests' own defaults apply;
# * §13.4 responses are decoded from bytes (``_soup`` / ``_text``), Shift_JIS pages served without a
#   charset come out right, and a legacy-charset form body is rebuilt from ``Step.form``.
#
# Plans are built by hand (no dependency on the plan builder); scripts are compiled and executed
# against ``tests.support``.

HTTP_H = "http://legacy.example.test"


# =========================================================================== helpers

def phase2_check_format(src: str) -> None:
    """Formatting contract: trailing newline, no trailing whitespace, parses as Python 3.8, no warnings."""
    assert src.endswith("\n") and not src.endswith("\n\n")
    for i, line in enumerate(src.split("\n"), 1):
        assert line == line.rstrip(), f"trailing whitespace on line {i}: {line!r}"
    ast.parse(src, feature_version=(3, 8))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        compile(src, "<gen>", "exec")


def docstring_of(src: str) -> str:
    return ast.get_docstring(ast.parse(src)) or ""


def exec_module(src: str) -> dict:
    """Execute the generated module (definitions only, ``main()`` is not called)."""
    ns: dict = {"__name__": "generated_under_test"}
    exec(compile(src, "<gen>", "exec"), ns)
    return ns


def phase2_step(index: int, method: str, path: str, host: str = H, **kw) -> Step:
    url = kw.pop("url", None) or [Ref.lit(host + path)]
    kw.setdefault("response_kind", "json")
    slug = path.strip("/").replace("/", "_").replace(".", "_").lower() or "root"
    func = kw.pop("func", None) or f"step_{index:02d}_{method.lower()}_{slug}"
    return Step(index=index, func_name=func, method=method, url=url, **kw)


def fake_response(body: bytes, content_type: str | None, url: str = H + "/x") -> requests.Response:
    """A ``requests.Response`` as the HTTP adapter would build it (``encoding`` from the header only)."""
    resp = requests.Response()
    resp.status_code = 200
    resp._content = body
    resp.url = url
    if content_type is not None:
        resp.headers["Content-Type"] = content_type
    resp.encoding = get_encoding_from_headers(resp.headers)
    return resp


def mounted_sessions(monkeypatch) -> list[requests.Session]:
    """Record every Session the script creates (``run_generated`` patches ``requests.Session`` itself,
    so we wrap ``Session.__init__``)."""
    created: list[requests.Session] = []
    original = requests.Session.__init__

    def init(self, *a, **k):
        original(self, *a, **k)
        created.append(self)

    monkeypatch.setattr(requests.Session, "__init__", init)
    return created


# =========================================================================== §13.1 final step

def three_step_plan(final: int | None) -> Plan:
    s1 = phase2_step(1, "GET", "/one", extractors=[Extractor("token", "json", path=["token"], sample="t1")])
    s2 = phase2_step(2, "GET", "/two", params=[("t", Ref.var("token"))], response_kind="html")
    s3 = phase2_step(3, "GET", "/three", params=[("t", Ref.var("token"))])
    return Plan(steps=[s1, s2, s3], final_step_index=final)


def three_step_adapter() -> MockAdapter:
    return MockAdapter([
        Rule(H + "/one", body={"token": "t1"}),
        Rule(H + "/two", body="<html><head><title>二番目のページ</title></head></html>", content_type="text/html; charset=utf-8"),
        Rule(H + "/three", body={"third": True}),
    ])


class TestFinalStep:
    def test_final_step_index_selects_the_printed_result(self):
        plan = three_step_plan(final=2)
        src = generate(plan)
        phase2_check_format(src)
        adapter = three_step_adapter()
        out = run_generated(src, adapter)
        assert [c.path for c in adapter.calls] == ["/one", "/two", "/three"]  # every step still runs
        assert out == "二番目のページ\n"  # ... but the HTML step's result is what main() prints
        assert src.count("final_resp = resp") == 1
        after_two = src.index("resp, out = step_02_get_two(")
        assert src.index("final_resp = resp") > after_two
        assert src.index("final_resp = resp") < src.index("resp, out = step_03_get_three(")
        assert "# ===== 結果を表示（ステップ 2: GET https://example.test/two） =====" in src
        assert "soup = _soup(final_resp)" in src
        assert "結果として表示するステップ: 2（GET https://example.test/two）" in docstring_of(src)
        assert plan.warnings == []

    def test_default_is_the_last_step_and_the_comment_names_it(self):
        src = generate(three_step_plan(final=None))
        phase2_check_format(src)
        assert "# ===== 最後のステップの結果を表示（ステップ 3: GET https://example.test/three） =====" in src
        assert "json.dumps(final_resp.json()" in src
        assert "結果として表示するステップ" not in docstring_of(src)
        assert json.loads(run_generated(src, three_step_adapter())) == {"third": True}

    def test_unknown_final_step_index_falls_back_with_a_warning(self):
        plan = three_step_plan(final=9)
        src = generate(plan)
        phase2_check_format(src)
        assert any("ステップ 9" in w and "最後のステップ" in w for w in plan.warnings)
        assert "ステップ 9" in docstring_of(src)
        assert json.loads(run_generated(src, three_step_adapter())) == {"third": True}
        # idempotent (apart from the generation time stamp, which has one-second resolution)
        unstamp = lambda text: re.sub(r"(生成: reqrec \S+ / )\S+", lambda m: m.group(1) + "<time>", text)  # noqa: E731
        assert unstamp(generate(plan)) == unstamp(src)

    def test_looped_final_step_prints_the_collected_json_list(self):
        s1 = phase2_step(1, "GET", "/api/items", params=[("page", Ref.var("page"))],
                  loop=Loop(var="page", values=["1", "2", "3"], numeric_range=(1, 3)),
                  extractors=[Extractor("last", "json", path=["last"], sample="x3")])
        s2 = phase2_step(2, "GET", "/api/after", params=[("after", Ref.var("last"))])
        plan = Plan(steps=[s1, s2], final_step_index=1)
        src = generate(plan)
        phase2_check_format(src)
        assert "final_results = results" in src
        assert "print(json.dumps(final_results, ensure_ascii=False, indent=2))" in src

        def items(req):
            page = dict(parse_qsl(urlsplit(req.url).query))["page"]
            return 200, None, {"page": int(page), "last": "x" + page}

        adapter = MockAdapter([Rule(H + "/api/items", handler=items), Rule(H + "/api/after", body={"after": "ok"})])
        out = run_generated(src, adapter)
        assert [c.path for c in adapter.calls] == ["/api/items"] * 3 + ["/api/after"]
        assert adapter.calls[-1].query_dict == {"after": "x3"}
        assert json.loads(out) == [{"page": 1, "last": "x1"}, {"page": 2, "last": "x2"}, {"page": 3, "last": "x3"}]

    def test_looped_final_step_with_text_pages(self):
        s1 = phase2_step(1, "GET", "/p", params=[("page", Ref.var("page"))], response_kind="text",
                  loop=Loop(var="page", values=["a", "b"]))
        s2 = phase2_step(2, "GET", "/done")
        src = generate(Plan(steps=[s1, s2], final_step_index=1))
        phase2_check_format(src)
        assert "results.append(_text(resp))" in src and "for text in final_results:" in src
        adapter = MockAdapter([Rule(H + "/p", body="ページ本文"), Rule(H + "/done", body={})])
        assert run_generated(src, adapter) == "ページ本文\nページ本文\n"

    def test_print_final_off_emits_no_final_bookkeeping(self):
        src = generate(three_step_plan(final=2), GenOptions(print_final=False))
        phase2_check_format(src)
        assert "final_resp" not in src and "final_results" not in src
        assert run_generated(src, three_step_adapter()) == ""

    @pytest.mark.parametrize("kind,body,ct,expected", [
        ("text", "テキスト結果", "text/plain; charset=utf-8", "テキスト結果\n"),
        ("empty", b"", None, f"200 {H}/mid\n"),
    ])
    def test_final_kind_comes_from_the_chosen_step(self, kind, body, ct, expected):
        s1 = phase2_step(1, "GET", "/mid", response_kind=kind)
        s2 = phase2_step(2, "GET", "/last")
        src = generate(Plan(steps=[s1, s2], final_step_index=1))
        phase2_check_format(src)
        adapter = MockAdapter([Rule(H + "/mid", body=body, content_type=ct), Rule(H + "/last", body={"z": 1})])
        assert run_generated(src, adapter) == expected
        assert "json.dumps(final_resp.json()" not in src  # the last step's JSON is not what gets printed


# =========================================================================== §13.2 authentication

def basic_plan(with_constants: bool = True, username: str = "alice") -> Plan:
    s1 = phase2_step(1, "GET", "/secure", host="https://intra.example.test",
              headers=[("Authorization", Ref.lit("Basic " + base64.b64encode(b"alice:recorded-pw").decode())),
                       ("X-Requested-With", Ref.lit("XMLHttpRequest"))],
              extractors=[Extractor("item", "json", path=["item"], sample="i1")])
    s2 = phase2_step(2, "GET", "/detail", host="https://intra.example.test", params=[("item", Ref.var("item"))],
              headers=[("authorization", Ref.lit("basic " + base64.b64encode(b"alice:recorded-pw").decode()))])
    auth = AuthInfo(kind="basic", hosts=["intra.example.test"], realm="Intranet", username=username)
    constants: list[Constant] = []
    if with_constants:
        auth.username_const, auth.password_const = "AUTH_USERNAME", "AUTH_PASSWORD"
        constants = [
            Constant("AUTH_USERNAME", username, comment="HTTP Basic 認証のユーザー名"),
            Constant("AUTH_PASSWORD", "recorded-pw", secret=True, env_var="REQREC_AUTH_PASSWORD",
                     comment="HTTP Basic 認証のパスワード（環境変数 REQREC_AUTH_PASSWORD で指定）"),
        ]
    return Plan(steps=[s1, s2], constants=constants, auth=auth)


def basic_adapter(expected_pw: str) -> MockAdapter:
    expected = "Basic " + base64.b64encode(f"alice:{expected_pw}".encode()).decode()

    def guard(handler):
        def inner(req):
            if req.headers.get("Authorization") != expected:
                return 401, [("WWW-Authenticate", 'Basic realm="Intranet"')], {"error": "unauthorized"}
            return handler(req)
        return inner

    return MockAdapter([
        Rule("https://intra.example.test/secure", handler=guard(lambda req: (200, None, {"item": "i1"}))),
        Rule("https://intra.example.test/detail", handler=guard(lambda req: (200, None, {"detail": "ok"}))),
    ])


class TestAuth:
    def test_basic_sets_session_auth_and_drops_recorded_headers(self):
        plan = basic_plan()
        src = generate(plan)
        phase2_check_format(src)
        assert "session.auth = (AUTH_USERNAME, AUTH_PASSWORD)" in src
        main_src = src[src.index("def main():"):]
        assert main_src.index("session = requests.Session()") < main_src.index("session.auth = (") < main_src.index("session.headers.update(BASE_HEADERS)")
        assert "AUTH_USERNAME = 'alice'" in src and "AUTH_PASSWORD = os.environ.get('REQREC_AUTH_PASSWORD', '')" in src
        assert base64.b64encode(b"alice:recorded-pw").decode() not in src
        assert "'Authorization'" not in src and "'authorization'" not in src
        assert "'X-Requested-With': 'XMLHttpRequest'" in src  # other headers stay
        doc = docstring_of(src)
        assert "認証: HTTP Basic 認証" in doc and "REQREC_AUTH_PASSWORD" in doc and "記録時のユーザー: alice" in doc
        assert any("Authorization" in w and "session.auth" in w for w in plan.warnings)

        adapter = basic_adapter("fresh-pw")
        out = run_generated(src, adapter, env={"REQREC_AUTH_PASSWORD": "fresh-pw"})
        assert [c.path for c in adapter.calls] == ["/secure", "/detail"]
        assert adapter.calls[1].query_dict == {"item": "i1"}
        assert json.loads(out) == {"detail": "ok"}
        with pytest.raises(requests.HTTPError):
            run_generated(src, basic_adapter("fresh-pw"), env={"REQREC_AUTH_PASSWORD": "wrong"})

    def test_basic_without_plan_constants_synthesises_them(self):
        plan = basic_plan(with_constants=False, username="bob")
        src = generate(plan)
        phase2_check_format(src)
        assert "AUTH_USERNAME = 'bob'" in src
        assert "AUTH_PASSWORD = os.environ.get('REQREC_AUTH_PASSWORD', '')" in src
        assert "session.auth = (AUTH_USERNAME, AUTH_PASSWORD)" in src
        assert any("AUTH_USERNAME" in w and "補いました" in w for w in plan.warnings)
        assert "REQREC_AUTH_PASSWORD" in docstring_of(src)
        assert plan.constants == []  # the plan itself is not mutated with constants
        exec_module(src)

    def test_digest_uses_http_digest_auth(self):
        plan = basic_plan()
        plan.auth.kind = "digest"
        plan.steps[0].headers[0] = ("Authorization", Ref.lit('Digest username="alice", realm="Intranet", nonce="abc", response="def"'))
        src = generate(plan)
        phase2_check_format(src)
        assert "session.auth = requests.auth.HTTPDigestAuth(AUTH_USERNAME, AUTH_PASSWORD)" in src
        assert 'nonce="abc"' not in src and "'Authorization'" not in src
        assert "認証: HTTP Digest 認証" in docstring_of(src)
        adapter = MockAdapter([
            Rule("https://intra.example.test/secure", body={"item": "i1"}),
            Rule("https://intra.example.test/detail", body={"detail": "ok"}),
        ])
        out = run_generated(src, adapter, env={"REQREC_AUTH_PASSWORD": "pw"})
        assert json.loads(out) == {"detail": "ok"}
        assert adapter.calls[0].header("Authorization") is None  # digest only answers a challenge

    def ntlm_plan(self, kind: str = "ntlm", username: str | None = "EXAMPLE\\taro") -> Plan:
        type3 = "NTLM TlRMTVNTUAADAAAAGAAYAHIAAAAYABgAigAAAA4ADgBIAAAACAAIAFYAAAAUABQAXgAAAAAAAACiAAAABYKIogoAY0UAAAAPRQBYAEEATQBQAEwARQB0AGEAcgBvAFcATwBSAEsAUwBUAEEAVABJAE8ATgA="
        s1 = phase2_step(1, "GET", "/Default.aspx", host="http://intra.example.local", response_kind="html",
                  headers=[("Authorization", Ref.lit(type3)), ("Accept", Ref.lit("text/html"))],
                  extractors=[Extractor("viewstate", "html_input", name="__VIEWSTATE", sample="/wEP")])
        s2 = phase2_step(2, "POST", "/Default.aspx", host="http://intra.example.local", body_kind="form",
                  form=[("__VIEWSTATE", Ref.var("viewstate"))],
                  headers=[("Authorization", Ref.expr('"Negotiate " + "oYG"')), ("Authorization", Ref.expr('"Bearer " + viewstate'))],
                  response_kind="html")
        return Plan(steps=[s1, s2], auth=AuthInfo(kind=kind, hosts=["intra.example.local"], username=username),
                    warnings=["統合 Windows 認証 (ntlm) を検出しました"])

    def test_ntlm_emits_sspi_then_requests_ntlm_fallback(self):
        plan = self.ntlm_plan()
        src = generate(plan)
        phase2_check_format(src)
        assert "from requests_negotiate_sspi import HttpNegotiateAuth" in src
        assert "session.auth = HttpNegotiateAuth()" in src
        assert "from requests_ntlm import HttpNtlmAuth" in src
        assert "session.auth = HttpNtlmAuth(os.environ.get(\"REQREC_NTLM_USER\", 'EXAMPLE\\\\taro'), os.environ.get(\"REQREC_NTLM_PASSWORD\", \"\"))" in src
        assert "TlRMTVNTUAAD" not in src and "oYG" not in src
        assert "'Authorization': \"Bearer \" + viewstate" in src  # a token scheme is not the session's auth -> kept
        assert "記録時のユーザー: EXAMPLE\\\\taro" in src  # repr-escaped in comments / docstring
        doc = docstring_of(src)
        assert "注意:" in doc
        assert 'pip install "reqrec[sspi]"' in doc and 'pip install "reqrec[ntlm]"' in doc
        assert "REQREC_NTLM_USER" in doc and "REQREC_NTLM_PASSWORD" in doc and "EXAMPLE\\taro" in doc
        assert "認証: 統合 Windows 認証（NTLM）" in doc and "session.auth" in doc
        assert len([w for w in plan.warnings if "Authorization" in w]) == 2  # once per step that carried one

    def test_negotiate_without_known_user_uses_placeholder(self):
        src = generate(self.ntlm_plan(kind="negotiate", username=None))
        phase2_check_format(src)
        assert 'os.environ.get("REQREC_NTLM_USER", r"DOMAIN\\user")' in src
        assert "統合 Windows 認証（Negotiate）" in docstring_of(src)
        assert "DOMAIN\\user" in docstring_of(src)

    def test_ntlm_script_runs_with_requests_ntlm_stub(self, monkeypatch):
        """Off Windows the SSPI import fails; the script must fall back to requests_ntlm and pass the
        env vars (default: the recorded user)."""
        created: list[tuple] = []

        class HttpNtlmAuth:
            def __init__(self, username, password, *a, **k):
                created.append((username, password))

            def __call__(self, r):
                return r

        stub = types.ModuleType("requests_ntlm")
        stub.HttpNtlmAuth = HttpNtlmAuth
        monkeypatch.setitem(sys.modules, "requests_negotiate_sspi", None)  # -> ImportError
        monkeypatch.setitem(sys.modules, "requests_ntlm", stub)
        monkeypatch.delenv("REQREC_NTLM_USER", raising=False)
        monkeypatch.delenv("REQREC_NTLM_PASSWORD", raising=False)
        src = generate(self.ntlm_plan())
        page = '<html><head><title>ok</title></head><body><input type="hidden" name="__VIEWSTATE" value="NEW"></body></html>'
        adapter = MockAdapter([
            Rule("http://intra.example.local/Default.aspx", method="GET", body=page, content_type="text/html"),
            Rule("http://intra.example.local/Default.aspx", method="POST", body=page, content_type="text/html"),
        ])
        out = run_generated(src, adapter)
        assert created == [("EXAMPLE\\taro", "")]
        assert adapter.calls[1].form == {"__VIEWSTATE": "NEW"}
        assert adapter.calls[0].header("Authorization") is None  # the recorded NTLM Type-3 token is gone
        assert adapter.calls[1].header("Authorization") == "Bearer NEW"  # the Bearer header (not NTLM) survives
        assert out == "ok\n"

        created.clear()
        run_generated(src, adapter, env={"REQREC_NTLM_USER": "OTHER\\hanako", "REQREC_NTLM_PASSWORD": "pw"})
        assert created == [("OTHER\\hanako", "pw")]

    def test_ntlm_script_fails_clearly_without_any_ntlm_package(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "requests_negotiate_sspi", None)
        monkeypatch.setitem(sys.modules, "requests_ntlm", None)
        src = generate(self.ntlm_plan())
        with pytest.raises(SystemExit) as info:
            run_generated(src, MockAdapter())
        message = str(info.value)
        assert 'reqrec[ntlm]' in message and 'reqrec[sspi]' in message and "REQREC_NTLM_USER" in message

    def test_unknown_auth_kind_becomes_a_todo(self):
        plan = basic_plan()
        plan.auth = AuthInfo(kind="kerberos-x", username="x")
        src = generate(plan)
        phase2_check_format(src)
        assert "session.auth =" not in src
        assert "TODO: 認証方式 'kerberos-x'" in src
        assert any("kerberos-x" in w for w in plan.warnings)
        assert "'Authorization'" in src  # an unknown scheme family drops nothing

    def test_comments_off_still_configures_auth(self):
        plan = basic_plan()
        src = generate(plan, GenOptions(comments=False))
        phase2_check_format(src)
        assert comment_tokens(src) == []
        assert "session.auth = (AUTH_USERNAME, AUTH_PASSWORD)" in src
        ntlm = generate(self.ntlm_plan(), GenOptions(comments=False))
        phase2_check_format(ntlm)
        assert comment_tokens(ntlm) == [] and "from requests_ntlm import HttpNtlmAuth" in ntlm

    def test_nasty_username_stays_data(self):
        nasty = "EX\\\"\"\"\nINJECTED = 1\n'); import os; ('"
        plan = self.ntlm_plan(username=nasty)
        src = generate(plan)
        phase2_check_format(src)
        assert "INJECTED" not in name_tokens(src)
        ns = exec_module(src)
        assert "INJECTED" in ns["__doc__"] and "\nINJECTED" not in ns["__doc__"]
        basic = basic_plan(with_constants=False, username=nasty)
        src = generate(basic)
        phase2_check_format(src)
        assert "INJECTED" not in name_tokens(src)
        assert exec_module(src)["AUTH_USERNAME"] == nasty


# =========================================================================== §13.3 TLS (removed)

class TestNoTLSSettings:
    """reqrec targets http:// sites only: the scripts carry no TLS knobs (``VERIFY_TLS``,
    ``_LegacyTLSAdapter``, ``session.mount``), so requests' own defaults apply."""

    REMOVED = ("VERIFY_TLS", "session.verify", "_LegacyTLSAdapter", "session.mount(", "import ssl", "import warnings")

    @pytest.mark.parametrize("opts", [GenOptions(), GenOptions(comments=False, strict_status=True, delay=1)])
    def test_no_tls_settings_are_emitted(self, opts):
        for plan in (three_step_plan(None), basic_plan(), TestAuth().ntlm_plan()):
            src = generate(plan, opts)
            phase2_check_format(src)
            assert [name for name in self.REMOVED if name in src] == []

    def test_the_session_keeps_the_requests_defaults(self, monkeypatch):
        sessions = mounted_sessions(monkeypatch)
        run_generated(generate(three_step_plan(None)), three_step_adapter())
        assert sessions and sessions[-1].verify is True


# =========================================================================== §13.4 encoding

SJIS_META_PAGE = ('<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS">'
                  '<title>売上レポート検索</title></head><body><p>担当者: 山田太郎</p><a id="r" href="Report.aspx?id=1234">日本支社</a></body></html>')
EUC_META_PAGE = '<html><head><meta charset="EUC-JP"><title>イベント一覧</title></head><body>こんにちは</body></html>'
HTML5_META_PAGE = '<html><head><meta charset="Shift_JIS"><title>見積書</title></head><body>御中</body></html>'
XML_DOC = '<?xml version="1.0" encoding="Shift_JIS"?>\n<root><item>日本語の項目</item></root>'
NO_META_PAGE = ("<html><head><title>文字コードの宣言が無いページです</title></head>"
                "<body><p>これは文字コードの自動判定を確かめるための、十分に長い日本語の本文です。株式会社の売上報告書、"
                "担当者一覧、業務用プリンターの在庫、東京支店と大阪支店の連絡先を含みます。</p></body></html>")


def encoding_helpers() -> dict:
    """``_text`` / ``_soup`` / ``_charset`` from a generated script (an HTML step so ``_soup`` exists)."""
    return exec_module(generate(Plan(steps=[phase2_step(1, "GET", "/x", response_kind="html")])))


class TestEncoding:
    def test_helpers_are_emitted(self):
        src = generate(Plan(steps=[phase2_step(1, "GET", "/x", response_kind="html")]))
        assert "def _text(resp):" in src and "def _charset(resp):" in src and "def _normalise_charset(name):" in src
        assert "return BeautifulSoup(resp.content, 'html.parser', from_encoding=_charset(resp))" in src
        assert "BeautifulSoup(resp.text" not in src
        assert "resp.apparent_encoding" in src
        assert "_META_CHARSET_RE" in src and "_XML_ENCODING_RE" in src

    @pytest.mark.parametrize("body,content_type,expected_text,expected_encoding", [
        # header charset present -> trusted (even though the meta says Shift_JIS)
        (SJIS_META_PAGE.encode("euc_jp"), "text/html; charset=EUC-JP", "売上レポート検索", "euc-jp"),
        (SJIS_META_PAGE.encode("cp932"), 'text/html; charset="Windows-31J"', "売上レポート検索", "cp932"),
        (EUC_META_PAGE.encode("euc_jp"), "text/html;charset=euc-jp", "イベント一覧", "euc-jp"),
        # no charset -> <meta http-equiv ... charset=Shift_JIS> -> cp932
        (SJIS_META_PAGE.encode("cp932"), "text/html", "担当者: 山田太郎", "cp932"),
        # no charset -> <meta charset="...">
        (HTML5_META_PAGE.encode("cp932"), "text/html", "見積書", "cp932"),
        (EUC_META_PAGE.encode("euc_jp"), "text/html", "こんにちは", "euc-jp"),
        # no charset -> <?xml encoding="Shift_JIS"?>
        (XML_DOC.encode("cp932"), "application/xml", "日本語の項目", "cp932"),
        (XML_DOC.encode("cp932"), "text/xml", "日本語の項目", "cp932"),
        # nothing declared -> apparent_encoding
        (NO_META_PAGE.encode("cp932"), "text/html", "文字コードの宣言が無いページです", "cp932"),
        (NO_META_PAGE.encode("utf-8"), "text/html", "文字コードの宣言が無いページです", "utf-8"),
        # JSON without charset -> UTF-8 (RFC 8259), also for +json
        ('{"name": "太郎"}'.encode("utf-8"), "application/json", "太郎", "utf-8"),
        ('{"name": "花子"}'.encode("utf-8"), "application/problem+json", "花子", "utf-8"),
        # unknown charset name -> sniffed from the body instead
        (HTML5_META_PAGE.encode("cp932"), "text/html; charset=x-bogus-charset", "見積書", "cp932"),
        # no Content-Type header at all
        (SJIS_META_PAGE.encode("cp932"), None, "山田太郎", "cp932"),
    ])
    def test_text_decodes_correctly(self, body, content_type, expected_text, expected_encoding):
        helpers = encoding_helpers()
        resp = fake_response(body, content_type)
        text = helpers["_text"](resp)
        assert expected_text in text
        assert resp.encoding.lower().replace("_", "-") == expected_encoding.replace("_", "-")
        assert helpers["_text"](resp) == text  # stable on a second call

    def test_text_without_helper_would_be_mojibake(self):
        """Sanity check of the premise: requests alone decodes charset-less text/html as ISO-8859-1."""
        resp = fake_response(SJIS_META_PAGE.encode("cp932"), "text/html")
        assert resp.encoding == "ISO-8859-1" and "山田太郎" not in resp.text
        assert "山田太郎" in encoding_helpers()["_text"](resp)

    def test_text_on_empty_body(self):
        helpers = encoding_helpers()
        assert helpers["_text"](fake_response(b"", "text/html")) == ""
        assert helpers["_text"](fake_response(b"", None)) == ""

    def test_charset_and_normalisation(self):
        helpers = encoding_helpers()
        norm = helpers["_normalise_charset"]
        for alias in ("Shift_JIS", "shift-jis", "SJIS", "x-sjis", "Windows-31J", "MS932", '"shift_jis"'):
            assert norm(alias) == "cp932", alias
        assert norm("EUC-JP") == "euc-jp" and norm("utf-8") == "utf-8" and norm("UTF8") == "utf8"
        assert norm("x-bogus") is None and norm("") is None and norm(None) is None
        assert helpers["_charset"](fake_response(b"", "text/html; charset=Shift_JIS")) == "cp932"
        assert helpers["_charset"](fake_response(b"", "text/html")) is None
        assert helpers["_charset"](fake_response(b"", None)) is None
        assert helpers["_charset"](fake_response(b"", "text/plain; boundary=x; CHARSET = 'euc-jp'")) == "euc-jp"

    def test_soup_parses_bytes_and_honours_header_charset(self):
        helpers = encoding_helpers()
        soup = helpers["_soup"](fake_response(SJIS_META_PAGE.encode("cp932"), "text/html"))
        assert soup.title.get_text() == "売上レポート検索"
        assert soup.select_one("#r")["href"] == "Report.aspx?id=1234"
        # the header wins over a wrong <meta>
        soup = helpers["_soup"](fake_response(SJIS_META_PAGE.encode("euc_jp"), "text/html; charset=EUC-JP"))
        assert soup.title.get_text() == "売上レポート検索"
        soup = helpers["_soup"](fake_response(NO_META_PAGE.encode("cp932"), "text/html"))
        assert "文字コードの宣言" in soup.title.get_text()

    def test_shift_jis_site_end_to_end(self):
        """Regex extraction on Japanese text of a charset-less Shift_JIS page, the value reused in a
        query string, and the final print of a Shift_JIS page - all readable Japanese."""
        s1 = phase2_step(1, "GET", "/Default.aspx", host=HTTP_H, response_kind="html",
                  extractors=[Extractor("person", "regex", pattern=r"担当者: ([^<]+)<", sample="山田太郎"),
                              Extractor("report_id", "html_attr", selector="#r", attr="href", pattern=r"id=(\d+)", sample="1234")])
        s2 = phase2_step(2, "GET", "/Report.aspx", host=HTTP_H, response_kind="html",
                  params=[("id", Ref.var("report_id")), ("name", Ref.var("person"))])
        src = generate(Plan(steps=[s1, s2]))
        phase2_check_format(src)
        assert "person = _regex(_text(resp), '担当者: ([^<]+)<')" in src

        def report(req):
            q = dict(parse_qsl(urlsplit(req.url).query))
            if q != {"id": "1234", "name": "山田太郎"}:
                return 404, [("Content-Type", "text/html")], b"<html>no</html>"
            html = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS">'
                    "<title>レポート 1234（業務用プリンター）</title></head><body>ok</body></html>")
            return 200, [("Content-Type", "text/html")], html.encode("cp932")

        adapter = MockAdapter([
            Rule(HTTP_H + "/Default.aspx", body=SJIS_META_PAGE.encode("cp932"), content_type="text/html"),
            Rule(HTTP_H + "/Report.aspx", handler=report),
        ])
        out = run_generated(src, adapter)
        assert adapter.calls[1].query_dict == {"id": "1234", "name": "山田太郎"}
        assert out == "レポート 1234（業務用プリンター）\n"

    def test_final_text_print_of_charset_less_shift_jis(self):
        src = generate(Plan(steps=[phase2_step(1, "GET", "/Export.aspx", host=HTTP_H, response_kind="text")]))
        assert "print(_text(final_resp)[:2000])" in src
        body = "商品,数量\r\n業務用プリンター,18\r\n複合機（カラー対応）,7\r\n東京支店,大阪支店,名古屋支店\r\n".encode("cp932")
        adapter = MockAdapter([Rule(HTTP_H + "/Export.aspx", body=body, content_type="text/csv")])
        out = run_generated(src, adapter)
        assert "業務用プリンター" in out and "複合機" in out


# =========================================================================== §13.4 legacy form bodies

KEYWORD_CP932 = "日本".encode("cp932")  # %93%FA%96%7B
BUTTON_CP932 = "検索".encode("cp932")  # %8C%9F%8D%F5
RECORDED_BODY = (b"__EVENTTARGET=&__VIEWSTATE=%2FwEPrecorded%3D%3D&ctl00%24txtKeyword=%93%FA%96%7B&ctl00%24btnSearch=%8C%9F%8D%F5")


def legacy_form_plan(content_type: str | None = "application/x-www-form-urlencoded", with_form: bool = True) -> Plan:
    s1 = phase2_step(1, "GET", "/Default.aspx", host=HTTP_H, response_kind="html",
              extractors=[Extractor("viewstate", "html_input", name="__VIEWSTATE", sample="/wEPrecorded==")])
    headers = [("Referer", Ref.lit(HTTP_H + "/Default.aspx"))]
    if content_type is not None:
        headers.insert(0, ("Content-Type", Ref.lit(content_type)))
    s2 = phase2_step(2, "POST", "/Default.aspx", host=HTTP_H, response_kind="html", body_kind="raw", raw_body=RECORDED_BODY,
              headers=headers,
              form=[("__EVENTTARGET", Ref.lit("")), ("__VIEWSTATE", Ref.var("viewstate")),
                    ("ctl00$txtKeyword", Ref.expr(repr(KEYWORD_CP932))), ("ctl00$btnSearch", Ref.expr(repr(BUTTON_CP932)))] if with_form else None)
    return Plan(steps=[s1, s2], warnings=["step 2: フォーム本文は Shift_JIS で URL エンコードされていたため、記録時の本文をそのまま送ります"])


def webforms_adapter(fresh_viewstate: str) -> MockAdapter:
    def page(req):
        html = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"></head><body>'
                f'<form><input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="{fresh_viewstate}" /></form></body></html>')
        return 200, [("Content-Type", "text/html")], html.encode("cp932")

    def postback(req):
        body = req.body if isinstance(req.body, bytes) else str(req.body or "").encode("latin-1")
        pairs = {}
        for segment in body.split(b"&"):
            name, _, value = segment.partition(b"=")
            pairs[unquote_to_bytes(name.replace(b"+", b" "))] = unquote_to_bytes(value.replace(b"+", b" "))
        ok = (pairs.get(b"__VIEWSTATE") == fresh_viewstate.encode() and pairs.get(b"ctl00$txtKeyword") == KEYWORD_CP932
              and pairs.get(b"ctl00$btnSearch") == BUTTON_CP932 and pairs.get(b"__EVENTTARGET") == b""
              and (req.headers.get("Content-Type") or "").startswith("application/x-www-form-urlencoded"))
        if not ok:
            return 500, [("Content-Type", "text/html")], "<html><title>Invalid viewstate</title></html>".encode("cp932")
        html = '<html><head><meta charset="Shift_JIS"><title>検索結果: 日本</title></head><body>1 件</body></html>'
        return 200, [("Content-Type", "text/html")], html.encode("cp932")

    return MockAdapter([
        Rule(HTTP_H + "/Default.aspx", method="GET", handler=page),
        Rule(HTTP_H + "/Default.aspx", method="POST", handler=postback),
    ])


class TestLegacyFormBody:
    def test_raw_form_is_rebuilt_from_step_form(self):
        plan = legacy_form_plan()
        src = generate(plan)
        phase2_check_format(src)
        assert "from urllib.parse import unquote, urlencode, urljoin" in src
        assert "data=urlencode({" in src
        assert "'__VIEWSTATE': viewstate,  # step_01_get_default_aspx で取得" in src
        assert "'ctl00$txtKeyword': b'\\x93\\xfa\\x96{',  # cp932 で「日本」（記録時の表記: %93%FA%96%7B）" in src
        assert "'ctl00$btnSearch': b'\\x8c\\x9f\\x8d\\xf5',  # cp932 で「検索」（記録時の表記: %8C%9F%8D%F5）" in src
        assert "%2FwEPrecorded" not in src  # the recorded VIEWSTATE is not replayed
        assert "data=b'" not in src
        assert "'Content-Type': 'application/x-www-form-urlencoded'" in src
        assert "記録時の文字コード" in src
        assert any(w.startswith("step_02_post_default_aspx:") and "組み直します" in w for w in plan.warnings)
        assert "組み直します" in docstring_of(src)
        assert ast.parse(src) and "viewstate" in [a.arg for a in next(
            n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "step_02_post_default_aspx").args.args]

        fresh = "/wEPNEW" + "Qq9XwZ1" * 10 + "=="
        adapter = webforms_adapter(fresh)
        out = run_generated(src, adapter)
        assert [c.method for c in adapter.calls] == ["GET", "POST"]
        post = adapter.calls[1]
        assert quote_from_bytes(fresh.encode(), safe="").encode() in post.body
        assert b"%93%FA%96%7B" in post.body and b"ctl00%24txtKeyword" in post.body
        assert post.header("Content-Type") == "application/x-www-form-urlencoded"
        assert out == "検索結果: 日本\n"

    def test_raw_body_without_form_hint_is_sent_verbatim(self):
        src = generate(legacy_form_plan(with_form=False))
        phase2_check_format(src)
        assert "urlencode(" not in src and "import unquote, urlencode" not in src
        assert "data=" + repr(RECORDED_BODY) in src
        adapter = MockAdapter([
            Rule(HTTP_H + "/Default.aspx", method="GET", body='<input name="__VIEWSTATE" value="v">', content_type="text/html"),
            Rule(HTTP_H + "/Default.aspx", method="POST", body="<html></html>", content_type="text/html"),
        ])
        run_generated(src, adapter)
        assert adapter.calls[1].body == RECORDED_BODY

    def test_raw_form_hint_ignored_for_non_form_content_type(self):
        src = generate(legacy_form_plan(content_type="application/json"))
        assert "urlencode(" not in src and "data=" + repr(RECORDED_BODY) in src

    def test_raw_form_without_content_type_header_gets_one(self):
        src = generate(legacy_form_plan(content_type=None))
        phase2_check_format(src)
        assert "data=urlencode(" in src
        assert "'Content-Type': 'application/x-www-form-urlencoded'" in src
        adapter = webforms_adapter("/wEPfresh==")
        run_generated(src, adapter)
        assert adapter.calls[1].header("Content-Type") == "application/x-www-form-urlencoded"

    def test_comments_off(self):
        src = generate(legacy_form_plan(), GenOptions(comments=False))
        phase2_check_format(src)
        assert comment_tokens(src) == [] and "data=urlencode(" in src


# =========================================================================== everything compiles with -W error

PHASE2_PLANS = {
    "final": lambda: generate(three_step_plan(2)),
    "final_missing": lambda: generate(three_step_plan(9)),
    "basic": lambda: generate(basic_plan()),
    "basic_synth": lambda: generate(basic_plan(with_constants=False)),
    "ntlm": lambda: generate(TestAuth().ntlm_plan()),
    "negotiate": lambda: generate(TestAuth().ntlm_plan("negotiate", None)),
    "last": lambda: generate(three_step_plan(None)),
    "basic_nocomments_strict": lambda: generate(basic_plan(), GenOptions(comments=False, strict_status=True, delay=1)),
    "legacy_form": lambda: generate(legacy_form_plan()),
    "empty_ntlm": lambda: generate(Plan(auth=AuthInfo(kind="ntlm"))),
}


@pytest.mark.parametrize("name", sorted(PHASE2_PLANS))
def test_every_phase2_plan_compiles_and_is_well_formatted(name):
    phase2_check_format(PHASE2_PLANS[name]())


# ===== former tests/test_review3_codegen.py: review-3 code generation fixes (secrets, downloads) =====
# Review 3 findings for ``reqrec.codegen`` / ``reqrec.core`` (DESIGN.md §13.13).
#
# The shared download rule (the generated scripts and the GUI's 「保存されるファイル」 list agree):
#
# 1. a response *is an attachment* when ``Content-Disposition`` (stripped, lower-cased) starts with
#    ``attachment``, or contains ``filename`` and does not start with ``inline``;
# 2. a step's response is saved when ``response_kind == "binary"`` (always) or when it is an
#    attachment at run time - for every step kind (``html`` included), non-loop steps and every
#    iteration of a loop step;
# 3. the final (printed) step is saved right after its own call; the final block only prints;
# 4. names are unique within one run (``name (2).ext``, ``(3)``); a previous run's file is overwritten.
#
# Also: the required-secret check in ``main()`` tests the *constants* (a value typed into the
# constant block works) and covers the Basic / Digest password even when nothing was recorded;
# RFC 2047 file names, Windows reserved names and over-long names.  Plans are built by hand and the
# scripts run against ``tests.support``; at the end every fixture recording is generated
# with several option sets and compiled.

XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


# =========================================================================== helpers

def review3_check_format(src: str) -> None:
    """Trailing newline, no trailing whitespace, Python 3.8 grammar, compiles with warnings as errors."""
    assert src.endswith("\n") and not src.endswith("\n\n")
    for i, line in enumerate(src.split("\n"), 1):
        assert line == line.rstrip(), f"trailing whitespace on line {i}: {line!r}"
    ast.parse(src, feature_version=(3, 8))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        compile(src, "<gen>", "exec")


def main_source(src: str) -> str:
    return src[src.index("def main():"):]


def review3_step(index: int, method: str, path: str, **kw) -> Step:
    url = kw.pop("url", None) or [Ref.lit(H + path)]
    kw.setdefault("response_kind", "json")
    slug = path.strip("/").replace("/", "_").replace(".", "_").lower() or "root"
    func = kw.pop("func", None) or f"step_{index:02d}_{method.lower()}_{slug}"
    return Step(index=index, func_name=func, method=method, url=url, **kw)


def review3_fake_response(disposition: str | None, url: str = H + "/Export.aspx", content_type: str = XLSX) -> requests.Response:
    resp = requests.Response()
    resp.status_code = 200
    resp._content = b"PK"
    resp.url = url
    resp.headers["Content-Type"] = content_type
    if disposition is not None:
        resp.headers["Content-Disposition"] = disposition
    return resp


def b64_word(text: str, charset: str = "UTF-8", codec: str = "utf-8") -> str:
    return f"=?{charset}?B?{base64.b64encode(text.encode(codec)).decode('ascii')}?="


@pytest.fixture
def outdir(tmp_path, monkeypatch):
    out = tmp_path / "out"
    monkeypatch.setenv("REQREC_OUTPUT_DIR", str(out))
    return out


def files_in(folder: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in folder.iterdir()} if folder.exists() else {}


# =========================================================================== required secrets

def password_plan(value: str = "recorded-pw") -> Plan:
    s1 = review3_step(1, "POST", "/Login.aspx", body_kind="form", response_kind="html",
              form=[("txtUser", Ref.lit("taro")), ("txtPassword", Ref.var("TXT_PASSWORD"))])
    const = Constant("TXT_PASSWORD", value, secret=True, env_var="REQREC_TXT_PASSWORD")
    return Plan(steps=[s1], constants=[const])


def review3_login_adapter() -> MockAdapter:
    return MockAdapter([Rule(H + "/Login.aspx", body="<html><head><title>メニュー</title></head></html>",
                             content_type="text/html; charset=utf-8")])


class TestRequiredSecrets:
    ASSIGN = "TXT_PASSWORD = os.environ.get('REQREC_TXT_PASSWORD', '')"

    def test_check_tests_the_constant(self, monkeypatch):
        monkeypatch.delenv("REQREC_TXT_PASSWORD", raising=False)
        src = generate(password_plan())
        review3_check_format(src)
        assert "missing = [env for env, value in [('REQREC_TXT_PASSWORD', TXT_PASSWORD)] if not value]" in src
        assert "os.environ.get(name)" not in src
        adapter = review3_login_adapter()
        with pytest.raises(SystemExit) as info:
            run_generated(src, adapter)
        assert "REQREC_TXT_PASSWORD" in str(info.value.code) and "設定されていません" in str(info.value.code)
        assert adapter.calls == []  # nothing is sent with an empty password

    @pytest.mark.parametrize("replacement", [
        "TXT_PASSWORD = 'typed-in'",                                   # the constant overwritten
        "TXT_PASSWORD = os.environ.get('REQREC_TXT_PASSWORD', 'typed-in')",  # the default filled in
    ])
    def test_value_typed_into_the_constant_block_runs(self, monkeypatch, replacement):
        monkeypatch.delenv("REQREC_TXT_PASSWORD", raising=False)
        src = generate(password_plan())
        assert src.count(self.ASSIGN) == 1
        edited = src.replace(self.ASSIGN, replacement)
        adapter = review3_login_adapter()
        assert run_generated(edited, adapter) == "メニュー\n"
        assert adapter.calls[0].form == {"txtUser": "taro", "txtPassword": "typed-in"}

    def test_environment_variable_still_works(self):
        adapter = review3_login_adapter()
        run_generated(generate(password_plan()), adapter, env={"REQREC_TXT_PASSWORD": "from-env"})
        assert adapter.calls[0].form["txtPassword"] == "from-env"

    def test_secret_recorded_empty_stays_optional(self, monkeypatch):
        monkeypatch.delenv("REQREC_TXT_PASSWORD", raising=False)
        src = generate(password_plan(value=""))
        assert "missing" not in src
        adapter = review3_login_adapter()
        run_generated(src, adapter)
        assert adapter.calls[0].form["txtPassword"] == ""

    @staticmethod
    def auth_plan(kind: str, with_constants: bool = True) -> Plan:
        host = "https://intra.example.test"
        s1 = review3_step(1, "GET", "/secure", url=[Ref.lit(host + "/secure")])
        auth = AuthInfo(kind=kind, hosts=["intra.example.test"], username="alice")
        constants: list[Constant] = []
        if with_constants:
            auth.username_const, auth.password_const = "AUTH_USERNAME", "AUTH_PASSWORD"
            constants = [Constant("AUTH_USERNAME", "alice"),
                         Constant("AUTH_PASSWORD", "", secret=True, env_var="REQREC_AUTH_PASSWORD")]
        return Plan(steps=[s1], constants=constants, auth=auth)

    @pytest.mark.parametrize("kind,with_constants", [("digest", True), ("basic", True), ("basic", False), ("digest", False)])
    def test_basic_digest_password_is_required_even_when_not_recorded(self, monkeypatch, kind, with_constants):
        """A Digest password is never on the wire and a synthesised AUTH_PASSWORD has no value:
        both are recorded as '' yet the site cannot be used without them."""
        monkeypatch.delenv("REQREC_AUTH_PASSWORD", raising=False)
        plan = self.auth_plan(kind, with_constants)
        src = generate(plan)
        review3_check_format(src)
        assert "[('REQREC_AUTH_PASSWORD', AUTH_PASSWORD)]" in src
        adapter = MockAdapter([Rule("https://intra.example.test/secure", body={"ok": True})])
        with pytest.raises(SystemExit) as info:
            run_generated(src, adapter)
        assert "REQREC_AUTH_PASSWORD" in str(info.value.code)
        assert adapter.calls == []
        assert run_generated(src, adapter, env={"REQREC_AUTH_PASSWORD": "pw"}) == '{\n  "ok": true\n}\n'

    def test_non_secret_basic_password_is_not_checked(self):
        plan = self.auth_plan("basic")
        plan.constants[1] = Constant("AUTH_PASSWORD", "recorded", secret=False)
        src = generate(plan)
        assert "missing" not in src and "AUTH_PASSWORD = 'recorded'" in src

    @pytest.mark.parametrize("kind", ["ntlm", "negotiate"])
    def test_windows_authentication_requires_nothing(self, kind):
        plan = Plan(steps=[review3_step(1, "GET", "/Default.aspx", response_kind="html")],
                    auth=AuthInfo(kind=kind, hosts=["example.test"], username="EXAMPLE\\taro"))
        src = generate(plan)
        review3_check_format(src)
        assert "missing" not in src and "REQREC_NTLM_PASSWORD" in src

    def test_several_secrets_are_listed_one_per_line_and_comment_free(self, monkeypatch):
        for env in ("REQREC_A_PASSWORD", "REQREC_B_TOKEN", "REQREC_AUTH_PASSWORD"):
            monkeypatch.delenv(env, raising=False)
        plan = self.auth_plan("basic")
        plan.constants += [Constant("A_PASSWORD", "x", secret=True, env_var="REQREC_A_PASSWORD"),
                           Constant("B_TOKEN", "y", secret=True, env_var="REQREC_B_TOKEN")]
        for comments in (True, False):
            src = generate(plan, GenOptions(comments=comments))
            review3_check_format(src)
            assert "missing = [env for env, value in [\n" in src and "] if not value]" in src
            for pair in ("('REQREC_AUTH_PASSWORD', AUTH_PASSWORD),", "('REQREC_A_PASSWORD', A_PASSWORD),",
                         "('REQREC_B_TOKEN', B_TOKEN),"):
                assert pair in src
            if not comments:
                assert comment_tokens(src) == []
        with pytest.raises(SystemExit) as info:
            run_generated(src, MockAdapter(), env={"REQREC_A_PASSWORD": "set"})
        assert str(info.value.code).startswith("環境変数 REQREC_AUTH_PASSWORD, REQREC_B_TOKEN が設定されていません")


# =========================================================================== attachment rule (1)

ATTACHMENT_CASES = [
    ("attachment", True),
    ("Attachment; filename=a.csv", True),
    ("  attachment;filename*=UTF-8''a.csv", True),
    ('filename="report.xlsx"', True),          # no disposition type, but names a file
    ("form-data; name=x; filename=a.bin", True),
    ("inline; filename=f.txt", False),         # Spring's RFD protection on every JSON response
    ("INLINE; FileName=\"x.json\"", False),
    ("  inline;filename*=UTF-8''f.txt", False),
    ("inline", False),
    ("", False),
    (None, False),
]


@pytest.mark.parametrize("value,expected", ATTACHMENT_CASES)
def test_util_is_attachment_disposition(value, expected):
    assert util.is_attachment_disposition(value) is expected


@pytest.mark.parametrize("value,expected", ATTACHMENT_CASES)
def test_generated_is_attachment_matches_util(value, expected):
    ns = exec_module(generate(Plan(steps=[review3_step(1, "GET", "/x")])))
    assert ns["_is_attachment"](review3_fake_response(value)) is expected


class TestInlineIsNotADownload:
    def test_final_json_with_inline_filename_is_pretty_printed_not_saved(self, outdir):
        plan = Plan(steps=[review3_step(1, "GET", "/api/a"), review3_step(2, "GET", "/api/b")])
        adapter = MockAdapter([
            Rule(H + "/api/a", body={"a": 1}, headers={"Content-Disposition": "inline;filename=f.txt"}),
            Rule(H + "/api/b", body={"名前": "値"}, headers={"Content-Disposition": "inline;filename=f.txt"}),
        ])
        out = run_generated(generate(plan), adapter)
        assert out == '{\n  "名前": "値"\n}\n'
        assert files_in(outdir) == {}

    def test_final_json_attachment_is_saved_and_previewed(self, outdir):
        plan = Plan(steps=[review3_step(1, "GET", "/api/export")])
        adapter = MockAdapter([Rule(H + "/api/export", body={"rows": [1, 2]},
                                    headers={"Content-Disposition": "attachment; filename=rows.json"})])
        out = run_generated(generate(plan), adapter)
        assert files_in(outdir) == {"rows.json": b'{"rows": [1, 2]}'}
        assert out.count("に保存しました") == 1 and out.endswith('{"rows": [1, 2]}\n')


# =========================================================================== saving rule (2) / (3)

class TestEveryKindIsSaved:
    HTML_XLS = "<table><tr><td>品番</td><td>数量</td></tr><tr><td>A-1</td><td>3</td></tr></table>".encode("cp932")

    def test_html_attachment_in_the_middle_is_saved(self, outdir):
        """An "Excel export" that is really an HTML table served as text/html."""
        plan = Plan(steps=[
            review3_step(1, "POST", "/List.aspx", response_kind="html"),
            review3_step(2, "GET", "/Menu.aspx", response_kind="html"),
            review3_step(3, "GET", "/api/done"),
        ])
        adapter = MockAdapter([
            Rule(H + "/List.aspx", body=self.HTML_XLS, content_type="text/html; charset=Shift_JIS",
                 headers={"Content-Disposition": "attachment; filename=list.xls"}),
            Rule(H + "/Menu.aspx", body="<html><title>menu</title></html>", content_type="text/html"),
            Rule(H + "/api/done", body={"done": True}),
        ])
        src = generate(plan)
        review3_check_format(src)
        out = run_generated(src, adapter)
        assert files_in(outdir) == {"list.xls": self.HTML_XLS}  # the ordinary page is not saved
        assert "list.xls に保存しました" in out

    @pytest.mark.parametrize("kind", ["html", "text", "xml", "json", "empty"])
    def test_every_kind_gets_the_attachment_check(self, kind):
        plan = Plan(steps=[review3_step(1, "GET", "/a", response_kind=kind), review3_step(2, "GET", "/b", response_kind=kind)])
        main = main_source(generate(plan))
        assert main.count("_save_if_attachment(resp)") == 2
        assert "_save_download(" not in main

    def test_html_final_attachment_is_saved_once_and_not_parsed(self, outdir):
        plan = Plan(steps=[review3_step(1, "POST", "/List.aspx", response_kind="html")])
        src = generate(plan)
        main = main_source(src)
        assert "final_saved = _save_if_attachment(resp)" in main
        assert main.count("_save_") == 1  # the final block never saves a second time
        adapter = MockAdapter([Rule(H + "/List.aspx", body=self.HTML_XLS, content_type="text/html",
                                    headers={"Content-Disposition": 'attachment; filename="list.xls"'})])
        out = run_generated(src, adapter)
        assert files_in(outdir) == {"list.xls": self.HTML_XLS}
        assert out.count("に保存しました") == 1 and len(out.splitlines()) == 1

    def test_html_final_page_is_still_printed(self, outdir):
        plan = Plan(steps=[review3_step(1, "GET", "/Menu.aspx", response_kind="html")])
        adapter = MockAdapter([Rule(H + "/Menu.aspx", body="<html><title>メニュー</title></html>",
                                    content_type="text/html; charset=utf-8")])
        assert run_generated(generate(plan), adapter) == "メニュー\n"
        assert files_in(outdir) == {}

    def test_empty_final_attachment(self, outdir):
        plan = Plan(steps=[review3_step(1, "GET", "/zero.csv", response_kind="empty")])
        adapter = MockAdapter([Rule(H + "/zero.csv", body=b"", headers={"Content-Disposition": "attachment; filename=zero.csv"})])
        out = run_generated(generate(plan), adapter)
        assert files_in(outdir) == {"zero.csv": b""} and "(0 バイト)" in out and H not in out

    def test_mid_run_final_download_survives_a_later_failure(self, outdir):
        plan = Plan(steps=[
            review3_step(1, "POST", "/Export.aspx", response_kind="binary"),
            review3_step(2, "GET", "/Broken.aspx", response_kind="html"),
        ], final_step_index=1)
        src = generate(plan)
        review3_check_format(src)
        main = main_source(src)
        assert main.index("_save_download(resp)") < main.index("step_02_get_broken_aspx(")
        assert main.count("_save_") == 2  # step 1 saves, step 2 checks; the final block does not
        adapter = MockAdapter([
            Rule(H + "/Export.aspx", body=b"PK-final", content_type=XLSX,
                 headers={"Content-Disposition": "attachment; filename=final.xlsx"}),
            Rule(H + "/Broken.aspx", status=500, body="boom", content_type="text/plain"),
        ])
        with pytest.raises(requests.HTTPError):
            run_generated(src, adapter)
        assert files_in(outdir) == {"final.xlsx": b"PK-final"}

    def test_mid_run_final_text_attachment_saved_before_later_steps(self, outdir):
        plan = Plan(steps=[review3_step(1, "GET", "/Export.aspx", response_kind="text"), review3_step(2, "GET", "/api/next")],
                    final_step_index=1)
        csv = "品番,数量\nA-1,3\n".encode("cp932")
        adapter = MockAdapter([
            Rule(H + "/Export.aspx", body=csv, content_type="text/csv; charset=Shift_JIS",
                 headers={"Content-Disposition": "attachment; filename=list.csv"}),
            Rule(H + "/api/next", body={"x": 1}),
        ])
        out = run_generated(generate(plan), adapter)
        assert files_in(outdir) == {"list.csv": csv}
        lines = out.splitlines()
        assert lines[0].endswith(f"list.csv に保存しました ({len(csv)} バイト)") and lines[1:] == ["品番,数量", "A-1,3", ""]


# =========================================================================== loop steps

def loop_step(kind: str, path: str = "/Report.aspx") -> Step:
    return review3_step(1, "GET", path, response_kind=kind, params=[("page", Ref.var("page"))],
                loop=Loop(var="page", values=["1", "2", "3"], numeric_range=(1, 3), note="3 回"))


def per_page(content_type: str, disposition: str | None = None, body=lambda page: f"page {page}".encode()):
    def handler(req):
        page = req.url.rsplit("page=", 1)[-1]
        headers = {"Content-Type": content_type}
        if disposition:
            headers["Content-Disposition"] = disposition
        return 200, headers, body(page)
    return handler


class TestLoopDownloads:
    def test_binary_loop_saves_every_iteration(self, outdir):
        plan = Plan(steps=[loop_step("binary")])
        src = generate(plan)
        review3_check_format(src)
        main = main_source(src)
        assert "results.append(_save_download(resp))" in main and "_text(resp)" not in main
        adapter = MockAdapter([Rule(H + "/Report.aspx", handler=per_page("application/pdf", "attachment; filename=report.pdf",
                                                                            lambda p: b"%PDF-" + p.encode() + b"\xff\x00"))])
        out = run_generated(src, adapter)
        assert files_in(outdir) == {"report.pdf": b"%PDF-1\xff\x00", "report (2).pdf": b"%PDF-2\xff\x00",
                                    "report (3).pdf": b"%PDF-3\xff\x00"}
        lines = out.splitlines()
        assert len(lines) == 3 and all(ln.endswith("に保存しました (8 バイト)") for ln in lines)  # no binary garbage

    def test_binary_loop_in_the_middle_keeps_the_paths(self, outdir):
        plan = Plan(steps=[loop_step("binary", "/Export.aspx"), review3_step(2, "GET", "/api/end")])
        adapter = MockAdapter([
            Rule(H + "/Export.aspx", handler=per_page(XLSX)),  # no Content-Disposition: output.xlsx
            Rule(H + "/api/end", body={"end": 1}),
        ])
        out = run_generated(generate(plan), adapter)
        assert sorted(files_in(outdir)) == ["output (2).xlsx", "output (3).xlsx", "output.xlsx"]
        assert out.endswith('{\n  "end": 1\n}\n')

    def test_text_loop_saves_attachments_and_keeps_the_text(self, outdir):
        plan = Plan(steps=[loop_step("text", "/Csv.aspx")])
        src = generate(plan)
        main = main_source(src)
        assert "_save_if_attachment(resp)" in main and "results.append(_text(resp))" in main
        adapter = MockAdapter([Rule(H + "/Csv.aspx", handler=per_page("text/csv; charset=utf-8", "attachment; filename=data.csv"))])
        out = run_generated(src, adapter)
        assert files_in(outdir) == {"data.csv": b"page 1", "data (2).csv": b"page 2", "data (3).csv": b"page 3"}
        assert [ln for ln in out.splitlines() if "保存しました" not in ln] == ["page 1", "page 2", "page 3"]

    def test_json_loop_with_inline_filename_is_not_saved(self, outdir):
        plan = Plan(steps=[loop_step("json", "/api/items")])
        adapter = MockAdapter([Rule(H + "/api/items", handler=per_page("application/json", "inline;filename=f.txt",
                                                                        lambda p: ('{"page": %s}' % p).encode()))])
        out = run_generated(generate(plan), adapter)
        assert files_in(outdir) == {}
        assert out == '[\n  {\n    "page": 1\n  },\n  {\n    "page": 2\n  },\n  {\n    "page": 3\n  }\n]\n'

    def test_html_loop_page_without_attachment_is_not_saved(self, outdir):
        plan = Plan(steps=[loop_step("html", "/Grid.aspx")])
        adapter = MockAdapter([Rule(H + "/Grid.aspx", handler=per_page("text/html; charset=utf-8"))])
        assert run_generated(generate(plan), adapter) == "page 1\npage 2\npage 3\n"
        assert files_in(outdir) == {}


# =========================================================================== unique names (4)

class TestUniqueNames:
    def plan(self, count: int = 3) -> Plan:
        return Plan(steps=[review3_step(i, "POST", "/Grid.aspx", response_kind="binary", func=f"step_{i:02d}_export")
                           for i in range(1, count + 1)])

    def adapter(self, tag: str, disposition: str = "attachment; filename=GridViewExport.xls") -> MockAdapter:
        bodies = iter([f"{tag}-1", f"{tag}-2", f"{tag}-3"])
        return MockAdapter([Rule(H + "/Grid.aspx", handler=lambda req: (200, {
            "Content-Type": "application/vnd.ms-excel", "Content-Disposition": disposition}, next(bodies).encode()))])

    def test_same_name_twice_in_one_run_is_numbered(self, outdir):
        src = generate(self.plan())
        out = run_generated(src, self.adapter("run1"))
        assert files_in(outdir) == {"GridViewExport.xls": b"run1-1", "GridViewExport (2).xls": b"run1-2",
                                    "GridViewExport (3).xls": b"run1-3"}
        assert "GridViewExport (3).xls に保存しました" in out
        # a new run starts from the same names again and overwrites what the previous run left
        run_generated(src, self.adapter("run2"))
        assert files_in(outdir) == {"GridViewExport.xls": b"run2-1", "GridViewExport (2).xls": b"run2-2",
                                    "GridViewExport (3).xls": b"run2-3"}

    def test_name_without_extension(self, outdir):
        run_generated(generate(self.plan(2)), self.adapter("x", "attachment; filename=README"))
        assert files_in(outdir) == {"README": b"x-1", "README (2)": b"x-2"}

    def test_names_differing_only_in_case(self, outdir):
        dispositions = iter(["attachment; filename=Report.xlsx", "attachment; filename=report.xlsx"])
        adapter = MockAdapter([Rule(H + "/Grid.aspx", handler=lambda req: (
            200, {"Content-Type": XLSX, "Content-Disposition": next(dispositions)}, b"PK"))])
        run_generated(generate(self.plan(2)), adapter)
        if os.name == "nt":  # one file system name on Windows: the second one must not overwrite the first
            assert sorted(files_in(outdir)) == ["Report.xlsx", "report (2).xlsx"]
        else:
            assert sorted(files_in(outdir)) == ["Report.xlsx", "report.xlsx"]


# =========================================================================== file names

NAME_CASES = [
    # RFC 2047 encoded words (.NET's ContentDisposition for non-ASCII names)
    ('attachment; filename="' + b64_word("生産実績.xlsx") + '"', "生産実績.xlsx"),
    ("attachment; filename=" + b64_word("生産実績.xlsx", "utf-8"), "生産実績.xlsx"),
    ('attachment; filename="=?utf-8?Q?=E6=97=A5=E5=A0=B1_2026.csv?="', "日報 2026.csv"),
    ('attachment; filename="' + b64_word("①報告.xlsx", "Shift_JIS", "cp932") + '"', "①報告.xlsx"),
    ('attachment; filename="' + b64_word("生産") + " " + b64_word("実績.xlsx") + '"', "生産実績.xlsx"),
    ('attachment; filename="' + b64_word("名前.csv", "x-unknown-charset") + '"', "名前.csv"),
    # the earlier forms still work
    ("attachment; filename*=UTF-8''%E7%94%9F%E7%94%A3.xlsx", "生産.xlsx"),
    ("attachment; filename=%E7%94%9F%E7%94%A3.xlsx", "生産.xlsx"),
    ('attachment; filename="' + "日報.xlsx".encode("cp932").decode("latin-1") + '"', "日報.xlsx"),
    ('attachment; filename="a=?b?=c.xlsx"', "a=_b_=c.xlsx"),  # not an encoded word
    # Windows reserved device names, with or without an extension
    ("attachment; filename=CON.xlsx", "_CON.xlsx"),
    ("attachment; filename=nul", "_nul"),
    ("attachment; filename=com1.tar.gz", "_com1.tar.gz"),
    ("attachment; filename=Lpt9.csv", "_Lpt9.csv"),
    ('attachment; filename="aux .txt"', "_aux .txt"),
    ("attachment; filename=CONSOLE.xlsx", "CONSOLE.xlsx"),
    ("attachment; filename=com10.csv", "com10.csv"),
    ("attachment; filename*=UTF-8''COM%C2%B9.txt", "_COM" + chr(0xB9) + ".txt"),  # COM + superscript one
    # path tricks
    ('attachment; filename="..\\\\..\\\\evil.xlsx"', "evil.xlsx"),
    # over-long names keep their extension
    ("attachment; filename*=UTF-8''" + "%E3%81%82" * 200 + ".xlsx", "あ" * 145 + ".xlsx"),
    ("attachment; filename=" + "a" * 300, "a" * 150),
    ("attachment; filename=" + "a" * 140 + "." + "b" * 20, ("a" * 140 + "." + "b" * 20)[:150]),
]


@pytest.mark.parametrize("disposition,expected", NAME_CASES)
def test_util_download_filename(disposition, expected):
    assert util.download_filename(disposition) == expected
    assert len(expected) <= util.MAX_FILE_NAME


@pytest.mark.parametrize("disposition,expected", NAME_CASES)
def test_generated_download_name_matches_util(disposition, expected):
    ns = exec_module(generate(Plan(steps=[review3_step(1, "GET", "/x")]), GenOptions(comments=False)))
    assert ns["_download_name"](review3_fake_response(disposition)) == expected


@pytest.mark.parametrize("disposition", [None, "attachment", "inline", 'attachment; filename=""', "attachment; filename=..."])
def test_util_download_filename_without_a_name(disposition):
    assert util.download_filename(disposition) is None


def test_url_fallback_is_made_safe_too():
    ns = exec_module(generate(Plan(steps=[review3_step(1, "GET", "/x")])))
    assert ns["_download_name"](review3_fake_response(None, url=H + "/files/NUL.xlsx")) == "_NUL.xlsx"
    assert ns["_download_name"](review3_fake_response(None, url=H + "/Export.aspx")) == "output.xlsx"


def test_saving_under_an_encoded_word_name(outdir):
    plan = Plan(steps=[review3_step(1, "POST", "/Export.aspx", response_kind="binary")])
    adapter = MockAdapter([Rule(H + "/Export.aspx", body=b"PK", content_type=XLSX,
                                headers={"Content-Disposition": 'attachment; filename="' + b64_word("生産実績_01.xlsx") + '"'})])
    out = run_generated(generate(plan), adapter)
    assert files_in(outdir) == {"生産実績_01.xlsx": b"PK"} and "生産実績_01.xlsx に保存しました" in out


# =========================================================================== format / options

def kitchen_sink_plan() -> Plan:
    s1 = review3_step(1, "GET", "/Login.aspx", response_kind="html",
              extractors=[Extractor("vs", "html_input", name="__VIEWSTATE", sample="x")])
    s2 = review3_step(2, "POST", "/Login.aspx", body_kind="form", response_kind="html",
              form=[("__VIEWSTATE", Ref.var("vs")), ("pw", Ref.var("TXT_PASSWORD"))])
    s3 = loop_step("binary", "/Pdf.aspx")
    s3.index, s3.func_name = 3, "step_03_get_pdf"
    s4 = loop_step("json", "/api/items")
    s4.index, s4.func_name, s4.loop = 4, "step_04_get_items", Loop(var="page_2", values=["a", "b", "c"])
    s4.params = [("page", Ref.var("page_2"))]
    s5 = review3_step(5, "GET", "/Export.aspx", response_kind="binary")
    s6 = review3_step(6, "GET", "/x.txt", response_kind="text")
    s7 = review3_step(7, "GET", "/none", response_kind="empty")
    constants = [Constant("TXT_PASSWORD", "pw", secret=True, env_var="REQREC_TXT_PASSWORD")]
    auth = AuthInfo(kind="digest", hosts=["example.test"], username="alice")
    return Plan(steps=[s1, s2, s3, s4, s5, s6, s7], constants=constants, auth=auth)


@pytest.mark.parametrize("final", [None, 1, 3, 4, 5, 6, 7])
@pytest.mark.parametrize("opts", [GenOptions(), GenOptions(comments=False), GenOptions(print_final=False),
                                  GenOptions(comments=False, strict_status=True, delay=0.5)])
def test_kitchen_sink_is_well_formed(final, opts):
    plan = kitchen_sink_plan()
    plan.final_step_index = final
    src = generate(plan, opts)
    review3_check_format(src)
    if not opts.comments:
        assert comment_tokens(src) == []
    main = main_source(src)
    assert main.count("_save_if_attachment(resp)") + main.count("_save_download(resp)") == len(plan.steps)
    assert "('REQREC_TXT_PASSWORD', TXT_PASSWORD)" in main and "AUTH_PASSWORD)" in main.split("session =")[0]


# =========================================================================== every fixture recording

FIXTURE_FILES = sorted(p for p in FIXTURES.iterdir() if p.suffix in (".har", ".json"))
PLAN_OPTION_SETS = {
    "default": PlanOptions(),
    "keep_all": PlanOptions(keep_all=True, detect_loops=False),
    "no_redact": PlanOptions(redact_secrets=False),
}
GEN_OPTION_SETS = {
    "default": GenOptions(),
    "no_comments": GenOptions(comments=False),
    "strict_lxml": GenOptions(strict_status=True, delay=1.0, html_parser="lxml"),
    "no_print": GenOptions(print_final=False, comments=False),
}


def test_fixture_list_includes_the_factory_recordings():
    names = {p.name for p in FIXTURE_FILES}
    assert {"factory_ie_recording_digit_key.json", "factory_ie_recording_letter_key.json"} <= names
    assert len(FIXTURE_FILES) >= 5


@pytest.mark.parametrize("fixture", FIXTURE_FILES, ids=lambda p: p.name)
@pytest.mark.parametrize("plan_opts", sorted(PLAN_OPTION_SETS))
def test_every_fixture_generates_well_formed_scripts(fixture, plan_opts):
    recording = load_recording(str(fixture))
    base = build_plan(recording, PLAN_OPTION_SETS[plan_opts])
    assert base.steps
    finals = [None] + sorted({base.steps[0].index, base.steps[len(base.steps) // 2].index})
    for final in finals:
        for gen_name, gen_opts in GEN_OPTION_SETS.items():
            plan = build_plan(recording, PLAN_OPTION_SETS[plan_opts])
            plan.final_step_index = final
            src = generate(plan, gen_opts)
            review3_check_format(src)
            if not gen_opts.comments:
                assert comment_tokens(src) == [], (fixture.name, gen_name)
            main = main_source(src)
            saves = main.count("_save_if_attachment(resp)") + main.count("_save_download(resp)")
            assert saves == len(plan.steps), (fixture.name, gen_name, final)
            if gen_opts.print_final:
                assert main.count("final_resp = resp") + main.count("final_results = results") == 1
            ns = exec_module(src)  # module level runs (constants, helpers) without a request
            assert callable(ns["main"]) and ns["_SAVED_PATHS"] == set()


def test_loop_variable_colliding_with_a_constant_is_refused():
    """main() reads the secret constants before the loops run; a loop variable of the same name would
    make that read an UnboundLocalError, so codegen refuses such a plan like an extractor collision."""
    plan = Plan(steps=[loop_step("json")], constants=[Constant("page", "x", secret=True, env_var="REQREC_PAGE")])
    with pytest.raises(CodegenError, match="loop variable 'page' collides with a constant"):
        generate(plan)
