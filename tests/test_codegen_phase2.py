"""Phase-2 tests for ``reqrec.codegen`` (DESIGN.md §13.1-§13.4).

* §13.1 the printed result follows ``Plan.final_step_index`` (``final_resp`` / ``final_results``);
* §13.2 ``Plan.auth`` -> ``session.auth`` (Basic tuple, ``HTTPDigestAuth``, SSPI -> ``requests_ntlm``
  fallback) and no ``Authorization`` header of that scheme survives in the script;
* §13.3 ``VERIFY_TLS`` always, ``_LegacyTLSAdapter`` with ``GenOptions.legacy_tls``;
* §13.4 responses are decoded from bytes (``_soup`` / ``_text``), Shift_JIS pages served without a
  charset come out right, and a legacy-charset form body is rebuilt from ``Step.form``.

Plans are built by hand (no dependency on the plan builder); scripts are compiled and executed
against ``tests.e2e.mock_adapter``.
"""

from __future__ import annotations

import ast
import base64
import io
import json
import ssl
import sys
import tokenize
import types
import warnings
from urllib.parse import parse_qsl, quote_from_bytes, unquote_to_bytes, urlsplit

import pytest
import requests
from requests.utils import get_encoding_from_headers

from reqrec.codegen import generate
from reqrec.model import AuthInfo, Constant, Extractor, GenOptions, Loop, Plan, Ref, Step
from tests.e2e.mock_adapter import MockAdapter, Rule, run_generated

H = "https://example.test"
HTTP_H = "http://legacy.example.test"


# =========================================================================== helpers

def check_format(src: str) -> None:
    """Formatting contract: trailing newline, no trailing whitespace, parses as Python 3.8, no warnings."""
    assert src.endswith("\n") and not src.endswith("\n\n")
    for i, line in enumerate(src.split("\n"), 1):
        assert line == line.rstrip(), f"trailing whitespace on line {i}: {line!r}"
    ast.parse(src, feature_version=(3, 8))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        compile(src, "<gen>", "exec")


def comment_tokens(src: str) -> list[str]:
    toks = tokenize.generate_tokens(io.StringIO(src).readline)
    return [t.string for t in toks if t.type == tokenize.COMMENT]


def name_tokens(src: str) -> set[str]:
    toks = tokenize.generate_tokens(io.StringIO(src).readline)
    return {t.string for t in toks if t.type == tokenize.NAME}


def docstring_of(src: str) -> str:
    return ast.get_docstring(ast.parse(src)) or ""


def exec_module(src: str) -> dict:
    """Execute the generated module (definitions only, ``main()`` is not called)."""
    ns: dict = {"__name__": "generated_under_test"}
    exec(compile(src, "<gen>", "exec"), ns)
    return ns


def step(index: int, method: str, path: str, host: str = H, **kw) -> Step:
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
    s1 = step(1, "GET", "/one", extractors=[Extractor("token", "json", path=["token"], sample="t1")])
    s2 = step(2, "GET", "/two", params=[("t", Ref.var("token"))], response_kind="html")
    s3 = step(3, "GET", "/three", params=[("t", Ref.var("token"))])
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
        check_format(src)
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
        check_format(src)
        assert "# ===== 最後のステップの結果を表示（ステップ 3: GET https://example.test/three） =====" in src
        assert "json.dumps(final_resp.json()" in src
        assert "結果として表示するステップ" not in docstring_of(src)
        assert json.loads(run_generated(src, three_step_adapter())) == {"third": True}

    def test_unknown_final_step_index_falls_back_with_a_warning(self):
        plan = three_step_plan(final=9)
        src = generate(plan)
        check_format(src)
        assert any("ステップ 9" in w and "最後のステップ" in w for w in plan.warnings)
        assert "ステップ 9" in docstring_of(src)
        assert json.loads(run_generated(src, three_step_adapter())) == {"third": True}
        assert generate(plan) == src  # idempotent

    def test_looped_final_step_prints_the_collected_json_list(self):
        s1 = step(1, "GET", "/api/items", params=[("page", Ref.var("page"))],
                  loop=Loop(var="page", values=["1", "2", "3"], numeric_range=(1, 3)),
                  extractors=[Extractor("last", "json", path=["last"], sample="x3")])
        s2 = step(2, "GET", "/api/after", params=[("after", Ref.var("last"))])
        plan = Plan(steps=[s1, s2], final_step_index=1)
        src = generate(plan)
        check_format(src)
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
        s1 = step(1, "GET", "/p", params=[("page", Ref.var("page"))], response_kind="text",
                  loop=Loop(var="page", values=["a", "b"]))
        s2 = step(2, "GET", "/done")
        src = generate(Plan(steps=[s1, s2], final_step_index=1))
        check_format(src)
        assert "results.append(_text(resp))" in src and "for text in final_results:" in src
        adapter = MockAdapter([Rule(H + "/p", body="ページ本文"), Rule(H + "/done", body={})])
        assert run_generated(src, adapter) == "ページ本文\nページ本文\n"

    def test_print_final_off_emits_no_final_bookkeeping(self):
        src = generate(three_step_plan(final=2), GenOptions(print_final=False))
        check_format(src)
        assert "final_resp" not in src and "final_results" not in src
        assert run_generated(src, three_step_adapter()) == ""

    @pytest.mark.parametrize("kind,body,ct,expected", [
        ("text", "テキスト結果", "text/plain; charset=utf-8", "テキスト結果\n"),
        ("empty", b"", None, f"200 {H}/mid\n"),
    ])
    def test_final_kind_comes_from_the_chosen_step(self, kind, body, ct, expected):
        s1 = step(1, "GET", "/mid", response_kind=kind)
        s2 = step(2, "GET", "/last")
        src = generate(Plan(steps=[s1, s2], final_step_index=1))
        check_format(src)
        adapter = MockAdapter([Rule(H + "/mid", body=body, content_type=ct), Rule(H + "/last", body={"z": 1})])
        assert run_generated(src, adapter) == expected
        assert "json.dumps(final_resp.json()" not in src  # the last step's JSON is not what gets printed


# =========================================================================== §13.2 authentication

def basic_plan(with_constants: bool = True, username: str = "alice") -> Plan:
    s1 = step(1, "GET", "/secure", host="https://intra.example.test",
              headers=[("Authorization", Ref.lit("Basic " + base64.b64encode(b"alice:recorded-pw").decode())),
                       ("X-Requested-With", Ref.lit("XMLHttpRequest"))],
              extractors=[Extractor("item", "json", path=["item"], sample="i1")])
    s2 = step(2, "GET", "/detail", host="https://intra.example.test", params=[("item", Ref.var("item"))],
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
        check_format(src)
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
        check_format(src)
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
        check_format(src)
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
        s1 = step(1, "GET", "/Default.aspx", host="http://intra.example.local", response_kind="html",
                  headers=[("Authorization", Ref.lit(type3)), ("Accept", Ref.lit("text/html"))],
                  extractors=[Extractor("viewstate", "html_input", name="__VIEWSTATE", sample="/wEP")])
        s2 = step(2, "POST", "/Default.aspx", host="http://intra.example.local", body_kind="form",
                  form=[("__VIEWSTATE", Ref.var("viewstate"))],
                  headers=[("Authorization", Ref.expr('"Negotiate " + "oYG"')), ("Authorization", Ref.expr('"Bearer " + viewstate'))],
                  response_kind="html")
        return Plan(steps=[s1, s2], auth=AuthInfo(kind=kind, hosts=["intra.example.local"], username=username),
                    warnings=["統合 Windows 認証 (ntlm) を検出しました"])

    def test_ntlm_emits_sspi_then_requests_ntlm_fallback(self):
        plan = self.ntlm_plan()
        src = generate(plan)
        check_format(src)
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
        check_format(src)
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
        check_format(src)
        assert "session.auth =" not in src
        assert "TODO: 認証方式 'kerberos-x'" in src
        assert any("kerberos-x" in w for w in plan.warnings)
        assert "'Authorization'" in src  # an unknown scheme family drops nothing

    def test_comments_off_still_configures_auth(self):
        plan = basic_plan()
        src = generate(plan, GenOptions(comments=False))
        check_format(src)
        assert comment_tokens(src) == []
        assert "session.auth = (AUTH_USERNAME, AUTH_PASSWORD)" in src
        ntlm = generate(self.ntlm_plan(), GenOptions(comments=False))
        check_format(ntlm)
        assert comment_tokens(ntlm) == [] and "from requests_ntlm import HttpNtlmAuth" in ntlm

    def test_nasty_username_stays_data(self):
        nasty = "EX\\\"\"\"\nINJECTED = 1\n'); import os; ('"
        plan = self.ntlm_plan(username=nasty)
        src = generate(plan)
        check_format(src)
        assert "INJECTED" not in name_tokens(src)
        ns = exec_module(src)
        assert "INJECTED" in ns["__doc__"] and "\nINJECTED" not in ns["__doc__"]
        basic = basic_plan(with_constants=False, username=nasty)
        src = generate(basic)
        check_format(src)
        assert "INJECTED" not in name_tokens(src)
        assert exec_module(src)["AUTH_USERNAME"] == nasty


# =========================================================================== §13.3 TLS

class TestTLS:
    def test_verify_tls_is_always_emitted_and_applied(self, monkeypatch):
        src = generate(three_step_plan(None))
        assert "VERIFY_TLS = True  # 自己署名証明書のサイトなら False か CA 証明書 (.pem) のパスに" in src
        assert "session.verify = VERIFY_TLS" in src
        assert src.index("VERIFY_TLS = True") < src.index("BASE_HEADERS = ")
        sessions = mounted_sessions(monkeypatch)
        run_generated(src, three_step_adapter())
        assert sessions and sessions[-1].verify is True
        off = generate(three_step_plan(None), GenOptions(comments=False))
        assert "VERIFY_TLS = True\n" in off and comment_tokens(off) == []

    def test_no_adapter_without_legacy_tls(self):
        src = generate(three_step_plan(None))
        assert "_LegacyTLSAdapter" not in src and "import ssl" not in src and "import warnings" not in src

    def test_legacy_adapter_is_emitted_and_builds_a_permissive_context(self):
        src = generate(three_step_plan(None), GenOptions(legacy_tls=True))
        check_format(src)
        assert "import ssl" in src and "import warnings" in src
        assert "class _LegacyTLSAdapter(requests.adapters.HTTPAdapter):" in src
        assert 'session.mount("https://", _LegacyTLSAdapter())' in src
        assert src.index("session.verify = VERIFY_TLS") < src.index('session.mount("https://"') < src.index("session.headers.update(")
        assert "ctx.minimum_version = ssl.TLSVersion.TLSv1" in src
        assert 'ctx.set_ciphers("DEFAULT:@SECLEVEL=1")' in src
        assert 'ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)' in src
        assert "IE モード" in src
        assert "CERT_NONE" not in src  # verification is left to requests / VERIFY_TLS

        ns = exec_module(src)
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # the deprecation of TLSv1 must be silenced by the adapter
            adapter = ns["_LegacyTLSAdapter"]()
        ctx = adapter.poolmanager.connection_pool_kw["ssl_context"]
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.protocol == ssl.PROTOCOL_TLS_CLIENT
        assert ctx.minimum_version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.MINIMUM_SUPPORTED)
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
        assert ctx.options & getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0) == getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
        assert ctx.cert_store_stats()["x509_ca"] >= 0
        proxy_ctx = adapter.proxy_manager_for("http://proxy.example.test:3128").connection_pool_kw["ssl_context"]
        assert isinstance(proxy_ctx, ssl.SSLContext) and proxy_ctx is not ctx

    @pytest.mark.parametrize("verify", [False, True, "/nonexistent/ca.pem"])
    def test_legacy_adapter_honours_verify(self, verify, tmp_path):
        """``cert_verify`` keeps ``check_hostname`` in step with ``verify`` so urllib3 can apply
        ``CERT_NONE`` to our context (it raises otherwise) while ``True`` / a CA path still verify."""
        ns = exec_module(generate(three_step_plan(None), GenOptions(legacy_tls=True)))
        adapter = ns["_LegacyTLSAdapter"]()
        request = requests.Request("GET", "https://legacy.example.test/x").prepare()
        if isinstance(verify, str):
            ca = tmp_path / "ca.pem"
            ca.write_text("not really a cert\n", encoding="utf-8")
            verify = str(ca)
        pool = adapter.get_connection_with_tls_context(request, verify=verify)
        adapter.cert_verify(pool, request.url, verify, None)
        ctx = pool.conn_kw["ssl_context"]
        if verify is False:
            assert ctx.check_hostname is False
            ctx.verify_mode = ssl.CERT_NONE  # what urllib3 does next; must not raise
            assert pool.cert_reqs == "CERT_NONE"
        else:
            assert ctx.check_hostname is True
            assert pool.cert_reqs == "CERT_REQUIRED"
            ctx.verify_mode = ssl.CERT_REQUIRED
            if isinstance(verify, str):
                assert pool.ca_certs == verify

    def test_legacy_script_still_runs_against_the_mock(self):
        """The adapter is mounted on https:// only; an http:// plan exercises the full script."""
        s1 = step(1, "GET", "/a", host=HTTP_H, extractors=[Extractor("v", "json", path=["v"], sample="1")])
        s2 = step(2, "GET", "/b", host=HTTP_H, params=[("v", Ref.var("v"))])
        src = generate(Plan(steps=[s1, s2]), GenOptions(legacy_tls=True))
        check_format(src)
        adapter = MockAdapter([Rule(HTTP_H + "/a", body={"v": 7}), Rule(HTTP_H + "/b", body={"ok": True})])
        out = run_generated(src, adapter)
        assert adapter.calls[1].query_dict == {"v": "7"} and json.loads(out) == {"ok": True}

    def test_legacy_adapter_with_comments_off(self):
        src = generate(three_step_plan(None), GenOptions(legacy_tls=True, comments=False))
        check_format(src)
        assert comment_tokens(src) == []
        ns = exec_module(src)
        assert isinstance(ns["_LegacyTLSAdapter"]().poolmanager.connection_pool_kw["ssl_context"], ssl.SSLContext)


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
    return exec_module(generate(Plan(steps=[step(1, "GET", "/x", response_kind="html")])))


class TestEncoding:
    def test_helpers_are_emitted(self):
        src = generate(Plan(steps=[step(1, "GET", "/x", response_kind="html")]))
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
        s1 = step(1, "GET", "/Default.aspx", host=HTTP_H, response_kind="html",
                  extractors=[Extractor("person", "regex", pattern=r"担当者: ([^<]+)<", sample="山田太郎"),
                              Extractor("report_id", "html_attr", selector="#r", attr="href", pattern=r"id=(\d+)", sample="1234")])
        s2 = step(2, "GET", "/Report.aspx", host=HTTP_H, response_kind="html",
                  params=[("id", Ref.var("report_id")), ("name", Ref.var("person"))])
        src = generate(Plan(steps=[s1, s2]))
        check_format(src)
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
        src = generate(Plan(steps=[step(1, "GET", "/Export.aspx", host=HTTP_H, response_kind="text")]))
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
    s1 = step(1, "GET", "/Default.aspx", host=HTTP_H, response_kind="html",
              extractors=[Extractor("viewstate", "html_input", name="__VIEWSTATE", sample="/wEPrecorded==")])
    headers = [("Referer", Ref.lit(HTTP_H + "/Default.aspx"))]
    if content_type is not None:
        headers.insert(0, ("Content-Type", Ref.lit(content_type)))
    s2 = step(2, "POST", "/Default.aspx", host=HTTP_H, response_kind="html", body_kind="raw", raw_body=RECORDED_BODY,
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
        check_format(src)
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
        check_format(src)
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
        check_format(src)
        assert "data=urlencode(" in src
        assert "'Content-Type': 'application/x-www-form-urlencoded'" in src
        adapter = webforms_adapter("/wEPfresh==")
        run_generated(src, adapter)
        assert adapter.calls[1].header("Content-Type") == "application/x-www-form-urlencoded"

    def test_comments_off(self):
        src = generate(legacy_form_plan(), GenOptions(comments=False))
        check_format(src)
        assert comment_tokens(src) == [] and "data=urlencode(" in src


# =========================================================================== everything compiles with -W error

PHASE2_PLANS = {
    "final": lambda: generate(three_step_plan(2)),
    "final_missing": lambda: generate(three_step_plan(9)),
    "basic": lambda: generate(basic_plan()),
    "basic_synth": lambda: generate(basic_plan(with_constants=False)),
    "ntlm": lambda: generate(TestAuth().ntlm_plan()),
    "negotiate": lambda: generate(TestAuth().ntlm_plan("negotiate", None)),
    "legacy_tls": lambda: generate(three_step_plan(None), GenOptions(legacy_tls=True)),
    "legacy_tls_nocomments": lambda: generate(basic_plan(), GenOptions(legacy_tls=True, comments=False, strict_status=True, delay=1)),
    "legacy_form": lambda: generate(legacy_form_plan()),
    "empty_legacy": lambda: generate(Plan(auth=AuthInfo(kind="ntlm")), GenOptions(legacy_tls=True)),
}


@pytest.mark.parametrize("name", sorted(PHASE2_PLANS))
def test_every_phase2_plan_compiles_and_is_well_formatted(name):
    check_format(PHASE2_PLANS[name]())
