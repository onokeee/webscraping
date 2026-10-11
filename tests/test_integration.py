"""Integration tests: the real pipeline on the bundled HAR fixtures.

``load_recording`` -> ``build_plan`` -> ``generate`` for ``tests/fixtures/login_flow_chrome.har``
and ``tests/fixtures/api_firefox.har``.  The plan-level assertions pin down the analysis DESIGN.md
promises (noise filtering with reasons, redirect collapsing, dependency tracing, loop folding,
secret redaction).  The execution tests run the generated scripts in-process against
``tests.e2e.mock_adapter``, where the fake ``shop.example.test`` / ``api.example.test`` /
``app.example.test`` hand out tokens that DIFFER from the recording and reject the recorded ones -
so the scripts can only succeed by re-deriving every dynamic value from the live responses.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import parse_qsl, urlsplit

import pytest
import requests

from reqrec import cli
from reqrec.codegen import generate
from reqrec.importers import load_recording
from reqrec.model import GenOptions, PlanOptions, Ref, to_plain
from reqrec.plan import build_plan
from tests.e2e.mock_adapter import MockAdapter, Rule, run_generated

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROME_HAR = os.path.join(ROOT, "tests", "fixtures", "login_flow_chrome.har")
FIREFOX_HAR = os.path.join(ROOT, "tests", "fixtures", "api_firefox.har")

#: values the browser saw while recording - the generated scripts must never send any of them
REC = {
    "login_token": "tokA1b2C3d4E5f6G7h8",
    "csrf": "csrfQ9w8E7r6T5y4",
    "api_token": "apiZ1x2C3v4B5n6M7",
    "sig": "sigHJK789",
    "org_id": "77",
    "password": "Secr3t!",
    "session_anon": "s1Rk9mB2pQ7vX4zL0nH6wC3tY8aD5fG1",
    "session_auth": "s2Hf4kP9mW2xV7bN1qZ6cL3yT8rJ5dA0",
    "xsrf_cookie": "xsrf%7CAbC123",
    "xsrf_header": "xsrf|AbC123",
    "access_token": ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0ODIxIiwiZXhwIjoxNzQxOTM5NjExfQ."
                     "k3F9zQpLm2WxYv8dTbC5nRaH1sJ6eUoG4iK7hP0qZ2s"),
}


# --------------------------------------------------------------------------- helpers

@pytest.fixture(scope="module")
def chrome():
    recording = load_recording(CHROME_HAR)
    plan = build_plan(recording, PlanOptions())
    source = generate(plan, GenOptions())
    compile(source, "chrome_scrape.py", "exec")
    return recording, plan, source


@pytest.fixture(scope="module")
def firefox():
    recording = load_recording(FIREFOX_HAR)
    plan = build_plan(recording, PlanOptions())
    source = generate(plan, GenOptions())
    compile(source, "firefox_scrape.py", "exec")
    return recording, plan, source


def _body_text(request) -> str:
    body = request.body
    if body is None:
        return ""
    return body.decode("utf-8") if isinstance(body, bytes) else str(body)


def _cookies(request) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (request.headers.get("Cookie") or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            out[name] = value
    return out


def _query(request) -> dict[str, str]:
    return dict(parse_qsl(urlsplit(request.url).query, keep_blank_values=True))


def _everything_sent(adapter: MockAdapter) -> str:
    """Every byte the script put on the wire (URLs, headers, bodies) as one searchable string."""
    chunks = []
    for call in adapter.calls:
        chunks.append(f"{call.method} {call.url}")
        chunks.extend(f"{k}: {v}" for k, v in call.headers.items())
        chunks.append(call.text)
    return "\n".join(chunks)


def _extractors(step) -> dict[str, object]:
    return {e.var: e for e in step.extractors}


# --------------------------------------------------------------------------- Chrome fixture: plan

def test_chrome_noise_is_dropped_with_reasons(chrome):
    recording, plan, _source = chrome
    assert len(recording.flows) == 14
    dropped = {d.flow_id: d for d in plan.dropped}
    assert set(dropped) == {"f0002", "f0003", "f0004", "f0005", "f0006", "f0007"}
    assert dropped["f0002"].url.endswith("/static/app.css") and dropped["f0002"].reason.startswith("static asset")
    assert dropped["f0003"].url.endswith("/static/logo.png") and dropped["f0003"].reason.startswith("static asset")
    assert "google-analytics.com" in dropped["f0004"].url and dropped["f0004"].reason == "tracker/analytics host"
    assert dropped["f0005"].url.endswith("/favicon.ico") and dropped["f0005"].reason.startswith("static asset")
    assert "ads.tracker.example.test" in dropped["f0006"].url and dropped["f0006"].reason == "no response recorded"
    assert dropped["f0007"].method == "OPTIONS" and dropped["f0007"].reason == "CORS preflight"
    assert plan.meta["flows_total"] == 14 and plan.meta["flows_kept"] == 8 and plan.meta["steps"] == 5
    assert [s.index for s in plan.steps] == [1, 2, 3, 4, 5]
    assert [s.func_name for s in plan.steps] == [
        "step_01_get_login", "step_02_post_login", "step_03_get_v1_me", "step_04_get_orgs_items", "step_05_get_export",
    ]


def test_chrome_login_form_uses_hidden_token_and_redacted_password(chrome):
    _recording, plan, source = chrome
    login_page, login_post = plan.steps[0], plan.steps[1]

    assert login_page.method == "GET" and login_page.literal_url() == "https://shop.example.test/login"
    (token,) = login_page.extractors
    assert (token.kind, token.name, token.var, token.sample) == ("html_input", "_token", "token", REC["login_token"])

    assert login_post.method == "POST" and login_post.literal_url() == "https://shop.example.test/login"
    assert login_post.body_kind == "form"
    form = dict(login_post.form)
    assert form["_token"] == Ref.var("token")
    assert form["username"] == Ref.lit("alice")  # used once -> plain literal
    assert form["password"] == Ref.var("PASSWORD")
    assert not any(name.lower() == "content-type" for name, _ in login_post.headers)

    (password,) = plan.constants
    assert (password.name, password.secret, password.env_var, password.value) == (
        "PASSWORD", True, "REQREC_PASSWORD", REC["password"])
    assert REC["password"] not in source
    assert 'os.environ.get(\'REQREC_PASSWORD\'' in source or 'os.environ.get("REQREC_PASSWORD"' in source
    assert any("REQREC_PASSWORD" in w for w in plan.warnings)


def test_chrome_redirect_chain_collapses_into_login_step(chrome):
    _recording, plan, _source = chrome
    login_post = plan.steps[1]
    assert login_post.source_flow_ids == ["f0008", "f0009"]  # 302 -> GET /dashboard folded in
    assert login_post.expected_status == 200
    assert login_post.response_kind == "html"
    assert login_post.allow_redirects is True
    assert not any(s.literal_url() == "https://shop.example.test/dashboard" for s in plan.steps)


def test_chrome_dashboard_extractors(chrome):
    recording, plan, _source = chrome
    exts = _extractors(plan.steps[1])
    assert set(exts) == {"api_token", "x_csrf_token", "sig"}
    dashboard_html = recording.flow_by_id("f0009").response.text()

    csrf = exts["x_csrf_token"]
    assert (csrf.kind, csrf.name, csrf.sample) == ("html_meta", "csrf-token", REC["csrf"])

    api = exts["api_token"]
    assert api.kind == "regex" and api.sample == REC["api_token"]
    assert re.compile(api.pattern).groups == 1
    assert re.search(api.pattern, dashboard_html).group(1) == REC["api_token"]
    assert REC["api_token"] not in api.pattern
    assert "API_TOKEN" in api.pattern
    assert not api.pattern.startswith("\\ ")  # indentation is not baked into the context

    sig = exts["sig"]
    assert (sig.kind, sig.selector, sig.attr, sig.sample) == ("html_attr", "#export-link", "href", REC["sig"])
    assert sig.pattern and re.compile(sig.pattern).groups == 1
    assert re.search(sig.pattern, "/export?sig=" + REC["sig"]).group(1) == REC["sig"]
    assert re.search(sig.pattern, "/export?sig=OTHER").group(1) == "OTHER"


def test_chrome_api_step_headers_and_org_id_trace(chrome):
    _recording, plan, _source = chrome
    me = plan.steps[2]
    assert me.method == "GET" and me.literal_url() == "https://api.example.test/v1/me"
    headers = {name.lower(): ref for name, ref in me.headers}
    assert headers["x-csrf-token"] == Ref.var("x_csrf_token")
    assert headers["authorization"] == Ref.expr('"Bearer " + api_token')
    assert me.response_kind == "json" and me.expected_status == 200
    (org,) = me.extractors
    assert (org.kind, org.path, org.name, org.var, org.sample) == ("json", ["org", "id"], "org.id", "org_id", REC["org_id"])


def test_chrome_pagination_folds_into_one_looped_step(chrome):
    _recording, plan, _source = chrome
    items = [s for s in plan.steps if "items" in s.func_name]
    assert len(items) == 1
    (step,) = items
    assert step.source_flow_ids == ["f0011", "f0012", "f0013"]
    assert step.loop is not None
    assert (step.loop.var, step.loop.values, step.loop.numeric_range) == ("page", ["1", "2", "3"], (1, 3))
    assert step.params == [("page", Ref.var("page"))]
    assert step.url == [Ref.lit("https://api.example.test/v1/orgs/"), Ref.var("org_id"), Ref.lit("/items")]
    assert step.literal_url() is None
    headers = {name.lower(): ref for name, ref in step.headers}
    assert headers["x-csrf-token"] == Ref.var("x_csrf_token")
    assert headers["authorization"] == Ref.expr('"Bearer " + api_token')
    assert step.response_kind == "json"


def test_chrome_export_uses_signed_link(chrome):
    _recording, plan, _source = chrome
    export = plan.steps[4]
    assert export.literal_url() == "https://shop.example.test/export"
    assert export.params == [("sig", Ref.var("sig"))]
    assert export.response_kind == "text" and export.expected_status == 200
    assert export.extractors == []
    assert plan.initial_cookies == []
    assert {k.lower() for k, _ in plan.base_headers} >= {"user-agent", "accept-language"}
    assert not any(k.lower() in ("referer", "origin", "authorization", "cookie", "content-type") for k, _ in plan.base_headers)


def test_chrome_plan_is_json_serialisable_and_warnings_are_benign(chrome):
    _recording, plan, _source = chrome
    dump = json.dumps(to_plain(plan), ensure_ascii=False)
    assert json.loads(dump)["steps"][3]["loop"]["numeric_range"] == [1, 3]
    assert all("looks dynamic" not in w for w in plan.warnings), plan.warnings


# --------------------------------------------------------------------------- Chrome fixture: execution

class ShopSite:
    """Scripted ``shop.example.test`` + ``api.example.test`` that issue all-new tokens and refuse
    every recorded one (wrong token / cookie / signature -> 4xx, which the script turns into an error)."""

    LOGIN_TOKEN = "tokNEW9z8y7x6w5v4u3t2"
    ANON_SESSION = "sessNEWanon0001"
    AUTH_SESSION = "sessNEWauth0002"
    CSRF = "csrfNEWq1w2e3r4t5"
    API_TOKEN = "apiNEWz9y8x7w6v5u4"
    SIG = "sigNEW456XYZ"
    ORG_ID = 4242
    PASSWORD = "N3wPassw0rd!"

    def __init__(self) -> None:
        self.adapter = MockAdapter([
            Rule("https://shop.example.test/login", method="GET", handler=self.login_page),
            Rule("https://shop.example.test/login", method="POST", handler=self.login_post),
            Rule("https://shop.example.test/dashboard", method="GET", handler=self.dashboard),
            Rule("https://api.example.test/v1/me", method="GET", handler=self.me),
            Rule(re.compile(r"^https://api\.example\.test/v1/orgs/\d+/items(\?|$)"), method="GET", handler=self.items),
            Rule("https://shop.example.test/export", method="GET", handler=self.export),
        ])

    def login_page(self, request):
        html = (
            '<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>ログイン</title></head><body>'
            f'<form method="post" action="/login" id="login-form"><input type="hidden" name="_token" value="{self.LOGIN_TOKEN}">'
            '<input type="text" name="username"><input type="password" name="password"></form></body></html>'
        )
        return 200, [("Content-Type", "text/html; charset=UTF-8"),
                     ("Set-Cookie", f"session={self.ANON_SESSION}; Path=/; HttpOnly")], html

    def login_post(self, request):
        form = dict(parse_qsl(_body_text(request), keep_blank_values=True))
        ok = (_cookies(request).get("session") == self.ANON_SESSION and form.get("_token") == self.LOGIN_TOKEN
              and form.get("username") == "alice" and form.get("password") == self.PASSWORD)
        if not ok:
            return 403, [("Content-Type", "text/html; charset=UTF-8")], "<html><body>forbidden</body></html>"
        return 302, [("Location", "/dashboard"), ("Set-Cookie", f"session={self.AUTH_SESSION}; Path=/; HttpOnly")], b""

    def dashboard(self, request):
        if _cookies(request).get("session") != self.AUTH_SESSION:
            return 403, [("Content-Type", "text/html; charset=UTF-8")], "<html><body>login required</body></html>"
        # same page structure as the recording, but different indentation / attribute order
        html = (
            '<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">'
            f'<meta content="{self.CSRF}" name="csrf-token"><title>ダッシュボード</title></head><body>'
            f'<nav><a href="/dashboard">ホーム</a><a href="/export?sig={self.SIG}" id="export-link">Export</a></nav>'
            f'<div id="app" data-org-id="{self.ORG_ID}"></div>'
            '<script>\nwindow.API_BASE = "https://api.example.test/v1";\n'
            f'window.API_TOKEN = "{self.API_TOKEN}";\n'
            'window.CURRENT_USER = {"id": 9001, "name": "Alice"};\n</script></body></html>'
        )
        return 200, [("Content-Type", "text/html; charset=UTF-8")], html

    def _api_ok(self, request) -> bool:
        return (request.headers.get("Authorization") == f"Bearer {self.API_TOKEN}"
                and request.headers.get("X-CSRF-Token") == self.CSRF)

    def me(self, request):
        if not self._api_ok(request):
            return 401, None, {"error": "unauthorized"}
        return 200, None, {"id": 9001, "name": "Alice", "org": {"id": self.ORG_ID, "name": "New Org"}, "roles": ["member"]}

    def items(self, request):
        if not self._api_ok(request):
            return 401, None, {"error": "unauthorized"}
        org = urlsplit(request.url).path.split("/")[3]
        if org != str(self.ORG_ID):
            return 404, None, {"error": f"no such org {org}"}
        page = _query(request).get("page")
        if page not in ("1", "2", "3"):
            return 400, None, {"error": f"bad page {page!r}"}
        n = int(page)
        return 200, None, {"items": [{"id": 100 + n, "name": f"new-item-{n}"}], "page": n, "next": n + 1 if n < 3 else None}

    def export(self, request):
        if _query(request).get("sig") != self.SIG or _cookies(request).get("session") != self.AUTH_SESSION:
            return 403, [("Content-Type", "text/plain")], "bad signature"
        return 200, [("Content-Type", "text/csv; charset=UTF-8"),
                     ("Content-Disposition", 'attachment; filename="export.csv"')], "id,name\n1,new-foo\n2,new-bar\n"


def _assert_chrome_replay(site: ShopSite, out: str) -> None:
    calls = site.adapter.calls
    assert site.adapter.unmatched == [], [c.url for c in site.adapter.unmatched]
    items_url = f"https://api.example.test/v1/orgs/{ShopSite.ORG_ID}/items"
    assert [(c.method, c.url_without_query) for c in calls] == [
        ("GET", "https://shop.example.test/login"),
        ("POST", "https://shop.example.test/login"),
        ("GET", "https://shop.example.test/dashboard"),
        ("GET", "https://api.example.test/v1/me"),
        ("GET", items_url),
        ("GET", items_url),
        ("GET", items_url),
        ("GET", "https://shop.example.test/export"),
    ]
    login, dashboard, me, pages, export = calls[1], calls[2], calls[3], calls[4:7], calls[7]

    # the second run's tokens are what gets sent
    assert login.form == {"_token": ShopSite.LOGIN_TOKEN, "username": "alice", "password": ShopSite.PASSWORD}
    assert login.cookies["session"] == ShopSite.ANON_SESSION
    assert login.header("Content-Type") == "application/x-www-form-urlencoded"
    assert dashboard.cookies["session"] == ShopSite.AUTH_SESSION
    for call in (me, *pages):
        assert call.header("Authorization") == f"Bearer {ShopSite.API_TOKEN}", call.url
        assert call.header("X-CSRF-Token") == ShopSite.CSRF, call.url
        assert "session" not in call.cookies  # the shop cookie never leaks to the API host
    assert [c.query_dict for c in pages] == [{"page": "1"}, {"page": "2"}, {"page": "3"}]
    assert export.query_dict == {"sig": ShopSite.SIG}
    assert export.cookies["session"] == ShopSite.AUTH_SESSION

    # browser-like base headers travel with every request
    for call in calls:
        assert call.header("User-Agent").startswith("Mozilla/5.0 (Windows NT 10.0"), call.url
        assert call.header("Accept-Language") == "ja,en-US;q=0.9,en;q=0.8", call.url

    # the final step's CSV is printed; nothing from the recording was replayed
    assert "id,name" in out and "new-foo" in out and "new-bar" in out
    sent = _everything_sent(site.adapter)
    for key in ("login_token", "csrf", "api_token", "sig", "password", "session_anon", "session_auth"):
        assert REC[key] not in sent, key
    assert "/orgs/77/" not in sent
    assert not any(host in sent for host in ("google-analytics.com", "ads.tracker.example.test", "/static/", "favicon.ico"))


def test_chrome_script_replays_with_fresh_tokens(chrome):
    _recording, _plan, source = chrome
    site = ShopSite()
    out = run_generated(source, site.adapter, env={"REQREC_PASSWORD": ShopSite.PASSWORD})
    _assert_chrome_replay(site, out)


def test_chrome_script_variants_replay_with_fresh_tokens(chrome):
    """Comment-free / strict-status / delayed output goes through the same conversation."""
    recording, _plan, _source = chrome
    plan = build_plan(recording, PlanOptions())
    source = generate(plan, GenOptions(comments=False, strict_status=True, delay=0.5, timeout=5))
    compile(source, "variant.py", "exec")
    assert "time.sleep(DELAY)" in source and "DELAY = 0.5" in source
    site = ShopSite()
    out = run_generated(source, site.adapter, env={"REQREC_PASSWORD": ShopSite.PASSWORD})
    _assert_chrome_replay(site, out)


def test_chrome_script_from_cli_replays(tmp_path, capsys):
    out_file = tmp_path / "scrape.py"
    dump = tmp_path / "plan.json"
    assert cli.main(["generate", CHROME_HAR, "-o", str(out_file), "--dump-plan", str(dump)]) == 0
    err = capsys.readouterr().err
    assert "REQREC_PASSWORD" in err and REC["password"] not in err
    dump_text = dump.read_text(encoding="utf-8")
    plan_json = json.loads(dump_text)
    assert plan_json["steps"][3]["loop"]["numeric_range"] == [1, 3]
    assert REC["password"] not in dump_text and REC["password"] not in out_file.read_text(encoding="utf-8")
    assert plan_json["constants"][0]["env_var"] == "REQREC_PASSWORD" and plan_json["constants"][0]["value"] is None
    site = ShopSite()
    out = run_generated(out_file.read_text(encoding="utf-8"), site.adapter, env={"REQREC_PASSWORD": ShopSite.PASSWORD})
    _assert_chrome_replay(site, out)


def test_chrome_script_fails_loudly_with_wrong_password(chrome):
    _recording, _plan, source = chrome
    site = ShopSite()
    with pytest.raises(requests.HTTPError) as info:
        run_generated(source, site.adapter, env={"REQREC_PASSWORD": "wrong-password"})
    assert info.value.response.status_code == 403
    assert [(c.method, c.path) for c in site.adapter.calls] == [("GET", "/login"), ("POST", "/login")]


def test_chrome_script_without_env_var_sends_empty_password(chrome, monkeypatch):
    """Redacted secret + no environment variable -> an empty password goes out and the login is refused."""
    _recording, _plan, source = chrome
    monkeypatch.delenv("REQREC_PASSWORD", raising=False)
    site = ShopSite()
    with pytest.raises(requests.HTTPError) as info:
        run_generated(source, site.adapter, env={})
    assert info.value.response.status_code == 403
    assert site.adapter.calls[1].form["password"] == ""


def test_cli_inspect_reports_the_traced_values(capsys):
    assert cli.main(["inspect", CHROME_HAR]) == 0
    out = capsys.readouterr().out
    assert "org_id" in out and "org.id" in out and "{org_id}" in out
    assert "page=1..3" in out
    assert "CORS preflight" in out and "tracker/analytics host" in out and "no response recorded" in out
    assert REC["password"] not in out

    assert cli.main(["inspect", CHROME_HAR, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert (report["flows_total"], report["steps_kept"], report["dropped"]) == (14, 5, 6)
    assert REC["password"] not in json.dumps(report)


# --------------------------------------------------------------------------- Firefox fixture: plan

def test_firefox_plan_shape(firefox):
    recording, plan, source = firefox
    assert len(recording.flows) == 6
    assert [s.func_name for s in plan.steps] == [
        "step_01_get_app_example_test", "step_02_post_auth_login", "step_03_get_v1_orders", "step_04_get_legacy_notice_html",
    ]
    dropped = {d.flow_id: d for d in plan.dropped}
    assert set(dropped) == {"f0002", "f0003"}
    assert dropped["f0002"].url.endswith(".js") and dropped["f0002"].reason.startswith("static asset")
    assert dropped["f0003"].url.endswith(".png") and dropped["f0003"].reason.startswith("static asset")
    assert all(s.loop is None for s in plan.steps)
    assert plan.meta["flows_total"] == 6 and plan.meta["flows_kept"] == 4

    home = plan.steps[0]
    assert home.literal_url() == "https://app.example.test/" and home.response_kind == "html"
    assert home.extractors == []  # the XSRF cookie is read from the jar, not scraped

    login = plan.steps[1]
    assert login.literal_url() == "https://api.example.test/v1/auth/login"
    assert login.body_kind == "json"
    assert login.json_body == {"email": "alice@example.test", "password": Ref.var("PASSWORD"), "remember": True}
    headers = {name.lower(): ref for name, ref in login.headers}
    xsrf = headers["x-xsrf-token"]
    assert xsrf.kind == "expr" and 'session.cookies.get("XSRF-TOKEN")' in xsrf.value and xsrf.value.startswith("unquote(")
    assert "content-type" not in headers
    (access,) = login.extractors
    assert (access.kind, access.path, access.var, access.sample) == ("json", ["access_token"], "access_token", REC["access_token"])
    assert login.response_kind == "json"

    orders = plan.steps[2]
    assert orders.literal_url() == "https://api.example.test/v1/orders"
    assert orders.params == [("status", Ref.lit("open")), ("limit", Ref.lit("20"))]
    assert {n.lower(): r for n, r in orders.headers}["authorization"] == Ref.expr('"Bearer " + access_token')

    notice = plan.steps[3]
    assert notice.literal_url() == "https://app.example.test/legacy/notice.html" and notice.response_kind == "html"

    (password,) = plan.constants
    assert (password.name, password.secret, password.env_var) == ("PASSWORD", True, "REQREC_PASSWORD")
    assert REC["password"] not in source
    assert [(c.name, c.value, c.domain) for c in plan.initial_cookies] == [("lang", "ja", "app.example.test")]
    assert any("INITIAL_COOKIES" in w for w in plan.warnings)
    assert {k.lower(): v for k, v in plan.base_headers} == {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
        "accept-language": "ja,en-US;q=0.7,en;q=0.3",
    }


# --------------------------------------------------------------------------- Firefox fixture: execution

class AppSite:
    """Scripted ``app.example.test`` SPA + ``api.example.test`` with a fresh XSRF cookie and JWT."""

    XSRF_COOKIE = "xsrfNEW%7CZz9Yy8"  # as stored in the cookie (URL-encoded)
    XSRF_HEADER = "xsrfNEW|Zz9Yy8"  # as the SPA sends it (decoded)
    ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiJ9.NEWpayload987654.NEWsignature321"
    PASSWORD = "N3wPassw0rd!"
    NOTICE_TITLE = "お知らせ（新）"

    def __init__(self) -> None:
        self.adapter = MockAdapter([
            Rule("https://app.example.test/", method="GET", handler=self.home),
            Rule("https://api.example.test/v1/auth/login", method="POST", handler=self.login),
            Rule("https://api.example.test/v1/orders", method="GET", handler=self.orders),
            Rule("https://app.example.test/legacy/notice.html", method="GET", handler=self.notice),
        ])

    def home(self, request):
        html = '<!doctype html><html lang="ja"><head><meta charset="UTF-8"><title>Example App</title></head><body><div id="root"></div></body></html>'
        return 200, [("Content-Type", "text/html; charset=utf-8"),
                     ("Set-Cookie", f"XSRF-TOKEN={self.XSRF_COOKIE}; Path=/; SameSite=Lax; Secure")], html

    def login(self, request):
        try:
            body = json.loads(_body_text(request))
        except ValueError:
            return 400, None, {"error": "bad json"}
        if request.headers.get("X-XSRF-TOKEN") != self.XSRF_HEADER:
            return 419, None, {"error": "xsrf mismatch"}
        if body != {"email": "alice@example.test", "password": self.PASSWORD, "remember": True}:
            return 401, None, {"error": "bad credentials"}
        return 200, [("Content-Type", "application/json; charset=utf-8"),
                     ("Set-Cookie", "refresh_token=rtNEW000; Path=/v1/auth; Domain=.example.test; HttpOnly; Secure")], json.dumps(
            {"access_token": self.ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 3600, "user": {"id": 9001}})

    def orders(self, request):
        if request.headers.get("Authorization") != f"Bearer {self.ACCESS_TOKEN}":
            return 401, None, {"error": "unauthorized"}
        if _query(request) != {"status": "open", "limit": "20"}:
            return 400, None, {"error": "bad query"}
        return 200, None, {"data": [{"id": "ord_new1", "status": "open", "total": 100}], "meta": {"count": 1, "limit": 20}}

    def notice(self, request):
        html = (f'<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS">'
                f"<title>{self.NOTICE_TITLE}</title></head><body><h1>メンテナンス</h1></body></html>")
        return 200, [("Content-Type", "text/html; charset=Shift_JIS")], html.encode("cp932")


def test_firefox_script_replays_with_fresh_tokens(firefox):
    _recording, _plan, source = firefox
    site = AppSite()
    out = run_generated(source, site.adapter, env={"REQREC_PASSWORD": AppSite.PASSWORD})
    calls = site.adapter.calls
    assert site.adapter.unmatched == [], [c.url for c in site.adapter.unmatched]
    assert [(c.method, c.url_without_query) for c in calls] == [
        ("GET", "https://app.example.test/"),
        ("POST", "https://api.example.test/v1/auth/login"),
        ("GET", "https://api.example.test/v1/orders"),
        ("GET", "https://app.example.test/legacy/notice.html"),
    ]
    home, login, orders, notice = calls
    assert home.cookies == {"lang": "ja"}  # the pre-existing cookie is replayed from INITIAL_COOKIES
    assert login.header("X-XSRF-TOKEN") == AppSite.XSRF_HEADER  # new cookie value, URL-decoded
    assert login.header("Content-Type") == "application/json"
    assert login.json() == {"email": "alice@example.test", "password": AppSite.PASSWORD, "remember": True}
    assert orders.header("Authorization") == f"Bearer {AppSite.ACCESS_TOKEN}"
    assert orders.query_dict == {"status": "open", "limit": "20"}
    assert notice.cookies == {"XSRF-TOKEN": AppSite.XSRF_COOKIE, "lang": "ja"}
    for call in calls:
        assert call.header("User-Agent").startswith("Mozilla/5.0 (Macintosh"), call.url
    assert AppSite.NOTICE_TITLE in out  # Shift_JIS page decoded and its title printed
    sent = _everything_sent(site.adapter)
    for key in ("access_token", "xsrf_header", "xsrf_cookie", "password"):
        assert REC[key] not in sent, key


def test_firefox_script_fails_loudly_with_wrong_password(firefox):
    _recording, _plan, source = firefox
    site = AppSite()
    with pytest.raises(requests.HTTPError) as info:
        run_generated(source, site.adapter, env={"REQREC_PASSWORD": "wrong"})
    assert info.value.response.status_code == 401
    assert [c.path for c in site.adapter.calls] == ["/", "/v1/auth/login"]


# =========================================================================== phase 2 (DESIGN.md §13)
#
# The IE-mode fixture (``legacy_webforms_ntlm.har``: NTLM handshake, Shift_JIS WebForms page, cp932
# percent-encoded postback), merging several recordings, and the manual overrides - at plan level,
# as generated source, and executed against ``mock_adapter`` sites that hand out fresh tokens.

import sys  # noqa: E402
import types  # noqa: E402
from urllib.parse import unquote_to_bytes  # noqa: E402

from reqrec.importers import load_recordings  # noqa: E402
from reqrec.webapp import TOKEN_HEADER, create_app  # noqa: E402

LEGACY_HAR = os.path.join(ROOT, "tests", "fixtures", "legacy_webforms_ntlm.har")
INTRA = "http://intra.example.local"
KEYWORD_CP932 = "日本".encode("cp932")  # recorded as %93%FA%96%7B
BUTTON_CP932 = "検索".encode("cp932")  # recorded as %8C%9F%8D%F5
JAPANESE_RE = re.compile(r"[぀-ヿ一-鿿]")


@pytest.fixture(scope="module")
def legacy():
    recording = load_recording(LEGACY_HAR)
    plan = build_plan(recording, PlanOptions())
    source = generate(plan, GenOptions())
    compile(source, "legacy_scrape.py", "exec")
    return recording, plan, source


@pytest.fixture(scope="module")
def merged():
    recording = load_recordings([CHROME_HAR, FIREFOX_HAR])
    plan = build_plan(recording, PlanOptions())
    source = generate(plan, GenOptions())
    compile(source, "merged_scrape.py", "exec")
    return recording, plan, source


def _headers(step) -> dict[str, Ref]:
    return {name.lower(): ref for name, ref in step.headers}


def _stub_module(name: str, **attrs) -> types.ModuleType:
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


class _NoAuth:
    """Stand-in for ``requests_negotiate_sspi.HttpNegotiateAuth``: a requests auth that does nothing."""

    def __call__(self, request):
        return request


# --------------------------------------------------------------------------- legacy fixture: plan

def test_legacy_plan_folds_ntlm_handshake_and_keeps_webforms_dependencies(legacy):
    recording, plan, _source = legacy
    assert plan.auth is not None
    assert (plan.auth.kind, plan.auth.hosts, plan.auth.username) == ("ntlm", ["intra.example.local"], "EXAMPLE\\taro")
    assert plan.meta["auth"] == "ntlm" and plan.constants == []
    assert [s.func_name for s in plan.steps] == [
        "step_01_get_default_aspx", "step_02_post_default_aspx", "step_03_get_report_aspx", "step_04_get_export_aspx",
    ]
    assert [s.source_flow_ids for s in plan.steps] == [["f0001", "f0002", "f0003"], ["f0005"], ["f0006"], ["f0007"]]
    assert [s.expected_status for s in plan.steps] == [200, 200, 200, 200]  # the 401 hops are gone
    assert [(d.flow_id, d.reason) for d in plan.dropped] == [("f0004", "static asset (mime application/x-javascript)")]
    for step in plan.steps:
        assert "authorization" not in _headers(step), step.func_name
    for flow in recording.flows[1:3]:  # the Type-1 / Type-3 tokens never reach the plan
        assert flow.request.header("Authorization").split(" ", 1)[1] not in json.dumps(to_plain(plan))

    page, post, report, export = plan.steps
    hidden = {e.name: e for e in page.extractors}
    assert set(hidden) == {"__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"}
    assert all(e.kind == "html_input" for e in hidden.values())
    form = dict(post.form)
    assert form["__VIEWSTATE"] == Ref.var(hidden["__VIEWSTATE"].var)
    assert form["__EVENTVALIDATION"] == Ref.var(hidden["__EVENTVALIDATION"].var)
    # the cp932 body is kept raw with its Content-Type (DESIGN.md §13.4) ...
    assert post.body_kind == "raw" and post.raw_body == recording.flows[4].request.body
    assert b"ctl00%24txtKeyword=%93%FA%96%7B&ctl00%24btnSearch=%8C%9F%8D%F5" in post.raw_body
    assert _headers(post)["content-type"] == Ref.lit("application/x-www-form-urlencoded")
    # ... and the field list carries the legacy values as bytes so codegen can rebuild it
    assert form["ctl00$txtKeyword"] == Ref.expr(repr(KEYWORD_CP932)) and form["ctl00$btnSearch"] == Ref.expr(repr(BUTTON_CP932))
    (warning,) = [w for w in plan.warnings if w.startswith("step 2:")]
    assert "Shift_JIS" in warning and "Content-Type" in warning and "__VIEWSTATE" in warning
    assert "そのまま送信します" not in warning  # the body IS rebuilt from the fields - no contradicting text
    # id traced from the result page's link, export id from the report page
    (link,) = post.extractors
    assert (link.kind, link.selector, link.attr, link.var) == ("html_attr", "a.report-link", "href", "report_id")
    assert re.search(link.pattern, "Report.aspx?id=555").group(1) == "555"
    assert report.params == [("id", Ref.var("report_id"))]
    assert export.params[0] == ("id", Ref.var(report.extractors[0].var)) and export.response_kind == "text"
    assert not any("looks dynamic" in w for w in plan.warnings), plan.warnings


def test_legacy_generated_script_matches_design_13(legacy):
    recording, plan, source = legacy
    # §13.2 session.auth with the sspi -> ntlm fallback and the recorded user as default
    assert "session.auth = HttpNegotiateAuth()" in source
    assert "from requests_negotiate_sspi import HttpNegotiateAuth" in source
    assert "from requests_ntlm import HttpNtlmAuth" in source
    assert 'os.environ.get("REQREC_NTLM_USER", \'EXAMPLE\\\\taro\')' in source
    assert 'os.environ.get("REQREC_NTLM_PASSWORD", "")' in source
    assert "Authorization" not in source and "TlRMTVNTUAA" not in source
    assert "reqrec[sspi]" in source and "reqrec[ntlm]" in source
    # §13.3 verification knob is always there
    assert "VERIFY_TLS = True  # 自己署名証明書のサイトなら False か CA 証明書 (.pem) のパスに" in source
    assert "session.verify = VERIFY_TLS" in source
    assert "_LegacyTLSAdapter" not in source  # only with legacy_tls
    # §13.4 bytes-based soup, _text(resp) for the text result, cp932 form rebuilt field by field
    assert "BeautifulSoup(resp.content, 'html.parser'" in source
    assert "def _text(resp):" in source and "print(_text(final_resp)[:2000])" in source
    assert "from urllib.parse import unquote, urlencode, urljoin" in source
    assert "data=urlencode({" in source
    assert "'ctl00$txtKeyword': b'\\x93\\xfa\\x96{',  # cp932 で「日本」（記録時の表記: %93%FA%96%7B）" in source
    assert "'ctl00$btnSearch': b'\\x8c\\x9f\\x8d\\xf5',  # cp932 で「検索」（記録時の表記: %8C%9F%8D%F5）" in source
    assert "'__VIEWSTATE': viewstate," in source and "'Content-Type': 'application/x-www-form-urlencoded'" in source
    assert "_attr(soup, 'input[name=\"__VIEWSTATE\"]', 'value')" in source
    # Japanese comments / docstring, English identifiers
    comments = [ln for ln in source.splitlines() if ln.lstrip().startswith("#")]
    assert sum(1 for c in comments if JAPANESE_RE.search(c)) >= 10
    assert "認証: 統合 Windows 認証（NTLM）" in source and "記録時のユーザー: EXAMPLE\\\\taro" in source
    assert recording.flows[2].response.text().count("売上レポート") >= 1  # the Shift_JIS page decodes for the plan


def test_legacy_script_with_legacy_tls_mounts_the_adapter(legacy):
    recording, _plan, _source = legacy
    plan = build_plan(recording, PlanOptions())
    source = generate(plan, GenOptions(legacy_tls=True))
    compile(source, "legacy_tls.py", "exec")
    assert "class _LegacyTLSAdapter(requests.adapters.HTTPAdapter):" in source
    assert 'session.mount("https://", _LegacyTLSAdapter())' in source
    assert "ctx.minimum_version = ssl.TLSVersion.TLSv1" in source
    assert 'ctx.set_ciphers("DEFAULT:@SECLEVEL=1")' in source
    assert 'getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)' in source
    assert "import ssl" in source and "IE モード" in source
    assert "session.verify = VERIFY_TLS" in source


# --------------------------------------------------------------------------- legacy fixture: execution

class IntranetSite:
    """``intra.example.local`` that issues NEW WebForms tokens and a new report id; never challenges
    with 401 (``session.auth`` is a no-op here), so what is checked is that the postback carries the
    fresh ``__VIEWSTATE`` / ``__EVENTVALIDATION`` and the cp932 keyword bytes unchanged."""

    VIEWSTATE = "/wEPDwUKNEWSTATE" + "Qq9XwZ1" * 30 + "=="
    EVENTVALIDATION = "/wEdAANEWVALID" + "kL0pZ" * 8 + "=="
    REPORT_ID = "9087"

    def __init__(self) -> None:
        self.adapter = MockAdapter([
            Rule(f"{INTRA}/Default.aspx", method="GET", handler=self.page),
            Rule(f"{INTRA}/Default.aspx", method="POST", handler=self.postback),
            Rule(f"{INTRA}/Report.aspx", method="GET", handler=self.report),
            Rule(f"{INTRA}/Export.aspx", method="GET", handler=self.export),
        ])

    @staticmethod
    def _sjis(body: str):
        html = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS" />'
                f"<title>売上レポート検索</title></head><body>{body}</body></html>")
        return 200, [("Content-Type", "text/html")], html.encode("cp932")  # no charset on the wire

    def page(self, request):
        return self._sjis(
            '<form method="post" action="./Default.aspx" id="form1">'
            f'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="{self.VIEWSTATE}" />'
            '<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="CA0B0334" />'
            f'<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="{self.EVENTVALIDATION}" />'
            '<input name="ctl00$txtKeyword" type="text" /><input type="submit" name="ctl00$btnSearch" value="検索" /></form>'
        )

    def postback(self, request):
        body = request.body if isinstance(request.body, bytes) else str(request.body or "").encode("latin-1")
        pairs = {}
        for segment in body.split(b"&"):
            name, _, value = segment.partition(b"=")
            pairs[unquote_to_bytes(name.replace(b"+", b" "))] = unquote_to_bytes(value.replace(b"+", b" "))
        ok = (pairs.get(b"__VIEWSTATE") == self.VIEWSTATE.encode()
              and pairs.get(b"__EVENTVALIDATION") == self.EVENTVALIDATION.encode()
              and pairs.get(b"ctl00$txtKeyword") == KEYWORD_CP932 and pairs.get(b"ctl00$btnSearch") == BUTTON_CP932
              and (request.headers.get("Content-Type") or "").startswith("application/x-www-form-urlencoded"))
        if not ok:
            return 500, [("Content-Type", "text/html")], "<html>Invalid viewstate or form</html>".encode("cp932")
        return self._sjis(f'<table id="ctl00_gvResults"><tr><td><a class="report-link" href="Report.aspx?id={self.REPORT_ID}">日本支社</a></td></tr></table>')

    def report(self, request):
        if dict(parse_qsl(urlsplit(request.url).query)).get("id") != self.REPORT_ID:
            return 404, [("Content-Type", "text/html")], b"<html>no such report</html>"
        return self._sjis(f'<a class="csv-link" href="Export.aspx?id={self.REPORT_ID}&amp;fmt=csv">CSV</a>')

    def export(self, request):
        query = dict(parse_qsl(urlsplit(request.url).query))
        if query.get("id") != self.REPORT_ID or query.get("fmt") != "csv":
            return 404, [("Content-Type", "text/plain")], b"bad export"
        return 200, [("Content-Type", "text/csv")], "商品,数量\r\n業務用プリンター,18\r\n".encode("cp932")


def _assert_legacy_replay(site: IntranetSite, out: str) -> None:
    calls = site.adapter.calls
    assert site.adapter.unmatched == [], [c.url for c in site.adapter.unmatched]
    assert [(c.method, c.path) for c in calls] == [
        ("GET", "/Default.aspx"), ("POST", "/Default.aspx"), ("GET", "/Report.aspx"), ("GET", "/Export.aspx"),
    ]
    post = calls[1]
    assert post.header("Content-Type") == "application/x-www-form-urlencoded"
    # the cp932 bytes went out exactly as recorded, the hidden fields are the live ones
    assert b"ctl00%24txtKeyword=%93%FA%96%7B&ctl00%24btnSearch=%8C%9F%8D%F5" in post.body
    assert unquote_to_bytes(post.body).count(IntranetSite.VIEWSTATE.encode()) == 1
    assert IntranetSite.EVENTVALIDATION.encode() in unquote_to_bytes(post.body)
    assert b"__VIEWSTATEGENERATOR=CA0B0334" in post.body and post.body.startswith(b"__EVENTTARGET=&__EVENTARGUMENT=&")
    assert calls[2].query_dict == {"id": IntranetSite.REPORT_ID}
    assert calls[3].query_dict == {"id": IntranetSite.REPORT_ID, "fmt": "csv"}
    for call in calls:
        assert call.header("Authorization") is None, call.url
        assert call.header("User-Agent") == "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
        assert call.header("Accept-Language") == "ja-JP"
    assert "業務用プリンター,18" in out  # text/csv without charset, decoded through _text(resp)


def test_legacy_script_replays_with_fresh_viewstate(legacy, monkeypatch):
    """Mounted without any NTLM library: ``requests_negotiate_sspi`` is a no-op stub."""
    recording, _plan, source = legacy
    monkeypatch.setitem(sys.modules, "requests_negotiate_sspi", _stub_module("requests_negotiate_sspi", HttpNegotiateAuth=_NoAuth))
    site = IntranetSite()
    out = run_generated(source, site.adapter, env={})
    _assert_legacy_replay(site, out)
    recorded_viewstate = dict(re.findall(r'name="(__\w+)" id="__\w+" value="([^"]*)"', recording.flows[2].response.text()))["__VIEWSTATE"]
    assert recorded_viewstate.encode() not in unquote_to_bytes(site.adapter.calls[1].body)


def test_legacy_script_legacy_tls_variant_replays(legacy, monkeypatch):
    recording, _plan, _source = legacy
    source = generate(build_plan(recording, PlanOptions()), GenOptions(legacy_tls=True, comments=False, strict_status=True))
    monkeypatch.setitem(sys.modules, "requests_negotiate_sspi", _stub_module("requests_negotiate_sspi", HttpNegotiateAuth=_NoAuth))
    site = IntranetSite()
    out = run_generated(source, site.adapter, env={})  # http:// URLs: the https adapter is mounted but unused
    _assert_legacy_replay(site, out)


def test_legacy_script_falls_back_to_requests_ntlm_with_env_credentials(legacy, monkeypatch):
    recording, _plan, source = legacy
    created: list[tuple] = []

    class HttpNtlmAuth(_NoAuth):
        def __init__(self, username, password):
            created.append((username, password))

    monkeypatch.setitem(sys.modules, "requests_negotiate_sspi", None)  # -> ImportError
    monkeypatch.setitem(sys.modules, "requests_ntlm", _stub_module("requests_ntlm", HttpNtlmAuth=HttpNtlmAuth))
    site = IntranetSite()
    run_generated(source, site.adapter, env={})
    assert created == [("EXAMPLE\\taro", "")]  # recorded DOMAIN\\user is the default
    created.clear()
    site = IntranetSite()
    run_generated(source, site.adapter, env={"REQREC_NTLM_USER": "CORP\\hanako", "REQREC_NTLM_PASSWORD": "p@ss"})
    assert created == [("CORP\\hanako", "p@ss")]
    _assert_legacy_replay(site, "業務用プリンター,18")


def test_legacy_script_without_any_ntlm_package_stops_with_japanese_hint(legacy, monkeypatch):
    _recording, _plan, source = legacy
    monkeypatch.setitem(sys.modules, "requests_negotiate_sspi", None)
    monkeypatch.setitem(sys.modules, "requests_ntlm", None)
    site = IntranetSite()
    with pytest.raises(SystemExit) as info:
        run_generated(source, site.adapter, env={})
    message = str(info.value.code)
    assert 'pip install "reqrec[sspi]"' in message and 'pip install "reqrec[ntlm]"' in message
    assert "REQREC_NTLM_USER" in message and "REQREC_NTLM_PASSWORD" in message
    assert site.adapter.calls == []  # nothing was sent


def test_legacy_cli_generate_with_legacy_tls_replays(tmp_path, capsys, monkeypatch):
    target = tmp_path / "legacy.py"
    assert cli.main(["generate", LEGACY_HAR, "-o", str(target), "--legacy-tls"]) == 0
    err = capsys.readouterr().err
    assert "認証: NTLM (記録時のユーザー: EXAMPLE\\taro)" in err and "session.auth" in err
    source = target.read_text(encoding="utf-8")
    assert "_LegacyTLSAdapter" in source and "TlRMTVNTUAA" not in source
    monkeypatch.setitem(sys.modules, "requests_negotiate_sspi", _stub_module("requests_negotiate_sspi", HttpNegotiateAuth=_NoAuth))
    site = IntranetSite()
    _assert_legacy_replay(site, run_generated(source, site.adapter, env={}))

    assert cli.main(["inspect", LEGACY_HAR]) == 0
    out = capsys.readouterr().out
    assert "認証: NTLM (記録時のユーザー: EXAMPLE\\taro) → 生成コードは session.auth を設定します" in out
    assert "f0001+f0002+f0003  GET     401→401→200" in out  # the handshake is one step with its three flows
    assert "f0004  http://intra.example.local/WebResource.axd" in out
    assert "viewstate←html_input[__VIEWSTATE]" in out and "report_id←html_attr[a.report-link@href]" in out


def test_legacy_fixture_through_the_gui_api_offers_ntlm_env_vars(tmp_path):
    """The no-code path: upload -> plan -> generate; the 実行 panel needs REQREC_NTLM_USER / _PASSWORD."""
    app = create_app(str(tmp_path / "work"), token="t", TESTING=True)
    client = app.test_client()
    H = {TOKEN_HEADER: "t"}
    with open(LEGACY_HAR, "rb") as fh:
        r = client.post("/api/recordings/upload", data={"files": (fh, "legacy_webforms_ntlm.har")}, headers=H,
                        content_type="multipart/form-data")
    assert r.status_code == 200 and r.get_json()["flows"] == 7
    plan = client.post("/api/plan", json={}, headers=H).get_json()
    assert plan["auth"]["kind"] == "ntlm" and plan["auth"]["username"] == "EXAMPLE\\taro"
    rows = {f["id"]: f for f in plan["flows"]}
    assert rows["f0001"]["kept"] and rows["f0002"]["kept"] and rows["f0001"]["step_index"] == rows["f0003"]["step_index"] == 1
    assert rows["f0004"]["kept"] is False and rows["f0004"]["reason"].startswith("static asset")
    assert plan["steps"][0]["flow_ids"] == "f0001+f0002+f0003" and plan["steps"][0]["status_chain"] == [401, 401, 200]
    gen = client.post("/api/generate", json={}, headers=H).get_json()
    compile(gen["code"], "gui_legacy.py", "exec")
    assert "Authorization" not in gen["code"]
    assert [s["env_var"] for s in gen["secrets"]] == ["REQREC_NTLM_USER", "REQREC_NTLM_PASSWORD"]
    user, password = gen["secrets"]
    assert user["secret"] is False and user["default"] == "EXAMPLE\\taro"
    assert password["secret"] is True and "reqrec[ntlm]" in password["comment"]
    assert gen["env_vars"] == ["REQREC_NTLM_USER", "REQREC_NTLM_PASSWORD"]
    assert client.get("/api/state").get_json()["secrets"] == gen["secrets"]
    app.extensions["reqrec"].close()


# --------------------------------------------------------------------------- merge (DESIGN.md §13.5)

def test_merge_orders_flows_by_time_and_renumbers(merged):
    recording, plan, _source = merged
    assert len(recording.flows) == 20
    assert [f.id for f in recording.flows] == [f"f{i:04d}" for i in range(1, 21)]
    stamps = [f.started_at for f in recording.flows]
    assert stamps == sorted(stamps)
    assert recording.meta["source"] == "merged"
    assert [m["file"] for m in recording.meta["sources"]] == [CHROME_HAR, FIREFOX_HAR]
    assert [m["creator"] for m in recording.meta["sources"]] == ["WebInspector/537.36", "Firefox/125.0.1"]
    # one file -> exactly what load_recording gives
    alone = load_recordings([CHROME_HAR])
    reference = load_recording(CHROME_HAR)
    assert alone.meta == reference.meta and [f.id for f in alone.flows] == [f.id for f in reference.flows]
    assert alone.to_dict()["flows"] == reference.to_dict()["flows"]
    # the Chrome tab (14 flows) comes first, then the Firefox tab (6 flows)
    assert [f.request.host for f in recording.flows[:14]] != [f.request.host for f in recording.flows[14:]]
    assert {f.request.host for f in recording.flows[14:]} <= {"app.example.test", "api.example.test"}
    assert [s.func_name for s in plan.steps] == [
        "step_01_get_login", "step_02_post_login", "step_03_get_v1_me", "step_04_get_orgs_items", "step_05_get_export",
        "step_06_get_app_example_test", "step_07_post_auth_login", "step_08_get_v1_orders", "step_09_get_legacy_notice_html",
    ]
    assert [s.source_flow_ids for s in plan.steps] == [
        ["f0001"], ["f0008", "f0009"], ["f0010"], ["f0011", "f0012", "f0013"], ["f0014"], ["f0015"], ["f0018"], ["f0019"], ["f0020"],
    ]
    assert len(plan.dropped) == 8 and plan.meta["flows_total"] == 20 and plan.meta["flows_kept"] == 12
    assert plan.meta["source"]["source"] == "merged"
    # cross-tab dependency: the second tab's login email is traced to the first tab's /v1/me JSON
    login = plan.steps[6]
    assert login.json_body["email"] == Ref.var("email") and login.json_body["password"] == Ref.var("PASSWORD")
    assert any(e.var == "email" and e.kind == "json" and e.path == ["email"] for e in plan.steps[2].extractors)
    (password,) = plan.constants
    assert (password.name, password.env_var) == ("PASSWORD", "REQREC_PASSWORD")
    assert [(c.name, c.domain) for c in plan.initial_cookies] == [("lang", "app.example.test")]


class MergedSite:
    """Both tabs' fake sites behind one adapter; ``/v1/me`` additionally reveals the e-mail the
    second tab's login form sends (the merged plan traced it there)."""

    def __init__(self) -> None:
        self.shop = ShopSite()
        self.app = AppSite()
        rules = []
        for rule in self.shop.adapter.rules:
            if rule.url == "https://api.example.test/v1/me":
                rules.append(Rule(rule.url, method="GET", handler=self.me))
            else:
                rules.append(rule)
        rules.extend(r for r in self.app.adapter.rules if r.url != "https://app.example.test/")
        rules.append(Rule("https://app.example.test/", method="GET", handler=self.app.home))
        self.adapter = MockAdapter(rules)

    def me(self, request):
        status, headers, body = self.shop.me(request)
        if status == 200:
            body = {**body, "email": "alice@example.test"}
        return status, headers, body


def test_merged_script_replays_both_tabs_with_fresh_tokens(merged):
    _recording, _plan, source = merged
    site = MergedSite()
    out = run_generated(source, site.adapter, env={"REQREC_PASSWORD": ShopSite.PASSWORD})
    calls = site.adapter.calls
    assert site.adapter.unmatched == [], [c.url for c in site.adapter.unmatched]
    items = f"https://api.example.test/v1/orgs/{ShopSite.ORG_ID}/items"
    assert [(c.method, c.url_without_query) for c in calls] == [
        ("GET", "https://shop.example.test/login"), ("POST", "https://shop.example.test/login"),
        ("GET", "https://shop.example.test/dashboard"), ("GET", "https://api.example.test/v1/me"),
        ("GET", items), ("GET", items), ("GET", items), ("GET", "https://shop.example.test/export"),
        ("GET", "https://app.example.test/"), ("POST", "https://api.example.test/v1/auth/login"),
        ("GET", "https://api.example.test/v1/orders"), ("GET", "https://app.example.test/legacy/notice.html"),
    ]
    assert calls[1].form["_token"] == ShopSite.LOGIN_TOKEN and calls[7].query_dict == {"sig": ShopSite.SIG}
    assert calls[9].json() == {"email": "alice@example.test", "password": ShopSite.PASSWORD, "remember": True}
    assert calls[9].header("X-XSRF-TOKEN") == AppSite.XSRF_HEADER
    assert calls[10].header("Authorization") == f"Bearer {AppSite.ACCESS_TOKEN}"
    assert AppSite.NOTICE_TITLE in out  # the last step of the second tab is the printed result
    sent = _everything_sent(site.adapter)
    for key in ("login_token", "csrf", "api_token", "sig", "password", "access_token", "xsrf_header"):
        assert REC[key] not in sent, key


def test_merge_through_the_cli(tmp_path, capsys):
    target = tmp_path / "merged.py"
    assert cli.main(["generate", CHROME_HAR, FIREFOX_HAR, "-o", str(target)]) == 0
    err = capsys.readouterr().err
    assert "ステップ 9 件を生成します（フロー合計 20 件" in err
    compile(target.read_text(encoding="utf-8"), str(target), "exec")
    assert cli.main(["inspect", CHROME_HAR, FIREFOX_HAR]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"入力: {CHROME_HAR}, {FIREFOX_HAR}  (結合 2 件: har, WebInspector/537.36 / har, Firefox/125.0.1)")
    assert "フロー合計 20 件 / 採用 12 件 → ステップ 9 件 / 除外 8 件" in out
    assert "06  f0015" in out and "09  f0020" in out
    assert cli.main(["inspect", CHROME_HAR, FIREFOX_HAR, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["inputs"] == [CHROME_HAR, FIREFOX_HAR] and report["flows_total"] == 20
    assert report["source"].startswith("結合 2 件")
    # the same file twice is loaded once
    assert cli.main(["inspect", CHROME_HAR, CHROME_HAR, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["flows_total"] == 14
    out_json = tmp_path / "merged.json"
    assert cli.main(["import", CHROME_HAR, FIREFOX_HAR, "-o", str(out_json)]) == 0
    assert "2 ファイルを結合して 20 件のフローを取り込みました" in capsys.readouterr().out
    assert len(load_recording(str(out_json)).flows) == 20


# --------------------------------------------------------------------------- manual overrides (DESIGN.md §13.1)

def test_override_exclude_include_and_final_at_plan_level(chrome):
    recording, _plan, _source = chrome
    excluded = build_plan(recording, PlanOptions(exclude_flow_ids=["f0010"]))
    assert [s.func_name for s in excluded.steps] == ["step_01_get_login", "step_02_post_login", "step_03_get_orgs_items", "step_04_get_export"]
    assert {d.flow_id: d.reason for d in excluded.dropped}["f0010"] == "excluded by user"
    org = next(e for s in excluded.steps for e in s.extractors if e.var == "org_id")
    assert (org.kind, org.selector, org.attr) == ("html_attr", "#app", "data-org-id")  # re-traced to the dashboard
    included = build_plan(recording, PlanOptions(include_flow_ids=["f0002"]))
    assert included.steps[1].func_name == "step_02_get_static_app_css" and included.steps[1].source_flow_ids == ["f0002"]
    assert len(included.steps) == 6 and not any(d.flow_id == "f0002" for d in included.dropped)
    still_dropped = build_plan(recording, PlanOptions(include_flow_ids=["f0006"]))  # no response recorded
    assert {d.flow_id: d.reason for d in still_dropped.dropped}["f0006"] == "no response recorded"
    both = build_plan(recording, PlanOptions(include_flow_ids=["f0010"], exclude_flow_ids=["f0010"]))
    assert {d.flow_id: d.reason for d in both.dropped}["f0010"] == "excluded by user"  # exclude wins
    final = build_plan(recording, PlanOptions(final_flow_id="f0009"))  # the redirect target names step 2
    assert final.final_step_index == 2
    assert build_plan(recording, PlanOptions(final_flow_id="8")).final_step_index == 2  # "8" == f0008
    dropped_final = build_plan(recording, PlanOptions(final_flow_id="f0002"))
    assert dropped_final.final_step_index is None
    assert any("f0002" in w and "除外" in w for w in dropped_final.warnings)


def test_override_final_step_changes_only_the_printed_result(chrome):
    recording, _plan, _source = chrome
    plan = build_plan(recording, PlanOptions(final_flow_id="f0009"))
    source = generate(plan, GenOptions())
    compile(source, "final.py", "exec")
    assert "結果として表示するステップ: 2（POST https://shop.example.test/login）" in source
    assert "# ===== 結果を表示（ステップ 2: POST https://shop.example.test/login） =====" in source
    assert source.count("final_resp = resp") == 1
    assert source.index("resp, out = step_02_post_login(") < source.index("final_resp = resp") < source.index("resp, out = step_03_get_v1_me(")
    assert "soup = _soup(final_resp)" in source
    site = ShopSite()
    out = run_generated(source, site.adapter, env={"REQREC_PASSWORD": ShopSite.PASSWORD})
    _assert_chrome_replay(site, out.replace("ダッシュボード", "id,name new-foo new-bar"))  # all 8 calls still happen
    assert out.strip() == "ダッシュボード"  # ... but the dashboard title is what gets printed


def test_override_exclude_step_via_cli_replays_without_the_export(tmp_path, capsys):
    target = tmp_path / "no_export.py"
    dump = tmp_path / "plan.json"
    assert cli.main(["generate", CHROME_HAR, "-o", str(target), "--exclude-step", "5", "--final-step", "3", "--dump-plan", str(dump)]) == 0
    err = capsys.readouterr().err
    assert "ステップ 4 件を生成します" in err and "結果にするステップ: 3（GET https://api.example.test/v1/me）" in err
    plan_json = json.loads(dump.read_text(encoding="utf-8"))
    assert plan_json["final_step_index"] == 3
    assert {d["flow_id"]: d["reason"] for d in plan_json["dropped"]}["f0014"] == "excluded by user"
    source = target.read_text(encoding="utf-8")
    assert "step_05_get_export" not in source and "'sig'" not in source  # nothing extracts the unused signature
    site = ShopSite()
    out = run_generated(source, site.adapter, env={"REQREC_PASSWORD": ShopSite.PASSWORD})
    assert [(c.method, c.path) for c in site.adapter.calls] == [
        ("GET", "/login"), ("POST", "/login"), ("GET", "/dashboard"), ("GET", "/v1/me"),
        ("GET", f"/v1/orgs/{ShopSite.ORG_ID}/items"), ("GET", f"/v1/orgs/{ShopSite.ORG_ID}/items"), ("GET", f"/v1/orgs/{ShopSite.ORG_ID}/items"),
    ]
    printed = json.loads(out)
    assert printed["org"] == {"id": ShopSite.ORG_ID, "name": "New Org"}  # /v1/me JSON is the printed result


def test_override_cli_inspect_shows_ids_and_validates_arguments(capsys):
    assert cli.main(["inspect", CHROME_HAR, "--exclude-flow", "f0010", "--final-flow", "9"]) == 0
    out = capsys.readouterr().out
    assert "結果にするステップ: 2 (POST https://shop.example.test/login)" in out
    assert "★ 結果として表示" in out and "excluded by user — 1 件" in out and "f0010  https://api.example.test/v1/me" in out
    assert "01  f0001" in out and "02  f0008+f0009" in out and "f0011+f0012+f0013" in out
    assert "（FLOW はフロー ID。--exclude-flow / --include-flow / --final-flow で指定できます）" in out
    for argv, fragment in (
        (["inspect", CHROME_HAR, "--exclude-step", "9"], "--exclude-step 9: ステップ番号は 1〜5 の範囲"),
        (["inspect", CHROME_HAR, "--exclude-flow", "f0099"], "--exclude-flow f0099: 記録にそのフロー ID はありません"),
        (["inspect", CHROME_HAR, "--exclude-flow", "f0010", "--include-flow", "f0010"], "両方に指定"),
        (["inspect", CHROME_HAR, "--exclude-step", "5", "--final-step", "5"], "除外の対象になっています"),
        (["inspect", CHROME_HAR, "--final-step", "2", "--final-flow", "f0010"], "別のステップを指しています"),
    ):
        assert cli.main(argv) == 1, argv
        assert fragment in capsys.readouterr().err, argv
    assert cli.main(["inspect", CHROME_HAR, "--exclude-flow", "f00/08"]) == 2  # malformed id -> usage error
    assert "フロー ID" in capsys.readouterr().err
    assert cli.main(["inspect", CHROME_HAR, "--exclude-flow", "f0010, f0014", "--json"]) == 0  # comma list, two ids
    report = json.loads(capsys.readouterr().out)
    assert {d["flow_id"] for d in report["dropped_flows"] if d["reason"] == "excluded by user"} == {"f0010", "f0014"}
    assert cli.main(["inspect", CHROME_HAR, "--final-flow", "f0002", "--json"]) == 0  # dropped -> warning, not an error
    report = json.loads(capsys.readouterr().out)
    assert report["final_step_index"] is None and any("f0002" in w for w in report["warnings"])
