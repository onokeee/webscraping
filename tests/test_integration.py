"""Integration and end-to-end tests: the real pipeline (import -> plan -> generate -> run) on the
bundled fixtures, against ``tests/support.py``'s mock transport and live local site.

One section per former test module (headed ``# ===== former tests/<name>.py ... =====``).  The
``legacy`` fixture of the former ``test_integration_legacy.py`` is ``legacy_plan`` here (the
integration section has its own ``legacy`` fixture); ``REPLAY_ROOT`` is the factory-replay
section's ``pathlib`` root.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qsl, unquote_to_bytes, urlsplit

import pytest
import requests

import reqrec as cli
from reqrec import build_plan
from reqrec import generate
from reqrec import GenOptions, Plan, PlanOptions, Recording, Ref, to_plain
from reqrec import load_recording
from tests import support as site_server
from tests.support import (
    BROWSER_HEADERS, LAST_PAGE, MockAdapter, PASSWORD, Rule, Site, SiteServer, TOKEN_KINDS, USERNAME,
    capture, default_scenario, flow_from_response, make_session, restart_server, run_generated, start_server,
    stop_server,
)


# ===== former tests/test_integration.py: the real pipeline on the bundled HAR fixtures =====
# Integration tests: the real pipeline on the bundled HAR fixtures.
#
# ``load_recording`` -> ``build_plan`` -> ``generate`` for ``tests/fixtures/login_flow_chrome.har``
# and ``tests/fixtures/api_firefox.har``.  The plan-level assertions pin down the analysis DESIGN.md
# promises (noise filtering with reasons, redirect collapsing, dependency tracing, loop folding,
# secret redaction).  The execution tests run the generated scripts in-process against
# ``tests.support``, where the fake ``shop.example.test`` / ``api.example.test`` /
# ``app.example.test`` hand out tokens that DIFFER from the recording and reject the recorded ones -
# so the scripts can only succeed by re-deriving every dynamic value from the live responses.

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
    plan = build_plan(recording, PlanOptions(redact_secrets=True))
    source = generate(plan, GenOptions())
    compile(source, "chrome_scrape.py", "exec")
    return recording, plan, source


@pytest.fixture(scope="module")
def firefox():
    recording = load_recording(FIREFOX_HAR)
    plan = build_plan(recording, PlanOptions(redact_secrets=True))
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
    plan = build_plan(recording, PlanOptions(redact_secrets=True))
    source = generate(plan, GenOptions(comments=False, strict_status=True, delay=0.5, timeout=5))
    compile(source, "variant.py", "exec")
    assert "time.sleep(DELAY)" in source and "DELAY = 0.5" in source
    site = ShopSite()
    out = run_generated(source, site.adapter, env={"REQREC_PASSWORD": ShopSite.PASSWORD})
    _assert_chrome_replay(site, out)


def test_chrome_script_from_cli_replays(tmp_path, capsys):
    out_file = tmp_path / "scrape.py"
    dump = tmp_path / "plan.json"
    assert cli.main(["generate", CHROME_HAR, "-o", str(out_file), "--dump-plan", str(dump), "--redact"]) == 0
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


def test_chrome_script_without_env_var_stops_before_sending(chrome, monkeypatch):
    """Redacted secret + no environment variable -> the script stops at once, naming the variable;
    an empty password is never sent."""
    _recording, _plan, source = chrome
    monkeypatch.delenv("REQREC_PASSWORD", raising=False)
    site = ShopSite()
    with pytest.raises(SystemExit) as info:
        run_generated(source, site.adapter, env={})
    assert "REQREC_PASSWORD" in str(info.value.code) and "設定されていません" in str(info.value.code)
    assert site.adapter.calls == []


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

import types  # noqa: E402

from reqrec import load_recordings  # noqa: E402
from reqrec import TOKEN_HEADER, create_app  # noqa: E402

LEGACY_HAR = os.path.join(ROOT, "tests", "fixtures", "legacy_webforms_ntlm.har")
INTRA = "http://intra.example.local"
KEYWORD_CP932 = "日本".encode("cp932")  # recorded as %93%FA%96%7B
BUTTON_CP932 = "検索".encode("cp932")  # recorded as %8C%9F%8D%F5
JAPANESE_RE = re.compile(r"[぀-ヿ一-鿿]")


@pytest.fixture(scope="module")
def legacy():
    recording = load_recording(LEGACY_HAR)
    plan = build_plan(recording, PlanOptions(redact_secrets=True))
    source = generate(plan, GenOptions())
    compile(source, "legacy_scrape.py", "exec")
    return recording, plan, source


@pytest.fixture(scope="module")
def merged():
    recording = load_recordings([CHROME_HAR, FIREFOX_HAR])
    plan = build_plan(recording, PlanOptions(redact_secrets=True))
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
    # §13.3 is gone: http:// sites only, so no TLS settings at all
    for removed in ("VERIFY_TLS", "session.verify", "_LegacyTLSAdapter", "session.mount(", "import ssl"):
        assert removed not in source, removed
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


def test_legacy_script_strict_variant_replays(legacy, monkeypatch):
    recording, _plan, _source = legacy
    source = generate(build_plan(recording, PlanOptions(redact_secrets=True)), GenOptions(comments=False, strict_status=True))
    monkeypatch.setitem(sys.modules, "requests_negotiate_sspi", _stub_module("requests_negotiate_sspi", HttpNegotiateAuth=_NoAuth))
    site = IntranetSite()
    out = run_generated(source, site.adapter, env={})
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


def test_legacy_cli_generate_replays(tmp_path, capsys, monkeypatch):
    target = tmp_path / "legacy.py"
    assert cli.main(["generate", LEGACY_HAR, "-o", str(target)]) == 0
    err = capsys.readouterr().err
    assert "認証: NTLM (記録時のユーザー: EXAMPLE\\taro)" in err and "session.auth" in err
    source = target.read_text(encoding="utf-8")
    assert "session.auth = HttpNegotiateAuth()" in source and "TlRMTVNTUAA" not in source
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
    """The no-code path: upload -> plan -> build; 試しに実行 asks for REQREC_NTLM_USER / _PASSWORD."""
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
    gen = client.post("/api/easy/build", json={}, headers=H).get_json()
    compile(gen["code"], "gui_legacy.py", "exec")
    assert "Authorization" not in gen["code"]
    assert [s["env_var"] for s in gen["secrets"]] == ["REQREC_NTLM_USER", "REQREC_NTLM_PASSWORD"]
    user, password = gen["secrets"]
    assert user["secret"] is False and user["default"] == "EXAMPLE\\taro"
    assert password["secret"] is True and "reqrec[ntlm]" in password["comment"]
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


def test_override_final_step_changes_only_the_printed_result(chrome, tmp_path, monkeypatch):
    recording, _plan, _source = chrome
    plan = build_plan(recording, PlanOptions(final_flow_id="f0009", redact_secrets=True))
    source = generate(plan, GenOptions())
    compile(source, "final.py", "exec")
    assert "結果として表示するステップ: 2（POST https://shop.example.test/login）" in source
    assert "# ===== 結果を表示（ステップ 2: POST https://shop.example.test/login） =====" in source
    assert source.count("final_resp = resp") == 1
    assert source.index("resp, out = step_02_post_login(") < source.index("final_resp = resp") < source.index("resp, out = step_03_get_v1_me(")
    assert "soup = _soup(final_resp)" in source
    site = ShopSite()
    monkeypatch.chdir(tmp_path)
    out = run_generated(source, site.adapter, env={"REQREC_PASSWORD": ShopSite.PASSWORD, "REQREC_OUTPUT_DIR": str(tmp_path / "out")})
    _assert_chrome_replay(site, out.replace("ダッシュボード", "id,name new-foo new-bar"))  # all 8 calls still happen
    assert out.strip().splitlines()[-1] == "ダッシュボード"  # ... but the dashboard title is what gets printed
    # the CSV export in the middle (Content-Disposition: attachment) is still kept as a file
    assert "export.csv に保存しました" in out and (tmp_path / "out" / "export.csv").is_file()


def test_override_exclude_step_via_cli_replays_without_the_export(tmp_path, capsys):
    target = tmp_path / "no_export.py"
    dump = tmp_path / "plan.json"
    assert cli.main(["generate", CHROME_HAR, "-o", str(target), "--exclude-step", "5", "--final-step", "3", "--dump-plan", str(dump),
                     "--redact"]) == 0
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


# ===== former tests/test_integration_legacy.py: the IE-mode legacy fixture (NTLM, Shift_JIS, WebForms) =====
# Integration test for the IE-mode / WebForms fixture (DESIGN.md §13.8).
#
# ``tests/fixtures/legacy_webforms_ntlm.har`` is an IE11 F12 style export of an intranet ASP.NET
# site: an NTLM 3-leg handshake, Shift_JIS pages served as ``text/html`` without charset, a postback
# whose form body is percent-encoded cp932, a results page linking to ``Report.aspx?id=1234``, the
# report page with a CSV export link, the export itself, and a ``WebResource.axd`` script.
#
# ``load_recording`` -> ``build_plan`` -> ``generate`` -> replay against the mock adapter (the code
# generator rebuilds the legacy form body from ``Step.form`` so fresh ``__VIEWSTATE`` values are sent).

HOST = "http://intra.example.local"


@pytest.fixture(scope="module")
def legacy_plan():
    recording = load_recording(LEGACY_HAR)
    plan = build_plan(recording, PlanOptions(redact_secrets=True))
    return recording, plan


def hidden_inputs(html: str) -> dict[str, str]:
    return dict(re.findall(r'<input type="hidden" name="(__\w+)" id="__\w+" value="([^"]*)"', html))


def step_headers(step) -> dict[str, Ref]:
    return {name.lower(): ref for name, ref in step.headers}


# --------------------------------------------------------------------------- import

def test_fixture_imports_as_an_ie_har(legacy_plan):
    recording, _plan = legacy_plan
    assert recording.meta["creator"].startswith("F12 Developer Tools")
    assert recording.meta["browser"].startswith("Internet Explorer")
    assert [f.id for f in recording.flows] == [f"f{i:04d}" for i in range(1, 8)]
    assert [(f.request.method, f.request.path, f.response.status) for f in recording.flows] == [
        ("GET", "/Default.aspx", 401), ("GET", "/Default.aspx", 401), ("GET", "/Default.aspx", 200),
        ("GET", "/WebResource.axd", 200), ("POST", "/Default.aspx", 200), ("GET", "/Report.aspx", 200), ("GET", "/Export.aspx", 200),
    ]
    page = recording.flows[2]
    assert page.response.header("Content-Type") == "text/html"  # no charset on the wire ...
    assert page.request.header("User-Agent").startswith("Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0)")
    assert page.request.header("Accept-Language") == "ja-JP"
    text = page.response.text()
    assert "売上レポート検索" in text and 'charset=Shift_JIS' in text  # ... decoded through the <meta http-equiv>
    assert page.response.body.startswith(b"<!DOCTYPE") and "検索".encode("cp932") in page.response.body
    post = recording.flows[4]
    assert post.request.content_type == "application/x-www-form-urlencoded"
    assert b"ctl00%24txtKeyword=%93%FA%96%7B&ctl00%24btnSearch=%8C%9F%8D%F5" in post.request.body
    assert recording.flows[6].response.mime_type == "text/csv"
    assert recording.flows[0].response.header("WWW-Authenticate") == "Negotiate"
    assert recording.flows[1].response.header("WWW-Authenticate").startswith("NTLM TlRMTVNTUAAC")


# --------------------------------------------------------------------------- plan

def test_auth_is_ntlm_with_recorded_user(legacy_plan):
    _recording, plan = legacy_plan
    auth = plan.auth
    assert auth is not None
    assert (auth.kind, auth.hosts, auth.realm, auth.username) == ("ntlm", ["intra.example.local"], None, "EXAMPLE\\taro")
    assert auth.username_const is None and auth.password_const is None
    assert plan.constants == []
    assert plan.meta["auth"] == "ntlm"
    assert any("REQREC_NTLM_USER" in w and "EXAMPLE\\taro" in w for w in plan.warnings)


def test_four_steps_handshake_folded_and_script_dropped(legacy_plan):
    _recording, plan = legacy_plan
    assert [s.func_name for s in plan.steps] == [
        "step_01_get_default_aspx", "step_02_post_default_aspx", "step_03_get_report_aspx", "step_04_get_export_aspx",
    ]
    assert [s.source_flow_ids for s in plan.steps] == [["f0001", "f0002", "f0003"], ["f0005"], ["f0006"], ["f0007"]]
    assert [s.expected_status for s in plan.steps] == [200, 200, 200, 200]
    assert [s.response_kind for s in plan.steps] == ["html", "html", "html", "text"]
    assert [(d.flow_id, d.reason) for d in plan.dropped] == [("f0004", "static asset (mime application/x-javascript)")]
    assert plan.meta["flows_total"] == 7 and plan.meta["flows_kept"] == 6 and plan.meta["steps"] == 4
    assert plan.steps[0].literal_url() == f"{HOST}/Default.aspx"
    assert plan.steps[1].literal_url() == f"{HOST}/Default.aspx"
    assert plan.steps[2].literal_url() == f"{HOST}/Report.aspx"
    assert plan.steps[3].literal_url() == f"{HOST}/Export.aspx"
    assert plan.final_step_index is None and plan.initial_cookies == []


def test_no_authorization_header_anywhere(legacy_plan):
    recording, plan = legacy_plan
    for step in plan.steps:
        assert "authorization" not in step_headers(step), step.func_name
    dump = json.dumps(to_plain(plan), ensure_ascii=False)
    for flow in recording.flows[1:3]:
        token = flow.request.header("Authorization").split(" ", 1)[1]
        assert token not in dump
    assert "TlRMTVNTUAA" not in dump  # no NTLMSSP token survives
    assert {k.lower() for k, _ in plan.base_headers} == {"accept", "accept-language", "user-agent"}
    assert dict(plan.base_headers)["Accept-Language"] == "ja-JP"


def test_webforms_hidden_fields_are_html_input_extractors(legacy_plan):
    recording, plan = legacy_plan
    page_values = hidden_inputs(recording.flows[2].response.text())
    exts = {e.name: e for e in plan.steps[0].extractors}
    assert set(exts) == {"__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"}
    for name, ext in exts.items():
        assert ext.kind == "html_input" and ext.sample == page_values[name], name
        assert "step 2" in ext.note
    assert (exts["__VIEWSTATE"].var, exts["__VIEWSTATEGENERATOR"].var, exts["__EVENTVALIDATION"].var) == (
        "viewstate", "viewstategenerator", "eventvalidation")
    assert len(page_values["__VIEWSTATE"]) > 300 and re.fullmatch(r"[0-9A-F]{8}", page_values["__VIEWSTATEGENERATOR"])
    form = dict(plan.steps[1].form)
    assert form["__VIEWSTATE"] == Ref.var("viewstate")
    assert form["__VIEWSTATEGENERATOR"] == Ref.var("viewstategenerator")
    assert form["__EVENTVALIDATION"] == Ref.var("eventvalidation")
    assert form["__EVENTTARGET"] == Ref.lit("") and form["__EVENTARGUMENT"] == Ref.lit("")


def test_legacy_form_body_kept_raw_with_content_type(legacy_plan):
    recording, plan = legacy_plan
    post = plan.steps[1]
    assert post.body_kind == "raw"
    assert post.raw_body == recording.flows[4].request.body
    assert b"ctl00%24txtKeyword=%93%FA%96%7B" in post.raw_body
    headers = step_headers(post)
    assert headers["content-type"] == Ref.lit("application/x-www-form-urlencoded")
    assert headers["referer"] == Ref.lit(f"{HOST}/Default.aspx") and headers["cache-control"] == Ref.lit("no-cache")
    # the form hint lets a generator rebuild the body: cp932 values are bytes literals
    form = dict(post.form)
    assert form["ctl00$txtKeyword"] == Ref.expr(repr(KEYWORD_CP932))
    assert form["ctl00$btnSearch"] == Ref.expr(repr(BUTTON_CP932))
    assert [name for name, _ in post.form] == [
        "__EVENTTARGET", "__EVENTARGUMENT", "__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION", "ctl00$txtKeyword", "ctl00$btnSearch",
    ]
    (warning,) = [w for w in plan.warnings if w.startswith("step 2:")]
    assert "Shift_JIS" in warning and "Content-Type" in warning and "__VIEWSTATE" in warning
    assert not any("looks dynamic" in w for w in plan.warnings), plan.warnings


def test_report_id_traced_through_href_pattern(legacy_plan):
    recording, plan = legacy_plan
    (link,) = plan.steps[1].extractors
    assert (link.kind, link.selector, link.attr, link.sample, link.var) == ("html_attr", "a.report-link", "href", "1234", "report_id")
    assert link.pattern and re.compile(link.pattern).groups == 1 and "1234" not in link.pattern
    assert re.search(link.pattern, "Report.aspx?id=1234").group(1) == "1234"
    assert re.search(link.pattern, "Report.aspx?id=98765").group(1) == "98765"
    assert plan.steps[2].params == [("id", Ref.var("report_id"))]
    # the CSV link on the report page feeds the export step
    (csv_link,) = plan.steps[2].extractors
    assert (csv_link.kind, csv_link.selector, csv_link.attr, csv_link.var) == ("html_attr", "a.csv-link", "href", "export_id")
    assert re.search(csv_link.pattern, "Export.aspx?id=4242&fmt=csv").group(1) == "4242"
    assert plan.steps[3].params == [("id", Ref.var("export_id")), ("fmt", Ref.lit("csv"))]
    assert plan.steps[3].response_kind == "text"
    # text/csv without charset: the bytes are Shift_JIS (codegen's _text(resp) sniffs that at run time)
    assert recording.flows[6].response.body.startswith("商品,数量".encode("cp932"))


def test_overrides_apply_to_the_fixture(legacy_plan):
    recording, _plan = legacy_plan
    plan = build_plan(recording, PlanOptions(final_flow_id="f0002", exclude_flow_ids=["f0007"], include_flow_ids=["f0004"]))
    assert plan.final_step_index == 1  # a 401 hop names the step it was folded into
    assert [s.source_flow_ids for s in plan.steps] == [["f0001", "f0002", "f0003"], ["f0004"], ["f0005"], ["f0006"]]
    assert {d.flow_id: d.reason for d in plan.dropped} == {"f0007": "excluded by user"}
    off = build_plan(recording, PlanOptions(detect_auth=False, detect_loops=False))
    assert off.auth is None and [s.expected_status for s in off.steps] == [401, 401, 200, 200, 200, 200]


# --------------------------------------------------------------------------- generate

def test_generated_script_compiles_and_leaks_nothing(legacy_plan):
    recording, plan = legacy_plan
    source = generate(plan, GenOptions())
    compile(source, "legacy_scrape.py", "exec")
    assert "def step_01_get_default_aspx(" in source and "def step_04_get_export_aspx(" in source
    for flow in recording.flows[1:3]:
        assert flow.request.header("Authorization").split(" ", 1)[1] not in source
    assert "TlRMTVNTUAA" not in source
    assert "'Authorization'" not in source and '"Authorization"' not in source  # no header of the folded scheme is emitted
    assert "%93%FA%96%7B" in source  # the recorded cp932 form bytes are in the script
    assert "__VIEWSTATE" in source


def test_cli_inspect_and_generate_succeed_on_the_fixture(tmp_path, capsys):
    assert cli.main(["inspect", LEGACY_HAR]) == 0
    out = capsys.readouterr().out
    assert "WebResource.axd" in out and "Default.aspx" in out  # flow ids per row are the CLI owner's §13.1 addition
    target = tmp_path / "legacy.py"
    assert cli.main(["generate", LEGACY_HAR, "-o", str(target)]) == 0
    compile(target.read_text(encoding="utf-8"), str(target), "exec")


# --------------------------------------------------------------------------- replay against a fresh server

class LegacySite:
    """Scripted ``intra.example.local`` that issues NEW WebForms tokens and rejects the recorded ones.

    It never challenges with 401 (so no NTLM library is needed in the test process); what it
    checks is that the postback carries the fresh ``__VIEWSTATE`` / ``__EVENTVALIDATION`` and the
    cp932-encoded keyword, and that the report / export ids come from the live pages."""

    VIEWSTATE = "/wEPDwUKNEW" + "Qq9XwZ1" * 40 + "=="
    EVENTVALIDATION = "/wEdAANEW" + "kL0pZ" * 12 + "=="
    REPORT_ID = "7788"

    def __init__(self) -> None:
        self.adapter = MockAdapter([
            Rule(f"{HOST}/Default.aspx", method="GET", handler=self.page),
            Rule(f"{HOST}/Default.aspx", method="POST", handler=self.postback),
            Rule(f"{HOST}/Report.aspx", method="GET", handler=self.report),
            Rule(f"{HOST}/Export.aspx", method="GET", handler=self.export),
        ])

    def _html(self, body: str) -> tuple[int, list, bytes]:
        html = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS" /></head><body>'
                f"{body}</body></html>")
        return 200, [("Content-Type", "text/html")], html.encode("cp932")

    def page(self, request):
        return self._html(
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
        ok = (pairs.get(b"__VIEWSTATE") == self.VIEWSTATE.encode() and pairs.get(b"__EVENTVALIDATION") == self.EVENTVALIDATION.encode()
              and pairs.get(b"ctl00$txtKeyword") == KEYWORD_CP932 and pairs.get(b"ctl00$btnSearch") == BUTTON_CP932
              and (request.headers.get("Content-Type") or "").startswith("application/x-www-form-urlencoded"))
        if not ok:
            return 500, [("Content-Type", "text/html")], "<html>Invalid viewstate or form</html>".encode("cp932")
        return self._html(f'<table id="ctl00_gvResults"><tr><td><a class="report-link" href="Report.aspx?id={self.REPORT_ID}">日本支社</a></td></tr></table>')

    def report(self, request):
        if dict(parse_qsl(urlsplit(request.url).query)).get("id") != self.REPORT_ID:
            return 404, [("Content-Type", "text/html")], b"<html>no such report</html>"
        return self._html(f'<a class="csv-link" href="Export.aspx?id={self.REPORT_ID}&amp;fmt=csv">CSV</a>')

    def export(self, request):
        query = dict(parse_qsl(urlsplit(request.url).query))
        if query.get("id") != self.REPORT_ID or query.get("fmt") != "csv":
            return 404, [("Content-Type", "text/plain")], b"bad export"
        return 200, [("Content-Type", "text/csv")], "商品,数量\r\n業務用プリンター,18\r\n".encode("cp932")


def test_script_replays_with_fresh_viewstate_against_mock(legacy_plan):
    _recording, plan = legacy_plan
    source = generate(plan, GenOptions())
    site = LegacySite()
    out = run_generated(source, site.adapter, env={})
    calls = site.adapter.calls
    assert site.adapter.unmatched == [], [c.url for c in site.adapter.unmatched]
    assert [(c.method, c.path) for c in calls] == [
        ("GET", "/Default.aspx"), ("POST", "/Default.aspx"), ("GET", "/Report.aspx"), ("GET", "/Export.aspx"),
    ]
    post = calls[1]
    assert LegacySite.VIEWSTATE.encode() in unquote_to_bytes(post.body) and KEYWORD_CP932 in unquote_to_bytes(post.body)
    assert post.header("Content-Type").startswith("application/x-www-form-urlencoded")
    assert calls[2].query_dict == {"id": LegacySite.REPORT_ID}
    assert calls[3].query_dict == {"id": LegacySite.REPORT_ID, "fmt": "csv"}
    assert "業務用プリンター" in out
    for call in calls:
        assert call.header("Authorization") is None
        assert call.header("User-Agent").startswith("Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0")


# ===== former tests/e2e/test_e2e.py: record a live site, generate, run against a restarted site =====
# The end-to-end proof: capture a browsing session, build a plan, generate a script and run that
# script - in a subprocess - against a **fresh** server that issues different tokens.
#
# If the generated script merely replayed recorded literals it would be rejected at the first
# protected step; it succeeds only by extracting the login token, csrf token, API bearer token and
# export signature from the live responses, exactly the way a browser user would.

SCRIPT_TIMEOUT = 60


# --------------------------------------------------------------------------- helpers

@dataclass
class Captured:
    """Everything the e2e tests need from the recording server (server A)."""

    recording: Recording
    base_url: str
    recorded_tokens: dict[str, set[str]]  # every token server A issued, by kind
    server: SiteServer = field(repr=False)


@pytest.fixture
def captured() -> Iterator[Captured]:
    """Start server A, capture the default scenario and hand over A (still running) for a restart."""
    server, base_url = start_server()
    try:
        recording = capture(default_scenario, base_url=base_url)
    except BaseException:
        stop_server(server)
        raise
    state = Captured(
        recording=recording,
        base_url=base_url,
        recorded_tokens={kind: server.site.issued_tokens(kind) for kind in TOKEN_KINDS},
        server=server,
    )
    try:
        yield state
    finally:
        stop_server(state.server)  # whichever server instance is current (A or its replacement)


def _fresh_server(state: Captured) -> Site:
    """Replace server A by server B on the same port: identical URLs, all-new tokens."""
    server, base_url = restart_server(state.server)
    state.server = server
    assert base_url == state.base_url
    return server.site


def _plan_and_generate(recording: Recording, plan_opts: PlanOptions) -> tuple[Plan, str]:
    from reqrec import generate
    from reqrec import build_plan

    plan = build_plan(recording, plan_opts)
    source = generate(plan, GenOptions())
    assert isinstance(source, str) and source.strip()
    compile(source, "scrape.py", "exec")  # must be valid Python before we even try to run it
    return plan, source


def _write_script(tmp_path: Path, source: str) -> Path:
    script = tmp_path / "scrape.py"
    script.write_text(source, encoding="utf-8")
    return script


def _run_script(script: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    env = {**env, "PYTHONIOENCODING": "utf-8"}  # the script prints Japanese comments / CSV
    return subprocess.run(
        [sys.executable, str(script)],
        env=env,
        cwd=str(script.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=SCRIPT_TIMEOUT,
    )


def _dump(proc: subprocess.CompletedProcess, source: str) -> str:
    return (
        f"returncode={proc.returncode}\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
        f"--- generated script ---\n{source}"
    )


def _assert_fresh_tokens_used(site_b: Site, recorded: dict[str, set[str]]) -> None:
    """Server B's log shows every protected value was re-derived from B's responses."""
    fresh = {kind: site_b.issued_tokens(kind) for kind in TOKEN_KINDS}
    for kind in TOKEN_KINDS:
        assert fresh[kind].isdisjoint(recorded[kind]), kind

    # login: the hidden _token is the one B put in *its* login page, not the recorded one
    posts = site_b.requests_for("POST", "/login")
    assert len(posts) == 1, [e["path"] for e in site_b.log]
    form = posts[0]["form"]
    assert form["_token"] in fresh["login_token"]
    assert form["_token"] not in recorded["login_token"]
    assert form["username"] == USERNAME and form["password"] == PASSWORD
    assert posts[0]["cookies"]["sid"] in fresh["sid"]  # session cookie from B's Set-Cookie

    # pagination: three pages with B's csrf + bearer token
    api_gets = site_b.requests_for("GET", "/api/items")
    assert sorted(e["query"].get("page") for e in api_gets) == ["1", "2", "3"]
    for entry in api_gets:
        csrf = entry["headers"].get("x-csrf-token")
        auth = entry["headers"].get("authorization", "")
        assert csrf in fresh["csrf"] and csrf not in recorded["csrf"], entry["headers"]
        assert auth.startswith("Bearer ") and auth[len("Bearer "):] in fresh["api_token"], auth
        assert auth[len("Bearer "):] not in recorded["api_token"]
        assert entry["cookies"]["sid"] in fresh["sid"]

    # JSON POST: csrf in the body is B's as well
    api_posts = site_b.requests_for("POST", "/api/items")
    assert len(api_posts) == 1
    body = api_posts[0]["json"]
    assert body["name"] == "new-item"
    assert body["csrf"] in fresh["csrf"] and body["csrf"] not in recorded["csrf"]
    assert api_posts[0]["headers"]["content-type"].startswith("application/json")
    assert site_b.items == [{"id": 1001, "name": "new-item"}]

    # signed export link parsed out of B's dashboard
    exports = site_b.requests_for("GET", "/export")
    assert len(exports) == 1
    assert exports[0]["query"].get("sig") in fresh["export_sig"]
    assert exports[0]["query"].get("sig") not in recorded["export_sig"]

    # noise was filtered out of the script
    assert not [e for e in site_b.log if e["route"].startswith("/static") or e["route"] == "/favicon.ico"]

    # browser-like base headers travel with every request
    for entry in site_b.log:
        assert entry["headers"].get("accept-language") == "ja,en;q=0.8", entry["path"]
        assert entry["headers"].get("user-agent", "").startswith("Mozilla/5.0"), entry["path"]


def _kept_sequence(recording: Recording) -> list[tuple[str, str]]:
    """(method, route) of the recorded flows that are not static noise."""
    out = []
    for flow in recording.flows:
        path = flow.request.path
        if path.startswith("/static") or path == "/favicon.ico":
            continue
        out.append((flow.request.method, path))
    return out


# --------------------------------------------------------------------------- tests

def test_generated_script_replays_against_fresh_tokens(captured: Captured, tmp_path: Path) -> None:
    plan, source = _plan_and_generate(captured.recording, PlanOptions(redact_secrets=True))

    # the plan dropped exactly the static noise and hid the password behind an env var
    dropped = {d.url.replace(captured.base_url, "") for d in plan.dropped}
    assert dropped == {"/static/app.css", "/static/logo.png", "/favicon.ico"}
    assert "Secr3t!" not in source
    assert "REQREC_PASSWORD" in source
    assert len(plan.steps) >= 5
    script = _write_script(tmp_path, source)

    site_b = _fresh_server(captured)
    proc = _run_script(script, {**os.environ, "REQREC_PASSWORD": PASSWORD})
    if proc.returncode != 0:
        print(_dump(proc, source))
        pytest.fail(f"generated script exited with {proc.returncode}")
    assert "Traceback" not in proc.stderr, proc.stderr

    # the last step is the CSV export, which main() prints
    assert proc.stdout.strip(), "the script printed nothing"
    assert "id,name" in proc.stdout
    assert "1,item-1-1" in proc.stdout and "3,item-1-3" in proc.stdout

    _assert_fresh_tokens_used(site_b, captured.recorded_tokens)
    # the script made the same conversation as the recording (minus noise), in the same order
    assert [(e["method"], e["route"]) for e in site_b.log] == _kept_sequence(captured.recording)
    assert not (tmp_path / "output.bin").exists()  # text output is printed, not saved


def test_generated_script_with_embedded_password(captured: Captured, tmp_path: Path) -> None:
    plan, source = _plan_and_generate(captured.recording, PlanOptions(redact_secrets=False))
    assert "Secr3t!" in source
    assert "REQREC_PASSWORD" not in source
    assert not any(c.secret for c in plan.constants)
    script = _write_script(tmp_path, source)

    site_b = _fresh_server(captured)
    env = {k: v for k, v in os.environ.items() if k != "REQREC_PASSWORD"}
    proc = _run_script(script, env)
    if proc.returncode != 0:
        print(_dump(proc, source))
        pytest.fail(f"generated script exited with {proc.returncode}")
    assert "id,name" in proc.stdout and "item-1-1" in proc.stdout
    _assert_fresh_tokens_used(site_b, captured.recorded_tokens)


def test_redacted_script_fails_loudly_without_the_secret(captured: Captured, tmp_path: Path) -> None:
    """Without REQREC_PASSWORD the script stops before sending anything, naming the variable."""
    _plan, source = _plan_and_generate(captured.recording, PlanOptions(redact_secrets=True))
    script = _write_script(tmp_path, source)

    site_b = _fresh_server(captured)
    env = {k: v for k, v in os.environ.items() if k != "REQREC_PASSWORD"}
    proc = _run_script(script, env)
    assert proc.returncode != 0, _dump(proc, source)
    assert "REQREC_PASSWORD" in proc.stderr and "設定されていません" in proc.stderr, proc.stderr
    assert "Traceback" not in proc.stderr
    assert "id,name" not in proc.stdout
    # no request at all: an empty password is never sent
    assert site_b.requests_for("POST", "/login") == []
    assert site_b.requests_for("GET", "/dashboard") == []
    assert site_b.requests_for(route="/api/items") == []


def test_generated_script_runs_twice_in_a_row(captured: Captured, tmp_path: Path) -> None:
    """Tokens are per *session*: a second run on the same server must log in afresh and succeed."""
    _plan, source = _plan_and_generate(captured.recording, PlanOptions(redact_secrets=True))
    script = _write_script(tmp_path, source)
    site_b = _fresh_server(captured)
    env = {**os.environ, "REQREC_PASSWORD": PASSWORD}
    first = _run_script(script, env)
    second = _run_script(script, env)
    for proc in (first, second):
        if proc.returncode != 0:
            print(_dump(proc, source))
            pytest.fail(f"generated script exited with {proc.returncode}")
        assert "id,name" in proc.stdout
    posts = site_b.requests_for("POST", "/login")
    assert len(posts) == 2
    assert posts[0]["form"]["_token"] != posts[1]["form"]["_token"]
    assert posts[0]["cookies"]["sid"] != posts[1]["cookies"]["sid"]
    assert len(site_b.requests_for("GET", "/export")) == 2
    assert [it["name"] for it in site_b.items] == ["new-item", "new-item"]


# ===== former tests/e2e/test_server_capture.py: the e2e site and the capture helper themselves =====
# Tests for the e2e harness itself: the fake site's token enforcement and the capture helper.

TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


@pytest.fixture
def site():
    """A freshly started site: ``(server, base_url)``.  Stopped after the test."""
    server, base_url = start_server()
    try:
        yield server, base_url
    finally:
        stop_server(server)


def _login(session: requests.Session, base_url: str) -> dict:
    """Log in through the real pages; returns the dashboard-derived tokens."""
    page = session.get(f"{base_url}/login")
    token = re.search(r'name="_token" value="([0-9a-f]+)"', page.text).group(1)
    resp = session.post(f"{base_url}/login", data={"_token": token, "username": USERNAME, "password": PASSWORD})
    assert resp.status_code == 200 and resp.url.endswith("/dashboard"), (resp.status_code, resp.url)
    html = resp.text
    return {
        "login_token": token,
        "csrf": re.search(r'name="csrf-token" content="([0-9a-f]+)"', html).group(1),
        "api_token": re.search(r'window\.API_TOKEN = "([0-9a-f]+)"', html).group(1),
        "export_sig": re.search(r"/export\?sig=([0-9a-f]+)", html).group(1),
    }


def _api_headers(tokens: dict) -> dict:
    return {"X-CSRF-Token": tokens["csrf"], "Authorization": f"Bearer {tokens['api_token']}"}


# =========================================================================== server


class TestServer:
    def test_ping_and_unknown_routes(self, site):
        server, base_url = site
        resp = requests.get(f"{base_url}/ping")
        assert resp.status_code == 200
        assert resp.text == "ok"
        assert resp.headers["Content-Type"].startswith("text/plain")
        assert requests.get(f"{base_url}/nowhere").status_code == 404
        assert requests.put(f"{base_url}/login").status_code == 405
        assert [e["route"] for e in server.site.log] == ["/ping", "/nowhere", "/login"]

    def test_login_page_sets_session_cookie_and_hidden_token(self, site):
        server, base_url = site
        resp = requests.get(f"{base_url}/login")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "text/html; charset=utf-8"
        set_cookies = resp.raw.headers.getlist("Set-Cookie")
        assert len(set_cookies) == 2
        assert set_cookies[0].startswith("sid=") and "HttpOnly" in set_cookies[0] and "Path=/" in set_cookies[0]
        sid = resp.cookies["sid"]
        assert TOKEN_RE.match(sid)
        token = re.search(r'<input type="hidden" name="_token" value="([^"]+)">', resp.text).group(1)
        assert TOKEN_RE.match(token)
        assert server.site.sessions[sid]["login_token"] == token
        assert server.site.sessions[sid]["logged_in"] is False
        # the page carries the noise references and the credential inputs
        assert 'href="/static/app.css"' in resp.text and 'src="/static/logo.png"' in resp.text
        assert 'name="username"' in resp.text and 'name="password"' in resp.text
        assert "ログイン" in resp.text  # utf-8 content decodes correctly

    def test_each_login_page_view_gets_distinct_tokens(self, site):
        _server, base_url = site
        pages = [requests.get(f"{base_url}/login") for _ in range(3)]
        tokens = {re.search(r'name="_token" value="([^"]+)"', p.text).group(1) for p in pages}
        sids = {p.cookies["sid"] for p in pages}
        assert len(tokens) == 3 and len(sids) == 3

    def test_login_success_rotates_sid_and_redirects_relative(self, site):
        server, base_url = site
        session = requests.Session()
        page = session.get(f"{base_url}/login")
        old_sid = session.cookies["sid"]
        token = re.search(r'name="_token" value="([^"]+)"', page.text).group(1)
        resp = session.post(
            f"{base_url}/login",
            data={"_token": token, "username": USERNAME, "password": PASSWORD},
            allow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/dashboard"
        new_sid = session.cookies["sid"]
        assert new_sid != old_sid
        assert resp.raw.headers.getlist("Set-Cookie") == [f"sid={new_sid}; Path=/; HttpOnly"]
        assert old_sid not in server.site.sessions
        sess = server.site.sessions[new_sid]
        assert sess["logged_in"] is True and sess["user"] == USERNAME
        assert all(TOKEN_RE.match(sess[k]) for k in ("csrf", "api_token", "export_sig"))
        assert sess["login_token"] is None  # one-time token consumed

    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda f: f.update(_token="0" * 32), id="wrong-token"),
            pytest.param(lambda f: f.pop("_token"), id="missing-token"),
            pytest.param(lambda f: f.update(password="wrong"), id="wrong-password"),
            pytest.param(lambda f: f.update(username="bob"), id="wrong-user"),
        ],
    )
    def test_login_rejects_bad_token_or_credentials(self, site, mutate):
        server, base_url = site
        session = requests.Session()
        page = session.get(f"{base_url}/login")
        sid = session.cookies["sid"]
        form = {
            "_token": re.search(r'name="_token" value="([^"]+)"', page.text).group(1),
            "username": USERNAME,
            "password": PASSWORD,
        }
        mutate(form)
        resp = session.post(f"{base_url}/login", data=form, allow_redirects=False)
        assert resp.status_code == 403
        assert resp.headers["Content-Type"].startswith("text/html")
        assert server.site.sessions[sid]["logged_in"] is False
        assert session.cookies["sid"] == sid  # not rotated

    def test_login_without_session_cookie_is_rejected(self, site):
        server, base_url = site
        page = requests.get(f"{base_url}/login")
        token = re.search(r'name="_token" value="([^"]+)"', page.text).group(1)
        # correct token, but the request does not carry the sid cookie it belongs to
        resp = requests.post(f"{base_url}/login", data={"_token": token, "username": USERNAME, "password": PASSWORD},
                             allow_redirects=False)
        assert resp.status_code == 403

    def test_login_token_is_single_use(self, site):
        _server, base_url = site
        session = requests.Session()
        tokens = _login(session, base_url)
        again = session.post(f"{base_url}/login", data={"_token": tokens["login_token"], "username": USERNAME,
                                                        "password": PASSWORD}, allow_redirects=False)
        assert again.status_code == 403

    def test_dashboard_requires_login(self, site):
        _server, base_url = site
        assert requests.get(f"{base_url}/dashboard").status_code == 403
        session = requests.Session()
        session.get(f"{base_url}/login")  # anonymous session only
        assert session.get(f"{base_url}/dashboard").status_code == 403

    def test_dashboard_exposes_csrf_api_token_and_signed_link(self, site):
        server, base_url = site
        session = requests.Session()
        tokens = _login(session, base_url)
        resp = session.get(f"{base_url}/dashboard")
        assert resp.status_code == 200
        sess = server.site.sessions[session.cookies["sid"]]
        assert f'<meta name="csrf-token" content="{sess["csrf"]}">' in resp.text
        assert f'<script>window.API_TOKEN = "{sess["api_token"]}";</script>' in resp.text
        assert f'<a id="export-link" href="/export?sig={sess["export_sig"]}">CSV</a>' in resp.text
        assert '<li data-id="1">item-1-1</li>' in resp.text
        assert tokens["csrf"] == sess["csrf"]
        # the same session sees stable tokens on a second view
        assert session.get(f"{base_url}/dashboard").text == resp.text

    def test_api_items_requires_csrf_and_bearer(self, site):
        _server, base_url = site
        session = requests.Session()
        tokens = _login(session, base_url)
        url = f"{base_url}/api/items"
        assert session.get(url, params={"page": 1}).status_code == 401
        wrong_csrf = session.get(url, params={"page": 1}, headers={**_api_headers(tokens), "X-CSRF-Token": "0" * 32})
        assert wrong_csrf.status_code == 401
        assert wrong_csrf.headers["Content-Type"].startswith("application/json")
        assert wrong_csrf.json()["error"] == "unauthorized"
        no_bearer = session.get(url, params={"page": 1}, headers={"X-CSRF-Token": tokens["csrf"]})
        assert no_bearer.status_code == 401
        wrong_bearer = session.get(url, params={"page": 1},
                                   headers={**_api_headers(tokens), "Authorization": "Bearer " + "0" * 32})
        assert wrong_bearer.status_code == 401
        # another logged-in session's tokens do not work either (tokens are per session)
        other = requests.Session()
        other_tokens = _login(other, base_url)
        assert session.get(url, params={"page": 1}, headers=_api_headers(other_tokens)).status_code == 401
        # anonymous (no cookie) with valid headers
        assert requests.get(url, params={"page": 1}, headers=_api_headers(tokens)).status_code == 401

    def test_api_items_pagination(self, site):
        _server, base_url = site
        session = requests.Session()
        tokens = _login(session, base_url)
        seen = []
        for page in range(1, LAST_PAGE + 1):
            resp = session.get(f"{base_url}/api/items", params={"page": page}, headers=_api_headers(tokens))
            assert resp.status_code == 200
            data = resp.json()
            assert data["page"] == page
            assert [it["name"] for it in data["items"]] == [f"item-{page}-{n}" for n in (1, 2, 3)]
            assert data["next"] == (page + 1 if page < LAST_PAGE else None)
            seen += [it["id"] for it in data["items"]]
        assert seen == list(range(1, 10))
        assert session.get(f"{base_url}/api/items", params={"page": "x"}, headers=_api_headers(tokens)).status_code == 400
        assert session.get(f"{base_url}/api/items", params={"page": 9}, headers=_api_headers(tokens)).status_code == 404

    def test_api_items_post_creates_item(self, site):
        server, base_url = site
        session = requests.Session()
        tokens = _login(session, base_url)
        url = f"{base_url}/api/items"
        resp = session.post(url, json={"name": "new-item", "csrf": tokens["csrf"]}, headers=_api_headers(tokens))
        assert resp.status_code == 201
        assert resp.json() == {"id": 1001, "name": "new-item"}
        assert server.site.items == [{"id": 1001, "name": "new-item"}]
        # body csrf must match too, even with correct headers
        bad = session.post(url, json={"name": "x", "csrf": "0" * 32}, headers=_api_headers(tokens))
        assert bad.status_code == 403
        assert session.post(url, json={"csrf": tokens["csrf"]}, headers=_api_headers(tokens)).status_code == 400
        assert session.post(url, data=b"not json", headers={**_api_headers(tokens), "Content-Type": "application/json"}).status_code == 400
        assert session.post(url, json={"name": "x", "csrf": tokens["csrf"]}).status_code == 401
        assert len(server.site.items) == 1

    def test_export_requires_valid_signature(self, site):
        _server, base_url = site
        session = requests.Session()
        tokens = _login(session, base_url)
        assert session.get(f"{base_url}/export", params={"sig": "0" * 32}).status_code == 403
        assert session.get(f"{base_url}/export").status_code == 403
        assert requests.get(f"{base_url}/export", params={"sig": tokens["export_sig"]}).status_code == 403  # no cookie
        resp = session.get(f"{base_url}/export", params={"sig": tokens["export_sig"]})
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "text/csv; charset=utf-8"
        assert "attachment" in resp.headers["Content-Disposition"]
        lines = resp.text.splitlines()
        assert lines[0] == "id,name"
        assert lines[1:] == ["1,item-1-1", "2,item-1-2", "3,item-1-3"]

    def test_static_assets(self, site):
        _server, base_url = site
        css = requests.get(f"{base_url}/static/app.css")
        assert css.status_code == 200 and css.headers["Content-Type"].startswith("text/css")
        png = requests.get(f"{base_url}/static/logo.png")
        assert png.status_code == 200 and png.headers["Content-Type"] == "image/png"
        assert png.content.startswith(b"\x89PNG\r\n\x1a\n") and png.content.endswith(b"IEND\xaeB`\x82")
        ico = requests.get(f"{base_url}/favicon.ico")
        assert ico.status_code == 200 and ico.headers["Content-Type"] == "image/x-icon"
        assert ico.content[:4] == b"\x00\x00\x01\x00"
        head = requests.head(f"{base_url}/static/logo.png")
        assert head.status_code == 200 and head.content == b""
        assert head.headers["Content-Length"] == str(len(png.content))

    def test_log_records_method_path_headers_and_body(self, site):
        server, base_url = site
        session = requests.Session()
        _login(session, base_url)
        get_login, post_login, dashboard = server.site.log[:3]
        assert (get_login["method"], get_login["path"], get_login["route"]) == ("GET", "/login", "/login")
        assert get_login["body"] == b""
        assert "user-agent" in get_login["headers"]  # header names are lower-cased
        assert post_login["method"] == "POST"
        assert isinstance(post_login["body"], bytes) and b"username=alice" in post_login["body"]
        assert post_login["form"]["password"] == PASSWORD
        assert post_login["headers"]["content-type"] == "application/x-www-form-urlencoded"
        assert post_login["cookies"]["sid"] in server.site.issued["sid"]
        assert dashboard["route"] == "/dashboard" and dashboard["cookies"]["sid"] == session.cookies["sid"]
        assert server.site.requests_for("POST", "/login") == [post_login]
        assert server.site.requests_for(route="/dashboard") == [dashboard]
        assert [e["time"] for e in server.site.log] == sorted(e["time"] for e in server.site.log)
        server.site.reset_log()
        assert server.site.log == []

    def test_log_parses_json_bodies_and_query(self, site):
        server, base_url = site
        session = requests.Session()
        tokens = _login(session, base_url)
        session.get(f"{base_url}/api/items", params={"page": 2}, headers=_api_headers(tokens))
        session.post(f"{base_url}/api/items", json={"name": "x", "csrf": tokens["csrf"]}, headers=_api_headers(tokens))
        get, post = server.site.log[-2:]
        assert get["path"] == "/api/items?page=2" and get["route"] == "/api/items" and get["query"] == {"page": "2"}
        assert post["json"] == {"name": "x", "csrf": tokens["csrf"]}
        assert post["headers"]["authorization"] == f"Bearer {tokens['api_token']}"

    def test_tokens_are_random_per_server_start(self):
        a, base_a = start_server()
        try:
            tokens_a = _login(requests.Session(), base_a)
            issued_a = {k: a.site.issued_tokens(k) for k in TOKEN_KINDS}
        finally:
            stop_server(a)
        b, base_b = start_server()
        try:
            tokens_b = _login(requests.Session(), base_b)
            for kind in TOKEN_KINDS:
                assert b.site.issued_tokens(kind).isdisjoint(issued_a[kind])
            assert tokens_a != tokens_b
        finally:
            stop_server(b)

    def test_restart_keeps_port_but_rejects_recorded_tokens(self):
        """The core property the e2e test relies on: a replayed *recorded* token must fail."""
        server, base_url = start_server()
        try:
            recorded = default_scenario(make_session(), base_url)
            site_a = server.site
        except BaseException:
            stop_server(server)
            raise
        server, base_b = restart_server(server)
        try:
            assert base_b == base_url  # same host:port, so recorded URLs still resolve
            assert server.site is not site_a and server.site.log == []
            session = make_session()
            session.get(f"{base_url}/login")  # obtain a fresh anonymous session on server B
            stale_login = session.post(
                f"{base_url}/login",
                data={"_token": recorded["login_token"], "username": USERNAME, "password": PASSWORD},
                allow_redirects=False,
            )
            assert stale_login.status_code == 403
            # even once properly logged in on B, A's csrf / bearer / sig are rejected
            fresh = _login(session, base_url)
            assert fresh["csrf"] != recorded["csrf"] and fresh["api_token"] != recorded["api_token"]
            stale_api = session.get(f"{base_url}/api/items", params={"page": 1}, headers=_api_headers(recorded))
            assert stale_api.status_code == 401
            stale_post = session.post(f"{base_url}/api/items", json={"name": "n", "csrf": recorded["csrf"]},
                                      headers=_api_headers(fresh))
            assert stale_post.status_code == 403
            assert session.get(f"{base_url}/export", params={"sig": recorded["export_sig"]}).status_code == 403
            for kind in TOKEN_KINDS:
                assert server.site.issued_tokens(kind).isdisjoint(site_a.issued_tokens(kind))
        finally:
            stop_server(server)

    def test_naive_literal_replay_of_a_recording_fails(self):
        """Replaying the recorded requests byte-for-byte (recorded Cookie + _token) breaks at login."""
        server, base_url = start_server()
        try:
            recording = capture(default_scenario, base_url=base_url)
        except BaseException:
            stop_server(server)
            raise
        server, _ = restart_server(server)
        try:
            statuses = []
            for flow in recording.flows:
                req = flow.request
                headers = {k: v for k, v in req.headers if k.lower() not in ("content-length", "accept-encoding", "connection")}
                resp = requests.request(req.method, req.url, headers=headers, data=req.body, allow_redirects=False, timeout=10)
                statuses.append((req.method, req.path, resp.status_code))
                if resp.status_code >= 400:
                    break
            assert statuses[-1] == ("POST", "/login", 403), statuses
            assert server.site.requests_for("GET", "/dashboard") == []
        finally:
            stop_server(server)

    def test_site_helpers(self):
        site = Site()
        assert Site.page_items(2) == [{"id": 4, "name": "item-2-1"}, {"id": 5, "name": "item-2-2"}, {"id": 6, "name": "item-2-3"}]
        sid, sess = site.create_session()
        assert site.get_session(sid) is sess and site.get_session(None) is None and site.get_session("nope") is None
        assert site.login(sid, sess["login_token"], USERNAME, "wrong") is None
        assert site.login("other", sess["login_token"], USERNAME, PASSWORD) is None
        new_sid = site.login(sid, sess["login_token"], USERNAME, PASSWORD)
        assert new_sid and new_sid != sid and site.get_session(sid) is None and site.get_session(new_sid) is sess
        assert site.login(new_sid, None, USERNAME, PASSWORD) is None  # token consumed
        assert site.add_item("a") == {"id": 1001, "name": "a"} and site.add_item("b")["id"] == 1002
        assert site.issued_tokens("sid") == {sid, new_sid}
        assert site_server.make_png(2, 2)[:8] == b"\x89PNG\r\n\x1a\n"


# =========================================================================== capture


@pytest.fixture
def recording(site):
    _server, base_url = site
    return capture(default_scenario, base_url=base_url), base_url


def _summary(recording: Recording, base_url: str) -> list[tuple[str, str, int]]:
    return [(f.request.method, f.request.url.replace(base_url, ""), f.response.status) for f in recording.flows]


class TestCapture:
    def test_default_scenario_flow_sequence_and_ids(self, recording):
        rec, base_url = recording
        assert _summary(rec, base_url) == [
            ("GET", "/login", 200),
            ("GET", "/static/app.css", 200),
            ("GET", "/static/logo.png", 200),
            ("GET", "/favicon.ico", 200),
            ("POST", "/login", 302),
            ("GET", "/dashboard", 200),  # the redirect hop requests followed
            ("GET", "/dashboard", 200),
            ("GET", "/api/items?page=1", 200),
            ("GET", "/api/items?page=2", 200),
            ("GET", "/api/items?page=3", 200),
            ("POST", "/api/items", 201),
            ("GET", f"/export?sig={rec.flows[-1].request.query_pairs[0][1]}", 200),
        ]
        assert [f.id for f in rec.flows] == [f"f{i:04d}" for i in range(1, 13)]
        assert rec.meta["source"] == "e2e-capture"
        assert rec.meta["base_url"] == base_url
        assert all(f.resource_type is None and f.page_ref is None for f in rec.flows)

    def test_started_at_is_strictly_increasing_and_recent(self, recording):
        rec, _ = recording
        stamps = [f.started_at for f in rec.flows]
        assert all(isinstance(t, float) for t in stamps)
        assert all(b > a for a, b in zip(stamps, stamps[1:]))
        assert abs(stamps[0] - time.time()) < 60

    def test_multiple_set_cookie_headers_are_preserved(self, recording):
        rec, _ = recording
        login_page = rec.flows[0]
        assert login_page.response.set_cookies == [
            f"sid={login_page.response.set_cookies[0].split('=', 1)[1].split(';', 1)[0]}; Path=/; HttpOnly",
            "lang=ja; Path=/",
        ]
        names = [k for k, _v in login_page.response.headers]
        assert names.count("Set-Cookie") == 2
        assert login_page.response.mime_type == "text/html"
        assert login_page.response.header("content-type") == "text/html; charset=utf-8"

    def test_redirect_hop_is_its_own_flow_followed_by_the_target(self, recording):
        rec, base_url = recording
        post = next(f for f in rec.flows if f.request.method == "POST" and f.request.path == "/login")
        follow = rec.flows[rec.flows.index(post) + 1]
        assert post.response.status == 302 and post.response.is_redirect
        assert post.response.location == "/dashboard"
        assert len(post.response.set_cookies) == 1 and post.response.set_cookies[0].startswith("sid=")
        assert follow.request.method == "GET" and follow.request.url == f"{base_url}/dashboard"
        assert follow.response.status == 200
        # the follow-up request carried the *rotated* sid that the 302 set
        new_sid = post.response.set_cookies[0].split(";", 1)[0]
        assert new_sid in (follow.request.header("cookie") or "")
        old_cookie = post.request.header("cookie") or ""
        assert "sid=" in old_cookie and new_sid not in old_cookie
        # the POST carried the hidden token from the login page
        login_page = rec.flows[0]
        token = re.search(r'name="_token" value="([^"]+)"', login_page.response.text()).group(1)
        assert post.request.body is not None and f"_token={token}".encode() in post.request.body
        assert post.request.content_type == "application/x-www-form-urlencoded"

    def test_bodies_are_bytes_or_none(self, recording):
        rec, _ = recording
        for f in rec.flows:
            assert f.request.body is None or isinstance(f.request.body, bytes), f.id
            assert isinstance(f.response.body, bytes), f.id
        post_json = next(f for f in rec.flows if f.request.method == "POST" and f.request.path == "/api/items")
        assert isinstance(post_json.request.body, bytes)
        assert post_json.request.content_type == "application/json"
        import json
        assert json.loads(post_json.request.body)["name"] == "new-item"
        assert post_json.response.body.startswith(b'{"id": 1001')
        png = next(f for f in rec.flows if f.request.path == "/static/logo.png")
        assert png.response.body.startswith(b"\x89PNG") and png.response.mime_type == "image/png"
        gets = [f for f in rec.flows if f.request.method == "GET"]
        assert all(f.request.body is None for f in gets)

    def test_request_headers_include_cookie_and_browser_headers(self, recording):
        rec, _ = recording
        for f in rec.flows:
            assert f.request.header("user-agent") == BROWSER_HEADERS["User-Agent"], f.id
            assert f.request.header("accept-language") == "ja,en;q=0.8", f.id
        dashboard = [f for f in rec.flows if f.request.path == "/dashboard"][-1]
        assert "sid=" in dashboard.request.header("cookie") and "lang=ja" in dashboard.request.header("cookie")
        api = next(f for f in rec.flows if f.request.path == "/api/items")
        assert api.request.header("x-csrf-token") and api.request.header("authorization", ).startswith("Bearer ")
        assert rec.flows[0].request.header("cookie") is None  # nothing before the first response

    def test_no_duplicate_flows_from_history(self, recording):
        rec, _ = recording
        keys = [(f.request.method, f.request.url, f.started_at) for f in rec.flows]
        assert len(set(keys)) == len(keys)
        assert sum(1 for f in rec.flows if f.request.method == "POST" and f.request.path == "/login") == 1
        assert sum(1 for f in rec.flows if f.request.path == "/dashboard") == 2

    def test_recording_survives_json_roundtrip(self, recording):
        rec, _ = recording
        again = Recording.from_json(rec.to_json())
        assert [f.to_dict() for f in again.flows] == [f.to_dict() for f in rec.flows]
        assert again.meta == rec.meta

    def test_capture_with_caller_session_restores_hooks_and_keeps_headers(self, site):
        _server, base_url = site
        session = requests.Session()
        session.headers["User-Agent"] = "custom-ua/1.0"
        before = list(session.hooks["response"])
        rec = capture(lambda s, b: s.get(f"{b}/ping"), session=session, base_url=base_url)
        assert session.hooks["response"] == before
        assert len(rec.flows) == 1
        assert rec.flows[0].request.header("user-agent") == "custom-ua/1.0"  # caller's header wins
        assert rec.flows[0].request.header("accept-language") == "ja,en;q=0.8"  # missing ones are added
        assert rec.flows[0].response.body == b"ok"
        # the caller's session is still usable afterwards
        assert session.get(f"{base_url}/ping").status_code == 200

    def test_capture_without_base_url_calls_fn_with_session_only(self, site):
        _server, base_url = site
        rec = capture(lambda s: s.get(f"{base_url}/ping"))
        assert [f.request.path for f in rec.flows] == ["/ping"]
        assert "base_url" not in rec.meta and rec.meta["source"] == "e2e-capture"

    def test_capture_records_failed_requests_and_propagates_scenario_errors(self, site):
        _server, base_url = site
        def scenario(s, b):
            assert s.get(f"{b}/dashboard").status_code == 403
            raise RuntimeError("boom")
        with pytest.raises(RuntimeError, match="boom"):
            capture(scenario, base_url=base_url)

    def test_flow_from_response_str_form_body_and_json_body(self, site):
        _server, base_url = site
        form = requests.post(f"{base_url}/login", data={"a": "1", "b": "x y"})
        assert isinstance(form.request.body, str)
        flow = flow_from_response(form, "f0001", started_at=123.5)
        assert flow.id == "f0001" and flow.started_at == 123.5
        assert flow.request.body == b"a=1&b=x+y"
        assert flow.request.method == "POST" and flow.request.url == f"{base_url}/login"
        assert flow.response.status == 403
        js = requests.post(f"{base_url}/api/items", json={"k": "値"})
        flow = flow_from_response(js, "f0002")
        assert flow.request.body == '{"k": "\\u5024"}'.encode()
        assert flow.response.status == 401 and flow.response.mime_type == "application/json"
        assert abs(flow.started_at - time.time()) < 5

    def test_flow_from_response_without_raw_falls_back_to_headers(self):
        resp = requests.Response()
        resp.status_code = 204
        resp.headers["X-Thing"] = "1"
        resp._content = b""
        resp.raw = None
        prepared = requests.Request("GET", "http://example.invalid/x").prepare()
        resp.request = prepared
        flow = flow_from_response(resp, "f0001", started_at=1.0)
        assert flow.response.headers == [("X-Thing", "1")]
        assert flow.response.body == b"" and flow.request.body is None


# ===== former tests/e2e/test_factory_replay.py: factory IE recordings replayed against a fresh mock site =====
# Factory intranet scenario recorded in the real IE-engine recording browser, replayed by the
# generated script against a FRESH mock server (every session id, __VIEWSTATE and URL key differs).
#
# The two recordings in ``tests/fixtures/factory_ie_recording_*.json`` were made by
# ``tests/ie_support.py``'s factory scenario (RecBrowser.exe + mitmdump + the reqrec addon): login
# (ASP.NET session id rotated at login, one-time __VIEWSTATE / __EVENTVALIDATION), the menu, the
# search screen opened with ``window.open`` and a per-session URL key, an autopostback plant dropdown
# that fills the line dropdown, an item picked in a ``showModalDialog`` window, search, page 2 of the
# grid, Excel export (``Content-Disposition`` with a percent-encoded Japanese name) and a
# ``target=_blank`` news page.  ``letter_key`` has a URL key made of letters only (no digit), which
# used to be mistaken for a page name and was not traced.
#
# No browser is needed here: the recordings are fixtures, the server is ``tests/ie_support.py``'s factory site.

REPLAY_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPLAY_ROOT / "tests" / "fixtures"
RECORDINGS = {
    "digit_key": FIXTURES / "factory_ie_recording_digit_key.json",
    "letter_key": FIXTURES / "factory_ie_recording_letter_key.json",
}
SCENARIO_FILTER = ("01", "L11", "D", "2026/09/01", "2026/10/10", "A-1002")
PASSWORD_ENV = "REQREC_TXT_PASSWORD"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


fs = _load("factory_site_for_replay", REPLAY_ROOT / "tests" / "ie_support.py")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _retarget(src: Path, dst: Path, port: int) -> str:
    """Point the recording at ``127.0.0.1:<port>`` (the recording used ``127.0.0.1.nip.io:<old>``
    because WinINet never proxies a literal loopback address; plain requests needs no DNS)."""
    text = src.read_text(encoding="utf-8")
    old = re.search(r"127\.0\.0\.1\.nip\.io:\d+", text).group(0)
    dst.write_text(text.replace(old, f"127.0.0.1:{port}"), encoding="utf-8")
    return old


@pytest.fixture(params=sorted(RECORDINGS))
def replay(request, tmp_path):
    """(script path, server, site log path, recording) for one fixture against a fresh server."""
    port = _free_port()
    rec_path = tmp_path / "rec.json"
    _retarget(RECORDINGS[request.param], rec_path, port)
    script = tmp_path / "scrape_factory.py"
    assert cli.main(["generate", str(rec_path), "-o", str(script), "--redact"]) == 0  # password from the environment
    log = tmp_path / "site.log"
    server = fs.serve_in_thread(str(log), port)
    try:
        yield script, server, log, Recording.load(str(rec_path))
    finally:
        server.stop()


def _run(script: Path, outdir: Path, password: str | None = fs.CREDENTIALS[1]) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("REQREC_")}
    env.update(PYTHONIOENCODING="utf-8", REQREC_OUTPUT_DIR=str(outdir))
    if password is not None:
        env[PASSWORD_ENV] = password
    return subprocess.run([sys.executable, str(script)], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, cwd=str(script.parent), timeout=120)


def _code_without_comments(source: str) -> str:
    import io
    import tokenize

    toks = [t for t in tokenize.generate_tokens(io.StringIO(source).readline) if t.type != tokenize.COMMENT]
    return tokenize.untokenize(toks)


def _events(log: Path) -> list:
    return [e for e in fs.read_log(str(log)) if e.get("event") not in ("static", "not_found")]


def test_generated_script_replays_the_whole_scenario_on_a_fresh_server(replay, tmp_path):
    script, _server, log, _rec = replay
    proc = _run(script, tmp_path / "out")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    names = [e["event"] for e in _events(log)]
    assert names == ["login_page", "login_ok", "menu", "search_page", "plant_change", "picker", "search", "page",
                     "excel_export", "news"], names
    assert not [e for e in fs.read_log(str(log)) if (e.get("event") or "").endswith("_reject") or e.get("status", 200) >= 400]
    # the Excel export in the middle is saved under the server's Japanese file name, with the right rows
    xlsx = tmp_path / "out" / fs.export_filename("01", "L11")
    assert xlsx.name == "生産実績_01_L11_20261011.xlsx" and xlsx.is_file(), os.listdir(tmp_path / "out")
    rows = fs.read_xlsx_rows(xlsx.read_bytes())
    assert [tuple(r) for r in rows[1:-1]] == [tuple(r) for r in fs.expected_rows(*SCENARIO_FILTER)]
    export = [e for e in fs.read_log(str(log)) if e.get("event") == "excel_export"][0]
    assert rows[-1] == ["出力ID", export["details"]["export_id"]]
    assert f"{xlsx.name} に保存しました" in proc.stdout
    # how far it got: one "[n/N] OK" line per step on stderr, then the final line
    progress = [ln for ln in proc.stderr.splitlines() if ln.startswith("[")]
    total = len(progress) - 1
    assert progress[0] == f"[1/{total}] OK  GET /Login.aspx (200)  「生産管理システム - ログイン」"
    assert progress[1] == f"[2/{total}] OK  POST /Login.aspx (200)  「生産管理システム - メニュー」"
    assert all(ln.startswith(f"[{n}/{total}] OK  ") for n, ln in enumerate(progress[:-1], start=1))
    assert progress[-1] == f"[完了] すべての手順が終わりました（{total} 手順）"


def test_no_recorded_session_value_is_replayed(replay):
    """Session ids, one-time tokens and the URL key of the recording must not be in the script."""
    script, _server, _log, rec = replay
    source = _code_without_comments(script.read_text(encoding="utf-8"))  # comments may quote recorded values
    secrets = set()
    for flow in rec.flows:
        for name, value in flow.request.headers:
            if name.lower() == "cookie":
                for part in value.split(";"):
                    k, _, v = part.strip().partition("=")
                    if k in ("ASP.NET_SessionId", ".ASPXAUTH") and v:
                        secrets.add(v)
        for m in re.finditer(r"[?&]key=([^&]+)", flow.request.url):
            secrets.add(m.group(1))
    assert secrets, "the fixture should contain session values"
    leaked = sorted(s for s in secrets if s in source)
    assert leaked == []
    assert fs.CREDENTIALS[1] not in source  # the password is read from the environment


def test_second_run_logs_in_again(replay, tmp_path):
    script, _server, log, _rec = replay
    assert _run(script, tmp_path / "a").returncode == 0
    assert _run(script, tmp_path / "b").returncode == 0
    logins = [e for e in fs.read_log(str(log)) if e.get("event") == "login_ok"]
    assert len(logins) == 2 and logins[0]["session"] != logins[1]["session"]
    assert (tmp_path / "b" / fs.export_filename("01", "L11")).is_file()


def test_missing_password_stops_before_any_request(replay, tmp_path):
    script, _server, log, _rec = replay
    proc = _run(script, tmp_path / "out", password=None)
    assert proc.returncode != 0
    assert PASSWORD_ENV in proc.stderr and "設定されていません" in proc.stderr and "Traceback" not in proc.stderr
    assert _events(log) == []  # not even the login page was requested


@pytest.mark.parametrize("key", sorted(RECORDINGS))
def test_default_script_has_the_password_written_in_and_needs_no_input(key, tmp_path):
    """Without ``--redact`` (the default, also the GUI's) the recorded password is written into the
    script, so it replays the whole scenario with nothing to type: [試しに実行する] is one click."""
    port = _free_port()
    rec_path = tmp_path / "rec.json"
    _retarget(RECORDINGS[key], rec_path, port)
    script = tmp_path / "scrape_factory.py"
    assert cli.main(["generate", str(rec_path), "-o", str(script)]) == 0
    source = script.read_text(encoding="utf-8")
    assert fs.CREDENTIALS[1] in source and PASSWORD_ENV not in source and "設定されていません" not in source
    log = tmp_path / "site.log"
    server = fs.serve_in_thread(str(log), port)
    try:
        proc = _run(script, tmp_path / "out", password=None)
    finally:
        server.stop()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [e["event"] for e in _events(log)][:2] == ["login_page", "login_ok"]
    assert (tmp_path / "out" / fs.export_filename("01", "L11")).is_file()


def test_wrong_password_fails_with_a_plain_message(replay, tmp_path):
    script, _server, log, _rec = replay
    proc = _run(script, tmp_path / "out", password="wrong")
    assert proc.returncode != 0
    assert "login_fail" in [e["event"] for e in _events(log)]
    # the progress lines show where it stopped: the login page came back, the login step failed
    progress = [ln for ln in proc.stderr.splitlines() if ln.startswith("[")]
    assert progress[0].startswith("[1/") and progress[0].endswith("「生産管理システム - ログイン」")
    assert progress[1].startswith("[2/") and "失敗  POST /Login.aspx" in progress[1]
    assert proc.stderr.index(progress[1]) < proc.stderr.index("Traceback")
    # the menu's URL key cannot be found on the login page that came back
    assert "要素が見つかりません" in proc.stderr or "パターンに一致しませんでした" in proc.stderr


# ===== the 受注管理 mock: a real IE-engine recording with every pattern at once, replayed =====
# ``tests/fixtures/order_ie_recording.json`` was recorded through the GUI with the real recording browser
# (tests/test_real_engine.py::test_order_site_with_every_pattern_through_the_gui): the session id the
# login puts into every URL (``/oms/s/<SID>/...``, no cookie), one-time tokens in hidden fields, links, a
# script variable and an XMLHttpRequest header, a ``window.open`` child window that writes the chosen
# customer into its opener, a ``showModalDialog`` child window, a date picked in a calendar that pops up
# over the field, an order opened in another tab and a CSV export that checks the Referer
# (``order_site`` section of tests/ie_support.py).  The script is replayed against a fresh site with the
# recorded data and with data that changed since (``drift``: a new customer listed FIRST in the picker,
# the first order of the result cancelled, a new order).

ORDER_RECORDING = FIXTURES / "order_ie_recording.json"
ORDER_EVENTS = ["login_page", "login_ok", "menu", "search_page", "custpicker", "itempicker", "result", "order",
                "shipment", "export"]


@pytest.mark.parametrize("drift", [False, True], ids=["same_data", "changed_data"])
def test_order_recording_with_every_pattern_replays_on_a_fresh_site(drift, tmp_path):
    port = _free_port()
    rec_path = tmp_path / "rec.json"
    _retarget(ORDER_RECORDING, rec_path, port)
    script = tmp_path / "scrape_order.py"
    assert cli.main(["generate", str(rec_path), "-o", str(script)]) == 0
    log = tmp_path / "site.log"
    server = fs.order_serve_in_thread(str(log), port, drift=drift)
    try:
        proc = _run(script, tmp_path / "out", password=None)  # the password is written into the script
    finally:
        server.stop()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    entries = [e for e in fs.read_log(str(log)) if e.get("event") not in ("not_found", "redirect")]
    assert [e["event"] for e in entries] == ORDER_EVENTS, entries
    assert all(e["status"] < 400 for e in entries), entries
    sc = fs.ORDER_SCENARIO
    result = next(e["details"] for e in entries if e["event"] == "result")
    # the user's choices: the customer of the child window (not the picker's first row), the item of the
    # modal dialog, the date of the calendar and the default end of the period
    assert (result["customer"], result["item"], result["date_from"], result["date_to"]) == (
        sc["customer"], sc["item"], sc["date_from"], sc["date_to"])
    assert next(e["details"]["no"] for e in entries if e["event"] == "order") == sc["order"]
    csv = tmp_path / "out" / fs.order_export_filename(sc["customer"])
    rows = [line.split(",") for line in csv.read_bytes().decode("cp932").splitlines()]
    assert rows == fs.order_expected_csv(drift=drift)


def test_order_recording_replays_no_recorded_session_value(tmp_path):
    """Neither the session id of the URLs nor any one-time token of the recording is in the script."""
    rec = Recording.load(str(ORDER_RECORDING))
    script = tmp_path / "scrape_order.py"
    assert cli.main(["generate", str(ORDER_RECORDING), "-o", str(script)]) == 0
    source = _code_without_comments(script.read_text(encoding="utf-8"))  # comments may quote recorded values
    values = set()
    for flow in rec.flows:
        m = re.search(r"/oms/s/([A-Za-z0-9]{24})/", flow.request.url)
        if m:
            values.add(m.group(1))
        values.update(v for k, v in flow.request.query_pairs if k == "tk")
        values.update(v for k, v in flow.request.headers if k.lower() == "x-api-token")
        if flow.request.method == "POST":
            values.update(v for k, v in parse_qsl(flow.request.text()) if k in ("token", "loginToken"))
    assert len(values) >= 8, values
    assert sorted(v for v in values if v in source) == []
