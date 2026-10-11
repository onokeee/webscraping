"""Tests for the e2e harness itself: the fake site's token enforcement and the capture helper."""

from __future__ import annotations

import re
import time

import pytest
import requests

from reqrec.model import Recording
from tests.e2e import server as site_server
from tests.e2e.capture import (
    BROWSER_HEADERS,
    capture,
    default_scenario,
    flow_from_response,
    make_session,
)
from tests.e2e.server import (
    LAST_PAGE,
    PASSWORD,
    TOKEN_KINDS,
    USERNAME,
    Site,
    restart_server,
    start_server,
    stop_server,
)

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
