"""End-to-end: the GUI's recording path with the **real** ``mitmdump`` (DESIGN.md §13.6).

This is the path a user takes in 「1 記録」: ``RecorderManager`` spawns ``mitmdump`` with the reqrec
addon exactly as ``reqrec gui`` does, the browser (here: ``requests`` with ``proxies=``) talks to the
site of ``tests/e2e/server.py`` through that proxy, 「記録停止して読み込む」 loads the recording and
the steps table lists the proxied requests.  The first test drives the JSON API with Flask's test
client and goes on to generate, save and *run* the script from the GUI against a restarted site
(fresh tokens); the second does the recording through a real browser with Playwright.

Skipped when mitmproxy is not installed (the browser test also when Playwright / Chromium are missing).
"""

from __future__ import annotations

import os
import re
import socket
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

import pytest
import requests

from reqrec.model import Recording
from reqrec.recorder.run import mitmproxy_available
from reqrec.webapp import TOKEN_HEADER, create_app
from tests.e2e.server import PASSWORD, USERNAME, restart_server, start_server, stop_server

pytestmark = [
    pytest.mark.skipif(not mitmproxy_available(), reason="mitmproxy (mitmdump) not installed"),
    pytest.mark.skipif(os.name == "nt", reason="SIGINT handling differs on Windows"),
]

TOKEN = "e2e-gui-token"
#: GET /login, POST /login (302), GET /dashboard, 3 x GET /api/items, GET /export, GET /static/app.css
EXPECTED_FLOWS = 8
PROXY_START_TIMEOUT = 60.0
CHROMIUM_CANDIDATES = [os.environ.get("REQREC_CHROMIUM"), "/opt/pw-browsers/chromium"]


# --------------------------------------------------------------------------- helpers

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until(pred: Callable[[], bool], timeout: float, what: str, interval: float = 0.2) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {what}")


def _wait_for_proxy(port: int, still_alive: Callable[[], str | None], timeout: float = PROXY_START_TIMEOUT) -> None:
    """Block until mitmdump accepts connections; ``still_alive()`` returns an error text once it died."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        err = still_alive()
        if err:
            raise AssertionError(f"mitmdump died before listening: {err}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return
        except OSError:
            time.sleep(0.2)
    raise AssertionError("the recording proxy never opened its port")


def _drive_site_through_proxy(base_url: str, proxy_port: int) -> dict[str, str]:
    """The user's browsing session: login -> dashboard -> 3 pages -> CSV export (+ one static file)."""
    session = requests.Session()
    session.trust_env = False  # never use the sandbox's HTTP(S)_PROXY for the local site
    proxies = {"http": f"http://127.0.0.1:{proxy_port}", "https": f"http://127.0.0.1:{proxy_port}"}
    resp = session.get(base_url + "/login", proxies=proxies, timeout=20)
    resp.raise_for_status()
    token = re.search(r'name="_token" value="([^"]+)"', resp.text).group(1)
    resp = session.post(base_url + "/login", data={"_token": token, "username": USERNAME, "password": PASSWORD},
                        proxies=proxies, timeout=20)
    resp.raise_for_status()
    assert resp.url.endswith("/dashboard"), resp.url
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', resp.text).group(1)
    api_token = re.search(r'window\.API_TOKEN = "([^"]+)"', resp.text).group(1)
    sig = re.search(r'/export\?sig=([^"]+)"', resp.text).group(1)
    headers = {"X-CSRF-Token": csrf, "Authorization": f"Bearer {api_token}"}
    for page in (1, 2, 3):
        session.get(f"{base_url}/api/items?page={page}", headers=headers, proxies=proxies, timeout=20).raise_for_status()
    session.get(f"{base_url}/export?sig={sig}", proxies=proxies, timeout=20).raise_for_status()
    session.get(base_url + "/static/app.css", proxies=proxies, timeout=20).raise_for_status()
    return {"login_token": token, "csrf": csrf, "api_token": api_token, "sig": sig}


# --------------------------------------------------------------------------- fixtures

@pytest.fixture
def gui(tmp_path: Path):
    workdir = tmp_path / "gui_work"
    app = create_app(str(workdir), host="127.0.0.1", port=_free_port(), token=TOKEN, TESTING=True)
    client = app.test_client()
    headers = {TOKEN_HEADER: TOKEN}
    try:
        yield SimpleNamespace(app=app, client=client, workdir=workdir, H=headers, state=app.extensions["reqrec"])
    finally:
        app.extensions["reqrec"].close()


# --------------------------------------------------------------------------- JSON API path

def test_record_with_real_mitmdump_then_plan_generate_and_run(gui):
    client, H, state = gui.client, gui.H, gui.state
    server, base_url = start_server()
    proxy_port = _free_port()
    try:
        # -- 記録開始 -------------------------------------------------------------------------
        r = client.post("/api/record/start", json={"port": proxy_port, "hosts": ["127.0.0.1"], "listen_host": "127.0.0.1"}, headers=H)
        assert r.status_code == 200, r.get_json()
        started = r.get_json()
        assert started["status"]["running"] is True and started["status"]["error"] is None
        assert started["proxy_address"] == f"127.0.0.1:{proxy_port}"
        assert re.fullmatch(r"rec_\d{8}_\d{6}\.json", started["out"])
        assert f"http://127.0.0.1:{proxy_port}" in started["instructions"] and "127.0.0.1" in started["instructions"]
        assert started["status"]["hosts"] == ["127.0.0.1"]

        def died() -> str | None:
            st = client.get("/api/record/status").get_json()
            return None if st["running"] else (st["error"] or st["stderr_tail"] or "exited")

        _wait_for_proxy(proxy_port, died)

        # -- the user browses through the proxy ------------------------------------------------
        tokens = _drive_site_through_proxy(base_url, proxy_port)
        _wait_until(lambda: client.get("/api/record/status").get_json()["flows"] == EXPECTED_FLOWS, 30,
                    f"{EXPECTED_FLOWS} recorded flows (live count)")
        live = client.get("/api/record/status").get_json()
        assert live["running"] is True and live["flows"] == EXPECTED_FLOWS
        assert client.get("/api/state").get_json()["recorder"]["running"] is True

        # -- 記録停止して読み込む -------------------------------------------------------------
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 200, r.get_json()
        stopped = r.get_json()
        assert stopped["loaded"] is True and stopped["flows"] == EXPECTED_FLOWS
        assert stopped["sources"] == [f"recordings/{started['out']}"]
        assert stopped["excluded_self"] == 0 and stopped["exit_code"] == 0
        assert (gui.workdir / "recordings" / started["out"]).is_file()
        assert state.recorder.running is False
        rec = Recording.load(str(gui.workdir / "recordings" / started["out"]))
        assert rec.meta["source"] == "mitmproxy" and rec.meta["hosts"] == ["127.0.0.1"]
        assert [f.request.path for f in rec.flows] == [
            "/login", "/login", "/dashboard", "/api/items", "/api/items", "/api/items", "/export", "/static/app.css",
        ]
        assert rec.flows[1].request.text() == f"_token={tokens['login_token']}&username={USERNAME}&password=Secr3t%21"
        assert rec.flows[1].response.status == 302
        listed = client.get("/api/recordings").get_json()["files"]
        assert any(f["name"] == started["out"] and f["folder"] == "recordings" and f["flows"] == EXPECTED_FLOWS for f in listed)

        # -- 3 ステップ: the table shows every proxied request --------------------------------
        plan = client.post("/api/plan", json={}, headers=H).get_json()
        assert plan["steps_kept"] == 4 and plan["flows_total"] == EXPECTED_FLOWS and plan["dropped"] == 1
        rows = {(f["method"], f["url"].split(str(server.server_port), 1)[1]): f for f in plan["flows"]}
        assert rows[("GET", "/login")]["kept"] is True and rows[("GET", "/login")]["step_index"] == 1
        assert rows[("POST", "/login")]["step_index"] == 2 and rows[("POST", "/login")]["status"] == 302
        assert rows[("GET", "/dashboard")]["step_index"] == 2 and rows[("GET", "/dashboard")]["referer"] is None
        assert rows[("GET", "/api/items?page=1")]["step_index"] == 3 and rows[("GET", "/api/items?page=3")]["step_index"] == 3
        assert rows[("GET", f"/export?sig={tokens['sig']}")]["step_index"] == 4
        css = rows[("GET", "/static/app.css")]
        assert css["kept"] is False and css["reason"].startswith("static asset") and css["step_index"] is None
        steps = plan["steps"]
        assert [s["method"] for s in steps] == ["GET", "POST", "GET", "GET"]
        assert steps[1]["source_flow_ids"] == ["f0002", "f0003"] and steps[1]["status_chain"] == [302, 200]
        assert steps[2]["loop"] == {"var": "page", "count": 3, "values": ["1", "2", "3"], "numeric_range": [1, 3]}
        assert {e["name"] for e in steps[0]["extractors"]} == {"_token"}
        kinds = {(e["kind"], e.get("name") or e.get("selector")) for e in steps[1]["extractors"]}
        assert ("html_meta", "csrf-token") in kinds and ("html_attr", "#export-link") in kinds
        assert any(e["kind"] == "regex" and "API_TOKEN" in e["pattern"] for e in steps[1]["extractors"])
        assert plan["env_vars"] == ["REQREC_PASSWORD"] and plan["auth"] is None

        # -- 4 コード -> 保存 -> 5 実行 against a RESTARTED site (all tokens change) -----------
        gen = client.post("/api/generate", json={}, headers=H).get_json()
        compile(gen["code"], "gui_recorded.py", "exec")
        assert PASSWORD not in gen["code"] and "os.environ.get('REQREC_PASSWORD'" in gen["code"]
        executable = "\n".join(ln.split("  # ")[0] for ln in gen["code"].splitlines() if not ln.lstrip().startswith("#"))
        for value in (tokens["csrf"], tokens["api_token"], tokens["sig"], tokens["login_token"]):
            assert value not in executable  # recorded tokens survive only in comments (記録時の値)
        assert [s["env_var"] for s in gen["secrets"]] == ["REQREC_PASSWORD"]
        saved = client.post("/api/scripts/save", json={"name": "recorded_site", "code": gen["code"]}, headers=H).get_json()
        assert saved["name"] == "recorded_site.py"

        server, base_url = restart_server(server)
        r = client.post("/api/run", json={"name": "recorded_site.py",
                                          "env": {"REQREC_PASSWORD": PASSWORD, "NO_PROXY": "127.0.0.1,localhost"}}, headers=H)
        assert r.status_code == 200, r.get_json()
        _wait_until(lambda: client.get("/api/run/status").get_json()["running"] is False, 60, "the script to finish")
        status = client.get("/api/run/status").get_json()
        assert status["exit_code"] == 0, status["stderr_tail"]
        assert "id,name" in status["stdout_tail"] and "item-1-1" in status["stdout_tail"]
        site = server.site
        posted = site.requests_for("POST", "/login")
        assert len(posted) == 1 and posted[0]["form"]["_token"] in site.issued_tokens("login_token")
        assert posted[0]["form"]["_token"] != tokens["login_token"]  # fresh token, not the recorded one
        assert [e["route"] for e in site.log] == [
            "/login", "/login", "/dashboard", "/api/items", "/api/items", "/api/items", "/export",
        ]
        items = site.requests_for("GET", "/api/items")
        assert all(e["headers"]["authorization"].split(" ", 1)[1] in site.issued_tokens("api_token") for e in items)
        assert [e["query"]["page"] for e in items] == ["1", "2", "3"]
        out = client.post("/api/run/save_output", json={"name": "recorded_site_out.txt"}, headers=H).get_json()
        assert (gui.workdir / "outputs" / "recorded_site_out.txt").read_text(encoding="utf-8").startswith("id,name")
        assert out["size"] > 0
    finally:
        if state.recorder.running:
            state.recorder.stop()
        stop_server(server)


def test_record_stop_without_traffic_reports_japanese_error(gui):
    """Stopping a recording nobody browsed through must not load an empty recording."""
    client, H, state = gui.client, gui.H, gui.state
    proxy_port = _free_port()
    r = client.post("/api/record/start", json={"port": proxy_port, "hosts": ["127.0.0.1"]}, headers=H)
    assert r.status_code == 200, r.get_json()
    try:
        def died() -> str | None:
            st = client.get("/api/record/status").get_json()
            return None if st["running"] else (st["error"] or "exited")

        _wait_for_proxy(proxy_port, died)
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 400
        body = r.get_json()
        assert "フロー" in body["error"] or "記録ファイル" in body["error"]
        assert client.get("/api/state").get_json()["recording"]["loaded"] is False
    finally:
        if state.recorder.running:
            state.recorder.stop()


# --------------------------------------------------------------------------- browser path (Playwright)

def _launch_chromium(pw):
    errors = []
    try:
        return pw.chromium.launch()
    except Exception as exc:  # default browser missing -> known binary
        errors.append(str(exc).splitlines()[0])
    for path in CHROMIUM_CANDIDATES:
        if path and os.path.exists(path):
            try:
                return pw.chromium.launch(executable_path=path)
            except Exception as exc:
                errors.append(str(exc).splitlines()[0])
    pytest.skip("Chromium unavailable for Playwright: " + " / ".join(errors))


def test_record_panel_in_real_browser_loads_recording_into_steps_table(tmp_path: Path):
    pw_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed")
    from werkzeug.serving import make_server

    workdir = tmp_path / "gui_work"
    app = create_app(str(workdir), host="127.0.0.1", port=8765)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    gui_port = srv.server_port
    app.extensions["reqrec"].port = gui_port
    threading.Thread(target=srv.serve_forever, name="reqrec-gui-e2e", daemon=True).start()
    server, base_url = start_server()
    proxy_port = _free_port()
    js_errors: list[str] = []
    try:
        with pw_api.sync_playwright() as pw:
            browser = _launch_chromium(pw)
            try:
                context = browser.new_context(viewport={"width": 1400, "height": 1000}, locale="ja-JP")
                page = context.new_page()
                page.set_default_timeout(60_000)
                pw_api.expect.set_options(timeout=60_000)
                expect = pw_api.expect
                page.on("pageerror", lambda err: js_errors.append(str(err)))
                page.on("console", lambda msg: js_errors.append(msg.text) if msg.type == "error" else None)
                page.goto(f"http://127.0.0.1:{gui_port}/", wait_until="networkidle")

                page.click('.nav-step[data-panel="record"]')
                page.fill("#rec-port", str(proxy_port))
                page.fill("#rec-hosts", "127.0.0.1")
                page.click("#btn-rec-start")
                expect(page.locator("#rec-state-text")).to_contain_text("記録中")
                expect(page.locator("#rec-proxy-address")).to_have_text(f"127.0.0.1:{proxy_port}")
                expect(page.locator("#status-text")).to_contain_text(f"127.0.0.1:{proxy_port}")
                expect(page.locator("#btn-rec-start")).to_be_disabled()
                expect(page.locator("#btn-rec-stop")).to_be_enabled()
                state = app.extensions["reqrec"]
                _wait_for_proxy(proxy_port, lambda: None if state.recorder.running else (state.recorder.status()["error"] or "exited"))

                _drive_site_through_proxy(base_url, proxy_port)
                expect(page.locator("#rec-flow-count")).to_have_text(str(EXPECTED_FLOWS))  # live count

                page.click("#btn-rec-stop")
                expect(page.locator("#panel-steps")).to_have_class(re.compile(r"\bactive\b"))
                rows = page.locator("#flow-tbody tr[data-flow-id]")
                expect(rows).to_have_count(EXPECTED_FLOWS)
                expect(page.locator("#status-text")).to_contain_text("解析完了")
                expect(page.locator("#sum-steps")).to_have_text("4")
                expect(page.locator("#sum-kept")).to_have_text("7")
                expect(page.locator("#sum-dropped")).to_have_text("1")
                expect(page.locator('#flow-tbody tr[data-flow-id="f0001"] .col-url')).to_contain_text("/login")
                expect(page.locator('#flow-tbody tr[data-flow-id="f0001"] .step-no')).to_have_text("1")
                expect(page.locator('#flow-tbody tr[data-flow-id="f0003"] .col-url')).to_contain_text("/dashboard")
                expect(page.locator('#flow-tbody tr[data-flow-id="f0003"] .step-no')).to_have_text("2")
                expect(page.locator('#flow-tbody tr[data-flow-id="f0007"] .col-url')).to_contain_text("/export")
                expect(page.locator('#flow-tbody tr[data-flow-id="f0008"]')).to_have_class(re.compile(r"\bdropped\b"))
                expect(page.locator('#flow-tbody tr[data-flow-id="f0008"] .col-reason')).to_contain_text("静的ファイル")
                expect(page.locator("#cur-sources")).to_contain_text("recordings/rec_")
                page.click('.nav-step[data-panel="record"]')
                expect(page.locator("#rec-state-text")).to_contain_text("停止中")
                expect(page.locator("#rec-flow-count")).to_have_text(str(EXPECTED_FLOWS))
                assert state.recorder.running is False
                assert len(list((workdir / "recordings").glob("rec_*.json"))) == 1
                context.close()
            finally:
                browser.close()
    finally:
        try:
            app.extensions["reqrec"].close()
        finally:
            srv.shutdown()
            stop_server(server)
    assert js_errors == []
