"""Browser-level tests of the GUI with Playwright (Chromium).  Contract: DESIGN.md §13.6.

The Flask app runs in a daemon thread on a free port (``werkzeug.serving.make_server``); a real
Chromium drives the page: upload the fixture HAR, watch the step table, uncheck a flow, pick the
result step, generate, save.  Skipped cleanly when Playwright or a Chromium binary is unavailable.
"""

from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

pw_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed")
from playwright.sync_api import expect, sync_playwright  # noqa: E402

from reqrec.webapp import create_app  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
LOGIN_HAR = ROOT / "tests" / "fixtures" / "login_flow_chrome.har"
CHROMIUM_CANDIDATES = [os.environ.get("REQREC_CHROMIUM"), "/opt/pw-browsers/chromium"]
TIMEOUT_MS = 45_000

expect.set_options(timeout=TIMEOUT_MS)


# --------------------------------------------------------------------------- fixtures

@pytest.fixture(scope="module")
def server(tmp_path_factory):
    from werkzeug.serving import make_server

    workdir = tmp_path_factory.mktemp("gui_work")
    app = create_app(str(workdir), host="127.0.0.1", port=8765)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    port = srv.server_port
    app.extensions["reqrec"].port = port
    thread = threading.Thread(target=srv.serve_forever, name="reqrec-test-server", daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(url=f"http://127.0.0.1:{port}", workdir=workdir, app=app, port=port)
    finally:
        srv.shutdown()
        app.extensions["reqrec"].close()


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as pw:
        browser = None
        errors = []
        try:
            browser = pw.chromium.launch()
        except Exception as exc:  # default browser missing -> known binary
            errors.append(str(exc).splitlines()[0])
            for path in CHROMIUM_CANDIDATES:
                if not path or not os.path.exists(path):
                    continue
                try:
                    browser = pw.chromium.launch(executable_path=path)
                    break
                except Exception as exc2:
                    errors.append(str(exc2).splitlines()[0])
        if browser is None:
            pytest.skip("Chromium unavailable for Playwright: " + " / ".join(errors))
        try:
            yield browser
        finally:
            browser.close()


@pytest.fixture
def page(browser, server):
    context = browser.new_context(viewport={"width": 1400, "height": 1000}, locale="ja-JP")
    page = context.new_page()
    page.set_default_timeout(TIMEOUT_MS)
    js_errors: list[str] = []
    page.on("pageerror", lambda err: js_errors.append(str(err)))
    page.on("console", lambda msg: js_errors.append(msg.text) if msg.type == "error" else None)
    page.js_errors = js_errors  # type: ignore[attr-defined]
    page.goto(server.url + "/", wait_until="networkidle")
    try:
        yield page
    finally:
        context.close()


@pytest.fixture
def advanced(page):
    """The page switched from the default かんたん画面 to 詳細設定 (the five panels)."""
    expect(page.locator("#panel-easy")).to_be_visible()
    page.click("#mode-toggle")
    expect(page.locator("#nav")).to_be_visible()
    expect(page.locator("#mode-toggle")).to_have_text("かんたん画面に戻る")
    return page


def _upload_fixture(page):
    page.click('.nav-step[data-panel="load"]')
    page.set_input_files("#file-input", str(LOGIN_HAR))
    expect(page.locator("#btn-upload")).to_be_enabled()
    page.click("#btn-upload")
    rows = page.locator("#flow-tbody tr[data-flow-id]")
    expect(rows).to_have_count(14)
    expect(page.locator("#panel-steps")).to_have_class(re.compile(r"\bactive\b"))
    return rows


# --------------------------------------------------------------------------- tests

def test_page_loads_in_japanese(advanced):
    page = advanced
    expect(page).to_have_title(re.compile("reqrec"))
    expect(page.locator("#status-text")).to_contain_text("準備完了")
    for label in ("記録", "読み込み", "ステップ", "コード", "実行"):
        expect(page.locator("#nav")).to_contain_text(label)
    assert page.evaluate("document.body.dataset.token").strip() != ""
    assert page.js_errors == []


def test_upload_shows_step_table(advanced, server):
    page = advanced
    rows = _upload_fixture(page)
    expect(page.locator("#status-text")).to_contain_text("解析完了")
    expect(page.locator("#sum-steps")).to_have_text("5")
    expect(page.locator("#sum-kept")).to_have_text("8")
    expect(page.locator("#sum-dropped")).to_have_text("6")
    first = page.locator('#flow-tbody tr[data-flow-id="f0001"]')
    expect(first).to_have_class(re.compile(r"\bkept\b"))
    expect(first.locator("input[type=checkbox]")).to_be_checked()
    expect(first.locator(".step-no")).to_have_text("1")
    static = page.locator('#flow-tbody tr[data-flow-id="f0002"]')
    expect(static).to_have_class(re.compile(r"\bdropped\b"))
    expect(static.locator("input[type=checkbox]")).not_to_be_checked()
    expect(static.locator(".col-reason")).to_contain_text("静的ファイル")
    expect(static.locator(".col-ref")).to_contain_text("shop.example.test/login")
    expect(page.locator("#cur-flows")).to_contain_text("14")
    assert (server.workdir / "uploads" / "login_flow_chrome.har").is_file()
    # detail drawer
    first.click()
    expect(page.locator("#drawer")).to_be_visible()
    expect(page.locator("#dr-url")).to_contain_text("https://shop.example.test/login")
    expect(page.locator("#dr-resp-body")).to_contain_text("<")
    page.click('#drawer .tab[data-tab="req"]')
    expect(page.locator("#dr-req-headers")).to_contain_text("user-agent")
    page.click("#drawer-close")
    expect(page.locator("#drawer")).to_be_hidden()
    assert page.js_errors == []


def test_uncheck_kept_flow_marks_it_dropped(advanced):
    page = advanced
    _upload_fixture(page)
    row = page.locator('#flow-tbody tr[data-flow-id="f0010"]')
    expect(row).to_have_class(re.compile(r"\bkept\b"))
    row.locator("input[type=checkbox]").uncheck()
    row = page.locator('#flow-tbody tr[data-flow-id="f0010"]')  # table re-renders
    expect(row).to_have_class(re.compile(r"\bdropped\b"))
    expect(row.locator(".col-reason")).to_contain_text("手動で除外")
    expect(row.locator("input[type=checkbox]")).not_to_be_checked()
    expect(page.locator("#sum-steps")).to_have_text("4")
    # and back again
    page.locator('#flow-tbody tr[data-flow-id="f0010"] input[type=checkbox]').check()
    expect(page.locator('#flow-tbody tr[data-flow-id="f0010"]')).to_have_class(re.compile(r"\bkept\b"))
    expect(page.locator("#sum-steps")).to_have_text("5")
    # a dropped flow can be forced in
    page.locator('#flow-tbody tr[data-flow-id="f0002"] input[type=checkbox]').check()
    expect(page.locator('#flow-tbody tr[data-flow-id="f0002"]')).to_have_class(re.compile(r"\bkept\b"))
    expect(page.locator("#sum-steps")).to_have_text("6")
    assert page.js_errors == []


def test_choose_result_step(advanced):
    page = advanced
    _upload_fixture(page)
    page.locator('#flow-tbody tr[data-flow-id="f0009"] input[type=radio]').check()
    expect(page.locator("#sum-final")).to_contain_text("ステップ 2")
    expect(page.locator('#flow-tbody tr[data-flow-id="f0009"]')).to_have_class(re.compile(r"\bfinal\b"))
    expect(page.locator('#flow-tbody tr[data-flow-id="f0009"] .col-reason')).to_contain_text("結果")
    page.click("#btn-final-clear")
    expect(page.locator("#sum-final")).to_contain_text("最後のステップ")
    assert page.js_errors == []


def test_generate_save_and_run_panel(advanced, server):
    page = advanced
    _upload_fixture(page)
    page.click("#btn-goto-code")
    expect(page.locator("#panel-code")).to_have_class(re.compile(r"\bactive\b"))
    page.click("#btn-generate")
    preview = page.locator("#code-preview")
    expect(preview).to_contain_text("def step_01_")
    expect(preview).to_contain_text("import requests")
    expect(page.locator("#gen-secrets")).to_contain_text("REQREC_PASSWORD")
    expect(page.locator("#script-name")).to_have_value(re.compile(r"^scrape_"))
    page.fill("#script-name", "browser_test")
    page.click("#btn-save")
    expect(page.locator("#save-result")).to_contain_text("保存しました")
    saved = server.workdir / "scripts" / "browser_test.py"
    assert saved.is_file()
    compile(saved.read_text(encoding="utf-8"), str(saved), "exec")
    download = page.locator("#btn-download")
    expect(download).not_to_have_class(re.compile(r"\bdisabled\b"))
    assert download.get_attribute("href") == "/api/scripts/browser_test.py/download"
    # the run panel knows the script and asks for the secret
    page.click("#btn-goto-run")
    expect(page.locator("#panel-run")).to_have_class(re.compile(r"\bactive\b"))
    expect(page.locator("#run-script")).to_have_value("browser_test.py")
    expect(page.locator('#env-inputs input[data-env="REQREC_PASSWORD"]')).to_have_attribute("type", "password")
    assert page.js_errors == []


def test_run_tiny_script_in_browser(advanced, server):
    page = advanced
    script = server.workdir / "scripts" / "hello_env.py"
    script.write_text("import os\nprint('ENV=' + os.environ.get('REQREC_PASSWORD', '(unset)'))\n", encoding="utf-8")
    page.click('.nav-step[data-panel="run"]')
    page.click("#btn-refresh-scripts")
    page.select_option("#run-script", "hello_env.py")
    page.click("#btn-run")
    expect(page.locator("#run-state")).to_contain_text("正常終了")
    expect(page.locator("#run-stdout")).to_contain_text("ENV=(unset)")
    page.fill("#output-name", "browser_out.txt")
    page.click("#btn-save-output")
    expect(page.locator("#save-output-result")).to_contain_text("保存しました")
    assert (server.workdir / "outputs" / "browser_out.txt").read_text(encoding="utf-8") == "ENV=(unset)\n"
    assert page.js_errors == []


# --------------------------------------------------------------------------- かんたん画面 (DESIGN.md §13.11)

def test_easy_screen_is_the_default(page):
    expect(page.locator("#panel-easy")).to_be_visible()
    expect(page.locator("#nav")).to_be_hidden()
    expect(page.locator("#easy-start")).to_contain_text("記録をはじめる")
    expect(page.locator("#easy-ready")).to_contain_text("記録")
    assert page.js_errors == []


def test_easy_builds_from_a_loaded_recording_and_runs_it(page, server):
    # load a HAR in 詳細設定, come back, and turn it into a script from the easy screen
    page.click("#mode-toggle")
    _upload_fixture(page)
    page.click("#mode-toggle")
    expect(page.locator("#panel-easy")).to_be_visible()
    expect(page.locator("#easy-loaded")).to_be_visible()
    expect(page.locator("#easy-loaded-count")).to_have_text("14")
    page.click("#easy-build-loaded")
    expect(page.locator("#easy-done")).to_be_visible()
    expect(page.locator("#easy-done-name")).to_contain_text(".py")
    expect(page.locator("#easy-done-steps")).to_contain_text("5 手順")
    expect(page.locator("#easy-done-secrets")).to_contain_text("パスワード")  # friendly name, not the env var
    expect(page.locator("#easy-done-secrets")).not_to_contain_text("REQREC_")
    expect(page.locator("#easy-done-files")).to_be_visible()  # the CSV export is listed as a saved file
    expect(page.locator("#easy-done-files")).to_contain_text("export.csv")
    name = page.locator("#easy-done-name").inner_text().strip()
    assert (server.workdir / "scripts" / name).is_file()
    assert page.locator("#easy-download").get_attribute("href") == f"/api/scripts/{name}/download"
    # 試しに実行: the secret is asked for; the fixture hosts do not exist, so the run fails with a plain hint
    page.click("#easy-test-run")
    expect(page.locator('#easy-env input[data-env="REQREC_PASSWORD"]')).to_have_attribute("type", "password")
    page.fill('#easy-env input[data-env="REQREC_PASSWORD"]', "x")
    page.click("#easy-run-btn")
    expect(page.locator("#easy-run-state")).to_contain_text("エラー", timeout=60000)
    expect(page.locator("#easy-run-hint")).to_be_visible()
    assert page.js_errors == []


def test_mode_choice_is_remembered(page, server):
    page.click("#mode-toggle")
    expect(page.locator("#nav")).to_be_visible()
    page.reload(wait_until="networkidle")
    expect(page.locator("#nav")).to_be_visible()
    page.click("#mode-toggle")
    expect(page.locator("#panel-easy")).to_be_visible()
    assert page.js_errors == []


# --------------------------------------------------------------------------- review fixes (easy screen)

def _load_into_server(server, recording):
    server.app.extensions["reqrec"].set_recording(recording, ["test"], append=False)


def _build_from_loaded(page):
    page.reload(wait_until="networkidle")
    expect(page.locator("#easy-loaded")).to_be_visible()
    page.click("#easy-build-loaded")
    expect(page.locator("#easy-done")).to_be_visible()


def test_easy_done_shows_plan_warnings_in_japanese_and_loop_downloads(page, server):
    from tests.test_webapp_easy import _synthetic_recording

    _load_into_server(server, _synthetic_recording())
    _build_from_loaded(page)
    warnings = page.locator("#easy-done-warning-list")
    expect(warnings).to_contain_text("毎回変わるもののようですが")
    expect(warnings).to_contain_text("「sid」の値")
    expect(warnings).not_to_contain_text("looks dynamic")
    files = page.locator("#easy-done-files")
    expect(files).to_contain_text("list.csv")
    expect(files).to_contain_text("p.csv")
    expect(files).to_contain_text("繰り返しのたびに保存")
    expect(files).not_to_contain_text("view.html")  # inline: shown in the browser, not saved
    assert page.js_errors == []


def test_easy_windows_auth_inputs_keep_their_instruction(page, server):
    from reqrec.importers import load_recording

    _load_into_server(server, load_recording(str(ROOT / "tests" / "fixtures" / "legacy_webforms_ntlm.har")))
    _build_from_loaded(page)
    secrets = page.locator("#easy-done-secrets")
    expect(secrets).to_contain_text("Windows 認証 (NTLM) のパスワード")
    expect(secrets).to_contain_text("入力不要")
    expect(secrets).not_to_contain_text("ユーザー名")  # written into the script as its default
    page.click("#easy-test-run")
    user = page.locator('#easy-env input[data-env="REQREC_NTLM_USER"]')
    expect(user).to_have_attribute("type", "text")
    expect(user).to_have_value("EXAMPLE\\taro")
    expect(page.locator("#easy-env")).to_contain_text("Windows 認証 (NTLM) のユーザー名")
    expect(page.locator("#easy-env")).to_contain_text("reqrec[sspi]")
    expect(page.locator("#easy-env")).not_to_contain_text("記録したときと同じ値")
    assert page.js_errors == []


def _fail_start(page, kind, message):
    import json

    page.route("**/api/record/start", lambda route: route.fulfill(
        status=500, content_type="application/json", body=json.dumps({"error": message, "kind": kind})))


@pytest.mark.skipif(os.name == "nt" and not __import__("reqrec.iehost", fromlist=["x"]).availability("x")["available"],
                    reason="the easy screen cannot record on this Windows PC")
def test_easy_start_errors_are_explained_by_kind(page, server):
    from reqrec.recorder.run import mitmproxy_available

    if not mitmproxy_available():
        pytest.skip("mitmproxy not installed: the easy screen cannot start")
    _fail_start(page, "proxy", "記録用プロキシを起動できませんでした: port busy")
    page.click("#easy-start")
    err = page.locator("#easy-error")
    expect(err).to_contain_text("中継サーバーが動きませんでした")
    expect(err).not_to_contain_text("RecBrowser.exe")
    expect(page.locator("#easy-ready")).not_to_contain_text("前回、起動できませんでした")
    page.unroute("**/api/record/start")
    _fail_start(page, "iehost", "記録用ブラウザを起動できませんでした: [WinError 1260]")
    page.click("#easy-start")
    expect(err).to_contain_text("RecBrowser.exe")
    if os.name == "nt":
        expect(page.locator("#easy-ready")).to_contain_text("前回、起動できませんでした")
    # the browser logs the two (intended) 500 responses; nothing else may fail
    assert [e for e in page.js_errors if "status of 500" not in e] == []


class _FakeRecorder:
    """A running recording as far as the page can tell (status only); ``stop`` / ``load_recording`` work."""

    def __init__(self, out):
        self.running = True
        self.out = out
        self.port = 18555
        self.listen_host = "127.0.0.1"
        self.command_builder = object()
        self.stopped = 0

    def status(self):
        return {"running": self.running, "flows": 3, "out": self.out, "out_name": os.path.basename(self.out),
                "pid": 1, "exit_code": None if self.running else 0, "started_at": 1.0, "stopped_at": None,
                "port": self.port, "listen_host": self.listen_host, "hosts": [], "stdout_tail": "",
                "stderr_tail": "", "error": None, "command": []}

    def stop(self, timeout=None):
        self.stopped += 1
        self.running = False
        return 0

    def forget(self):
        self.out = None
        return True

    def close(self):
        self.running = False

    def load_recording(self):
        from reqrec.importers import load_recording

        return load_recording(str(LOGIN_HAR))


class _FakeBrowser:
    pid = 4321
    log_path = None

    def __init__(self):
        self.code = None

    def poll(self):
        return self.code

    def close(self, timeout=5.0):
        if self.code is None:
            self.code = 0
        return self.code


@pytest.mark.parametrize("origin, auto_stops", [("advanced", False), ("easy", True)])
def test_auto_stop_only_for_easy_started_recordings(page, server, origin, auto_stops):
    state = server.app.extensions["reqrec"]
    real_recorder = state.recorder
    fake, browser = _FakeRecorder(str(server.workdir / "recordings" / "rec_fake.json")), _FakeBrowser()
    stops = []
    page.on("request", lambda req: stops.append(req.post_data) if req.url.endswith("/api/record/stop") else None)
    try:
        with state.lock:
            state.recorder = fake
            state.browser = browser
            state.record_browser_kind = "iehost"
            state.record_origin = origin
            state.record_append = False
        page.reload(wait_until="networkidle")  # the page picks the recording up after a reload
        expect(page.locator("#easy-recording")).to_be_visible()
        page.wait_for_timeout(1500)  # the poller sees the recording browser running
        browser.code = 0  # the user closes the recording browser
        if auto_stops:
            expect(page.locator("#easy-done")).to_be_visible()
            assert stops and all("append" not in (s or "") for s in stops), stops
        else:
            expect(page.locator("#status-text")).to_contain_text("記録用ブラウザが閉じられました")
            page.wait_for_timeout(2500)
            expect(page.locator("#easy-recording")).to_be_visible()  # still recording: only pointed out
            assert stops == []
    finally:
        with state.lock:
            state.recorder = real_recorder
            state.browser = None
            state.record_browser_kind = None
            state.record_origin = None
    assert page.js_errors == []
