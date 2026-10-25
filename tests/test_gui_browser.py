"""Browser-level tests of the GUI with Playwright (Chromium).  Contract: DESIGN.md §13.6.

The Flask app runs in a daemon thread on a free port (``werkzeug.serving.make_server``); a real
Chromium drives the page: a HAR file becomes a script on the かんたん画面, then 詳細設定 shows the steps,
unchecks a flow, picks the result step, rebuilds from the settings, edits the code by hand, saves and
runs it.  Skipped cleanly when Playwright or a Chromium binary is unavailable.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

pw_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed")
from playwright.sync_api import expect, sync_playwright  # noqa: E402

from reqrec import create_app  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
LOGIN_HAR = ROOT / "tests" / "fixtures" / "login_flow_chrome.har"
CHROMIUM_CANDIDATES = [os.environ.get("REQREC_CHROMIUM"), "/opt/pw-browsers/chromium"]
TIMEOUT_MS = 45_000
#: What the patched ``iehost.availability`` reports: the in-app recording browser can be used.
RECBROWSER_AVAILABLE = {"available": True, "reason": None, "exe": "RecBrowser.exe", "built": True,
                        "source": "RecBrowser.cs", "csc": "csc.exe", "prebuilt": None}

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


def _build_from_har(page, path: Path = LOGIN_HAR) -> str:
    """かんたん画面 [HAR ファイルから作る]: the file is uploaded and turned into a saved script at once."""
    expect(page.locator("#panel-easy")).to_be_visible()
    page.set_input_files("#easy-har-input", str(path))
    expect(page.locator("#easy-done")).to_be_visible()
    return page.locator("#easy-done-name").inner_text().strip()


def _open_detail(page):
    page.click("#easy-open-detail")
    expect(page.locator("#panel-detail")).to_be_visible()
    expect(page.locator("#panel-easy")).to_be_hidden()
    expect(page.locator("#mode-toggle")).to_have_text("かんたん画面に戻る")
    rows = page.locator("#flow-tbody tr[data-flow-id]")
    expect(rows).to_have_count(8)  # the flows the script uses (the others only with 「使わない通信も表示」)
    return rows


# --------------------------------------------------------------------------- tests

def test_page_loads_in_japanese(page):
    expect(page).to_have_title(re.compile("reqrec"))
    expect(page.locator("#status-text")).to_contain_text("準備完了")
    expect(page.locator("#panel-easy")).to_be_visible()
    expect(page.locator("#panel-detail")).to_be_hidden()
    expect(page.locator("#easy-start")).to_contain_text("記録をはじめる")
    expect(page.locator("#easy-ready")).to_contain_text("記録")
    expect(page.locator("#easy-har-pick")).to_be_visible()
    assert page.evaluate("document.body.dataset.token").strip() != ""
    # nothing recorded yet: 詳細設定 says how to get a script
    page.click("#mode-toggle")
    expect(page.locator("#detail-empty")).to_be_visible()
    expect(page.locator("#detail-body")).to_be_hidden()
    assert page.js_errors == []


def test_har_file_becomes_a_script_on_the_easy_screen(page, server):
    name = _build_from_har(page)
    assert name.endswith(".py") and (server.workdir / "scripts" / name).is_file()
    assert (server.workdir / "uploads" / "login_flow_chrome.har").is_file()
    expect(page.locator("#easy-done-steps")).to_contain_text("5 手順")
    expect(page.locator("#easy-done-secrets")).to_be_hidden()  # the password is written into the script
    expect(page.locator("#easy-done-files")).to_be_visible()  # the CSV export is listed as a saved file
    expect(page.locator("#easy-done-files")).to_contain_text("export.csv")
    assert page.locator("#easy-download").get_attribute("href") == f"/api/scripts/{name}/download"
    # 試しに実行: nothing to type; the fixture hosts do not exist, so the run fails with a plain hint and
    # the result box says at which step it stopped
    page.click("#easy-test-run")
    expect(page.locator("#easy-env")).to_contain_text("入力するものはありません")
    assert page.locator("#easy-env input").count() == 0
    page.click("#easy-run-btn")
    expect(page.locator("#easy-run-state")).to_contain_text("エラー", timeout=60000)
    expect(page.locator("#easy-run-hint")).to_be_visible()
    expect(page.locator("#easy-run-out")).to_contain_text("[1/5] 失敗  GET /login")
    expect(page.locator("#easy-run-err")).not_to_contain_text("[1/5]")  # progress lines are not errors
    assert page.js_errors == []


def test_detail_screen_shows_the_script_and_its_steps(page, server):
    name = _build_from_har(page)
    rows = _open_detail(page)
    expect(page.locator("#detail-script")).to_have_text(name)
    expect(page.locator("#detail-source")).to_contain_text("uploads/login_flow_chrome")
    editor = page.locator("#code-editor")
    expect(editor).to_have_value(re.compile(r"import requests[\s\S]*def step_01_"))
    expect(editor).to_be_editable()
    expect(page.locator("#code-dirty")).to_be_hidden()
    expect(page.locator("#sum-steps")).to_have_text("5")
    expect(page.locator("#sum-kept")).to_have_text("8")
    expect(page.locator("#sum-dropped")).to_have_text("6")
    page.check("#show-dropped")
    expect(rows).to_have_count(14)
    first = page.locator('#flow-tbody tr[data-flow-id="f0001"]')
    expect(first).to_have_class(re.compile(r"\bkept\b"))
    expect(first.locator("input[type=checkbox]")).to_be_checked()
    expect(first.locator(".step-no")).to_have_text("1")
    static = page.locator('#flow-tbody tr[data-flow-id="f0002"]')
    expect(static).to_have_class(re.compile(r"\bdropped\b"))
    expect(static.locator("input[type=checkbox]")).not_to_be_checked()
    expect(static.locator(".col-reason")).to_contain_text("静的ファイル")
    expect(static.locator(".col-ref")).to_contain_text("shop.example.test/login")
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


def test_detail_steps_and_settings_rebuild_the_same_script(page, server):
    name = _build_from_har(page)
    _open_detail(page)
    script = server.workdir / "scripts" / name
    note = page.locator("#regen-note")
    expect(note).to_be_hidden()
    # uncheck a step's flow: the table follows at once, the code only after [設定から作り直す]
    row = page.locator('#flow-tbody tr[data-flow-id="f0010"]')
    expect(row).to_have_class(re.compile(r"\bkept\b"))
    page.check("#show-dropped")
    row.locator("input[type=checkbox]").uncheck()
    row = page.locator('#flow-tbody tr[data-flow-id="f0010"]')  # table re-renders
    expect(row).to_have_class(re.compile(r"\bdropped\b"))
    expect(row.locator(".col-reason")).to_contain_text("手動で除外")
    expect(page.locator("#sum-steps")).to_have_text("4")
    expect(note).to_be_visible()
    assert script.read_text(encoding="utf-8").count("\ndef step_0") == 5  # not rebuilt yet
    # a setting of the script itself
    page.fill("#gopt-delay", "1.5")
    page.locator("#gopt-delay").dispatch_event("change")
    page.click("#btn-regenerate")  # nothing was edited by hand: no question
    expect(page.locator("#status-text")).to_contain_text("作り直して保存しました")
    expect(note).to_be_hidden()
    expect(page.locator("#detail-script")).to_have_text(name)  # the same file is replaced
    code = script.read_text(encoding="utf-8")
    assert code.count("\ndef step_0") == 4 and "DELAY = 1.5" in code
    expect(page.locator("#code-editor")).to_have_value(re.compile(r"DELAY = 1\.5"))
    expect(page.locator("#easy-done-steps")).to_contain_text("4 手順")  # the easy screen follows
    # a dropped flow can be forced in, and the result step chosen
    page.locator('#flow-tbody tr[data-flow-id="f0002"] input[type=checkbox]').check()
    expect(page.locator('#flow-tbody tr[data-flow-id="f0002"]')).to_have_class(re.compile(r"\bkept\b"))
    expect(page.locator("#sum-steps")).to_have_text("5")
    page.locator('#flow-tbody tr[data-flow-id="f0009"] input[type=radio]').check()
    expect(page.locator("#sum-final")).to_contain_text("手順 3")
    expect(page.locator('#flow-tbody tr[data-flow-id="f0009"]')).to_have_class(re.compile(r"\bfinal\b"))
    expect(page.locator('#flow-tbody tr[data-flow-id="f0009"] .col-reason')).to_contain_text("結果")
    page.click("#btn-final-clear")
    expect(page.locator("#sum-final")).to_contain_text("最後の手順")
    assert page.js_errors == []


def test_detail_opt_in_redaction_asks_for_the_password(page, server):
    _build_from_har(page)
    _open_detail(page)
    page.check('input.opt[data-opt="redact_secrets"]')
    page.click("#btn-regenerate")
    expect(page.locator("#status-text")).to_contain_text("作り直して保存しました")
    expect(page.locator('#detail-env input[data-env="REQREC_PASSWORD"]')).to_have_attribute("type", "password")
    expect(page.locator("#detail-env")).to_contain_text("REQREC_PASSWORD")  # 詳細設定 names the variable
    expect(page.locator("#code-editor")).not_to_have_value(re.compile("Secr3t!"))
    expect(page.locator("#easy-done-secrets")).to_contain_text("パスワード")  # the easy screen: friendly name only
    expect(page.locator("#easy-done-secrets")).not_to_contain_text("REQREC_")
    assert page.js_errors == []


def test_detail_hand_edits_are_saved_and_run(page, server):
    name = _build_from_har(page)
    _open_detail(page)
    script = server.workdir / "scripts" / name
    editor = page.locator("#code-editor")
    expect(page.locator("#btn-save")).to_be_disabled()
    editor.fill("import os\nprint('HELLO from the editor')\n")
    expect(page.locator("#code-dirty")).to_be_visible()
    expect(page.locator("#btn-save")).to_be_enabled()
    editor.press("Tab")  # Python indentation, not a focus change
    expect(editor).to_have_value("import os\nprint('HELLO from the editor')\n    ")
    editor.press("Control+s")
    expect(page.locator("#save-result")).to_contain_text("保存しました")
    expect(page.locator("#code-dirty")).to_be_hidden()
    assert script.read_text(encoding="utf-8") == "import os\nprint('HELLO from the editor')\n    \n"
    page.click("#detail-run-btn")
    expect(page.locator("#detail-run-state")).to_contain_text("正常に終わりました")
    expect(page.locator("#detail-run-out")).to_contain_text("HELLO from the editor")
    page.click("#detail-save-output")
    expect(page.locator("#detail-save-output-result")).to_contain_text("保存しました")
    # an unsaved edit is saved before 試しに実行
    editor.fill("print('second version')\n")
    page.click("#detail-run-btn")
    expect(page.locator("#detail-run-out")).to_contain_text("second version")
    assert script.read_text(encoding="utf-8") == "print('second version')\n"
    # [設定から作り直す] after hand edits asks first; declining keeps them
    page.once("dialog", lambda dialog: dialog.dismiss())
    page.click("#btn-regenerate")
    expect(editor).to_have_value("print('second version')\n")
    page.once("dialog", lambda dialog: dialog.accept())
    page.click("#btn-regenerate")
    expect(editor).to_have_value(re.compile(r"def step_01_"))
    # saved under another name: that file becomes the current script on both screens
    page.fill("#script-name", "edited_copy")
    page.click("#btn-save")
    expect(page.locator("#detail-script")).to_have_text("edited_copy.py")
    assert (server.workdir / "scripts" / "edited_copy.py").is_file()
    expect(page.locator("#easy-done-name")).to_have_text("edited_copy.py")
    # a reload brings the saved script back into the editor
    page.reload(wait_until="networkidle")
    expect(page.locator("#panel-detail")).to_be_visible()  # the screen choice is remembered
    expect(page.locator("#detail-script")).to_have_text("edited_copy.py")
    expect(editor).to_have_value(re.compile(r"def step_01_"))
    page.click("#mode-toggle")
    expect(page.locator("#panel-easy")).to_be_visible()
    assert page.js_errors == []


# --------------------------------------------------------------------------- かんたん画面 (DESIGN.md §13.11)

def _load_into_server(server, recording):
    server.app.extensions["reqrec"].set_recording(recording, ["test"])


def _build_from_loaded(page):
    page.reload(wait_until="networkidle")
    expect(page.locator("#easy-loaded")).to_be_visible()
    page.click("#easy-build-loaded")
    expect(page.locator("#easy-done")).to_be_visible()


def test_easy_done_shows_plan_warnings_in_japanese_and_loop_downloads(page, server):
    from tests.test_gui import _synthetic_recording

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
    from reqrec import load_recording

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


def _pretend_recording_is_possible(page, monkeypatch, emulation_value=None):
    """[記録をはじめる] is enabled only with mitmproxy and a usable recording browser: pretend both (any OS)."""
    import reqrec

    monkeypatch.setattr(reqrec, "mitmproxy_available", lambda: True)
    monkeypatch.setattr(reqrec.iehost, "availability", lambda workdir, **kw: dict(RECBROWSER_AVAILABLE))
    monkeypatch.setattr(reqrec.iehost, "get_emulation", lambda *a, **kw: emulation_value)  # the registry is never read
    page.reload(wait_until="networkidle")
    expect(page.locator("#easy-start")).to_be_enabled()


def _fail_start(page, kind, message, bodies=None):
    def answer(route):
        if bodies is not None:
            bodies.append(json.loads(route.request.post_data))
        route.fulfill(status=500, content_type="application/json", body=json.dumps({"error": message, "kind": kind}))

    page.route("**/api/record/start", answer)


def test_easy_start_errors_are_explained_by_kind(page, server, monkeypatch):
    _pretend_recording_is_possible(page, monkeypatch)
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
    expect(page.locator("#easy-ready")).to_contain_text("前回、起動できませんでした")
    page.unroute("**/api/record/start")
    _fail_start(page, "emulation", "記録用ブラウザの表示モードを設定できませんでした: locked")
    page.click("#easy-start")
    expect(err).to_contain_text("「表示モード」を「既定」にして")
    # the browser logs the (intended) 500 responses; nothing else may fail
    assert [e for e in page.js_errors if "status of 500" not in e] == []


def test_easy_display_mode_is_sent_only_when_changed(page, server, monkeypatch):
    _pretend_recording_is_possible(page, monkeypatch, emulation_value=11000)  # IE11 相当, chosen earlier
    select = page.locator("#easy-emulation")
    expect(select).to_have_value("ie11")
    bodies: list[dict] = []
    _fail_start(page, "proxy", "記録用プロキシを起動できませんでした: test", bodies)
    page.click("#easy-start")
    expect(page.locator("#easy-error")).to_be_visible()
    select.select_option("default")
    page.click("#easy-start")
    page.wait_for_function("() => !document.querySelector('#easy-start').disabled")
    for _ in range(50):
        if len(bodies) == 2:
            break
        page.wait_for_timeout(100)
    assert [b["emulation"] for b in bodies] == ["keep", "default"]  # unchanged: the registry is not touched
    assert all(set(b) == {"start_url", "emulation"} for b in bodies)  # no host filter, no 追加モード
    assert [e for e in page.js_errors if "status of 500" not in e] == []


class _FakeRecorder:
    """A running recording as far as the page can tell (status only); ``stop`` / ``load_recording`` work."""

    def __init__(self, out):
        self.running = True
        self.out = out
        self.port = 18555
        self.command_builder = object()
        self.stopped = 0

    def status(self):
        return {"running": self.running, "flows": 3, "out": self.out, "out_name": os.path.basename(self.out),
                "pid": 1, "exit_code": None if self.running else 0, "started_at": 1.0, "stopped_at": None,
                "port": self.port, "stdout_tail": "",
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
        from reqrec import load_recording

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


def test_closing_the_recording_browser_stops_and_builds(page, server):
    state = server.app.extensions["reqrec"]
    real_recorder = state.recorder
    fake, browser = _FakeRecorder(str(server.workdir / "recordings" / "rec_fake.json")), _FakeBrowser()
    stops = []
    page.on("request", lambda req: stops.append(req.post_data) if req.url.endswith("/api/record/stop") else None)
    try:
        with state.lock:
            state.recorder = fake
            state.browser = browser
        page.reload(wait_until="networkidle")  # the page picks the recording up after a reload
        expect(page.locator("#easy-recording")).to_be_visible()
        expect(page.locator("#mode-toggle")).to_be_disabled()  # 詳細設定 waits for the script
        page.wait_for_timeout(1500)  # the poller sees the recording browser running
        browser.code = 0  # the user closes the recording browser
        expect(page.locator("#easy-done")).to_be_visible()
        assert stops and all("append" not in (s or "") for s in stops), stops
        expect(page.locator("#mode-toggle")).to_be_enabled()
    finally:
        with state.lock:
            state.recorder = real_recorder
            state.browser = None
    assert page.js_errors == []
