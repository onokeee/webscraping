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

def test_page_loads_in_japanese(page):
    expect(page).to_have_title(re.compile("reqrec"))
    expect(page.locator("#status-text")).to_contain_text("準備完了")
    for label in ("記録", "読み込み", "ステップ", "コード", "実行"):
        expect(page.locator("#nav")).to_contain_text(label)
    assert page.evaluate("document.body.dataset.token").strip() != ""
    assert page.js_errors == []


def test_upload_shows_step_table(page, server):
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


def test_uncheck_kept_flow_marks_it_dropped(page):
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


def test_choose_result_step(page):
    _upload_fixture(page)
    page.locator('#flow-tbody tr[data-flow-id="f0009"] input[type=radio]').check()
    expect(page.locator("#sum-final")).to_contain_text("ステップ 2")
    expect(page.locator('#flow-tbody tr[data-flow-id="f0009"]')).to_have_class(re.compile(r"\bfinal\b"))
    expect(page.locator('#flow-tbody tr[data-flow-id="f0009"] .col-reason')).to_contain_text("結果")
    page.click("#btn-final-clear")
    expect(page.locator("#sum-final")).to_contain_text("最後のステップ")
    assert page.js_errors == []


def test_generate_save_and_run_panel(page, server):
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


def test_run_tiny_script_in_browser(page, server):
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
