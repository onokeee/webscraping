"""Opt-in test of the test-only browser driver ``tests/iehost_fixtures/IEDriver.cs`` (+ ``iedriver.py``)
against the real recording browser (``reqrec/iehost/RecBrowser.cs``).

Runs only when all of the following hold, otherwise it is skipped (same gate as
``tests/test_iehost_engine.py``):

* ``sys.platform == "win32"``
* ``REQREC_IEHOST_TESTS=1`` in the environment
* the inbox C# compiler exists (``C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe``)
* mitmproxy is installed

What it does: compiles RecBrowser with ``reqrec.iehost.ensure_built`` and the driver with
``iedriver.build_driver``, serves the fixture site (``tests/iehost_fixtures/testsite.py``'s handler,
unchanged, plus a few extra pages defined *here* - buttons for window.open / showModalDialog /
alert, a ``target=_blank`` form with a submit button, an autopostback ``<select>``, a download link
and a frameset), starts mitmdump with the reqrec addon (the GUI's ``HTTPS_PASSTHROUGH_ARGS``) on a free port,
launches ``RecBrowser.exe --proxy ... --url http://127.0.0.1.nip.io:<port>/index.html`` and then
operates the pages only through the driver, like a user: popups become tabs, the modal dialog is
listed as kind ``dialog`` and operated while the opener's click is still blocked, the download
dialog is cancelled, the window is closed with WM_CLOSE (exit code 0) and the recording must contain
every request the engine made.

Run::

    set REQREC_IEHOST_TESTS=1
    .venv\\Scripts\\python -m pytest tests/test_iedriver.py -q

The small test at the bottom runs everywhere (import safety of the helpers).
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, quote, urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "iehost_fixtures")
FIXTURE_SITE = os.path.join(FIXTURES, "testsite.py")
DRIVER_MODULE = os.path.join(FIXTURES, "iedriver.py")
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

IS_WINDOWS = sys.platform == "win32"
OPTED_IN = os.environ.get("REQREC_IEHOST_TESTS") == "1"


def _mitmproxy_available() -> bool:
    try:
        from reqrec.recorder.run import mitmproxy_available
    except ImportError:  # pragma: no cover
        return False
    return mitmproxy_available()


engine = pytest.mark.skipif(
    not (IS_WINDOWS and OPTED_IN and os.path.exists(CSC) and _mitmproxy_available()),
    reason="IE driver test: needs Windows, REQREC_IEHOST_TESTS=1, the inbox csc.exe and mitmproxy",
)


# --------------------------------------------------------------------------- helpers

def _load(path: str, name: str):
    """Import a fixture module by path (``tests/iehost_fixtures`` is not a package)."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_port(port: int, timeout: float = 30.0, proc: Optional[subprocess.Popen] = None) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"process exited early with code {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError(f"port {port} did not open within {timeout}s")


def _kill(proc: Optional[subprocess.Popen]) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        pass


def _site_host() -> tuple[str, str]:
    """``(host, proxy_bypass)``: WinINet never proxies literal loopback addresses, so use a name."""
    try:
        infos = socket.getaddrinfo("127.0.0.1.nip.io", None, socket.AF_INET)
        if any(info[4][0] == "127.0.0.1" for info in infos):
            return "127.0.0.1.nip.io", ""
    except OSError:
        pass
    return "127.0.0.1", "<-loopback>"


def _request_body(flow: dict) -> str:
    b64 = flow["request"].get("body_b64")
    return base64.b64decode(b64).decode("utf-8", "replace") if b64 else ""


# --------------------------------------------------------------------------- extra pages

#: Labels of the autopostback ``<select id="kind">`` on /driver.html.
KIND_LABELS = {"": "未選択", "a": "Aコース", "b": "Bコース"}

#: Value typed into ``#name`` by the test (goes into the target=_blank POST).
TYPED_NAME = "山田太郎"

DRIVER_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>ドライバー試験</title></head><body>
<h1>ドライバー試験ページ</h1>
<p id="state">選択: %(label)s</p>
<form id="sf" method="get" action="/driver.html">
  <input type="hidden" name="run" value="%(run)s">
  <select id="kind" name="kind" onchange="this.form.submit()">
    <option value="">（選んでください）</option><option value="a">Aコース</option><option value="b">Bコース</option>
  </select>
</form>
<form id="pf" method="post" action="/post" target="_blank">
  <input id="name" name="name" value="">
  <input name="secret" value="abc123"><input name="jp" value="日本語">
  <input type="submit" id="postBtn" value="別ウィンドウで送信">
</form>
<p>
<button id="openBtn" onclick="openWin()">ポップアップを開く</button>
<button id="modalBtn" onclick="openModal()">モーダルを開く</button>
<button id="alertBtn" onclick="showAlert()">お知らせを表示</button>
</p>
<p id="modalResult">戻り値: なし</p>
<p id="alertResult">アラート: 未表示</p>
<p><a id="dl" href="/download.csv">CSV をダウンロード</a></p>
<p><a href="/drv_frames.html?run=%(run)s">フレームのページへ</a></p>
<script>
function openWin(){ window.open('/popup.html?via=driver', 'drvwin', 'width=500,height=400'); }
function openModal(){
  var r = window.showModalDialog('/drv_modal.html?via=driver', '引数ABC', 'dialogWidth:420px;dialogHeight:320px');
  document.getElementById('modalResult').innerText = '戻り値: ' + r;
}
function showAlert(){ alert('確認メッセージです'); document.getElementById('alertResult').innerText = 'アラート: 閉じました'; }
</script></body></html>"""

MODAL_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>モーダル画面</title></head><body>
<h1>モーダル画面</h1>
<p id="args">引数: (なし)</p>
<input id="memo" value="">
<button id="closeBtn" onclick="closeMe()">閉じる</button>
<script>
try { document.getElementById('args').innerText = '引数: ' + window.dialogArguments; } catch (e) {}
function closeMe(){ window.returnValue = 'OK:' + document.getElementById('memo').value; window.close(); }
</script></body></html>"""

FRAMESET_PAGE = """<html><head><meta charset="utf-8"><title>フレーム</title></head>
<frameset cols="35%%,65%%"><frame name="menu" src="/drv_menu.html?run=%(run)s"><frame name="main" src="/drv_main.html?page=1"></frameset></html>"""

MENU_PAGE = """<html><head><meta charset="utf-8"><title>メニュー</title></head><body>
<a id="next" href="/drv_main.html?page=2" target="main">次のページ</a></body></html>"""

MAIN_PAGE = """<html><head><meta charset="utf-8"><title>本文</title></head><body><h1 id="h">本文 %(page)s</h1></body></html>"""


def make_site_handler(fixture: Any, log_path: str) -> type:
    """testsite.py's handler (all of its pages unchanged) plus the driver pages above."""
    base = fixture.make_handler(log_path)

    class Handler(base):  # type: ignore[misc, valid-type]
        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            run = q.get("run", "")
            if u.path == "/driver.html":
                self._send(DRIVER_PAGE % {"label": KIND_LABELS.get(q.get("kind", ""), "?"), "run": run})
            elif u.path == "/drv_modal.html":
                self._send(MODAL_PAGE)
            elif u.path == "/drv_frames.html":
                self._send(FRAMESET_PAGE % {"run": run})
            elif u.path == "/drv_menu.html":
                self._send(MENU_PAGE)
            elif u.path == "/drv_main.html":
                self._send(MAIN_PAGE % {"page": q.get("page", "?")})
            else:
                super().do_GET()

    return Handler


def start_site(log_path: str, port: int = 0) -> ThreadingHTTPServer:
    """Serve the fixture site in a daemon thread on 127.0.0.1 (``port=0``: any free port)."""
    fixture = _load(FIXTURE_SITE, "reqrec_iedriver_testsite")
    open(log_path, "w", encoding="utf-8").close()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_site_handler(fixture, log_path))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="iedriver-site", daemon=True).start()
    return server


# --------------------------------------------------------------------------- opt-in test

@pytest.fixture(scope="session")
def binaries(tmp_path_factory) -> tuple[str, str, Any]:
    """``(RecBrowser.exe, IEDriver.exe, iedriver module)`` compiled into temporary directories."""
    if not (IS_WINDOWS and OPTED_IN and os.path.exists(CSC)):
        pytest.skip("csc.exe / opt-in not available")
    from reqrec import iehost

    recbrowser = iehost.ensure_built(str(tmp_path_factory.mktemp("iedriver_work")))
    iedriver = _load(DRIVER_MODULE, "reqrec_iedriver")
    driver = iedriver.build_driver(str(tmp_path_factory.mktemp("iedriver_bin")))
    assert iedriver.build_driver(os.path.dirname(driver)) == driver  # cached by source hash
    return recbrowser, driver, iedriver


def _poll(predicate, timeout: float = 10.0, interval: float = 0.25) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value or time.monotonic() >= deadline:
            return value
        time.sleep(interval)


def _header(flow: dict, name: str) -> Optional[str]:
    for key, value in flow["request"]["headers"]:
        if key.lower() == name.lower():
            return value
    return None


@engine
class TestIEDriver:
    def test_driver_operates_the_recording_browser_like_a_user(self, binaries, tmp_path):
        from reqrec.recorder.run import build_command
        from reqrec.webapp.routes import HTTPS_PASSTHROUGH_ARGS

        recbrowser_exe, driver_exe, iedriver = binaries
        host, bypass = _site_host()
        run = str(int(time.time()))
        site_log = tmp_path / "site.log"
        rec_json = tmp_path / "rec.json"
        host_log = tmp_path / "recbrowser.log"

        server = recorder = browser = None
        pending: list[subprocess.Popen] = []
        try:
            server = start_site(str(site_log))
            site_port = server.server_address[1]
            proxy_port = _free_port()
            base = f"http://{host}:{site_port}"
            with open(tmp_path / "mitmdump.out", "w", encoding="utf-8") as out:
                recorder = subprocess.Popen(
                    build_command(str(rec_json), port=proxy_port, listen_host="127.0.0.1", quiet=True,
                                  extra_args=list(HTTPS_PASSTHROUGH_ARGS)),
                    stdout=out, stderr=subprocess.STDOUT, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                _wait_port(proxy_port, timeout=60, proc=recorder)
                browser = subprocess.Popen([
                    recbrowser_exe, "--proxy", f"127.0.0.1:{proxy_port}", "--bypass", bypass,
                    "--url", f"{base}/index.html?run={run}", "--title", "driver test", "--log", str(host_log),
                ])
                drv = iedriver.IEDriver(driver_exe, browser.pid)
                self._operate(drv, iedriver, base, run, pending)
                closed = drv.close(timeout=20)
                assert closed["posted"] and closed["exited"], closed
                assert closed["exitCode"] == 0, closed
                assert browser.wait(timeout=10) == 0
        finally:
            for proc in pending:
                _kill(proc)
            _kill(browser)
            _kill(recorder)
            if server is not None:
                server.shutdown()
                server.server_close()

        log_text = host_log.read_text(encoding="utf-8") if host_log.exists() else "(no log)"
        assert rec_json.exists(), "recorder wrote no recording\n" + log_text
        self._check_recording(json.loads(rec_json.read_text(encoding="utf-8"))["flows"], site_port, run, log_text)

    # ------------------------------------------------------------------ steps

    def _operate(self, drv: Any, iedriver: Any, base: str, run: str, pending: list) -> None:
        # --- testsite.py's own index page: read it, then its target=_blank link opens a tab
        index = drv.wait(f"/index.html?run={run}", text="index page")
        assert index["kind"] == "tab" and index["readyState"] == "complete"
        docs = drv.list()
        assert [d["url"] for d in docs] == [f"{base}/index.html?run={run}"], docs
        assert drv.attr("/index.html", id="lnk", name="href")["value"] == f"{base}/settings.html?via=blank"
        assert drv.attr("/index.html", id="lnk", name="target")["value"] == "_blank"
        assert "index page" in drv.text("/index.html")["text"]
        drv.click("/index.html", id="lnk")
        settings = drv.wait("/settings.html?via=blank", text="opened via target=_blank link")
        tabs = drv.list(kind="tab")
        assert len(tabs) == 2, tabs
        assert {d["hwnd"] for d in tabs} == {index["hwnd"], settings["hwnd"]}
        assert settings["visible"] and not [d for d in tabs if d["hwnd"] == index["hwnd"]][0]["visible"]

        # --- the address box (selected tab = the popup) -> the driver page of this test
        drv.navigate(f"{base}/driver.html?run={run}")
        page = drv.wait(f"/driver.html?run={run}", text="ドライバー試験ページ")
        assert page["title"] == "ドライバー試験" and page["hwnd"] == settings["hwnd"]

        # --- typing + the target=_blank form's submit button -> POST in a new tab
        typed = drv.value(f"/driver.html?run={run}", id="name", value=TYPED_NAME)
        assert typed["value"] == TYPED_NAME
        assert drv.attr(f"/driver.html?run={run}", id="name", name="value")["value"] == TYPED_NAME
        drv.click(f"/driver.html?run={run}", id="postBtn")
        post = drv.wait("/post", text="secret=abc123")
        assert "name=" + quote(TYPED_NAME) in drv.text("/post")["text"]
        assert post["kind"] == "tab" and post["hwnd"] not in (index["hwnd"], settings["hwnd"])

        # --- window.open from a button -> another tab
        drv.click(f"/driver.html?run={run}", id="openBtn")
        popup = drv.wait("/popup.html?via=driver", text="opened via window.open")
        assert popup["kind"] == "tab"
        assert len(drv.list(kind="tab")) == 4

        # --- autopostback <select>: option chosen + fireEvent("onchange") submits the form
        chosen = drv.select(f"/driver.html?run={run}", id="kind", text="Bコース")
        assert (chosen["value"], chosen["selectedIndex"], chosen["fired"]) == ("b", 2, "fireEvent")
        drv.wait("kind=b", text="選択: Bコース")
        with pytest.raises(iedriver.IEDriverError):
            drv.select("kind=b", id="kind", text="存在しないコース", timeout=1)

        # --- showModalDialog: the opener's click blocks until the dialog closes -> click_async
        clicking = drv.click_async("kind=b", id="modalBtn")
        pending.append(clicking)
        modal = drv.wait("/drv_modal.html?via=driver", kind="dialog")
        dialogs = drv.list(kind="dialog")
        assert [d["url"] for d in dialogs] == [modal["url"]], dialogs
        assert "引数: 引数ABC" in drv.text("/drv_modal.html", kind="dialog")["text"]
        assert clicking.poll() is None, "the click returned although the modal dialog is still open"
        with pytest.raises(iedriver.IEDriverError) as refused:  # the X button is disabled for a user too
            drv.close(timeout=1)
        assert "disabled by a modal dialog" in str(refused.value)
        assert [d["class"] for d in refused.value.result["detail"]] == ["Internet Explorer_TridentDlgFrame"]
        drv.value("/drv_modal.html", id="memo", value="メモ", kind="dialog")
        drv.click("/drv_modal.html", id="closeBtn", kind="dialog")
        clicked = drv.finish(clicking)
        assert clicked["clicked"]["id"] == "modalBtn"
        assert _poll(lambda: not drv.list(kind="dialog")), drv.list(kind="dialog")
        assert drv.text("kind=b", id="modalResult")["text"] == "戻り値: OK:メモ"

        # --- alert(): a standard dialog of the process, closed with its OK button
        clicking = drv.click_async("kind=b", id="alertBtn")
        pending.append(clicking)
        box = drv.dialog(text="確認メッセージです")
        assert box["buttons"] == ["OK"] and "確認メッセージです" in box["texts"], box
        with pytest.raises(iedriver.IEDriverError) as refused:
            drv.navigate(f"{base}/index.html?never=1")
        assert "disabled by a modal dialog" in str(refused.value)
        pressed = drv.dialog(text="確認メッセージです", button="OK")
        assert pressed["clicked"] == "OK" and pressed["closed"], pressed
        drv.finish(clicking)
        assert drv.text("kind=b", id="alertResult")["text"] == "アラート: 閉じました"

        # --- file download: the engine's 「ファイルのダウンロード」 dialog -> キャンセル
        drv.click("kind=b", id="dl")
        download = drv.dialog(title="ファイルのダウンロード", button="キャンセル", timeout=20)
        assert download["clicked"] == "キャンセル" and download["closed"], download
        assert any("保存" in b for b in download["buttons"]), download
        with pytest.raises(iedriver.IEDriverError) as no_dialog:
            drv.dialog(title="ファイルのダウンロード", timeout=1)
        assert no_dialog.value.result["detail"] == []

        # --- link by its text -> frameset; frames are windowless (same hwnd as their tab)
        drv.click("kind=b", link_text="フレームのページ")
        drv.wait("/drv_main.html?page=1", kind="frame", text="本文 1")
        frames = drv.list(kind="frame")
        assert sorted(d["frame"] for d in frames) == ["0", "1"], frames
        assert {d["hwnd"] for d in frames} == {settings["hwnd"]}
        drv.click("/drv_menu.html", id="next", kind="frame")
        drv.wait("/drv_main.html?page=2", kind="frame", text="本文 2")
        assert drv.text("/drv_main.html", id="h", kind="frame")["text"] == "本文 2"

        # --- failures are reported as JSON with what was seen
        with pytest.raises(iedriver.IEDriverError) as missing:
            drv.text("/no-such-page.html", timeout=1)
        assert "no-such-page" in str(missing.value)
        assert any(d.get("url", "").endswith("/drv_frames.html?run=" + run) for d in missing.value.result["detail"])
        with pytest.raises(iedriver.IEDriverError):
            drv.click("/drv_main.html", id="no-such-element", timeout=1)

    def _check_recording(self, flows: list[dict], site_port: int, run: str, log_text: str) -> None:
        urls = [f["request"]["url"] for f in flows]

        def find(method: str, fragment: str) -> dict:
            hits = [f for f in flows if f["request"]["method"] == method and fragment in f["request"]["url"]]
            assert hits, f"{method} {fragment} not recorded:\n" + "\n".join(urls) + "\n" + log_text
            return hits[0]

        index = find("GET", f"/index.html?run={run}")
        settings = find("GET", "/settings.html?via=blank")
        typed = find("GET", f"/driver.html?run={run}")
        post = find("POST", f":{site_port}/post")
        find("GET", "/popup.html?via=driver")
        postback = find("GET", f"/driver.html?run={run}&kind=b")
        find("GET", "/drv_modal.html?via=driver")
        download = find("GET", "/download.csv")
        find("GET", f"/drv_frames.html?run={run}")
        find("GET", "/drv_main.html?page=2")

        assert _request_body(post) == "name=" + quote(TYPED_NAME) + "&secret=abc123&jp=" + quote("日本語")
        assert post["response"] and post["response"]["status"] == 200
        assert download["response"] and download["response"]["status"] == 200
        # what a real user session looks like: links / forms send a Referer, the address box does not
        assert _header(settings, "Referer") == index["request"]["url"]
        assert _header(typed, "Referer") is None
        assert _header(post, "Referer") == typed["request"]["url"]
        assert _header(postback, "Referer") == typed["request"]["url"]
        assert "MSIE 7.0" in (_header(post, "User-Agent") or "")
        assert "sid=TESTSESSION" in (_header(post, "Cookie") or ""), "session cookie not sent with the POST"


# --------------------------------------------------------------------------- always-on checks

def _strip_cs_comments(source: str) -> str:
    """Remove ``//`` and ``/* */`` comments (no string literal in IEDriver.cs contains them)."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n]*", "", source)


def test_driver_helpers_are_import_safe(tmp_path, monkeypatch):
    """Importing the wrapper compiles / runs nothing; argv building is plain."""
    monkeypatch.chdir(tmp_path)
    iedriver = _load(DRIVER_MODULE, "reqrec_iedriver_check")
    assert list(tmp_path.iterdir()) == []
    cmd = iedriver.build_command("csc.exe", "IEDriver.cs", "out.exe")
    assert "-target:exe" in cmd and "-platform:x64" in cmd and "-r:Microsoft.CSharp.dll" in cmd
    drv = iedriver.IEDriver("IEDriver.exe", 1234)
    assert drv.argv("click", *iedriver._opts(url="/a", id="b", link_text=None, timeout=2.5)) == [
        "IEDriver.exe", "click", "--pid", "1234", "--url", "/a", "--id", "b", "--timeout", "2.5",
    ]
    handler = make_site_handler(_load(FIXTURE_SITE, "reqrec_iedriver_testsite_check"), str(tmp_path / "x.log"))
    assert callable(handler.do_GET)
    assert list(tmp_path.iterdir()) == []


def test_driver_source_guard_rails():
    """C# 5 only (inbox csc), DOM access only (no execScript / eval), no registry."""
    with open(os.path.join(FIXTURES, "IEDriver.cs"), encoding="utf-8") as fh:
        source = fh.read()
    assert source.startswith("//")
    code = _strip_cs_comments(source)
    assert '$"' not in code and "nameof(" not in code and "?." not in code
    assert "execScript" not in code and "InvokeScript" not in code and '"eval"' not in code
    assert "Microsoft.Win32" not in code and "Registry" not in code
    assert '"WM_HTML_GETOBJECT"' in code and "ObjectFromLresult" in code
