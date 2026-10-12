"""Tests with the real recording engine and the IE-engine test helpers (``tests/ie_support.py``).

Most of them are opt-in: they run only on Windows with ``REQREC_IEHOST_TESTS=1`` (they open small
browser windows briefly) plus the inbox C# compiler and mitmproxy::

    set REQREC_IEHOST_TESTS=1
    .venv\\Scripts\\python -m pytest tests/test_real_engine.py -q

Always on: the import-safety / source checks at the end of the first two sections and the whole
``factory_site`` self-check section.  The GUI recording section runs the real ``mitmdump`` (when
mitmproxy is installed) with a faked recording browser: ``requests`` stands in for RecBrowser.exe.

One section per former test module (headed ``# ===== former tests/<name>.py ... =====``); helpers
shared by several of them are defined once, in the first section.
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
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, quote, unquote, urlencode, urljoin, urlsplit

import pytest
import requests
from bs4 import BeautifulSoup

import reqrec
from reqrec import Recording
from reqrec import TOKEN_HEADER, create_app
from reqrec import mitmproxy_available
from tests.support import PASSWORD, USERNAME, restart_server, start_server, stop_server


# ===== former tests/test_iehost_engine.py: RecBrowser.exe engine self-test (opt-in) =====
# Engine test for the IE-host recording browser (``reqrec/RecBrowser.cs``).
#
# The real test (``TestRecBrowserEngine``) drives the actual IE engine and is **opt-in**: it runs only
# when all of the following hold, otherwise it is skipped.
#
# * ``sys.platform == "win32"``
# * ``REQREC_IEHOST_TESTS=1`` in the environment
# * the inbox C# compiler exists (``C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe``)
# * mitmproxy is installed (``mitmdump`` on PATH or the ``mitmproxy`` package)
#
# What it does: compiles RecBrowser.cs with the production command line (``iehost.build_command``:
# a 32-bit ``-platform:x86`` exe, checked in the PE header), starts the fixture site
# (``tests/ie_support.py``'s testsite) and a recorder (``mitmdump`` + reqrec addon, the GUI's
# ``HTTPS_PASSTHROUGH_ARGS``), runs ``RecBrowser.exe --selftest`` against the site and then checks
# the host's log and the recording: the window.open popup, the ``target=_blank`` POST (with body),
# the ``target=_blank`` link, the modeless and the modal dialog documents must all have gone
# through the proxy.  The Windows proxy settings and FEATURE_BROWSER_EMULATION are compared
# before/after: the host must not touch them.
#
# The site is addressed as ``http://127.0.0.1.nip.io:<port>/`` because WinINet never proxies literal
# loopback addresses; when that name does not resolve (offline PC) the test falls back to
# ``127.0.0.1`` with ``--bypass "<-loopback>"``.
#
# Run::
#
#     set REQREC_IEHOST_TESTS=1
#     .venv\Scripts\python -m pytest tests/test_real_engine.py -q
#
# The two small tests at the bottom run everywhere (fixture import safety, source guard rails).

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CS_SOURCE = reqrec.RECBROWSER_CS  # the recording browser's C# source (embedded in reqrec.py)
FIXTURE_SITE = os.path.join(ROOT, "tests", "ie_support.py")
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
FEATURE_BROWSER_EMULATION = r"Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION"
PROXY_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")

IS_WINDOWS = sys.platform == "win32"
OPTED_IN = os.environ.get("REQREC_IEHOST_TESTS") == "1"


def _mitmproxy_available() -> bool:
    try:
        from reqrec import mitmproxy_available
    except ImportError:  # pragma: no cover
        return False
    return mitmproxy_available()


engine = pytest.mark.skipif(
    not (IS_WINDOWS and OPTED_IN and os.path.exists(CSC) and _mitmproxy_available()),
    reason="IE-host engine test: needs Windows, REQREC_IEHOST_TESTS=1, the inbox csc.exe and mitmproxy",
)


# --------------------------------------------------------------------------- helpers

def _load_fixture_module():
    """Import tests/ie_support.py (its testsite section) by path (no package import needed)."""
    spec = importlib.util.spec_from_file_location("reqrec_iehost_testsite", FIXTURE_SITE)
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
    """``(host, proxy_bypass)`` for the test site: a non-loopback name when it resolves to 127.0.0.1,
    else the literal address with WinINet's ``<-loopback>`` bypass override."""
    try:
        infos = socket.getaddrinfo("127.0.0.1.nip.io", None, socket.AF_INET)
        if any(info[4][0] == "127.0.0.1" for info in infos):
            return "127.0.0.1.nip.io", ""
    except OSError:
        pass
    return "127.0.0.1", "<-loopback>"


def _registry_snapshot() -> dict[str, Any]:
    """Proxy-related HKCU values and every FEATURE_BROWSER_EMULATION value (what the host must not touch)."""
    import winreg  # Windows only

    snapshot: dict[str, Any] = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_READ) as key:
            for name in PROXY_VALUES:
                try:
                    snapshot[name] = winreg.QueryValueEx(key, name)
                except OSError:
                    snapshot[name] = None
    except OSError:
        snapshot["InternetSettings"] = "missing"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, FEATURE_BROWSER_EMULATION, 0, winreg.KEY_READ) as key:
            values = {}
            index = 0
            while True:
                try:
                    name, value, kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                values[name] = (value, kind)
                index += 1
            snapshot["FEATURE_BROWSER_EMULATION"] = values
    except OSError:
        snapshot["FEATURE_BROWSER_EMULATION"] = "missing"
    return snapshot


def _pe_platform(path: str) -> tuple[int, int]:
    """``(machine, cor_flags)`` of a .NET exe: machine 0x14c = i386, 0x8664 = AMD64; ``cor_flags``
    bit 0x2 = 32BITREQUIRED (what ``-platform:x86`` sets; AnyCPU leaves it clear)."""
    import struct

    with open(path, "rb") as fh:
        data = fh.read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0", "not a PE file"
    machine, sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dirs = opt + (96 if magic == 0x10B else 112)  # PE32 / PE32+
    clr_rva = struct.unpack_from("<I", data, dirs + 14 * 8)[0]
    table = opt + opt_size
    for i in range(sections):
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", data, table + i * 40 + 8)
        if vaddr <= clr_rva < vaddr + max(vsize, rsize):
            cor20 = clr_rva - vaddr + raw
            return machine, struct.unpack_from("<I", data, cor20 + 16)[0]
    raise AssertionError("no CLR header found")


def _request_body(flow: dict) -> str:
    b64 = flow["request"].get("body_b64")
    return base64.b64decode(b64).decode("utf-8", "replace") if b64 else ""


# --------------------------------------------------------------------------- engine test (opt-in)

@pytest.fixture(scope="session")
def recbrowser_exe(tmp_path_factory) -> str:
    """RecBrowser.exe compiled with the production csc command line (``iehost.build_command``)."""
    if not (IS_WINDOWS and OPTED_IN and os.path.exists(CSC)):
        pytest.skip("csc.exe / opt-in not available")
    from reqrec import iehost

    out_dir = tmp_path_factory.mktemp("iehost_bin")
    exe = os.path.join(str(out_dir), "RecBrowser.exe")
    src = os.path.join(str(out_dir), "RecBrowser.cs")
    with open(src, "wb") as fh:
        fh.write(CS_SOURCE.encode("utf-8"))
    cmd = iehost.build_command(CSC, src, exe)
    assert "-platform:x86" in cmd  # 32-bit like IE mode: legacy 32-bit ActiveX controls must load
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, f"csc failed:\n{result.stdout}\n{result.stderr}"
    assert os.path.exists(exe)
    machine, cor_flags = _pe_platform(exe)
    assert machine == 0x14C and cor_flags & 0x2, f"RecBrowser.exe is not a 32-bit-only exe: machine={machine:#x} flags={cor_flags:#x}"
    return exe


@engine
class TestRecBrowserEngine:
    def test_selftest_records_popups_post_and_dialogs(self, recbrowser_exe, tmp_path):
        from reqrec import build_command

        fixture = _load_fixture_module()
        site_port = _free_port()
        proxy_port = _free_port()
        while proxy_port == site_port:
            proxy_port = _free_port()
        host, bypass = _site_host()
        site_log = tmp_path / "site.log"
        rec_json = tmp_path / "rec.json"
        host_log = tmp_path / "recbrowser.log"
        run_token = str(int(time.time()))
        start_url = f"http://{host}:{site_port}/index.html?run={run_token}"

        before = _registry_snapshot()
        site = recorder = None
        try:
            site = subprocess.Popen(
                [sys.executable, "-I", FIXTURE_SITE, "testsite", str(site_log), str(site_port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            _wait_port(site_port, proc=site)
            from reqrec import HTTPS_PASSTHROUGH_ARGS

            recorder_cmd = build_command(
                str(rec_json), port=proxy_port, extra_args=list(HTTPS_PASSTHROUGH_ARGS),
            )
            with open(tmp_path / "mitmdump.out", "w", encoding="utf-8") as out:
                recorder = subprocess.Popen(
                    recorder_cmd, stdout=out, stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                _wait_port(proxy_port, timeout=60, proc=recorder)

                cmd = [
                    recbrowser_exe, "--proxy", f"127.0.0.1:{proxy_port}", "--bypass", bypass,
                    "--url", start_url, "--title", "engine test", "--selftest", "--seconds", "25",
                    "--log", str(host_log),
                ]
                result = subprocess.run(cmd, timeout=90)
        finally:
            _kill(recorder)
            _kill(site)
        after = _registry_snapshot()

        log_text = host_log.read_text(encoding="utf-8") if host_log.exists() else "(no log)"
        assert result.returncode == 0, f"RecBrowser.exe exit code {result.returncode}\n{log_text}"

        # --- host log ------------------------------------------------------------------
        lines = log_text.splitlines()
        assert all(re.match(r"^\d\d:\d\d:\d\d\.\d\d\d ", line) for line in lines if line), log_text
        assert f"proxy 127.0.0.1:{proxy_port} -> ok" in log_text, log_text
        assert "engine test — 記録中" in log_text, "window title line missing or mis-encoded:\n" + log_text
        assert "selftest: done -> exit 0" in log_text, log_text
        tab_lines = [line.split(" ", 1)[1] for line in lines if " tab: " in line]
        assert len(tab_lines) == 4, log_text  # index + popup + POST result + settings
        assert all(re.search(r" mode=\d+ opener=(yes|no) name=", line) for line in tab_lines), tab_lines
        assert any("/popup.html?via=open mode=" in line and "opener=yes name=cfgwin" in line for line in tab_lines), tab_lines
        assert any(f":{site_port}/post mode=" in line and "opener=yes" in line for line in tab_lines), tab_lines
        assert any("/settings.html?via=blank mode=" in line and "opener=yes" in line for line in tab_lines), tab_lines
        assert "NewWindow3" in log_text or "NewWindow2" in log_text, log_text
        # doClosePopup: the popup's window.close() reaches the host as OLECMDID_CLOSE and removes the tab
        assert "selftest: doClosePopup -> opened" in log_text, log_text
        assert re.search(r"OLECMDID_CLOSE tab\d+ \(window\.close\)", log_text), log_text
        assert re.search(r"close tab tab\d+", log_text), log_text
        assert not any("/closer.html" in line for line in tab_lines), tab_lines  # the closed tab is gone

        # --- recording -----------------------------------------------------------------
        assert rec_json.exists(), "recorder wrote no recording"
        recording = json.loads(rec_json.read_text(encoding="utf-8"))
        flows = recording["flows"]
        urls = [f["request"]["url"] for f in flows]

        def find(method: str, fragment: str) -> list[dict]:
            return [f for f in flows if f["request"]["method"] == method and fragment in f["request"]["url"]]

        assert find("GET", f"/index.html?run={run_token}"), urls
        assert find("GET", "/popup.html?via=open"), urls
        posts = find("POST", f":{site_port}/post")
        assert posts, urls
        assert _request_body(posts[0]) == fixture.EXPECTED_POST_BODY
        assert posts[0]["response"] and posts[0]["response"]["status"] == 200
        assert find("GET", "/settings.html?via=blank"), urls
        assert find("GET", "/modeless.html?via=modeless"), urls
        assert find("GET", "/modal.html?via=modal"), urls
        assert find("GET", "/closer.html?via=close"), urls
        # self-reports prove the engine state inside the hosted windows
        assert any("tag=popup" in u and "name=cfgwin" in u and "opener=yes" in u for u in urls), urls
        assert any("tag=modal" in u and "args=ARGS" in u for u in urls), urls
        assert any("tag=post" in u and "post=secret%3Dabc123" in u for u in urls), urls
        cookie = fixture.TESTSITE_SESSION_COOKIE.replace("=", "%3D")
        assert any("tag=popup" in u and f"cookie={cookie}" in u for u in urls), "session cookie not carried into the popup"
        # the server saw the POST body too
        site_lines = [json.loads(line) for line in site_log.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert any(e.get("method") == "POST" and e.get("body") == fixture.EXPECTED_POST_BODY for e in site_lines)

        # --- nothing in Windows changed -------------------------------------------------
        assert before == after, f"registry changed by RecBrowser.exe:\nbefore={before}\nafter={after}"
        if isinstance(after.get("FEATURE_BROWSER_EMULATION"), dict):
            assert not any("recbrowser" in name.lower() for name in after["FEATURE_BROWSER_EMULATION"])

    def test_missing_proxy_argument_exits_2(self, recbrowser_exe, tmp_path):
        log = tmp_path / "noproxy.log"
        result = subprocess.run([recbrowser_exe, "--log", str(log)], timeout=60)
        assert result.returncode == 2
        assert "proxy (none) -> FAILED" in log.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- always-on checks

def test_fixture_site_is_import_safe(tmp_path, monkeypatch):
    """Importing the fixture must not read argv, open files or bind sockets."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["testsite.py", "SHOULD_NOT_BE_READ.log", "1"])
    module = _load_fixture_module()
    assert callable(module.main) and callable(module.serve) and callable(module.make_handler)
    assert module.SELFTEST_FUNCTIONS == ("doOpen", "doBlankPost", "doBlankLink", "doModeless", "doModal", "doClosePopup")
    for name in module.SELFTEST_FUNCTIONS:
        assert f"function {name}(" in module.INDEX
    assert list(tmp_path.iterdir()) == []


def _strip_cs_comments(source: str) -> str:
    """Remove ``//`` and ``/* */`` comments (string literals in RecBrowser.cs / IEDriver.cs never contain them)."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n]*", "", source)


def test_host_source_guard_rails():
    """RecBrowser.cs must keep the proven WinINet path and never touch the registry."""
    source = CS_SOURCE
    assert source.startswith("//"), "source must be plain UTF-8 without BOM (csc reads it as UTF-8)"
    assert "-target:winexe" in source  # build line documented in the header
    assert "-platform:x86" in source and "-platform:x64" not in source  # 32-bit, like IE mode
    code = _strip_cs_comments(source)
    assert 'EntryPoint = "InternetSetOptionA"' in code  # ANSI variant only: the W variant breaks WinINet
    assert "InternetSetOptionW" not in code
    assert "PER_CONNECTION_OPTION" not in code  # NULL-handle per-connection options write the registry
    assert "Microsoft.Win32" not in code and "Registry" not in code
    for dispid in ("DispId(251)", "DispId(263)", "DispId(270)", "DispId(273)"):
        assert dispid in code
    # C# 5 language level (inbox csc): no interpolated strings, no nameof, no null-conditional.
    assert '$"' not in code and "nameof(" not in code and "?." not in code
    # http:// only: there is no switch that makes the host claim it records https:// pages
    assert '"--https"' not in code and "HttpsRecorded" not in code


# ===== former tests/test_iedriver.py: the test-only browser driver IEDriver.cs (opt-in) =====
# Opt-in test of the test-only browser driver ``tests/IEDriver.cs`` (+ ``tests/ie_support.py``)
# against the real recording browser (``reqrec/RecBrowser.cs``).
#
# Runs only when all of the following hold, otherwise it is skipped (same gate as
# the RecBrowser engine section above):
#
# * ``sys.platform == "win32"``
# * ``REQREC_IEHOST_TESTS=1`` in the environment
# * the inbox C# compiler exists (``C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe``)
# * mitmproxy is installed
#
# What it does: compiles RecBrowser with ``reqrec.iehost.ensure_built`` and the driver with
# ``iedriver.build_driver``, serves the fixture site (``tests/ie_support.py``'s testsite handler,
# unchanged, plus a few extra pages defined *here* - buttons for window.open / showModalDialog /
# alert, a ``target=_blank`` form with a submit button, an autopostback ``<select>``, a download link
# and a frameset), starts mitmdump with the reqrec addon (the GUI's ``HTTPS_PASSTHROUGH_ARGS``) on a free port,
# launches ``RecBrowser.exe --proxy ... --url http://127.0.0.1.nip.io:<port>/index.html`` and then
# operates the pages only through the driver, like a user: popups become tabs, the modal dialog is
# listed as kind ``dialog`` and operated while the opener's click is still blocked, the download
# dialog is cancelled, the window is closed with WM_CLOSE (exit code 0) and the recording must contain
# every request the engine made.
#
# Run::
#
#     set REQREC_IEHOST_TESTS=1
#     .venv\Scripts\python -m pytest tests/test_real_engine.py -q
#
# The small test at the bottom runs everywhere (import safety of the helpers).

FIXTURES = os.path.join(ROOT, "tests")
DRIVER_MODULE = os.path.join(FIXTURES, "ie_support.py")
# ``ROOT``, ``FIXTURE_SITE``, ``CSC``, ``IS_WINDOWS``, ``OPTED_IN`` and the helpers ``_mitmproxy_available``,
# ``_free_port``, ``_wait_port``, ``_kill``, ``_site_host``, ``_request_body`` and ``_strip_cs_comments``
# are defined once in the first section (former tests/test_iehost_engine.py).


driver_engine = pytest.mark.skipif(
    not (IS_WINDOWS and OPTED_IN and os.path.exists(CSC) and _mitmproxy_available()),
    reason="IE driver test: needs Windows, REQREC_IEHOST_TESTS=1, the inbox csc.exe and mitmproxy",
)


# --------------------------------------------------------------------------- helpers

def _load(path: str, name: str):
    """Import ``tests/ie_support.py`` by path under ``name``."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    """The testsite handler of tests/ie_support.py (all of its pages unchanged) plus the driver pages above."""
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


@driver_engine
class TestIEDriver:
    def test_driver_operates_the_recording_browser_like_a_user(self, binaries, tmp_path):
        from reqrec import build_command
        from reqrec import HTTPS_PASSTHROUGH_ARGS

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
                    build_command(str(rec_json), port=proxy_port, extra_args=list(HTTPS_PASSTHROUGH_ARGS)),
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
        # --- the testsite's own index page: read it, then its target=_blank link opens a tab
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


# ===== former tests/test_factory_site.py: self-check of the factory mock site (always on, no browser) =====
# Self-check of the factory mock site (``tests/ie_support.py``, factory_site section; always on, no browser).
#
# The site is started in-process on a free port and driven with ``requests`` exactly like IE would:
# forms are serialised from the HTML (successful controls only, the clicked submit button only,
# ``__doPostBack`` fills ``__EVENTTARGET`` / ``__EVENTARGUMENT``) and URL-encoded in Shift_JIS (cp932).

SITE_PATH = os.path.join(ROOT, "tests", "ie_support.py")
IE7_UA = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)"


def _load_site():
    """Import tests/ie_support.py by path (a fresh module object)."""
    spec = importlib.util.spec_from_file_location("reqrec_factory_site", SITE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fs = _load_site()


# --------------------------------------------------------------------------- browser-like client


class Browser:
    """A ``requests.Session`` that submits forms the way IE does on a Shift_JIS page."""

    def __init__(self, base_url: str) -> None:
        self.base = base_url
        self.session = requests.Session()
        self.session.headers["User-Agent"] = IE7_UA

    def url(self, path: str) -> str:
        return urljoin(self.base, path)

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(self.url(path), allow_redirects=False, timeout=10, **kwargs)

    def post(self, url: str, fields: Sequence[Tuple[str, str]], **kwargs) -> requests.Response:
        body = urlencode(list(fields), encoding="cp932")  # IE encodes form data in the page's charset
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        headers.update(kwargs.pop("headers", {}))
        return self.session.post(self.url(url), data=body, headers=headers, allow_redirects=False, timeout=10, **kwargs)

    def submit(self, page: "Page", click: Optional[str] = None, overrides: Optional[Dict[str, str]] = None,
               postback: Optional[Tuple[str, str]] = None) -> requests.Response:
        """Submit ``page``'s form: click a submit button, or run ``__doPostBack(target, argument)``."""
        values = dict(overrides or {})
        if postback is not None:
            values["__EVENTTARGET"], values["__EVENTARGUMENT"] = postback
        return self.post(page.action_url, page.fields(click=click, overrides=values))

    def cookie(self, name: str) -> Optional[str]:
        return self.session.cookies.get(name)


class Page:
    """A decoded HTML response."""

    def __init__(self, resp: requests.Response) -> None:
        assert resp.headers["Content-Type"] == "text/html; charset=Shift_JIS", resp.headers
        assert b'<meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS" />' in resp.content
        self.resp = resp
        self.text = resp.content.decode("shift_jis")  # strict: the page really is Shift_JIS
        self.soup = BeautifulSoup(self.text, "html.parser")

    @property
    def form(self):
        form = self.soup.find("form")
        assert form is not None
        return form

    @property
    def action_url(self) -> str:
        return urljoin(self.resp.url, self.form["action"])

    def hidden(self, name: str) -> str:
        el = self.soup.find("input", {"name": name})
        assert el is not None, name
        return el.get("value", "")

    def fields(self, click: Optional[str] = None, overrides: Optional[Dict[str, str]] = None) -> List[Tuple[str, str]]:
        """The form's successful controls in document order (what IE would post)."""
        out: List[Tuple[str, str]] = []
        for el in self.form.find_all(["input", "select", "textarea"]):
            name = el.get("name")
            if not name or el.has_attr("disabled"):
                continue
            if el.name == "input":
                kind = (el.get("type") or "text").lower()
                if kind in ("submit", "image"):
                    if name == click:
                        out.append((name, el.get("value", "")))
                    continue
                if kind in ("button", "reset", "file"):
                    continue
                if kind in ("checkbox", "radio") and not el.has_attr("checked"):
                    continue
                out.append((name, el.get("value", "")))
            elif el.name == "select":
                options = el.find_all("option")
                if not options:
                    continue  # an empty <select> is not posted
                chosen = [o for o in options if o.has_attr("selected")] or options[:1]
                out.append((name, chosen[0].get("value", chosen[0].get_text())))
            else:
                out.append((name, el.get_text()))
        if click is not None:
            assert any(name == click for name, _ in out), f"no submit button {click!r}"
        for name, value in (overrides or {}).items():
            if any(n == name for n, _ in out):
                out = [(n, value if n == name else v) for n, v in out]
            else:
                out.append((name, value))
        return out

    def select_options(self, name: str) -> List[Tuple[str, str, bool]]:
        sel = self.soup.find("select", {"name": name})
        assert sel is not None, name
        return [(o.get("value", ""), o.get_text(), o.has_attr("selected")) for o in sel.find_all("option")]

    def grid_rows(self) -> List[Tuple[str, ...]]:
        table = self.soup.find("table", id="gvResult")
        assert table is not None
        rows = []
        for tr in table.find_all("tr", recursive=False)[1:]:
            if "pager" in (tr.get("class") or []):
                continue
            rows.append(tuple(td.get_text(strip=True) for td in tr.find_all("td", recursive=False)))
        return rows

    def pager_links(self) -> List[str]:
        return [a["href"] for a in self.soup.select("#gvResult tr.pager a")]

    def message(self) -> str:
        el = self.soup.find(id="lblMessage")
        return el.get_text(strip=True) if el is not None else ""


def set_cookies(resp: requests.Response) -> List[str]:
    return list(resp.raw.headers.getlist("Set-Cookie"))


def cookie_value(headers: List[str], name: str) -> Optional[str]:
    for header in headers:
        if header.startswith(name + "="):
            return header.split(";", 1)[0].split("=", 1)[1]
    return None


def log_entries(log_path: str) -> List[dict]:
    return fs.read_log(log_path)


def events(log_path: str) -> List[str]:
    return [e["event"] for e in log_entries(log_path)]


# --------------------------------------------------------------------------- fixtures / flows


@pytest.fixture
def site(tmp_path):
    log = str(tmp_path / "factory.log")
    server = fs.serve_in_thread(log)
    try:
        yield server, log
    finally:
        server.stop()


def login(base_url: str) -> Tuple[Browser, Page]:
    """Log in like a user; returns the browser and the menu page."""
    b = Browser(base_url)
    page = Page(b.get("Login.aspx"))
    user, password = fs.CREDENTIALS
    r = b.submit(page, click="btnLogin", overrides={"txtUserId": user, "txtPassword": password})
    assert r.status_code == 302 and r.headers["Location"] == "/Menu.aspx", r.text
    menu = Page(b.get(r.headers["Location"]))
    return b, menu


def navkey_of(menu: Page) -> str:
    onclick = menu.soup.find("a", id="lnkSearch")["onclick"]
    m = re.fullmatch(r"window\.open\('Search\.aspx\?key=(\w+)','search',"
                     r"'width=980,height=720,resizable=yes,scrollbars=yes'\);return false;", onclick)
    assert m, onclick
    return m.group(1)


def open_search(b: Browser, navkey: str) -> Page:
    r = b.get(f"Search.aspx?key={navkey}")
    assert r.status_code == 200, r.text
    return Page(r)


def choose_plant(b: Browser, search: Page, plant: str) -> Page:
    r = b.submit(search, overrides={"ddlPlant": plant}, postback=("ddlPlant", ""))
    assert r.status_code == 200, r.text
    return Page(r)


# --------------------------------------------------------------------------- tests


def test_import_is_side_effect_free(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["factory_site.py", "SHOULD_NOT_BE_READ.log", "1"])
    module = _load_site()
    assert callable(module.make_server) and callable(module.main) and callable(module.serve_in_thread)
    assert module.CREDENTIALS == ("tanaka", "Seisan#2026!")
    assert list(tmp_path.iterdir()) == []


def test_dataset_and_helpers():
    rows = fs.dataset()
    assert len(rows) == 280  # 35 working days (2026/09/01-2026/10/10 without Sundays) x 8 records
    assert rows == fs.dataset()  # deterministic
    assert (fs.DEFAULT_FROM, fs.DEFAULT_TO) == ("2026/09/01", "2026/10/10")
    l11 = fs.expected_rows("01", "L11", "ALL", fs.DEFAULT_FROM, fs.DEFAULT_TO, "")
    assert len(l11) > 2 * fs.PAGE_SIZE  # the result needs more than two pages
    assert [r[0] for r in l11] == sorted(r[0] for r in l11)
    assert all(r[1] == "L11" and r[2] in ("日勤", "夜勤") for r in l11)
    # the recording scenario's filter (tests/ie_support.py, factory_scenario section) has exactly two pages
    scenario = fs.expected_rows("01", "L11", "D", fs.DEFAULT_FROM, fs.DEFAULT_TO, "A-1002")
    assert scenario == [r for r in l11 if r[2] == "日勤" and r[3] == "A-1002"]
    assert fs.PAGE_SIZE < len(scenario) <= 2 * fs.PAGE_SIZE
    assert fs.expected_rows("01", "L11", "D", "2026/10/01", "2026/10/10", "A-1002") == [
        r for r in scenario if r[0] >= "2026/10/01"]
    assert fs.expected_rows("01", "L11", "ALL", "2026/10/04", "2026/10/04", "") == []  # Sunday
    sheet = [fs.EXPORT_HEADER, ("2026/10/01", "L11", "日勤", "A-1001", 120, 118, 2), ("出力ID", "EX1")]
    assert fs.read_xlsx_rows(fs.build_xlsx(sheet)) == [list(fs.EXPORT_HEADER),
                                                      ["2026/10/01", "L11", "日勤", "A-1001", "120", "118", "2"],
                                                      ["出力ID", "EX1"]]
    assert fs.export_filename("01", "L11") == "生産実績_01_L11_20261011.xlsx"
    assert fs.parse_form(b"txtUserId=%93%63%92%86&btnLogin=%83%8D%83O%83C%83%93&a=1+2") == {
        "txtUserId": "田中", "btnLogin": "ログイン", "a": "1 2"}
    assert fs.hidden_fields('<input type="hidden" name="__VIEWSTATE" value="a&amp;b" /><input name="x" value="y">') == {
        "__VIEWSTATE": "a&b"}


def test_recording_scenario_matches_the_site(tmp_path, monkeypatch):
    """tests/ie_support.py (with the IE-engine recording scenario) imports without side
    effects, and its search filter is the page's default period with exactly two grid pages (it clicks
    the pager link 2 and expects 「2/2 ページ」)."""
    monkeypatch.chdir(tmp_path)
    path = os.path.join(ROOT, "tests", "ie_support.py")
    spec = importlib.util.spec_from_file_location("reqrec_factory_scenario_check", path)
    assert spec is not None and spec.loader is not None
    scenario = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scenario)
    assert list(tmp_path.iterdir()) == []
    plant, line, shift, date_from, date_to, item = scenario.SCENARIO_FILTER
    assert (date_from, date_to) == (fs.DEFAULT_FROM, fs.DEFAULT_TO)
    assert dict(fs.PLANTS)[plant] == "本社工場" and dict(fs.LINES[plant])[line] == "組立1ライン"
    assert dict(fs.SHIFTS)[shift] == "日勤" and item in dict(fs.ITEMS[plant])
    rows = fs.expected_rows(*scenario.SCENARIO_FILTER)
    assert fs.PAGE_SIZE < len(rows) <= 2 * fs.PAGE_SIZE
    assert scenario.STEPS[0] == "start" and scenario.STEPS[-1] == "close"


def test_root_static_and_auth_redirects(site):
    server, log = site
    b = Browser(server.base_url)
    r = b.get("/")
    assert r.status_code == 302 and r.headers["Location"] == "/Login.aspx"
    assert r.headers["Server"] == "Microsoft-IIS/8.5"
    css = b.get("/css/site.css")
    assert css.status_code == 200 and css.headers["Content-Type"] == "text/css" and b"#header" in css.content
    gif = b.get("/img/logo.gif")
    assert gif.status_code == 200 and gif.headers["Content-Type"] == "image/gif" and gif.content.startswith(b"GIF89a")
    ico = b.get("/favicon.ico")
    assert ico.status_code == 200 and ico.headers["Content-Type"] == "image/x-icon"
    assert ico.content.startswith(b"\x00\x00\x01\x00")
    again = b.get("/img/logo.gif", headers={"If-None-Match": gif.headers["ETag"]})
    assert again.status_code == 304
    missing = b.get("/nothing.aspx")
    assert missing.status_code == 404
    Page(missing)  # still a Shift_JIS page
    for path in ("Menu.aspx", "News.aspx", "Search.aspx?key=x", "ItemPicker.aspx?plant=01&key=x"):
        r = b.get(path)
        name = path.split("?")[0]
        assert r.status_code == 302 and r.headers["Location"] == f"/Login.aspx?ReturnUrl=%2f{name}", (path, r.headers)
    assert not b.session.cookies  # no session is issued outside the login page
    entries = log_entries(log)
    assert [e["event"] for e in entries[:6]] == ["redirect", "static", "static", "static", "static", "not_found"]
    assert all(e["auth_ok"] is False and e["session"] is None for e in entries)


def test_login_page_markup_session_cookie_and_encoding(site):
    server, log = site
    b = Browser(server.base_url)
    r = b.get("Login.aspx")
    assert r.status_code == 200
    assert r.encoding.lower() == "shift_jis" and "生産管理システム" in r.text
    assert "ログイン".encode("cp932") in r.content
    cookies = set_cookies(r)
    sid = cookie_value(cookies, "ASP.NET_SessionId")
    assert sid and re.fullmatch(r"[a-z0-9]{24}", sid)
    assert "HttpOnly" in cookies[0] and "path=/" in cookies[0]
    page = Page(r)
    form = page.form
    assert form["method"] == "post" and form["action"] == "Login.aspx"
    vs = page.hidden("__VIEWSTATE")
    assert len(vs) >= 100 and re.fullmatch(r"[A-Za-z0-9+/]+=*", vs)
    assert page.hidden("__VIEWSTATEGENERATOR") == fs.VIEWSTATE_GENERATORS["Login.aspx"]
    assert re.fullmatch(r"[A-Za-z0-9+/]+=*", page.hidden("__EVENTVALIDATION"))
    assert page.soup.find("input", {"name": "txtUserId"})["type"] == "text"
    assert page.soup.find("input", {"name": "txtPassword"})["type"] == "password"
    btn = page.soup.find("input", {"name": "btnLogin"})
    assert btn["type"] == "submit" and btn["value"] == "ログイン"
    # the same session gets no new cookie but fresh tokens
    r2 = b.get("Login.aspx")
    assert cookie_value(set_cookies(r2), "ASP.NET_SessionId") is None
    page2 = Page(r2)
    assert page2.hidden("__VIEWSTATE") != vs and page2.hidden("__EVENTVALIDATION") != page.hidden("__EVENTVALIDATION")
    # a cp932 user id is decoded on the server and echoed back
    r3 = b.submit(page2, click="btnLogin", overrides={"txtUserId": "田中", "txtPassword": "x"})
    assert r3.status_code == 200
    page3 = Page(r3)
    assert page3.message() == "ユーザー ID またはパスワードが違います。"
    assert page3.soup.find("input", {"name": "txtUserId"})["value"] == "田中"
    fail = [e for e in log_entries(log) if e["event"] == "login_fail"][-1]
    assert fail["details"]["user"] == "田中" and fail["session"] == sid


def test_full_browser_flow(site):
    server, log = site
    b = Browser(server.base_url)

    # ---- login: wrong password, reused token, success with session rotation ------------
    r = b.get("/")
    assert r.status_code == 302
    login1 = Page(b.get(r.headers["Location"]))
    sid_before = b.cookie("ASP.NET_SessionId")
    user, password = fs.CREDENTIALS
    r = b.submit(login1, click="btnLogin", overrides={"txtUserId": user, "txtPassword": "seisan#2026!"})
    login2 = Page(r)
    assert r.status_code == 200 and login2.message() == "ユーザー ID またはパスワードが違います。"
    assert login2.hidden("__VIEWSTATE") != login1.hidden("__VIEWSTATE")
    r = b.submit(login1, click="btnLogin", overrides={"txtUserId": user, "txtPassword": password})
    assert r.status_code == 500 and fs.VIEWSTATE_ERROR in r.content.decode("cp932")
    r = b.submit(login2, click="btnLogin", overrides={"txtUserId": user, "txtPassword": password})
    assert r.status_code == 302 and r.headers["Location"] == "/Menu.aspx"
    cookies = set_cookies(r)
    sid_after = cookie_value(cookies, "ASP.NET_SessionId")
    auth = cookie_value(cookies, ".ASPXAUTH")
    assert sid_after and sid_after != sid_before and re.fullmatch(r"[a-z0-9]{24}", sid_after)
    assert auth and re.fullmatch(r"[0-9A-Fa-f]{64}", auth)
    assert all("HttpOnly" in c for c in cookies)
    assert b.cookie("ASP.NET_SessionId") == sid_after

    # ---- menu --------------------------------------------------------------------------
    menu = Page(b.get("Menu.aspx"))
    assert "ようこそ 田中 太郎 さん" in menu.soup.get_text()
    navkey = navkey_of(menu)
    news_link = menu.soup.find("a", id="lnkNews")
    assert news_link["href"] == "News.aspx" and news_link["target"] == "_blank"
    assert menu.soup.find("a", id="lnkLogout")["href"] == "Logout.aspx"
    assert menu.soup.find("img", src="/img/logo.gif") and menu.soup.find("link", href="/css/site.css")
    news = Page(b.get(news_link["href"]))
    assert "お知らせ" in news.soup.get_text() and news.resp.status_code == 200

    # ---- Search.aspx (the window.open popup) --------------------------------------------
    assert b.get("Search.aspx?key=WRONGKEY").status_code == 403
    assert b.get("Search.aspx").status_code == 403
    search = open_search(b, navkey)
    assert search.form["action"] == f"Search.aspx?key={navkey}"
    assert "function __doPostBack(eventTarget, eventArgument)" in search.text
    assert search.hidden("__EVENTTARGET") == "" and search.hidden("__EVENTARGUMENT") == ""
    assert search.hidden("__VIEWSTATEGENERATOR") == fs.VIEWSTATE_GENERATORS["Search.aspx"]
    plant_sel = search.soup.find("select", {"name": "ddlPlant"})
    assert plant_sel["onchange"] == "__doPostBack('ddlPlant','')"
    assert [(v, t) for v, t, _ in search.select_options("ddlPlant")] == [
        ("", "-- 選択してください --"), ("01", "本社工場"), ("02", "第二工場")]
    assert search.select_options("ddlLine") == []
    assert [(v, t) for v, t, _ in search.select_options("ddlShift")] == [("ALL", "全て"), ("D", "日勤"), ("N", "夜勤")]
    assert search.soup.find("input", {"name": "txtFrom"})["value"] == fs.DEFAULT_FROM == "2026/09/01"
    assert search.soup.find("input", {"name": "txtTo"})["value"] == fs.DEFAULT_TO == "2026/10/10"
    assert search.soup.find("input", {"name": "txtItem"})["readonly"] == "readonly"
    pick = search.soup.find("input", {"name": "btnPick"})
    assert pick["type"] == "button" and pick["value"] == "品番選択"
    assert (f"var r = window.showModalDialog('ItemPicker.aspx?plant=' + plant + '&key={navkey}', window, "
            "'dialogWidth:420px;dialogHeight:360px'); if (r) document.getElementById('txtItem').value = r;") in pick["onclick"]
    assert "alert(" in pick["onclick"]
    assert search.soup.find("input", {"name": "btnSearch"})["value"] == "検索"
    assert search.soup.find("input", {"name": "btnExcel"})["value"] == "Excel出力"
    assert search.soup.find("table", id="gvResult") is None

    # ---- AutoPostBack of the plant fills the lines ---------------------------------------
    plant01 = choose_plant(b, search, "01")
    assert [(v, t, s) for v, t, s in plant01.select_options("ddlPlant") if s] == [("01", "本社工場", True)]
    assert [(v, t) for v, t, _ in plant01.select_options("ddlLine")] == [("L11", "組立1ライン"), ("L12", "組立2ライン")]

    # ---- the modal item picker -----------------------------------------------------------
    picker = Page(b.get(f"ItemPicker.aspx?plant=01&key={navkey}"))
    links = picker.soup.select("#tblItems a")
    assert [a["id"] for a in links] == ["item_A-1001", "item_A-1002", "item_A-1003"]
    assert links[0]["onclick"] == "window.returnValue='A-1001';window.close();return false;"
    assert "ブラケット" in picker.soup.get_text()

    # ---- a line that does not belong to the plant is an invalid postback argument --------
    r = b.submit(plant01, click="btnSearch", overrides={"ddlLine": "L21"})
    assert r.status_code == 500 and fs.POSTBACK_ERROR in r.content.decode("cp932")
    r = b.submit(plant01, click="btnSearch", overrides={"ddlPlant": "02", "ddlLine": "L11"})
    assert r.status_code == 500 and fs.POSTBACK_ERROR in r.content.decode("cp932")

    # ---- search, page 2 ------------------------------------------------------------------
    expected = fs.expected_rows("01", "L11", "ALL", fs.DEFAULT_FROM, fs.DEFAULT_TO, "")
    pages = (len(expected) + fs.PAGE_SIZE - 1) // fs.PAGE_SIZE
    assert pages > 2
    r = b.submit(plant01, click="btnSearch", overrides={"ddlLine": "L11"})  # the rejected posts used up nothing
    assert r.status_code == 200
    page1 = Page(r)
    assert page1.grid_rows() == expected[:fs.PAGE_SIZE]
    assert f"{len(expected)} 件（1/{pages} ページ）" in page1.soup.find(id="lblCount").get_text()
    assert page1.pager_links() == [f"javascript:__doPostBack('gvResult','Page${n}')" for n in range(2, pages + 1)]
    # paging keeps the searched filter even when a control was changed without searching again
    r = b.submit(page1, overrides={"ddlShift": "N"}, postback=("gvResult", "Page$2"))
    assert r.status_code == 200
    page2 = Page(r)
    assert page2.grid_rows() == expected[fs.PAGE_SIZE:2 * fs.PAGE_SIZE]
    assert page2.pager_links() == [f"javascript:__doPostBack('gvResult','Page${n}')" for n in range(1, pages + 1) if n != 2]
    # page 1's tokens were used by the paging postback
    r = b.submit(page1, postback=("gvResult", "Page$2"))
    assert r.status_code == 500 and fs.VIEWSTATE_ERROR in r.content.decode("cp932")
    # a page that was never rendered is not a valid argument
    r = b.submit(page2, postback=("gvResult", "Page$9"))
    assert r.status_code == 500 and fs.POSTBACK_ERROR in r.content.decode("cp932")

    # ---- Excel出力 -------------------------------------------------------------------------
    r = b.submit(page2, click="btnExcel", overrides={"ddlShift": "ALL"})
    assert r.status_code == 200
    assert r.headers["Content-Type"] == fs.XLSX_CONTENT_TYPE
    assert r.headers["Cache-Control"] == "private"
    disposition = r.headers["Content-Disposition"]
    m = re.fullmatch(r"attachment; filename=([A-Za-z0-9%._-]+)", disposition)
    assert m, disposition
    assert unquote(m.group(1), encoding="utf-8") == "生産実績_01_L11_20261011.xlsx"
    sheet = fs.read_xlsx_rows(r.content)
    assert sheet[0] == list(fs.EXPORT_HEADER)
    assert [tuple(row) for row in sheet[1:-1]] == expected  # every matching row, not one page
    assert sheet[-1][0] == "出力ID" and re.fullmatch(r"EX[0-9A-F]{12}", sheet[-1][1])
    export_id = sheet[-1][1]
    # the download leaves the page in the browser: its tokens still work (filters as posted)
    r = b.submit(page2, click="btnExcel", overrides={"ddlShift": "D", "txtItem": "A-1002"})
    assert r.status_code == 200
    sheet2 = fs.read_xlsx_rows(r.content)
    assert [tuple(row) for row in sheet2[1:-1]] == fs.expected_rows("01", "L11", "D", fs.DEFAULT_FROM, fs.DEFAULT_TO, "A-1002")
    assert sheet2[-1][1] != export_id
    r = b.submit(page2, click="btnSearch", overrides={"ddlShift": "N"})
    assert r.status_code == 200
    assert Page(r).grid_rows() == fs.expected_rows("01", "L11", "N", fs.DEFAULT_FROM, fs.DEFAULT_TO, "")[:fs.PAGE_SIZE]

    # ---- logout -------------------------------------------------------------------------
    r = b.get("Logout.aspx")
    assert r.status_code == 302 and r.headers["Location"] == "/Login.aspx"
    r = b.get("Menu.aspx")
    assert r.status_code == 302 and r.headers["Location"].startswith("/Login.aspx?ReturnUrl=")

    # ---- log --------------------------------------------------------------------------
    entries = log_entries(log)
    for e in entries:
        assert {"t", "method", "path", "query", "session", "auth_ok", "event", "details"} <= set(e)
        assert isinstance(e["t"], float) and e["event"]
    names = [e["event"] for e in entries]
    for name in ("login_page", "login_fail", "viewstate_reject", "login_ok", "menu", "news", "navkey_reject",
                 "search_page", "plant_change", "picker", "eventvalidation_reject", "search", "page",
                 "excel_export", "logout", "auth_redirect"):
        assert name in names, (name, names)
    ok = next(e for e in entries if e["event"] == "login_ok")
    assert ok["session"] == sid_before and ok["details"]["new_session"] == sid_after
    # the Shift_JIS-encoded submit button values arrive decoded
    assert ok["details"]["button"] == "ログイン"
    assert next(e for e in entries if e["event"] == "search")["details"]["button"] == "検索"
    assert next(e for e in entries if e["event"] == "excel_export")["details"]["button"] == "Excel出力"
    exports = [e for e in entries if e["event"] == "excel_export"]
    assert exports[0]["details"]["export_id"] == export_id and exports[0]["details"]["rows"] == len(expected)
    assert exports[0]["details"]["filters"]["line"] == "L11" and exports[0]["auth_ok"] is True
    rejects = [e for e in entries if e["event"] in ("viewstate_reject", "eventvalidation_reject")]
    assert all(e["details"].get("reason") for e in rejects)
    assert any(e["details"]["reason"] == "viewstate_reused" for e in rejects)
    assert any(e["details"]["reason"].startswith("ddlLine_not_rendered:L21") for e in rejects)
    assert any(e["details"]["reason"].startswith("line_not_in_plant:L11@02") for e in rejects)
    assert all(e["ua"] == IE7_UA for e in entries)


def test_stale_session_or_auth_cookie_redirects_to_login(site, tmp_path):
    server, _log = site
    b = Browser(server.base_url)
    first = Page(b.get("Login.aspx"))
    old_sid = b.cookie("ASP.NET_SessionId")
    user, password = fs.CREDENTIALS
    r = b.submit(first, click="btnLogin", overrides={"txtUserId": user, "txtPassword": password})
    assert r.status_code == 302
    sid, auth = b.cookie("ASP.NET_SessionId"), b.cookie(".ASPXAUTH")
    url = server.base_url + "Menu.aspx"

    def menu_with(cookie_header: Optional[str]) -> requests.Response:
        headers = {"User-Agent": IE7_UA}
        if cookie_header is not None:
            headers["Cookie"] = cookie_header
        return requests.get(url, headers=headers, allow_redirects=False, timeout=10)

    assert menu_with(f"ASP.NET_SessionId={sid}; .ASPXAUTH={auth}").status_code == 200
    for cookie in (
        f"ASP.NET_SessionId={old_sid}; .ASPXAUTH={auth}",   # the pre-login session id (rotated away)
        f"ASP.NET_SessionId={sid}; .ASPXAUTH={'0' * 64}",    # wrong auth ticket
        f"ASP.NET_SessionId={sid}",                          # no auth ticket
        f".ASPXAUTH={auth}",                                 # no session
        None,
    ):
        r = menu_with(cookie)
        assert r.status_code == 302 and r.headers["Location"] == "/Login.aspx?ReturnUrl=%2fMenu.aspx", cookie
    # cookies from another run of the site are never valid
    other = fs.serve_in_thread(str(tmp_path / "other.log"))
    try:
        ob, _menu = login(other.base_url)
        r = menu_with(f"ASP.NET_SessionId={ob.cookie('ASP.NET_SessionId')}; .ASPXAUTH={ob.cookie('.ASPXAUTH')}")
        assert r.status_code == 302
    finally:
        other.stop()


def test_viewstate_must_belong_to_this_session_and_page(site, tmp_path):
    server, log = site
    a, b = Browser(server.base_url), Browser(server.base_url)
    pa, pb = Page(a.get("Login.aspx")), Page(b.get("Login.aspx"))
    pa2 = Page(a.get("Login.aspx"))
    creds = {"txtUserId": fs.CREDENTIALS[0], "txtPassword": fs.CREDENTIALS[1]}

    def rejected(r: requests.Response) -> bool:
        return r.status_code == 500 and fs.VIEWSTATE_ERROR in r.content.decode("cp932")

    assert rejected(a.post(pa.action_url, pb.fields(click="btnLogin", overrides=creds)))  # B's tokens
    assert rejected(a.submit(pa, click="btnLogin", overrides=dict(creds, __EVENTVALIDATION=pa2.hidden("__EVENTVALIDATION"))))
    assert rejected(a.submit(pa, click="btnLogin", overrides=dict(creds, __EVENTVALIDATION="")))
    assert rejected(a.submit(pa, click="btnLogin", overrides=dict(creds, __VIEWSTATEGENERATOR="00000000")))
    no_session = Browser(server.base_url)
    assert rejected(no_session.post(pa.action_url, pa.fields(click="btnLogin", overrides=creds)))
    # tokens of a previous server run are unknown
    other = fs.serve_in_thread(str(tmp_path / "other.log"))
    try:
        op = Page(Browser(other.base_url).get("Login.aspx"))
    finally:
        other.stop()
    assert rejected(a.post(pa.action_url, op.fields(click="btnLogin", overrides=creds)))
    # none of the rejected posts used up pa's tokens
    r = a.submit(pa, click="btnLogin", overrides=creds)
    assert r.status_code == 302
    # Login.aspx tokens are not accepted by Search.aspx
    menu = Page(a.get("Menu.aspx"))
    navkey = navkey_of(menu)
    search = open_search(a, navkey)
    login_again = Page(a.get("Login.aspx"))
    forged = search.fields(click="btnSearch", overrides={
        "__VIEWSTATE": login_again.hidden("__VIEWSTATE"),
        "__EVENTVALIDATION": login_again.hidden("__EVENTVALIDATION"),
    })
    assert rejected(a.post(search.action_url, forged))
    reasons = [e["details"]["reason"] for e in log_entries(log) if e["event"] in ("viewstate_reject", "eventvalidation_reject")]
    assert reasons == ["viewstate_of_other_session", "eventvalidation_mismatch", "missing_eventvalidation",
                       "bad_viewstategenerator", "no_session", "unknown_viewstate", "viewstate_of_page:Login.aspx"]


def test_navkey_is_checked(site):
    server, log = site
    b, menu = login(server.base_url)
    navkey = navkey_of(menu)
    other_b, other_menu = login(server.base_url)
    other_key = navkey_of(other_menu)
    assert other_key != navkey
    search = open_search(b, navkey)
    for path in ("Search.aspx", "Search.aspx?key=", f"Search.aspx?key={other_key}",
                 f"ItemPicker.aspx?plant=01&key={other_key}", "ItemPicker.aspx?plant=01"):
        r = b.get(path)
        assert r.status_code == 403, path
        assert "不正なアクセスです。" in Page(r).text
    r = b.post(f"Search.aspx?key={other_key}", search.fields(click="btnSearch"))
    assert r.status_code == 403
    rejects = [e for e in log_entries(log) if e["event"] == "navkey_reject"]
    assert len(rejects) == 6 and all(e["auth_ok"] for e in rejects)


def test_search_validation_messages(site):
    server, _log = site
    b, menu = login(server.base_url)
    navkey = navkey_of(menu)
    search = open_search(b, navkey)
    r = b.submit(search, click="btnSearch")
    no_plant = Page(r)
    assert r.status_code == 200 and no_plant.message() == "工場を選択してください。"
    r = b.submit(no_plant, click="btnExcel")  # no download without a plant
    assert r.status_code == 200 and Page(r).message() == "工場を選択してください。"
    page = choose_plant(b, Page(r), "02")
    assert page.select_options("ddlLine")[0][:2] == ("L21", "プレスライン")

    def search_with(current: Page, **overrides: str) -> Page:
        resp = b.submit(current, click="btnSearch", overrides=overrides)
        assert resp.status_code == 200, resp.content.decode("cp932")
        return Page(resp)

    page = search_with(page, txtFrom="2026/13/01")
    assert page.message() == "日付は yyyy/mm/dd の形式で入力してください。"
    page = search_with(page, txtFrom="2026/10/09", txtTo="2026/10/02")
    assert page.message() == "期間の開始日が終了日より後になっています。"
    page = search_with(page, txtFrom="2026/10/01", txtTo="2026/10/10", txtItem="A-1001")
    assert page.message() == "品番が正しくありません。"
    empty = search_with(page, ddlLine="L22", txtFrom="2026/10/04", txtTo="2026/10/04", txtItem="")
    assert empty.message() == ""
    assert "該当するデータがありません。" in empty.soup.find("table", id="gvResult").get_text()
    result = search_with(empty, ddlLine="L22", ddlShift="D", txtFrom="2026/10/1", txtTo="2026/10/10", txtItem="B-2002")
    assert result.grid_rows() == fs.expected_rows("02", "L22", "D", "2026/10/01", "2026/10/10", "B-2002")
    assert result.pager_links() == []
    # switching the plant resets the line and clears the item
    plant01 = choose_plant(b, result, "01")
    assert [v for v, _t, s in plant01.select_options("ddlLine") if s] == ["L11"]
    assert plant01.soup.find("input", {"name": "txtItem"})["value"] == ""
    picker = Page(b.get(f"ItemPicker.aspx?plant=&key={navkey}"))
    assert picker.message() == "工場が選択されていません。"
    # pages without postback controls still validate a posted form (and keep the URL key in the action)
    picker = Page(b.get(f"ItemPicker.aspx?plant=02&key={navkey}"))
    assert picker.form["action"] == f"ItemPicker.aspx?plant=02&key={navkey}"
    r = b.submit(picker)
    assert r.status_code == 200 and "フレーム" in Page(r).text
    r = b.submit(picker)
    assert r.status_code == 500 and fs.VIEWSTATE_ERROR in r.content.decode("cp932")


def test_concurrent_logins_and_log_lines(site):
    server, log = site
    errors: List[str] = []

    def worker() -> None:
        try:
            b, menu = login(server.base_url)
            search = open_search(b, navkey_of(menu))
            page = choose_plant(b, search, "01")
            r = b.submit(page, click="btnSearch")
            assert r.status_code == 200 and len(Page(r).grid_rows()) == fs.PAGE_SIZE
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, errors
    with open(log, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    parsed = [json.loads(line) for line in lines]
    assert sum(1 for e in parsed if e["event"] == "login_ok") == 8
    assert len({e["details"]["new_session"] for e in parsed if e["event"] == "login_ok"}) == 8


def test_command_line(tmp_path):
    port = _free_port()
    log = tmp_path / "cli.log"
    proc = subprocess.Popen([sys.executable, "-I", SITE_PATH, "factory-site", str(log), str(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        deadline = time.monotonic() + 20
        while True:
            assert proc.poll() is None, proc.stdout.read() if proc.stdout else ""
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                assert time.monotonic() < deadline, "site did not start"
                time.sleep(0.1)
        r = requests.get(f"http://127.0.0.1:{port}/Login.aspx", timeout=10)
        assert r.status_code == 200 and "ログイン" in r.content.decode("cp932")
    finally:
        proc.kill()
        proc.wait(timeout=10)
        if proc.stdout:
            proc.stdout.close()
    assert [e["event"] for e in fs.read_log(str(log))] == ["login_page"]


# ===== former tests/e2e/test_gui_recording.py: the GUI's recording path with the real mitmdump =====
# End-to-end: the GUI's recording path with the **real** ``mitmdump`` (DESIGN.md §13.6, §13.12).
#
# [記録開始] starts ``mitmdump`` with the reqrec addon exactly as ``reqrec gui`` does (``RecorderManager``
# on a free port of 127.0.0.1 with ``HTTPS_PASSTHROUGH_ARGS``) and then opens the recording browser
# through it.  The recording browser itself is faked (``iehost.availability`` / ``launch`` /
# ``get_emulation`` / ``set_emulation`` patched, so this runs without RecBrowser.exe; the opt-in sections
# above drive the real one): ``requests`` with ``proxies=`` stands in for it and browses the site of
# ``tests/support.py`` through the proxy address the GUI handed to the browser.  「記録停止して読み込む」
# closes the browser, loads the recording and the steps table lists the proxied requests.  The first
# test drives the JSON API with Flask's test client and goes on to generate, save and *run* the script
# from the GUI against a restarted site (fresh tokens); the last one clicks through 詳細設定「1 記録」
# in a real browser with Playwright.
#
# Runs on every OS; skipped when mitmproxy is not installed (the browser test also when Playwright /
# Chromium are missing).

#: The former module-level ``pytestmark`` of this section (applied to each of its tests).
needs_mitmdump = pytest.mark.skipif(not mitmproxy_available(), reason="mitmproxy (mitmdump) not installed")

TOKEN = "e2e-gui-token"
#: GET /login, POST /login (302), GET /dashboard, 3 x GET /api/items, GET /export, GET /static/app.css
EXPECTED_FLOWS = 8
#: ``record_start`` waits for the real mitmdump itself; its own limit (20 s) is short for a cold first import.
PROXY_START_TIMEOUT = 60.0
CHROMIUM_CANDIDATES = [os.environ.get("REQREC_CHROMIUM"), "/opt/pw-browsers/chromium"]
#: What the faked ``iehost.availability`` reports: the recording browser can be used.
STAND_IN_AVAILABLE = {"available": True, "reason": None, "exe": "RecBrowser.exe", "built": True,
                      "source": "RecBrowser.cs", "csc": "csc.exe", "prebuilt": None}


# --------------------------------------------------------------------------- helpers


class _StandInBrowser:
    """What the faked ``iehost.launch`` returns: a recording browser that stays open until the GUI closes it."""

    pid = 4242
    log_path = None

    def __init__(self) -> None:
        self.code: Optional[int] = None

    def poll(self) -> Optional[int]:
        return self.code

    def close(self, timeout: float = 5.0) -> int:
        if self.code is None:
            self.code = 0
        return self.code


def _fake_recording_browser(monkeypatch: pytest.MonkeyPatch) -> List[Dict[str, Any]]:
    """Replace the recording browser by :class:`_StandInBrowser`; returns the ``iehost.launch`` calls."""
    launched: List[Dict[str, Any]] = []

    def launch(workdir: str, proxy_address: str, url: Optional[str] = None, title: Optional[str] = None, **kwargs: Any):
        launched.append({"workdir": workdir, "proxy_address": proxy_address, "url": url, "title": title, **kwargs})
        return _StandInBrowser()

    monkeypatch.setattr(reqrec.iehost, "availability", lambda workdir, **kw: dict(STAND_IN_AVAILABLE))
    monkeypatch.setattr(reqrec.iehost, "launch", launch)
    monkeypatch.setattr(reqrec.iehost, "get_emulation", lambda *a, **kw: None)  # the registry is never read
    monkeypatch.setattr(reqrec.iehost, "set_emulation", lambda *a, **kw: None)  # ... nor written
    monkeypatch.setattr(reqrec, "PROXY_READY_TIMEOUT", PROXY_START_TIMEOUT)
    return launched


def _wait_until(pred: Callable[[], bool], timeout: float, what: str, interval: float = 0.2) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {what}")


def _drive_site_through_proxy(base_url: str, proxy_port: int) -> dict[str, str]:
    """The user's session in the recording browser: login -> dashboard -> 3 pages -> CSV export (+ one static file)."""
    session = requests.Session()
    session.trust_env = False  # never use the sandbox's HTTP(S)_PROXY for the local site
    proxies = {"http": f"http://127.0.0.1:{proxy_port}"}  # http:// only, like the recording browser
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
def gui(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    launched = _fake_recording_browser(monkeypatch)
    workdir = tmp_path / "gui_work"
    app = create_app(str(workdir), host="127.0.0.1", port=_free_port(), token=TOKEN, TESTING=True)
    client = app.test_client()
    headers = {TOKEN_HEADER: TOKEN}
    try:
        yield SimpleNamespace(app=app, client=client, workdir=workdir, H=headers, state=app.extensions["reqrec"],
                              launched=launched)
    finally:
        app.extensions["reqrec"].close()


# --------------------------------------------------------------------------- JSON API path

@needs_mitmdump
def test_record_with_real_mitmdump_then_plan_generate_and_run(gui):
    client, H, state = gui.client, gui.H, gui.state
    server, base_url = start_server()
    try:
        # -- 記録開始: the proxy on a free port, then the recording browser through it ---------------
        r = client.post("/api/record/start", json={"hosts": ["127.0.0.1"]}, headers=H)
        assert r.status_code == 200, r.get_json()
        started = r.get_json()
        proxy_port = started["port"]
        assert started["status"]["running"] is True and started["status"]["error"] is None
        assert started["proxy_address"] == f"127.0.0.1:{proxy_port}"
        assert re.fullmatch(r"rec_\d{8}_\d{6}\.json", started["out"])
        assert started["status"]["hosts"] == ["127.0.0.1"]
        assert started["browser"]["kind"] == "iehost" and started["browser"]["running"] is True
        assert [(c["proxy_address"], c["url"]) for c in gui.launched] == [(started["proxy_address"], None)]
        # the browser is opened only once mitmdump accepts connections
        socket.create_connection(("127.0.0.1", proxy_port), timeout=5).close()

        # -- the user browses in the recording browser -----------------------------------------------
        tokens = _drive_site_through_proxy(base_url, proxy_port)
        _wait_until(lambda: client.get("/api/record/status").get_json()["flows"] == EXPECTED_FLOWS, 30,
                    f"{EXPECTED_FLOWS} recorded flows (live count)")
        live = client.get("/api/record/status").get_json()
        assert live["running"] is True and live["flows"] == EXPECTED_FLOWS
        assert live["browser"]["kind"] == "iehost" and live["browser"]["running"] is True
        assert client.get("/api/state").get_json()["recorder"]["running"] is True

        # -- 記録停止して読み込む (the recording browser is closed first) ------------------------------
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 200, r.get_json()
        stopped = r.get_json()
        assert stopped["loaded"] is True and stopped["flows"] == EXPECTED_FLOWS
        assert stopped["sources"] == [f"recordings/{started['out']}"]
        assert stopped["excluded_self"] == 0 and stopped["browser_exit_code"] == 0
        # mitmdump exits 0 after SIGINT; on Windows the CTRL_BREAK ends it with STATUS_CONTROL_C_EXIT
        # (0xC000013A), after the addon has flushed every flow: the recording is complete either way
        assert stopped["exit_code"] == 0 or (os.name == "nt" and stopped["exit_code"] is not None)
        assert (gui.workdir / "recordings" / started["out"]).is_file()
        assert state.recorder.running is False and state.browser is None
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
        # the export was saved by the script into the outputs folder; its stdout names it, then prints it
        assert (gui.workdir / "outputs" / "items.csv").read_text(encoding="utf-8").startswith("id,name\n1,item-1-1\n")
        out = client.post("/api/run/save_output", json={"name": "recorded_site_out.txt"}, headers=H).get_json()
        saved_out = (gui.workdir / "outputs" / "recorded_site_out.txt").read_text(encoding="utf-8")
        assert "items.csv" in saved_out and "id,name\n1,item-1-1\n" in saved_out
        assert out["size"] > 0
    finally:
        if state.recorder.running:
            state.recorder.stop()
        stop_server(server)


@needs_mitmdump
def test_record_stop_without_traffic_reports_japanese_error(gui):
    """Stopping a recording nobody browsed through must not load an empty recording."""
    client, H, state = gui.client, gui.H, gui.state
    r = client.post("/api/record/start", json={"hosts": ["127.0.0.1"]}, headers=H)
    assert r.status_code == 200, r.get_json()
    assert len(gui.launched) == 1  # mitmdump listened, the recording browser was opened (and never used)
    try:
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 400
        body = r.get_json()
        assert "何も記録されませんでした" in body["error"] and body["empty"] is True
        assert body["browser_exit_code"] == 0 and state.browser is None  # the recording browser was closed
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


@needs_mitmdump
def test_record_panel_in_real_browser_loads_recording_into_steps_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pw_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed")
    from werkzeug.serving import make_server

    launched = _fake_recording_browser(monkeypatch)  # before the page is rendered: [記録開始] is enabled
    workdir = tmp_path / "gui_work"
    app = create_app(str(workdir), host="127.0.0.1", port=8765)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    gui_port = srv.server_port
    app.extensions["reqrec"].port = gui_port
    threading.Thread(target=srv.serve_forever, name="reqrec-gui-e2e", daemon=True).start()
    server, base_url = start_server()
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

                page.click("#mode-toggle")  # 詳細設定: the default かんたん画面 hides the five panels
                page.click('.nav-step[data-panel="record"]')
                page.fill("#rec-hosts", "127.0.0.1")
                page.click("#btn-rec-start")
                expect(page.locator("#rec-state-text")).to_contain_text("記録中")
                address = page.locator("#rec-proxy-address")
                expect(address).to_have_text(re.compile(r"^127\.0\.0\.1:\d+$"))
                proxy_port = int(address.inner_text().rsplit(":", 1)[1])
                assert [c["proxy_address"] for c in launched] == [f"127.0.0.1:{proxy_port}"]
                expect(page.locator("#status-text")).to_contain_text("記録を開始しました")
                expect(page.locator("#rec-browser-state")).to_contain_text("起動中")
                expect(page.locator("#btn-rec-start")).to_be_disabled()
                expect(page.locator("#btn-rec-stop")).to_be_enabled()
                state = app.extensions["reqrec"]

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
                assert state.recorder.running is False and state.browser is None
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


# ===== former tests/e2e/test_factory_live.py: record, generate and replay the factory scenario (opt-in) =====
# Opt-in, real engine: record the factory scenario in RecBrowser.exe, generate the script, replay it
# against a FRESH mock server and check the Excel file (DESIGN.md §13.13).
#
# Runs only on Windows with ``REQREC_IEHOST_TESTS=1`` (it opens a browser window for ~15 s), the inbox
# C# compiler and mitmproxy.  The factory-replay section of ``tests/test_integration.py`` covers
# the same replay without a browser, from recordings made by this flow.

LIVE_ROOT = Path(__file__).resolve().parents[1]

#: The former module-level ``pytestmark`` of this section (applied to its test).
live_opt_in = pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("REQREC_IEHOST_TESTS") != "1",
    reason="real recording-browser test: Windows + REQREC_IEHOST_TESTS=1",
)


def _live_load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@live_opt_in
def test_record_generate_and_replay_the_factory_scenario(tmp_path):
    import reqrec as cli
    from reqrec import iehost

    if not iehost.availability(str(tmp_path / "iehost_work"))["available"]:
        pytest.skip("recording browser unavailable (no csc.exe)")
    pytest.importorskip("mitmproxy")
    fs = _live_load("factory_site_live", LIVE_ROOT / "tests" / "ie_support.py")
    sc = _live_load("factory_scenario_live", LIVE_ROOT / "tests" / "ie_support.py")

    exe = iehost.ensure_built(str(tmp_path / "iehost_work"))
    port = _free_port()
    rec = tmp_path / "rec.json"
    result = sc.run_factory_recording(str(tmp_path / "work"), str(rec), port, 0, exe)
    assert result["browser_exit_code"] == 0
    assert result["site_events"][-1] == "news" and "excel_export" in result["site_events"]

    script = tmp_path / "scrape_factory.py"
    assert cli.main(["generate", str(rec), "-o", str(script)]) == 0

    log = tmp_path / "replay.log"
    server = fs.serve_in_thread(str(log), port)  # fresh server: new session ids, tokens and URL keys
    try:
        out = tmp_path / "outputs"
        env = {k: v for k, v in os.environ.items() if not k.startswith("REQREC_")}
        env.update(PYTHONIOENCODING="utf-8", REQREC_OUTPUT_DIR=str(out), REQREC_TXT_PASSWORD=fs.CREDENTIALS[1])
        proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", env=env, cwd=str(tmp_path), timeout=120)
    finally:
        server.stop()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    events = [e["event"] for e in fs.read_log(str(log)) if e.get("event") not in ("static", "not_found")]
    assert events == ["login_page", "login_ok", "menu", "search_page", "plant_change", "picker", "search", "page",
                      "excel_export", "news"], events
    xlsx = out / fs.export_filename("01", "L11")
    rows = fs.read_xlsx_rows(xlsx.read_bytes())
    assert [tuple(r) for r in rows[1:-1]] == [tuple(r) for r in fs.expected_rows(*sc.SCENARIO_FILTER)]
