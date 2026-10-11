"""Engine test for the IE-host recording browser (``reqrec/iehost/RecBrowser.cs``).

The real test (``TestRecBrowserEngine``) drives the actual IE engine and is **opt-in**: it runs only
when all of the following hold, otherwise it is skipped.

* ``sys.platform == "win32"``
* ``REQREC_IEHOST_TESTS=1`` in the environment
* the inbox C# compiler exists (``C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe``)
* mitmproxy is installed (``mitmdump`` on PATH or the ``mitmproxy`` package)

What it does: compiles RecBrowser.cs with the production command line (``iehost.build_command``:
a 32-bit ``-platform:x86`` exe, checked in the PE header), starts the fixture site
(``tests/iehost_fixtures/testsite.py``) and a recorder (``mitmdump`` + reqrec addon, the GUI's
``HTTPS_PASSTHROUGH_ARGS``), runs ``RecBrowser.exe --selftest`` against the site and then checks
the host's log and the recording: the window.open popup, the ``target=_blank`` POST (with body),
the ``target=_blank`` link, the modeless and the modal dialog documents must all have gone
through the proxy.  The Windows proxy settings and FEATURE_BROWSER_EMULATION are compared
before/after: the host must not touch them.

The site is addressed as ``http://127.0.0.1.nip.io:<port>/`` because WinINet never proxies literal
loopback addresses; when that name does not resolve (offline PC) the test falls back to
``127.0.0.1`` with ``--bypass "<-loopback>"``.

Run::

    set REQREC_IEHOST_TESTS=1
    .venv\\Scripts\\python -m pytest tests/test_iehost_engine.py -q

The two small tests at the bottom run everywhere (fixture import safety, source guard rails).
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Optional

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CS_SOURCE = os.path.join(ROOT, "reqrec", "iehost", "RecBrowser.cs")
FIXTURE_SITE = os.path.join(ROOT, "tests", "iehost_fixtures", "testsite.py")
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
FEATURE_BROWSER_EMULATION = r"Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION"
PROXY_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")

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
    reason="IE-host engine test: needs Windows, REQREC_IEHOST_TESTS=1, the inbox csc.exe and mitmproxy",
)


# --------------------------------------------------------------------------- helpers

def _load_fixture_module():
    """Import tests/iehost_fixtures/testsite.py by path (no package import needed)."""
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
    cmd = iehost.build_command(CSC, CS_SOURCE, exe)
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
        from reqrec.recorder.run import build_command

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
                [sys.executable, "-I", FIXTURE_SITE, str(site_log), str(site_port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            _wait_port(site_port, proc=site)
            from reqrec.webapp.routes import HTTPS_PASSTHROUGH_ARGS

            recorder_cmd = build_command(
                str(rec_json), port=proxy_port, listen_host="127.0.0.1", quiet=True,
                extra_args=list(HTTPS_PASSTHROUGH_ARGS),
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
        assert any(f"/popup.html?via=open mode=" in line and "opener=yes name=cfgwin" in line for line in tab_lines), tab_lines
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
        cookie = fixture.SESSION_COOKIE.replace("=", "%3D")
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
    """Remove ``//`` and ``/* */`` comments (string literals in RecBrowser.cs never contain them)."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n]*", "", source)


def test_host_source_guard_rails():
    """RecBrowser.cs must keep the proven WinINet path and never touch the registry."""
    with open(CS_SOURCE, encoding="utf-8") as fh:
        source = fh.read()
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
