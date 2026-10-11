"""Records the factory mock site (``factory_site.py``) through the real recording browser - TEST ONLY.

:func:`run_factory_recording` starts the mock 生産管理システム, a recorder (mitmdump + the reqrec addon,
the GUI's ``HTTPS_PASSTHROUGH_ARGS``) and ``RecBrowser.exe``, then operates the pages with the test driver
(``IEDriver.cs`` / ``iedriver.py``) exactly like a factory user would:

==================  ==========================================================================
step                what the user does (what the engine sends)
==================  ==========================================================================
``start``           the browser opens ``/Login.aspx`` (GET, ``ASP.NET_SessionId``)
``login``           types tanaka / ``Seisan#2026!`` and clicks ログイン (POST -> 302 -> /Menu.aspx)
``open_search``     clicks 生産実績照会 = ``window.open('Search.aspx?key=<NAVKEY>')`` -> popup tab
``plant``           selects 本社工場 (AutoPostBack: ``__doPostBack('ddlPlant','')`` POST)
``line_shift``      selects 組立1ライン and 日勤 (no request)
``item_picker``     clicks 品番選択 = ``showModalDialog('ItemPicker.aspx?...')`` (GET in a dialog),
                    clicks A-1002 there; the dialog closes and txtItem becomes ``A-1002``
``search``          clicks 検索 (POST; 35 rows = 2 pages)
``page2``           clicks the pager link 2 = ``javascript:__doPostBack('gvResult','Page$2')`` (POST)
``excel``           clicks Excel出力 (POST answered with the .xlsx) and cancels the engine's
                    「ファイルのダウンロード」 dialog with キャンセル
``news``            clicks お知らせ in the menu tab (``target=_blank`` GET in a new tab)
``close``           closes the browser window (WM_CLOSE, exit code 0)
==================  ==========================================================================

Nothing is asserted here: the function only raises when a step cannot be performed in time
(:class:`ScenarioError` / ``iedriver.IEDriverError``).  The caller judges the run from the site log
(``factory_site.read_log``), the recording JSON and the returned timings.  The search filter is
:data:`SCENARIO_FILTER`; ``factory_site.expected_rows(*SCENARIO_FILTER)`` gives the rows of the grid
and of the Excel file.

Requirements: Windows, the inbox C# compiler (for ``IEDriver.exe``), mitmproxy, a compiled
``RecBrowser.exe`` (``reqrec.iehost.ensure_built``) and DNS for ``127.0.0.1.nip.io`` (WinINet never
proxies literal loopback addresses; without that name the site is addressed as ``127.0.0.1`` with the
``<-loopback>`` bypass override).  RecBrowser's windows appear on screen while the scenario runs.

Usage::

    scenario = <import tests/iehost_fixtures/factory_scenario.py by path>
    result = scenario.run_factory_recording(workdir, out_json, site_port=0, proxy_port=0,
                                            recbrowser_exe=reqrec.iehost.ensure_built(workdir))
    result["timings"]      # {"start": 1.9, "login": 1.2, ...} seconds per step
    result["site_log"]     # factory_site JSON-lines log of this run

Importing this module has no side effects (nothing is compiled, started or written).
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional

__all__ = ["SCENARIO_FILTER", "STEPS", "ScenarioError", "run_factory_recording", "site_host", "free_port",
           "load_fixture"]

FIXTURES = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(FIXTURES))
SITE_MODULE = os.path.join(FIXTURES, "factory_site.py")
DRIVER_MODULE = os.path.join(FIXTURES, "iedriver.py")
ADDON_PATH = os.path.join(ROOT, "reqrec", "recorder", "addon.py")

#: ``factory_site.expected_rows`` arguments of the search the scenario performs
#: (plant, line, shift, date_from, date_to, item); the dates are the page's defaults.
SCENARIO_FILTER = ("01", "L11", "D", "2026/09/01", "2026/10/10", "A-1002")

#: Step names, in order (keys of the returned ``timings``).
STEPS = ("start", "login", "open_search", "plant", "line_shift", "item_picker", "search", "page2",
         "excel", "news", "close")

#: Title / button of the engine's download dialog (Japanese Windows).
DOWNLOAD_DIALOG_TITLE = "ファイルのダウンロード"
DOWNLOAD_CANCEL = "キャンセル"

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class ScenarioError(RuntimeError):
    """A step could not be completed (timeout or a process that died)."""


# --------------------------------------------------------------------------- small helpers

def load_fixture(path: str, name: str) -> Any:
    """Import a module of ``tests/iehost_fixtures`` by path (the folder is not a package)."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def site_host() -> tuple:
    """``(host, proxy_bypass)``: ``127.0.0.1.nip.io`` when it resolves to 127.0.0.1, else the literal
    address with WinINet's ``<-loopback>`` override (WinINet never proxies loopback addresses)."""
    try:
        infos = socket.getaddrinfo("127.0.0.1.nip.io", None, socket.AF_INET)
        if any(info[4][0] == "127.0.0.1" for info in infos):
            return "127.0.0.1.nip.io", ""
    except OSError:
        pass
    return "127.0.0.1", "<-loopback>"


def _wait_port(port: int, timeout: float, proc: Optional[subprocess.Popen] = None, what: str = "port") -> None:
    deadline = time.monotonic() + timeout
    while True:
        if proc is not None and proc.poll() is not None:
            raise ScenarioError(f"{what} exited early with code {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise ScenarioError(f"{what} did not listen on port {port} within {timeout:.0f}s") from None
            time.sleep(0.2)


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


def _mitmdump_command(out_json: str, proxy_port: int) -> List[str]:
    """``mitmdump -s <addon> --set reqrec_out=<file> -p <port> --listen-host 127.0.0.1 --set flow_detail=0``
    plus the GUI's ``HTTPS_PASSTHROUGH_ARGS`` (HTTPS on every port passes through unrecorded, as in the
    recording browser started by the GUI); the venv's mitmdump next to this interpreter when present."""
    from reqrec.webapp.routes import HTTPS_PASSTHROUGH_ARGS

    scripts = os.path.dirname(os.path.abspath(sys.executable))
    exe = os.path.join(scripts, "mitmdump.exe" if os.name == "nt" else "mitmdump")
    if os.path.isfile(exe):
        launcher = [exe]
    elif shutil.which("mitmdump"):
        launcher = [str(shutil.which("mitmdump"))]
    else:
        launcher = [sys.executable, "-c", "import sys; from mitmproxy.tools.main import mitmdump; sys.exit(mitmdump())"]
    return launcher + [
        "-s", ADDON_PATH, "--set", f"reqrec_out={os.path.abspath(out_json)}", "-p", str(int(proxy_port)),
        "--listen-host", "127.0.0.1", "--set", "flow_detail=0", *HTTPS_PASSTHROUGH_ARGS,
    ]


def _poll(what: str, probe: Callable[[], Any], timeout: float, interval: float = 0.2) -> Any:
    """Call ``probe`` until it returns something truthy; driver errors count as "not yet"."""
    deadline = time.monotonic() + timeout
    last: Any = None
    while True:
        try:
            value = probe()
        except Exception as exc:  # IEDriverError while a page is being replaced
            value, last = None, exc
        if value:
            return value
        if time.monotonic() >= deadline:
            raise ScenarioError(f"timeout ({timeout:.0f}s) waiting for {what}" + (f": {last}" if last else ""))
        time.sleep(interval)


# --------------------------------------------------------------------------- the scenario

def _operate(drv: Any, browser: subprocess.Popen, step: Callable[[str], Any], pending: List[subprocess.Popen],
             info: Dict[str, Any], timeout: float) -> None:
    user, password = info["credentials"]
    search = "/Search.aspx?key="

    def alive() -> None:
        if browser.poll() is not None:
            raise ScenarioError(f"RecBrowser exited unexpectedly (code {browser.returncode})")

    with step("start"):
        drv.wait("/Login.aspx", text="ログイン", kind="tab", timeout=max(timeout, 60.0))

    with step("login"):
        drv.value("/Login.aspx", id="txtUserId", value=user, kind="tab")
        drv.value("/Login.aspx", id="txtPassword", value=password, kind="tab")
        drv.click("/Login.aspx", id="btnLogin", kind="tab")
        drv.wait("/Menu.aspx", text="ようこそ", kind="tab", timeout=timeout)

    with step("open_search"):
        drv.click("/Menu.aspx", id="lnkSearch", kind="tab")   # window.open -> a new tab
        drv.wait(search, text="生産実績照会", kind="tab", timeout=timeout)

    with step("plant"):
        drv.select(search, id="ddlPlant", text="本社工場", kind="tab")   # onchange -> __doPostBack
        # same URL after the postback: wait until the NEW document has the line options
        _poll("the plant postback (ddlLine filled)",
              lambda: int(drv.attr(search, id="ddlLine", name="length", kind="tab", timeout=2)["value"] or 0) > 0,
              timeout)
        drv.wait(search, text="生産実績照会", kind="tab", timeout=timeout)

    with step("line_shift"):
        drv.select(search, id="ddlLine", text="組立1ライン", kind="tab")
        drv.select(search, id="ddlShift", text="日勤", kind="tab")

    with step("item_picker"):
        clicking = drv.click_async(search, id="btnPick", kind="tab")   # blocks until the modal closes
        pending.append(clicking)
        drv.wait("/ItemPicker.aspx", text="A-1002", kind="dialog", timeout=timeout)
        drv.click("/ItemPicker.aspx", id="item_A-1002", kind="dialog")   # returnValue + window.close()
        drv.finish(clicking, timeout=timeout)
        pending.remove(clicking)
        _poll("txtItem = A-1002",
              lambda: drv.attr(search, id="txtItem", name="value", kind="tab", timeout=2)["value"] == "A-1002",
              timeout)

    with step("search"):
        drv.click(search, id="btnSearch", kind="tab")
        drv.wait(search, text="1/2 ページ", kind="tab", timeout=timeout)

    with step("page2"):
        drv.click(search, link_text="2", kind="tab")   # javascript:__doPostBack('gvResult','Page$2')
        drv.wait(search, text="2/2 ページ", kind="tab", timeout=timeout)

    with step("excel"):
        drv.click(search, id="btnExcel", kind="tab")
        info["download_dialog"] = drv.dialog(title=DOWNLOAD_DIALOG_TITLE, button=DOWNLOAD_CANCEL,
                                             timeout=max(timeout, 20.0))
        alive()

    with step("news"):
        drv.click("/Menu.aspx", id="lnkNews", kind="tab")   # target=_blank -> a new tab
        drv.wait("/News.aspx", text="システムメンテナンス", kind="tab", timeout=timeout)

    with step("close"):
        info["close"] = drv.close(timeout=max(timeout, 20.0))
        try:
            info["browser_exit_code"] = browser.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise ScenarioError("RecBrowser did not exit after WM_CLOSE") from None


class _Steps:
    """``with step("name"):`` records the duration of each step (also of a failing one)."""

    def __init__(self) -> None:
        self.timings: "OrderedDict[str, float]" = OrderedDict()
        self.current: Optional[str] = None
        self._name = ""
        self._t0 = 0.0

    def __call__(self, name: str) -> "_Steps":
        self._name = name
        return self

    def __enter__(self) -> "_Steps":
        self.current = self._name
        self._t0 = time.monotonic()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.timings[self._name] = round(time.monotonic() - self._t0, 3)
        if exc_type is None:
            self.current = None


def run_factory_recording(
    workdir: str,
    out_json: str,
    site_port: int,
    proxy_port: int,
    recbrowser_exe: str,
    *,
    driver_exe: Optional[str] = None,
    timeout: float = 30.0,
    keep_site: bool = False,
    title: str = "生産管理 記録",
) -> Dict[str, Any]:
    """Run the recording scenario of the module docstring and return what happened.

    ``workdir`` receives the site log (``factory_site.log``), ``recbrowser.log``, ``mitmdump.out`` and
    (unless ``driver_exe`` is given) the compiled driver in ``iedriver_bin/``.  ``out_json`` is the
    recording the reqrec addon writes (deleted first).  ``site_port`` / ``proxy_port`` 0 = a free port.
    ``timeout`` bounds each wait of the scenario (the first page and the download dialog get at least
    60 s / 20 s).  With ``keep_site`` the mock site keeps running after the browser is closed and the
    result carries it as ``site_server`` (call ``.stop()``); otherwise it is stopped.

    Returns ``{"timings": {step: seconds}, "setup_seconds", "total_seconds", "site_log", "out_json",
    "recbrowser_log", "mitmdump_log", "base_url", "start_url", "host", "bypass", "site_port",
    "proxy_port", "browser_pid", "browser_exit_code", "close", "download_dialog", "driver_exe",
    "scenario_filter", "credentials", "site_events"}`` (+ ``"site_server"`` with ``keep_site``).
    Raises :class:`ScenarioError` / ``IEDriverError`` (with the timings so far in ``exc.timings`` and
    the step in ``exc.step``) when a step does not complete.
    """
    fs = load_fixture(SITE_MODULE, "reqrec_factory_site_fixture")
    iedriver = load_fixture(DRIVER_MODULE, "reqrec_iedriver_fixture")
    workdir = os.path.abspath(workdir)
    os.makedirs(workdir, exist_ok=True)
    out_json = os.path.abspath(out_json)
    if os.path.exists(out_json):
        os.remove(out_json)
    site_log = os.path.join(workdir, "factory_site.log")
    host_log = os.path.join(workdir, "recbrowser.log")
    mitm_log = os.path.join(workdir, "mitmdump.out")
    if driver_exe is None:
        driver_exe = iedriver.build_driver(os.path.join(workdir, "iedriver_bin"))
    host, bypass = site_host()
    proxy_port = int(proxy_port) or free_port()

    info: Dict[str, Any] = {
        "credentials": fs.CREDENTIALS, "scenario_filter": SCENARIO_FILTER, "driver_exe": driver_exe,
        "site_log": site_log, "out_json": out_json, "recbrowser_log": host_log, "mitmdump_log": mitm_log,
        "host": host, "bypass": bypass, "proxy_port": proxy_port, "browser_exit_code": None,
        "close": None, "download_dialog": None,
    }
    steps = _Steps()
    started = time.monotonic()
    server = recorder = browser = None
    pending: List[subprocess.Popen] = []
    ok = False
    try:
        server = fs.make_server(site_log, int(site_port)).start()
        info["site_port"] = server.port
        base = f"http://{host}:{server.port}"
        info["base_url"] = base + "/"
        info["start_url"] = base + "/Login.aspx"
        env = dict(os.environ, PYTHONUNBUFFERED="1")  # mitmdump is killed at the end: keep its log complete
        with open(mitm_log, "w", encoding="utf-8") as out:
            recorder = subprocess.Popen(_mitmdump_command(out_json, proxy_port), stdout=out, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, env=env, creationflags=_NO_WINDOW)
        _wait_port(proxy_port, 60.0, recorder, "mitmdump")
        browser = subprocess.Popen(
            [recbrowser_exe, "--proxy", f"127.0.0.1:{proxy_port}", "--bypass", bypass, "--url", info["start_url"],
             "--title", title, "--log", host_log],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        info["browser_pid"] = browser.pid
        info["setup_seconds"] = round(time.monotonic() - started, 3)
        drv = iedriver.IEDriver(driver_exe, browser.pid, timeout=timeout)
        _operate(drv, browser, steps, pending, info, timeout)
        ok = True
    except BaseException as exc:
        try:
            exc.timings = dict(steps.timings)  # type: ignore[attr-defined]
            exc.step = steps.current  # type: ignore[attr-defined]
        except Exception:
            pass
        raise
    finally:
        for proc in pending:
            _kill(proc)
        _kill(browser)       # only when the scenario failed before "close"
        _kill(recorder)      # the addon rewrites the recording after every response: nothing is lost
        if server is not None and not (ok and keep_site):
            server.stop()
    info["timings"] = dict(steps.timings)
    info["total_seconds"] = round(time.monotonic() - started, 3)
    info["site_events"] = [entry.get("event") for entry in fs.read_log(site_log)]
    if keep_site:
        info["site_server"] = server
    return info
