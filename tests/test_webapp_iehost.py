"""GUI integration of the in-app IE-engine recording browser.  Contract: DESIGN.md §13.12.

Everything runs with fakes (no mitmdump, no csc.exe, no RecBrowser.exe, no registry):

* a ``FakeRecorder`` in the style of ``tests/test_webapp_easy.py::TestAutoPort`` that records the
  ``extra_args`` it was started with and serves a real recording on ``load_recording``;
* ``reqrec.iehost.availability`` / ``launch`` / ``set_emulation`` monkeypatched on the module the
  routes call (``routes_mod.iehost``), ``launch`` returning a ``FakeBrowser`` (``pid`` / ``running``
  / ``poll()`` / ``close()``);
* ``winsupport.is_windows`` monkeypatched so the Windows-only checks pass on every OS.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reqrec import iehost, winsupport
from reqrec.iehost import EMULATION_LEVELS, IEHostError
from reqrec.importers import load_recording
from reqrec.webapp import TOKEN_HEADER, create_app
from reqrec.webapp import routes as routes_mod

ROOT = Path(__file__).resolve().parent.parent
LOGIN_HAR = ROOT / "tests" / "fixtures" / "login_flow_chrome.har"

AVAILABLE = {"available": True, "reason": None, "exe": "X:\\work\\bin\\RecBrowser.exe", "built": True,
             "source": "src.cs", "csc": "csc.exe", "prebuilt": None}
UNAVAILABLE = {"available": False, "reason": "記録用ブラウザを作成するためのコンパイラ (csc.exe) が見つかりません。", "exe": None,
               "built": False, "source": "src.cs", "csc": None, "prebuilt": None}


# --------------------------------------------------------------------------- fakes

class FakeRecorder:
    """Enough of ``RecorderManager`` for the record endpoints; ``events`` is shared with the browser fake."""

    def __init__(self, events: list, with_flows: bool = True):
        self.events = events
        self.with_flows = with_flows
        self.running = False
        self.out = None
        self.port = None
        self.listen_host = None
        self.hosts = []
        self.command_builder = object()  # not the default builder -> the mitmproxy check is skipped
        self.start_calls = []

    def start(self, out, port=8080, hosts=None, listen_host="127.0.0.1", **kwargs):
        self.start_calls.append({"out": out, "port": port, "hosts": hosts, "listen_host": listen_host, **kwargs})
        self.running = True
        self.out = out
        self.port = port
        self.listen_host = listen_host
        self.hosts = list(hosts or [])
        self.events.append("recorder.start")
        return self.status()

    def status(self):
        return {"running": self.running, "flows": 0, "out": self.out, "out_name": os.path.basename(self.out) if self.out else None,
                "port": self.port, "listen_host": self.listen_host, "hosts": list(self.hosts), "stdout_tail": "",
                "stderr_tail": "", "error": None, "pid": 1 if self.running else None, "exit_code": None if self.running else 0,
                "started_at": None, "stopped_at": None, "command": []}

    def stop(self, timeout=None):
        self.events.append("recorder.stop")
        self.running = False
        return 0

    def close(self):
        self.running = False

    def forget(self):
        self.events.append("recorder.forget")
        if self.running:
            return False
        self.out = None
        return True

    def load_recording(self):
        from reqrec.model import Recording
        if not self.with_flows:
            return Recording(flows=[], meta={})
        return load_recording(str(LOGIN_HAR))


class FakeBrowser:
    """Stands in for ``iehost.BrowserProcess``."""

    def __init__(self, events: list, pid: int = 4242, log_path: str = "X:\\work\\logs\\recbrowser_x.log"):
        self.events = events
        self.pid = pid
        self.exe = "X:\\work\\bin\\RecBrowser.exe"
        self.log_path = log_path
        self.started_at = 0.0
        self._code = None
        self.close_calls = []

    @property
    def running(self):
        return self._code is None

    def poll(self):
        return self._code

    def exit(self, code: int = 0):
        self._code = code

    def close(self, timeout=5.0):
        self.close_calls.append(timeout)
        self.events.append("browser.close")
        if self._code is None:
            self._code = 0
        return self._code


class LaunchSpy:
    def __init__(self, events: list, fail: Exception | None = None):
        self.events = events
        self.fail = fail
        self.calls = []
        self.browsers = []

    def __call__(self, workdir, proxy_address, url=None, title=None, **kwargs):
        self.calls.append({"workdir": workdir, "proxy_address": proxy_address, "url": url, "title": title, **kwargs})
        if self.fail is not None:
            raise self.fail
        b = FakeBrowser(self.events, pid=1000 + len(self.browsers))
        self.browsers.append(b)
        self.events.append("browser.launch")
        return b


# --------------------------------------------------------------------------- fixtures

@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    return tmp_path / "work"


@pytest.fixture
def app(workdir: Path):
    application = create_app(str(workdir), host="127.0.0.1", port=8765, token="test-token-123", TESTING=True)
    yield application
    application.extensions["reqrec"].close()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def H(app):
    return {TOKEN_HEADER: app.config["REQREC_TOKEN"]}


@pytest.fixture
def events() -> list:
    return []


@pytest.fixture
def recorder(app, events):
    state = app.extensions["reqrec"]
    rec = FakeRecorder(events)
    state.recorder = rec
    return rec


class _Levels(list):
    """The emulation levels written by ``set_emulation`` plus ``current`` (what ``get_emulation`` reports)."""

    current: dict


@pytest.fixture
def win(monkeypatch):
    """Pretend to be on Windows with a usable recording browser (fakes only)."""
    monkeypatch.setattr(routes_mod, "mitmproxy_available", lambda: True)
    monkeypatch.setattr(winsupport, "is_windows", lambda: True)
    monkeypatch.setattr(routes_mod.iehost, "availability", lambda workdir, **kw: dict(AVAILABLE))
    levels = _Levels()
    levels.current = {"value": None}  # what get_emulation() reports (the real registry is never read)
    monkeypatch.setattr(routes_mod.iehost, "set_emulation", lambda level, **kw: levels.append(level))
    monkeypatch.setattr(routes_mod.iehost, "get_emulation", lambda *a, **kw: levels.current["value"])
    return levels


@pytest.fixture
def launched(monkeypatch, events):
    spy = LaunchSpy(events)
    monkeypatch.setattr(routes_mod.iehost, "launch", spy)
    return spy


def _start(client, H, **extra):
    body = {"port": "auto", "hosts": [], "listen_host": "127.0.0.1", "browser": "iehost", "append": False}
    body.update(extra)
    return client.post("/api/record/start", json=body, headers=H)


# --------------------------------------------------------------------------- start

class TestStart:
    def test_iehost_start_launches_browser_through_the_proxy(self, app, client, H, recorder, win, launched, workdir):
        r = _start(client, H, start_url="kanri/top.aspx", emulation="ie11")
        assert r.status_code == 200, r.get_json()
        j = r.get_json()
        # recorder: extra args tunnel HTTPS on every port (no certificate needed)
        call = recorder.start_calls[0]
        assert call["extra_args"] == ["--ignore-hosts", ".*"] == list(routes_mod.HTTPS_PASSTHROUGH_ARGS)
        assert call["port"] == j["port"] and j["auto_port"] is True
        # browser: launched after the recorder, against the recorder's proxy address, with the typed URL
        assert launched.calls == [{"workdir": str(workdir), "proxy_address": f"127.0.0.1:{j['port']}",
                                   "url": "http://kanri/top.aspx", "title": "reqrec 記録用ブラウザ"}]
        assert launched.calls[0]["proxy_address"] == j["proxy_address"]
        assert win == [EMULATION_LEVELS["ie11"]]
        assert j["browser"] == {"kind": "iehost", "pid": 1000, "running": True, "exit_code": None, "log": launched.browsers[0].log_path}
        assert j["https_passthrough"] is True and j["emulation"] == "ie11" and j["system_proxy"] is None
        state = app.extensions["reqrec"]
        assert state.browser is launched.browsers[0]
        assert ["recorder.start", "browser.launch"] == [e for e in recorder.events if e != "browser.close"]

    def test_blank_start_url_means_no_url(self, client, H, recorder, win, launched):
        r = _start(client, H, start_url="   ")
        assert r.status_code == 200, r.get_json()
        assert launched.calls[0]["url"] is None
        assert win == []  # "default" and no value present -> the registry is not opened for writing

    @pytest.mark.parametrize("level", sorted(k for k in EMULATION_LEVELS if EMULATION_LEVELS[k] is not None))
    def test_emulation_levels_are_mapped(self, client, H, recorder, win, launched, level):
        r = _start(client, H, emulation=level)
        assert r.status_code == 200, r.get_json()
        assert win == [EMULATION_LEVELS[level]]

    def test_default_emulation_writes_nothing_when_no_value(self, client, H, recorder, win, launched):
        r = _start(client, H, emulation="default")
        assert r.status_code == 200, r.get_json()
        assert win == [] and r.get_json()["warnings"] == []

    def test_default_emulation_removes_a_leftover_value(self, client, H, recorder, win, launched):
        win.current["value"] = 11000  # left by an earlier "IE11 相当" recording
        r = _start(client, H, emulation="default")
        assert r.status_code == 200, r.get_json()
        assert win == [None]

    def test_default_emulation_cleanup_failure_is_only_a_warning(self, client, H, recorder, win, launched, monkeypatch):
        win.current["value"] = 11000
        def bad(level, **kw):
            raise PermissionError("access denied by security software")
        monkeypatch.setattr(routes_mod.iehost, "set_emulation", bad)
        r = _start(client, H, emulation="default")
        assert r.status_code == 200, r.get_json()
        assert launched.calls and recorder.running is True
        assert any("表示モード" in w for w in r.get_json()["warnings"])

    def test_bad_emulation_is_400_before_anything_starts(self, client, H, recorder, win, launched):
        r = _start(client, H, emulation="ie99")
        assert r.status_code == 400 and "表示モード" in r.get_json()["error"]
        assert recorder.start_calls == [] and launched.calls == []

    def test_bad_browser_kind_is_400(self, client, H, recorder, win, launched):
        r = _start(client, H, browser="firefox")
        assert r.status_code == 400 and "記録方式" in r.get_json()["error"]
        assert recorder.start_calls == []

    def test_bad_start_url_is_400(self, client, H, recorder, win, launched):
        for bad in ("javascript:alert(1)", "edge://newtab", "file:///C:/x"):
            r = _start(client, H, start_url=bad)
            assert r.status_code == 400, bad
        assert recorder.start_calls == [] and launched.calls == []

    def test_unavailable_iehost_is_400_with_reason(self, client, H, recorder, win, launched, monkeypatch):
        monkeypatch.setattr(routes_mod.iehost, "availability", lambda workdir, **kw: dict(UNAVAILABLE))
        r = _start(client, H)
        assert r.status_code == 400
        assert r.get_json()["error"] == UNAVAILABLE["reason"]
        assert recorder.running is False and recorder.start_calls == [] and launched.calls == []

    def test_non_windows_is_400(self, client, H, recorder, win, launched, monkeypatch):
        monkeypatch.setattr(winsupport, "is_windows", lambda: False)
        r = _start(client, H)
        assert r.status_code == 400 and r.get_json()["error"] == winsupport.NOT_WINDOWS_MESSAGE
        assert recorder.start_calls == [] and launched.calls == []

    def test_system_proxy_with_iehost_is_400(self, client, H, recorder, win, launched):
        r = _start(client, H, set_system_proxy=True)
        assert r.status_code == 400 and "システムプロキシ" in r.get_json()["error"]
        assert recorder.start_calls == []

    def test_launch_failure_stops_recorder_and_reports_compiler_output(self, app, client, H, recorder, win, monkeypatch, events):
        boom = IEHostError("記録用ブラウザの作成 (コンパイル) に失敗しました。\nRecBrowser.cs(12,3): error CS1002: ; が必要です")
        monkeypatch.setattr(routes_mod.iehost, "launch", LaunchSpy(events, fail=boom))
        r = _start(client, H)
        assert r.status_code == 500
        err = r.get_json()["error"]
        assert "記録用ブラウザを起動できませんでした" in err and "CS1002" in err and "コンパイル" in err
        assert recorder.running is False and events == ["recorder.start", "recorder.stop", "recorder.forget"]
        assert app.extensions["reqrec"].browser is None

    def test_emulation_failure_stops_recorder(self, client, H, recorder, win, launched, monkeypatch):
        def bad(level, **kw):
            raise OSError("registry locked")
        monkeypatch.setattr(routes_mod.iehost, "set_emulation", bad)
        r = _start(client, H, emulation="ie11")  # an explicit choice that cannot be applied is fatal
        assert r.status_code == 500 and "表示モード" in r.get_json()["error"]
        assert recorder.running is False and launched.calls == []

    def test_none_browser_keeps_the_classic_flow(self, client, H, recorder, win, launched):
        r = _start(client, H, browser="none")
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["browser"] is None and r.get_json()["https_passthrough"] is False
        assert "extra_args" not in recorder.start_calls[0]  # a FakeRecorder without that keyword keeps working
        assert launched.calls == [] and win == []

    def test_https_passthrough_is_independent_of_the_browser(self, client, H, recorder, win, launched):
        r = _start(client, H, browser="none", https_passthrough=True)
        assert r.status_code == 200 and recorder.start_calls[0]["extra_args"] == list(routes_mod.HTTPS_PASSTHROUGH_ARGS)
        recorder.stop()
        r = _start(client, H, browser="iehost", https_passthrough=False)
        assert r.status_code == 200 and "extra_args" not in recorder.start_calls[1]

    def test_browser_not_launched_when_recorder_died_immediately(self, client, H, recorder, win, launched):
        def start(out, **kw):
            recorder.start_calls.append(kw)
            recorder.out = out
            recorder.running = False  # died at once (port in use)
            return recorder.status()
        recorder.start = start
        r = _start(client, H)
        assert r.status_code == 200 and r.get_json()["browser"] is None and launched.calls == []


# --------------------------------------------------------------------------- status / stop

class TestStatusAndStop:
    def test_status_reports_browser(self, client, H, recorder, win, launched):
        assert client.get("/api/record/status").get_json()["browser"] == {"kind": None, "running": False, "pid": None, "exit_code": None}
        _start(client, H)
        st = client.get("/api/record/status").get_json()["browser"]
        assert st == {"kind": "iehost", "running": True, "pid": 1000, "exit_code": None}
        launched.browsers[0].exit(0)
        st = client.get("/api/record/status").get_json()["browser"]
        assert st == {"kind": "iehost", "running": False, "pid": 1000, "exit_code": 0}
        assert client.get("/api/state").get_json()["browser"] == st

    def test_stop_closes_browser_before_recorder_and_reports_exit_code(self, app, client, H, recorder, win, launched, events):
        _start(client, H)
        del events[:]
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 200, r.get_json()
        j = r.get_json()
        assert events == ["browser.close", "recorder.stop"]
        assert launched.browsers[0].close_calls == [5.0]
        assert j["browser_exit_code"] == 0 and j["exit_code"] == 0 and j["flows"] > 0
        state = app.extensions["reqrec"]
        assert state.browser is None
        assert client.get("/api/record/status").get_json()["browser"]["kind"] is None

    def test_stop_with_already_closed_browser(self, client, H, recorder, win, launched, events):
        _start(client, H)
        launched.browsers[0].exit(3)
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 200 and r.get_json()["browser_exit_code"] == 3

    def test_stop_with_empty_recording_mentions_http_only(self, client, H, recorder, win, launched):
        recorder.with_flows = False
        _start(client, H)
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 400
        j = r.get_json()
        assert "http://" in j["error"] and j["browser_exit_code"] == 0

    def test_appstate_close_closes_browser(self, app, events):
        state = app.extensions["reqrec"]
        b = FakeBrowser(events)
        state.browser = b
        state.close()
        assert b.close_calls and state.browser is None

    def test_close_browser_swallows_errors(self, app):
        state = app.extensions["reqrec"]

        class Bad(FakeBrowser):
            def close(self, timeout=5.0):
                raise RuntimeError("gone")
        state.browser = Bad([])
        assert state.close_browser() is None and state.browser is None


# --------------------------------------------------------------------------- /api/browser/open

class TestBrowserOpen:
    def test_running_browser_is_not_relaunched(self, client, H, recorder, win, launched):
        _start(client, H)
        r = client.post("/api/browser/open", json={"browser": "iehost", "url": "http://kanri/"}, headers=H)
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["running"] is True and r.get_json()["relaunched"] is False
        assert len(launched.calls) == 1

    def test_closed_browser_is_relaunched_against_the_recorder(self, app, client, H, recorder, win, launched):
        j = _start(client, H).get_json()
        launched.browsers[0].exit(0)
        r = client.post("/api/browser/open", json={"browser": "iehost", "url": "kanri/"}, headers=H)
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["running"] is True and r.get_json()["relaunched"] is True
        assert len(launched.calls) == 2
        assert launched.calls[1]["proxy_address"] == winsupport.proxy_server_for(recorder.listen_host, recorder.port) == j["proxy_address"]
        assert launched.calls[1]["url"] == "http://kanri/" and launched.calls[1]["title"] == "reqrec 記録用ブラウザ"
        assert app.extensions["reqrec"].browser is launched.browsers[1]
        assert r.get_json()["browser"]["pid"] == 1001

    def test_without_recording_is_409(self, client, H, recorder, win, launched):
        r = client.post("/api/browser/open", json={"browser": "iehost"}, headers=H)
        assert r.status_code == 409 and r.get_json()["error"] == "記録が開始されていません"
        assert launched.calls == []

    def test_relaunch_failure_is_500(self, client, H, recorder, win, launched, monkeypatch, events):
        _start(client, H)
        launched.browsers[0].exit(0)
        monkeypatch.setattr(routes_mod.iehost, "launch", LaunchSpy(events, fail=IEHostError("記録用ブラウザを起動できません: x")))
        r = client.post("/api/browser/open", json={"browser": "iehost"}, headers=H)
        assert r.status_code == 500 and "記録用ブラウザ" in r.get_json()["error"]

    def test_edge_flow_unchanged(self, client, H, monkeypatch):
        calls = []
        monkeypatch.setattr(routes_mod.launch, "open_url", lambda url, prefer_edge=True: calls.append(url) or {"url": "http://x", "browser": "edge", "path": "msedge.exe"})
        r = client.post("/api/browser/open", json={"url": "intra.example.test/"}, headers=H)
        assert r.status_code == 200 and r.get_json()["browser"] == "edge" and calls == ["intra.example.test/"]
        r = client.post("/api/browser/open", json={"browser": "none", "url": "a.b/"}, headers=H)
        assert r.status_code == 200 and calls == ["intra.example.test/", "a.b/"]


# --------------------------------------------------------------------------- page / state

class TestPageAndState:
    def test_state_and_page_expose_availability(self, client, monkeypatch):
        monkeypatch.setattr(routes_mod.iehost, "availability", lambda workdir, **kw: dict(AVAILABLE))
        monkeypatch.setattr(routes_mod.iehost, "get_emulation", lambda *a, **kw: 11000)
        st = client.get("/api/state").get_json()
        assert st["iehost"] == {"available": True, "reason": None, "exe": AVAILABLE["exe"], "built": True,
                                "shipped": None, "emulation": "ie11", "last_error": None}
        assert st["browser"] == {"kind": None, "running": False, "pid": None, "exit_code": None}
        html = client.get("/").get_data(as_text=True)
        assert 'data-iehost-available="true"' in html and 'data-iehost-reason=""' in html

    def test_page_carries_reason_when_unavailable(self, client, monkeypatch):
        monkeypatch.setattr(routes_mod.iehost, "availability", lambda workdir, **kw: dict(UNAVAILABLE))
        html = client.get("/").get_data(as_text=True)
        assert 'data-iehost-available="false"' in html
        assert f'data-iehost-reason="{UNAVAILABLE["reason"]}"' in html
        st = client.get("/api/state").get_json()["iehost"]
        assert st["available"] is False and st["reason"] == UNAVAILABLE["reason"] and st["exe"] is None

    def test_page_has_the_new_record_controls(self, client):
        html = client.get("/").get_data(as_text=True)
        for marker in ('id="rec-browser"', 'value="iehost"', 'value="none"', 'id="rec-emulation"', 'value="ie11_force"',
                       'id="rec-https-passthrough"', 'id="rec-start-url"', 'id="easy-guide"', 'id="easy-hint-1"', 'id="easy-hint-3"',
                       "記録方式", "表示モード (記録用ブラウザ)", "https:// の通信は記録せず素通しする", "最初に開くアドレス",
                       "開くサイトのアドレス"):
            assert marker in html, marker

    def test_real_availability_is_used_by_default(self, client, workdir):
        info = client.get("/api/state").get_json()["iehost"]
        expected = iehost.availability(str(workdir))
        assert {k: info[k] for k in ("available", "reason", "exe", "built")} == {k: expected[k] for k in ("available", "reason", "exe", "built")}
        assert info["last_error"] is None and info["emulation"] in set(iehost.EMULATION_LEVELS) | {"custom"}


# =========================================================================== review fixes (DESIGN.md §13.12)

class TestReviewFixes:
    def test_browser_waits_for_the_proxy_and_gives_up_when_it_never_listens(self, client, H, recorder, win, launched):
        waits = []

        def never(timeout=None):
            waits.append(timeout)
            return False

        recorder.wait_until_listening = never
        r = _start(client, H)
        assert r.status_code == 500 and "記録用プロキシ" in r.get_json()["error"]
        assert waits and waits[0] == routes_mod.PROXY_READY_TIMEOUT
        assert launched.calls == [] and recorder.running is False

    def test_browser_is_launched_after_the_proxy_listens(self, client, H, recorder, win, launched, events):
        def ready(timeout=None):
            events.append("recorder.listening")
            return True

        recorder.wait_until_listening = ready
        r = _start(client, H)
        assert r.status_code == 200, r.get_json()
        assert "browser.launch" in events
        assert events.index("recorder.start") < events.index("recorder.listening") < events.index("browser.launch")

    def test_recorder_stopped_while_waiting_is_not_followed_by_a_launch(self, client, H, recorder, win, launched):
        def stopped_meanwhile(timeout=None):
            recorder.running = False  # e.g. [記録停止] pressed in the advanced panel during the wait
            return True

        recorder.wait_until_listening = stopped_meanwhile
        r = _start(client, H)
        assert r.status_code == 409 and launched.calls == []

    def test_start_url_is_ignored_for_the_manual_flow(self, client, H, recorder, win, launched):
        r = _start(client, H, browser="none", start_url="edge://newtab")
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["browser_kind"] == "none"

    def test_status_reports_the_recording_mode(self, client, H, recorder, win, launched):
        assert _start(client, H).status_code == 200
        assert client.get("/api/record/status").get_json()["browser_kind"] == "iehost"
        assert client.get("/api/state").get_json()["record_browser_kind"] == "iehost"
        client.post("/api/record/stop", json={}, headers=H)
        assert client.get("/api/record/status").get_json()["browser_kind"] is None

    def test_browser_open_refuses_a_manual_recording(self, client, H, recorder, win, launched):
        assert _start(client, H, browser="none").status_code == 200
        r = client.post("/api/browser/open", json={"browser": "iehost"}, headers=H)
        assert r.status_code == 409 and launched.calls == []

    def test_discard_stop_loads_nothing_and_removes_the_file(self, client, H, recorder, win, launched, app):
        state = app.extensions["reqrec"]
        assert state.recording is None
        r = _start(client, H)
        assert r.status_code == 200
        out = recorder.out
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("{}")
        r = client.post("/api/record/stop", json={"discard": True}, headers=H)
        data = r.get_json()
        assert r.status_code == 200 and data["discarded"] is True and data["removed"] is True
        assert not os.path.exists(out)
        assert state.recording is None and data["recording"]["loaded"] is False
        assert launched.calls[0] is not None and recorder.running is False


class TestLaunchJobAndEmulation:
    def test_launch_binds_the_process_to_a_job(self, tmp_path):
        from reqrec import iehost

        class P:
            pid = 99

            def poll(self):
                return None

        bound = []
        workdir = tmp_path / "w"
        (workdir / "bin").mkdir(parents=True)
        exe = workdir / "bin" / iehost.EXE_NAME
        exe.write_bytes(b"MZ")
        import hashlib
        (workdir / "bin" / iehost.HASH_NAME).write_text(iehost._build_digest(iehost.SOURCE_PATH), encoding="utf-8")
        proc = iehost.launch(str(workdir), "127.0.0.1:8080", popen=lambda argv, **kw: P(), run=lambda *a, **k: None,
                             job=lambda p: bound.append(p) or 1234)
        assert bound and proc.job_handle == 1234

    def test_kill_on_close_job_never_raises_without_a_handle(self):
        from reqrec import iehost

        assert iehost.kill_on_close_job(object()) is None

    def test_set_emulation_default_does_not_open_for_write_when_absent(self):
        from reqrec import iehost

        class Reg:
            HKEY_CURRENT_USER = object()
            KEY_READ = 1
            KEY_SET_VALUE = 2
            REG_DWORD = 4

            def __init__(self):
                self.opened = []

            def OpenKey(self, hive, path, reserved, access):
                self.opened.append(access)
                raise FileNotFoundError

        reg = Reg()
        iehost.set_emulation(None, winreg=reg)
        assert reg.opened == [Reg.KEY_READ]


class TestHostPortUrls:
    @pytest.mark.parametrize("typed,expected", [
        ("kanri:8080/app", "http://kanri:8080/app"),
        ("intra.example.co.jp:8080/top", "http://intra.example.co.jp:8080/top"),
        ("192.168.1.10:8080", "http://192.168.1.10:8080"),
        ("kanri", "http://kanri"),
    ])
    def test_scheme_less_host_port(self, typed, expected):
        from reqrec.webapp.launch import validate_url

        assert validate_url(typed) == expected


class TestWaitUntilListening:
    def _manager(self, running=True):
        from reqrec.recorder.manager import RecorderManager

        m = RecorderManager(command_builder=lambda *a, **k: ["x"])
        m.port = 18080
        m.listen_host = "0.0.0.0"
        m.out = "o.json"

        class Proc:
            pid = 1

            def poll(self):
                return None if running else 1

        m._proc = Proc()
        return m

    def test_returns_true_once_connectable_and_maps_wildcard_to_loopback(self):
        m = self._manager()
        tried = []

        class Conn:
            def close(self):
                pass

        def connect(addr, timeout=None):
            tried.append(addr)
            if len(tried) < 3:
                raise ConnectionRefusedError
            return Conn()

        assert m.wait_until_listening(timeout=5, connect=connect, interval=0.01) is True
        assert tried[0] == ("127.0.0.1", 18080) and len(tried) == 3

    def test_returns_false_when_the_child_exits(self):
        m = self._manager(running=False)
        assert m.wait_until_listening(timeout=5, connect=lambda *a, **k: None) is False

    def test_returns_false_on_timeout(self):
        m = self._manager()

        def refuse(addr, timeout=None):
            raise ConnectionRefusedError

        assert m.wait_until_listening(timeout=0.05, connect=refuse, interval=0.01) is False


class TestSecondReviewFixes:
    def test_empty_recording_without_file_is_reported_as_nothing_recorded(self, client, H, recorder, win, launched):
        from reqrec.recorder.manager import RecorderError

        assert _start(client, H).status_code == 200

        def no_file():
            raise RecorderError("記録ファイルが作成されませんでした。")

        recorder.load_recording = no_file  # the addon never wrote the file (0 responses + CTRL_BREAK)
        r = client.post("/api/record/stop", json={}, headers=H)
        data = r.get_json()
        assert r.status_code == 400 and data["empty"] is True
        assert "何も記録されませんでした" in data["error"] and "https://" in data["error"]

    def test_keep_emulation_never_touches_the_registry(self, client, H, recorder, win, launched, monkeypatch):
        calls = []
        monkeypatch.setattr(routes_mod.iehost, "get_emulation", lambda *a, **kw: calls.append("get") or 11000)
        r = _start(client, H, emulation="keep")
        assert r.status_code == 200, r.get_json()
        assert win == [] and calls == []

    def test_missing_emulation_means_keep(self, client, H, recorder, win, launched):
        body = {"port": "auto", "hosts": [], "listen_host": "127.0.0.1", "browser": "iehost", "append": False}
        r = client.post("/api/record/start", json=body, headers=H)
        assert r.status_code == 200 and r.get_json()["emulation"] == "keep" and win == []

    def test_launch_failure_is_remembered_for_the_page(self, client, H, recorder, win, monkeypatch):
        from reqrec.iehost import IEHostError

        def blocked(*a, **kw):
            raise IEHostError("記録用ブラウザを起動できません: [WinError 1260] グループ ポリシーによってブロックされています")

        monkeypatch.setattr(routes_mod.iehost, "launch", blocked)
        r = _start(client, H)
        assert r.status_code == 500 and r.get_json()["kind"] == "iehost"
        assert "1260" in client.get("/api/state").get_json()["iehost"]["last_error"]

    def test_https_mode_reaches_the_browser(self, client, H, recorder, win, launched):
        assert _start(client, H, https_passthrough=False).status_code == 200
        assert launched.calls[0].get("https_recorded") is True
        client.post("/api/record/stop", json={}, headers=H)
        assert _start(client, H).status_code == 200
        assert "https_recorded" not in launched.calls[1]


# =========================================================================== third review (error kinds, forget, origin)

def _assert_start_undone(client, recorder, events):
    """After a failed start: recorder stopped and forgotten, nothing reported as saved, stop is a 409."""
    assert recorder.running is False and recorder.out is None
    assert events[-2:] == ["recorder.stop", "recorder.forget"]
    st = client.get("/api/record/status").get_json()
    assert st["out"] is None and st["browser_kind"] is None and st["origin"] is None
    assert client.get("/api/state").get_json()["record_browser_kind"] is None


class TestErrorKinds:
    def test_proxy_that_never_listens_is_kind_proxy_not_iehost(self, client, H, recorder, win, launched, events):
        recorder.wait_until_listening = lambda timeout=None: False
        r = _start(client, H)
        assert r.status_code == 500 and r.get_json()["kind"] == "proxy"
        assert "記録用プロキシ" in r.get_json()["error"]
        # not a launch failure: no AppLocker hint on the page, nothing remembered for the readiness list
        assert client.get("/api/state").get_json()["iehost"]["last_error"] is None
        assert launched.calls == []
        _assert_start_undone(client, recorder, events)
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 409  # 「記録は開始されていません」, not a confusing "file missing"

    def test_emulation_failure_is_kind_emulation(self, client, H, recorder, win, launched, monkeypatch, events):
        def bad(level, **kw):
            raise OSError("registry locked")
        monkeypatch.setattr(routes_mod.iehost, "set_emulation", bad)
        r = _start(client, H, emulation="ie11")
        assert r.status_code == 500 and r.get_json()["kind"] == "emulation"
        assert client.get("/api/state").get_json()["iehost"]["last_error"] is None
        _assert_start_undone(client, recorder, events)

    def test_launch_failure_is_kind_iehost_and_remembered(self, client, H, recorder, win, monkeypatch, events):
        monkeypatch.setattr(routes_mod.iehost, "launch", LaunchSpy(events, fail=IEHostError("[WinError 1260] ブロック")))
        r = _start(client, H)
        assert r.status_code == 500 and r.get_json()["kind"] == "iehost"
        assert "1260" in client.get("/api/state").get_json()["iehost"]["last_error"]
        _assert_start_undone(client, recorder, events)

    def test_failed_start_removes_a_half_made_file(self, client, H, recorder, win, monkeypatch, events):
        def launch_after_a_write(*a, **kw):
            with open(recorder.out, "w", encoding="utf-8") as fh:  # something wrote a file meanwhile
                fh.write("{}")
            raise IEHostError("起動できません")
        monkeypatch.setattr(routes_mod.iehost, "launch", launch_after_a_write)
        out = None

        def remember_out(timeout=None):
            nonlocal out
            out = recorder.out
            return True
        recorder.wait_until_listening = remember_out
        assert _start(client, H).status_code == 500
        assert out and not os.path.exists(out)


class TestForgetAfterDiscard:
    def test_discard_forgets_the_deleted_file(self, client, H, recorder, win, launched, events):
        assert _start(client, H).status_code == 200
        out = recorder.out
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("{}")
        r = client.post("/api/record/stop", json={"discard": True}, headers=H)
        assert r.status_code == 200 and r.get_json()["removed"] is True and not os.path.exists(out)
        assert "recorder.forget" in events and recorder.out is None
        st = client.get("/api/record/status").get_json()
        assert st["out"] is None and st["running"] is False  # 詳細設定: 「停止中」, [記録停止] disabled
        assert client.post("/api/record/stop", json={}, headers=H).status_code == 409

    def test_discard_without_forget_support_still_works(self, client, H, recorder, win, launched):
        del FakeRecorder.forget  # an older / foreign recorder object
        try:
            assert _start(client, H).status_code == 200
            assert client.post("/api/record/stop", json={"discard": True}, headers=H).status_code == 200
        finally:
            FakeRecorder.forget = _fake_forget


_fake_forget = FakeRecorder.forget


class TestRecordOrigin:
    def test_origin_is_remembered_until_stop(self, client, H, recorder, win, launched):
        r = _start(client, H, origin="easy")
        assert r.status_code == 200 and r.get_json()["origin"] == "easy"
        assert client.get("/api/record/status").get_json()["origin"] == "easy"
        assert client.get("/api/state").get_json()["record_origin"] == "easy"
        client.post("/api/record/stop", json={}, headers=H)
        assert client.get("/api/record/status").get_json()["origin"] is None
        assert client.get("/api/state").get_json()["record_origin"] is None

    def test_default_origin_is_advanced(self, client, H, recorder, win, launched):
        assert _start(client, H).get_json()["origin"] == "advanced"
        assert client.get("/api/record/status").get_json()["origin"] == "advanced"

    def test_bad_origin_is_400_before_anything_starts(self, client, H, recorder, win, launched):
        r = _start(client, H, origin="robot")
        assert r.status_code == 400 and recorder.start_calls == []

    def test_stop_without_append_uses_the_start_flag(self, app, client, H, recorder, win, launched):
        state = app.extensions["reqrec"]
        state.set_recording(load_recording(str(LOGIN_HAR)), ["x.har"], append=False)
        before = state.recording_summary()["flows"]
        assert _start(client, H, browser="none", append=True, origin="advanced").status_code == 200
        r = client.post("/api/record/stop", json={}, headers=H)  # what the easy screen's [記録をおわる] sends now
        assert r.status_code == 200 and r.get_json()["appended"] is True
        assert r.get_json()["flows"] > before


class TestWindowsAuthSecrets:
    def test_ntlm_entries_are_tagged_and_keep_their_instruction(self, client, H):
        legacy = ROOT / "tests" / "fixtures" / "legacy_webforms_ntlm.har"
        with open(legacy, "rb") as fh:
            r = client.post("/api/recordings/upload", data={"files": (fh, legacy.name)}, headers=H,
                            content_type="multipart/form-data")
        assert r.status_code == 200
        secrets = client.post("/api/easy/build", json={}, headers=H).get_json()["secrets"]
        user, password = [s for s in secrets if s["env_var"] in ("REQREC_NTLM_USER", "REQREC_NTLM_PASSWORD")]
        assert user["auth"] == password["auth"] == "ntlm"
        assert user["secret"] is False and user["default"] == "EXAMPLE\\taro"  # written into the script as default
        assert password["secret"] is True
        assert "reqrec[sspi]" in password["comment"] and "空欄" in password["comment"] and "reqrec[ntlm]" in password["comment"]
        assert "reqrec[sspi]" in user["comment"]


# =========================================================================== real mitmdump: HTTPS pass-through

def _self_signed(tmp_path):
    """A throwaway self-signed certificate for ``localhost`` -> (cert.pem, key.pem, DER bytes)."""
    import datetime

    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "reqrec-origin-server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_pem, key_pem = tmp_path / "origin.pem", tmp_path / "origin.key"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
    return str(cert_pem), str(key_pem), cert.public_bytes(serialization.Encoding.DER)


def _serve(tls=None):
    """A tiny HTTP(S) server on a free loopback port (daemon thread); returns the server."""
    import http.server
    import ssl
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            body = b"hello " + self.path.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _read_all(sock) -> bytes:
    data = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data


def _connect_tunnel(proxy_port: int, target: str):
    import socket

    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=15)
    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            break
        head += chunk
    return sock, head.split(b"\r\n", 1)[0]


@pytest.mark.skipif(not routes_mod.mitmproxy_available(), reason="mitmproxy (mitmdump) not installed")
class TestHttpsPassthroughWithRealMitmdump:
    """``HTTPS_PASSTHROUGH_ARGS`` with the real mitmdump in regular (explicit proxy) mode: plain
    ``http://`` is still recorded, HTTPS on a **non-443** port is tunnelled untouched (the client sees
    the origin server's own certificate, not the untrusted mitmproxy CA) and is not recorded."""

    def test_http_recorded_and_https_on_any_port_tunnelled(self, tmp_path):
        import ssl

        from reqrec.recorder.manager import RecorderManager
        from reqrec.webapp.state import find_free_port

        cert_pem, key_pem, origin_der = _self_signed(tmp_path)
        plain = _serve()
        secure = _serve(tls=(cert_pem, key_pem))
        tls_port = secure.server_address[1]
        assert tls_port != 443
        manager = RecorderManager()
        out = tmp_path / "rec.json"
        proxy_port = find_free_port("127.0.0.1", preferred=18300, avoid=(8765,))
        try:
            manager.start(str(out), port=proxy_port, listen_host="127.0.0.1", extra_args=routes_mod.HTTPS_PASSTHROUGH_ARGS)
            assert manager.wait_until_listening(timeout=60), manager.status()["stderr_tail"]
            # 1) plain http:// through the proxy (absolute-form request, what WinINet sends)
            import socket

            sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=15)
            http_port = plain.server_address[1]
            sock.sendall(f"GET http://127.0.0.1:{http_port}/plain HTTP/1.1\r\nHost: 127.0.0.1:{http_port}\r\n"
                         f"Connection: close\r\n\r\n".encode())
            reply = _read_all(sock)
            sock.close()
            assert reply.split(b" ", 2)[1] == b"200" and reply.endswith(b"hello /plain"), reply[:200]
            # 2) https:// on a non-443 port through CONNECT
            sock, status_line = _connect_tunnel(proxy_port, f"localhost:{tls_port}")
            assert status_line.startswith(b"HTTP/1.1 200"), status_line
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls = ctx.wrap_socket(sock, server_hostname="localhost")
            assert tls.getpeercert(binary_form=True) == origin_der  # the origin's certificate: not intercepted
            tls.sendall(b"GET /secret HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            body = _read_all(tls)
            tls.close()
            assert b"hello /secret" in body
            assert _wait(lambda: manager.flow_count() >= 1)
        finally:
            manager.stop()
            plain.shutdown()
            secure.shutdown()
        recording = manager.load_recording()
        urls = [f.request.url for f in recording.flows]
        assert any(u.endswith("/plain") for u in urls), urls
        assert not any("/secret" in u for u in urls), urls  # tunnelled HTTPS is never recorded


def _wait(predicate, timeout: float = 10.0) -> bool:
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return bool(predicate())
