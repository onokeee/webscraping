"""Tests for the かんたんモード (easy mode) of the GUI.  Contract: DESIGN.md §13.11.

* ``find_free_port`` / ``port: "auto"`` on ``/api/record/start``
* ``/api/easy/build`` (analyse + generate + save in one call)
* ``/api/browser/open`` and ``/api/folder/open`` (with the launchers stubbed)
* ``reqrec.webapp.launch`` helpers with injected fakes
* 「保存されるファイル」 (shared download rule), plan warnings in Japanese, static checks of app.js
"""

from __future__ import annotations

import io
import os
import re
import socket
import sys
from pathlib import Path

import pytest

from reqrec.webapp import TOKEN_HEADER, create_app
from reqrec.webapp import launch
from reqrec.webapp import routes as routes_mod
from reqrec.webapp.state import find_free_port

ROOT = Path(__file__).resolve().parent.parent
LOGIN_HAR = ROOT / "tests" / "fixtures" / "login_flow_chrome.har"


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
def loaded(client, H):
    data = {"append": "false", "files": (io.BytesIO(LOGIN_HAR.read_bytes()), LOGIN_HAR.name)}
    r = client.post("/api/recordings/upload", data=data, headers=H, content_type="multipart/form-data")
    assert r.status_code == 200, r.get_json()
    return r.get_json()


# --------------------------------------------------------------------------- page

class TestPage:
    def test_easy_panel_and_mode_toggle_present(self, client):
        html = client.get("/").get_data(as_text=True)
        assert 'id="panel-easy"' in html
        assert 'id="easy-start"' in html and "記録をはじめる" in html
        assert 'id="easy-stop"' in html and "記録をおわる" in html
        assert 'id="mode-toggle"' in html and "詳細設定を表示" in html
        # the advanced panels are still there (hidden by CSS in easy mode)
        assert 'id="panel-record"' in html and 'id="panel-steps"' in html


# --------------------------------------------------------------------------- free port

class TestFindFreePort:
    def test_prefers_requested_port_when_free(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free = s.getsockname()[1]
        assert find_free_port("127.0.0.1", preferred=free) == free

    def test_skips_busy_and_avoided_ports(self):
        with socket.socket() as busy:
            busy.bind(("127.0.0.1", 0))
            busy.listen(1)
            taken = busy.getsockname()[1]
            port = find_free_port("127.0.0.1", preferred=taken, avoid=(taken + 1,), attempts=5)
            assert port not in (taken, taken + 1)
            assert 1 <= port <= 65535

    def test_falls_back_to_os_choice(self):
        port = find_free_port("127.0.0.1", preferred=65535, attempts=1)
        assert 1 <= port <= 65535

    def test_wildcard_host_binds_loopback(self):
        assert 1 <= find_free_port("0.0.0.0", preferred=8080) <= 65535


class TestAutoPort:
    def test_record_start_with_auto_port(self, app, client, H, monkeypatch):
        state = app.extensions["reqrec"]
        seen = {}

        class FakeRecorder:
            running = False
            out = None
            command_builder = object()

            def start(self, out, port=8080, hosts=None, listen_host="127.0.0.1"):
                seen.update(out=out, port=port, hosts=hosts, listen_host=listen_host)
                self.running = True
                self.out = out
                return self.status()

            def status(self):
                return {"running": self.running, "flows": 0, "out": self.out, "port": seen.get("port"),
                        "listen_host": "127.0.0.1", "hosts": [], "stdout_tail": "", "stderr_tail": "", "error": None, "pid": 1}

            def stop(self, timeout=None):
                self.running = False
                return 0

            def close(self):
                pass

        state.recorder = FakeRecorder()
        monkeypatch.setattr(routes_mod, "mitmproxy_available", lambda: True)
        r = client.post("/api/record/start", json={"port": "auto", "hosts": [], "listen_host": "127.0.0.1"}, headers=H)
        assert r.status_code == 200, r.get_json()
        data = r.get_json()
        assert data["auto_port"] is True
        assert data["port"] == seen["port"]
        assert 1 <= data["port"] <= 65535 and data["port"] != 8765
        assert data["proxy_address"].endswith(f":{data['port']}")

    def test_bad_port_still_rejected(self, client, H):
        r = client.post("/api/record/start", json={"port": "abc"}, headers=H)
        assert r.status_code == 400
        assert "ポート" in r.get_json()["error"]


# --------------------------------------------------------------------------- /api/easy/build

class TestEasyBuild:
    def test_requires_recording(self, client, H):
        r = client.post("/api/easy/build", json={}, headers=H)
        assert r.status_code in (400, 409)
        assert "記録" in r.get_json()["error"]

    def test_builds_and_saves(self, app, client, H, loaded, workdir):
        r = client.post("/api/easy/build", json={}, headers=H)
        assert r.status_code == 200, r.get_json()
        b = r.get_json()
        assert b["ok"] is True
        assert b["name"].endswith(".py") and b["name"].startswith("scrape_")
        path = Path(b["path"])
        assert path.is_file() and path.parent == workdir / "scripts"
        assert b["download_url"] == f"/api/scripts/{b['name']}/download"
        assert b["steps"] >= 1 and len(b["steps_view"]) == b["steps"]
        assert b["final_step_index"] == b["steps_view"][-1]["index"]
        assert b["final_url"] and b["final_url"].startswith("http")
        assert b["flows_total"] == loaded["flows"]
        assert "def step_01_" in b["code"]
        assert path.read_text(encoding="utf-8") == b["code"] if b["code"].endswith("\n") else b["code"] + "\n"
        # secrets of the fixture (the login password) are reported so the easy screen can ask for them
        assert any(s["env_var"] == "REQREC_PASSWORD" for s in b["secrets"])
        # the saved script is now the "last script" for the run panel
        state = app.extensions["reqrec"]
        assert state.last_script_name == b["name"]
        assert state.last_code == b["code"]
        listing = client.get("/api/scripts").get_json()
        assert any(f["name"] == b["name"] for f in listing["files"])
        assert listing["last"] == b["name"]

    def test_custom_name_and_options(self, client, H, loaded):
        r = client.post("/api/easy/build", json={"name": "my_job", "gen_options": {"comments": False}}, headers=H)
        assert r.status_code == 200, r.get_json()
        b = r.get_json()
        assert b["name"] == "my_job.py"
        r2 = client.get(b["download_url"])
        assert r2.status_code == 200 and b"def step_01_" in r2.data

    def test_rejects_unsafe_name(self, client, H, loaded):
        r = client.post("/api/easy/build", json={"name": "../evil"}, headers=H)
        assert r.status_code == 400

    def test_token_required(self, client, loaded):
        r = client.post("/api/easy/build", json={})
        assert r.status_code == 403


# --------------------------------------------------------------------------- /api/browser/open, /api/folder/open

class TestOpenEndpoints:
    def test_browser_open_calls_launcher(self, client, H, monkeypatch):
        calls = []
        monkeypatch.setattr(routes_mod.launch, "open_url", lambda url, prefer_edge=True: calls.append((url, prefer_edge)) or {"url": "http://x", "browser": "edge", "path": "msedge.exe"})
        r = client.post("/api/browser/open", json={"url": "intra.example.test/"}, headers=H)
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["browser"] == "edge"
        assert calls == [("intra.example.test/", True)]

    def test_browser_open_rejects_bad_url(self, client, H):
        r = client.post("/api/browser/open", json={"url": "javascript:alert(1)"}, headers=H)
        assert r.status_code == 400
        assert "http" in r.get_json()["error"]

    def test_browser_open_failure_is_500(self, client, H, monkeypatch):
        def boom(url, prefer_edge=True):
            raise RuntimeError("ブラウザを開けませんでした")
        monkeypatch.setattr(routes_mod.launch, "open_url", boom)
        r = client.post("/api/browser/open", json={}, headers=H)
        assert r.status_code == 500 and "ブラウザ" in r.get_json()["error"]

    def test_folder_open(self, client, H, workdir, monkeypatch):
        opened = []
        monkeypatch.setattr(routes_mod.launch, "open_folder", lambda path: opened.append(path) or {"path": path, "opener": "fake"})
        r = client.post("/api/folder/open", json={"folder": "scripts"}, headers=H)
        assert r.status_code == 200, r.get_json()
        assert opened == [str(workdir / "scripts")]
        r = client.post("/api/folder/open", json={"folder": "workdir"}, headers=H)
        assert r.status_code == 200 and opened[-1] == str(workdir)

    def test_folder_open_rejects_other_paths(self, client, H):
        r = client.post("/api/folder/open", json={"folder": "../.."}, headers=H)
        assert r.status_code == 400
        r = client.post("/api/folder/open", json={"folder": "C:\\Windows"}, headers=H)
        assert r.status_code == 400


# --------------------------------------------------------------------------- launch helpers (pure logic)

class TestLaunchHelpers:
    def test_validate_url(self):
        assert launch.validate_url("") == launch.DEFAULT_START_URL
        assert launch.validate_url("intra.example.co.jp/top") == "http://intra.example.co.jp/top"
        assert launch.validate_url("https://a.b/c?x=1&y=2") == "https://a.b/c?x=1&y=2"
        assert launch.validate_url("edge://newtab") == "edge://newtab"
        for bad in ("javascript:alert(1)", "file:///C:/x", "ftp://host/", "http://", "http://a\nb"):
            with pytest.raises(ValueError):
                launch.validate_url(bad)

    def test_find_edge_known_paths_and_registry(self):
        assert launch.find_edge(exists=lambda p: p.endswith("Application\\msedge.exe") and "Program Files\\" in p, winreg=None, env={}) is not None

        class FakeKey:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class FakeReg:
            HKEY_LOCAL_MACHINE = 1
            HKEY_CURRENT_USER = 2

            def OpenKey(self, hive, key):
                if hive == 1:
                    raise OSError("no")
                return FakeKey()

            def QueryValueEx(self, key, name):
                return ('"D:\\Edge\\msedge.exe"', 1)

        assert launch.find_edge(exists=lambda p: p == "D:\\Edge\\msedge.exe", winreg=FakeReg(), env={}) == "D:\\Edge\\msedge.exe"
        assert launch.find_edge(exists=lambda p: False, winreg=FakeReg(), env={}) is None

    def test_open_url_prefers_edge(self):
        spawned = []
        res = launch.open_url("intra.example.test", popen=lambda args, **kw: spawned.append(args), edge_path="E:\\msedge.exe")
        assert spawned == [["E:\\msedge.exe", "http://intra.example.test"]]
        assert res == {"url": "http://intra.example.test", "browser": "edge", "path": "E:\\msedge.exe"}

    def test_open_url_falls_back_to_default_browser(self):
        opened = []
        res = launch.open_url("", edge_path="", browser_open=lambda u: opened.append(u) or True)
        assert res["browser"] == "default" and opened == ["about:blank"]
        with pytest.raises(RuntimeError):
            launch.open_url("http://a/", edge_path="", browser_open=lambda u: False)

    def test_open_url_edge_spawn_failure_falls_back(self):
        def bad_spawn(args, **kw):
            raise OSError("nope")
        opened = []
        res = launch.open_url("http://a/", popen=bad_spawn, edge_path="E:\\msedge.exe", browser_open=lambda u: opened.append(u) or True)
        assert res["browser"] == "default" and opened == ["http://a/"]

    def test_open_folder(self, tmp_path):
        calls = []
        assert launch.open_folder(str(tmp_path), startfile=lambda p: calls.append(p), platform="win32")["opener"] == "explorer"
        assert calls == [str(tmp_path)]
        spawned = []
        assert launch.open_folder(str(tmp_path), popen=lambda a, **k: spawned.append(a), platform="linux")["opener"] == "xdg-open"
        assert launch.open_folder(str(tmp_path), popen=lambda a, **k: spawned.append(a), platform="darwin")["opener"] == "open"
        assert spawned == [["xdg-open", str(tmp_path)], ["open", str(tmp_path)]]
        with pytest.raises(FileNotFoundError):
            launch.open_folder(str(tmp_path / "missing"), startfile=lambda p: None, platform="win32")

        def no_opener(a, **k):
            raise OSError("missing")
        with pytest.raises(RuntimeError):
            launch.open_folder(str(tmp_path), popen=no_opener, platform="linux")


# =========================================================================== review fixes (DESIGN.md §13.11 / §13.13)

FIXTURES = ROOT / "tests" / "fixtures"
APP_JS = ROOT / "reqrec" / "webapp" / "static" / "app.js"
_JAPANESE = re.compile(r"[぀-ヿ一-鿿]")
#: English sentence fragments of plan.py that must never reach the easy screen
_ENGLISH = re.compile(r"looks dynamic|could not be traced|looks like a credential|existed before the recording|"
                      r"truncated to|replayed as|may fail|may have expired|step\(s\)|^step \d+:|^step_\d+_")


def _html_flow(i, url, headers=(("Content-Type", "text/html; charset=utf-8"),),
               body=b"<html><title>t</title><body>x</body></html>"):
    from reqrec.model import Flow, RecordedRequest, RecordedResponse

    return Flow(id=f"f{i:04d}", started_at=1700000000.0 + i, resource_type="document",
                request=RecordedRequest("GET", url, [("Accept", "text/html")]),
                response=RecordedResponse(200, list(headers), body))


def _synthetic_recording():
    """A small intranet recording: downloads of every kind and two untraceable random tokens."""
    from reqrec.model import Recording

    html = (("Content-Type", "text/html; charset=utf-8"),)
    flows = [
        _html_flow(1, "http://kanri.test/menu.aspx"),
        # html step with an attachment (the server says "save as list.csv")
        _html_flow(2, "http://kanri.test/export.aspx?kind=csv", html + (("Content-Disposition", "attachment; filename=list.csv"),)),
        # text step with an attachment but no file name
        _html_flow(3, "http://kanri.test/report.aspx",
                   (("Content-Type", "text/plain; charset=utf-8"), ("Content-Disposition", "attachment")), b"a,b\n1,2\n"),
        # inline with a file name: shown in the browser, NOT a download
        _html_flow(4, "http://kanri.test/view.aspx", (("Content-Type", "text/html"), ("Content-Disposition", "inline; filename=view.html"))),
        # binary without Content-Disposition: always saved
        _html_flow(5, "http://kanri.test/logo.aspx?id=1", (("Content-Type", "application/octet-stream"),), bytes(range(256)) * 4),
        # a loop whose every iteration is an attachment
        _html_flow(6, "http://kanri.test/page.aspx?p=1", html + (("Content-Disposition", "attachment; filename=p.csv"),)),
        _html_flow(7, "http://kanri.test/page.aspx?p=2", html + (("Content-Disposition", "attachment; filename=p.csv"),)),
        _html_flow(8, "http://kanri.test/page.aspx?p=3", html + (("Content-Disposition", "attachment; filename=p.csv"),)),
        # random-looking values that no earlier response contains -> "looks dynamic" warnings
        _html_flow(9, "http://kanri.test/files/Zq8XkLmPwRtVyNbQ2w7e/show.aspx?sid=Hq3Lp9Zt8Wx2Kv5Mn7Rb"),
    ]
    return Recording(flows=flows, meta={})


class TestDownloadsFollowTheSharedRule:
    """``_downloads_of`` lists exactly what the generated script saves (shared download rule (1), (5))."""

    def test_rule_on_recorded_responses(self):
        from reqrec.plan import build_plan

        rec = _synthetic_recording()
        plan = build_plan(rec)
        by_url = {s.literal_url(): s for s in plan.steps}
        assert by_url["http://kanri.test/page.aspx"].loop is not None  # the three exports fold into a loop
        got = {d["url"]: d for d in routes_mod._downloads_of(rec, plan)}
        assert set(got) == {
            "http://kanri.test/export.aspx",   # html + attachment: listed (and saved by the script)
            "http://kanri.test/report.aspx",   # text + attachment without a name: listed
            "http://kanri.test/logo.aspx",     # binary: listed
            "http://kanri.test/page.aspx",     # loop step: listed, marked as a loop
        }
        assert got["http://kanri.test/export.aspx"]["filename"] == "list.csv"
        assert got["http://kanri.test/export.aspx"]["loop"] is False
        assert got["http://kanri.test/report.aspx"]["filename"] is None
        assert got["http://kanri.test/logo.aspx"]["filename"] is None
        assert got["http://kanri.test/page.aspx"]["loop"] is True and got["http://kanri.test/page.aspx"]["filename"] == "p.csv"
        assert all(set(d) == {"index", "method", "url", "filename", "mime", "loop"} for d in got.values())

    @pytest.mark.parametrize("value, expected", [
        ("attachment", True), ("Attachment; filename=a.xlsx", True), ("  attachment ", True),
        ('filename="a.csv"', True), ("form-data; filename=x", True),
        ("inline; filename=a.pdf", False), ("INLINE; filename*=UTF-8''a.pdf", False), ("inline", False),
        ("", False), (None, False),
    ])
    def test_attachment_rule(self, value, expected):
        assert routes_mod._is_attachment(value) is expected

    def test_easy_build_payload_marks_loop_downloads(self, app, client, H):
        state = app.extensions["reqrec"]
        state.set_recording(_synthetic_recording(), ["synthetic"], append=False)
        r = client.post("/api/easy/build", json={}, headers=H)
        assert r.status_code == 200, r.get_json()
        b = r.get_json()
        loops = [d for d in b["downloads"] if d["loop"]]
        assert len(b["downloads"]) == 4 and len(loops) == 1 and loops[0]["filename"] == "p.csv"


class TestWarningsInJapanese:
    """Every warning ``build_plan`` (+ ``generate``) really produces is shown in Japanese on the easy screen."""

    @staticmethod
    def _all_warnings():
        from reqrec.codegen import generate
        from reqrec.importers import load_recording
        from reqrec.model import PlanOptions
        from reqrec.plan import build_plan

        recordings = [(p.name, load_recording(str(p))) for p in sorted(FIXTURES.iterdir())
                      if p.suffix.lower() in (".har", ".json")]
        recordings.append(("synthetic", _synthetic_recording()))
        out = []
        for name, rec in recordings:
            for opts in (PlanOptions(), PlanOptions(max_steps=1)):
                plan = build_plan(rec, opts)
                generate(plan)  # codegen adds its own notes to plan.warnings
                out.extend((name, w) for w in plan.warnings)
        return out

    def test_every_produced_warning_is_translated(self):
        warnings = self._all_warnings()
        assert len(warnings) >= 10
        for source, text in warnings:
            message = routes_mod.warning_message(text)
            assert _JAPANESE.search(message), (source, text, message)
            assert not _ENGLISH.search(message), (source, text, message)
        # the four English sentences of plan.py are all exercised (a change of wording breaks this test)
        raw = " ".join(text for _source, text in warnings)
        for marker in ("looks dynamic but could not be traced", "looks like a credential",
                       "truncated to --max-steps", "INITIAL_COOKIES"):
            assert marker in raw, marker

    def test_translation_details(self):
        msg = routes_mod.warning_message(
            "step 7: value of `path segment 1` looks dynamic but could not be traced to any earlier response; "
            "replaying the recorded literal may fail")
        assert msg.startswith("手順 7: URL の / で区切った 2 番目の部分は") and "記録したときの値をそのまま送る" in msg
        msg = routes_mod.warning_message(
            "step 3: value of `sid` looks dynamic but could not be traced to any earlier response; "
            "replaying the recorded literal may fail")
        assert msg.startswith("手順 3: 「sid」の値は")
        msg = routes_mod.warning_message(
            "step 2: `txtPassword` looks like a credential; the script reads it from the environment variable "
            "REQREC_TXT_PASSWORD (set it before running)")
        assert "「txtPassword」" in msg and "REQREC_TXT_PASSWORD" in msg and "実行するときに入力" in msg
        msg = routes_mod.warning_message("recording has 9 steps; truncated to --max-steps 1 (8 step(s) ignored)")
        assert "9 手順" in msg and "1 手順" in msg and "8 手順" in msg
        msg = routes_mod.warning_message(
            "2 cookie(s) existed before the recording started (a, b); they are replayed as INITIAL_COOKIES and may have expired")
        assert "Cookie が 2 個" in msg and "(a, b)" in msg
        assert routes_mod.warning_message("step_02_post_login_aspx: 本文を組み直します") == "手順 2: 本文を組み直します"
        assert routes_mod.warning_message("何かの注意") == "何かの注意"

    def test_easy_build_returns_messages_next_to_warnings(self, client, H, loaded):
        b = client.post("/api/easy/build", json={}, headers=H).get_json()
        assert [d["text"] for d in b["warning_details"]] == b["warnings"]
        assert [d["text"] for d in b["note_details"]] == b["notes"]
        assert b["note_details"]  # the login password is a credential note
        assert all(_JAPANESE.search(d["message"]) for d in b["note_details"] + b["warning_details"])

    def test_page_script_uses_the_server_messages(self):
        js = APP_JS.read_text(encoding="utf-8")
        assert "warning_details" in js and "WARNING_PATTERNS" not in js


class TestEasyScreenScript:
    """Static checks of app.js for behaviour only a browser runs (tests/test_webapp_browser.py drives it)."""

    def test_easy_stop_does_not_override_append(self):
        js = APP_JS.read_text(encoding="utf-8")
        stops = re.findall(r"api\('/api/record/stop', \{ method: 'POST', json: (\{[^}]*\}) \}\)", js)
        assert len(stops) >= 3 and not any("append: false" in s for s in stops), stops

    def test_auto_stop_only_for_easy_started_recordings_in_easy_mode(self):
        js = APP_JS.read_text(encoding="utf-8")
        assert "origin: 'easy'" in js and "origin: 'advanced'" in js
        block = js[js.index("Record.subscribe((st) => {  // Record polls"):]
        block = block[:block.index("const pollOnce")]
        assert "!body.classList.contains('easy-mode')) return;" in block
        guard = block.index("if (recOrigin !== 'easy') {")
        assert guard < block.index("stop();") and guard < block.index("discardSilently(")

    def test_windows_auth_entries_keep_their_instruction(self):
        js = APP_JS.read_text(encoding="utf-8")
        assert "if (s.auth) return s.comment" in js
        assert "filter((s) => s.secret !== false)" in js

    def test_only_launch_failures_get_the_applocker_guidance(self):
        js = APP_JS.read_text(encoding="utf-8")
        block = js[js.index("const kind = e.data && e.data.kind;"):]
        block = block[:block.index("setStatus('記録を始められませんでした', 'error');")]
        iehost_branch, rest = block.split("} else if (kind === 'proxy') {", 1)
        assert "kind === 'iehost'" in iehost_branch and "RecBrowser.exe" in iehost_branch and "lastIEError = e.message" in iehost_branch
        assert "RecBrowser.exe" not in rest and "lastIEError" not in rest and "kind === 'emulation'" in rest
