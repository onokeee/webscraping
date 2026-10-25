"""Tests for the gui section of ``reqrec.py`` (+ ``GUI_HTML``): the Flask GUI's endpoints, かんたんモード and the
IE-engine recording browser endpoints.

One section per former test module (headed ``# ===== former tests/<name>.py ... =====``).  The
``workdir`` / ``app`` / ``client`` / ``H`` / ``loaded`` fixtures, identical in several of them, are
defined once in the first section.  The Playwright tests of the GUI are in ``tests/test_gui_browser.py``.
"""

from __future__ import annotations

import errno
import io
import json
import os
import re
import socket
import sys
import textwrap
import time
from pathlib import Path

import flask
import pytest

import reqrec as launch, reqrec as routes_mod, reqrec as webapp
from reqrec import iehost
from reqrec import PlanOptions
from reqrec import (
    ApiError, AppState, ScriptRunner, TOKEN_HEADER, create_app, exclude_netlocs, find_free_port,
    gen_options_from_json, host_allowed, is_windows, normalise_netloc, origin_allowed, plan_options_from_json,
    run_gui, safe_name, sanitise_upload_name,
)
from reqrec import IEHostError
from reqrec import load_recording
from reqrec import RecorderError, RecorderManager, count_flows_in_file

EMULATION_LEVELS = iehost.EMULATION_LEVELS


# ===== former tests/test_webapp.py: GUI endpoints, security checks, recorder manager =====
# Tests for the Flask GUI (reqrec.gui), the RecorderManager and run_gui.  Contract: DESIGN.md §13.6.

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
LOGIN_HAR = FIXTURES / "login_flow_chrome.har"
API_HAR = FIXTURES / "api_firefox.har"

IS_WINDOWS = sys.platform == "win32"


# --------------------------------------------------------------------------- stub "mitmdump"

STUB_SOURCE = textwrap.dedent(
    r'''
    """Fake mitmdump: writes a Recording JSON shortly after start, then idles until SIGINT/SIGTERM."""
    import os, signal, sys, time
    sys.path.insert(0, %(root)r)
    out = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    self_url = sys.argv[3] if len(sys.argv) > 3 else ""
    delay = float(os.environ.get("REQREC_STUB_DELAY", "0.2"))

    def _bye(signum, frame):
        print("stub: signal %%d, exiting" %% signum, flush=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, _bye)
    signal.signal(signal.SIGTERM, _bye)
    if hasattr(signal, "SIGBREAK"):  # Windows: RecorderManager.stop() sends CTRL_BREAK_EVENT
        signal.signal(signal.SIGBREAK, _bye)
    from reqrec import Flow, Recording, RecordedRequest, RecordedResponse

    rec = Recording(meta={"source": "mitmproxy", "started_at": "stub"})
    for i in range(n):
        rec.flows.append(Flow(
            id="f%%04d" %% (i + 1), started_at=1000.0 + i,
            request=RecordedRequest("GET", "https://example.test/page%%d" %% i, [("Accept", "text/html")]),
            response=RecordedResponse(200, [("Content-Type", "text/html; charset=utf-8")], b"<html><title>p</title></html>"),
        ))
    if self_url:
        rec.flows.append(Flow(
            id="f%%04d" %% (n + 1), started_at=1000.0 + n,
            request=RecordedRequest("GET", self_url, []),
            response=RecordedResponse(200, [("Content-Type", "application/json")], b"{}"),
        ))
    print("stub: started", flush=True)
    sys.stderr.write("stub: listening\n")
    sys.stderr.flush()
    time.sleep(delay)
    rec.save(out)
    print("stub: wrote %%d flows" %% len(rec.flows), flush=True)
    while True:
        time.sleep(0.1)
    '''
) % {"root": str(ROOT)}


@pytest.fixture
def stub_script(tmp_path: Path) -> Path:
    path = tmp_path / "fake_mitmdump.py"
    path.write_text(STUB_SOURCE, encoding="utf-8")
    return path


def _stub_builder(stub: Path, n: int = 3, self_url: str = ""):
    def builder(out, port=8080, hosts=None, **_kw):
        return [sys.executable, str(stub), out, str(n), self_url]

    return builder


def _wait_until(pred, timeout: float = 15.0, interval: float = 0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return pred()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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


def _upload(client, headers, *paths: Path, append: bool = False):
    files = [("files", (io.BytesIO(p.read_bytes()), p.name)) for p in paths]
    data = {"append": "true" if append else "false"}
    data["files"] = [f[1] for f in files] if len(files) > 1 else files[0][1]
    return client.post("/api/recordings/upload", data=data, headers=headers, content_type="multipart/form-data")


@pytest.fixture
def loaded(client, H):
    r = _upload(client, H, LOGIN_HAR)
    assert r.status_code == 200, r.get_json()
    return r.get_json()


# =========================================================================== security

class TestSecurity:
    def test_index_renders_token_and_japanese(self, client, app):
        r = client.get("/")
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert f'data-token="{app.config["REQREC_TOKEN"]}"' in html
        assert "記録" in html and "読み込み" in html and "ステップ" in html and "コード" in html and "実行" in html
        # offline: every script / stylesheet comes from this server
        assert not re.findall(r'(?:src|href)=["\']https?://', html)
        assert not re.findall(r'(?:src|href)=["\']//', html)
        # the CSS / JS are inlined into the page (GUI_HTML), nothing else is fetched
        assert "<script src=" not in html and 'rel="stylesheet"' not in html
        assert "<style>" in html and "const TOKEN = body.dataset.token;" in html

    def test_no_static_route(self, client):
        assert client.get("/static/app.js").status_code == 404
        assert client.get("/static/app.css").status_code == 404

    @pytest.mark.parametrize("host", ["evil.com", "evil.com:8765", "127.0.0.1.evil.com", "localhost.evil.com:80"])
    def test_foreign_host_rejected_even_for_get(self, client, host):
        r = client.get("/api/state", headers={"Host": host})
        assert r.status_code == 403
        assert "Host" in r.get_json()["error"]

    def test_foreign_host_rejected_for_page_and_static(self, client):
        assert client.get("/", headers={"Host": "evil.com"}).status_code == 403
        assert client.get("/static/app.js", headers={"Host": "evil.com"}).status_code == 403

    @pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.1:8765", "localhost", "localhost:8765", "LOCALHOST:1234", "[::1]", "[::1]:8765"])
    def test_local_hosts_allowed(self, client, host):
        assert client.get("/api/state", headers={"Host": host}).status_code == 200

    def test_bound_host_allowed(self, tmp_path):
        a = create_app(str(tmp_path / "w"), host="192.168.1.20", port=9000, TESTING=True)
        c = a.test_client()
        assert c.get("/api/state", headers={"Host": "192.168.1.20:9000"}).status_code == 200
        assert c.get("/api/state", headers={"Host": "192.168.1.21:9000"}).status_code == 403

    def test_host_allowed_helper(self):
        assert host_allowed("127.0.0.1:8765", "127.0.0.1")
        assert host_allowed("localhost", "127.0.0.1")
        assert host_allowed("[::1]:8765", "127.0.0.1")
        assert not host_allowed("evil.com", "127.0.0.1")
        assert not host_allowed("", "127.0.0.1")
        assert host_allowed("10.0.0.5:8765", "0.0.0.0")  # wildcard bind: IP literals ok
        assert not host_allowed("rebind.example.com", "0.0.0.0")  # ... but never a DNS name

    def test_post_without_token_is_403(self, client):
        r = client.post("/api/recordings/clear", json={})
        assert r.status_code == 403
        assert "トークン" in r.get_json()["error"]

    def test_post_with_wrong_token_is_403(self, client):
        r = client.post("/api/recordings/clear", json={}, headers={TOKEN_HEADER: "nope"})
        assert r.status_code == 403

    def test_post_with_token_ok(self, client, H):
        assert client.post("/api/recordings/clear", json={}, headers=H).status_code == 200

    def test_cross_origin_post_rejected(self, client, H):
        r = client.post("/api/recordings/clear", json={}, headers={**H, "Origin": "http://evil.com"})
        assert r.status_code == 403
        assert "オリジン" in r.get_json()["error"]
        r = client.post("/api/recordings/clear", json={}, headers={**H, "Origin": "null"})
        assert r.status_code == 403

    def test_same_origin_post_accepted(self, client, H):
        r = client.post("/api/recordings/clear", json={}, headers={**H, "Origin": "http://localhost"})
        assert r.status_code == 200
        r = client.post("/api/recordings/clear", json={}, headers={**H, "Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765"})
        assert r.status_code == 200

    def test_origin_helper(self):
        assert origin_allowed(None, "localhost:8765")
        assert origin_allowed("http://localhost:8765", "localhost:8765")
        assert origin_allowed("http://localhost", "localhost:80")
        assert not origin_allowed("http://localhost:9999", "localhost:8765")
        assert not origin_allowed("null", "localhost:8765")
        assert not origin_allowed("file://", "localhost:8765")

    def test_get_needs_no_token(self, client):
        assert client.get("/api/state").status_code == 200

    def test_unknown_api_is_json_404(self, client):
        r = client.get("/api/nope")
        assert r.status_code == 404
        assert r.is_json and "error" in r.get_json()

    def test_wrong_method_is_json_405(self, client, H):
        r = client.post("/api/state", json={}, headers=H)
        assert r.status_code == 405 and "error" in r.get_json()

    def test_non_json_body_is_400(self, client, H):
        r = client.post("/api/recordings/open", data="not json", headers={**H, "Content-Type": "text/plain"})
        assert r.status_code == 400 and "JSON" in r.get_json()["error"]
        r = client.post("/api/recordings/open", data="[1,2]", headers={**H, "Content-Type": "application/json"})
        assert r.status_code == 400

    def test_security_headers(self, client):
        r = client.get("/api/state")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["Cache-Control"] == "no-store"

    def test_each_app_has_random_token(self, tmp_path):
        a = create_app(str(tmp_path / "a"))
        b = create_app(str(tmp_path / "b"))
        assert a.config["REQREC_TOKEN"] != b.config["REQREC_TOKEN"]
        assert len(a.config["REQREC_TOKEN"]) >= 32


# =========================================================================== path safety

class TestPathSafety:
    @pytest.mark.parametrize("bad", [
        "../x", "..\\x", "a/b", "a\\b", "C:\\x", "C:x", "/etc/passwd", "", " ", ".", "..", ".hidden", "x\x00y",
        "con:", "a b", "名前?.py", "x" * 201, None, 5, ["a"],
    ])
    def test_safe_name_rejects(self, bad):
        with pytest.raises(ApiError) as exc:
            safe_name(bad)
        assert exc.value.status == 400

    @pytest.mark.parametrize("good", ["rec.json", "login_flow_chrome.har", "a-b_c.1.py", "日本語.har", "x"])
    def test_safe_name_accepts(self, good):
        assert safe_name(good) == good

    def test_path_in_stays_inside_subfolder(self, workdir):
        st = AppState(str(workdir), token="t")
        p = st.path_in("scripts", "s.py")
        assert Path(p).parent == (workdir / "scripts").resolve()
        for bad in ("../s.py", "sub/s.py", "..", "C:\\s.py"):
            with pytest.raises(ApiError):
                st.path_in("scripts", bad)
        with pytest.raises(ApiError):
            st.path_in("somewhere_else", "s.py")

    def test_sanitise_upload_name(self):
        assert sanitise_upload_name("C:\\Users\\me\\My File (1).har") == "My_File_1_.har"
        assert sanitise_upload_name("../../etc/passwd") == "passwd"
        assert sanitise_upload_name("..") == "upload"
        assert sanitise_upload_name("") == "upload"
        assert sanitise_upload_name(".hidden.har") == "hidden.har"

    def test_download_traversal_rejected(self, client):
        assert client.get("/api/scripts/../../x/download").status_code == 404
        r = client.get("/api/scripts/..%2F..%2Fx/download")
        assert r.status_code in (400, 404)
        r = client.get("/api/scripts/.hidden/download")
        assert r.status_code in (400, 404)

    @pytest.mark.parametrize("name", ["../evil", "a/b", "C:\\x", ".", "..", ".hidden", "a b"])
    def test_save_traversal_rejected(self, client, H, name, workdir):
        r = client.post("/api/scripts/save", json={"name": name, "code": "print(1)\n"}, headers=H)
        assert r.status_code == 400, r.get_json()
        assert not list((workdir / "scripts").glob("*")) or all(p.suffix == ".py" and "evil" not in p.name for p in (workdir / "scripts").iterdir())

    @pytest.mark.parametrize("name", ["../x.har", "a/b.har", "..", ".hidden.har"])
    def test_open_traversal_rejected(self, client, H, name):
        r = client.post("/api/recordings/open", json={"names": [name]}, headers=H)
        assert r.status_code == 400

    def test_open_bad_folder_rejected(self, client, H):
        r = client.post("/api/recordings/open", json={"names": [{"folder": "scripts", "name": "x.har"}]}, headers=H)
        assert r.status_code == 400

    def test_save_output_traversal_rejected(self, client, H):
        r = client.post("/api/run/save_output", json={"name": "../out.txt"}, headers=H)
        assert r.status_code == 400


# =========================================================================== option coercion

class TestOptions:
    def test_plan_options_coercion(self):
        o = plan_options_from_json({
            "keep_static": "true", "keep_trackers": 1, "collapse_redirects": "off", "min_value_length": "6",
            "max_steps": "", "include_hosts": "a.com, b.com", "exclude_hosts": ["x.com", " ", "x.com"],
            "exclude_flow_ids": ["f0001"], "final_flow_id": "", "unknown_key": 123,
        })
        assert o.keep_static is True and o.keep_trackers is True and o.collapse_redirects is False
        assert o.min_value_length == 6 and o.max_steps is None
        assert o.include_hosts == ["a.com", "b.com"] and o.exclude_hosts == ["x.com"]
        assert o.exclude_flow_ids == ["f0001"] and o.final_flow_id is None
        assert o.detect_auth is True  # default kept
        assert plan_options_from_json({"include_hosts": []}).include_hosts is None
        assert plan_options_from_json(None) == PlanOptions()

    def test_plan_options_errors(self):
        with pytest.raises(ApiError):
            plan_options_from_json({"min_value_length": "abc"})
        with pytest.raises(ApiError):
            plan_options_from_json({"max_steps": 0})
        with pytest.raises(ApiError):
            plan_options_from_json({"keep_static": "maybe"})
        with pytest.raises(ApiError):
            plan_options_from_json([1, 2])

    def test_gen_options_coercion(self):
        g = gen_options_from_json({"html_parser": "lxml", "delay": "0.5", "timeout": 10, "comments": "false", "legacy_tls": True, "strict_status": "on"})
        assert g.html_parser == "lxml" and g.delay == 0.5 and g.timeout == 10.0
        assert g.comments is False and g.strict_status is True
        assert not hasattr(g, "legacy_tls")  # the removed option is an unknown key now: ignored
        with pytest.raises(ApiError):
            gen_options_from_json({"html_parser": "regex"})
        with pytest.raises(ApiError):
            gen_options_from_json({"delay": "-1"})
        with pytest.raises(ApiError):
            gen_options_from_json({"timeout": "nan"})


# =========================================================================== state

class TestStateEndpoint:
    def test_initial_state(self, client):
        s = client.get("/api/state").get_json()
        assert s["recording"] == {"loaded": False, "sources": [], "flows": 0, "hosts": [], "meta": None, "excluded_self_flows": 0}
        assert s["recorder"]["running"] is False
        assert s["run"]["running"] is False
        assert s["plan_options"]["collapse_redirects"] is True
        assert s["gen_options"]["html_parser"] == "html.parser"
        assert "windows" not in s and "record_browser_kind" not in s  # no system proxy / recording-mode state any more
        assert isinstance(s["mitmproxy_available"], bool)

    def test_workdir_subfolders_created(self, app, workdir):
        for sub in ("recordings", "uploads", "scripts", "outputs"):
            assert (workdir / sub).is_dir()


# =========================================================================== recordings

class TestRecordings:
    def test_upload_har(self, client, H, workdir):
        r = _upload(client, H, LOGIN_HAR)
        assert r.status_code == 200
        j = r.get_json()
        assert j["loaded"] is True and j["flows"] == 14
        assert j["sources"] == ["uploads/login_flow_chrome.har"]
        assert "shop.example.test" in j["hosts"]
        assert (workdir / "uploads" / "login_flow_chrome.har").is_file()
        s = client.get("/api/state").get_json()
        assert s["recording"]["flows"] == 14

    def test_upload_two_files_at_once_merges(self, client, H):
        r = _upload(client, H, LOGIN_HAR, API_HAR)
        assert r.status_code == 200
        assert r.get_json()["flows"] == 20
        assert len(r.get_json()["sources"]) == 2

    def test_upload_append_merges_with_current(self, client, H, loaded):
        r = _upload(client, H, API_HAR, append=True)
        j = r.get_json()
        assert r.status_code == 200 and j["flows"] == 20 and j["appended"] is True
        assert j["sources"] == ["uploads/login_flow_chrome.har", "uploads/api_firefox.har"]
        # flow ids are renumbered chronologically
        plan = client.post("/api/plan", json={}, headers=H).get_json()
        ids = [f["id"] for f in plan["flows"]]
        assert ids == [f"f{i:04d}" for i in range(1, 21)]
        times = [f["started_at"] for f in plan["flows"]]
        assert times == sorted(times)

    def test_upload_without_append_replaces(self, client, H, loaded):
        r = _upload(client, H, API_HAR, append=False)
        assert r.get_json()["flows"] == 6
        assert r.get_json()["sources"] == ["uploads/api_firefox.har"]

    def test_upload_same_name_twice_keeps_both_files(self, client, H, workdir):
        _upload(client, H, LOGIN_HAR)
        _upload(client, H, LOGIN_HAR)
        names = sorted(p.name for p in (workdir / "uploads").iterdir())
        assert names == ["login_flow_chrome.har", "login_flow_chrome_2.har"]

    @pytest.mark.parametrize("name", ["notes.txt", "flows.mitm", "x.flows", "x.flow"])  # mitmproxy files are not read any more
    def test_upload_rejects_unknown_extension(self, client, H, name):
        r = client.post("/api/recordings/upload", data={"files": (io.BytesIO(b"x"), name)}, headers=H, content_type="multipart/form-data")
        assert r.status_code == 400 and "形式" in r.get_json()["error"]
        assert r.get_json()["error"].endswith("(対応: .har / .json)")

    def test_upload_rejects_garbage_json(self, client, H):
        r = client.post("/api/recordings/upload", data={"files": (io.BytesIO(b"{\"nothing\": 1}"), "x.json")}, headers=H, content_type="multipart/form-data")
        assert r.status_code == 400

    def test_upload_without_file(self, client, H):
        r = client.post("/api/recordings/upload", data={}, headers=H, content_type="multipart/form-data")
        assert r.status_code == 400 and "ファイル" in r.get_json()["error"]

    def test_list_and_open(self, client, H, loaded):
        files = client.get("/api/recordings").get_json()["files"]
        assert [(f["folder"], f["name"], f["flows"]) for f in files] == [("uploads", "login_flow_chrome.har", 14)]
        client.post("/api/recordings/clear", json={}, headers=H)
        assert client.get("/api/state").get_json()["recording"]["loaded"] is False
        r = client.post("/api/recordings/open", json={"names": ["login_flow_chrome.har"]}, headers=H)
        assert r.status_code == 200 and r.get_json()["flows"] == 14
        r = client.post("/api/recordings/open", json={"names": [{"folder": "uploads", "name": "login_flow_chrome.har"}], "append": True}, headers=H)
        assert r.get_json()["flows"] == 28  # appended to itself

    def test_open_missing_is_404(self, client, H):
        r = client.post("/api/recordings/open", json={"names": ["nope.har"]}, headers=H)
        assert r.status_code == 404

    def test_open_needs_names(self, client, H):
        assert client.post("/api/recordings/open", json={}, headers=H).status_code == 400
        assert client.post("/api/recordings/open", json={"names": []}, headers=H).status_code == 400

    def test_clear(self, client, H, loaded):
        r = client.post("/api/recordings/clear", json={}, headers=H)
        assert r.status_code == 200 and r.get_json()["recording"]["loaded"] is False
        assert client.post("/api/plan", json={}, headers=H).status_code == 409

    def test_exclude_netlocs_helper(self):
        rec = load_recording(str(LOGIN_HAR))
        same, n = exclude_netlocs(rec, {"localhost:8765"})
        assert n == 0 and same is rec
        trimmed, n = exclude_netlocs(rec, {"shop.example.test"})
        assert n == 7 and len(trimmed.flows) == 7
        assert [f.id for f in trimmed.flows] == [f"f{i:04d}" for i in range(1, 8)]
        assert trimmed.meta["excluded_self_flows"] == 7
        assert normalise_netloc("LOCALHOST:80") == "localhost"
        assert normalise_netloc("localhost:443", "https") == "localhost"
        assert normalise_netloc("localhost:8765") == "localhost:8765"


# =========================================================================== plan

class TestPlan:
    def test_plan_without_recording(self, client, H):
        r = client.post("/api/plan", json={}, headers=H)
        assert r.status_code == 409 and "読み込" in r.get_json()["error"]

    def test_plan_content(self, client, H, loaded):
        r = client.post("/api/plan", json={"plan_options": {}}, headers=H)
        assert r.status_code == 200
        j = r.get_json()
        assert j["steps_kept"] == 5 and j["flows_total"] == 14 and j["flows_kept"] == 8 and j["dropped"] == 6
        assert len(j["flows"]) == 14
        for key in ("id", "started_at", "method", "status", "mime", "url", "referer", "kept", "reason", "step_index", "resource_type"):
            assert all(key in f for f in j["flows"]), key
        by_id = {f["id"]: f for f in j["flows"]}
        assert by_id["f0001"]["kept"] is True and by_id["f0001"]["step_index"] == 1 and by_id["f0001"]["reason"] is None
        assert by_id["f0002"]["kept"] is False and by_id["f0002"]["reason"].startswith("static asset") and by_id["f0002"]["step_index"] is None
        assert by_id["f0002"]["referer"] == "https://shop.example.test/login"
        assert by_id["f0001"]["referer"] is None
        assert by_id["f0004"]["reason"] == "tracker/analytics host"
        assert by_id["f0006"]["reason"] == "no response recorded" and by_id["f0006"]["status"] is None
        assert by_id["f0007"]["reason"] == "CORS preflight" and by_id["f0007"]["method"] == "OPTIONS"
        assert by_id["f0008"]["step_index"] == 2 and by_id["f0009"]["step_index"] == 2  # collapsed redirect
        assert by_id["f0011"]["step_index"] == 4 and by_id["f0013"]["step_index"] == 4  # loop
        assert by_id["f0010"]["mime"] == "application/json"
        # sorted by started_at then id
        assert [f["id"] for f in j["flows"]] == sorted((f["id"] for f in j["flows"]))
        assert j["constants"][0]["name"] == "PASSWORD" and j["constants"][0]["value"] is None
        assert "REQREC_PASSWORD" in j["env_vars"]
        assert j["auth"] is None
        assert "final_step_index" in j
        assert any("ステップ" in j["summary"] for _ in [0])
        assert j["loops"] == [{"step_index": 4, "var": "page", "count": 3, "numeric_range": [1, 3]}]
        assert j["steps"][0]["func_name"].startswith("step_01_")
        assert isinstance(j["warnings"], list)
        assert j["plan_options"]["keep_static"] is False

    def test_plan_options_change_result(self, client, H, loaded):
        j = client.post("/api/plan", json={"plan_options": {"keep_static": "true"}}, headers=H).get_json()
        by_id = {f["id"]: f for f in j["flows"]}
        assert by_id["f0002"]["kept"] is True
        assert j["plan_options"]["keep_static"] is True
        # top-level options accepted too
        j2 = client.post("/api/plan", json={"keep_all": True}, headers=H).get_json()
        assert j2["steps_kept"] > j["steps_kept"] or j2["flows_kept"] >= j["flows_kept"]
        # options persist in state
        assert client.get("/api/state").get_json()["plan_options"]["keep_all"] is True

    def test_plan_bad_option_is_400(self, client, H, loaded):
        r = client.post("/api/plan", json={"plan_options": {"min_value_length": "x"}}, headers=H)
        assert r.status_code == 400 and "min_value_length" in r.get_json()["error"]

    def test_plan_include_hosts(self, client, H, loaded):
        j = client.post("/api/plan", json={"plan_options": {"include_hosts": "api.example.test"}}, headers=H).get_json()
        by_id = {f["id"]: f for f in j["flows"]}
        assert by_id["f0001"]["kept"] is False and "host" in by_id["f0001"]["reason"]
        assert by_id["f0010"]["kept"] is True

    def test_exclude_flow_override(self, client, H, loaded):
        j = client.post("/api/plan", json={"plan_options": {"exclude_flow_ids": ["f0010"]}}, headers=H).get_json()
        by_id = {f["id"]: f for f in j["flows"]}
        assert by_id["f0010"]["kept"] is False and by_id["f0010"]["reason"] == "excluded by user"
        assert j["steps_kept"] == 4

    def test_include_flow_override(self, client, H, loaded):
        j = client.post("/api/plan", json={"plan_options": {"include_flow_ids": ["f0002"]}}, headers=H).get_json()
        by_id = {f["id"]: f for f in j["flows"]}
        assert by_id["f0002"]["kept"] is True and by_id["f0002"]["step_index"] is not None
        assert j["steps_kept"] == 6

    def test_final_flow_override(self, client, H, loaded):
        j = client.post("/api/plan", json={"plan_options": {"final_flow_id": "f0009"}}, headers=H).get_json()
        assert j["final_step_index"] == 2
        by_id = {f["id"]: f for f in j["flows"]}
        assert by_id["f0009"]["is_final"] is True and by_id["f0008"]["is_final"] is True and by_id["f0001"]["is_final"] is False
        j = client.post("/api/plan", json={"plan_options": {"final_flow_id": "f0002"}}, headers=H).get_json()
        assert j["final_step_index"] is None  # dropped flow cannot be the result


# =========================================================================== flow detail

class TestFlowDetail:
    def test_html_flow(self, client, H, loaded):
        client.post("/api/plan", json={}, headers=H)
        r = client.get("/api/flow/f0001")
        assert r.status_code == 200
        j = r.get_json()
        assert j["request"]["method"] == "GET" and j["request"]["url"].endswith("/login")
        assert isinstance(j["request"]["headers"], list) and all(len(h) == 2 for h in j["request"]["headers"])
        assert j["response"]["status"] == 200 and j["response"]["body"]["kind"] == "html"
        assert "<" in j["response"]["body"]["text"] and j["response"]["body"]["truncated"] is False
        assert j["step_index"] == 1 and j["reason"] is None
        assert j["started_at_iso"]

    def test_json_flow_pretty_printed(self, client, H, loaded):
        j = client.get("/api/flow/f0010").get_json()
        body = j["response"]["body"]
        assert body["kind"] == "json" and body["text"].startswith("{\n  ")
        json.loads(body["text"])

    def test_form_request_body(self, client, H, loaded):
        j = client.get("/api/flow/f0008").get_json()
        body = j["request"]["body"]
        assert body["kind"] == "form" and any(k == "password" for k, _ in body["pairs"])
        assert j["response"]["status"] == 302

    def test_no_response_flow(self, client, H, loaded):
        j = client.get("/api/flow/f0006").get_json()
        assert j["response"] is None

    def test_dropped_flow_reports_reason(self, client, H, loaded):
        client.post("/api/plan", json={}, headers=H)
        j = client.get("/api/flow/f0004").get_json()
        assert j["step_index"] is None and j["reason"] == "tracker/analytics host"

    def test_unknown_flow_404(self, client, H, loaded):
        assert client.get("/api/flow/f9999").status_code == 404
        assert client.get("/api/flow/zzz").status_code == 404
        assert client.get("/api/flow/f9999").get_json()["error"]

    def test_binary_body_summarised(self, client, H, loaded):
        j = client.get("/api/flow/f0003").get_json()  # PNG
        body = j["response"]["body"]
        assert body["kind"] == "binary" and body["text"] is None and body["size"] > 0

    def test_long_body_truncated(self, client, H, loaded):
        state = client.application.extensions["reqrec"]
        flow = state.recording.flow_by_id("f0001")
        flow.response.body = b"<html>" + b"x" * (300 * 1024) + b"</html>"
        body = client.get("/api/flow/f0001").get_json()["response"]["body"]
        assert body["truncated"] is True and len(body["text"]) == routes_mod.BODY_LIMIT

    def test_without_recording_409(self, client):
        assert client.get("/api/flow/f0001").status_code == 409


# =========================================================================== generate / scripts

class TestGenerate:
    def test_generate(self, client, H, loaded):
        r = client.post("/api/generate", json={"plan_options": {}, "gen_options": {"delay": "0.5", "legacy_tls": True}}, headers=H)
        assert r.status_code == 200
        j = r.get_json()
        compile(j["code"], "<gen>", "exec")
        assert "def step_01_" in j["code"] and "DELAY = 0.5" in j["code"]
        assert j["secrets"] == [{"name": "PASSWORD", "env_var": "REQREC_PASSWORD", "comment": j["secrets"][0]["comment"]}]
        assert j["env_vars"] == ["REQREC_PASSWORD"]
        assert "ステップ" in j["summary"] and isinstance(j["warnings"], list)
        assert j["steps"] == 5 and j["suggested_name"] == "scrape_shop_example_test"
        assert "legacy_tls" not in j["gen_options"]  # removed option: ignored, never echoed back
        assert "VERIFY_TLS" not in j["code"] and "_LegacyTLSAdapter" not in j["code"]
        s = client.get("/api/state").get_json()
        assert s["gen_options"]["delay"] == 0.5 and s["secrets"] == j["secrets"]

    def test_generate_without_recording(self, client, H):
        assert client.post("/api/generate", json={}, headers=H).status_code == 409

    def test_generate_bad_gen_option(self, client, H, loaded):
        r = client.post("/api/generate", json={"gen_options": {"html_parser": "nope"}}, headers=H)
        assert r.status_code == 400

    def test_generate_uses_plan_options(self, client, H, loaded):
        j = client.post("/api/generate", json={"plan_options": {"include_hosts": ["api.example.test"]}}, headers=H).get_json()
        assert "shop.example.test" not in j["code"].split("BASE_HEADERS")[-1] or j["steps"] == 2
        assert j["steps"] == 2

    def test_save_list_download(self, client, H, loaded, workdir):
        code = client.post("/api/generate", json={}, headers=H).get_json()["code"]
        r = client.post("/api/scripts/save", json={"name": "my_script", "code": code}, headers=H)
        assert r.status_code == 200
        j = r.get_json()
        assert j["name"] == "my_script.py" and Path(j["path"]) == (workdir / "scripts" / "my_script.py").resolve()
        assert (workdir / "scripts" / "my_script.py").read_text(encoding="utf-8") == code
        lst = client.get("/api/scripts").get_json()
        assert [f["name"] for f in lst["files"]] == ["my_script.py"] and lst["last"] == "my_script.py"
        d = client.get("/api/scripts/my_script.py/download")
        assert d.status_code == 200 and d.get_data(as_text=True) == code
        assert "attachment" in d.headers["Content-Disposition"]
        assert client.get("/api/scripts/my_script/download").status_code == 200  # .py optional
        assert client.get("/api/scripts/other/download").status_code == 404

    def test_save_uses_last_generated_code_when_omitted(self, client, H, loaded):
        client.post("/api/generate", json={}, headers=H)
        r = client.post("/api/scripts/save", json={"name": "auto"}, headers=H)
        assert r.status_code == 200 and r.get_json()["name"] == "auto.py"

    def test_save_without_code_or_name(self, client, H):
        r = client.post("/api/scripts/save", json={"name": "x"}, headers=H)
        assert r.status_code == 400 and "生成" in r.get_json()["error"]
        r = client.post("/api/scripts/save", json={"code": "print(1)\n"}, headers=H)
        assert r.status_code == 200 and re.match(r"scrape_\d{8}_\d{6}\.py", r.get_json()["name"])


# =========================================================================== run

TINY_SCRIPT = textwrap.dedent(
    """
    import os, sys
    print("HELLO " + os.environ.get("REQREC_TEST_VAR", "(unset)"))
    print("日本語の出力")
    sys.stderr.write("warn line\\n")
    """
)
SLEEPY_SCRIPT = "import time\nprint('sleeping', flush=True)\ntime.sleep(60)\n"


def _save(client, H, name, code):
    r = client.post("/api/scripts/save", json={"name": name, "code": code}, headers=H)
    assert r.status_code == 200, r.get_json()
    return r.get_json()["name"]


def _wait_run_finished(client, timeout=30.0):
    def done():
        return client.get("/api/run/status").get_json()["running"] is False
    assert _wait_until(done, timeout), client.get("/api/run/status").get_json()
    return client.get("/api/run/status").get_json()


class TestRun:
    def test_run_prints_env_var_and_finishes(self, client, H, workdir):
        _save(client, H, "tiny", TINY_SCRIPT)
        r = client.post("/api/run", json={"name": "tiny", "env": {"REQREC_TEST_VAR": "secret-value"}}, headers=H)
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["name"] == "tiny.py"
        st = _wait_run_finished(client)
        assert st["exit_code"] == 0
        assert "HELLO secret-value" in st["stdout_tail"] and "日本語の出力" in st["stdout_tail"]
        assert "warn line" in st["stderr_tail"]
        assert st["started_at"] and st["finished_at"] and st["stopped_by_user"] is False
        # the secret never lands on disk
        for p in workdir.rglob("*"):
            if p.is_file():
                assert b"secret-value" not in p.read_bytes()
        # save the output
        r = client.post("/api/run/save_output", json={"name": "result.txt"}, headers=H)
        assert r.status_code == 200
        saved = workdir / "outputs" / "result.txt"
        assert saved.read_text(encoding="utf-8") == "HELLO secret-value\n日本語の出力\n"
        r = client.post("/api/run/save_output", json={}, headers=H)
        assert r.status_code == 200 and re.match(r"output_\d{8}_\d{6}\.txt", r.get_json()["name"])
        r = client.post("/api/run/save_output", json={"name": "noext"}, headers=H)
        assert r.get_json()["name"] == "noext.txt"

    def test_run_failing_script_reports_exit_code(self, client, H):
        _save(client, H, "bad", "import sys\nprint('before')\nraise SystemExit(7)\n")
        assert client.post("/api/run", json={"name": "bad"}, headers=H).status_code == 200
        st = _wait_run_finished(client)
        assert st["exit_code"] == 7 and "before" in st["stdout_tail"]

    def test_run_exception_shows_traceback(self, client, H):
        _save(client, H, "boom", "raise RuntimeError('kaboom')\n")
        client.post("/api/run", json={"name": "boom"}, headers=H)
        st = _wait_run_finished(client)
        assert st["exit_code"] == 1 and "kaboom" in st["stderr_tail"]

    def test_run_only_one_at_a_time_and_stop(self, client, H):
        _save(client, H, "sleepy", SLEEPY_SCRIPT)
        r = client.post("/api/run", json={"name": "sleepy"}, headers=H)
        assert r.status_code == 200 and r.get_json()["running"] is True
        r2 = client.post("/api/run", json={"name": "sleepy"}, headers=H)
        assert r2.status_code == 409 and "実行中" in r2.get_json()["error"]
        assert _wait_until(lambda: "sleeping" in client.get("/api/run/status").get_json()["stdout_tail"], 15)
        r = client.post("/api/run/stop", json={}, headers=H)
        assert r.status_code == 200
        j = r.get_json()
        assert j["running"] is False and j["exit_code"] not in (None, 0) and j["stopped_by_user"] is True and j["stopped"] is True
        # stopping again is harmless
        assert client.post("/api/run/stop", json={}, headers=H).get_json()["stopped"] is False

    def test_run_missing_script_404(self, client, H):
        r = client.post("/api/run", json={"name": "nope"}, headers=H)
        assert r.status_code == 404

    def test_run_bad_env_name(self, client, H):
        _save(client, H, "tiny", TINY_SCRIPT)
        r = client.post("/api/run", json={"name": "tiny", "env": {"BAD NAME": "x"}}, headers=H)
        assert r.status_code == 400
        r = client.post("/api/run", json={"name": "tiny", "env": ["x"]}, headers=H)
        assert r.status_code == 400

    def test_run_name_defaults_to_last_saved(self, client, H):
        _save(client, H, "tiny", TINY_SCRIPT)
        assert client.post("/api/run", json={}, headers=H).status_code == 200
        assert _wait_run_finished(client)["exit_code"] == 0

    def test_save_output_before_any_run_409(self, client, H):
        r = client.post("/api/run/save_output", json={"name": "x.txt"}, headers=H)
        assert r.status_code == 409

    def test_run_status_initial(self, client):
        st = client.get("/api/run/status").get_json()
        assert st == {**st, "running": False, "exit_code": None, "stdout_tail": "", "stderr_tail": ""}

    def test_script_runner_bounded_output(self, tmp_path):
        script = tmp_path / "many.py"
        script.write_text("for i in range(5000):\n    print('line', i)\n", encoding="utf-8")
        runner = ScriptRunner(max_lines=50, max_output_bytes=2000)
        runner.start(str(script), {})
        assert runner.wait(30) == 0
        st = runner.status()
        assert st["stdout_tail"].count("\n") == 49 and st["stdout_tail"].endswith("line 4999")
        assert st["stdout_truncated"] is True and len(runner.last_stdout().encode()) <= 2000


# =========================================================================== removed Windows endpoints

class TestNoWindowsSettingsEndpoints:
    """The system proxy / CA certificate endpoints are gone: the GUI never changes Windows settings."""

    def test_status_is_not_routed(self, client):
        r = client.get("/api/win/status")
        assert r.status_code == 404 and r.is_json

    @pytest.mark.parametrize("path", ["/api/win/proxy", "/api/win/proxy/restore", "/api/win/cert/install"])
    def test_posts_are_not_routed(self, client, H, path):
        r = client.post(path, json={"enable": True, "server": "127.0.0.1:8080"}, headers=H)
        assert r.status_code == 404 and "error" in r.get_json()


# =========================================================================== RecorderManager

class TestRecorderManager:
    def test_start_status_flow_count_stop(self, tmp_path, stub_script):
        out = tmp_path / "recs" / "rec.json"
        m = RecorderManager(command_builder=_stub_builder(stub_script, n=4))
        assert m.running is False and m.status()["running"] is False and m.flow_count() == 0
        st = m.start(str(out), port=18080, hosts="example.test, b.test")
        try:
            assert st["running"] is True and st["out"] == str(out) and st["pid"]
            assert st["hosts"] == ["example.test", "b.test"] and st["port"] == 18080
            assert "listen_host" not in st  # always 127.0.0.1 (RECORD_LISTEN_HOST)
            assert m.running is True
            assert _wait_until(lambda: m.flow_count() == 4, 15)
            assert m.status()["flows"] == 4
            assert _wait_until(lambda: "stub: wrote 4 flows" in m.status()["stdout_tail"], 5)
            assert "stub: listening" in m.status()["stderr_tail"]
            assert m.status()["error"] is None
        finally:
            rc = m.stop()
        assert rc == 0  # SIGINT -> sys.exit(0)
        st = m.status()
        assert st["running"] is False and st["exit_code"] == 0 and st["error"] is None and st["flows"] == 4
        assert m.load_recording().flows[0].request.url == "https://example.test/page0"
        assert m.stop() == 0  # idempotent

    def test_command_builder_gets_port_hosts_and_extra_args_only(self, tmp_path, stub_script):
        seen = []

        def builder(out, **kw):
            seen.append((out, kw))
            return _stub_builder(stub_script)(out, **kw)

        m = RecorderManager(command_builder=builder)
        out = str(tmp_path / "r.json")
        m.start(out, port=18081, hosts=["a.test"], extra_args=("--ignore-hosts", ".*"))
        m.stop()
        m.start(out, port=18082)
        m.stop()
        assert seen == [(os.path.abspath(out), {"port": 18081, "hosts": ["a.test"], "extra_args": ["--ignore-hosts", ".*"]}),
                        (os.path.abspath(out), {"port": 18082, "hosts": []})]  # no listen_host: always 127.0.0.1

    def test_start_twice_is_an_error(self, tmp_path, stub_script):
        m = RecorderManager(command_builder=_stub_builder(stub_script))
        m.start(str(tmp_path / "r.json"))
        try:
            with pytest.raises(RecorderError, match="記録中"):
                m.start(str(tmp_path / "r2.json"))
        finally:
            m.stop()

    def test_bad_port(self, tmp_path, stub_script):
        m = RecorderManager(command_builder=_stub_builder(stub_script))
        with pytest.raises(RecorderError):
            m.start(str(tmp_path / "r.json"), port=70000)
        with pytest.raises(RecorderError):
            m.start(str(tmp_path / "r.json"), port="abc")

    def test_command_that_cannot_start(self, tmp_path):
        m = RecorderManager(command_builder=lambda out, **kw: ["/nonexistent/mitmdump-xyz", out])
        with pytest.raises(RecorderError, match="起動できません"):
            m.start(str(tmp_path / "r.json"))
        assert m.running is False

    def test_forget_drops_the_output_of_a_stopped_session_only(self, tmp_path, stub_script):
        m = RecorderManager(command_builder=_stub_builder(stub_script, n=2))
        out = tmp_path / "r.json"
        m.start(str(out))
        try:
            assert m.forget() is False and m.out == str(out)  # never while running
            assert _wait_until(lambda: m.flow_count() == 2, 15)
        finally:
            m.stop()
        assert m.forget() is True
        st = m.status()
        assert st["out"] is None and st["out_name"] is None and st["flows"] == 0 and st["running"] is False
        assert st["exit_code"] == 0 and "stub" in st["stdout_tail"]  # diagnostics stay
        with pytest.raises(RecorderError):
            m.load_recording()
        assert out.is_file()  # forget() never deletes anything itself

    def test_child_dying_is_reported(self, tmp_path):
        m = RecorderManager(command_builder=lambda out, **kw: [sys.executable, "-c", "import sys; sys.stderr.write('Address already in use\\n'); sys.exit(3)"])
        m.start(str(tmp_path / "r.json"))
        assert _wait_until(lambda: m.status()["running"] is False, 10)
        st = m.status()
        assert st["exit_code"] == 3 and "3" in st["error"] and "Address already in use" in st["error"]
        assert m.stop() == 3
        with pytest.raises(RecorderError, match="作成されませんでした"):
            m.load_recording()

    def test_stop_escalates_to_kill(self, tmp_path):
        script = tmp_path / "stubborn.py"
        script.write_text("import signal, time\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nprint('x', flush=True)\nwhile True: time.sleep(0.1)\n", encoding="utf-8")
        m = RecorderManager(command_builder=lambda out, **kw: [sys.executable, str(script)], stop_timeout=0.5)
        m.start(str(tmp_path / "r.json"))
        import reqrec as mgr

        old = mgr._MANAGER_GRACE_AFTER_TERMINATE
        mgr._MANAGER_GRACE_AFTER_TERMINATE = 0.5
        try:
            t0 = time.time()
            rc = m.stop()
        finally:
            mgr._MANAGER_GRACE_AFTER_TERMINATE = old
        assert rc != 0 and time.time() - t0 < 10
        assert m.running is False

    def test_stop_without_start(self):
        m = RecorderManager(command_builder=lambda out, **kw: ["x"])
        assert m.stop() is None
        assert m.status()["running"] is False and m.status()["out"] is None

    def test_load_recording_without_start(self):
        with pytest.raises(RecorderError):
            RecorderManager(command_builder=lambda out, **kw: ["x"]).load_recording()

    def test_count_flows_in_file(self, tmp_path):
        assert count_flows_in_file(str(tmp_path / "missing.json"), default=-1) == -1
        p = tmp_path / "bad.json"
        p.write_text("{\"flows\": [", encoding="utf-8")  # mid-write
        assert count_flows_in_file(str(p), default=-1) == -1
        p.write_text("", encoding="utf-8")
        assert count_flows_in_file(str(p), default=5) == 5
        p.write_text(json.dumps({"version": 1, "meta": {}, "flows": [{"id": "f0001"}, {"id": "f0002"}]}), encoding="utf-8")
        assert count_flows_in_file(str(p)) == 2

    def test_flow_count_keeps_last_good_value_while_file_broken(self, tmp_path):
        out = tmp_path / "r.json"
        m = RecorderManager(command_builder=lambda o, **kw: ["x"])
        m.out = str(out)
        out.write_text(json.dumps({"version": 1, "meta": {}, "flows": [{"id": "f0001"}]}), encoding="utf-8")
        assert m.flow_count() == 1
        out.write_text("{\"flows\": [{", encoding="utf-8")
        assert m.flow_count() == 1

    def test_default_command_builder_is_build_command(self):
        from reqrec import build_command

        assert RecorderManager().command_builder is build_command


# =========================================================================== recorder endpoints

def _proxy_ready(state) -> None:
    """The stub mitmdump never binds its port: report the proxy as listening at once (else 500 kind=proxy)."""
    state.recorder.wait_until_listening = lambda timeout=None: True


class TestRecordEndpoints:
    """The real ``RecorderManager`` with the stub mitmdump; the recording browser is faked (``win`` / ``launched``)."""

    @pytest.fixture
    def stubbed(self, client, H, stub_script, win, launched):
        state = client.application.extensions["reqrec"]
        state.recorder.command_builder = _stub_builder(stub_script, n=3, self_url="http://localhost/api/record/status")
        _proxy_ready(state)
        yield state
        state.recorder.close()

    def test_full_cycle(self, client, H, stubbed, workdir, launched):
        r = client.post("/api/record/start", json={"hosts": "example.test"}, headers=H)
        assert r.status_code == 200, r.get_json()
        j = r.get_json()
        assert re.match(r"rec_\d{8}_\d{6}\.json$", j["out"])
        assert j["proxy_address"] == f"127.0.0.1:{j['port']}" and j["status"]["port"] == j["port"]
        assert j["status"]["running"] is True and j["status"]["hosts"] == ["example.test"]
        assert j["browser"]["kind"] == "iehost" and launched.calls[0]["proxy_address"] == j["proxy_address"]
        assert "localhost" in j["self_excluded_hosts"]
        # status polling: flows appear (3 + the GUI's own request)
        assert _wait_until(lambda: client.get("/api/record/status").get_json()["flows"] == 4, 15)
        st = client.get("/api/record/status").get_json()
        assert st["running"] is True and st["error"] is None and "stub" in st["stdout_tail"]
        assert "listen_host" not in st and "proxy_backup_active" not in st and "browser_kind" not in st
        assert st["browser"]["kind"] == "iehost" and st["browser"]["running"] is True
        assert client.get("/api/state").get_json()["recorder"]["running"] is True
        # a second start is refused
        r = client.post("/api/record/start", json={}, headers=H)
        assert r.status_code == 409 and len(launched.calls) == 1
        # stop -> loaded, GUI's own traffic excluded
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 200, r.get_json()
        j = r.get_json()
        assert j["flows"] == 3 and j["excluded_self"] == 1 and j["exit_code"] == 0
        assert j["sources"] == [f"recordings/{j['out']}"]
        assert (workdir / "recordings" / j["out"]).is_file()
        st = client.get("/api/record/status").get_json()
        assert st["running"] is False and st["exit_code"] == 0
        plan = client.post("/api/plan", json={}, headers=H).get_json()
        assert plan["flows_total"] == 3 and plan["excluded_self_flows"] == 1
        assert all("localhost" not in f["url"] for f in plan["flows"])
        # the recording is listed and can be re-opened (self traffic excluded again, harmlessly)
        files = client.get("/api/recordings").get_json()["files"]
        assert any(f["folder"] == "recordings" and f["name"] == j["out"] for f in files)
        r = client.post("/api/recordings/open", json={"names": [j["out"]]}, headers=H)
        assert r.status_code == 200 and r.get_json()["flows"] == 3

    def test_stop_with_append_merges(self, client, H, stubbed, loaded):
        assert client.post("/api/record/start", json={}, headers=H).status_code == 200
        assert _wait_until(lambda: client.get("/api/record/status").get_json()["flows"] == 4, 15)
        r = client.post("/api/record/stop", json={"append": True}, headers=H)
        assert r.status_code == 200 and r.get_json()["flows"] == 14 + 3

    def test_append_flag_from_start_is_remembered(self, client, H, stubbed, loaded):
        assert client.post("/api/record/start", json={"append": True}, headers=H).status_code == 200
        assert _wait_until(lambda: client.get("/api/record/status").get_json()["flows"] == 4, 15)
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.get_json()["flows"] == 17

    def test_stop_without_start_409(self, client, H):
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 409

    def test_discard_with_the_real_recorder_forgets_the_file(self, client, H, stubbed, workdir):
        r = client.post("/api/record/start", json={}, headers=H)
        assert r.status_code == 200
        out = workdir / "recordings" / r.get_json()["out"]
        assert _wait_until(lambda: out.is_file(), 15)
        r = client.post("/api/record/stop", json={"discard": True}, headers=H)
        assert r.status_code == 200 and r.get_json()["removed"] is True and not out.exists()
        st = client.get("/api/record/status").get_json()
        assert st["out"] is None and st["running"] is False  # the panel shows 「停止中」, not 「記録は保存されました」
        assert client.post("/api/record/stop", json={}, headers=H).status_code == 409

    def test_start_validation(self, client, H, stubbed, launched):
        assert client.post("/api/record/start", json={"hosts": 5}, headers=H).status_code == 400
        assert client.post("/api/record/start", json={"start_url": "javascript:alert(1)"}, headers=H).status_code == 400
        assert stubbed.recorder.running is False and launched.calls == []

    def test_stop_with_empty_recording_is_400(self, client, H, stub_script, win, launched):
        state = client.application.extensions["reqrec"]
        state.recorder.command_builder = _stub_builder(stub_script, n=0)
        _proxy_ready(state)
        assert client.post("/api/record/start", json={}, headers=H).status_code == 200
        assert _wait_until(lambda: "wrote 0 flows" in client.get("/api/record/status").get_json()["stdout_tail"], 15)
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 400 and "何も記録されませんでした" in r.get_json()["error"] and r.get_json()["empty"] is True
        assert client.get("/api/state").get_json()["recording"]["loaded"] is False

    def test_stop_when_no_file_written_is_400(self, client, H, win, launched):
        state = client.application.extensions["reqrec"]
        state.recorder.command_builder = lambda out, **kw: [sys.executable, "-c", "import time\ntime.sleep(30)"]
        _proxy_ready(state)
        assert client.post("/api/record/start", json={}, headers=H).status_code == 200
        r = client.post("/api/record/stop", json={}, headers=H)
        # no file at all = nothing was recorded (the addon writes after the first response only)
        assert r.status_code == 400 and "何も記録されませんでした" in r.get_json()["error"] and r.get_json()["empty"] is True
        assert client.get("/api/state").get_json()["recording"]["loaded"] is False

    def test_missing_mitmproxy_is_reported(self, client, H, monkeypatch):
        monkeypatch.setattr(routes_mod, "mitmproxy_available", lambda: False)
        r = client.post("/api/record/start", json={}, headers=H)
        assert r.status_code == 400 and "mitmproxy" in r.get_json()["error"] and "reqrec[record]" in r.get_json()["error"]


# =========================================================================== run_gui

class TestRunGui:
    def test_keyboard_interrupt_returns_0_and_prints_url(self, monkeypatch, tmp_path, capsys):
        calls = {}

        def fake_run(self, host, port, debug, use_reloader, threaded):
            calls.update(host=host, port=port, debug=debug, use_reloader=use_reloader, threaded=threaded)
            raise KeyboardInterrupt

        monkeypatch.setattr(flask.Flask, "run", fake_run)
        port = _free_port()
        rc = run_gui(host="127.0.0.1", port=port, workdir=str(tmp_path / "w"), open_browser=False)
        assert rc == 0
        out = capsys.readouterr().out
        assert f"GUI を起動しました: http://127.0.0.1:{port}  (Ctrl+C で終了)" in out
        assert calls == {"host": "127.0.0.1", "port": port, "debug": False, "use_reloader": False, "threaded": True}
        assert (tmp_path / "w" / "scripts").is_dir()

    def test_port_in_use_returns_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr(flask.Flask, "run", lambda self, **kw: pytest.fail("server must not start"))
        monkeypatch.setattr(webapp.webbrowser, "open", lambda url: pytest.fail("browser must not open"))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            rc = run_gui(host="127.0.0.1", port=port, workdir=str(tmp_path / "w"), open_browser=True)
        assert rc == 1
        err = capsys.readouterr().err
        assert "ポート" in err and str(port) in err

    def test_bind_error_from_app_run_returns_1(self, monkeypatch, tmp_path, capsys):
        def fake_run(self, **kw):
            raise OSError(errno.EADDRINUSE, "Address already in use")  # 98 on Linux, 10048 on Windows

        monkeypatch.setattr(flask.Flask, "run", fake_run)
        rc = run_gui(host="127.0.0.1", port=_free_port(), workdir=str(tmp_path / "w"), open_browser=False)
        assert rc == 1 and "ポート" in capsys.readouterr().err

    def test_browser_opened_once_server_answers(self, monkeypatch):
        opened = []
        monkeypatch.setattr(webapp.webbrowser, "open", lambda url: opened.append(url))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            t = webapp._open_browser_later(f"http://127.0.0.1:{port}", "127.0.0.1", port, delay=0)
            t.join(10)
        assert opened == [f"http://127.0.0.1:{port}"]

    def test_browser_not_opened_when_server_never_answers(self, monkeypatch):
        opened = []
        monkeypatch.setattr(webapp.webbrowser, "open", lambda url: opened.append(url))
        monkeypatch.setattr(webapp.time, "time", _FakeClock())
        port = _free_port()
        t = webapp._open_browser_later(f"http://127.0.0.1:{port}", "127.0.0.1", port, delay=0)
        t.join(15)
        assert opened == [] and not t.is_alive()

    def test_cli_gui_subcommand_calls_run_gui(self, monkeypatch, tmp_path):
        import reqrec as cli

        seen = {}
        monkeypatch.setattr(webapp, "run_gui", lambda **kw: seen.update(kw) or 0)
        rc = cli.main(["gui", "--port", "9999", "--workdir", str(tmp_path), "--no-browser"])
        assert rc == 0
        assert seen == {"host": "127.0.0.1", "port": 9999, "workdir": str(tmp_path), "open_browser": False}


class _FakeClock:
    """time.time() replacement that jumps forward 3 s per call so the 10 s wait loop ends quickly."""

    def __init__(self):
        self.now = time.time()

    def __call__(self):
        self.now += 3.0
        return self.now


# ===== former tests/test_webapp_easy.py: かんたんモード (easy mode) =====
# Tests for the かんたんモード (easy mode) of the GUI.  Contract: DESIGN.md §13.11.
#
# * ``find_free_port`` and the automatic proxy port of ``/api/record/start``
# * ``/api/easy/build`` (analyse + generate + save in one call)
# * ``/api/folder/open`` (with the opener stubbed) and the address check of ``/api/browser/open``
# * ``validate_url`` / ``open_folder`` with injected fakes
# * 「保存されるファイル」 (shared download rule), plan warnings in Japanese, static checks of the page script (former app.js)

# --------------------------------------------------------------------------- fixtures
#
# ``workdir`` / ``app`` / ``client`` / ``H`` / ``loaded``: defined once in the first section (former tests/test_webapp.py).


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


class TestAutoPort:
    @pytest.mark.parametrize("port", [8765, "auto", "abc"])  # a ``port`` in the body is ignored (no port input any more)
    def test_record_start_picks_a_free_loopback_port(self, client, H, recorder, win, launched, port):
        r = client.post("/api/record/start", json={"port": port, "hosts": []}, headers=H)
        assert r.status_code == 200, r.get_json()
        data = r.get_json()
        assert data["port"] == recorder.start_calls[0]["port"]
        assert 1 <= data["port"] <= 65535 and data["port"] != 8765  # never the GUI's own port
        assert data["proxy_address"] == f"127.0.0.1:{data['port']}" == launched.calls[0]["proxy_address"]
        assert "auto_port" not in data


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
    @pytest.mark.parametrize("url", ["javascript:alert(1)", "edge://newtab", "file:///C:/x"])
    def test_browser_open_rejects_bad_url(self, client, H, url):
        r = client.post("/api/browser/open", json={"url": url}, headers=H)  # checked before anything else
        assert r.status_code == 400
        assert "http" in r.get_json()["error"]

    def test_folder_open(self, client, H, workdir, monkeypatch):
        opened = []
        monkeypatch.setattr(routes_mod, "open_folder", lambda path: opened.append(path) or {"path": path, "opener": "fake"})
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
        assert launch.validate_url("intra.example.co.jp/top") == "http://intra.example.co.jp/top"
        assert launch.validate_url("https://a.b/c?x=1&y=2") == "https://a.b/c?x=1&y=2"
        for empty in ("", "   ", None):
            with pytest.raises(ValueError, match="サイトのアドレスを入力してください"):
                launch.validate_url(empty)
        for bad in ("javascript:alert(1)", "edge://newtab", "file:///C:/x", "ftp://host/", "http://"):
            with pytest.raises(ValueError, match="http:// で始まる形で入力してください"):
                launch.validate_url(bad)
        with pytest.raises(ValueError):
            launch.validate_url("http://a\nb")

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

APP_JS = routes_mod.GUI_HTML  # app.js is inlined in the page template (GUI_HTML, the former gui.html)
_JAPANESE = re.compile(r"[぀-ヿ一-鿿]")
#: English sentence fragments of the plan section (reqrec.analysis) that must never reach the easy screen
_ENGLISH = re.compile(r"looks dynamic|could not be traced|looks like a credential|existed before the recording|"
                      r"truncated to|replayed as|may fail|may have expired|step\(s\)|^step \d+:|^step_\d+_")


def _html_flow(i, url, headers=(("Content-Type", "text/html; charset=utf-8"),),
               body=b"<html><title>t</title><body>x</body></html>"):
    from reqrec import Flow, RecordedRequest, RecordedResponse

    return Flow(id=f"f{i:04d}", started_at=1700000000.0 + i, resource_type="document",
                request=RecordedRequest("GET", url, [("Accept", "text/html")]),
                response=RecordedResponse(200, list(headers), body))


def _synthetic_recording():
    """A small intranet recording: downloads of every kind and two untraceable random tokens."""
    from reqrec import Recording

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
        from reqrec import build_plan

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
        from reqrec import generate
        from reqrec import load_recording
        from reqrec import PlanOptions
        from reqrec import build_plan

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
        # the four English sentences of the plan section are all exercised (a change of wording breaks this test)
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
        js = APP_JS
        assert "warning_details" in js and "WARNING_PATTERNS" not in js


class TestEasyScreenScript:
    """Static checks of the page script in gui.html (former app.js) for behaviour only a browser runs (tests/test_gui_browser.py drives it)."""

    def test_easy_stop_does_not_override_append(self):
        js = APP_JS
        stops = re.findall(r"api\('/api/record/stop', \{ method: 'POST', json: (\{[^}]*\}) \}\)", js)
        assert len(stops) >= 3 and not any("append: false" in s for s in stops), stops

    def test_auto_stop_only_for_easy_started_recordings_in_easy_mode(self):
        js = APP_JS
        assert "origin: 'easy'" in js and "origin: 'advanced'" in js
        block = js[js.index("Record.subscribe((st) => {  // Record polls"):]
        block = block[:block.index("const pollOnce")]
        assert "!body.classList.contains('easy-mode')) return;" in block
        guard = block.index("if (recOrigin !== 'easy') {")
        assert guard < block.index("stop();") and guard < block.index("discardSilently(")

    def test_windows_auth_entries_keep_their_instruction(self):
        js = APP_JS
        assert "if (s.auth) return s.comment" in js
        assert "filter((s) => s.secret !== false)" in js

    def test_only_launch_failures_get_the_applocker_guidance(self):
        js = APP_JS
        block = js[js.index("const kind = e.data && e.data.kind;"):]
        block = block[:block.index("setStatus('記録を始められませんでした', 'error');")]
        iehost_branch, rest = block.split("} else if (kind === 'proxy') {", 1)
        assert "kind === 'iehost'" in iehost_branch and "RecBrowser.exe" in iehost_branch and "lastIEError = e.message" in iehost_branch
        assert "RecBrowser.exe" not in rest and "lastIEError" not in rest and "kind === 'emulation'" in rest

    def test_every_recording_goes_through_the_recording_browser(self):
        js = APP_JS
        # the easy screen can start only with mitmproxy and the recording browser (no manual-proxy fallback)
        assert "function canStart() { return MITM_AVAILABLE && IEHOST; }" in js
        assert "const IEHOST = body.dataset.iehostAvailable === 'true'" in js
        # 詳細設定 [記録開始] keeps the server-rendered disabled state: it needs mitmproxy as well
        assert "const CAN_RECORD = IEHOST_AVAILABLE && body.dataset.mitmAvailable === 'true';" in js
        assert "btnStart.disabled = running || !CAN_RECORD;" in js and "btnStart.disabled = !CAN_RECORD;" in js
        assert "btnStart.disabled = false;" not in js.split("const Record = (() => {")[1].split("const Load = (() => {")[0]
        # [ブラウザをもう一度開く] always (re)opens the recording browser: only the address is sent
        assert "api('/api/browser/open', { method: 'POST', json: { url } })" in js
        assert "if (!st.browser || st.browser.kind !== 'iehost') return;" in js
        # neither start request sends a port, a listen address, a browser kind or a pass-through switch
        starts = re.findall(r"api\('/api/record/start', \{ method: 'POST', json: \{(.*?)\} \}\)", js, re.S)
        assert len(starts) == 2, starts  # 詳細設定 [記録開始] and かんたん画面 [記録をはじめる]
        for start in starts:
            keys = re.findall(r"\b(\w+):", re.sub(r"//[^\n]*", "", start))
            assert {"hosts", "append", "start_url", "emulation", "origin"} == set(keys), keys
        for removed in ("/api/win/", "listen_host", "set_system_proxy", "https_passthrough", "IS_WINDOWS",
                        "EASY_BLOCKED", "recMode", "GUIDE_EDGE", "browser_kind", "legacy_tls", "mitm.it"):
            assert removed not in js, removed


# ===== former tests/test_webapp_iehost.py: GUI endpoints of the IE-engine recording browser =====
# GUI integration of the in-app IE-engine recording browser.  Contract: DESIGN.md §13.12.
#
# Every recording goes through the recording browser.  Everything runs with fakes (no mitmdump, no
# csc.exe, no RecBrowser.exe, no registry), so these tests pass on every OS:
#
# * a ``FakeRecorder`` (enough of ``RecorderManager``) that records the arguments it was started with
#   (``extra_args`` included) and serves a real recording on ``load_recording``;
# * ``reqrec.iehost.availability`` / ``launch`` / ``set_emulation`` / ``get_emulation`` monkeypatched on
#   the class the routes call (``routes_mod.iehost``), ``launch`` returning a ``FakeBrowser`` (``pid`` /
#   ``running`` / ``poll()`` / ``close()``).  ``availability`` is the only platform check of the routes.

AVAILABLE = {"available": True, "reason": None, "exe": "X:\\work\\bin\\RecBrowser.exe", "built": True,
             "source": "src.cs", "csc": "csc.exe", "prebuilt": None}
UNAVAILABLE = {"available": False, "reason": "記録用ブラウザを作成するためのコンパイラ (csc.exe) が見つかりません。", "exe": None,
               "built": False, "source": "src.cs", "csc": None, "prebuilt": None}
#: The real ``iehost.availability`` (the ``win`` fixture replaces it).
_REAL_AVAILABILITY = iehost.availability


# --------------------------------------------------------------------------- fakes

class FakeRecorder:
    """Enough of ``RecorderManager`` for the record endpoints; ``events`` is shared with the browser fake."""

    def __init__(self, events: list, with_flows: bool = True):
        self.events = events
        self.with_flows = with_flows
        self.running = False
        self.out = None
        self.port = None
        self.hosts = []
        self.command_builder = object()  # not the default builder -> the mitmproxy check is skipped
        self.start_calls = []

    def start(self, out, port=8080, hosts=None, **kwargs):
        self.start_calls.append({"out": out, "port": port, "hosts": hosts, **kwargs})
        self.running = True
        self.out = out
        self.port = port
        self.hosts = list(hosts or [])
        self.events.append("recorder.start")
        return self.status()

    def status(self):
        return {"running": self.running, "flows": 0, "out": self.out, "out_name": os.path.basename(self.out) if self.out else None,
                "port": self.port, "hosts": list(self.hosts), "stdout_tail": "",
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
        from reqrec import Recording
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
#
# ``workdir`` / ``app`` / ``client`` / ``H``: defined once in the first section (former tests/test_webapp.py).


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
    """mitmproxy and a usable recording browser on any OS (fakes only; the registry is never touched)."""
    monkeypatch.setattr(routes_mod, "mitmproxy_available", lambda: True)
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
    body = {"hosts": [], "append": False}
    body.update(extra)
    return client.post("/api/record/start", json=body, headers=H)


def _disabled_button(html: str, button_id: str) -> bool:
    """Whether the page renders ``<button id="...">`` with the ``disabled`` attribute."""
    tag = re.search(r'<button[^>]*\bid="%s"[^>]*>' % re.escape(button_id), html)
    assert tag, button_id
    return re.search(r"\sdisabled(?=[\s>=])", tag.group(0)) is not None


# --------------------------------------------------------------------------- start

class TestStart:
    def test_iehost_start_launches_browser_through_the_proxy(self, app, client, H, recorder, win, launched, workdir):
        r = _start(client, H, start_url="kanri/top.aspx", emulation="ie11")
        assert r.status_code == 200, r.get_json()
        j = r.get_json()
        # recorder: extra args tunnel HTTPS on every port (no certificate needed)
        call = recorder.start_calls[0]
        assert call["extra_args"] == ["--ignore-hosts", ".*"] == list(routes_mod.HTTPS_PASSTHROUGH_ARGS)
        assert call["port"] == j["port"] and j["port"] != 8765 and set(call) == {"out", "port", "hosts", "extra_args"}
        # browser: launched after the recorder, against the recorder's proxy address, with the typed URL
        assert launched.calls == [{"workdir": str(workdir), "proxy_address": f"127.0.0.1:{j['port']}",
                                   "url": "http://kanri/top.aspx", "title": "reqrec 記録用ブラウザ"}]
        assert launched.calls[0]["proxy_address"] == j["proxy_address"]
        assert win == [EMULATION_LEVELS["ie11"]]
        assert j["browser"] == {"kind": "iehost", "pid": 1000, "running": True, "exit_code": None, "log": launched.browsers[0].log_path}
        assert j["emulation"] == "ie11" and j["origin"] == "advanced" and j["warnings"] == []
        # the fields of the removed manual / system-proxy / https modes are gone from the response
        assert not {"instructions", "auto_port", "system_proxy", "browser_kind", "https_passthrough"} & set(j)
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
        # the real availability check, as it answers off Windows: there is no other way to record
        monkeypatch.setattr(routes_mod.iehost, "availability", lambda workdir, **kw: _REAL_AVAILABILITY(workdir, platform="linux"))
        r = _start(client, H)
        assert r.status_code == 400 and r.get_json()["error"] == "記録用ブラウザ (IE エンジン) は Windows でのみ使えます。"
        assert recorder.start_calls == [] and launched.calls == []

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

    def test_fields_of_the_removed_modes_are_ignored(self, client, H, recorder, win, launched):
        # manual proxy (browser "none"), a chosen port / listen address, the system proxy and recorded
        # https no longer exist: such keys change nothing, HTTPS is always passed through untouched
        r = _start(client, H, browser="none", port=8765, listen_host="0.0.0.0", set_system_proxy=True, https_passthrough=False)
        assert r.status_code == 200, r.get_json()
        j = r.get_json()
        call = recorder.start_calls[0]
        assert call["extra_args"] == list(routes_mod.HTTPS_PASSTHROUGH_ARGS) and call["port"] == j["port"] != 8765
        assert "listen_host" not in call
        assert j["proxy_address"] == f"127.0.0.1:{j['port']}" and j["browser"]["kind"] == "iehost"
        assert len(launched.calls) == 1 and "https_recorded" not in launched.calls[0]
        assert launched.calls[0]["proxy_address"] == j["proxy_address"] and win == []

    def test_browser_not_launched_when_recorder_died_immediately(self, client, H, recorder, win, launched):
        def start(out, **kw):
            recorder.start_calls.append(kw)
            recorder.out = out
            recorder.running = False  # died at once (port in use)
            return recorder.status()
        recorder.start = start
        r = _start(client, H)
        assert r.status_code == 200 and r.get_json()["browser"] is None and launched.calls == []

    def test_stop_after_recorder_died_explains_without_proxy_or_certificate(self, client, H, recorder, win, launched):
        # the no-browser branch of the empty-recording message: the recorder died before the browser opened
        def start(out, **kw):
            recorder.start_calls.append(kw)
            recorder.out = out
            recorder.running = False
            return recorder.status()
        recorder.start = start
        recorder.with_flows = False
        assert _start(client, H).status_code == 200
        r = client.post("/api/record/stop", json={}, headers=H)
        j = r.get_json()
        assert r.status_code == 400 and j["empty"] is True and launched.calls == []
        assert "記録用ブラウザが開く前に記録が止まった" in j["error"] and "http://" in j["error"]
        assert "プロキシ" not in j["error"] and "証明書" not in j["error"]


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
        r = client.post("/api/browser/open", json={"url": "http://kanri/"}, headers=H)
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["running"] is True and r.get_json()["relaunched"] is False
        assert len(launched.calls) == 1

    def test_closed_browser_is_relaunched_against_the_recorder(self, app, client, H, recorder, win, launched):
        j = _start(client, H).get_json()
        launched.browsers[0].exit(0)
        r = client.post("/api/browser/open", json={"url": "kanri/"}, headers=H)
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["running"] is True and r.get_json()["relaunched"] is True
        assert len(launched.calls) == 2
        assert launched.calls[1]["proxy_address"] == f"127.0.0.1:{recorder.port}" == j["proxy_address"]
        assert launched.calls[1]["url"] == "http://kanri/" and launched.calls[1]["title"] == "reqrec 記録用ブラウザ"
        assert app.extensions["reqrec"].browser is launched.browsers[1]
        assert r.get_json()["browser"]["pid"] == 1001

    def test_browser_field_is_ignored(self, client, H, recorder, win, launched):
        # there is no other browser to open: a ``browser`` key (formerly "none" = normal Edge) changes nothing
        _start(client, H)
        launched.browsers[0].exit(0)
        r = client.post("/api/browser/open", json={"browser": "none", "url": "a.b/"}, headers=H)
        assert r.status_code == 200 and r.get_json()["relaunched"] is True and r.get_json()["browser"]["kind"] == "iehost"
        assert len(launched.calls) == 2 and launched.calls[1]["url"] == "http://a.b/"

    def test_blank_url_opens_an_empty_page(self, client, H, recorder, win, launched):
        _start(client, H)
        launched.browsers[0].exit(0)
        r = client.post("/api/browser/open", json={}, headers=H)
        assert r.status_code == 200 and r.get_json()["relaunched"] is True and launched.calls[1]["url"] is None

    def test_without_recording_is_409(self, client, H, recorder, win, launched):
        r = client.post("/api/browser/open", json={}, headers=H)
        assert r.status_code == 409 and r.get_json()["error"] == "記録が開始されていません"
        assert launched.calls == []

    def test_unavailable_iehost_is_400_with_reason(self, client, H, recorder, win, launched, monkeypatch):
        _start(client, H)
        launched.browsers[0].exit(0)
        monkeypatch.setattr(routes_mod.iehost, "availability", lambda workdir, **kw: dict(UNAVAILABLE))
        r = client.post("/api/browser/open", json={}, headers=H)
        assert r.status_code == 400 and r.get_json()["error"] == UNAVAILABLE["reason"]
        assert len(launched.calls) == 1

    def test_relaunch_failure_is_500(self, client, H, recorder, win, launched, monkeypatch, events):
        _start(client, H)
        launched.browsers[0].exit(0)
        monkeypatch.setattr(routes_mod.iehost, "launch", LaunchSpy(events, fail=IEHostError("記録用ブラウザを起動できません: x")))
        r = client.post("/api/browser/open", json={}, headers=H)
        assert r.status_code == 500 and "記録用ブラウザ" in r.get_json()["error"]


# --------------------------------------------------------------------------- page / state

class TestPageAndState:
    def test_state_and_page_expose_availability(self, client, monkeypatch):
        monkeypatch.setattr(routes_mod, "mitmproxy_available", lambda: True)
        monkeypatch.setattr(routes_mod.iehost, "availability", lambda workdir, **kw: dict(AVAILABLE))
        monkeypatch.setattr(routes_mod.iehost, "get_emulation", lambda *a, **kw: 11000)
        st = client.get("/api/state").get_json()
        assert st["iehost"] == {"available": True, "reason": None, "exe": AVAILABLE["exe"], "built": True,
                                "shipped": None, "emulation": "ie11", "last_error": None}
        assert st["browser"] == {"kind": None, "running": False, "pid": None, "exit_code": None}
        html = client.get("/").get_data(as_text=True)
        assert 'data-iehost-available="true"' in html and 'data-iehost-reason=""' in html
        assert 'id="rec-unavailable"' not in html
        assert not _disabled_button(html, "easy-start") and not _disabled_button(html, "btn-rec-start")

    def test_page_carries_reason_when_unavailable(self, client, monkeypatch):
        monkeypatch.setattr(routes_mod, "mitmproxy_available", lambda: True)
        monkeypatch.setattr(routes_mod.iehost, "availability", lambda workdir, **kw: dict(UNAVAILABLE))
        html = client.get("/").get_data(as_text=True)
        assert 'data-iehost-available="false"' in html
        assert f'data-iehost-reason="{UNAVAILABLE["reason"]}"' in html
        # no fallback: both start buttons are disabled on the server and 1 記録 says why
        assert _disabled_button(html, "easy-start") and _disabled_button(html, "btn-rec-start")
        notice = html[html.index('id="rec-unavailable"'):]
        assert UNAVAILABLE["reason"] in notice[:notice.index("</div>")]
        st = client.get("/api/state").get_json()["iehost"]
        assert st["available"] is False and st["reason"] == UNAVAILABLE["reason"] and st["exe"] is None

    def test_start_buttons_need_mitmproxy_too(self, client, monkeypatch):
        monkeypatch.setattr(routes_mod, "mitmproxy_available", lambda: False)
        monkeypatch.setattr(routes_mod.iehost, "availability", lambda workdir, **kw: dict(AVAILABLE))
        html = client.get("/").get_data(as_text=True)
        assert _disabled_button(html, "easy-start") and _disabled_button(html, "btn-rec-start")
        assert 'data-mitm-available="false"' in html

    def test_page_has_the_new_record_controls(self, client):
        html = client.get("/").get_data(as_text=True)
        for marker in ('id="rec-emulation"', 'value="ie11_force"', 'id="rec-start-url"', 'id="rec-proxy-address"',
                       'id="rec-browser-state"',
                       'id="easy-browser-note"', 'accept=".har,.json"', "IEChooser.exe",
                       "表示モード (記録用ブラウザ)", "最初に開くアドレス", "開くサイトのアドレス"):
            assert marker in html, marker
        # the manual-proxy / system-proxy / certificate / https controls are gone
        for removed in ('id="rec-port"', 'id="rec-listen"', 'id="rec-sysproxy"', 'id="rec-browser"', 'id="rec-browser-hint"',
                        'id="rec-https-passthrough"', 'id="rec-instructions"', 'id="howto-proxy"', 'id="howto-chrome"',
                        'id="btn-win-cert"', 'id="btn-win-proxy-restore"', 'id="win-proxy-status"', 'id="win-cert-status"',
                        'id="easy-cert-note"', 'id="easy-manual-proxy"', 'value="iehost"', "/api/win/", "mitm.it",
                        "mitmproxy-ca-cert", "data-is-windows", "win-only", "howto-chrome", "記録方式", "自分でブラウザを設定する",
                        "ブラウザ側の手順", "https:// の通信は記録せず素通しする", "legacy_tls"):
            assert removed not in html, removed

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

    def test_status_reports_the_recording_browser(self, client, H, recorder, win, launched):
        assert _start(client, H).status_code == 200
        st = client.get("/api/record/status").get_json()
        assert st["browser"]["kind"] == "iehost" and "browser_kind" not in st
        state = client.get("/api/state").get_json()
        assert state["browser"]["kind"] == "iehost" and "record_browser_kind" not in state
        client.post("/api/record/stop", json={}, headers=H)
        assert client.get("/api/record/status").get_json()["browser"]["kind"] is None

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
        (workdir / "bin" / iehost.HASH_NAME).write_text(iehost._build_digest(), encoding="utf-8")
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
        from reqrec import validate_url

        assert validate_url(typed) == expected


class TestWaitUntilListening:
    def _manager(self, running=True):
        from reqrec import RecorderManager

        m = RecorderManager(command_builder=lambda *a, **k: ["x"])
        m.port = 18080
        m.out = "o.json"

        class Proc:
            pid = 1

            def poll(self):
                return None if running else 1

        m._proc = Proc()
        return m

    def test_returns_true_once_connectable_on_loopback(self):
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
        from reqrec import RecorderError

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
        body = {"hosts": [], "append": False}
        r = client.post("/api/record/start", json=body, headers=H)
        assert r.status_code == 200 and r.get_json()["emulation"] == "keep" and win == []

    def test_launch_failure_is_remembered_for_the_page(self, client, H, recorder, win, monkeypatch):
        from reqrec import IEHostError

        def blocked(*a, **kw):
            raise IEHostError("記録用ブラウザを起動できません: [WinError 1260] グループ ポリシーによってブロックされています")

        monkeypatch.setattr(routes_mod.iehost, "launch", blocked)
        r = _start(client, H)
        assert r.status_code == 500 and r.get_json()["kind"] == "iehost"
        assert "1260" in client.get("/api/state").get_json()["iehost"]["last_error"]


# =========================================================================== third review (error kinds, forget, origin)

def _assert_start_undone(client, recorder, events):
    """After a failed start: recorder stopped and forgotten, nothing reported as saved, stop is a 409."""
    assert recorder.running is False and recorder.out is None
    assert events[-2:] == ["recorder.stop", "recorder.forget"]
    st = client.get("/api/record/status").get_json()
    assert st["out"] is None and st["browser"]["kind"] is None and st["origin"] is None
    assert client.get("/api/state").get_json()["record_origin"] is None


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
        assert _start(client, H, append=True, origin="advanced").status_code == 200
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

        from reqrec import RecorderManager
        from reqrec import find_free_port

        cert_pem, key_pem, origin_der = _self_signed(tmp_path)
        plain = _serve()
        secure = _serve(tls=(cert_pem, key_pem))
        tls_port = secure.server_address[1]
        assert tls_port != 443
        manager = RecorderManager()
        out = tmp_path / "rec.json"
        proxy_port = find_free_port("127.0.0.1", preferred=18300, avoid=(8765,))
        try:
            manager.start(str(out), port=proxy_port, extra_args=routes_mod.HTTPS_PASSTHROUGH_ARGS)
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


# =========================================================================== platform helpers
# ``is_windows`` (core).  The Windows system proxy / CA certificate helpers of the former winsupport
# section are gone: the recording browser sets its own per-process proxy and tunnels https untouched.

def test_is_windows_matches_platform():
    assert is_windows() is IS_WINDOWS
    assert isinstance(is_windows(), bool)


def test_module_imports_without_winreg():
    import importlib.util

    # import a fresh copy of the whole reqrec.py instead of reloading the shared module (a reload would
    # replace every class the other tests hold): winreg is only ever imported lazily
    name = "reqrec_fresh_copy"
    spec = importlib.util.spec_from_file_location(name, routes_mod.__file__)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    assert "winreg" not in vars(module)


# ===== GUI password (REQREC_GUI_PASSWORD) and ``flask --app reqrec run`` =====
# A personal GUI on a LAN server (e.g. started from a JupyterLab terminal): with a password every page
# and API needs a login; without one only this PC may use the GUI.

PASSWORD = "pw-for-tests"


@pytest.fixture
def pw_app(workdir: Path):
    application = create_app(str(workdir), token="test-token-123", password=PASSWORD, TESTING=True, LOGIN_FAIL_DELAY=0)
    yield application
    application.extensions["reqrec"].close()


def _login(client, password=PASSWORD, origin="http://localhost", **kw):
    return client.post("/login", data={"password": password}, headers={"Origin": origin}, **kw)


class TestPassword:
    def test_without_login_the_page_redirects_and_the_api_is_401(self, pw_app):
        c = pw_app.test_client()
        r = c.get("/")
        assert r.status_code == 302 and r.headers["Location"].endswith("/login")
        r = c.get("/api/state")
        assert r.status_code == 401 and r.get_json()["login"] is True
        assert c.post("/api/recordings/clear", json={}, headers={TOKEN_HEADER: "test-token-123"}).status_code == 401
        assert c.get("/api/scripts/x.py/download").status_code == 401

    def test_login_page(self, pw_app):
        r = pw_app.test_client().get("/login")
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and 'type="password"' in html and 'action="/login"' in html
        assert "<script" not in html  # plain form: works in any browser engine
        # the GUI's no-referrer would make browsers send ``Origin: null`` with the form post (refused)
        assert r.headers["Referrer-Policy"] == "same-origin" and 'content="same-origin"' in html

    def test_wrong_then_right_password(self, pw_app):
        c = pw_app.test_client()
        r = _login(c, "nope")
        assert r.status_code == 401 and "パスワードが違います" in r.get_data(as_text=True)
        r = _login(c)
        assert r.status_code == 302 and r.headers["Location"].endswith("/")
        page = c.get("/")
        assert page.status_code == 200 and 'id="logout-link"' in page.get_data(as_text=True)
        assert c.get("/api/state").status_code == 200
        assert c.post("/api/recordings/clear", json={}, headers={TOKEN_HEADER: "test-token-123"}).status_code == 200
        assert c.get("/login").status_code == 302  # already logged in: back to the GUI

    def test_session_cookie(self, pw_app):
        cookie = _login(pw_app.test_client()).headers["Set-Cookie"]
        assert cookie.startswith("reqrec_session_") and "HttpOnly" in cookie and "SameSite=Strict" in cookie

    def test_token_and_origin_still_checked_after_login(self, pw_app):
        c = pw_app.test_client()
        _login(c)
        assert c.post("/api/recordings/clear", json={}).status_code == 403
        r = c.post("/api/recordings/clear", json={}, headers={TOKEN_HEADER: "test-token-123", "Origin": "http://evil.example"})
        assert r.status_code == 403

    def test_logout(self, pw_app):
        c = pw_app.test_client()
        _login(c)
        r = c.get("/logout")
        assert r.status_code == 302 and r.headers["Location"].endswith("/login")
        assert c.get("/api/state").status_code == 401

    def test_login_posted_from_another_site_is_refused(self, pw_app):
        c = pw_app.test_client()
        assert _login(c, origin="http://evil.example").status_code == 403
        assert _login(c, origin="null").status_code == 403
        assert c.get("/api/state").status_code == 401

    def test_lockout_after_wrong_passwords(self, pw_app):
        c = pw_app.test_client()
        for _ in range(4):
            assert _login(c, "nope").status_code == 401
        r = _login(c, "nope")
        assert r.status_code == 429 and "秒間ログインできません" in r.get_data(as_text=True)
        r = _login(c)  # even the right password has to wait until the lock ends
        assert r.status_code == 429 and c.get("/api/state").status_code == 401
        # the lock belongs to that address only
        r = _login(c, environ_base={"REMOTE_ADDR": "192.168.1.30"})
        assert r.status_code == 302

    def test_lock_ends(self, pw_app, monkeypatch):
        c = pw_app.test_client()
        now = [1000.0]
        monkeypatch.setattr(webapp.time, "time", lambda: now[0])
        for _ in range(5):
            _login(c, "nope")
        assert _login(c).status_code == 429
        now[0] += 61
        assert _login(c).status_code == 302

    def test_wrong_password_is_slowed_down(self, workdir, monkeypatch):
        sleeps = []
        monkeypatch.setattr(webapp.time, "sleep", sleeps.append)
        application = create_app(str(workdir), password=PASSWORD, TESTING=True)
        try:
            c = application.test_client()
            _login(c, "nope")
            assert sleeps == [1.0]
            _login(c)
            assert sleeps == [1.0]
        finally:
            application.extensions["reqrec"].close()

    def test_other_pcs_and_server_names_work_after_login(self, pw_app):
        c = pw_app.test_client()
        env = {"REMOTE_ADDR": "192.168.1.30"}
        r = c.post("/login", data={"password": PASSWORD}, environ_base=env,
                   headers={"Origin": "http://jupyter-srv:8765", "Host": "jupyter-srv:8765"})
        assert r.status_code == 302
        assert c.get("/api/state", headers={"Host": "jupyter-srv:8765"}, environ_base=env).status_code == 200

    def test_password_from_the_environment(self, workdir, monkeypatch):
        monkeypatch.setenv("REQREC_GUI_PASSWORD", "from-env")
        application = create_app(str(workdir), TESTING=True, LOGIN_FAIL_DELAY=0)
        try:
            c = application.test_client()
            assert c.get("/").status_code == 302
            assert _login(c, "from-env").status_code == 302
            assert application.config["REQREC_LOGIN_ENABLED"] is True
        finally:
            application.extensions["reqrec"].close()

    def test_the_page_goes_to_the_login_when_the_session_ends(self):
        js = APP_JS
        assert "if (resp.status === 401 && data.login) window.location.href = '/login';" in js


class TestWithoutPassword:
    def test_only_this_pc(self, client):
        env = {"REMOTE_ADDR": "192.168.1.30"}
        r = client.get("/", environ_base=env)
        assert r.status_code == 403 and "REQREC_GUI_PASSWORD" in r.get_data(as_text=True)
        r = client.get("/api/state", environ_base=env)
        assert r.status_code == 403 and "REQREC_GUI_PASSWORD" in r.get_json()["error"]
        assert client.get("/").status_code == 200
        assert client.get("/api/state", environ_base={"REMOTE_ADDR": "::1"}).status_code == 200
        assert client.get("/api/state", environ_base={"REMOTE_ADDR": "::ffff:127.0.0.1"}).status_code == 200

    def test_no_login_routes_and_no_logout_link(self, client):
        assert client.get("/login").status_code == 404 and client.get("/logout").status_code == 404
        assert 'id="logout-link"' not in client.get("/").get_data(as_text=True)

    def test_run_gui_refuses_the_lan_without_a_password(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr(flask.Flask, "run", lambda self, **kw: pytest.fail("server must not start"))
        rc = run_gui(host="0.0.0.0", port=_free_port(), workdir=str(tmp_path / "w"), open_browser=False)
        assert rc == 1 and "REQREC_GUI_PASSWORD" in capsys.readouterr().err
        assert not (tmp_path / "w").exists()

    def test_run_gui_on_the_lan_with_a_password(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("REQREC_GUI_PASSWORD", "x")
        calls = {}

        def fake_run(self, host, port, **kw):
            calls.update(host=host)
            raise KeyboardInterrupt

        monkeypatch.setattr(flask.Flask, "run", fake_run)
        rc = run_gui(host="0.0.0.0", port=_free_port(), workdir=str(tmp_path / "w"), open_browser=False)
        assert rc == 0 and calls == {"host": "0.0.0.0"}
        assert "パスワードが必要です" in capsys.readouterr().out


class TestFlaskCli:
    def test_flask_cli_finds_the_factory(self, tmp_path, monkeypatch, capsys):
        from flask.cli import ScriptInfo
        import atexit

        monkeypatch.setenv("REQREC_WORKDIR", str(tmp_path / "w"))
        registered = []
        monkeypatch.setattr(atexit, "register", lambda fn, *a, **k: registered.append((fn, a)))
        application = ScriptInfo(app_import_path="reqrec").load_app()  # what ``flask --app reqrec run`` does
        state = application.extensions["reqrec"]
        try:
            assert isinstance(application, flask.Flask)
            assert state.workdir == str(tmp_path / "w") and (tmp_path / "w" / "scripts").is_dir()
            assert registered == [(webapp._shutdown, (state,))]  # children stopped at exit
            err = capsys.readouterr().err
            assert "作業フォルダ" in err and "ログイン: なし" in err
            assert application.test_client().get("/").status_code == 200
        finally:
            state.close()

    def test_flask_cli_with_a_password(self, tmp_path, monkeypatch, capsys):
        from flask.cli import ScriptInfo
        import atexit

        monkeypatch.setenv("REQREC_WORKDIR", str(tmp_path / "w"))
        monkeypatch.setenv("REQREC_GUI_PASSWORD", "x")
        monkeypatch.setattr(atexit, "register", lambda fn, *a, **k: None)
        application = ScriptInfo(app_import_path="reqrec").load_app()
        try:
            assert "パスワードが必要です" in capsys.readouterr().err
            assert application.test_client().get("/").status_code == 302
        finally:
            application.extensions["reqrec"].close()

    def test_scripts_do_not_get_the_gui_password(self, tmp_path, monkeypatch):
        monkeypatch.setenv("REQREC_GUI_PASSWORD", "secret-gui")
        script = tmp_path / "env.py"
        script.write_text("import os\nprint(os.environ.get('REQREC_GUI_PASSWORD', 'absent'))\n", encoding="utf-8")
        runner = ScriptRunner()
        runner.start(str(script), {})
        assert runner.wait(30) == 0
        assert runner.status()["stdout_tail"].strip() == "absent"
