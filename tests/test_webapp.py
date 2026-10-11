"""Tests for the Flask GUI (reqrec.webapp), the RecorderManager and run_gui.  Contract: DESIGN.md §13.6."""

from __future__ import annotations

import errno
import io
import json
import os
import re
import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import flask
import pytest

from reqrec import webapp
from reqrec.importers import load_recording
from reqrec.model import PlanOptions
from reqrec.recorder.manager import RecorderError, RecorderManager, count_flows_in_file
from reqrec.webapp import TOKEN_HEADER, create_app, host_allowed, origin_allowed, run_gui
from reqrec.webapp import routes as routes_mod
from reqrec.webapp.state import (
    ApiError,
    AppState,
    ScriptRunner,
    exclude_netlocs,
    gen_options_from_json,
    normalise_netloc,
    plan_options_from_json,
    safe_name,
    sanitise_upload_name,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
LOGIN_HAR = FIXTURES / "login_flow_chrome.har"
API_HAR = FIXTURES / "api_firefox.har"

IS_WINDOWS = sys.platform == "win32"
not_on_windows = pytest.mark.skipif(IS_WINDOWS, reason="behaviour differs on Windows")


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
    from reqrec.model import Flow, Recording, RecordedRequest, RecordedResponse

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
    def builder(out, port=8080, hosts=None, listen_host="127.0.0.1", **_kw):
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
        assert 'src="/static/app.js' in html and 'href="/static/app.css' in html

    def test_static_files_served(self, client):
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/static/app.css").status_code == 200

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
        assert g.comments is False and g.legacy_tls is True and g.strict_status is True
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
        assert s["windows"]["is_windows"] == IS_WINDOWS
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

    def test_upload_rejects_unknown_extension(self, client, H):
        r = client.post("/api/recordings/upload", data={"files": (io.BytesIO(b"x"), "notes.txt")}, headers=H, content_type="multipart/form-data")
        assert r.status_code == 400 and "形式" in r.get_json()["error"]

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
        assert j["gen_options"]["legacy_tls"] is True
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


# =========================================================================== Windows endpoints

@not_on_windows
class TestWindowsEndpointsOffWindows:
    def test_status(self, client):
        j = client.get("/api/win/status").get_json()
        assert j["is_windows"] is False and j["proxy"] is None and j["cert"]["installed"] is None

    @pytest.mark.parametrize("path, body", [
        ("/api/win/proxy", {"enable": True, "server": "127.0.0.1:8080"}),
        ("/api/win/proxy/restore", {}),
        ("/api/win/cert/install", {}),
    ])
    def test_posts_are_400(self, client, H, path, body):
        r = client.post(path, json=body, headers=H)
        assert r.status_code == 400
        assert r.get_json()["error"] == "Windows 以外では使えません"

    def test_record_start_with_system_proxy_is_400(self, client, H, stub_script):
        state = client.application.extensions["reqrec"]
        state.recorder.command_builder = _stub_builder(stub_script)
        r = client.post("/api/record/start", json={"port": 18080, "set_system_proxy": True}, headers=H)
        assert r.status_code == 400 and r.get_json()["error"] == "Windows 以外では使えません"
        assert state.recorder.running is False

    def test_state_windows_block(self, client):
        w = client.get("/api/state").get_json()["windows"]
        assert w["is_windows"] is False and w["proxy_backup_active"] is False


# =========================================================================== RecorderManager

class TestRecorderManager:
    def test_start_status_flow_count_stop(self, tmp_path, stub_script):
        out = tmp_path / "recs" / "rec.json"
        m = RecorderManager(command_builder=_stub_builder(stub_script, n=4))
        assert m.running is False and m.status()["running"] is False and m.flow_count() == 0
        st = m.start(str(out), port=18080, hosts="example.test, b.test", listen_host="127.0.0.1")
        try:
            assert st["running"] is True and st["out"] == str(out) and st["pid"]
            assert st["hosts"] == ["example.test", "b.test"] and st["port"] == 18080
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
        import reqrec.recorder.manager as mgr

        old = mgr._GRACE_AFTER_TERMINATE
        mgr._GRACE_AFTER_TERMINATE = 0.5
        try:
            t0 = time.time()
            rc = m.stop()
        finally:
            mgr._GRACE_AFTER_TERMINATE = old
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
        p.write_text(json.dumps({"log": {"entries": [1, 2, 3]}}), encoding="utf-8")
        assert count_flows_in_file(str(p)) == 3

    def test_flow_count_keeps_last_good_value_while_file_broken(self, tmp_path):
        out = tmp_path / "r.json"
        m = RecorderManager(command_builder=lambda o, **kw: ["x"])
        m.out = str(out)
        out.write_text(json.dumps({"version": 1, "meta": {}, "flows": [{"id": "f0001"}]}), encoding="utf-8")
        assert m.flow_count() == 1
        out.write_text("{\"flows\": [{", encoding="utf-8")
        assert m.flow_count() == 1

    def test_default_command_builder_is_build_command(self):
        from reqrec.recorder.run import build_command

        assert RecorderManager().command_builder is build_command


# =========================================================================== recorder endpoints

class TestRecordEndpoints:
    @pytest.fixture
    def stubbed(self, client, H, stub_script):
        state = client.application.extensions["reqrec"]
        state.recorder.command_builder = _stub_builder(stub_script, n=3, self_url="http://localhost/api/record/status")
        yield state
        state.recorder.close()

    def test_full_cycle(self, client, H, stubbed, workdir):
        r = client.post("/api/record/start", json={"port": 18080, "hosts": "example.test", "listen_host": "127.0.0.1"}, headers=H)
        assert r.status_code == 200, r.get_json()
        j = r.get_json()
        assert re.match(r"rec_\d{8}_\d{6}\.json$", j["out"])
        assert "プロキシ" in j["instructions"] and "127.0.0.1:18080" in j["instructions"] and "example.test" in j["instructions"]
        assert j["proxy_address"] == "127.0.0.1:18080"
        assert j["status"]["running"] is True and j["system_proxy"] is None
        assert "localhost" in j["self_excluded_hosts"]
        # status polling: flows appear (3 + the GUI's own request)
        assert _wait_until(lambda: client.get("/api/record/status").get_json()["flows"] == 4, 15)
        st = client.get("/api/record/status").get_json()
        assert st["running"] is True and st["error"] is None and "stub" in st["stdout_tail"]
        assert client.get("/api/state").get_json()["recorder"]["running"] is True
        # a second start is refused
        r = client.post("/api/record/start", json={"port": 18081}, headers=H)
        assert r.status_code == 409
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
        client.post("/api/record/start", json={"port": 18080}, headers=H)
        assert _wait_until(lambda: client.get("/api/record/status").get_json()["flows"] == 4, 15)
        r = client.post("/api/record/stop", json={"append": True}, headers=H)
        assert r.status_code == 200 and r.get_json()["flows"] == 14 + 3

    def test_append_flag_from_start_is_remembered(self, client, H, stubbed, loaded):
        client.post("/api/record/start", json={"port": 18080, "append": True}, headers=H)
        assert _wait_until(lambda: client.get("/api/record/status").get_json()["flows"] == 4, 15)
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.get_json()["flows"] == 17

    def test_stop_without_start_409(self, client, H):
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 409

    def test_discard_with_the_real_recorder_forgets_the_file(self, client, H, stubbed, workdir):
        r = client.post("/api/record/start", json={"port": 18080}, headers=H)
        assert r.status_code == 200
        out = workdir / "recordings" / r.get_json()["out"]
        assert _wait_until(lambda: out.is_file(), 15)
        r = client.post("/api/record/stop", json={"discard": True}, headers=H)
        assert r.status_code == 200 and r.get_json()["removed"] is True and not out.exists()
        st = client.get("/api/record/status").get_json()
        assert st["out"] is None and st["running"] is False  # the panel shows 「停止中」, not 「記録は保存されました」
        assert client.post("/api/record/stop", json={}, headers=H).status_code == 409

    def test_start_validation(self, client, H, stubbed):
        assert client.post("/api/record/start", json={"port": "abc"}, headers=H).status_code == 400
        assert client.post("/api/record/start", json={"port": 0}, headers=H).status_code == 400
        assert client.post("/api/record/start", json={"hosts": 5}, headers=H).status_code == 400
        r = client.post("/api/record/start", json={"port": 8765}, headers=H)  # the GUI's own port
        assert r.status_code == 400 and "GUI" in r.get_json()["error"]
        assert stubbed.recorder.running is False

    def test_stop_with_empty_recording_is_400(self, client, H, stub_script):
        state = client.application.extensions["reqrec"]
        state.recorder.command_builder = _stub_builder(stub_script, n=0)
        client.post("/api/record/start", json={"port": 18080}, headers=H)
        assert _wait_until(lambda: "wrote 0 flows" in client.get("/api/record/status").get_json()["stdout_tail"], 15)
        r = client.post("/api/record/stop", json={}, headers=H)
        assert r.status_code == 400 and "何も記録されませんでした" in r.get_json()["error"] and r.get_json()["empty"] is True
        assert client.get("/api/state").get_json()["recording"]["loaded"] is False

    def test_stop_when_no_file_written_is_400(self, client, H):
        state = client.application.extensions["reqrec"]
        state.recorder.command_builder = lambda out, **kw: [sys.executable, "-c", "import time\ntime.sleep(30)"]
        client.post("/api/record/start", json={"port": 18080}, headers=H)
        r = client.post("/api/record/stop", json={}, headers=H)
        # no file at all = nothing was recorded (the addon writes after the first response only)
        assert r.status_code == 400 and "何も記録されませんでした" in r.get_json()["error"] and r.get_json()["empty"] is True
        assert client.get("/api/state").get_json()["recording"]["loaded"] is False

    def test_missing_mitmproxy_is_reported(self, client, H, monkeypatch):
        monkeypatch.setattr(routes_mod, "mitmproxy_available", lambda: False)
        r = client.post("/api/record/start", json={"port": 18080}, headers=H)
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
        from reqrec import cli

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
