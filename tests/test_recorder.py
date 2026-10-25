"""Tests for the recorder section of reqrec.py (mitmproxy addon + mitmdump launcher)."""

from __future__ import annotations

import http.server
import importlib.machinery
import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from reqrec import Recording
import reqrec as run_mod
from reqrec import ADDON_PATH, HTTPS_PASSTHROUGH_ARGS, MITMDUMP_PYTHON_STUB, RECORD_LISTEN_HOST, build_command

from reqrec import DEFAULT_OUT, ReqRecAddon, addons, write_recording_atomic

try:
    from mitmproxy.test import taddons, tflow

    HAVE_MITMPROXY = True
except ImportError:  # launcher / helper tests still run without mitmproxy
    HAVE_MITMPROXY = False

needs_mitmproxy = pytest.mark.skipif(not HAVE_MITMPROXY, reason="mitmproxy not installed")
ADDON_FILE = Path(ADDON_PATH)


def _http_flow(host: str, path: str = "/", ts: float | None = None, method: str = "GET", resp: bool = True):
    f = tflow.tflow(resp=resp)
    f.request.host = host
    f.request.port = 443
    f.request.scheme = "https"
    f.request.path = path
    f.request.method = method
    if ts is not None:
        f.request.timestamp_start = ts
    return f


def _read(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _no_temp_files(directory: Path) -> bool:
    return not [p for p in directory.iterdir() if p.name.startswith(".reqrec-")]


# =========================================================================== helpers

class TestWriteRecordingAtomic:
    def test_writes_valid_json_and_leaves_no_temp_files(self, tmp_path: Path):
        rec = Recording(meta={"source": "test"})
        out = tmp_path / "sub" / "rec.json"
        written = write_recording_atomic(rec, str(out))
        assert written == str(out)
        assert Recording.load(str(out)).meta == {"source": "test"}
        assert _no_temp_files(out.parent)

    def test_overwrites_existing_file(self, tmp_path: Path):
        out = tmp_path / "rec.json"
        out.write_text("garbage", encoding="utf-8")
        write_recording_atomic(Recording(meta={"n": 1}), str(out))
        write_recording_atomic(Recording(meta={"n": 2}), str(out))
        assert _read(out)["meta"] == {"n": 2}
        assert _no_temp_files(tmp_path)

    def test_failure_cleans_up_temp_file(self, tmp_path: Path, monkeypatch):
        def boom(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(os, "replace", boom)
        with pytest.raises(OSError):
            write_recording_atomic(Recording(), str(tmp_path / "rec.json"))
        assert _no_temp_files(tmp_path)
        assert not (tmp_path / "rec.json").exists()


# =========================================================================== addon through mitmproxy's option machinery

@needs_mitmproxy
class TestAddonWithMitmproxyContext:
    def test_module_level_addons_list(self):
        assert len(addons) == 1 and isinstance(addons[0], ReqRecAddon)

    def test_options_are_declared_with_defaults(self):
        addon = ReqRecAddon()
        with taddons.context(addon) as tctx:
            assert tctx.options.reqrec_out == DEFAULT_OUT
            assert "reqrec_hosts" not in tctx.options  # every host is recorded (filter removed 2026-10-25)
            assert addon.output_path == os.path.abspath(DEFAULT_OUT)

    def test_configure_sets_output(self, tmp_path: Path):
        addon = ReqRecAddon()
        out = tmp_path / "rec.json"
        with taddons.context(addon) as tctx:
            tctx.configure(addon, reqrec_out=str(out))
            assert addon.out == str(out)
            assert addon.output_path == str(out)

    def test_response_writes_valid_json_after_every_call(self, tmp_path: Path):
        addon = ReqRecAddon()
        out = tmp_path / "rec.json"
        with taddons.context(addon) as tctx:
            tctx.configure(addon, reqrec_out=str(out))
            assert not out.exists()
            for n in range(1, 4):
                addon.response(_http_flow("shop.example.test", f"/page{n}", ts=1000.0 + n))
                data = _read(out)  # valid JSON after each response
                assert data["version"] == 1
                assert len(data["flows"]) == n
                assert [f["id"] for f in data["flows"]] == [f"f{i:04d}" for i in range(1, n + 1)]
                assert _no_temp_files(tmp_path)
            rec = Recording.load(str(out))
            assert [f.request.url for f in rec.flows] == [f"https://shop.example.test/page{n}" for n in range(1, 4)]
            assert rec.flows[0].response.status == 200
            assert rec.flows[0].response.body == b"message"
            assert rec.meta["source"] == "mitmproxy" and "hosts" not in rec.meta
            assert rec.meta["flows_total"] == 3 and rec.meta["errors"] == 0
            assert rec.meta["started_at"] and rec.meta["updated_at"]
            assert addon.flush_count == 3

    def test_ids_follow_chronological_order_not_arrival(self, tmp_path: Path):
        addon = ReqRecAddon(out=str(tmp_path / "rec.json"))
        addon.response(_http_flow("a.test", "/late", ts=2000.0))
        addon.response(_http_flow("a.test", "/early", ts=1000.0))
        addon.response(_http_flow("a.test", "/middle", ts=1500.0))
        rec = Recording.load(addon.output_path)
        assert [(f.id, f.request.path) for f in rec.flows] == [("f0001", "/early"), ("f0002", "/middle"), ("f0003", "/late")]

    def test_every_host_is_recorded(self, tmp_path: Path):
        addon = ReqRecAddon()
        out = tmp_path / "rec.json"
        with taddons.context(addon) as tctx:
            tctx.configure(addon, reqrec_out=str(out))
            addon.response(_http_flow("example.test", "/"))
            addon.response(_http_flow("API.example.test", "/v1/me"))
            addon.response(_http_flow("tracker.other.test", "/pixel"))  # dropped later by the analysis, not here
            rec = Recording.load(str(out))
            assert [f.request.host for f in rec.flows] == ["example.test", "api.example.test", "tracker.other.test"]
            assert rec.flows[1].request.url == "https://API.example.test/v1/me"  # URL kept as captured

    def test_error_hook_records_request_without_response(self, tmp_path: Path):
        addon = ReqRecAddon(out=str(tmp_path / "rec.json"))
        failed = tflow.tflow(resp=False, err=True)
        failed.request.host = "down.example.test"
        addon.error(failed)
        data = _read(tmp_path / "rec.json")
        assert len(data["flows"]) == 1
        assert data["flows"][0]["response"] is None
        assert data["flows"][0]["request"]["url"].startswith("http://down.example.test")
        assert data["meta"]["errors"] == 1
        assert addon.errors == 1

    def test_same_flow_not_recorded_twice(self, tmp_path: Path):
        addon = ReqRecAddon(out=str(tmp_path / "rec.json"))
        f = _http_flow("example.test", "/once")
        addon.response(f)
        addon.error(f)  # late error after the response was already delivered
        addon.response(f)
        assert len(_read(tmp_path / "rec.json")["flows"]) == 1
        assert len(addon) == 1

    def test_non_http_flows_ignored(self, tmp_path: Path):
        addon = ReqRecAddon(out=str(tmp_path / "rec.json"))
        addon.response(tflow.ttcpflow())
        addon.error(tflow.tudpflow())
        addon.response(object())
        assert not (tmp_path / "rec.json").exists()
        assert not addon.wants(tflow.ttcpflow())
        assert addon.wants(_http_flow("x.test"))

    def test_done_flushes_even_with_nothing_recorded(self, tmp_path: Path):
        addon = ReqRecAddon()
        out = tmp_path / "empty.json"
        with taddons.context(addon) as tctx:
            tctx.configure(addon, reqrec_out=str(out))
            addon.done()
        rec = Recording.load(str(out))
        assert rec.flows == []
        assert rec.meta["source"] == "mitmproxy"
        assert _no_temp_files(tmp_path)

    def test_done_after_responses_keeps_everything(self, tmp_path: Path):
        addon = ReqRecAddon(out=str(tmp_path / "rec.json"))
        addon.response(_http_flow("example.test", "/a"))
        addon.response(_http_flow("example.test", "/b"))
        addon.done()
        assert len(Recording.load(addon.output_path).flows) == 2

    def test_write_failure_does_not_raise_from_hook(self, tmp_path: Path, monkeypatch):
        addon = ReqRecAddon(out=str(tmp_path / "rec.json"))
        import reqrec as addon_mod

        def boom(*a, **k):
            raise OSError("read-only file system")

        monkeypatch.setattr(addon_mod, "write_recording_atomic", boom)
        addon.response(_http_flow("example.test", "/"))  # must not raise
        assert addon.last_flush_error and "read-only" in addon.last_flush_error
        addon.done()  # must not raise either
        assert len(addon) == 1

    def test_programmatic_use_without_mitmproxy_options(self, tmp_path: Path, monkeypatch):
        from mitmproxy import ctx

        # Simulate plain-Python use: no mitmproxy master is running (taddons leaves a stale global ctx).
        monkeypatch.delattr(ctx, "options", raising=False)
        monkeypatch.delattr(ctx, "master", raising=False)
        addon = ReqRecAddon(out=str(tmp_path / "direct.json"))
        addon.configure({"reqrec_out"})  # no options readable: the constructor value stays
        assert addon.output_path == str(tmp_path / "direct.json")
        addon.response(_http_flow("example.test", "/x"))
        assert len(_read(tmp_path / "direct.json")["flows"]) == 1

    def test_non_default_option_overrides_constructor_value(self, tmp_path: Path):
        addon = ReqRecAddon(out=str(tmp_path / "ctor.json"))
        with taddons.context(addon) as tctx:
            tctx.configure(addon, reqrec_out=str(tmp_path / "opt.json"))
            assert addon.output_path == str(tmp_path / "opt.json")
            tctx.configure(addon, reqrec_out=DEFAULT_OUT)  # back to the default -> constructor value
            assert addon.output_path == str(tmp_path / "ctor.json")

    def test_recording_snapshot_is_valid_recording(self, tmp_path: Path):
        addon = ReqRecAddon(out=str(tmp_path / "rec.json"))
        addon.response(_http_flow("example.test", "/x", ts=5.0))
        rec = addon.recording()
        assert isinstance(rec, Recording) and rec.flows[0].id == "f0001"
        assert Recording.from_json(rec.to_json()).to_dict() == rec.to_dict()


# =========================================================================== script mode

@needs_mitmproxy
class TestScriptMode:
    def _load_as_mitmproxy_script(self):
        """Mimic mitmproxy's Script addon: exec the file under a dotted name with no parent package."""
        fullname = "__mitmproxy_script__.reqrec"
        sys.modules.pop(fullname, None)
        old_path = list(sys.path)
        sys.path.insert(0, str(ADDON_FILE.parent))
        try:
            loader = importlib.machinery.SourceFileLoader(fullname, str(ADDON_FILE))
            spec = importlib.util.spec_from_loader(fullname, loader=loader)
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            return module
        finally:
            sys.path[:] = old_path
            sys.modules.pop(fullname, None)

    def test_file_loads_without_package_context(self, tmp_path: Path):
        module = self._load_as_mitmproxy_script()
        assert module.__name__ == "__mitmproxy_script__.reqrec"
        assert len(module.addons) == 1
        addon = module.addons[0]
        assert type(addon).__name__ == "ReqRecAddon"
        addon.out = str(tmp_path / "script.json")
        addon.response(_http_flow("example.test", "/from-script"))
        rec = Recording.load(str(tmp_path / "script.json"))
        assert rec.flows[0].request.url == "https://example.test/from-script"
        # mitmproxy registers the script module itself as an addon too and calls every attribute
        # named like an event hook, so no top-level name of reqrec.py may be a hook name (Flask's
        # ``request`` proxy is imported as ``flask_request`` for this reason).
        import mitmproxy.addons  # noqa: F401 - every hook is registered once mitmproxy's addons are imported
        import mitmproxy.eventsequence  # noqa: F401
        from mitmproxy import hooks

        assert {"request", "response", "error", "load", "running", "done"} <= set(hooks.all_hooks)
        assert sorted(name for name in hooks.all_hooks if hasattr(module, name)) == []

    def test_addon_path_points_to_the_module_file(self):
        import reqrec as addon_mod

        assert ADDON_FILE.is_file()
        assert os.path.samefile(ADDON_PATH, addon_mod.__file__)


# =========================================================================== build_command

class TestBuildCommand:
    def test_prefers_mitmdump_executable(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(shutil, "which", lambda name: "/opt/venv/bin/mitmdump" if name == "mitmdump" else None)
        cmd = build_command(str(tmp_path / "rec.json"), port=8081)
        assert cmd[0] == "/opt/venv/bin/mitmdump"
        assert cmd[1:3] == ["-s", ADDON_PATH]
        assert cmd[3:5] == ["--set", f"reqrec_out={tmp_path / 'rec.json'}"]
        assert cmd[5:7] == ["-p", "8081"]
        assert cmd[7:9] == ["--listen-host", "127.0.0.1"]
        assert cmd[9:11] == ["--set", "flow_detail=0"]
        assert len(cmd) == 11
        assert not any(a.startswith("reqrec_hosts=") for a in cmd)  # every host is recorded

    def test_proxy_only_ever_listens_on_this_pc(self, monkeypatch):
        """The recording proxy's only client is the recording browser on this PC: no listen-host knob."""
        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/mitmdump")
        assert RECORD_LISTEN_HOST == "127.0.0.1"
        cmd = build_command("rec.json", port=8090, extra_args=list(HTTPS_PASSTHROUGH_ARGS))
        assert cmd.count("--listen-host") == 1 and cmd[cmd.index("--listen-host") + 1] == "127.0.0.1"
        assert cmd[-2:] == ["--ignore-hosts", ".*"]  # the GUI's always-on https:// pass-through
        with pytest.raises(TypeError):
            build_command("rec.json", listen_host="0.0.0.0")
        with pytest.raises(TypeError):
            build_command("rec.json", hosts=["a.test"])  # the host filter was removed (2026-10-25)

    def test_falls_back_to_python_entry_point(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(shutil, "which", lambda name: None)
        cmd = build_command(str(tmp_path / "rec.json"))
        assert cmd[:3] == [sys.executable, "-c", MITMDUMP_PYTHON_STUB]
        assert "mitmproxy.tools.main" in MITMDUMP_PYTHON_STUB and "mitmdump()" in MITMDUMP_PYTHON_STUB
        assert cmd[3:5] == ["-s", ADDON_PATH]
        assert "-p" in cmd and cmd[cmd.index("-p") + 1] == "8080"
        assert cmd[cmd.index("--listen-host") + 1] == "127.0.0.1"

    def test_extra_args(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/mitmdump")
        cmd = build_command("rec.json", port="9000", extra_args=["--ssl-insecure", "--set", "connection_strategy=lazy"])
        assert cmd[cmd.index("flow_detail=0") - 1] == "--set"  # mitmdump's own per-flow dump is always off
        assert cmd[-3:] == ["--ssl-insecure", "--set", "connection_strategy=lazy"]
        assert cmd[cmd.index("-p") + 1] == "9000"
        assert os.path.isabs(cmd[cmd.index("--set") + 1].split("=", 1)[1])  # out made absolute

    @needs_mitmproxy
    def test_real_environment_launcher_runs(self):
        """Whatever launcher this environment resolves to must actually start mitmdump."""
        launcher = run_mod.mitmdump_launcher()
        proc = subprocess.run(launcher + ["--version"], capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0
        assert "Mitmproxy" in proc.stdout


# =========================================================================== real mitmdump end-to-end

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = "<html><head><title>hi</title></head><body>こんにちは</body></html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sid=abc123; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep pytest output clean
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, proc: subprocess.Popen, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"mitmdump exited early with {proc.returncode}: {proc.stdout.read()}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("proxy port never opened")


@needs_mitmproxy
@pytest.mark.skipif(os.name == "nt", reason="SIGINT handling differs on Windows")
def test_real_mitmdump_records_proxied_request(tmp_path: Path):
    """Spawn the command RecorderManager uses (with the GUI's always-on https:// pass-through),
    proxy one plain http:// request through it, Ctrl+C it."""
    requests = pytest.importorskip("requests")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server_port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    proxy_port = _free_port()
    out = tmp_path / "live.json"
    cmd = build_command(str(out), port=proxy_port, extra_args=list(HTTPS_PASSTHROUGH_ARGS))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        _wait_for_port(proxy_port, proc)
        session = requests.Session()
        session.trust_env = False  # ignore the sandbox's HTTPS_PROXY etc.
        resp = session.get(
            f"http://127.0.0.1:{server_port}/hello?x=1",
            proxies={"http": f"http://127.0.0.1:{proxy_port}"},
            timeout=15,
        )
        assert resp.status_code == 200
        deadline = time.time() + 10
        while time.time() < deadline and not out.exists():
            time.sleep(0.1)
        assert out.exists(), "addon should flush right after the response"
        proc.send_signal(signal.SIGINT)
        rc = proc.wait(timeout=30)
        output = proc.stdout.read()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        server.shutdown()
        server.server_close()
    assert rc == 0, output
    assert "[reqrec] #0001 GET" in output
    rec = Recording.load(str(out))
    assert len(rec.flows) == 1
    flow = rec.flows[0]
    assert flow.request.url == f"http://127.0.0.1:{server_port}/hello?x=1"
    assert flow.request.body is None
    assert flow.response.status == 200
    assert flow.response.mime_type == "text/html"
    assert "こんにちは" in flow.response.text()
    assert flow.response.set_cookies == ["sid=abc123; Path=/"]
    assert rec.meta["source"] == "mitmproxy" and "hosts" not in rec.meta
