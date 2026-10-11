"""Tests for reqrec.recorder (mitmproxy addon + mitmdump launcher)."""

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

from reqrec.importers.mitm import MITMPROXY_INSTALL_HINT
from reqrec.model import Recording
from reqrec.recorder import run as run_mod
from reqrec.recorder.run import ADDON_PATH, MITMDUMP_PYTHON_STUB, build_command, format_instructions, run_record, stop_child

from reqrec.recorder.addon import DEFAULT_OUT, ReqRecAddon, addons, parse_hosts, write_recording_atomic

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

class TestParseHosts:
    @pytest.mark.parametrize("spec, expected", [
        (None, []),
        ("", []),
        ("  , ", []),
        ("example.com", ["example.com"]),
        ("Example.COM, api.example.com;foo.test", ["example.com", "api.example.com", "foo.test"]),
        ("a.com b.com\nc.com.", ["a.com", "b.com", "c.com"]),
        (["A.com", "a.com", "b.com,c.com"], ["a.com", "b.com", "c.com"]),
        (("x.test",), ["x.test"]),
    ])
    def test_parse(self, spec, expected):
        assert parse_hosts(spec) == expected


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
            assert tctx.options.reqrec_hosts == ""
            assert addon.output_path == os.path.abspath(DEFAULT_OUT)

    def test_configure_sets_output_and_hosts(self, tmp_path: Path):
        addon = ReqRecAddon()
        out = tmp_path / "rec.json"
        with taddons.context(addon) as tctx:
            tctx.configure(addon, reqrec_out=str(out), reqrec_hosts="Shop.example.test, api.example.test")
            assert addon.out == str(out)
            assert addon.output_path == str(out)
            assert addon.hosts == ["shop.example.test", "api.example.test"]

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
            assert rec.meta["source"] == "mitmproxy"
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

    def test_host_filtering_including_subdomains(self, tmp_path: Path):
        addon = ReqRecAddon()
        out = tmp_path / "rec.json"
        with taddons.context(addon) as tctx:
            tctx.configure(addon, reqrec_out=str(out), reqrec_hosts="example.test")
            addon.response(_http_flow("tracker.other.test", "/pixel"))
            assert not out.exists()  # nothing recorded -> nothing written yet
            addon.response(_http_flow("example.test", "/"))
            addon.response(_http_flow("API.example.test", "/v1/me"))
            addon.response(_http_flow("notexample.test", "/"))
            addon.response(_http_flow("example.test.evil.com", "/"))
            rec = Recording.load(str(out))
            assert [f.request.host for f in rec.flows] == ["example.test", "api.example.test"]
            assert rec.flows[1].request.url == "https://API.example.test/v1/me"  # URL kept as captured
            # widening the filter at runtime applies to later flows
            tctx.configure(addon, reqrec_hosts="")
            addon.response(_http_flow("anything.test", "/"))
            assert len(_read(out)["flows"]) == 3

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
        import reqrec.recorder.addon as addon_mod

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
        addon = ReqRecAddon(out=str(tmp_path / "direct.json"), hosts=["example.test"])
        addon.configure({"reqrec_out", "reqrec_hosts"})  # no options readable: constructor values stay
        assert addon.hosts == ["example.test"]
        assert addon.output_path == str(tmp_path / "direct.json")
        addon.response(_http_flow("example.test", "/x"))
        assert len(_read(tmp_path / "direct.json")["flows"]) == 1

    def test_non_default_options_override_constructor_values(self, tmp_path: Path):
        addon = ReqRecAddon(out=str(tmp_path / "ctor.json"), hosts=["ctor.test"])
        with taddons.context(addon) as tctx:
            tctx.configure(addon, reqrec_out=str(tmp_path / "opt.json"), reqrec_hosts="opt.test")
            assert addon.output_path == str(tmp_path / "opt.json")
            assert addon.hosts == ["opt.test"]
            tctx.configure(addon, reqrec_out=DEFAULT_OUT, reqrec_hosts="")  # back to defaults -> constructor values
            assert addon.output_path == str(tmp_path / "ctor.json")
            assert addon.hosts == ["ctor.test"]

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
        fullname = "__mitmproxy_script__.addon"
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
        assert module.__name__ == "__mitmproxy_script__.addon"
        assert len(module.addons) == 1
        addon = module.addons[0]
        assert type(addon).__name__ == "ReqRecAddon"
        addon.out = str(tmp_path / "script.json")
        addon.response(_http_flow("example.test", "/from-script"))
        rec = Recording.load(str(tmp_path / "script.json"))
        assert rec.flows[0].request.url == "https://example.test/from-script"

    def test_addon_path_points_to_the_module_file(self):
        import reqrec.recorder.addon as addon_mod

        assert ADDON_FILE.is_file()
        assert os.path.samefile(ADDON_PATH, addon_mod.__file__)


# =========================================================================== build_command

class TestBuildCommand:
    def test_prefers_mitmdump_executable(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(shutil, "which", lambda name: "/opt/venv/bin/mitmdump" if name == "mitmdump" else None)
        cmd = build_command(str(tmp_path / "rec.json"), port=8081, hosts=["Shop.example.test", "api.example.test"], listen_host="0.0.0.0", quiet=True)
        assert cmd[0] == "/opt/venv/bin/mitmdump"
        assert cmd[1:3] == ["-s", ADDON_PATH]
        assert cmd[3:5] == ["--set", f"reqrec_out={tmp_path / 'rec.json'}"]
        assert cmd[5:7] == ["--set", "reqrec_hosts=shop.example.test,api.example.test"]
        assert cmd[7:9] == ["-p", "8081"]
        assert cmd[9:11] == ["--listen-host", "0.0.0.0"]
        assert cmd[11:13] == ["--set", "flow_detail=0"]
        assert len(cmd) == 13

    def test_falls_back_to_python_entry_point(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(shutil, "which", lambda name: None)
        cmd = build_command(str(tmp_path / "rec.json"))
        assert cmd[:3] == [sys.executable, "-c", MITMDUMP_PYTHON_STUB]
        assert "mitmproxy.tools.main" in MITMDUMP_PYTHON_STUB and "mitmdump()" in MITMDUMP_PYTHON_STUB
        assert cmd[3:5] == ["-s", ADDON_PATH]
        assert "-p" in cmd and cmd[cmd.index("-p") + 1] == "8080"
        assert cmd[cmd.index("--listen-host") + 1] == "127.0.0.1"
        assert not any(a.startswith("reqrec_hosts=") for a in cmd)  # no hosts -> option omitted (= all)

    def test_hosts_as_string_quiet_false_and_extra_args(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/mitmdump")
        cmd = build_command("rec.json", port="9000", hosts="a.com, b.com", quiet=False, extra_args=["--ssl-insecure", "--set", "connection_strategy=lazy"])
        assert "reqrec_hosts=a.com,b.com" in cmd
        assert "flow_detail=0" not in cmd
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


class TestInstructions:
    def test_japanese_instructions_mention_everything(self):
        text = format_instructions("/tmp/out/rec.json", 8081, ["shop.example.test"], "127.0.0.1")
        assert "http://127.0.0.1:8081" in text
        assert "/tmp/out/rec.json" in text
        assert "shop.example.test" in text
        assert "mitmproxy-ca-cert.pem" in text
        assert "http://mitm.it" in text
        assert "Ctrl+C" in text
        assert "プロキシ" in text and "証明書" in text

    def test_wildcard_listen_host(self):
        text = format_instructions("rec.json", 8080, [], "0.0.0.0")
        assert "IPアドレス" in text
        assert "すべてのホスト" in text


# =========================================================================== run_record (fake child)

class _FakeProc:
    """Stand-in for subprocess.Popen whose wait() behaviour is scripted."""

    def __init__(self, script, on_start=None):
        self._script = list(script)  # each item: int return code, or an exception instance to raise
        self.signals: list = []
        self.terminated = False
        self.killed = False
        self.returncode = None
        if on_start:
            on_start()

    def wait(self, timeout=None):
        item = self._script.pop(0) if self._script else 0
        if isinstance(item, BaseException):
            raise item
        self.returncode = item
        return item

    def send_signal(self, sig):
        self.signals.append(sig)

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class TestRunRecord:
    def test_missing_mitmproxy_prints_hint_and_returns_1(self, monkeypatch, capsys, tmp_path: Path):
        monkeypatch.setattr(run_mod, "mitmproxy_available", lambda: False)
        rc = run_record(str(tmp_path / "rec.json"))
        assert rc == 1
        err = capsys.readouterr().err
        assert 'pip install "reqrec[record]"' in err
        assert MITMPROXY_INSTALL_HINT in err

    def test_popen_failure_returns_1(self, monkeypatch, capsys, tmp_path: Path):
        monkeypatch.setattr(run_mod, "mitmproxy_available", lambda: True)

        def fail(cmd):
            raise FileNotFoundError("mitmdump")

        monkeypatch.setattr(run_mod.subprocess, "Popen", fail)
        assert run_record(str(tmp_path / "rec.json")) == 1
        assert "mitmdump" in capsys.readouterr().err

    def test_ctrl_c_is_translated_to_graceful_stop(self, monkeypatch, capsys, tmp_path: Path):
        out = tmp_path / "deep" / "dir" / "rec.json"
        monkeypatch.setattr(run_mod, "mitmproxy_available", lambda: True)
        captured: dict = {}

        def fake_popen(cmd):
            captured["cmd"] = cmd

            def child_flushes():  # the addon writes the recording before the child exits
                Recording(meta={"source": "mitmproxy"}).save(str(out))

            proc = _FakeProc([KeyboardInterrupt(), 0], on_start=child_flushes)
            captured["proc"] = proc
            return proc

        monkeypatch.setattr(run_mod.subprocess, "Popen", fake_popen)
        rc = run_record(str(out), port=8090, hosts=["shop.example.test"], listen_host="127.0.0.1")
        assert rc == 0
        assert out.parent.is_dir()  # output directory created up front
        cmd = captured["cmd"]
        assert "-s" in cmd and ADDON_PATH in cmd
        assert f"reqrec_out={out}" in cmd
        assert "reqrec_hosts=shop.example.test" in cmd
        assert cmd[cmd.index("-p") + 1] == "8090"
        printed = capsys.readouterr().out
        assert "http://127.0.0.1:8090" in printed
        assert "Ctrl+C" in printed and "mitm.it" in printed and "mitmproxy-ca-cert.pem" in printed
        assert str(out) in printed
        assert "0 件" in printed  # summary after stop

    def test_ctrl_c_without_recording_file_returns_1(self, monkeypatch, capsys, tmp_path: Path):
        monkeypatch.setattr(run_mod, "mitmproxy_available", lambda: True)
        monkeypatch.setattr(run_mod.subprocess, "Popen", lambda cmd: _FakeProc([KeyboardInterrupt(), 0]))
        assert run_record(str(tmp_path / "never.json")) == 1
        assert "記録ファイル" in capsys.readouterr().err

    def test_child_exit_code_is_returned(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(run_mod, "mitmproxy_available", lambda: True)
        monkeypatch.setattr(run_mod.subprocess, "Popen", lambda cmd: _FakeProc([3]))
        assert run_record(str(tmp_path / "rec.json")) == 3
        monkeypatch.setattr(run_mod.subprocess, "Popen", lambda cmd: _FakeProc([0]))
        assert run_record(str(tmp_path / "rec.json")) == 0

    def test_hosts_none_and_string_accepted(self, monkeypatch, tmp_path: Path):
        monkeypatch.setattr(run_mod, "mitmproxy_available", lambda: True)
        seen = []
        monkeypatch.setattr(run_mod.subprocess, "Popen", lambda cmd: seen.append(cmd) or _FakeProc([0]))
        run_record(str(tmp_path / "a.json"), hosts=None)
        run_record(str(tmp_path / "b.json"), hosts="x.test,y.test")
        assert not any(a.startswith("reqrec_hosts=") for a in seen[0])
        assert "reqrec_hosts=x.test,y.test" in seen[1]


class TestStopChild:
    def test_child_already_exiting(self):
        proc = _FakeProc([0])
        assert stop_child(proc) == 0
        assert proc.signals == [] and not proc.terminated and not proc.killed

    def test_escalation_sigint_then_terminate_then_kill(self, monkeypatch):
        monkeypatch.setattr(run_mod, "_GRACE_FIRST_WAIT", 0.01)
        monkeypatch.setattr(run_mod, "_GRACE_AFTER_TERMINATE", 0.01)
        expired = subprocess.TimeoutExpired(cmd="mitmdump", timeout=0.01)
        proc = _FakeProc([expired, expired, expired, -9])
        assert stop_child(proc, grace=0.01) == -9
        if os.name != "nt":
            assert proc.signals == [signal.SIGINT]
        assert proc.terminated and proc.killed

    def test_sigint_is_enough(self, monkeypatch):
        monkeypatch.setattr(run_mod, "_GRACE_FIRST_WAIT", 0.01)
        expired = subprocess.TimeoutExpired(cmd="mitmdump", timeout=0.01)
        proc = _FakeProc([expired, 0])
        assert stop_child(proc, grace=0.01) == 0
        if os.name == "nt":  # Windows has no reliable Ctrl+C for a child: terminate() is the "SIGINT" step
            assert proc.terminated and not proc.killed
        else:
            assert proc.signals == [signal.SIGINT] and not proc.terminated and not proc.killed

    def test_second_ctrl_c_kills(self, monkeypatch):
        proc = _FakeProc([KeyboardInterrupt(), 137])
        assert stop_child(proc) == 137
        assert proc.killed


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
    """Spawn the exact command run_record uses, proxy one request through it, Ctrl+C it."""
    requests = pytest.importorskip("requests")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server_port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    proxy_port = _free_port()
    out = tmp_path / "live.json"
    cmd = build_command(str(out), port=proxy_port, hosts=["127.0.0.1"], listen_host="127.0.0.1", quiet=True)
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
    assert rec.meta["source"] == "mitmproxy" and rec.meta["hosts"] == ["127.0.0.1"]
