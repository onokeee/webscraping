"""Tests for the iehost section of reqrec.py (namespace ``reqrec.iehost``) with fake csc / popen /
taskkill / winreg (pure logic, runs on every OS).  Contract: DESIGN.md §13.12.  Nothing here compiles,
starts a process or touches the registry."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest

import reqrec
from reqrec import BrowserProcess, IEHostError, iehost

# the former module's names, taken from the ``iehost`` namespace (the functions look each other up
# through ``iehost.``, so monkeypatching ``iehost.<name>`` still reaches them)
EMULATION_LEVELS = iehost.EMULATION_LEVELS
EXE_NAME = iehost.EXE_NAME
FEATURE_BROWSER_EMULATION_KEY = iehost.FEATURE_BROWSER_EMULATION_KEY
HASH_NAME = iehost.HASH_NAME
availability = iehost.availability
build_command = iehost.build_command
csc_path = iehost.csc_path
ensure_built = iehost.ensure_built
exe_path = iehost.exe_path
get_emulation = iehost.get_emulation
launch = iehost.launch
resolve_emulation = iehost.resolve_emulation
set_emulation = iehost.set_emulation

CSC64 = os.path.join(r"C:\Windows", "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe")
CSC32 = os.path.join(r"C:\Windows", "Microsoft.NET", "Framework", "v4.0.30319", "csc.exe")
ENV = {"WINDIR": r"C:\Windows"}


# --------------------------------------------------------------------------- fakes

def exists_for(*paths):
    """A fake ``os.path.isfile`` that knows only the given paths (case-insensitive like Windows)."""
    known = {os.path.normcase(p) for p in paths}
    return lambda p: os.path.normcase(p) in known


class FakeRun:
    """Stands in for ``subprocess.run``: records calls; optionally writes the exe / fails / raises."""

    def __init__(self, returncode=0, stdout="", stderr="", raises=None, write_exe=True):
        self.calls = []
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.raises = raises
        self.write_exe = write_exe

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))
        if self.raises is not None:
            raise self.raises
        if self.write_exe and self.returncode == 0 and cmd and cmd[0] != "taskkill":
            out = [a for a in cmd if a.startswith("-out:")]
            if out:
                with open(out[0][len("-out:"):], "wb") as fh:
                    fh.write(b"MZ fake exe")
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


class FakeProc:
    """A ``Popen`` double that dies at a chosen step: ``"taskkill"``, ``"terminate"``, ``"kill"`` or never."""

    def __init__(self, pid=4321, dies_on="taskkill", exit_code=0):
        self.pid = pid
        self.dies_on = dies_on
        self.exit_code = exit_code
        self.returncode = None
        self.events = []
        self.waits = []

    def _die(self, step):
        if self.dies_on == step:
            self.returncode = self.exit_code

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.returncode is None:
            raise subprocess.TimeoutExpired("RecBrowser.exe", timeout)
        return self.returncode

    def terminate(self):
        self.events.append("terminate")
        self._die("terminate")

    def kill(self):
        self.events.append("kill")
        self._die("kill")


def taskkill_run(proc: FakeProc, log: list, raises=None):
    """A fake ``run`` for ``taskkill`` that lets ``proc`` die when it was told to die on taskkill."""

    def run(cmd, **kwargs):
        log.append((list(cmd), kwargs))
        if raises is not None:
            raise raises
        proc.events.append("taskkill")
        proc._die("taskkill")
        return subprocess.CompletedProcess(cmd, 0, "SUCCESS", "")

    return run


class FakePopen:
    def __init__(self, raises=None, pid=777):
        self.calls = []
        self.raises = raises
        self.pid = pid
        self.proc = None

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if self.raises is not None:
            raise self.raises
        self.proc = FakeProc(pid=self.pid, dies_on="taskkill")
        return self.proc


class FakeKey:
    def __init__(self, reg, path, write):
        self.reg = reg
        self.path = path
        self.write = write

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.reg.closed += 1
        return False


class FakeWinreg:
    """Just enough of ``winreg`` for the FEATURE_BROWSER_EMULATION key: ``keys`` maps path -> {name: (value, type)}."""

    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 0x20019
    KEY_SET_VALUE = 0x0002
    REG_DWORD = 4

    def __init__(self, keys=None):
        self.keys = {path: dict(values) for path, values in (keys or {}).items()}
        self.opened = []
        self.created = []
        self.closed = 0
        self.writes = []
        self.deletes = []
        self.queries = []

    def OpenKey(self, hive, path, reserved, access):
        assert hive == self.HKEY_CURRENT_USER
        assert reserved == 0
        self.opened.append((path, access))
        if path not in self.keys:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return FakeKey(self, path, bool(access & self.KEY_SET_VALUE))

    def CreateKeyEx(self, hive, path, reserved, access):
        assert hive == self.HKEY_CURRENT_USER
        assert reserved == 0
        self.created.append((path, access))
        self.keys.setdefault(path, {})
        return FakeKey(self, path, bool(access & self.KEY_SET_VALUE))

    def QueryValueEx(self, key, name):
        self.queries.append((key.path, name))
        values = self.keys[key.path]
        if name not in values:
            raise FileNotFoundError(2, "no such value")
        return values[name]

    def SetValueEx(self, key, name, reserved, type_, value):
        assert key.write, "SetValueEx on a read-only key"
        assert reserved == 0
        self.keys[key.path][name] = (value, type_)
        self.writes.append((key.path, name, value, type_))

    def DeleteValue(self, key, name):
        assert key.write, "DeleteValue on a read-only key"
        values = self.keys[key.path]
        if name not in values:
            raise FileNotFoundError(2, "no such value")
        del values[name]
        self.deletes.append((key.path, name))


@pytest.fixture
def fake_source(tmp_path, monkeypatch):
    """A stand-in for the embedded C# source ``RECBROWSER_CS`` (the real one must not be compiled here),
    as text.  The distribution folder of a prebuilt exe (``iehost.SHIPPED_DIR``, next to reqrec.py) is
    redirected to an empty temporary folder, so a real prebuilt exe never takes part."""
    src_dir = tmp_path / "pkg"
    src_dir.mkdir()
    monkeypatch.setattr(iehost, "SHIPPED_DIR", str(src_dir))
    return "// fake C# source v1\nclass P { static void Main() {} }\n"


@pytest.fixture
def workdir(tmp_path):
    wd = tmp_path / "work"
    wd.mkdir()
    return str(wd)


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# --------------------------------------------------------------------------- constants / import

def test_constants():
    assert EXE_NAME == "RecBrowser.exe"
    assert iehost.SOURCE_NAME == "RecBrowser.cs"  # RECBROWSER_CS is written under this name for csc
    assert iehost.SHIPPED_DIR == os.path.dirname(os.path.abspath(reqrec.__file__))  # prebuilt exe: next to reqrec.py
    assert reqrec.RECBROWSER_CS.startswith("// RecBrowser.cs") and "\r" not in reqrec.RECBROWSER_CS
    assert HASH_NAME == "RecBrowser.cs.sha256"
    assert EMULATION_LEVELS == {"default": None, "ie8": 8000, "ie11": 11000, "ie11_force": 11001}
    assert FEATURE_BROWSER_EMULATION_KEY.endswith(r"FeatureControl\FEATURE_BROWSER_EMULATION")
    assert issubclass(IEHostError, RuntimeError)


def test_module_does_not_depend_on_source_or_winreg_at_import():
    """reqrec imports on any OS without any RecBrowser.cs file (the source is a string constant)."""
    assert iehost.EXE_NAME == "RecBrowser.exe"
    assert "winreg" not in iehost.__dict__ and "winreg" not in vars(reqrec)  # imported lazily inside _winreg()
    public = [name for name in vars(iehost) if not name.startswith("_")]
    assert all(callable(getattr(iehost, name)) or name.isupper() for name in public)


def test_exe_path_is_under_bin(workdir):
    assert exe_path(workdir) == os.path.join(workdir, "bin", "RecBrowser.exe")


# --------------------------------------------------------------------------- csc discovery

class TestCscPath:
    def test_prefers_framework64(self):
        assert csc_path(exists=exists_for(CSC64, CSC32), env=ENV) == CSC64

    def test_falls_back_to_32bit_framework(self):
        assert csc_path(exists=exists_for(CSC32), env=ENV) == CSC32

    def test_none_when_missing(self):
        assert csc_path(exists=lambda p: False, env=ENV) is None

    def test_uses_windir_from_env(self):
        env = {"WINDIR": r"D:\Win"}
        expected = os.path.join(r"D:\Win", "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe")
        assert csc_path(exists=exists_for(expected), env=env) == expected

    def test_systemroot_fallback_and_default(self):
        expected = os.path.join(r"E:\Sys", "Microsoft.NET", "Framework", "v4.0.30319", "csc.exe")
        assert csc_path(exists=exists_for(expected), env={"SystemRoot": r"E:\Sys"}) == expected
        assert csc_path(exists=exists_for(CSC64), env={}) == CSC64  # C:\Windows default


# --------------------------------------------------------------------------- availability

class TestAvailability:
    def test_non_windows_platform_is_unavailable_with_japanese_reason(self, workdir):
        info = availability(workdir, platform="linux", exists=exists_for(CSC64), env=ENV)
        assert info["available"] is False
        assert info["exe"] is None
        assert info["built"] is False
        assert info["reason"] and "Windows" in info["reason"]
        assert any(ord(ch) > 0x7F for ch in info["reason"])  # Japanese text
        assert availability(workdir, platform="darwin", exists=lambda p: True)["available"] is False

    def test_windows_with_csc_and_source(self, workdir, fake_source):
        info = availability(workdir, platform="win32", exists=exists_for(CSC64), env=ENV, source=fake_source)
        assert info["available"] is True
        assert info["reason"] is None
        assert info["exe"] == exe_path(workdir)
        assert info["built"] is False
        assert info["csc"] == CSC64
        assert info["prebuilt"] is None

    def test_built_exe_reported(self, workdir, fake_source):
        exe = exe_path(workdir)
        info = availability(workdir, platform="win32", exists=exists_for(CSC64, exe), env=ENV, source=fake_source)
        assert info["available"] is True
        assert info["built"] is True
        assert info["exe"] == exe

    def test_no_csc_but_prebuilt_next_to_source(self, workdir, fake_source):
        prebuilt = os.path.join(iehost.SHIPPED_DIR, EXE_NAME)
        info = availability(workdir, platform="win32", exists=exists_for(prebuilt), env=ENV, source=fake_source)
        assert info["available"] is True
        assert info["csc"] is None
        assert info["prebuilt"] == prebuilt

    def test_no_csc_no_prebuilt(self, workdir, fake_source):
        info = availability(workdir, platform="win32", exists=exists_for(), env=ENV, source=fake_source)
        assert info["available"] is False
        assert info["exe"] is None
        assert "csc.exe" in info["reason"]
        assert any(ord(ch) > 0x7F for ch in info["reason"])

    def test_csc_but_source_missing(self, workdir, tmp_path):
        # no RecBrowser.cs file exists anywhere: the C# source is part of reqrec.py (RECBROWSER_CS), so
        # csc alone is enough; ``source`` reports where it will be written for the compiler
        info = availability(workdir, platform="win32", exists=exists_for(CSC64), env=ENV, folder=str(tmp_path / "nowhere"))
        assert info["available"] is True
        assert info["reason"] is None and info["exe"] == exe_path(workdir)
        assert info["source"] == os.path.join(workdir, "bin", "RecBrowser.cs")

    def test_default_platform_is_sys_platform(self, workdir):
        info = availability(workdir, exists=lambda p: False, env=ENV)
        if sys.platform == "win32":
            assert info["reason"] == iehost._NO_CSC_MESSAGE
        else:
            assert "Windows" in info["reason"]


# --------------------------------------------------------------------------- build command

class TestBuildCommand:
    def test_exact_argv(self):
        cmd = build_command(CSC64, r"C:\src\RecBrowser.cs", r"C:\work\bin\RecBrowser.exe")
        assert cmd[0] == CSC64
        assert cmd[-1] == r"C:\src\RecBrowser.cs"
        assert "-nologo" in cmd
        assert "-target:winexe" in cmd
        assert "-platform:x86" in cmd  # always 32-bit: 32-bit ActiveX controls of legacy pages must load
        assert r"-out:C:\work\bin\RecBrowser.exe" in cmd
        assert "-r:System.Windows.Forms.dll" in cmd
        assert "-r:System.Drawing.dll" in cmd
        assert all(not a.startswith("/") for a in cmd[1:-1]), "use - flags (Git Bash mangles /flags)"
        assert "-target:exe" not in cmd  # a console window must never flash

    def test_returns_fresh_list(self):
        a = build_command("csc", "s.cs", "o.exe")
        b = build_command("csc", "s.cs", "o.exe")
        assert a == b and a is not b


# --------------------------------------------------------------------------- ensure_built

class TestEnsureBuilt:
    def test_compiles_and_writes_hash(self, workdir, fake_source):
        run = FakeRun()
        exe = ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        assert exe == exe_path(workdir)
        assert os.path.isfile(exe)
        assert len(run.calls) == 1
        cmd, kwargs = run.calls[0]
        written = os.path.join(workdir, "bin", "RecBrowser.cs")  # the source as csc reads it
        assert cmd == build_command(CSC64, written, exe)
        assert open(written, "rb").read() == fake_source.encode("utf-8")
        assert kwargs["capture_output"] is True and kwargs["text"] is True
        assert kwargs["timeout"] > 0
        hash_file = os.path.join(workdir, "bin", HASH_NAME)
        assert open(hash_file, encoding="utf-8").read().strip() == iehost._build_digest(fake_source)

    def test_second_call_does_not_rebuild(self, workdir, fake_source):
        run = FakeRun()
        ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        assert len(run.calls) == 1

    def test_changed_source_rebuilds(self, workdir, fake_source):
        run = FakeRun()
        ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        changed = fake_source + "// v2\n"  # a new reqrec version
        ensure_built(workdir, run=run, csc=CSC64, source=changed)
        assert len(run.calls) == 2
        hash_file = os.path.join(workdir, "bin", HASH_NAME)
        assert open(hash_file, encoding="utf-8").read().strip() == iehost._build_digest(changed)

    def test_missing_hash_file_rebuilds(self, workdir, fake_source):
        run = FakeRun()
        ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        os.remove(os.path.join(workdir, "bin", HASH_NAME))
        ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        assert len(run.calls) == 2

    def test_force_rebuilds(self, workdir, fake_source):
        run = FakeRun()
        ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        ensure_built(workdir, run=run, csc=CSC64, source=fake_source, force=True)
        assert len(run.calls) == 2

    def test_compiler_error_raises_with_output(self, workdir, fake_source):
        run = FakeRun(returncode=1, stdout="RecBrowser.cs(12,3): error CS1002: ; expected", write_exe=False)
        with pytest.raises(IEHostError) as info:
            ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        msg = str(info.value)
        assert "error CS1002" in msg
        assert msg.startswith("記録用ブラウザ")
        assert not os.path.exists(os.path.join(workdir, "bin", HASH_NAME))

    def test_zero_exit_without_exe_is_failure(self, workdir, fake_source):
        run = FakeRun(returncode=0, write_exe=False)
        with pytest.raises(IEHostError):
            ensure_built(workdir, run=run, csc=CSC64, source=fake_source)

    def test_failure_on_rebuild_hints_at_open_browser(self, workdir, fake_source):
        ensure_built(workdir, run=FakeRun(), csc=CSC64, source=fake_source)
        run = FakeRun(returncode=1, stderr="error CS2012: Cannot open RecBrowser.exe for writing", write_exe=False)
        with pytest.raises(IEHostError) as info:
            ensure_built(workdir, run=run, csc=CSC64, source=fake_source + "// v2\n")
        assert "閉じて" in str(info.value)
        assert "CS2012" in str(info.value)

    def test_run_raising_file_not_found(self, workdir, fake_source):
        run = FakeRun(raises=FileNotFoundError(2, "csc.exe"))
        with pytest.raises(IEHostError) as info:
            ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        assert CSC64 in str(info.value)

    def test_run_timeout(self, workdir, fake_source):
        run = FakeRun(raises=subprocess.TimeoutExpired("csc", 120))
        with pytest.raises(IEHostError) as info:
            ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        assert "タイムアウト" in str(info.value)

    def test_no_csc_and_no_prebuilt_raises(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(iehost, "csc_path", lambda *a, **k: None)
        run = FakeRun()
        with pytest.raises(IEHostError) as info:
            ensure_built(workdir, run=run, source=fake_source)
        assert "csc.exe" in str(info.value)
        assert run.calls == []

    def test_no_csc_copies_prebuilt(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(iehost, "csc_path", lambda *a, **k: None)
        prebuilt = os.path.join(iehost.SHIPPED_DIR, EXE_NAME)
        with open(prebuilt, "wb") as fh:
            fh.write(b"MZ prebuilt")
        run = FakeRun()
        exe = ensure_built(workdir, run=run, source=fake_source)
        assert run.calls == []
        assert open(exe, "rb").read() == b"MZ prebuilt"
        hash_file = os.path.join(workdir, "bin", HASH_NAME)
        assert open(hash_file, encoding="utf-8").read().strip() == iehost._build_digest(fake_source)
        # cached afterwards
        assert ensure_built(workdir, run=run, source=fake_source) == exe

    def test_source_missing_raises(self, workdir, tmp_path):
        # the source file csc needs cannot be put in place (a folder is in the way of
        # <workdir>/bin/RecBrowser.cs): Japanese error naming the file, nothing compiled
        os.makedirs(os.path.join(workdir, "bin", "RecBrowser.cs"))
        run = FakeRun()
        with pytest.raises(IEHostError) as info:
            ensure_built(workdir, run=run, csc=CSC64, source="class A {}", folder=str(tmp_path / "nowhere"))
        assert "RecBrowser.cs" in str(info.value) and str(info.value).startswith("記録用ブラウザ")
        assert run.calls == []

    def test_source_missing_but_exe_present_is_kept(self, workdir, fake_source):
        run = FakeRun()
        exe = ensure_built(workdir, run=run, csc=CSC64, source=fake_source)
        os.remove(os.path.join(workdir, "bin", "RecBrowser.cs"))  # the copy written for csc was cleaned up
        assert ensure_built(workdir, run=run, csc=CSC64, source=fake_source) == exe
        assert len(run.calls) == 1

    def test_default_source_is_module_constant(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", fake_source)
        run = FakeRun()
        ensure_built(workdir, run=run, csc=CSC64)
        written = os.path.join(workdir, "bin", "RecBrowser.cs")
        assert run.calls[0][0][-1] == written
        assert open(written, "rb").read() == fake_source.encode("utf-8")

    def test_never_prints(self, workdir, fake_source, capsys):
        ensure_built(workdir, run=FakeRun(), csc=CSC64, source=fake_source)
        with pytest.raises(IEHostError):
            ensure_built(workdir, run=FakeRun(returncode=1, stderr="boom", write_exe=False), csc=CSC64,
                         source=fake_source, force=True)
        out = capsys.readouterr()
        assert out.out == "" and out.err == ""


# --------------------------------------------------------------------------- launch

class TestLaunch:
    def _prebuild(self, workdir, fake_source):
        ensure_built(workdir, run=FakeRun(), csc=CSC64, source=fake_source)

    def test_argv_and_popen_kwargs(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", fake_source)
        self._prebuild(workdir, fake_source)
        popen = FakePopen(pid=777)
        run = FakeRun()
        bp = launch(workdir, "127.0.0.1:8098", url="http://kanri/", title="在庫管理", popen=popen, run=run)
        assert run.calls == []  # already built: no compile
        assert len(popen.calls) == 1
        argv, kwargs = popen.calls[0]
        exe = exe_path(workdir)
        assert argv[0] == exe
        assert argv[1:7] == ["--proxy", "127.0.0.1:8098", "--bypass", "", "--log", bp.log_path]
        assert argv[7:] == ["--url", "http://kanri/", "--title", "在庫管理"]
        assert kwargs["cwd"] == os.path.dirname(exe)
        assert kwargs["close_fds"] is True
        assert "creationflags" not in kwargs
        assert isinstance(bp, BrowserProcess)
        assert bp.pid == 777
        assert bp.exe == exe
        assert bp.running is True
        assert bp.poll() is None
        assert isinstance(bp.started_at, float)
        log_dir = os.path.join(workdir, "logs")
        assert os.path.isdir(log_dir)
        assert os.path.dirname(bp.log_path) == log_dir
        assert re.fullmatch(r"recbrowser_\d{8}_\d{6}(_\d+)?\.log", os.path.basename(bp.log_path))

    def test_without_url_and_title(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", fake_source)
        self._prebuild(workdir, fake_source)
        popen = FakePopen()
        launch(workdir, "127.0.0.1:8098", popen=popen, run=FakeRun())
        argv, _ = popen.calls[0]
        assert "--url" not in argv and "--title" not in argv
        assert argv[1:5] == ["--proxy", "127.0.0.1:8098", "--bypass", ""]

    def test_builds_first_when_needed(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", fake_source)
        monkeypatch.setattr(iehost, "csc_path", lambda *a, **k: CSC64)
        popen = FakePopen()
        run = FakeRun()
        bp = launch(workdir, "127.0.0.1:8098", popen=popen, run=run)
        assert len(run.calls) == 1 and run.calls[0][0][0] == CSC64
        assert os.path.isfile(bp.exe)
        assert popen.calls[0][0][0] == bp.exe

    def test_custom_log_dir(self, workdir, fake_source, tmp_path, monkeypatch):
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", fake_source)
        self._prebuild(workdir, fake_source)
        logs = str(tmp_path / "elsewhere" / "logs")
        bp = launch(workdir, "127.0.0.1:8098", popen=FakePopen(), run=FakeRun(), log_dir=logs)
        assert os.path.dirname(bp.log_path) == logs
        assert os.path.isdir(logs)

    def test_two_launches_in_one_second_get_distinct_logs(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", fake_source)
        self._prebuild(workdir, fake_source)
        a = launch(workdir, "127.0.0.1:8098", popen=FakePopen(), run=FakeRun())
        open(a.log_path, "w").close()  # the browser would create it
        b = launch(workdir, "127.0.0.1:8098", popen=FakePopen(), run=FakeRun())
        assert a.log_path != b.log_path

    def test_popen_failure_raises_iehosterror(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", fake_source)
        self._prebuild(workdir, fake_source)
        with pytest.raises(IEHostError) as info:
            launch(workdir, "127.0.0.1:8098", popen=FakePopen(raises=OSError(5, "access denied")), run=FakeRun())
        assert "起動できません" in str(info.value)

    def test_build_failure_propagates(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", fake_source)
        monkeypatch.setattr(iehost, "csc_path", lambda *a, **k: CSC64)
        popen = FakePopen()
        with pytest.raises(IEHostError):
            launch(workdir, "127.0.0.1:8098", popen=popen, run=FakeRun(returncode=1, stderr="error", write_exe=False))
        assert popen.calls == []

    def test_empty_proxy_rejected(self, workdir):
        popen = FakePopen()
        with pytest.raises(ValueError):
            launch(workdir, "", popen=popen, run=FakeRun())
        with pytest.raises(ValueError):
            launch(workdir, "   ", popen=popen, run=FakeRun())
        assert popen.calls == []

    def test_close_uses_injected_run_for_taskkill(self, workdir, fake_source, monkeypatch):
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", fake_source)
        self._prebuild(workdir, fake_source)
        popen = FakePopen(pid=4242)
        calls = []

        def run(cmd, **kwargs):
            calls.append(list(cmd))
            popen.proc._die("taskkill")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        bp = launch(workdir, "127.0.0.1:8098", popen=popen, run=run)
        bp._windows = True  # the taskkill path regardless of the host OS running the tests
        assert bp.close(timeout=0.01) == 0
        assert calls == [["taskkill", "/PID", "4242"]]
        assert bp.running is False


# --------------------------------------------------------------------------- BrowserProcess.close

class TestBrowserProcessClose:
    def test_graceful_taskkill_is_enough(self):
        proc = FakeProc(pid=1234, dies_on="taskkill", exit_code=0)
        log = []
        bp = BrowserProcess(proc, "x.exe", "x.log", run=taskkill_run(proc, log), windows=True)
        assert bp.running is True
        assert bp.close(timeout=0.01) == 0
        assert log[0][0] == ["taskkill", "/PID", "1234"]
        assert "/F" not in log[0][0]
        assert log[0][1].get("capture_output") is True
        assert proc.events == ["taskkill"]
        assert bp.running is False
        assert bp.returncode == 0

    def test_terminate_after_taskkill(self):
        proc = FakeProc(pid=1, dies_on="terminate", exit_code=1)
        log = []
        bp = BrowserProcess(proc, "x.exe", "x.log", run=taskkill_run(proc, log), windows=True)
        assert bp.close(timeout=0.01) == 1
        assert proc.events == ["taskkill", "terminate"]

    def test_kill_last(self):
        proc = FakeProc(pid=1, dies_on="kill", exit_code=-9)
        log = []
        bp = BrowserProcess(proc, "x.exe", "x.log", run=taskkill_run(proc, log), windows=True)
        assert bp.close(timeout=0.01) == -9
        assert proc.events == ["taskkill", "terminate", "kill"]

    def test_unkillable_returns_none(self):
        proc = FakeProc(pid=1, dies_on="never")
        log = []
        bp = BrowserProcess(proc, "x.exe", "x.log", run=taskkill_run(proc, log), windows=True)
        assert bp.close(timeout=0.01) is None
        assert proc.events == ["taskkill", "terminate", "kill"]

    def test_already_exited(self):
        proc = FakeProc(pid=1, dies_on="never")
        proc.returncode = 3
        log = []
        bp = BrowserProcess(proc, "x.exe", "x.log", run=taskkill_run(proc, log), windows=True)
        assert bp.running is False
        assert bp.close() == 3
        assert log == [] and proc.events == []

    def test_taskkill_failure_falls_through(self):
        proc = FakeProc(pid=1, dies_on="terminate", exit_code=0)
        log = []
        bp = BrowserProcess(proc, "x.exe", "x.log", run=taskkill_run(proc, log, raises=FileNotFoundError("taskkill")),
                            windows=True)
        assert bp.close(timeout=0.01) == 0
        assert len(log) == 1
        assert proc.events == ["terminate"]

    def test_non_windows_skips_taskkill(self):
        proc = FakeProc(pid=1, dies_on="terminate", exit_code=0)
        log = []
        bp = BrowserProcess(proc, "x.exe", "x.log", run=taskkill_run(proc, log), windows=False)
        assert bp.close(timeout=0.01) == 0
        assert log == []
        assert proc.events == ["terminate"]

    def test_attributes(self):
        proc = FakeProc(pid=99)
        bp = BrowserProcess(proc, "C:/w/bin/RecBrowser.exe", "C:/w/logs/r.log", run=FakeRun(), started_at=1700000000.0,
                            windows=True)
        assert (bp.pid, bp.exe, bp.log_path, bp.started_at) == (99, "C:/w/bin/RecBrowser.exe", "C:/w/logs/r.log", 1700000000.0)
        assert bp.wait(timeout=0.01) is None
        proc.returncode = 0
        assert bp.wait(timeout=0.01) == 0

    def test_windows_default_follows_host_os(self):
        bp = BrowserProcess(FakeProc(), "x.exe", "x.log", run=FakeRun())
        assert bp._windows is (sys.platform == "win32")


# --------------------------------------------------------------------------- emulation (registry)

class TestEmulation:
    def test_set_writes_dword_under_feature_control_key(self):
        reg = FakeWinreg()
        set_emulation(11000, winreg=reg)
        assert reg.writes == [(FEATURE_BROWSER_EMULATION_KEY, "RecBrowser.exe", 11000, FakeWinreg.REG_DWORD)]
        assert reg.created == [(FEATURE_BROWSER_EMULATION_KEY, FakeWinreg.KEY_READ | FakeWinreg.KEY_SET_VALUE)]
        assert reg.closed == 1
        assert get_emulation(winreg=reg) == 11000

    def test_set_accepts_preset_names(self):
        reg = FakeWinreg()
        set_emulation("ie11_force", winreg=reg)
        assert get_emulation(winreg=reg) == 11001
        set_emulation("IE8", winreg=reg)
        assert get_emulation(winreg=reg) == 8000
        set_emulation("default", winreg=reg)
        assert get_emulation(winreg=reg) is None

    def test_custom_exe_name(self):
        reg = FakeWinreg()
        set_emulation(8000, exe_name="Other.exe", winreg=reg)
        assert reg.writes[0][1] == "Other.exe"
        assert get_emulation(exe_name="Other.exe", winreg=reg) == 8000
        assert get_emulation(winreg=reg) is None

    def test_none_deletes_value(self):
        reg = FakeWinreg({FEATURE_BROWSER_EMULATION_KEY: {"RecBrowser.exe": (11000, 4), "iexplore.exe": (11000, 4)}})
        set_emulation(None, winreg=reg)
        assert reg.deletes == [(FEATURE_BROWSER_EMULATION_KEY, "RecBrowser.exe")]
        assert reg.writes == []
        assert reg.created == []
        assert "iexplore.exe" in reg.keys[FEATURE_BROWSER_EMULATION_KEY]  # other apps untouched
        assert get_emulation(winreg=reg) is None

    def test_none_when_value_absent_is_silent(self):
        reg = FakeWinreg({FEATURE_BROWSER_EMULATION_KEY: {}})
        set_emulation(None, winreg=reg)
        assert reg.deletes == [] and reg.writes == []

    def test_none_when_key_absent_is_silent(self):
        reg = FakeWinreg()
        set_emulation(None, winreg=reg)
        assert reg.deletes == [] and reg.writes == [] and reg.created == []

    def test_get_when_key_missing(self):
        reg = FakeWinreg()
        assert get_emulation(winreg=reg) is None
        assert reg.opened == [(FEATURE_BROWSER_EMULATION_KEY, FakeWinreg.KEY_READ)]

    def test_get_when_value_missing(self):
        reg = FakeWinreg({FEATURE_BROWSER_EMULATION_KEY: {"iexplore.exe": (11000, 4)}})
        assert get_emulation(winreg=reg) is None
        assert reg.queries == [(FEATURE_BROWSER_EMULATION_KEY, "RecBrowser.exe")]

    def test_get_tolerates_non_numeric_value(self):
        reg = FakeWinreg({FEATURE_BROWSER_EMULATION_KEY: {"RecBrowser.exe": ("junk", 1)}})
        assert get_emulation(winreg=reg) is None

    @pytest.mark.parametrize("bad", ["ie12", "", -1, 1.5, True, "abc"])
    def test_invalid_level_rejected_before_touching_registry(self, bad):
        reg = FakeWinreg()
        with pytest.raises(ValueError):
            set_emulation(bad, winreg=reg)
        assert reg.writes == [] and reg.created == [] and reg.opened == []

    def test_resolve_emulation(self):
        assert resolve_emulation(None) is None
        assert resolve_emulation("ie11") == 11000
        assert resolve_emulation(" IE11 ") == 11000
        assert resolve_emulation("11001") == 11001
        assert resolve_emulation(8000) == 8000

    def test_non_windows_without_winreg_raises_iehosterror(self, monkeypatch):
        monkeypatch.setattr(iehost, "is_windows", lambda: False)
        with pytest.raises(IEHostError) as info:
            set_emulation(11000)
        assert "Windows" in str(info.value)
        with pytest.raises(IEHostError):
            get_emulation()


# =========================================================================== review fixes (DESIGN.md §13.12)

class TestPlatformAndShippedExe:
    def test_platform_is_always_x86(self):
        # like Edge's IE mode, the recording browser must be a 32-bit process so the 32-bit in-process
        # ActiveX controls of legacy intranet pages can load, whichever csc.exe builds it
        csc64 = iehost.build_command(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe", "s.cs", "o.exe")
        csc32 = iehost.build_command(r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe", "s.cs", "o.exe")
        for cmd in (csc64, csc32):
            assert [a for a in cmd if a.startswith("-platform:")] == ["-platform:x86"]
        assert iehost.BUILD_PLATFORM == "x86"

    def _ship(self, tmp_path, source_text="class A {}", matching=True):
        folder = tmp_path / "pkg"  # the distribution folder (normally the folder of reqrec.py)
        folder.mkdir(parents=True)
        exe = folder / iehost.EXE_NAME
        exe.write_bytes(b"MZ shipped")
        digest = iehost._build_digest(source_text) if matching else "0" * 64
        (folder / (iehost.EXE_NAME + ".sha256")).write_text(digest, encoding="utf-8")
        return folder, exe

    def test_shipped_exe_is_run_in_place_when_built_from_this_source(self, tmp_path):
        folder, exe = self._ship(tmp_path)
        assert iehost.shipped_exe(str(folder), source="class A {}") == str(exe)
        calls = []
        got = iehost.ensure_built(str(tmp_path / "work"), run=lambda *a, **k: calls.append(a), folder=str(folder),
                                  source="class A {}")
        assert got == str(exe) and calls == []  # no compile, nothing under the work folder
        assert not (tmp_path / "work" / "bin").exists()

    def test_stale_shipped_exe_is_not_used_in_place(self, tmp_path):
        folder, exe = self._ship(tmp_path, matching=False)
        assert iehost.shipped_exe(str(folder), source="class A {}") is None

    def test_availability_reports_the_shipped_exe(self, tmp_path):
        folder, exe = self._ship(tmp_path)
        info = iehost.availability(str(tmp_path / "work"), platform="win32", folder=str(folder), source="class A {}",
                                   exists=lambda p: os.path.isfile(p))
        assert info["available"] is True and info["exe"] == str(exe) and info["shipped"] is True

    def test_build_shipped_writes_exe_and_hash(self, tmp_path):
        folder = tmp_path / "pkg"
        folder.mkdir(parents=True)
        seen = []
        compiled = []

        def fake_run(cmd, **kw):
            seen.append(cmd)
            compiled.append(open(cmd[-1], encoding="utf-8").read())  # the source csc gets (a temporary file)
            out = [a for a in cmd if a.startswith("-out:")][0][5:]
            with open(out, "wb") as fh:
                fh.write(b"MZ")

            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            return R()

        exe = iehost.build_shipped(run=fake_run, csc=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
                                   folder=str(folder), source="class A {}")
        assert exe == str(folder / iehost.EXE_NAME)
        assert iehost.shipped_exe(str(folder), source="class A {}") == exe and "-platform:x86" in seen[0]
        assert compiled == ["class A {}"] and not os.path.exists(seen[0][-1])  # temporary source removed

    def test_cli(self, monkeypatch, capsys):
        # ``reqrec browser build | status`` (former ``python -m reqrec.iehost build | status``)
        monkeypatch.setattr(iehost, "build_shipped", lambda: r"X:\reqrec\RecBrowser.exe")
        assert reqrec.main(["browser", "build"]) == 0 and "RecBrowser.exe" in capsys.readouterr().out
        monkeypatch.setattr(iehost, "shipped_exe", lambda: None)
        assert reqrec.main(["browser", "status"]) == 0 and "なし" in capsys.readouterr().out
        assert reqrec.main(["browser"]) == 2

    def test_launch_runs_the_shipped_exe_in_place(self, tmp_path, monkeypatch):
        folder, exe = self._ship(tmp_path)
        monkeypatch.setattr(iehost, "SHIPPED_DIR", str(folder))
        monkeypatch.setattr(reqrec, "RECBROWSER_CS", "class A {}")
        argv = []

        class P:
            pid = 1

            def poll(self):
                return None

        proc = iehost.launch(str(tmp_path / "work"), "127.0.0.1:8080", popen=lambda a, **k: argv.append(a) or P(),
                             run=lambda *a, **k: None, job=lambda p: None)
        # the whole argv: no URL / title given, and http only (there is no --https mode any more)
        assert argv == [[str(exe), "--proxy", "127.0.0.1:8080", "--bypass", "", "--log", proc.log_path]]
        assert proc.exe == str(exe) and proc.job_handle is None
        assert not (tmp_path / "work" / "bin").exists()  # nothing compiled or copied under the work folder


@pytest.mark.skipif(sys.platform != "win32", reason="Windows job objects")
class TestKillOnCloseJob:
    def test_child_dies_when_the_job_handle_is_closed(self):
        import subprocess as sp

        child = sp.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            job = iehost.kill_on_close_job(child)
            assert isinstance(job, int) and job
            assert child.poll() is None
            iehost._close_handle(job)  # what happens when the GUI process dies
            assert child.wait(timeout=10) is not None
        finally:
            if child.poll() is None:
                child.kill()



class TestBuildDigest:
    def test_build_settings_are_part_of_the_digest(self, tmp_path, monkeypatch):
        x86 = iehost._build_digest("class A {}")
        monkeypatch.setattr(iehost, "BUILD_PLATFORM", "x64")
        assert iehost._build_digest("class A {}") != x86  # an exe built for x64 is rebuilt once as x86

    def test_old_source_only_hash_triggers_one_rebuild(self, tmp_path):
        source = "class A {}"
        nowhere = str(tmp_path / "nowhere")  # no distribution folder
        work = tmp_path / "w"
        (work / "bin").mkdir(parents=True)
        (work / "bin" / iehost.EXE_NAME).write_bytes(b"MZ old x64")
        (work / "bin" / iehost.HASH_NAME).write_text(hashlib.sha256(source.encode("utf-8")).hexdigest(), encoding="utf-8")
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            out = [a for a in cmd if a.startswith("-out:")][0][5:]
            open(out, "wb").write(b"MZ new x86")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        exe = iehost.ensure_built(str(work), run=fake_run, csc=r"C:\csc.exe", folder=nowhere, source=source)
        assert calls and "-platform:x86" in calls[0]
        assert open(exe, "rb").read() == b"MZ new x86"
        assert iehost.ensure_built(str(work), run=fake_run, csc=r"C:\csc.exe", folder=nowhere, source=source) == exe and len(calls) == 1
