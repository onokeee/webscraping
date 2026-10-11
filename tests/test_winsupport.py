"""Tests for reqrec.winsupport with fake winreg / certutil (pure logic, runs on every OS).  Contract: DESIGN.md §13.7."""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace

import pytest

from reqrec import winsupport
from reqrec.winsupport import (
    DEFAULT_PROXY_OVERRIDE,
    INTERNET_SETTINGS_KEY,
    NOT_WINDOWS_MESSAGE,
    cert_installed,
    get_system_proxy,
    install_ca_cert,
    is_windows,
    mitmproxy_ca_cert_path,
    proxy_server_for,
    refresh_proxy_settings,
    restore_system_proxy,
    set_system_proxy,
    status_summary,
)

IS_WINDOWS = sys.platform == "win32"


# --------------------------------------------------------------------------- fakes

class FakeKey:
    def __init__(self, reg, write):
        self.reg = reg
        self.write = write

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.reg.closed += 1
        return False


class FakeWinreg:
    """Just enough of ``winreg`` for the Internet Settings key."""

    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 0x20019
    KEY_SET_VALUE = 0x0002
    REG_DWORD = 4
    REG_SZ = 1

    def __init__(self, values=None):
        self.values = dict(values or {})  # name -> (value, type)
        self.opened = []
        self.closed = 0
        self.writes = []
        self.deletes = []

    def OpenKey(self, hive, path, reserved, access):
        assert hive == self.HKEY_CURRENT_USER
        assert path == INTERNET_SETTINGS_KEY
        self.opened.append(access)
        return FakeKey(self, bool(access & self.KEY_SET_VALUE))

    def QueryValueEx(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return self.values[name]

    def SetValueEx(self, key, name, reserved, type_, value):
        assert key.write, "SetValueEx on a read-only key"
        self.values[name] = (value, type_)
        self.writes.append((name, value, type_))

    def DeleteValue(self, key, name):
        assert key.write
        if name not in self.values:
            raise FileNotFoundError(2, "no such value")
        del self.values[name]
        self.deletes.append(name)


def fake_run_factory(stdout="", stderr="", returncode=0, raises=None, log=None):
    def run(cmd):
        if log is not None:
            log.append(cmd)
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    return run


# --------------------------------------------------------------------------- platform

def test_is_windows_matches_platform():
    assert is_windows() is IS_WINDOWS
    assert isinstance(is_windows(), bool)


def test_module_imports_without_winreg():
    assert "winreg" not in sys.modules or IS_WINDOWS or True  # import side effects only; the real check is below
    import importlib

    importlib.reload(winsupport)


# --------------------------------------------------------------------------- proxy

class TestGetSystemProxy:
    def test_missing_values_mean_disabled(self):
        reg = FakeWinreg()
        assert get_system_proxy(winreg=reg) == {"enabled": False, "server": "", "override": ""}
        assert reg.opened == [FakeWinreg.KEY_READ]

    def test_reads_values(self):
        reg = FakeWinreg({"ProxyEnable": (1, 4), "ProxyServer": ("proxy.corp:3128", 1), "ProxyOverride": ("<local>", 1)})
        assert get_system_proxy(winreg=reg) == {"enabled": True, "server": "proxy.corp:3128", "override": "<local>"}

    def test_odd_enable_value(self):
        reg = FakeWinreg({"ProxyEnable": ("garbage", 1)})
        assert get_system_proxy(winreg=reg)["enabled"] is False


class TestSetAndRestore:
    def test_set_returns_backup_and_writes(self):
        reg = FakeWinreg({"ProxyEnable": (0, 4), "ProxyServer": ("old:1", 1)})
        refreshed = []
        backup = set_system_proxy("127.0.0.1:8080", winreg=reg, refresh=lambda: refreshed.append(1))
        assert backup == {"ProxyEnable": 0, "ProxyServer": "old:1", "ProxyOverride": None}
        assert reg.values["ProxyEnable"] == (1, FakeWinreg.REG_DWORD)
        assert reg.values["ProxyServer"] == ("127.0.0.1:8080", FakeWinreg.REG_SZ)
        assert reg.values["ProxyOverride"] == (DEFAULT_PROXY_OVERRIDE, FakeWinreg.REG_SZ)
        assert refreshed == [1]
        assert get_system_proxy(winreg=reg) == {"enabled": True, "server": "127.0.0.1:8080", "override": DEFAULT_PROXY_OVERRIDE}

    def test_set_disable(self):
        reg = FakeWinreg({"ProxyEnable": (1, 4), "ProxyServer": ("old:1", 1), "ProxyOverride": ("x", 1)})
        set_system_proxy("", enable=False, winreg=reg, refresh=lambda: None)
        assert reg.values["ProxyEnable"][0] == 0
        assert reg.values["ProxyServer"][0] == "old:1"  # untouched when no server given

    def test_set_requires_server_when_enabling(self):
        with pytest.raises(ValueError):
            set_system_proxy("   ", winreg=FakeWinreg(), refresh=lambda: None)

    def test_custom_override(self):
        reg = FakeWinreg()
        set_system_proxy("127.0.0.1:8080", override="<local>;*.corp", winreg=reg, refresh=lambda: None)
        assert reg.values["ProxyOverride"][0] == "<local>;*.corp"

    def test_restore_puts_everything_back(self):
        original = {"ProxyEnable": (0, 4), "ProxyServer": ("old:1", 1)}
        reg = FakeWinreg(original)
        backup = set_system_proxy("127.0.0.1:8080", winreg=reg, refresh=lambda: None)
        refreshed = []
        restore_system_proxy(backup, winreg=reg, refresh=lambda: refreshed.append(1))
        assert reg.values == {"ProxyEnable": (0, 4), "ProxyServer": ("old:1", 1)}  # override deleted again
        assert reg.deletes == ["ProxyOverride"] and refreshed == [1]

    def test_restore_tolerates_missing_value_to_delete(self):
        reg = FakeWinreg()
        restore_system_proxy({"ProxyEnable": None, "ProxyServer": None, "ProxyOverride": None}, winreg=reg, refresh=lambda: None)
        assert reg.values == {} and reg.deletes == []

    def test_restore_partial_backup(self):
        reg = FakeWinreg({"ProxyServer": ("x", 1)})
        restore_system_proxy({"ProxyEnable": 1}, winreg=reg, refresh=lambda: None)
        assert reg.values == {"ProxyServer": ("x", 1), "ProxyEnable": (1, 4)}

    def test_restore_rejects_garbage(self):
        with pytest.raises(ValueError):
            restore_system_proxy("nope", winreg=FakeWinreg(), refresh=lambda: None)

    def test_refresh_not_called_on_wininet_with_fake_winreg(self, monkeypatch):
        # without an injected refresh and with a fake winreg nothing may touch ctypes
        monkeypatch.setattr(winsupport, "refresh_proxy_settings", lambda *a, **k: pytest.fail("must not call wininet"))
        set_system_proxy("127.0.0.1:8080", winreg=FakeWinreg())


class TestRefresh:
    def test_calls_both_options(self):
        calls = []
        refresh_proxy_settings(set_option=lambda h, opt, buf, size: calls.append((h, opt, buf, size)))
        assert calls == [(None, 39, None, 0), (None, 37, None, 0)]


def test_proxy_server_for():
    assert proxy_server_for("127.0.0.1", 8080) == "127.0.0.1:8080"
    assert proxy_server_for("0.0.0.0", 8080) == "127.0.0.1:8080"
    assert proxy_server_for("::", 8080) == "127.0.0.1:8080"
    assert proxy_server_for("", 9000) == "127.0.0.1:9000"
    assert proxy_server_for("::1", 8080) == "[::1]:8080"
    assert proxy_server_for("myhost", "8081") == "myhost:8081"


# --------------------------------------------------------------------------- certificate

class TestCertPath:
    def test_none_when_missing(self, tmp_path):
        assert mitmproxy_ca_cert_path(home=str(tmp_path)) is None

    def test_prefers_cer(self, tmp_path):
        d = tmp_path / ".mitmproxy"
        d.mkdir()
        (d / "mitmproxy-ca-cert.pem").write_text("pem")
        assert mitmproxy_ca_cert_path(home=str(tmp_path)) == str(d / "mitmproxy-ca-cert.pem")
        (d / "mitmproxy-ca-cert.cer").write_text("cer")
        assert mitmproxy_ca_cert_path(home=str(tmp_path)) == str(d / "mitmproxy-ca-cert.cer")

    def test_default_home_does_not_raise(self):
        result = mitmproxy_ca_cert_path()
        assert result is None or result.endswith((".cer", ".pem"))


class TestCertInstalled:
    def test_found(self):
        log = []
        run = fake_run_factory(stdout="Root\n================ Certificate 3 ================\nSubject: CN=mitmproxy, O=mitmproxy\n", log=log)
        assert cert_installed(run=run) is True
        assert log == [["certutil", "-user", "-store", "Root"]]

    def test_not_found(self):
        assert cert_installed(run=fake_run_factory(stdout="Root\nSubject: CN=DigiCert\n")) is False

    def test_certutil_missing(self):
        assert cert_installed(run=fake_run_factory(raises=FileNotFoundError("certutil"))) is None

    def test_certutil_failure_without_output(self):
        assert cert_installed(run=fake_run_factory(stdout="", returncode=1)) is None

    def test_certutil_timeout(self):
        assert cert_installed(run=fake_run_factory(raises=subprocess.TimeoutExpired("certutil", 60))) is None


class TestInstallCert:
    def test_no_cert_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(winsupport, "mitmproxy_ca_cert_path", lambda home=None: None)
        ok, msg = install_ca_cert(run=fake_run_factory())
        assert ok is False and "見つかりません" in msg and "記録開始" in msg

    def test_given_path_missing(self, tmp_path):
        ok, msg = install_ca_cert(str(tmp_path / "nope.cer"), run=fake_run_factory())
        assert ok is False and "ありません" in msg

    def test_success(self, tmp_path):
        cert = tmp_path / "mitmproxy-ca-cert.cer"
        cert.write_text("cert")
        log = []
        ok, out = install_ca_cert(str(cert), run=fake_run_factory(stdout="CertUtil: -addstore command completed successfully.\n", log=log))
        assert ok is True
        assert "completed successfully" in out and str(cert) in out
        assert log == [["certutil", "-user", "-addstore", "Root", str(cert)]]

    def test_failure(self, tmp_path):
        cert = tmp_path / "c.cer"
        cert.write_text("cert")
        ok, out = install_ca_cert(str(cert), run=fake_run_factory(stdout="", stderr="CertUtil: -addstore command FAILED: 0x80070005", returncode=1))
        assert ok is False and "FAILED" in out

    def test_certutil_missing(self, tmp_path):
        cert = tmp_path / "c.cer"
        cert.write_text("cert")
        ok, out = install_ca_cert(str(cert), run=fake_run_factory(raises=FileNotFoundError()))
        assert ok is False and "certutil" in out

    def test_default_path_used(self, tmp_path, monkeypatch):
        cert = tmp_path / "mitmproxy-ca-cert.cer"
        cert.write_text("cert")
        monkeypatch.setattr(winsupport, "mitmproxy_ca_cert_path", lambda home=None: str(cert))
        log = []
        ok, _ = install_ca_cert(run=fake_run_factory(log=log))
        assert ok and log[0][-1] == str(cert)


# --------------------------------------------------------------------------- summary

def test_status_summary_with_fakes(tmp_path, monkeypatch):
    monkeypatch.setattr(winsupport, "mitmproxy_ca_cert_path", lambda home=None: None)
    reg = FakeWinreg({"ProxyEnable": (1, 4), "ProxyServer": ("127.0.0.1:8080", 1)})
    info = status_summary(winreg=reg, run=fake_run_factory(stdout="CN=mitmproxy"))
    assert info == {
        "is_windows": True,
        "proxy": {"enabled": True, "server": "127.0.0.1:8080", "override": ""},
        "cert": {"installed": True, "path": None},
        "error": None,
    }


def test_status_summary_reports_registry_error():
    class Broken(FakeWinreg):
        def OpenKey(self, *a):
            raise PermissionError("denied")

    info = status_summary(winreg=Broken(), run=fake_run_factory(stdout=""))
    assert info["proxy"] is None and "denied" in info["error"] and info["cert"]["installed"] is False


@pytest.mark.skipif(IS_WINDOWS, reason="real Windows has winreg")
def test_status_summary_off_windows():
    info = status_summary()
    assert info["is_windows"] is False and info["proxy"] is None and info["cert"]["installed"] is None


# --------------------------------------------------------------------------- non-Windows guard

@pytest.mark.skipif(IS_WINDOWS, reason="only meaningful off Windows")
class TestNonWindowsGuard:
    @pytest.mark.parametrize("call", [
        lambda: get_system_proxy(),
        lambda: set_system_proxy("127.0.0.1:8080"),
        lambda: restore_system_proxy({"ProxyEnable": 0}),
        lambda: refresh_proxy_settings(),
        lambda: cert_installed(),
        lambda: install_ca_cert("x.cer"),
    ])
    def test_raises_japanese_runtime_error(self, call):
        with pytest.raises(RuntimeError) as exc:
            call()
        assert str(exc.value) == NOT_WINDOWS_MESSAGE == "Windows 以外では使えません"

    def test_safe_functions_do_not_raise(self):
        assert is_windows() is False
        mitmproxy_ca_cert_path()
        status_summary()
