"""Windows helpers for proxy recording with Edge / IE mode (system proxy, mitmproxy CA cert).
Contract: DESIGN.md §13.7.  Every function must be importable and safe to call on non-Windows
(returning ``None`` / raising ``RuntimeError`` with a Japanese message).

Edge's IE mode (and every other WinINet / WinHTTP based client) honours the per-user proxy stored
under ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings``:

``ProxyEnable``   REG_DWORD  1 = use ``ProxyServer``
``ProxyServer``   REG_SZ     ``host:port`` (or ``http=host:port;https=host:port``)
``ProxyOverride`` REG_SZ     ``;``-separated hosts that bypass the proxy (``<local>`` = no dot in name)

Writing the registry alone is not enough: running browsers only pick the change up after
``InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED)`` / ``INTERNET_OPTION_REFRESH``.

The mitmproxy CA certificate (``~/.mitmproxy/mitmproxy-ca-cert.cer``) must be in the user's
*Trusted Root Certification Authorities* store (``certutil -user -addstore Root``) before HTTPS
sites can be recorded.

Every function takes injectable ``winreg`` / ``run`` / ``set_option`` callables so the logic is unit
tested on any OS; without them, a call on a non-Windows OS raises
``RuntimeError("Windows 以外では使えません")`` (``is_windows`` and ``mitmproxy_ca_cert_path`` excepted).
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Any, Callable, Optional

__all__ = [
    "NOT_WINDOWS_MESSAGE", "INTERNET_SETTINGS_KEY", "DEFAULT_PROXY_OVERRIDE",
    "is_windows", "get_system_proxy", "set_system_proxy", "restore_system_proxy",
    "refresh_proxy_settings", "mitmproxy_ca_cert_path", "cert_installed", "install_ca_cert",
    "proxy_server_for", "status_summary",
]

NOT_WINDOWS_MESSAGE = "Windows 以外では使えません"

#: Registry path (under HKEY_CURRENT_USER) holding the WinINet proxy configuration.
INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

#: Hosts that bypass the proxy by default: the GUI itself and anything on this machine.
DEFAULT_PROXY_OVERRIDE = "<local>;localhost;127.0.0.1"

# WinINet option ids (wininet.h)
INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39

#: Registry value names managed by this module, in the order they appear in a backup.
_PROXY_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride")

#: Substring certutil prints for the mitmproxy certificate (its CN is "mitmproxy").
_CERT_MARKER = "mitmproxy"

_CERTUTIL_TIMEOUT = 60.0


# --------------------------------------------------------------------------- platform

def is_windows() -> bool:
    """True when running on Windows (``sys.platform == "win32"``)."""
    return sys.platform == "win32" or os.name == "nt"


def _require_windows(injected: Any) -> None:
    """Raise unless we are on Windows or a test double was injected."""
    if injected is None and not is_windows():
        raise RuntimeError(NOT_WINDOWS_MESSAGE)


def _winreg(injected: Any) -> Any:
    """The injected fake or the real ``winreg`` module (imported lazily: it only exists on Windows)."""
    if injected is not None:
        return injected
    _require_windows(None)
    import winreg  # noqa: WPS433 - Windows only

    return winreg


def _default_run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=_CERTUTIL_TIMEOUT)


# --------------------------------------------------------------------------- proxy (registry)

def _read_value(winreg: Any, key: Any, name: str) -> Any:
    """Registry value or None when it does not exist."""
    try:
        value, _type = winreg.QueryValueEx(key, name)
    except FileNotFoundError:
        return None
    except OSError as exc:  # pragma: no cover - other registry errors
        if getattr(exc, "winerror", None) == 2:  # ERROR_FILE_NOT_FOUND
            return None
        raise
    return value


def _open_key(winreg: Any, write: bool) -> Any:
    access = winreg.KEY_READ | (winreg.KEY_SET_VALUE if write else 0)
    return winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, access)


def _raw_proxy_values(winreg: Any) -> dict[str, Any]:
    with _open_key(winreg, write=False) as key:
        return {name: _read_value(winreg, key, name) for name in _PROXY_VALUES}


def get_system_proxy(winreg: Any = None) -> dict:
    """Current WinINet proxy settings: ``{"enabled": bool, "server": str, "override": str}``."""
    reg = _winreg(winreg)
    raw = _raw_proxy_values(reg)
    enabled_raw = raw.get("ProxyEnable")
    try:
        enabled = bool(int(enabled_raw)) if enabled_raw is not None else False
    except (TypeError, ValueError):
        enabled = False
    return {
        "enabled": enabled,
        "server": str(raw.get("ProxyServer") or ""),
        "override": str(raw.get("ProxyOverride") or ""),
    }


def proxy_server_for(listen_host: str, port: int) -> str:
    """``host:port`` string browsers understand for a proxy bound to ``listen_host``.

    A wildcard bind (``0.0.0.0`` / ``::``) is reachable locally as ``127.0.0.1``.
    """
    host = (listen_host or "").strip()
    if host in ("", "0.0.0.0", "::", "*", "[::]"):
        host = "127.0.0.1"
    if ":" in host and not host.startswith("["):  # bare IPv6 literal
        host = f"[{host}]"
    return f"{host}:{int(port)}"


def set_system_proxy(
    server: str,
    enable: bool = True,
    override: str = DEFAULT_PROXY_OVERRIDE,
    winreg: Any = None,
    refresh: Optional[Callable[[], None]] = None,
) -> dict:
    """Point the system (WinINet) proxy at ``server`` and return a backup of the previous values.

    The backup (``{"ProxyEnable": int|None, "ProxyServer": str|None, "ProxyOverride": str|None}``)
    is what :func:`restore_system_proxy` expects; ``None`` means the value did not exist.
    ``refresh`` (default :func:`refresh_proxy_settings`) tells running browsers about the change.
    """
    server = (server or "").strip()
    if enable and not server:
        raise ValueError("プロキシのアドレス (host:port) を指定してください")
    reg = _winreg(winreg)
    backup = _raw_proxy_values(reg)
    with _open_key(reg, write=True) as key:
        reg.SetValueEx(key, "ProxyEnable", 0, reg.REG_DWORD, 1 if enable else 0)
        if server:
            reg.SetValueEx(key, "ProxyServer", 0, reg.REG_SZ, server)
        if enable:
            reg.SetValueEx(key, "ProxyOverride", 0, reg.REG_SZ, override or "")
    _call_refresh(refresh, winreg)
    return backup


def restore_system_proxy(backup: dict, winreg: Any = None, refresh: Optional[Callable[[], None]] = None) -> None:
    """Undo :func:`set_system_proxy`: write every backed-up value back (delete values that did not exist)."""
    if not isinstance(backup, dict):
        raise ValueError("プロキシ設定のバックアップが不正です")
    reg = _winreg(winreg)
    with _open_key(reg, write=True) as key:
        for name in _PROXY_VALUES:
            if name not in backup:
                continue
            value = backup[name]
            if value is None:
                try:
                    reg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
                except OSError as exc:  # pragma: no cover - other registry errors
                    if getattr(exc, "winerror", None) != 2:
                        raise
                continue
            if name == "ProxyEnable":
                reg.SetValueEx(key, name, 0, reg.REG_DWORD, int(value))
            else:
                reg.SetValueEx(key, name, 0, reg.REG_SZ, str(value))
    _call_refresh(refresh, winreg)


def _call_refresh(refresh: Optional[Callable[[], None]], winreg: Any) -> None:
    if refresh is not None:
        refresh()
        return
    if winreg is not None:  # test double in use: never touch wininet
        return
    try:
        refresh_proxy_settings()
    except Exception:  # pragma: no cover - browsers simply pick the change up later
        pass


def refresh_proxy_settings(set_option: Optional[Callable[[Any, int, Any, int], Any]] = None) -> None:
    """Notify WinINet (and thus IE mode / Edge / Windows apps) that the proxy settings changed.

    ``set_option`` defaults to ``ctypes.windll.wininet.InternetSetOptionW``.
    """
    if set_option is None:
        _require_windows(None)
        import ctypes  # noqa: WPS433

        set_option = ctypes.windll.wininet.InternetSetOptionW  # type: ignore[attr-defined]
    set_option(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    set_option(None, INTERNET_OPTION_REFRESH, None, 0)


# --------------------------------------------------------------------------- CA certificate

def mitmproxy_ca_cert_path(home: Optional[str] = None) -> Optional[str]:
    """``~/.mitmproxy/mitmproxy-ca-cert.cer`` (preferred by certutil) or ``.pem``, whichever exists."""
    base = os.path.join(home or os.path.expanduser("~"), ".mitmproxy")
    for name in ("mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem"):
        path = os.path.join(base, name)
        if os.path.isfile(path):
            return path
    return None


def cert_installed(run: Optional[Callable[[list[str]], Any]] = None) -> Optional[bool]:
    """Is the mitmproxy CA in the current user's Root store?  ``None`` when certutil is unavailable."""
    _require_windows(run)
    runner = run or _default_run
    try:
        result = runner(["certutil", "-user", "-store", "Root"])
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        return None
    except OSError:
        return None
    output = f"{getattr(result, 'stdout', '') or ''}\n{getattr(result, 'stderr', '') or ''}"
    if getattr(result, "returncode", 1) != 0 and _CERT_MARKER not in output.lower():
        return None if not output.strip() else False
    return _CERT_MARKER in output.lower()


def install_ca_cert(path: Optional[str] = None, run: Optional[Callable[[list[str]], Any]] = None) -> tuple[bool, str]:
    """``certutil -user -addstore Root <cert>``; returns ``(success, output)``.

    Installing into the *user* store needs no administrator rights.  Edge / IE mode trust the user
    store, so this is enough for recording.
    """
    _require_windows(run)
    cert = path or mitmproxy_ca_cert_path()
    if not cert:
        return False, (
            "mitmproxy の CA 証明書が見つかりません。先に一度「記録開始」でプロキシを起動すると "
            "~/.mitmproxy/mitmproxy-ca-cert.cer が作成されます。"
        )
    if not os.path.isfile(cert):
        return False, f"証明書ファイルがありません: {cert}"
    runner = run or _default_run
    try:
        result = runner(["certutil", "-user", "-addstore", "Root", cert])
    except FileNotFoundError:
        return False, "certutil が見つかりません (Windows 標準のコマンドです。PATH を確認してください)"
    except subprocess.TimeoutExpired:
        return False, "certutil が応答しません (タイムアウト)"
    except OSError as exc:
        return False, f"certutil を実行できません: {exc}"
    output = f"{getattr(result, 'stdout', '') or ''}{getattr(result, 'stderr', '') or ''}".strip()
    ok = getattr(result, "returncode", 1) == 0
    if ok:
        output = (output + "\n" if output else "") + f"CA 証明書を登録しました: {cert}"
    return ok, output


# --------------------------------------------------------------------------- aggregated status

def status_summary(winreg: Any = None, run: Optional[Callable[[list[str]], Any]] = None) -> dict:
    """``{"is_windows", "proxy": {...}|None, "cert": {"installed", "path"}}`` for the GUI.

    Never raises: on other OSes ``proxy`` is ``None`` and ``cert.installed`` is ``None``; registry /
    certutil errors are reported in ``error``.
    """
    windows = is_windows() or winreg is not None or run is not None
    info: dict[str, Any] = {
        "is_windows": windows,
        "proxy": None,
        "cert": {"installed": None, "path": mitmproxy_ca_cert_path()},
        "error": None,
    }
    if not windows:
        return info
    try:
        info["proxy"] = get_system_proxy(winreg=winreg)
    except Exception as exc:  # registry access problems should not break the GUI
        info["error"] = f"プロキシ設定を読み取れません: {exc}"
    try:
        info["cert"]["installed"] = cert_installed(run=run)
    except Exception as exc:
        info["error"] = (info["error"] + " / " if info["error"] else "") + f"証明書の確認に失敗しました: {exc}"
    return info
