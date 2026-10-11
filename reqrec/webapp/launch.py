"""Open a browser / a folder from the GUI (かんたんモード).  Contract: DESIGN.md §13.11.

The easy mode never asks the user to configure a proxy by hand: after the recording proxy is up
(and, on Windows, the system proxy is set) the GUI opens **Microsoft Edge** itself so the user only
has to operate the site.  Edge is preferred because Edge's IE mode is the main target; when Edge
is not found the OS default browser is used.

Every function takes injectable callables so the logic is unit tested on any OS without launching
anything.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import webbrowser
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

__all__ = ["find_edge", "open_url", "open_folder", "validate_url", "DEFAULT_START_URL"]

#: What Edge opens when the user did not type a site address.
DEFAULT_START_URL = "edge://newtab"

_EDGE_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)
_EDGE_APP_PATHS_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
#: ``scheme:`` prefix (RFC 3986); anything with one that is not http(s) is rejected, never patched.
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
#: ``host:port[/...]`` typed without a scheme (``kanri:8080/app``): the part before ``:`` is a host, not a scheme.
_HOST_PORT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]*:\d{1,5}(?:[/?#]|$)")


def _is_windows() -> bool:
    return sys.platform == "win32" or os.name == "nt"


def find_edge(exists: Callable[[str], bool] = os.path.isfile, winreg: Any = None, env: Optional[dict] = None) -> Optional[str]:
    """Path of ``msedge.exe`` (known install folders, then the registry *App Paths*), else None."""
    environ = os.environ if env is None else env
    candidates = list(_EDGE_CANDIDATES)
    for var in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
        base = environ.get(var)
        if base:
            candidates.append(os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"))
    for path in candidates:
        if exists(path):
            return path
    reg = winreg
    if reg is None:
        if not _is_windows():
            return None
        try:
            import winreg as reg  # type: ignore[no-redef]
        except ImportError:  # pragma: no cover
            return None
    for hive_name in ("HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"):
        hive = getattr(reg, hive_name, None)
        if hive is None:
            continue
        try:
            with reg.OpenKey(hive, _EDGE_APP_PATHS_KEY) as key:
                value, _ = reg.QueryValueEx(key, None)
        except OSError:
            continue
        value = str(value or "").strip().strip('"')
        if value and exists(value):
            return value
    return None


def validate_url(url: Any) -> str:
    """``http(s)://...`` or ``edge://...``; an address without a scheme gets ``http://``.

    Raises ``ValueError`` with a Japanese message for anything else (``javascript:`` and friends
    must never reach the browser from an API call).
    """
    text = str(url or "").strip()
    if not text:
        return DEFAULT_START_URL
    if text.startswith("edge://"):
        return text
    if not _SCHEME_RE.match(text) or _HOST_PORT_RE.match(text):  # "kanri/top", "kanri:8080/top" -> http://...
        text = "http://" + text
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("サイトのアドレスは http:// または https:// で始まる形で入力してください (例: https://intra.example.co.jp/)")
    if any(ch in text for ch in "\r\n\x00"):
        raise ValueError("サイトのアドレスに使えない文字が含まれています")
    return text


def open_url(
    url: Any,
    prefer_edge: bool = True,
    popen: Optional[Callable[..., Any]] = None,
    browser_open: Optional[Callable[[str], bool]] = None,
    edge_path: Optional[str] = None,
) -> dict[str, Any]:
    """Open ``url`` in Edge when available (else the default browser).

    Returns ``{"url", "browser": "edge"|"default", "path"}``.  Raises ``ValueError`` for an
    invalid URL and ``RuntimeError`` when nothing could be started.
    """
    target = validate_url(url)
    spawn = popen or subprocess.Popen
    opener = browser_open or webbrowser.open
    edge = edge_path if edge_path is not None else (find_edge() if prefer_edge else None)
    if edge:
        try:
            spawn([edge, target], close_fds=True)
            return {"url": target, "browser": "edge", "path": edge}
        except OSError as exc:  # fall back to the default browser
            last_error = str(exc)
    else:
        last_error = "Edge が見つかりません"
    if target.startswith("edge://"):
        target = "about:blank"
    try:
        ok = opener(target)
    except Exception as exc:  # pragma: no cover - webbrowser rarely raises
        raise RuntimeError(f"ブラウザを開けませんでした: {exc} ({last_error})") from exc
    if not ok:
        raise RuntimeError(f"ブラウザを開けませんでした ({last_error})。手でブラウザを開いてサイトにアクセスしてください。")
    return {"url": target, "browser": "default", "path": None}


def open_folder(
    path: str,
    startfile: Optional[Callable[[str], Any]] = None,
    popen: Optional[Callable[..., Any]] = None,
    platform: Optional[str] = None,
) -> dict[str, Any]:
    """Show ``path`` in the OS file manager (Explorer / Finder / xdg-open).

    Raises ``FileNotFoundError`` when the folder does not exist and ``RuntimeError`` when the OS
    has no opener.
    """
    if not os.path.isdir(path):
        raise FileNotFoundError(f"フォルダがありません: {path}")
    plat = platform or sys.platform
    if plat == "win32":
        opener = startfile or getattr(os, "startfile", None)
        if opener is None:  # pragma: no cover - os.startfile always exists on Windows
            raise RuntimeError("この OS ではフォルダを開けません")
        opener(path)
        return {"path": path, "opener": "explorer"}
    spawn = popen or subprocess.Popen
    command = ["open", path] if plat == "darwin" else ["xdg-open", path]
    try:
        spawn(command, close_fds=True)
    except OSError as exc:
        raise RuntimeError(f"フォルダを開けませんでした: {exc}") from exc
    return {"path": path, "opener": command[0]}
