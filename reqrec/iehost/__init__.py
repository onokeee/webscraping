"""Recording browser for legacy intranet sites: a hosted IE engine routed through the local proxy.
Contract: DESIGN.md §13.12.  Importable on every OS; everything Windows-specific is guarded and
takes injectable dependencies (``exists`` / ``run`` / ``popen`` / ``winreg``) so the logic is unit
tested anywhere without compiling, starting processes or touching the registry.

Why a separate process
----------------------
Edge's IE mode only honours the *system* proxy (``winsupport.set_system_proxy``) and HTTPS recording
needs the mitmproxy CA certificate.  Many factory PCs forbid both.  ``RecBrowser.exe`` (source:
``RecBrowser.cs`` next to this file, compiled on first use with the ``csc.exe`` that ships with the
inbox .NET Framework 4.x) hosts the very same Trident / MSHTML engine (``WebBrowser`` control) and
sets the proxy **for its own process only**::

    InternetSetOptionA(NULL, INTERNET_OPTION_PROXY, {dwAccessType=3, "127.0.0.1:PORT", bypass=""})

Nothing is written to the registry or Internet Options, no certificate is needed (the recorder is
started with a catch-all ``--ignore-hosts`` pattern so HTTPS on every port passes through untouched
and only plain ``http://``, the normal case for a LAN intranet site, is recorded).  The exe is always
built 32-bit (``-platform:x86``) so the 32-bit ActiveX controls of legacy pages load, as in IE mode.  The bypass list is deliberately **empty**:
``<local>`` would exclude dotless host names such as ``http://kanri/`` from the recording.  Popups
(``window.open``, ``target=_blank``, ``showModalDialog`` ...) open as tabs inside the same process,
so their traffic is recorded too.

Build cache
-----------
``ensure_built(workdir)`` compiles to ``<workdir>/bin/RecBrowser.exe`` and stores the SHA-256 of
the source in ``<workdir>/bin/RecBrowser.cs.sha256``; it recompiles only when the exe is missing,
the hash differs (reqrec was updated) or ``force=True``.  Without ``csc.exe`` a prebuilt
``RecBrowser.exe`` next to the source is copied instead.

Document mode
-------------
Without a ``FEATURE_BROWSER_EMULATION`` entry the hosted control runs in IE7 mode (what IE mode
does for Compatibility-View intranet sites).  :func:`set_emulation` writes the per-user value
``HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BROWSER_EMULATION\\RecBrowser.exe``
(``11000`` = IE11 mode); this is the only registry value this module ever touches and it affects
nothing but ``RecBrowser.exe``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Callable, Optional

from ..winsupport import NOT_WINDOWS_MESSAGE, is_windows

__all__ = [
    "SOURCE_PATH", "EXE_NAME", "HASH_NAME", "EMULATION_LEVELS", "EMULATION_LABELS",
    "FEATURE_BROWSER_EMULATION_KEY", "IEHostError", "BrowserProcess",
    "csc_path", "is_available", "availability", "exe_path", "build_command", "ensure_built",
    "launch", "set_emulation", "get_emulation", "resolve_emulation", "BUILD_PLATFORM",
]

#: C# source of the recording browser (packaged with reqrec; see pyproject ``package-data``).
SOURCE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RecBrowser.cs")

#: Name of the compiled host; also the value name FEATURE_BROWSER_EMULATION looks up.
EXE_NAME = "RecBrowser.exe"

#: File next to the exe holding the SHA-256 of the source it was built from.
HASH_NAME = "RecBrowser.cs.sha256"

#: Registry path (under HKEY_CURRENT_USER) of the per-executable document-mode override.
FEATURE_BROWSER_EMULATION_KEY = r"Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION"

#: Document-mode presets for :func:`set_emulation` (``None`` = no override = IE7 mode in the hosted control).
EMULATION_LEVELS: dict[str, Optional[int]] = {
    "default": None,
    "ie8": 8000,
    "ie11": 11000,
    "ie11_force": 11001,
}

#: Japanese labels for the GUI, keyed like :data:`EMULATION_LEVELS`.
EMULATION_LABELS: dict[str, str] = {
    "default": "標準 (IE7 相当・IE モードの互換表示と同じ)",
    "ie8": "IE8 相当",
    "ie11": "IE11 相当 (ページの互換表示指定を尊重)",
    "ie11_force": "IE11 相当 (常に IE11 として表示)",
}

#: ``%WINDIR%``-relative locations of the inbox C# compiler, preferred first (either one builds the
#: 32-bit exe, see :data:`BUILD_PLATFORM`).
_CSC_RELATIVE = (
    os.path.join("Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe"),
    os.path.join("Microsoft.NET", "Framework", "v4.0.30319", "csc.exe"),
)

_CSC_TIMEOUT = 120.0
_TASKKILL_TIMEOUT = 10.0
_GRACE_AFTER_TERMINATE = 3.0

_NO_CSC_MESSAGE = (
    "記録用ブラウザを作成するためのコンパイラ (csc.exe) が見つかりません。"
    "Windows 標準の .NET Framework 4.x が入っているパソコンで実行してください。"
)


class IEHostError(RuntimeError):
    """Raised with a Japanese, user-facing message when the recording browser cannot be built or started."""


# --------------------------------------------------------------------------- discovery

def csc_path(exists: Callable[[str], bool] = os.path.isfile, env: Optional[dict] = None) -> Optional[str]:
    """Path of the inbox C# compiler: ``%WINDIR%\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe``
    (then the 32-bit ``Framework`` directory), or ``None`` when neither exists."""
    environ = os.environ if env is None else env
    windir = environ.get("WINDIR") or environ.get("SystemRoot") or environ.get("windir") or r"C:\Windows"
    for rel in _CSC_RELATIVE:
        candidate = os.path.join(windir, rel)
        if exists(candidate):
            return candidate
    return None


def _prebuilt_exe(source: str) -> str:
    """A ready-made ``RecBrowser.exe`` shipped next to the source (``python -m reqrec.iehost build``)."""
    return os.path.join(os.path.dirname(os.path.abspath(source)), EXE_NAME)


def shipped_exe(source: Optional[str] = None, exists: Callable[[str], bool] = os.path.isfile) -> Optional[str]:
    """The prebuilt exe next to the source when it was built from **this** source, else ``None``.

    Run in place (not copied into the work folder): locked-down PCs often allow executables only in
    the folder IT approved (where reqrec / the portable Python lives), not under the user profile.
    A shipped exe without a hash file, or one built from another version, is not used directly.
    """
    src = source or SOURCE_PATH
    exe = _prebuilt_exe(src)
    if not exists(exe):
        return None
    recorded = _read_text(exe + ".sha256")
    current = _build_digest(src)
    if current is None or (recorded and recorded == current):
        return exe
    return None


def build_shipped(run: Callable[..., Any] = subprocess.run, csc: Optional[str] = None, source: Optional[str] = None) -> str:
    """Compile ``RecBrowser.exe`` next to the source (for a distribution folder) and record its source hash.

    ``python -m reqrec.iehost build`` calls this; afterwards every PC that uses this folder runs the
    exe from there and nothing is compiled or written under the user's profile.
    """
    src = source or SOURCE_PATH
    digest = _build_digest(src)
    if digest is None:
        raise IEHostError(f"記録用ブラウザのソースファイルが見つかりません: {src}")
    compiler = csc or csc_path()
    if compiler is None:
        raise IEHostError(_NO_CSC_MESSAGE)
    exe = _prebuilt_exe(src)
    kwargs: dict[str, Any] = {"capture_output": True, "text": True, "errors": "replace", "timeout": _CSC_TIMEOUT}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = run(build_command(compiler, src, exe), **kwargs)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IEHostError(f"記録用ブラウザの作成 (コンパイル) に失敗しました。\n{exc}") from exc
    if getattr(result, "returncode", 1) != 0 or not os.path.isfile(exe):
        output = _run_output(result)
        raise IEHostError("記録用ブラウザの作成 (コンパイル) に失敗しました。" + ("\n" + output if output else ""))
    _write_text(exe + ".sha256", digest)
    return exe


def is_available(
    platform: Optional[str] = None,
    exists: Callable[[str], bool] = os.path.isfile,
    env: Optional[dict] = None,
    source: Optional[str] = None,
) -> bool:
    """Windows **and** (csc.exe found **or** a prebuilt exe next to the source)."""
    if (platform or sys.platform) != "win32":
        return False
    src = source or SOURCE_PATH
    return csc_path(exists=exists, env=env) is not None or bool(exists(_prebuilt_exe(src)))


def exe_path(workdir: str) -> str:
    """``<workdir>/bin/RecBrowser.exe`` (the compiled host lives in the work directory, not in the package)."""
    return os.path.join(workdir, "bin", EXE_NAME)


def _hash_path(workdir: str) -> str:
    return os.path.join(workdir, "bin", HASH_NAME)


def availability(
    workdir: str,
    platform: Optional[str] = None,
    exists: Callable[[str], bool] = os.path.isfile,
    env: Optional[dict] = None,
    source: Optional[str] = None,
) -> dict:
    """``{"available": bool, "reason": str|None, "exe": str|None, "built": bool, ...}`` for the GUI.

    ``reason`` is a Japanese sentence explaining why the recording browser cannot be used (``None``
    when it can); ``exe`` is the path :func:`launch` will run (``None`` when unavailable); ``built``
    tells whether that exe already exists (otherwise the first launch compiles it, a few seconds).
    Also reports ``source``, ``csc`` and ``prebuilt`` for diagnostics.  Never raises.
    """
    src = source or SOURCE_PATH
    exe = exe_path(workdir)
    info: dict[str, Any] = {
        "available": False,
        "reason": None,
        "exe": None,
        "built": False,
        "source": src,
        "csc": None,
        "prebuilt": None,
    }
    if (platform or sys.platform) != "win32":
        info["reason"] = "記録用ブラウザ (IE エンジン) は Windows でのみ使えます。"
        return info
    csc = csc_path(exists=exists, env=env)
    prebuilt = _prebuilt_exe(src)
    info["csc"] = csc
    info["prebuilt"] = prebuilt if exists(prebuilt) else None
    shipped = shipped_exe(src, exists=exists) if info["prebuilt"] else None
    if shipped:
        info.update(available=True, exe=shipped, built=True, shipped=True)
        return info
    info["built"] = bool(exists(exe))
    source_ok = bool(exists(src))
    if info["built"] or info["prebuilt"] or (csc and source_ok):
        info["available"] = True
        info["exe"] = exe
        return info
    if csc is None:
        info["reason"] = _NO_CSC_MESSAGE
    else:
        info["reason"] = f"記録用ブラウザのソースファイルが見つかりません: {src}"
    return info


# --------------------------------------------------------------------------- build

#: Target platform of ``RecBrowser.exe``: always 32-bit, whichever compiler builds it.  Legacy intranet
#: pages load in-process ActiveX controls (report viewers, barcode / printing controls, ...) that
#: mostly exist only as 32-bit DLLs; Edge's IE mode hosts them in a 32-bit content process, and a
#: 64-bit host could not load them at all.  An x86 exe runs on 32- and 64-bit Windows alike (WOW64).
BUILD_PLATFORM = "x86"


def build_command(csc: str, source: str, exe: str) -> list[str]:
    """Exact ``csc`` argv: a 32-bit (``-platform:x86``, see :data:`BUILD_PLATFORM`) GUI executable
    (``winexe``: no console window) with WinForms references.

    The platform does not depend on the compiler :func:`csc_path` picked: the ``Framework64`` and the
    32-bit ``Framework`` csc.exe both emit x86 executables.  The P/Invoke structs use ``IntPtr``
    fields with sequential layout, which is correct for either bitness.
    """
    return [
        csc,
        "-nologo",
        "-target:winexe",
        f"-platform:{BUILD_PLATFORM}",
        "-optimize+",
        f"-out:{exe}",
        "-r:System.dll",
        "-r:System.Windows.Forms.dll",
        "-r:System.Drawing.dll",
        source,
    ]


def _sha256_file(path: str) -> Optional[str]:
    """Hex SHA-256 of a file, ``None`` when it cannot be read."""
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def _build_digest(source: str) -> Optional[str]:
    """What a built exe is checked against: the source **and** the build settings (platform), so a
    change of build options alone (x64 -> x86) also rebuilds an exe that is already there."""
    try:
        with open(source, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    return hashlib.sha256(data + f"\0platform={BUILD_PLATFORM}".encode("ascii")).hexdigest()


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")


def _run_output(result: Any) -> str:
    return f"{getattr(result, 'stdout', '') or ''}\n{getattr(result, 'stderr', '') or ''}".strip()


def ensure_built(
    workdir: str,
    run: Callable[..., Any] = subprocess.run,
    csc: Optional[str] = None,
    force: bool = False,
    source: Optional[str] = None,
) -> str:
    """Compile ``RecBrowser.cs`` into ``<workdir>/bin/RecBrowser.exe`` when needed and return the exe path.

    Compiles when the exe is missing, when ``<workdir>/bin/RecBrowser.cs.sha256`` differs from the
    current source hash, or when ``force`` is set; the hash is written after a successful build.
    ``csc`` defaults to :func:`csc_path`; without a compiler a prebuilt exe next to the source is
    copied instead.  ``run`` is called like ``subprocess.run`` (``capture_output`` / ``text`` /
    ``timeout`` keywords).  Raises :class:`IEHostError` (Japanese prefix + the compiler's output) on
    failure.  Never prints.
    """
    src = source or SOURCE_PATH
    if not force:
        shipped = shipped_exe(src)
        if shipped is not None:
            return shipped  # prebuilt for this version in the distribution folder: run it in place
    exe = exe_path(workdir)
    hash_file = _hash_path(workdir)
    bin_dir = os.path.dirname(exe)
    current_hash = _build_digest(src)
    exe_exists = os.path.isfile(exe)

    if not force and exe_exists:
        if current_hash is None or _read_text(hash_file) == current_hash:
            return exe  # up to date (or the source is gone: trust what we have)

    if current_hash is None:
        if exe_exists:
            return exe
        prebuilt = _prebuilt_exe(src)
        if os.path.isfile(prebuilt):
            return _copy_prebuilt(prebuilt, exe, hash_file, _sha256_file(prebuilt) or "")
        raise IEHostError(f"記録用ブラウザのソースファイルが見つかりません: {src}")

    compiler = csc or csc_path()
    if compiler is None:
        prebuilt = _prebuilt_exe(src)
        if os.path.isfile(prebuilt):
            return _copy_prebuilt(prebuilt, exe, hash_file, current_hash)
        raise IEHostError(_NO_CSC_MESSAGE)

    os.makedirs(bin_dir, exist_ok=True)
    cmd = build_command(compiler, src, exe)
    kwargs: dict[str, Any] = {"capture_output": True, "text": True, "errors": "replace", "timeout": _CSC_TIMEOUT}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = run(cmd, **kwargs)
    except FileNotFoundError:
        raise IEHostError(f"コンパイラが見つかりません: {compiler}") from None
    except subprocess.TimeoutExpired:
        raise IEHostError("記録用ブラウザの作成 (コンパイル) がタイムアウトしました。") from None
    except OSError as exc:
        raise IEHostError(f"コンパイラを実行できません: {exc}") from exc

    output = _run_output(result)
    if getattr(result, "returncode", 1) != 0 or not os.path.isfile(exe):
        hint = ""
        if exe_exists:
            hint = "\n記録用ブラウザが開いたままの場合は、閉じてからもう一度お試しください。"
        raise IEHostError("記録用ブラウザの作成 (コンパイル) に失敗しました。" + hint + ("\n" + output if output else ""))
    _write_text(hash_file, current_hash)
    return exe


def _copy_prebuilt(prebuilt: str, exe: str, hash_file: str, digest: str) -> str:
    os.makedirs(os.path.dirname(exe), exist_ok=True)
    try:
        shutil.copyfile(prebuilt, exe)
    except OSError as exc:
        raise IEHostError(f"記録用ブラウザをコピーできません: {exc}") from exc
    _write_text(hash_file, digest)
    return exe


# --------------------------------------------------------------------------- process

def _wait(proc: Any, timeout: float) -> Optional[int]:
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


class BrowserProcess:
    """A running ``RecBrowser.exe``: ``pid`` / ``exe`` / ``log_path`` / ``started_at`` plus ``poll`` / ``close``.

    ``close()`` is graceful first: on Windows ``taskkill /PID <pid>`` (no ``/F``) posts ``WM_CLOSE``
    so the browser window closes like a user clicking the X; then ``terminate()``, then ``kill()``.
    ``run`` / ``windows`` are injectable for tests.
    """

    def __init__(
        self,
        proc: Any,
        exe: str,
        log_path: str,
        run: Callable[..., Any] = subprocess.run,
        started_at: Optional[float] = None,
        windows: Optional[bool] = None,
    ) -> None:
        self._proc = proc
        self._run = run
        self._windows = is_windows() if windows is None else bool(windows)
        self.pid: int = int(getattr(proc, "pid", 0) or 0)
        self.exe = exe
        self.log_path = log_path
        #: Windows job handle that ends the browser if this process dies (see :func:`kill_on_close_job`).
        self.job_handle: Optional[int] = None
        self.started_at: float = time.time() if started_at is None else float(started_at)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "running" if self.running else f"exited({self.poll()})"
        return f"<BrowserProcess pid={self.pid} {state} exe={self.exe!r}>"

    @property
    def running(self) -> bool:
        """True while the browser process is alive."""
        return self.poll() is None

    @property
    def returncode(self) -> Optional[int]:
        return self.poll()

    def poll(self) -> Optional[int]:
        """Exit code, or ``None`` while running."""
        return self._proc.poll()

    def wait(self, timeout: Optional[float] = None) -> Optional[int]:
        """Wait for the browser to exit; ``None`` on timeout."""
        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def close(self, timeout: float = 5.0) -> Optional[int]:
        """Close the browser window and return its exit code (``None`` if it would not die).

        Order: ``taskkill /PID`` (WM_CLOSE, Windows only) -> wait ``timeout`` -> ``terminate()`` ->
        wait -> ``kill()`` -> wait.  The job handle is released once the process is gone.
        """
        rc = self._close(timeout)
        if rc is not None and self.job_handle:
            _close_handle(self.job_handle)
            self.job_handle = None
        return rc

    def _close(self, timeout: float) -> Optional[int]:
        rc = self.poll()
        if rc is not None:
            return rc
        if self._windows and self.pid:
            try:
                self._run(
                    ["taskkill", "/PID", str(self.pid)],
                    capture_output=True, text=True, errors="replace", timeout=_TASKKILL_TIMEOUT,
                )
            except Exception:  # taskkill missing / refused: fall through to terminate()
                pass
            rc = _wait(self._proc, timeout)
            if rc is not None:
                return rc
        try:
            self._proc.terminate()
        except (ProcessLookupError, OSError):
            pass
        rc = _wait(self._proc, _GRACE_AFTER_TERMINATE)
        if rc is not None:
            return rc
        try:
            self._proc.kill()
        except (ProcessLookupError, OSError):
            pass
        return _wait(self._proc, timeout)


def kill_on_close_job(proc: Any) -> Optional[int]:
    """Put ``proc`` in a Windows job object with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` and return the
    job handle (``None`` when unsupported or it failed — never raises).

    The handle stays open in this (GUI) process; if the GUI dies without cleaning up (console
    window closed, ended from Task Manager), Windows closes the handle and ends the recording browser
    too, so no orphaned window keeps sending traffic to a proxy port the next session may reuse.
    No setting, file or registry value is involved.
    """
    if not is_windows():
        return None
    handle = getattr(proc, "_handle", None)
    if not handle:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class _IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class _BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimit),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _ExtendedLimit()
        # KILL_ON_JOB_CLOSE | SILENT_BREAKAWAY_OK: only RecBrowser.exe is tied to the GUI; programs it
        # starts (Excel opened from a download, a mail client ...) stay outside the job and survive.
        info.BasicLimitInformation.LimitFlags = 0x2000 | 0x1000
        ok = kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))  # JobObjectExtendedLimitInformation
        if ok:
            ok = kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(int(handle)))
        if not ok:
            kernel32.CloseHandle(job)
            return None
        return int(job)
    except Exception:
        return None


def _close_handle(handle: Optional[int]) -> None:
    if not handle or not is_windows():
        return
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle(wintypes.HANDLE(handle))
    except Exception:
        pass


def _log_file(log_dir: str, now: float) -> str:
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(now))
    path = os.path.join(log_dir, f"recbrowser_{stamp}.log")
    n = 2
    while os.path.exists(path):  # two launches within one second
        path = os.path.join(log_dir, f"recbrowser_{stamp}_{n}.log")
        n += 1
    return path


def launch(
    workdir: str,
    proxy_address: str,
    url: Optional[str] = None,
    title: Optional[str] = None,
    popen: Callable[..., Any] = subprocess.Popen,
    run: Callable[..., Any] = subprocess.run,
    log_dir: Optional[str] = None,
    job: Optional[Callable[[Any], Optional[int]]] = None,
    https_recorded: bool = False,
) -> BrowserProcess:
    """Build if needed, then start the recording browser routed through ``proxy_address`` (``host:port``).

    argv: ``RecBrowser.exe --proxy <addr> --bypass "" --log <workdir>/logs/recbrowser_<timestamp>.log
    [--url <url>] [--title <title>]``.  The bypass list is empty on purpose (see module docstring).
    ``run`` is used for the compiler and later for ``taskkill`` in :meth:`BrowserProcess.close`.
    Raises :class:`IEHostError` when the exe cannot be built or started.
    """
    proxy_address = (proxy_address or "").strip()
    if not proxy_address:
        raise ValueError("プロキシのアドレス (host:port) を指定してください")
    exe = ensure_built(workdir, run=run)
    logs = log_dir or os.path.join(workdir, "logs")
    try:
        os.makedirs(logs, exist_ok=True)
    except OSError as exc:
        raise IEHostError(f"ログ用フォルダを作成できません: {exc}") from exc
    started_at = time.time()
    log_path = _log_file(logs, started_at)
    argv = [exe, "--proxy", proxy_address, "--bypass", "", "--log", log_path]
    if url:
        argv += ["--url", str(url)]
    if title:
        argv += ["--title", str(title)]
    if https_recorded:  # the recorder intercepts HTTPS (certificate installed): no "https is not recorded" notices
        argv += ["--https"]
    try:
        proc = popen(
            argv,
            cwd=os.path.dirname(exe),
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise IEHostError(f"記録用ブラウザを起動できません: {exc}") from exc
    binder = job if job is not None else (kill_on_close_job if popen is subprocess.Popen else None)
    job_handle = binder(proc) if binder is not None else None
    browser = BrowserProcess(proc, exe, log_path, run=run, started_at=started_at)
    browser.job_handle = job_handle
    return browser


# --------------------------------------------------------------------------- document mode (registry)

def _winreg(injected: Any) -> Any:
    """The injected fake or the real ``winreg`` module; :class:`IEHostError` on other OSes."""
    if injected is not None:
        return injected
    if not is_windows():
        raise IEHostError(NOT_WINDOWS_MESSAGE)
    import winreg  # noqa: WPS433 - Windows only

    return winreg


def resolve_emulation(level: Any) -> Optional[int]:
    """Accept a preset name (``"ie11"``), an int (``11000``) or ``None`` and return the DWORD (or ``None``)."""
    if level is None:
        return None
    if isinstance(level, str):
        key = level.strip().lower()
        if key in EMULATION_LEVELS:
            return EMULATION_LEVELS[key]
        if not key or not key.isdigit():
            raise ValueError(f"表示モードの指定が不正です: {level!r}")
        level = int(key)
    if isinstance(level, bool) or not isinstance(level, int) or level < 0:
        raise ValueError(f"表示モードの指定が不正です: {level!r}")
    return level


def set_emulation(level: Optional[int], exe_name: str = EXE_NAME, winreg: Any = None) -> None:
    """Write (or, for ``None``, delete) the ``FEATURE_BROWSER_EMULATION`` DWORD for ``exe_name`` under HKCU.

    Only this one per-user value is touched; it affects nothing but the named executable.
    """
    value = resolve_emulation(level)
    reg = _winreg(winreg)
    access = reg.KEY_READ | reg.KEY_SET_VALUE
    if value is None:
        # read-only first: on the default path nothing is opened for writing unless a value exists
        # (some security products guard this key and refuse write access)
        if get_emulation(exe_name, winreg=reg) is None:
            return
        try:
            key = reg.OpenKey(reg.HKEY_CURRENT_USER, FEATURE_BROWSER_EMULATION_KEY, 0, access)
        except FileNotFoundError:
            return  # key absent: nothing to delete
        with key:
            try:
                reg.DeleteValue(key, exe_name)
            except FileNotFoundError:
                pass
            except OSError as exc:  # pragma: no cover - other registry errors
                if getattr(exc, "winerror", None) != 2:
                    raise
        return
    with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, FEATURE_BROWSER_EMULATION_KEY, 0, access) as key:
        reg.SetValueEx(key, exe_name, 0, reg.REG_DWORD, int(value))


def get_emulation(exe_name: str = EXE_NAME, winreg: Any = None) -> Optional[int]:
    """Current ``FEATURE_BROWSER_EMULATION`` DWORD for ``exe_name`` (``None`` when not set)."""
    reg = _winreg(winreg)
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, FEATURE_BROWSER_EMULATION_KEY, 0, reg.KEY_READ)
    except FileNotFoundError:
        return None
    with key:
        try:
            value, _type = reg.QueryValueEx(key, exe_name)
        except FileNotFoundError:
            return None
        except OSError as exc:  # pragma: no cover - other registry errors
            if getattr(exc, "winerror", None) == 2:
                return None
            raise
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
