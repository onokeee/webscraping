"""Per-process state of the GUI and the helpers the routes build on.  Contract: DESIGN.md §13.6.

* :class:`AppState` - the loaded recording, the current plan / options, the recorder, the script
  runner and the Windows proxy backup, guarded by one re-entrant lock.
* :func:`safe_name` / :meth:`AppState.path_in` - the **only** way a client-supplied name becomes a
  path (always inside the right ``workdir`` sub-folder).
* :func:`plan_options_from_json` / :func:`gen_options_from_json` - whitelist + coerce the option
  objects the browser sends.
* :class:`ScriptRunner` - runs a saved script in a subprocess with live stdout / stderr buffers.
* :func:`load_sources` / :func:`exclude_netlocs` - load & merge recordings, drop the GUI's own traffic.

Everything user-facing raises :class:`ApiError` with a Japanese message and an HTTP status.
"""

from __future__ import annotations

import dataclasses
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import types
import typing
from collections import deque
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlsplit

from .. import importers
from ..model import GenOptions, Plan, PlanOptions, Recording
from ..recorder.manager import RecorderManager

__all__ = [
    "ApiError", "AppState", "ScriptRunner", "SUBDIRS",
    "safe_name", "plan_options_from_json", "gen_options_from_json", "options_to_plain",
    "load_sources", "exclude_netlocs", "normalise_netloc", "RECORDING_EXTENSIONS",
]

#: Sub-folders of ``workdir`` (created on start-up).
SUBDIRS = ("recordings", "uploads", "scripts", "outputs")

#: What the upload / open endpoints accept (``importers.load_recording`` dispatches on these).
RECORDING_EXTENSIONS = frozenset({".har", ".json", ".mitm", ".flows", ".flow"})

#: File names coming from the browser must match this after basename reduction.
_NAME_RE = re.compile(r"^[\w.\-]+$", re.UNICODE)
#: Characters that are replaced by ``_`` when *sanitising* an uploaded file name.
_UNSAFE_CHAR_RE = re.compile(r"[^\w.\-]", re.UNICODE)
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_HTML_PARSERS = ("html.parser", "lxml")
_TRUE_WORDS = {"1", "true", "yes", "on", "y", "t"}
_FALSE_WORDS = {"0", "false", "no", "off", "n", "f", ""}


class ApiError(Exception):
    """An error reported to the browser as ``{"error": message}`` with ``status``."""

    def __init__(self, message: str, status: int = 400, **extra: Any) -> None:
        super().__init__(message)
        self.message = message
        self.status = int(status)
        self.extra = extra

    def to_dict(self) -> dict[str, Any]:
        data = {"error": self.message}
        data.update(self.extra)
        return data


# --------------------------------------------------------------------------- names & paths

def safe_name(name: Any, what: str = "ファイル名") -> str:
    """Validate a client-supplied file name.

    Accepts only a bare name made of word characters, ``.`` and ``-`` (``^[\\w.\\-]+$``); rejects
    empty names, ``.``/``..``, hidden names (leading ``.``), anything containing a path separator
    (``/``, ``\\``) or a drive / NUL character.  Returns the name unchanged.
    """
    if not isinstance(name, str):
        raise ApiError(f"{what}が指定されていません")
    candidate = name.strip()
    if not candidate:
        raise ApiError(f"{what}が指定されていません")
    if len(candidate) > 200:
        raise ApiError(f"{what}が長すぎます (200 文字まで)")
    if "/" in candidate or "\\" in candidate or "\x00" in candidate or ":" in candidate:
        raise ApiError(f"{what}にフォルダ区切りやドライブ名は使えません: {candidate}")
    if candidate in (".", "..") or candidate.startswith("."):
        raise ApiError(f"{what}が不正です: {candidate}")
    if not _NAME_RE.match(candidate):
        raise ApiError(f"{what}に使えない文字が含まれています (英数字 . - _ のみ): {candidate}")
    return candidate


def sanitise_upload_name(filename: Any, default: str = "upload") -> str:
    """Reduce an uploaded file's name to something :func:`safe_name` accepts (never raises)."""
    base = os.path.basename(str(filename or "").replace("\\", "/")).strip()
    base = re.sub(r"_+", "_", _UNSAFE_CHAR_RE.sub("_", base)).strip("._ ") or default
    if base in (".", ".."):
        base = default
    try:
        return safe_name(base)
    except ApiError:  # pragma: no cover - the substitutions above make this unreachable
        return default


def _ensure_within(path: str, root: str) -> str:
    """``path`` resolved, guaranteed to be inside ``root`` (defence in depth after ``safe_name``)."""
    real_root = os.path.realpath(root)
    real_path = os.path.realpath(path)
    if real_path != real_root and not real_path.startswith(real_root + os.sep):
        raise ApiError("作業フォルダの外は参照できません", status=403)
    return real_path


def unique_path(path: str) -> str:
    """``x.har`` -> ``x_2.har`` ... when the file already exists."""
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    for n in range(2, 10000):
        candidate = f"{stem}_{n}{ext}"
        if not os.path.exists(candidate):
            return candidate
    raise ApiError("同名のファイルが多すぎます", status=409)


# --------------------------------------------------------------------------- option coercion

def _to_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _TRUE_WORDS:
            return True
        if v in _FALSE_WORDS:
            return False
    if value is None:
        return False
    raise ApiError(f"オプション {name} は true / false で指定してください")


def _to_int(value: Any, name: str, minimum: Optional[int] = None) -> int:
    if isinstance(value, bool):
        value = int(value)
    try:
        if isinstance(value, str):
            value = value.strip()
        n = int(value)
    except (TypeError, ValueError):
        raise ApiError(f"オプション {name} は整数で指定してください") from None
    if minimum is not None and n < minimum:
        raise ApiError(f"オプション {name} は {minimum} 以上で指定してください")
    return n


def _to_float(value: Any, name: str, minimum: Optional[float] = None) -> float:
    try:
        if isinstance(value, str):
            value = value.strip()
        f = float(value)
    except (TypeError, ValueError):
        raise ApiError(f"オプション {name} は数値で指定してください") from None
    if f != f or f in (float("inf"), float("-inf")):
        raise ApiError(f"オプション {name} は数値で指定してください")
    if minimum is not None and f < minimum:
        raise ApiError(f"オプション {name} は {minimum:g} 以上で指定してください")
    return f


def _to_str_list(value: Any, name: str) -> list[str]:
    """``["a", "b"]`` / ``"a, b"`` / ``None`` -> stripped, de-duplicated list."""
    if value is None:
        return []
    if isinstance(value, str):
        items: Iterable[Any] = re.split(r"[,\s;]+", value)
    elif isinstance(value, (list, tuple, set)):
        items = value
    else:
        raise ApiError(f"オプション {name} は文字列の配列で指定してください")
    out: list[str] = []
    for item in items:
        if item is None:
            continue
        s = str(item).strip()
        if s and s not in out:
            out.append(s)
    return out


def _is_empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip()) or (isinstance(value, (list, tuple)) and not value)


def _coerce_field(cls: type, field: dataclasses.Field, value: Any, hints: dict[str, Any]) -> Any:
    name = field.name
    hint = hints.get(name)
    origin = typing.get_origin(hint)
    args = typing.get_args(hint)
    optional = origin in (typing.Union, types.UnionType) and type(None) in args
    inner = next((a for a in args if a is not type(None)), hint) if optional else hint
    inner_origin = typing.get_origin(inner)

    if inner is bool:
        return _to_bool(value, name)
    if inner_origin is list or inner is list:
        items = _to_str_list(value, name)
        if optional and not items:
            return None
        return items
    if optional and _is_empty(value):
        return None
    if inner is int:
        return _to_int(value, name, minimum=1 if name in ("min_value_length", "max_steps") else None)
    if inner is float:
        return _to_float(value, name, minimum=0.0)
    if inner is str:
        s = str(value).strip()
        if name == "html_parser":
            if s not in _HTML_PARSERS:
                raise ApiError(f"HTML パーサーは {' / '.join(_HTML_PARSERS)} のどちらかを指定してください")
        return s
    return value  # pragma: no cover - no other field types exist in model.py


def _options_from_json(cls: type, data: Any, what: str):
    if data is None:
        return cls()
    if not isinstance(data, dict):
        raise ApiError(f"{what} はオブジェクトで指定してください")
    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for field in dataclasses.fields(cls):
        if field.name in data:
            kwargs[field.name] = _coerce_field(cls, field, data[field.name], hints)
    return cls(**kwargs)


def plan_options_from_json(data: Any) -> PlanOptions:
    """``PlanOptions`` from the JSON the browser sends (unknown keys ignored, types coerced)."""
    return _options_from_json(PlanOptions, data, "plan_options")


def gen_options_from_json(data: Any) -> GenOptions:
    """``GenOptions`` from the JSON the browser sends (unknown keys ignored, types coerced)."""
    return _options_from_json(GenOptions, data, "gen_options")


def options_to_plain(opts: Any) -> dict[str, Any]:
    return dataclasses.asdict(opts)


# --------------------------------------------------------------------------- recordings

def normalise_netloc(netloc: str, scheme: str = "http") -> str:
    """``LOCALHOST:80`` -> ``localhost`` (default ports dropped, lower-case, IPv6 brackets kept)."""
    n = (netloc or "").strip().lower()
    if not n:
        return ""
    default = {"http": ":80", "https": ":443"}.get((scheme or "http").lower())
    if default and n.endswith(default):
        n = n[: -len(default)]
    return n


def gui_netlocs(host: str, port: int, request_host: Optional[str] = None) -> set[str]:
    """Every ``host[:port]`` spelling a browser could use to reach this GUI."""
    out: set[str] = set()
    hosts = {"127.0.0.1", "localhost", "[::1]"}
    h = (host or "").strip().lower()
    if h and h not in ("0.0.0.0", "::", "*", "[::]"):
        hosts.add(h if ":" not in h or h.startswith("[") else f"[{h}]")
    for name in hosts:
        out.add(normalise_netloc(f"{name}:{int(port)}"))
    if request_host:
        out.add(normalise_netloc(request_host))
    return {n for n in out if n}


def exclude_netlocs(recording: Recording, netlocs: set[str]) -> tuple[Recording, int]:
    """Drop every flow whose request host[:port] is one of ``netlocs`` (the GUI itself) and
    re-number the rest.  Returns ``(recording, removed_count)``; untouched when nothing matched."""
    if not netlocs or not recording.flows:
        return recording, 0
    keep = []
    removed = 0
    for flow in recording.flows:
        parts = urlsplit(flow.request.url)
        if normalise_netloc(parts.netloc, parts.scheme) in netlocs:
            removed += 1
        else:
            keep.append(flow)
    if not removed:
        return recording, 0
    trimmed = Recording.merge([Recording(flows=keep, meta=dict(recording.meta))])
    trimmed.meta = dict(recording.meta)
    trimmed.meta["excluded_self_flows"] = int(trimmed.meta.get("excluded_self_flows", 0)) + removed
    return trimmed, removed


def _load_recordings(paths: list[str]) -> Recording:
    """``importers.load_recordings`` when the importer provides it, else load + ``Recording.merge``."""
    loader = getattr(importers, "load_recordings", None)
    if callable(loader):
        return loader(list(paths))
    if len(paths) == 1:
        return importers.load_recording(paths[0])
    return Recording.merge([importers.load_recording(p) for p in paths])


def load_sources(paths: list[str]) -> Recording:
    """Load one or more recording files into a single ``Recording`` (merged when several).

    Import problems become :class:`ApiError` (400) with the importer's Japanese message.
    """
    if not paths:
        raise ApiError("読み込むファイルが指定されていません")
    try:
        return _load_recordings(paths)
    except ImportError as exc:  # .mitm without mitmproxy
        raise ApiError(str(exc)) from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise ApiError(f"記録ファイルを読み込めません: {exc}") from exc
    except OSError as exc:
        raise ApiError(f"ファイルを開けません: {exc}") from exc


# --------------------------------------------------------------------------- script runner

class ScriptRunner:
    """Run one generated script at a time in a subprocess.

    stdout / stderr are read by daemon threads into line ring buffers (``tail``) and, for
    stdout, additionally kept in full up to ``max_output_bytes`` so the user can save the result.
    Secrets arrive as environment variables for the child only; they are never stored or logged.
    """

    def __init__(self, max_lines: int = 2000, max_output_bytes: int = 32 * 1024 * 1024, popen=None) -> None:
        self.max_lines = int(max_lines)
        self.max_output_bytes = int(max_output_bytes)
        self._popen = popen or subprocess.Popen
        self._lock = threading.RLock()
        self._proc: Optional[subprocess.Popen] = None
        self._threads: list[threading.Thread] = []
        self._stdout_tail: deque[str] = deque(maxlen=self.max_lines)
        self._stderr_tail: deque[str] = deque(maxlen=self.max_lines)
        self._stdout_full: list[str] = []
        self._stdout_bytes = 0
        self._stdout_truncated = False
        self.script_path: Optional[str] = None
        self.name: Optional[str] = None
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.exit_code: Optional[int] = None
        self._stop_requested = False

    @property
    def running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def start(self, script_path: str, env: Optional[dict[str, str]] = None, cwd: Optional[str] = None) -> dict[str, Any]:
        with self._lock:
            if self.running:
                raise ApiError("すでにスクリプトを実行中です。終了を待つか [停止] を押してください。", status=409)
            if not os.path.isfile(script_path):
                raise ApiError(f"スクリプトが見つかりません: {os.path.basename(script_path)}", status=404)
            child_env = dict(os.environ)
            child_env["PYTHONIOENCODING"] = "utf-8"
            child_env["PYTHONUNBUFFERED"] = "1"
            for key, value in (env or {}).items():
                if not isinstance(key, str) or not _ENV_NAME_RE.match(key):
                    raise ApiError(f"環境変数名が不正です: {key!r}")
                if value is None:
                    continue
                child_env[key] = str(value)
            cmd = [sys.executable, "-X", "utf8", script_path]
            try:
                proc = self._popen(
                    cmd,
                    cwd=cwd or os.path.dirname(script_path) or None,
                    env=child_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
            except OSError as exc:
                raise ApiError(f"スクリプトを起動できません: {exc}", status=500) from exc
            self._proc = proc
            self.script_path = script_path
            self.name = os.path.basename(script_path)
            self.started_at = time.time()
            self.finished_at = None
            self.exit_code = None
            self._stop_requested = False
            self._stdout_tail = deque(maxlen=self.max_lines)
            self._stderr_tail = deque(maxlen=self.max_lines)
            self._stdout_full = []
            self._stdout_bytes = 0
            self._stdout_truncated = False
            self._threads = [
                threading.Thread(target=self._drain_stdout, args=(proc.stdout,), name="reqrec-run-stdout", daemon=True),
                threading.Thread(target=self._drain_stderr, args=(proc.stderr,), name="reqrec-run-stderr", daemon=True),
            ]
            for t in self._threads:
                t.start()
            return self.status()

    def _drain_stdout(self, stream: Any) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                self._stdout_tail.append(line.rstrip("\r\n"))
                if not self._stdout_truncated:
                    size = len(line.encode("utf-8", "replace"))
                    if self._stdout_bytes + size > self.max_output_bytes:
                        self._stdout_truncated = True
                    else:
                        self._stdout_full.append(line)
                        self._stdout_bytes += size
        except (ValueError, OSError):
            pass
        finally:
            self._finish_if_done()

    def _drain_stderr(self, stream: Any) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                self._stderr_tail.append(line.rstrip("\r\n"))
        except (ValueError, OSError):
            pass
        finally:
            self._finish_if_done()

    def _finish_if_done(self) -> None:
        proc = self._proc
        if proc is None:
            return
        rc = proc.poll()
        if rc is None:
            return
        with self._lock:
            if self.exit_code is None and self._proc is proc:
                self.exit_code = rc
                self.finished_at = time.time()

    def stop(self, timeout: float = 5.0) -> dict[str, Any]:
        with self._lock:
            proc = self._proc
            if proc is None or proc.poll() is not None:
                return self.status()
            self._stop_requested = True
            try:
                proc.terminate()
            except (ProcessLookupError, OSError):
                pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass
                proc.wait()
            self.exit_code = proc.returncode
            self.finished_at = time.time()
            return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            proc = self._proc
            running = proc is not None and proc.poll() is None
            if proc is not None and not running:
                self.exit_code = proc.returncode
                if self.finished_at is None:
                    self.finished_at = time.time()
            return {
                "running": running,
                "exit_code": None if running else self.exit_code,
                "stdout_tail": "\n".join(self._stdout_tail),
                "stderr_tail": "\n".join(self._stderr_tail),
                "started_at": self.started_at,
                "finished_at": None if running else self.finished_at,
                "name": self.name,
                "pid": proc.pid if proc is not None else None,
                "stopped_by_user": self._stop_requested,
                "stdout_truncated": self._stdout_truncated,
                "stdout_bytes": self._stdout_bytes,
            }

    def wait(self, timeout: Optional[float] = None) -> Optional[int]:
        """Block until the child exits (tests / shutdown)."""
        proc = self._proc
        if proc is None:
            return self.exit_code
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        for t in self._threads:
            t.join(2.0)
        with self._lock:
            self.exit_code = rc
            if self.finished_at is None:
                self.finished_at = time.time()
        return rc

    def last_stdout(self) -> str:
        """Everything the last run printed to stdout (bounded by ``max_output_bytes``)."""
        with self._lock:
            return "".join(self._stdout_full)

    def close(self) -> None:
        try:
            self.stop(timeout=2.0)
        except Exception:
            pass


# --------------------------------------------------------------------------- app state

class AppState:
    """Everything the GUI remembers between requests (one instance per Flask app)."""

    def __init__(
        self,
        workdir: str,
        host: str = "127.0.0.1",
        port: int = 8765,
        token: Optional[str] = None,
        recorder: Optional[RecorderManager] = None,
        runner: Optional[ScriptRunner] = None,
    ) -> None:
        self.workdir = os.path.abspath(workdir)
        self.host = host
        self.port = int(port)
        self.token = token or secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.recording: Optional[Recording] = None
        self.sources: list[str] = []
        self.plan: Optional[Plan] = None
        self.plan_options = PlanOptions()
        self.gen_options = GenOptions()
        self.last_code: Optional[str] = None
        self.last_secrets: list[dict[str, Any]] = []
        self.last_script_name: Optional[str] = None
        self.recorder = recorder or RecorderManager()
        self.runner = runner or ScriptRunner()
        self.proxy_backup: Optional[dict] = None
        self.proxy_server: Optional[str] = None
        self.record_append = False
        #: ``browser`` of the running recording (``"iehost"`` / ``"none"``), ``None`` when idle.
        self.record_browser_kind: Optional[str] = None
        self.record_https_passthrough = True
        #: Screen that started the running recording: ``"easy"`` (かんたん画面) or ``"advanced"``
        #: (詳細設定); ``None`` when idle.  Only an easy-started recording may be stopped automatically
        #: by the easy screen when its recording browser is closed (survives a page reload).
        self.record_origin: Optional[str] = None
        #: Last ``iehost.launch`` failure of this session (e.g. the exe blocked by AppLocker), for the page.
        self.iehost_error: Optional[str] = None
        #: The in-app recording browser (``reqrec.iehost.BrowserProcess``) of the current / last
        #: recording started with ``browser: "iehost"`` (DESIGN.md §13.12); ``None`` otherwise.
        self.browser: Optional[Any] = None
        self.last_message: Optional[str] = None
        self._atexit_registered = False
        self.ensure_dirs()

    # ------------------------------------------------------------------ folders & paths

    def ensure_dirs(self) -> None:
        try:
            for sub in SUBDIRS:
                os.makedirs(os.path.join(self.workdir, sub), exist_ok=True)
        except OSError as exc:
            raise RuntimeError(f"作業フォルダを作成できません: {self.workdir} ({exc})") from exc

    def subdir(self, sub: str) -> str:
        if sub not in SUBDIRS:
            raise ApiError(f"不正なフォルダです: {sub}")
        path = os.path.join(self.workdir, sub)
        os.makedirs(path, exist_ok=True)
        return path

    def path_in(self, sub: str, name: Any, what: str = "ファイル名") -> str:
        """Absolute path of ``workdir/<sub>/<name>`` for a validated client name (never outside)."""
        folder = self.subdir(sub)
        clean = safe_name(name, what)
        return _ensure_within(os.path.join(folder, clean), folder)

    def list_files(self, sub: str, extensions: Optional[Iterable[str]] = None) -> list[dict[str, Any]]:
        folder = self.subdir(sub)
        exts = {e.lower() for e in extensions} if extensions else None
        out: list[dict[str, Any]] = []
        try:
            names = os.listdir(folder)
        except OSError:
            return out
        for name in sorted(names):
            if name.startswith("."):
                continue
            path = os.path.join(folder, name)
            if not os.path.isfile(path):
                continue
            if exts is not None and os.path.splitext(name)[1].lower() not in exts:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            out.append({"name": name, "folder": sub, "size": st.st_size, "mtime": st.st_mtime, "path": path})
        out.sort(key=lambda d: d["mtime"], reverse=True)
        return out

    # ------------------------------------------------------------------ recording

    def set_recording(self, recording: Recording, sources: list[str], append: bool) -> Recording:
        """Replace or merge the current recording; invalidates the plan."""
        with self.lock:
            if append and self.recording is not None and self.recording.flows:
                merged = Recording.merge([self.recording, recording])
                self.recording = merged
                self.sources = list(self.sources) + [s for s in sources if s not in self.sources]
            else:
                self.recording = recording
                self.sources = list(sources)
            self.plan = None
            return self.recording

    def clear_recording(self) -> None:
        with self.lock:
            self.recording = None
            self.sources = []
            self.plan = None
            self.last_code = None
            self.last_secrets = []

    def require_recording(self) -> Recording:
        with self.lock:
            if self.recording is None or not self.recording.flows:
                raise ApiError("記録が読み込まれていません。先に「記録」または「読み込み」で記録ファイルを読み込んでください。", status=409)
            return self.recording

    def recording_summary(self) -> dict[str, Any]:
        with self.lock:
            rec = self.recording
            hosts: list[str] = []
            if rec is not None:
                for flow in rec.flows:
                    h = flow.request.host
                    if h and h not in hosts:
                        hosts.append(h)
            return {
                "loaded": rec is not None,
                "sources": list(self.sources),
                "flows": len(rec.flows) if rec is not None else 0,
                "hosts": hosts[:50],
                "meta": _plain_meta(rec.meta) if rec is not None else None,
                "excluded_self_flows": int(rec.meta.get("excluded_self_flows", 0)) if rec is not None else 0,
            }

    # ------------------------------------------------------------------ Windows proxy

    def register_proxy_restore(self, restore: Callable[[dict], None]) -> None:
        """Make sure the system proxy is put back even if the process dies with Ctrl+C."""
        if self._atexit_registered:
            return
        import atexit

        def _restore_at_exit() -> None:
            backup = self.proxy_backup
            if backup is None:
                return
            try:
                restore(backup)
            except Exception:
                pass
            self.proxy_backup = None

        atexit.register(_restore_at_exit)
        self._atexit_registered = True

    # ------------------------------------------------------------------ recording browser

    def close_browser(self, timeout: float = 5.0) -> Optional[int]:
        """Close the in-app recording browser (if any) and forget it; returns its exit code.

        Never raises: a browser that cannot be closed is still dropped from the state so the GUI
        is not stuck with it.  ``None`` when there was no browser or it did not exit in time.
        """
        browser = self.browser
        if browser is None:
            return None
        self.browser = None
        try:
            return browser.close(timeout=timeout)
        except Exception:
            return None

    # ------------------------------------------------------------------ shutdown

    def close(self) -> None:
        self.close_browser()
        self.recorder.close()
        self.runner.close()


def _plain_meta(meta: dict[str, Any]) -> dict[str, Any]:
    """Recording meta reduced to JSON-safe scalars (nested ``sources`` of a merge included)."""
    out: dict[str, Any] = {}
    for k, v in meta.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, list):
            out[k] = [_plain_meta(x) if isinstance(x, dict) else str(x) for x in v]
        elif isinstance(v, dict):
            out[k] = _plain_meta(v)
        else:
            out[k] = str(v)
    return out


# --------------------------------------------------------------------------- free port (かんたんモード)

def find_free_port(host: str = "127.0.0.1", preferred: int = 8080, avoid: Iterable[int] = (), attempts: int = 40) -> int:
    """A TCP port the recording proxy can bind: ``preferred`` first, then the following ports,
    finally one chosen by the OS.  Ports in ``avoid`` (the GUI's own) are skipped.

    The easy mode uses this so the user never has to know what a port is.
    """
    import socket

    skip = {int(p) for p in avoid}
    bind_host = "127.0.0.1" if host in ("0.0.0.0", "", "*") else host
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    for port in range(int(preferred), int(preferred) + max(1, int(attempts))):
        if port in skip or not 1 <= port <= 65535:
            continue
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((bind_host, port))
            except OSError:
                continue
            return port
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((bind_host, 0))
        return int(sock.getsockname()[1])
