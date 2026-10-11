"""Start / stop / watch a mitmdump recording from the GUI.  Contract: DESIGN.md §13.6 (RecorderManager).

``RecorderManager`` owns at most one child process.  The command line comes from an injectable
``command_builder`` (default :func:`reqrec.recorder.run.build_command`) so tests can substitute a
small Python stub for mitmdump.  The child's stdout / stderr are drained by reader threads into
bounded ring buffers (``status()["stdout_tail"]`` / ``["stderr_tail"]``) so a child that logs a
lot can never block, and the addon's atomically flushed recording file is read to count flows while
the session runs.

Stopping mirrors :func:`reqrec.recorder.run.stop_child`: SIGINT (``CTRL_BREAK_EVENT`` on Windows,
where the child is started in its own process group) -> ``terminate()`` -> ``kill()``.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
from collections import deque
from typing import Any, Callable, Iterable, Optional, Sequence, Union

from ..model import Recording
from .addon import parse_hosts
from .run import build_command

__all__ = ["RecorderError", "RecorderManager", "count_flows_in_file"]

#: Reading a very large recording with ``json.loads`` every second would hurt; above this size a
#: regular expression counts the flow ids instead.
_JSON_COUNT_MAX_BYTES = 24 * 1024 * 1024
_FLOW_ID_RE = re.compile(rb'"id":\s*"f\d{4,}"')

_GRACE_AFTER_TERMINATE = 5.0
_READER_JOIN_TIMEOUT = 2.0

CommandBuilder = Callable[..., Sequence[str]]


class RecorderError(RuntimeError):
    """Raised by :class:`RecorderManager` with a Japanese, user-facing message."""


def count_flows_in_file(path: str, default: int = 0) -> int:
    """Number of flows in a recording JSON file.

    Tolerates a missing or half-written file (the addon writes atomically, but a plain
    ``mitmdump`` run or a foreign tool may not): returns ``default`` whenever the file cannot be
    parsed.  Large files are counted with a regular expression on the raw bytes.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return default
    if not raw:
        return default
    if size > _JSON_COUNT_MAX_BYTES:
        return len(_FLOW_ID_RE.findall(raw))
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        return default
    if not isinstance(data, dict):
        return default
    flows = data.get("flows")
    if isinstance(flows, list):
        return len(flows)
    # a mitmproxy ``-w`` file or a HAR has no "flows"; try the HAR shape before giving up
    log = data.get("log")
    if isinstance(log, dict) and isinstance(log.get("entries"), list):
        return len(log["entries"])
    return default


class RecorderManager:
    """Lifecycle of one recording child process (see module docstring).

    ``command_builder(out, port=..., hosts=[...], listen_host=...)`` must return the argument
    vector to run; it is called with the absolute output path.  ``popen`` is injectable too.
    """

    def __init__(
        self,
        command_builder: Optional[CommandBuilder] = None,
        popen: Optional[Callable[..., subprocess.Popen]] = None,
        max_lines: int = 500,
        stop_timeout: float = 10.0,
    ) -> None:
        self.command_builder: CommandBuilder = command_builder or build_command
        self._popen = popen or subprocess.Popen
        self.max_lines = int(max_lines)
        self.stop_timeout = float(stop_timeout)
        self._lock = threading.RLock()
        self._proc: Optional[subprocess.Popen] = None
        self._threads: list[threading.Thread] = []
        self._stdout: deque[str] = deque(maxlen=self.max_lines)
        self._stderr: deque[str] = deque(maxlen=self.max_lines)
        self._last_count = 0
        self._error: Optional[str] = None
        self._stop_requested = False
        self.command: list[str] = []
        self.out: Optional[str] = None
        self.port: Optional[int] = None
        self.hosts: list[str] = []
        self.listen_host: Optional[str] = None
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self.exit_code: Optional[int] = None

    # ------------------------------------------------------------------ properties

    @property
    def running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    @property
    def pid(self) -> Optional[int]:
        with self._lock:
            return self._proc.pid if self._proc is not None else None

    # ------------------------------------------------------------------ start

    def start(
        self,
        out: str,
        port: int = 8080,
        hosts: Union[None, str, Iterable[str]] = None,
        listen_host: str = "127.0.0.1",
        extra_args: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Spawn the recording process; returns :meth:`status`.

        Raises :class:`RecorderError` when a session is already running, the output directory
        cannot be created or the process fails to start.
        """
        with self._lock:
            if self.running:
                raise RecorderError("すでに記録中です。先に記録を停止してください。")
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                raise RecorderError(f"ポート番号が不正です: {port!r}") from None
            if not 1 <= port_int <= 65535:
                raise RecorderError(f"ポート番号は 1〜65535 で指定してください: {port_int}")
            host_list = parse_hosts(hosts)
            out_abs = os.path.abspath(out)
            try:
                os.makedirs(os.path.dirname(out_abs) or ".", exist_ok=True)
            except OSError as exc:
                raise RecorderError(f"出力先フォルダを作成できません: {exc}") from exc
            kwargs: dict[str, Any] = {}
            if extra_args:
                kwargs["extra_args"] = list(extra_args)
            cmd = [str(c) for c in self.command_builder(out_abs, port=port_int, hosts=host_list, listen_host=listen_host, **kwargs)]
            popen_kwargs: dict[str, Any] = dict(
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            if os.name == "nt":  # own process group so CTRL_BREAK_EVENT reaches only the child
                popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            try:
                proc = self._popen(cmd, **popen_kwargs)
            except OSError as exc:
                raise RecorderError(f"記録プロセスを起動できません: {exc}") from exc
            self._proc = proc
            self.command = cmd
            self.out = out_abs
            self.port = port_int
            self.hosts = host_list
            self.listen_host = listen_host
            self.started_at = time.time()
            self.stopped_at = None
            self.exit_code = None
            self._error = None
            self._stop_requested = False
            self._last_count = 0
            self._stdout = deque(maxlen=self.max_lines)
            self._stderr = deque(maxlen=self.max_lines)
            self._threads = []
            for stream, buf, label in ((proc.stdout, self._stdout, "stdout"), (proc.stderr, self._stderr, "stderr")):
                if stream is None:
                    continue
                t = threading.Thread(target=self._drain, args=(stream, buf), name=f"reqrec-recorder-{label}", daemon=True)
                t.start()
                self._threads.append(t)
            return self.status()

    @staticmethod
    def _drain(stream: Any, buf: deque) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                buf.append(line.rstrip("\r\n"))
        except (ValueError, OSError):  # stream closed while reading
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ stop

    def stop(self, timeout: Optional[float] = None) -> Optional[int]:
        """Stop the child gracefully and return its exit code (``None`` when nothing was running).

        Order: SIGINT / CTRL_BREAK_EVENT (lets the addon flush) -> wait ``timeout`` ->
        ``terminate()`` -> wait -> ``kill()``.
        """
        grace = self.stop_timeout if timeout is None else float(timeout)
        with self._lock:
            proc = self._proc
            if proc is None:
                return self.exit_code
            self._stop_requested = True
            rc = proc.poll()
            if rc is None:
                rc = self._shutdown(proc, grace)
            for t in self._threads:
                t.join(_READER_JOIN_TIMEOUT)
            self._threads = []
            self.exit_code = rc
            self.stopped_at = time.time()
            self._proc = None
            return rc

    @staticmethod
    def _shutdown(proc: subprocess.Popen, grace: float) -> int:
        try:
            if os.name == "nt":
                sig = getattr(signal, "CTRL_BREAK_EVENT", None)
                if sig is not None:
                    proc.send_signal(sig)
                else:  # pragma: no cover - very old Python on Windows
                    proc.terminate()
            else:
                proc.send_signal(signal.SIGINT)
        except (ProcessLookupError, OSError, ValueError):
            pass
        rc = _wait(proc, grace)
        if rc is not None:
            return rc
        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass
        rc = _wait(proc, _GRACE_AFTER_TERMINATE)
        if rc is not None:
            return rc
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
        return proc.wait()

    def close(self) -> None:
        """``stop()`` that never raises (for ``atexit`` / app shutdown)."""
        try:
            self.stop()
        except Exception:
            pass

    # ------------------------------------------------------------------ inspection

    def flow_count(self) -> int:
        """Flows written so far (``0`` before the first flush).  While the file is being replaced
        the previous good count is returned."""
        out = self.out
        if not out:
            return 0
        count = count_flows_in_file(out, default=-1)
        if count < 0:
            return self._last_count
        self._last_count = count
        return count

    def status(self) -> dict[str, Any]:
        """Snapshot for the GUI: ``{running, flows, out, pid, exit_code, started_at, stopped_at,
        port, listen_host, hosts, stdout_tail, stderr_tail, error, command}``."""
        with self._lock:
            proc = self._proc
            running = proc is not None and proc.poll() is None
            exit_code = self.exit_code
            if proc is not None and not running:
                exit_code = proc.returncode
                self.exit_code = exit_code
            stderr_tail = "\n".join(self._stderr)
            stdout_tail = "\n".join(self._stdout)
            error = self._error
            if (not running and not self._stop_requested and self.out is not None
                    and exit_code not in (None, 0) and self.started_at is not None):
                # The child died on its own (port in use, missing dependency, ...): surface why.
                detail = stderr_tail.strip().splitlines()
                last = detail[-1] if detail else ""
                error = f"記録プロセスが終了コード {exit_code} で終了しました" + (f": {last}" if last else "")
            return {
                "running": running,
                "flows": self.flow_count(),
                "out": self.out,
                "out_name": os.path.basename(self.out) if self.out else None,
                "pid": proc.pid if proc is not None else None,
                "exit_code": exit_code,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "port": self.port,
                "listen_host": self.listen_host,
                "hosts": list(self.hosts),
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "error": error,
                "command": list(self.command),
            }

    def load_recording(self) -> Recording:
        """Parse the recording written by the last / current session (``Recording.load``)."""
        if not self.out:
            raise RecorderError("記録ファイルがありません。先に記録を開始してください。")
        if not os.path.exists(self.out):
            raise RecorderError(
                "記録ファイルが作成されませんでした。ブラウザのプロキシ設定を確認し、"
                "記録中にページを 1 つ以上開いてください。"
            )
        try:
            return Recording.load(self.out)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RecorderError(f"記録ファイルを読み込めません: {exc}") from exc


def _wait(proc: subprocess.Popen, timeout: float) -> Optional[int]:
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

