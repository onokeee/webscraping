"""Spawn mitmdump with the reqrec addon.  Contract: DESIGN.md §3.

``run_record`` prints Japanese instructions (proxy address, CA certificate, Ctrl+C), starts
``mitmdump -s addon.py --set reqrec_out=... [--set reqrec_hosts=...] -p PORT --listen-host HOST``
as a child process and turns the user's Ctrl+C into a graceful shutdown of the child (which gives
the addon the chance to run its final flush).
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import signal
import subprocess
import sys
from typing import Iterable, Optional, Sequence, Union

from ..importers.mitm import MITMPROXY_INSTALL_HINT
from .addon import parse_hosts

__all__ = [
    "ADDON_PATH", "MITMDUMP_PYTHON_STUB", "mitmproxy_available", "mitmdump_launcher",
    "build_command", "format_instructions", "run_record", "stop_child",
]

#: Absolute path of the addon file passed to ``mitmdump -s``.
ADDON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "addon.py")

#: ``mitmproxy.tools.main`` has no ``__main__`` guard, so ``python -m mitmproxy.tools.main`` does
#: nothing; the documented programmatic entry point is the ``mitmdump()`` function.
MITMDUMP_PYTHON_STUB = "import sys; from mitmproxy.tools.main import mitmdump; sys.exit(mitmdump())"

_GRACE_FIRST_WAIT = 1.5  # seconds: the child usually got the terminal's SIGINT as well
_GRACE_AFTER_SIGINT = 10.0
_GRACE_AFTER_TERMINATE = 5.0


# --------------------------------------------------------------------------- discovery

def mitmproxy_available() -> bool:
    """True when either a ``mitmdump`` executable or the ``mitmproxy`` package can be found."""
    if shutil.which("mitmdump"):
        return True
    try:
        return importlib.util.find_spec("mitmproxy") is not None
    except (ImportError, ValueError):  # pragma: no cover - broken sys.modules entry
        return False


def mitmdump_launcher() -> list[str]:
    """Command prefix that runs mitmdump: the ``mitmdump`` executable when on PATH, otherwise the
    current interpreter calling ``mitmproxy.tools.main.mitmdump()``."""
    exe = shutil.which("mitmdump")
    if exe:
        return [exe]
    return [sys.executable, "-c", MITMDUMP_PYTHON_STUB]


# --------------------------------------------------------------------------- command line

def build_command(
    out: str,
    port: int = 8080,
    hosts: Union[None, str, Iterable[str]] = None,
    listen_host: str = "127.0.0.1",
    quiet: bool = True,
    extra_args: Sequence[str] = (),
) -> list[str]:
    """Full ``mitmdump`` argument vector for a recording session.

    * ``out`` is made absolute (mitmdump's cwd is ours, but absolute paths survive ``--set`` quoting).
    * ``hosts`` (list or comma-separated string) becomes ``--set reqrec_hosts=a,b``; omitted when empty
      (= record every host).
    * ``quiet`` suppresses mitmdump's own per-flow dump (``flow_detail=0``) while keeping the addon's
      one-line-per-recorded-flow log and mitmproxy warnings (e.g. TLS handshake failures when the CA
      certificate is not installed yet) visible.
    * ``extra_args`` are appended verbatim (e.g. ``["--ssl-insecure"]`` or ``["--mode", "upstream:..."]``).
    """
    cmd = mitmdump_launcher()
    cmd += ["-s", ADDON_PATH, "--set", f"reqrec_out={os.path.abspath(out)}"]
    host_list = parse_hosts(hosts)
    if host_list:
        cmd += ["--set", "reqrec_hosts=" + ",".join(host_list)]
    cmd += ["-p", str(int(port)), "--listen-host", str(listen_host)]
    if quiet:
        cmd += ["--set", "flow_detail=0"]
    cmd += [str(a) for a in extra_args]
    return cmd


def format_instructions(out: str, port: int, hosts: Sequence[str], listen_host: str) -> str:
    """Japanese how-to shown before mitmdump starts."""
    if listen_host in ("0.0.0.0", "::", "", "*"):
        proxy_addr = f"http://<このPCのIPアドレス>:{port}  (全インターフェースで待ち受け中)"
    else:
        proxy_addr = f"http://{listen_host}:{port}"
    scope = ", ".join(hosts) if hosts else "すべてのホスト (絞り込みなし)"
    ca_path = os.path.join("~", ".mitmproxy", "mitmproxy-ca-cert.pem")
    lines = [
        "=" * 64,
        " reqrec 記録モード (mitmproxy)",
        "=" * 64,
        f"プロキシのアドレス : {proxy_addr}",
        f"記録対象ホスト     : {scope}",
        f"出力ファイル       : {out}",
        "",
        "手順:",
        "  1. ブラウザ (または OS) の HTTP/HTTPS プロキシを上記のアドレスに設定します。",
        "     例 (Chrome を専用プロファイルで起動):",
        f'       chrome --proxy-server="{listen_host or "127.0.0.1"}:{port}" --user-data-dir=/tmp/reqrec-profile',
        "  2. 初回のみ mitmproxy の CA 証明書を信頼済みルート証明書として登録します。",
        f"       - {ca_path}  (プロキシ初回起動時に自動生成されます)",
        "       - または、プロキシ経由で http://mitm.it を開いてダウンロード",
        "     ※ 登録しないと HTTPS サイトで証明書エラーになり記録できません。",
        "  3. ブラウザで記録したい操作を行います。レスポンスを受け取るごとに自動保存されます。",
        "  4. 終了するには Ctrl+C を押してください (保存してから終了します)。",
        "-" * 64,
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- running

def run_record(
    out: str,
    port: int = 8080,
    hosts: Optional[list[str]] = None,
    listen_host: str = "127.0.0.1",
    quiet: bool = True,
    extra_args: Sequence[str] = (),
) -> int:
    """Run a recording session; returns a process exit code.

    * ``0`` when the session was stopped with Ctrl+C and the recording file exists.
    * ``1`` when mitmproxy is not installed (an install hint is printed), the child could not be
      started, or nothing was written.
    * otherwise the child's own exit code.
    """
    host_list = parse_hosts(hosts)
    if not mitmproxy_available():
        print(MITMPROXY_INSTALL_HINT, file=sys.stderr)
        return 1

    out_abs = os.path.abspath(out)
    try:
        os.makedirs(os.path.dirname(out_abs) or ".", exist_ok=True)
    except OSError as exc:
        print(f"出力先ディレクトリを作成できません / cannot create output directory: {exc}", file=sys.stderr)
        return 1

    cmd = build_command(out_abs, port=port, hosts=host_list, listen_host=listen_host, quiet=quiet, extra_args=extra_args)
    print(format_instructions(out_abs, port, host_list, listen_host), flush=True)

    try:
        proc = subprocess.Popen(cmd)
    except OSError as exc:
        print(f"mitmdump を起動できません / failed to start mitmdump: {exc}", file=sys.stderr)
        print(MITMPROXY_INSTALL_HINT, file=sys.stderr)
        return 1

    interrupted = False
    try:
        returncode = proc.wait()
    except KeyboardInterrupt:
        interrupted = True
        print("\n停止しています... (記録を保存中) / stopping...", flush=True)
        returncode = stop_child(proc)

    _print_summary(out_abs)
    if interrupted:
        if os.path.exists(out_abs):
            return 0
        print("記録ファイルが作成されませんでした / no recording file was written", file=sys.stderr)
        return 1
    return returncode


def stop_child(proc: subprocess.Popen, grace: float = _GRACE_AFTER_SIGINT) -> int:
    """Shut the mitmdump child down gracefully after Ctrl+C and return its exit code.

    Order: wait briefly (the terminal normally delivered SIGINT to the child as well) -> SIGINT
    (``terminate`` on Windows) -> ``terminate`` -> ``kill``.  A second Ctrl+C kills immediately.
    """
    try:
        rc = _wait(proc, _GRACE_FIRST_WAIT)
        if rc is not None:
            return rc
        if os.name == "nt":  # no reliable Ctrl+C delivery to a child on Windows
            proc.terminate()
        else:
            try:
                proc.send_signal(signal.SIGINT)
            except (ProcessLookupError, OSError):
                pass
        rc = _wait(proc, grace)
        if rc is not None:
            return rc
        proc.terminate()
        rc = _wait(proc, _GRACE_AFTER_TERMINATE)
        if rc is not None:
            return rc
        proc.kill()
        return proc.wait()
    except KeyboardInterrupt:
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
        return proc.wait()


def _wait(proc: subprocess.Popen, timeout: float) -> Optional[int]:
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def _print_summary(out_abs: str) -> None:
    if not os.path.exists(out_abs):
        return
    try:
        from ..model import Recording

        count = len(Recording.load(out_abs).flows)
    except Exception:
        print(f"記録ファイル: {out_abs}", flush=True)
        return
    print(f"記録したフロー: {count} 件 -> {out_abs}", flush=True)
    print("次のステップ: reqrec inspect <記録ファイル> / reqrec generate <記録ファイル> -o scrape.py", flush=True)
