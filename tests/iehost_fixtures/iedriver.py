"""Python wrapper for ``IEDriver.exe`` (source: ``IEDriver.cs`` next to this file) - TEST ONLY.

The driver operates the pages inside a running recording browser (``RecBrowser.exe``) the way a
user would: it finds the IE engine's documents by window handle (WM_HTML_GETOBJECT) and calls DOM
methods on them, so every navigation, popup, POST and dialog is performed by the engine itself and
the recorder sees the real browser's HTTP.

Usage::

    iedriver = <import tests/iehost_fixtures/iedriver.py by path, as tests/test_iedriver.py does>
    exe = iedriver.build_driver(str(tmp_path / "bin"))  # compiles once per source hash
    drv = iedriver.IEDriver(exe, browser_pid)
    drv.wait("/index.html", text="index page")
    drv.click("/index.html", id="lnk")                  # target=_blank -> new tab
    drv.wait("/settings.html")
    proc = drv.click_async("/driver.html", id="modalBtn")   # that click blocks until the modal closes
    drv.wait("/drv_modal.html", kind="dialog")
    drv.click("/drv_modal.html", id="closeBtn", kind="dialog")
    drv.finish(proc)                                    # result of the async click
    drv.dialog(title="ファイルのダウンロード", button="キャンセル")
    drv.close()                                         # -> {"exited": True, "exitCode": 0, ...}

Every method runs the exe once (``subprocess.run`` with a timeout, no console window) and returns
the parsed JSON; a failure (exit code 1 or a timeout) raises :class:`IEDriverError` whose ``result``
holds the driver's JSON (``{"error": ..., "detail": [...documents or dialogs seen...]}``).

Matching: ``url`` is a case-insensitive substring of ``document.URL`` (tabs, dialogs and frames);
``kind="tab"|"dialog"|"frame"`` and ``hwnd=`` narrow it further.  Element commands retry (every
200 ms) until ``timeout`` while the document or the element is not there yet, preferring documents
whose readyState is ``complete``.

Pitfalls (measured on Windows 11 with the IE7-mode recording browser):

* Cost: one call is about 0.2-0.4 s (process start + cross-process COM).  ``IEDriver.cs`` uses plain
  IDispatch late binding on purpose; C# ``dynamic`` made every call 3-8x slower (its COM binder
  reads the MSHTML type library through cross-process ITypeInfo calls in every new process).
* Navigation is asynchronous: ``click`` / ``select`` / ``navigate`` return before the new page is
  loaded, and the old document stays ``complete`` (and may still match a broad ``url``) until it
  is replaced.  Always ``wait`` for a url substring (or ``text``) that only the new page has, e.g.
  ``"kind=b"`` after an autopostback of ``/driver.html``.
* Popups: the new tab exists when the click returns (the host answers NewWindow3 synchronously);
  ``wait`` for its url.  ``navigate`` and real users type into the *selected* tab, which is the
  newest popup.  DOM clicks also work on background (hidden) tabs; the driver never switches tabs.
* Modal blocking: ``element.click()`` returns only when its handler returns, i.e. after an
  ``alert()`` / ``confirm()`` / ``showModalDialog`` it opened has been closed.  Use
  :meth:`IEDriver.click_async`, operate the dialog (``wait(kind="dialog")`` + DOM commands for an
  HTML dialog, :meth:`IEDriver.dialog` for a standard box), then :meth:`IEDriver.finish`.  A plain
  ``click`` on such a button hangs until the wrapper's timeout (``timeout`` + 15 s), and killing the
  driver then leaves the dialog open.  While a modal dialog is up the main window is disabled and
  ``navigate`` / ``close`` refuse (a user could not use them either).
* Standard dialogs (alert: title 「Web ページからのメッセージ」, button ``OK``; download:
  「ファイルのダウンロード」 with 開く(&O) / 保存(&S) / キャンセル) are matched by title / static text /
  button text with ``&`` removed; titles and captions follow the Windows display language.  The
  download dialog appears 0.3-1.5 s after the click (``dialog`` polls; give it ``timeout=20``).
* Focus: nothing needs the foreground.  DOM calls and WM_HTML_GETOBJECT work on background or
  hidden windows; ``dialog`` presses buttons with WM_COMMAND/BN_CLICKED posted to the dialog
  (``method="bmclick"`` posts BM_CLICK instead, which Windows may ignore for an inactive dialog).
  RecBrowser's windows still pop up on screen, and a person clicking in them can interfere.
* ``navigate`` sets the text of RecBrowser's address box (its only WinForms EDIT) and sends Enter;
  call it when the selected tab is idle (after a ``wait``).  The engine sends no Referer for it,
  like a typed address, while link clicks / form posts carry one.
* From Git Bash, run the exe with ``MSYS_NO_PATHCONV=1``: otherwise ``--url /index.html`` is
  rewritten to a Windows path.  The JSON output is pure ASCII (``\\uXXXX``), so console code pages
  do not matter.

Importing this module has no side effects.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from typing import Any, Optional, Sequence

__all__ = ["DRIVER_SOURCE", "CSC", "IEDriverError", "build_command", "build_driver", "IEDriver"]

#: C# source of the driver.
DRIVER_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "IEDriver.cs")

#: Inbox C# 5 compiler (.NET Framework 4.x, 64-bit).
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

EXE_NAME = "IEDriver.exe"
HASH_NAME = "IEDriver.cs.sha256"

#: Extra seconds the Python side waits on top of the driver's own ``--timeout`` before killing it.
_MARGIN = 15.0
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class IEDriverError(RuntimeError):
    """The driver reported a failure (or hung).  ``result`` is its JSON (may be ``None``)."""

    def __init__(self, message: str, result: Any = None, argv: Optional[Sequence[str]] = None) -> None:
        super().__init__(message)
        self.result = result
        self.argv = list(argv or [])


def build_command(csc: str, source: str, exe: str) -> list[str]:
    """csc argv: 64-bit console exe.  Microsoft.CSharp / System.Core are referenced so the source may use
    ``dynamic``; it deliberately does not (too slow cross-process, see the module docstring)."""
    return [
        csc, "-nologo", "-target:exe", "-platform:x64", "-optimize+", f"-out:{exe}",
        "-r:System.Windows.Forms.dll", "-r:Microsoft.CSharp.dll", "-r:System.Core.dll", source,
    ]


def _sha256(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def build_driver(out_dir: str, csc: str = CSC, source: str = DRIVER_SOURCE, force: bool = False) -> str:
    """Compile ``IEDriver.cs`` into ``<out_dir>/IEDriver.exe`` unless the cached build matches the
    source's SHA-256 (``<out_dir>/IEDriver.cs.sha256``).  Returns the exe path; raises
    :class:`IEDriverError` with the compiler output on failure."""
    os.makedirs(out_dir, exist_ok=True)
    exe = os.path.join(out_dir, EXE_NAME)
    hash_file = os.path.join(out_dir, HASH_NAME)
    digest = _sha256(source)
    if not force and os.path.isfile(exe) and os.path.isfile(hash_file):
        with open(hash_file, encoding="utf-8") as fh:
            if fh.read().strip() == digest:
                return exe
    if not os.path.isfile(csc):
        raise IEDriverError(f"C# compiler not found: {csc}")
    result = subprocess.run(
        build_command(csc, source, exe), capture_output=True, text=True, errors="replace",
        timeout=180, creationflags=_NO_WINDOW,
    )
    if result.returncode != 0 or not os.path.isfile(exe):
        raise IEDriverError(f"IEDriver.cs failed to compile:\n{result.stdout}\n{result.stderr}")
    with open(hash_file, "w", encoding="utf-8") as fh:
        fh.write(digest + "\n")
    return exe


def _parse(stdout: str) -> Any:
    lines = [line for line in (stdout or "").splitlines() if line.strip()]
    if not lines:
        return None
    try:
        return json.loads(lines[-1])
    except ValueError:
        return None


def _opts(**kwargs: Any) -> list[str]:
    """``foo_bar="x"`` -> ``["--foo-bar", "x"]``; ``None`` values are left out."""
    argv: list[str] = []
    for key, value in kwargs.items():
        if value is None:
            continue
        argv += ["--" + key.replace("_", "-"), str(value)]
    return argv


class IEDriver:
    """Drives the recording browser process ``pid`` through ``exe`` (see module docstring)."""

    def __init__(self, exe: str, pid: int, timeout: float = 30.0) -> None:
        self.exe = exe
        self.pid = int(pid)
        self.timeout = float(timeout)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<IEDriver pid={self.pid} exe={self.exe!r}>"

    # ------------------------------------------------------------------ plumbing

    def argv(self, command: str, *extra: str) -> list[str]:
        return [self.exe, command, "--pid", str(self.pid), *extra]

    def run(self, command: str, *extra: str, timeout: Optional[float] = None, check: bool = True) -> Any:
        """Run one driver command; returns the parsed JSON (raises :class:`IEDriverError` if ``check``)."""
        argv = self.argv(command, *extra)
        limit = (timeout if timeout is not None else self.timeout) + _MARGIN
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, encoding="ascii", errors="replace",
                timeout=limit, creationflags=_NO_WINDOW, stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            raise IEDriverError(f"IEDriver {command} did not finish within {limit:.0f}s", None, argv) from None
        result = _parse(proc.stdout)
        if check and (proc.returncode != 0 or result is None):
            message = result.get("error") if isinstance(result, dict) else (proc.stdout + proc.stderr).strip()
            raise IEDriverError(f"IEDriver {command}: {message}", result, argv)
        return result

    def start(self, command: str, *extra: str) -> subprocess.Popen:
        """Start a driver command without waiting (see :meth:`click_async` / :meth:`finish`)."""
        return subprocess.Popen(
            self.argv(command, *extra), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, creationflags=_NO_WINDOW,
        )

    def finish(self, proc: subprocess.Popen, timeout: float = 30.0, check: bool = True) -> Any:
        """Wait for a command started with :meth:`start` / :meth:`click_async` and return its JSON."""
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise IEDriverError(f"async IEDriver command did not finish within {timeout:.0f}s", None, proc.args) from None
        stdout = out.decode("ascii", "replace")
        result = _parse(stdout)
        if check and (proc.returncode != 0 or result is None):
            message = result.get("error") if isinstance(result, dict) else (stdout + err.decode("ascii", "replace")).strip()
            raise IEDriverError(f"IEDriver (async): {message}", result, proc.args)
        return result

    @staticmethod
    def _filters(kind: Optional[str], hwnd: Optional[int]) -> list[str]:
        return _opts(kind=kind, hwnd=hwnd)

    # ------------------------------------------------------------------ commands

    def list(self, url: Optional[str] = None, kind: Optional[str] = None) -> list[dict]:
        """Every document: ``[{hwnd, kind: tab|dialog|frame, url, title, readyState, visible, ...}]``."""
        return self.run("list", *_opts(url=url, kind=kind))

    def wait(self, url: str = "", text: Optional[str] = None, timeout: float = 30.0,
             kind: Optional[str] = None, hwnd: Optional[int] = None) -> dict:
        """Wait until a document whose url contains ``url`` is complete (and its body contains ``text``)."""
        return self.run("wait", *_opts(url=url, text=text, timeout=timeout), *self._filters(kind, hwnd), timeout=timeout)

    def value(self, url: str, id: str, value: str, fire: Optional[str] = None,
              kind: Optional[str] = None, hwnd: Optional[int] = None, timeout: float = 10.0) -> dict:
        """``element.value = value`` (plain; ``fire="onchange"`` additionally fires that event)."""
        return self.run("value", *_opts(url=url, id=id, value=value, fire=fire, timeout=timeout),
                        *self._filters(kind, hwnd), timeout=timeout)

    def select(self, url: str, id: str, text: Optional[str] = None, value: Optional[str] = None,
               kind: Optional[str] = None, hwnd: Optional[int] = None, timeout: float = 10.0) -> dict:
        """Select the option with ``text`` (exact, then substring) or ``value`` and fire ``onchange``."""
        return self.run("select", *_opts(url=url, id=id, text=text, value=value, timeout=timeout),
                        *self._filters(kind, hwnd), timeout=timeout)

    def _click_args(self, url: str, id: Optional[str], link_text: Optional[str], button_text: Optional[str],
                    kind: Optional[str], hwnd: Optional[int], timeout: float) -> list[str]:
        return [*_opts(url=url, id=id, link_text=link_text, button_text=button_text, timeout=timeout),
                *self._filters(kind, hwnd)]

    def click(self, url: str, id: Optional[str] = None, link_text: Optional[str] = None,
              button_text: Optional[str] = None, kind: Optional[str] = None, hwnd: Optional[int] = None,
              timeout: float = 10.0) -> dict:
        """``element.click()``.  Blocks while the click's handler runs, i.e. until an ``alert`` /
        ``showModalDialog`` it opens is closed - use :meth:`click_async` for those."""
        return self.run("click", *self._click_args(url, id, link_text, button_text, kind, hwnd, timeout), timeout=timeout)

    def click_async(self, url: str, id: Optional[str] = None, link_text: Optional[str] = None,
                    button_text: Optional[str] = None, kind: Optional[str] = None, hwnd: Optional[int] = None,
                    timeout: float = 10.0) -> subprocess.Popen:
        """Start a click without waiting; returns the ``Popen`` (collect it with :meth:`finish`)."""
        return self.start("click", *self._click_args(url, id, link_text, button_text, kind, hwnd, timeout))

    def text(self, url: str = "", id: Optional[str] = None, kind: Optional[str] = None,
             hwnd: Optional[int] = None, timeout: float = 10.0) -> dict:
        """``{"text": innerText of the element (or of the body), "doc": {...}}``."""
        return self.run("text", *_opts(url=url, id=id, timeout=timeout), *self._filters(kind, hwnd), timeout=timeout)

    def attr(self, url: str, id: str, name: str, kind: Optional[str] = None,
             hwnd: Optional[int] = None, timeout: float = 10.0) -> dict:
        """``{"name", "value", "source": property|attribute|missing, "element", "doc"}``."""
        return self.run("attr", *_opts(url=url, id=id, name=name, timeout=timeout),
                        *self._filters(kind, hwnd), timeout=timeout)

    def dialog(self, title: str = "", button: Optional[str] = None, text: Optional[str] = None,
               timeout: float = 10.0, method: Optional[str] = None) -> dict:
        """Find a standard dialog (#32770) of the browser and, with ``button``, press that button."""
        return self.run("dialog", *_opts(title=title, button=button, text=text, timeout=timeout, method=method),
                        timeout=timeout)

    def navigate(self, to: str) -> dict:
        """Type ``to`` into the address box of the selected tab and press Enter (no Referer, like a user)."""
        return self.run("navigate", *_opts(to=to))

    def close(self, timeout: float = 15.0) -> dict:
        """WM_CLOSE to the main window; ``{"posted", "exited", "exitCode"}``."""
        return self.run("close", *_opts(timeout=timeout), timeout=timeout)


if __name__ == "__main__":  # pragma: no cover - manual use: python iedriver.py OUT_DIR
    print(build_driver(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.getcwd(), "iedriver_bin")))
