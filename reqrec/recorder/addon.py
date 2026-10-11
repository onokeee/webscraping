"""mitmproxy addon that writes a reqrec Recording.  Run via ``reqrec record`` or
``mitmdump -s reqrec/recorder/addon.py --set reqrec_out=rec.json``.  Contract: DESIGN.md §3.

Options (declared in :meth:`ReqRecAddon.load`):

``reqrec_out``
    Path of the recording JSON file.  Rewritten **atomically after every response** (temp file in
    the same directory + ``os.replace``) so a killed session still leaves a valid file.
``reqrec_hosts``
    Comma-separated host names to record; a host matches itself and its sub-domains
    (``util.host_matches``).  Empty = record everything.

The module works both as a package module (``reqrec.recorder.addon``) and when mitmproxy exec's
the file directly (script mode, where relative imports are impossible), hence the import dance below.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import threading
from typing import Any, Iterable, Optional, Union

try:  # normal package import: reqrec.recorder.addon
    from .. import util
    from ..importers.mitm import flow_from_mitm
    from ..model import Flow, Recording
except ImportError:  # script mode: ``mitmdump -s .../addon.py`` loads this file as "__mitmproxy_script__.addon"
    try:
        from reqrec import util
        from reqrec.importers.mitm import flow_from_mitm
        from reqrec.model import Flow, Recording
    except ImportError:
        # reqrec is not installed: make the repository / site-packages root importable
        # (this file lives at <root>/reqrec/recorder/addon.py).
        _ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from reqrec import util
        from reqrec.importers.mitm import flow_from_mitm
        from reqrec.model import Flow, Recording

try:  # mitmproxy is only needed for type checks / option access; the addon stays importable without it
    from mitmproxy import ctx as _mitm_ctx
    from mitmproxy import http as _mitm_http
except ImportError:  # pragma: no cover - exercised only when mitmproxy is absent
    _mitm_ctx = None
    _mitm_http = None

log = logging.getLogger("reqrec.recorder")

__all__ = ["ReqRecAddon", "addons", "parse_hosts", "write_recording_atomic", "OPT_OUT", "OPT_HOSTS", "DEFAULT_OUT"]

OPT_OUT = "reqrec_out"
OPT_HOSTS = "reqrec_hosts"
DEFAULT_OUT = "reqrec_recording.json"

HostsSpec = Union[None, str, Iterable[str]]


def parse_hosts(spec: HostsSpec) -> list[str]:
    """``"a.com, B.com;c.com"`` / ``["a.com", ...]`` -> ``["a.com", "b.com", "c.com"]`` (lower-case,
    de-duplicated, order kept).  ``None`` / ``""`` -> ``[]`` (= record every host)."""
    if spec is None:
        return []
    if isinstance(spec, str):
        items: Iterable[str] = spec.replace(";", ",").replace("\n", ",").split(",")
    else:
        items = []
        for item in spec:
            items.extend(str(item).replace(";", ",").split(","))
    out: list[str] = []
    for item in items:
        for token in item.split():
            host = token.strip().lower().rstrip(".")
            if host and host not in out:
                out.append(host)
    return out


def write_recording_atomic(recording: Recording, path: str) -> str:
    """Serialise ``recording`` to ``path`` via a temp file in the same directory + ``os.replace``.

    Readers never observe a partially written file.  Returns the absolute path written.
    """
    path = os.path.abspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".reqrec-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(recording.to_json(indent=1))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


class ReqRecAddon:
    """Collect completed HTTP flows and keep ``reqrec_out`` up to date on disk.

    The addon can also be used programmatically without mitmproxy's option machinery::

        addon = ReqRecAddon(out="rec.json", hosts=["example.com"])
        addon.response(flow)      # flow: mitmproxy.http.HTTPFlow
        addon.done()

    Options set through mitmproxy (``--set reqrec_out=...``) take precedence once ``configure`` runs.
    """

    def __init__(self, out: Optional[str] = None, hosts: HostsSpec = None) -> None:
        # Constructor arguments are the baseline; mitmproxy options set to a non-default value
        # override them in ``configure`` (and fall back to these when reset to the default).
        self._init_out: Optional[str] = out
        self._init_hosts: list[str] = parse_hosts(hosts)
        self.out: Optional[str] = out
        self.hosts: list[str] = list(self._init_hosts)
        self.started_at: str = util.now_iso()
        self.errors: int = 0  # flows recorded through the error hook (no response)
        self.flush_count: int = 0
        self.last_flush_error: Optional[str] = None
        self._flows: list[Flow] = []
        self._seen: set[Any] = set()  # mitmproxy flow ids already recorded (response/error both fire)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ mitmproxy option hooks

    def load(self, loader: Any) -> None:
        """Declare the ``reqrec_out`` / ``reqrec_hosts`` options."""
        loader.add_option(
            name=OPT_OUT,
            typespec=str,
            default=DEFAULT_OUT,
            help="reqrec: path of the recording JSON file (rewritten atomically after every response)",
        )
        loader.add_option(
            name=OPT_HOSTS,
            typespec=str,
            default="",
            help="reqrec: comma-separated hosts to record (sub-domains included); empty = every host",
        )

    def configure(self, updated: Iterable[str]) -> None:
        """Pick up option changes (mitmproxy calls this at start-up with every option name)."""
        updated = set(updated)
        if OPT_OUT in updated:
            value = self._option(OPT_OUT)
            if isinstance(value, str) and value.strip() and value.strip() != DEFAULT_OUT:
                self.out = value.strip()
            else:
                self.out = self._init_out  # option at its default -> constructor value / DEFAULT_OUT
        if OPT_HOSTS in updated:
            value = self._option(OPT_HOSTS)
            self.hosts = parse_hosts(str(value)) if value is not None else []
            if not self.hosts:
                self.hosts = list(self._init_hosts)
        if updated & {OPT_OUT, OPT_HOSTS}:
            scope = ", ".join(self.hosts) if self.hosts else "all hosts"
            log.info("[reqrec] recording %s -> %s", scope, self.output_path)

    def _option(self, name: str) -> Any:
        """Read a mitmproxy option, or ``None`` when no master is running (plain Python use)."""
        if _mitm_ctx is None:
            return None
        try:
            options = _mitm_ctx.options
        except AttributeError:
            return None
        try:
            return getattr(options, name)
        except (AttributeError, KeyError):
            return None

    @property
    def output_path(self) -> str:
        """Absolute output path: explicit ``out`` > mitmproxy option > ``DEFAULT_OUT``."""
        out = self.out
        if not out:
            value = self._option(OPT_OUT)
            out = value if isinstance(value, str) and value.strip() else DEFAULT_OUT
        return os.path.abspath(out)

    # ------------------------------------------------------------------ mitmproxy event hooks

    def response(self, flow: Any) -> None:
        """A full response has arrived: record the flow and flush the file."""
        self._record(flow, errored=False)

    def error(self, flow: Any) -> None:
        """The flow failed (connection refused, TLS failure, client abort, ...).

        The request is still worth keeping (``response=None``) so the user sees what the browser
        attempted; ``filters`` drops such flows from the generated script.
        """
        self._record(flow, errored=True)

    def done(self) -> None:
        """mitmproxy is shutting down: final flush (also when nothing was recorded)."""
        try:
            path = self.flush()
        except Exception as exc:  # never let shutdown blow up
            log.error("[reqrec] final flush failed: %s", exc)
            return
        log.info("[reqrec] %d flow(s) saved to %s", len(self._flows), path)

    # ------------------------------------------------------------------ core

    def wants(self, flow: Any) -> bool:
        """Should this flow be recorded?  HTTP only, host filter applied."""
        if _mitm_http is not None and not isinstance(flow, _mitm_http.HTTPFlow):
            return False
        request = getattr(flow, "request", None)
        if request is None or not hasattr(request, "method"):
            return False
        if not self.hosts:
            return True
        return util.host_matches(_host_of(request), self.hosts)

    def _record(self, flow: Any, errored: bool) -> None:
        if not self.wants(flow):
            return
        key = getattr(flow, "id", None) or id(flow)
        with self._lock:
            if key in self._seen:
                return
            try:
                recorded = flow_from_mitm(flow, "f0000")  # real id assigned when sorted at flush time
            except Exception as exc:
                log.warning("[reqrec] could not convert flow: %s", exc)
                return
            self._seen.add(key)
            self._flows.append(recorded)
            if errored:
                self.errors += 1
            try:
                self.flush()
            except Exception as exc:
                self.last_flush_error = str(exc)
                log.error("[reqrec] could not write %s: %s", self.output_path, exc)
        status: Any = recorded.response.status if recorded.response is not None else "ERR"
        log.info("[reqrec] #%04d %s %s -> %s", len(self._flows), recorded.request.method, util.truncate(recorded.request.url, 100), status)

    def recording(self) -> Recording:
        """Snapshot of everything recorded so far, chronologically ordered with fresh ids."""
        with self._lock:
            ordered = self._sorted_flows()
            for n, flow in enumerate(ordered, start=1):
                flow.id = f"f{n:04d}"
            meta: dict[str, Any] = {
                "source": "mitmproxy",
                "started_at": self.started_at,
                "updated_at": util.now_iso(),
                "hosts": list(self.hosts),
                "flows_total": len(ordered),
                "errors": self.errors,
            }
            return Recording(flows=list(ordered), meta=meta)

    def _sorted_flows(self) -> list[Flow]:
        """Stable sort by ``started_at``; flows without a timestamp keep their arrival position."""
        keyed: list[tuple[float, int, Flow]] = []
        last = float("-inf")
        for index, flow in enumerate(self._flows):
            if flow.started_at is None:
                key = last
            else:
                key = last = float(flow.started_at)
            keyed.append((key, index, flow))
        keyed.sort(key=lambda t: (t[0], t[1]))
        return [f for _, _, f in keyed]

    def flush(self) -> str:
        """Write the current recording atomically; returns the path written."""
        with self._lock:
            path = write_recording_atomic(self.recording(), self.output_path)
            self.flush_count += 1
            self.last_flush_error = None
            return path

    def __len__(self) -> int:
        return len(self._flows)


def _host_of(request: Any) -> str:
    for attr in ("pretty_host", "host"):
        try:
            host = getattr(request, attr)
        except Exception:
            continue
        if host:
            return str(host)
    return ""


addons = [ReqRecAddon()]
