"""Live recording through a mitmproxy-based proxy.  Contract: DESIGN.md §3.

* :mod:`reqrec.recorder.addon` - the mitmproxy addon (``ReqRecAddon``); needs mitmproxy at run time.
* :mod:`reqrec.recorder.run` - ``run_record`` / ``build_command``: spawn ``mitmdump`` with the addon.

Only the launcher is re-exported here so that importing ``reqrec.recorder`` never requires
mitmproxy itself.
"""

from .run import build_command, run_record

__all__ = ["build_command", "run_record"]
