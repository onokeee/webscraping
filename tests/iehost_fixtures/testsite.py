"""Tiny intranet-like test site for the IE-host engine test (``tests/test_iehost_engine.py``).

Plain http only.  ``RecBrowser.exe --selftest`` loads ``/index.html`` and calls the page functions
``doOpen`` (window.open), ``doBlankPost`` (form target=_blank POST), ``doBlankLink`` (link
target=_blank), ``doModeless`` (showModelessDialog) and ``doModal`` (showModalDialog); every page
self-reports its document mode, window name, opener and cookies to ``/report`` so a run can be judged
from the recording alone.  Every request (and every self-report) is appended as a JSON line to the
log file given on the command line.

Importing this module has no side effects (nothing is read from ``sys.argv``, no file or socket is
touched); the server only starts from :func:`main` / :func:`serve`::

    python -I testsite.py LOGFILE PORT
"""

from __future__ import annotations

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Sequence
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
DEFAULT_PORT = 8099
DEFAULT_LOG = "testsite.log"

#: Page functions ``RecBrowser.exe --selftest`` invokes on /index.html, in this order (the last one
#: opens a popup that closes itself with window.close(): the host must remove that tab again).
SELFTEST_FUNCTIONS = ("doOpen", "doBlankPost", "doBlankLink", "doModeless", "doModal", "doClosePopup")

#: Body of the ``target=_blank`` POST that ``doBlankPost`` submits (``secret=abc123`` + ``jp=日本語``).
EXPECTED_POST_BODY = "secret=abc123&jp=%E6%97%A5%E6%9C%AC%E8%AA%9E"

#: Session cookie set by /index.html; the pages echo it back in their self-report.
SESSION_COOKIE = "sid=TESTSESSION"

COMMON_JS = """
function report(tag, extra){
  var q = 'tag=' + tag + '&mode=' + document.documentMode + '&name=' + encodeURIComponent(window.name || '')
        + '&opener=' + (window.opener ? 'yes' : 'no') + '&ua=' + encodeURIComponent(navigator.userAgent)
        + '&cookie=' + encodeURIComponent(document.cookie || '') + (extra ? '&' + extra : '');
  try { var x = new XMLHttpRequest(); x.open('GET', '/report?' + q, true); x.send(); } catch (e) {}
}
"""

INDEX = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>index</title></head><body>
<h1>index page</h1>
<form id="f" method="post" action="/post" target="_blank">
  <input name="secret" value="abc123"><input name="jp" value="日本語"></form>
<a id="lnk" href="/settings.html?via=blank" target="_blank">settings (target=_blank)</a>
<script>%(common)s
report('index');
function doOpen(){ var w = window.open('/popup.html?via=open', 'cfgwin', 'width=500,height=400'); return w ? 'opened' : 'blocked'; }
function doBlankPost(){ document.getElementById('f').submit(); return 'submitted'; }
function doModal(){ try { var r = window.showModalDialog('/modal.html?via=modal', 'ARGS', 'dialogWidth:400px;dialogHeight:300px'); return 'modal returned: ' + r; } catch (e) { return 'modal error: ' + e.message; } }
function doBlankLink(){ document.getElementById('lnk').click(); return 'clicked'; }
function doModeless(){ try { var w = window.showModelessDialog('/modeless.html?via=modeless', 'ARGS', 'dialogWidth:400px;dialogHeight:300px'); return w ? 'modeless opened' : 'modeless blocked'; } catch (e) { return 'modeless error: ' + e.message; } }
function doClosePopup(){ var w = window.open('/closer.html?via=close', 'closer', 'width=300,height=200'); return w ? 'opened' : 'blocked'; }
</script></body></html>""" % {"common": COMMON_JS}

CLOSER = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>closer</title></head><body>
<h1>closes itself</h1>
<script>%(common)s report('closer'); setTimeout(function(){ window.close(); }, 700);</script></body></html>""" % {"common": COMMON_JS}

POPUP = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>%(title)s</title></head><body>
<h1>%(title)s</h1><p>%(body)s</p>
<script>%(common)s report('%(title)s'%(extra)s);</script></body></html>"""

MODAL = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>modal</title></head><body>
<h1>modal dialog</h1>
<script>%(common)s
var args = ''; try { args = window.dialogArguments; } catch (e) { args = 'n/a'; }
report('modal', 'args=' + encodeURIComponent(args));
setTimeout(function(){ try { window.returnValue = 'OK'; } catch (e) {} window.close(); }, 700);
</script></body></html>""" % {"common": COMMON_JS}

MODELESS = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>modeless</title></head><body>
<h1>modeless dialog</h1>
<script>%(common)s report('modeless'); setTimeout(function(){ window.close(); }, 700);</script></body></html>""" % {"common": COMMON_JS}


def make_handler(log_path: str) -> type:
    """Request handler class bound to ``log_path`` (one JSON object per line)."""

    def log(entry: dict) -> None:
        entry["t"] = round(time.time(), 3)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, body: str, status: int = 200, ctype: str = "text/html; charset=utf-8", extra: Optional[dict] = None) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")  # repeated runs must hit the proxy every time
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            u = urlsplit(self.path)
            log({"method": "GET", "path": self.path, "ua": self.headers.get("User-Agent"), "cookie": self.headers.get("Cookie")})
            if u.path == "/report":
                log({"report": {k: v[0] for k, v in parse_qs(u.query).items()}})
                self._send("ok", ctype="text/plain")
            elif u.path in ("/", "/index.html"):
                self._send(INDEX, extra={"Set-Cookie": SESSION_COOKIE + "; Path=/"})
            elif u.path == "/popup.html":
                self._send(POPUP % {"title": "popup", "body": "opened via window.open", "common": COMMON_JS, "extra": ""})
            elif u.path == "/settings.html":
                self._send(POPUP % {"title": "settings", "body": "opened via target=_blank link", "common": COMMON_JS, "extra": ""})
            elif u.path == "/modal.html":
                self._send(MODAL)
            elif u.path == "/modeless.html":
                self._send(MODELESS)
            elif u.path == "/closer.html":
                self._send(CLOSER)
            elif u.path == "/download.csv":
                self._send("a,b\n1,2\n", ctype="text/csv", extra={"Content-Disposition": "attachment; filename=data.csv"})
            else:
                self._send("not found", status=404, ctype="text/plain")

        def do_POST(self) -> None:  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace")
            log({"method": "POST", "path": self.path, "body": body, "cookie": self.headers.get("Cookie")})
            self._send(POPUP % {"title": "post", "body": "POST body: " + body, "common": COMMON_JS, "extra": ", 'post=' + encodeURIComponent(%r)" % body})

        def log_message(self, *args) -> None:  # silence the default stderr access log
            pass

    return Handler


def serve(log_path: str, port: int = DEFAULT_PORT, host: str = HOST) -> None:
    """Truncate ``log_path`` and serve forever (blocking)."""
    open(log_path, "w", encoding="utf-8").close()
    ThreadingHTTPServer((host, port), make_handler(log_path)).serve_forever()


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Command line: ``testsite.py [LOGFILE [PORT]]``."""
    args = list(sys.argv[1:] if argv is None else argv)
    log_path = args[0] if args else DEFAULT_LOG
    port = int(args[1]) if len(args) > 1 else DEFAULT_PORT
    serve(log_path, port)


if __name__ == "__main__":
    main()
