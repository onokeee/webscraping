"""Test-only helpers of the IE-engine (RecBrowser) tests - stdlib only, importable by path.

* ``testsite``: tiny intranet-like site for ``RecBrowser.exe --selftest``,
* ``factory_site``: mock legacy factory intranet (ASP.NET WebForms, Shift_JIS, one-time __VIEWSTATE),
* ``factory_scenario``: records the factory site through the real recording browser,
* ``iedriver``: Python wrapper for the test driver ``IEDriver.exe`` (source: ``IEDriver.cs`` next to
  this file).

One section per former module of ``tests/iehost_fixtures/`` (headed
``# ===== former tests/iehost_fixtures/<name>.py ... =====``).  Importing this module has no side
effects.  Command line (see :func:`main`)::

    python -I tests/ie_support.py testsite LOGFILE PORT
    python -I tests/ie_support.py factory-site LOGFILE PORT [HOST]
    python -I tests/ie_support.py iedriver OUT_DIR
"""

from __future__ import annotations

import base64
import datetime as _dt
import functools
import hashlib
import io
import json
import os
import random
import re
import secrets
import shutil
import socket
import socketserver
import string
import struct
import subprocess
import sys
import threading
import time
import zipfile
from collections import OrderedDict
from html import escape as _html_escape
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, parse_qsl, quote, unquote_to_bytes, urlsplit
from xml.etree import ElementTree as ET

__all__ = [
    # testsite (RecBrowser self-test site)
    "SELFTEST_FUNCTIONS", "EXPECTED_POST_BODY", "TESTSITE_SESSION_COOKIE", "make_handler", "serve", "testsite_main",
    # factory_site (mock 生産管理システム)
    "CREDENTIALS", "USER_NAME", "PLANTS", "LINES", "SHIFTS", "ITEMS", "PAGE_SIZE", "DEFAULT_FROM", "DEFAULT_TO",
    "EXPORT_DATE", "EXPORT_HEADER", "EXPORT_ID_LABEL", "XLSX_CONTENT_TYPE", "VIEWSTATE_GENERATORS", "FactoryServer",
    "make_server", "serve_in_thread", "factory_site_main", "dataset", "expected_rows", "export_filename",
    "build_xlsx", "read_xlsx_rows", "read_log", "hidden_fields", "parse_form",
    # factory_scenario
    "SCENARIO_FILTER", "STEPS", "ScenarioError", "run_factory_recording", "site_host", "free_port",
    # iedriver (IEDriver.exe wrapper)
    "DRIVER_SOURCE", "CSC", "IEDriverError", "build_command", "build_driver", "IEDriver",
    # command line
    "main",
]


# ===== former tests/iehost_fixtures/testsite.py: tiny intranet-like site for the RecBrowser self-test =====
# Tiny intranet-like test site for the IE-host engine test (``tests/test_real_engine.py``).
#
# Plain http only.  ``RecBrowser.exe --selftest`` loads ``/index.html`` and calls the page functions
# ``doOpen`` (window.open), ``doBlankPost`` (form target=_blank POST), ``doBlankLink`` (link
# target=_blank), ``doModeless`` (showModelessDialog) and ``doModal`` (showModalDialog); every page
# self-reports its document mode, window name, opener and cookies to ``/report`` so a run can be judged
# from the recording alone.  Every request (and every self-report) is appended as a JSON line to the
# log file given on the command line.
#
# Importing this module has no side effects (nothing is read from ``sys.argv``, no file or socket is
# touched); the server only starts from :func:`testsite_main` / :func:`serve`::
#
#     python -I tests/ie_support.py testsite LOGFILE PORT

HOST = "127.0.0.1"
TESTSITE_DEFAULT_PORT = 8099
TESTSITE_DEFAULT_LOG = "testsite.log"

#: Page functions ``RecBrowser.exe --selftest`` invokes on /index.html, in this order (the last one
#: opens a popup that closes itself with window.close(): the host must remove that tab again).
SELFTEST_FUNCTIONS = ("doOpen", "doBlankPost", "doBlankLink", "doModeless", "doModal", "doClosePopup")

#: Body of the ``target=_blank`` POST that ``doBlankPost`` submits (``secret=abc123`` + ``jp=日本語``).
EXPECTED_POST_BODY = "secret=abc123&jp=%E6%97%A5%E6%9C%AC%E8%AA%9E"

#: Session cookie set by /index.html; the pages echo it back in their self-report.
TESTSITE_SESSION_COOKIE = "sid=TESTSESSION"

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
                self._send(INDEX, extra={"Set-Cookie": TESTSITE_SESSION_COOKIE + "; Path=/"})
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


def serve(log_path: str, port: int = TESTSITE_DEFAULT_PORT, host: str = HOST) -> None:
    """Truncate ``log_path`` and serve forever (blocking)."""
    open(log_path, "w", encoding="utf-8").close()
    ThreadingHTTPServer((host, port), make_handler(log_path)).serve_forever()


def testsite_main(argv: Optional[Sequence[str]] = None) -> None:
    """Command line: ``ie_support.py testsite [LOGFILE [PORT]]``."""
    args = list(sys.argv[1:] if argv is None else argv)
    log_path = args[0] if args else TESTSITE_DEFAULT_LOG
    port = int(args[1]) if len(args) > 1 else TESTSITE_DEFAULT_PORT
    serve(log_path, port)


# ===== former tests/iehost_fixtures/factory_site.py: mock factory intranet (ASP.NET WebForms, Shift_JIS) =====
# Mock legacy factory production-management intranet (生産管理システム) for reqrec / IE-host tests.
#
# It imitates an ASP.NET WebForms site written for Internet Explorer and served by "IIS":
#
# * **Shift_JIS everywhere** — every HTML page carries ``Content-Type: text/html; charset=Shift_JIS``
#   and ``<meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS">``; form posts arrive
#   percent-encoded in Shift_JIS and are decoded with cp932.  HTML/JS is ES3 / IE7-document-mode safe
#   (``onclick`` / ``onchange`` attributes, ``document.getElementById``, ``document.forms``).
# * **ASP.NET session + forms authentication** — ``GET /Login.aspx`` issues ``ASP.NET_SessionId``
#   (24 lowercase alnum); a successful login *rotates* the session id and sets ``.ASPXAUTH`` (64 hex,
#   HttpOnly).  Every page except the login page and the static files needs a valid
#   ``ASP.NET_SessionId`` + ``.ASPXAUTH`` pair, otherwise ``302 /Login.aspx?ReturnUrl=<path>``.
# * **One-time ``__VIEWSTATE`` / ``__EVENTVALIDATION``** — each rendered page gets fresh random
#   tokens bound to the session and to the page.  A postback with a missing / foreign / stale /
#   already used token is answered with HTTP 500 "Validation of viewstate MAC failed."; a posted
#   value the page never rendered (e.g. a line of another plant) with HTTP 500 "Invalid postback or
#   callback argument."  A postback that was *rejected* does not use up its tokens; the Excel
#   download does not use them up either (the browser keeps showing the same page, so the next click
#   posts the same tokens again).
# * **Popups** — Menu.aspx opens 生産実績照会 (Search.aspx) with ``window.open`` and a per-session
#   URL key (NAVKEY, cookieless-style; a wrong / missing key is a 403) and お知らせ (News.aspx) with
#   ``target="_blank"``.  Search.aspx is a ``__doPostBack`` page: an AutoPostBack plant dropdown
#   that fills the line dropdown, a ``showModalDialog`` item picker (ItemPicker.aspx, returns the
#   item code through ``window.returnValue``), a paged result grid (``gvResult``, 20 rows per page,
#   ``__doPostBack('gvResult','Page$2')``) and an Excel (.xlsx) download with an IE-style
#   percent-encoded UTF-8 file name.
#
# Every request is appended as one JSON line to the log file::
#
#     {"t", "method", "path", "query", "session", "auth_ok", "event", "status", "ua", "details"}
#
# ``session`` is the server-side session the request's ``ASP.NET_SessionId`` cookie names (``null``
# when there is none / it is unknown); ``event`` is e.g. ``login_page``, ``login_ok``, ``login_fail``,
# ``viewstate_reject``, ``eventvalidation_reject``, ``navkey_reject``, ``auth_redirect``, ``menu``,
# ``search_page``, ``plant_change``, ``search``, ``page``, ``excel_export``, ``picker``, ``news``,
# ``logout``, ``static``; ``details`` holds the filters, the export id, the rejection reason and the
# first characters of rejected tokens.
#
# Importing this module has no side effects (nothing is read from ``sys.argv``, no file or socket is
# touched).  Command line::
#
#     python -I tests/ie_support.py factory-site LOGFILE PORT [HOST]
#
# From a test::
#
#     server = make_server(log_path, 0)           # port 0 = any free port; server.port / server.base_url
#     threading.Thread(target=server.serve_forever, daemon=True).start()
#     ...
#     server.shutdown(); server.server_close()
#
# or ``server = serve_in_thread(log_path)`` … ``server.stop()``.  Helpers: :data:`CREDENTIALS`,
# :func:`expected_rows`, :func:`read_xlsx_rows`, :func:`export_filename`, :func:`read_log`,
# :func:`hidden_fields`.

# --------------------------------------------------------------------------- constants

DEFAULT_PORT = 8098
DEFAULT_LOG = "factory_site.log"

CODEC = "cp932"
HTML_CONTENT_TYPE = "text/html; charset=Shift_JIS"
XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

#: The only account: (user id, password).  The symbols must survive the form encoding.
CREDENTIALS = ("tanaka", "Seisan#2026!")
USER_NAME = "田中 太郎"

SESSION_COOKIE = "ASP.NET_SessionId"
AUTH_COOKIE = ".ASPXAUTH"

PLANTS: Tuple[Tuple[str, str], ...] = (("01", "本社工場"), ("02", "第二工場"))
LINES: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "01": (("L11", "組立1ライン"), ("L12", "組立2ライン")),
    "02": (("L21", "プレスライン"), ("L22", "塗装ライン")),
}
SHIFTS: Tuple[Tuple[str, str], ...] = (("ALL", "全て"), ("D", "日勤"), ("N", "夜勤"))
SHIFT_LABELS = {"D": "日勤", "N": "夜勤"}
ITEMS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "01": (("A-1001", "ブラケット"), ("A-1002", "ステー"), ("A-1003", "カバー")),
    "02": (("B-2001", "パネル"), ("B-2002", "フレーム")),
}

#: Default search period (the whole data period: last month + this month up to "yesterday").
DEFAULT_FROM = "2026/09/01"
DEFAULT_TO = "2026/10/10"
PAGE_SIZE = 20
#: Date part of the export file name (the site's "today").
EXPORT_DATE = "20261011"
EXPORT_HEADER = ("日付", "ライン", "直", "品番", "計画数", "実績数", "不良数")
EXPORT_ID_LABEL = "出力ID"
SHEET_NAME = "生産実績"

#: Fixed per page, like the real thing.
VIEWSTATE_GENERATORS = {
    "Login.aspx": "C2EE9ABB",
    "Menu.aspx": "B6E7A1F4",
    "Search.aspx": "5F0D8C21",
    "News.aspx": "3A9E44D0",
    "ItemPicker.aspx": "E81B2C9F",
}

DATA_SEED = 20261001
#: items produced per (day, line, shift); Sundays are holidays.  組立1ライン makes every item on the
#: day shift, so the recording scenario's filter (本社工場 / 組立1ライン / 日勤 / A-1002, default period)
#: has one row per working day = 35 rows = two grid pages.
_LINE_PLAN: Dict[str, Tuple[Tuple[str, int], ...]] = {
    "L11": (("D", 3), ("N", 1)),
    "L12": (("D", 1), ("N", 1)),
    "L21": (("D", 1),),
    "L22": (("D", 1),),
}
_DATA_FIRST_DAY = _dt.date(2026, 9, 1)
_DATA_LAST_DAY = _dt.date(2026, 10, 10)

MAX_TOKENS_PER_SESSION = 300
MAX_SESSIONS = 5000

MSG_LOGIN_FAIL = "ユーザー ID またはパスワードが違います。"
MSG_LOGIN_EMPTY = "ユーザー ID とパスワードを入力してください。"
MSG_NEED_PLANT = "工場を選択してください。"
MSG_NEED_LINE = "ラインを選択してください。"
MSG_BAD_DATE = "日付は yyyy/mm/dd の形式で入力してください。"
MSG_BAD_RANGE = "期間の開始日が終了日より後になっています。"
MSG_BAD_ITEM = "品番が正しくありません。"
MSG_NO_DATA = "該当するデータがありません。"

VIEWSTATE_ERROR = "Validation of viewstate MAC failed."
POSTBACK_ERROR = "Invalid postback or callback argument."

_ALNUM_LOWER = string.ascii_lowercase + string.digits
_ALNUM = string.ascii_letters + string.digits

# --------------------------------------------------------------------------- static files

SITE_CSS = b"""body { margin: 0; font-family: "MS PGothic", "MS UI Gothic", sans-serif; font-size: 13px; background: #f4f6f9; color: #222; }
#header { background: #1f3a70; color: #fff; padding: 6px 10px; height: 26px; }
#header img { vertical-align: middle; border: 1px solid #fff; }
#header .sys { font-size: 16px; font-weight: bold; margin-left: 6px; vertical-align: middle; }
#header .user { float: right; margin-top: 4px; }
#content { padding: 10px 14px; }
h2 { font-size: 15px; border-left: 6px solid #1f3a70; padding-left: 6px; }
table.form th { text-align: left; background: #dfe6f2; padding: 3px 8px; font-weight: normal; }
table.form td { padding: 3px 8px; }
table.grid { border-collapse: collapse; background: #fff; }
table.grid th { background: #1f3a70; color: #fff; padding: 2px 8px; }
table.grid td { padding: 2px 8px; }
tr.alt td { background: #eef2f8; }
tr.pager td { background: #fff; text-align: center; }
.msg { color: #c00; font-weight: bold; }
.count { margin: 6px 0; }
ul.menu li { margin: 6px 0; font-size: 14px; }
"""


def _make_gif() -> bytes:
    """A real 1x1 GIF89a (one navy pixel, two-colour global table)."""
    return (b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0x80, 0, 0) + bytes((0x1F, 0x3A, 0x70, 0xFF, 0xFF, 0xFF))
            + b"," + struct.pack("<HHHHB", 0, 0, 1, 1, 0) + bytes((2, 2, 0x44, 0x01, 0)) + b";")


def _make_ico() -> bytes:
    """A real 1x1 32-bit .ico."""
    bmp = (struct.pack("<IiiHHIIiiII", 40, 1, 2, 1, 32, 0, 8, 0, 0, 0, 0)
           + bytes((0x70, 0x3A, 0x1F, 0xFF)) + b"\x00\x00\x00\x00")
    return struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, len(bmp), 22) + bmp


LOGO_GIF = _make_gif()
FAVICON_ICO = _make_ico()
STATIC_LAST_MODIFIED = "Thu, 01 Oct 2026 00:00:00 GMT"
STATIC_FILES: Dict[str, Tuple[str, bytes, str]] = {
    "/css/site.css": ("text/css", SITE_CSS, '"80c1a3e2f4d9d1:0"'),
    "/img/logo.gif": ("image/gif", LOGO_GIF, '"80c1a3e2f4d9d2:0"'),
    "/favicon.ico": ("image/x-icon", FAVICON_ICO, '"80c1a3e2f4d9d3:0"'),
}

# --------------------------------------------------------------------------- data


def _days() -> Iterator[_dt.date]:
    day = _DATA_FIRST_DAY
    while day <= _DATA_LAST_DAY:
        yield day
        day += _dt.timedelta(days=1)


@functools.lru_cache(maxsize=1)
def dataset() -> Tuple[Tuple[Any, ...], ...]:
    """The deterministic production records, in export order.

    Each row is ``(date "yyyy/mm/dd", plant, line, shift "D"|"N", item, plan, actual, defects)``;
    order: date, plant, line, shift (日勤 before 夜勤), item.
    """
    rng = random.Random(DATA_SEED)
    rows: List[Tuple[Any, ...]] = []
    for day in _days():
        if day.weekday() == 6:  # 日曜は休み
            continue
        ds = day.strftime("%Y/%m/%d")
        for plant, lines in LINES.items():
            codes = [code for code, _name in ITEMS[plant]]
            for line, _name in lines:
                for shift, count in _LINE_PLAN[line]:
                    for item in sorted(rng.sample(codes, count)):
                        plan = rng.choice((80, 100, 120, 150, 200))
                        actual = max(0, plan - rng.randint(-5, 15))
                        defects = rng.randint(0, 6)
                        rows.append((ds, plant, line, shift, item, plan, actual, defects))
    return tuple(rows)


_DATE_RE = re.compile(r"^\s*(\d{4})/(\d{1,2})/(\d{1,2})\s*$")


def parse_date(text: Optional[str]) -> Optional[str]:
    """``"2026/10/1"`` -> ``"2026/10/01"``; ``None`` for anything that is not a valid yyyy/mm/dd."""
    m = _DATE_RE.match(text or "")
    if not m:
        return None
    try:
        day = _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None
    return day.strftime("%Y/%m/%d")


def _query(plant: str, line: Optional[str], shift: Optional[str], date_from: str, date_to: str,
           item: Optional[str]) -> List[Tuple[Any, ...]]:
    lo = parse_date(date_from)
    hi = parse_date(date_to)
    if lo is None or hi is None:
        raise ValueError(f"bad date range {date_from!r} - {date_to!r} (yyyy/mm/dd)")
    out = []
    for row in dataset():
        if row[1] != plant:
            continue
        if line and row[2] != line:
            continue
        if shift and shift != "ALL" and row[3] != shift:
            continue
        if not (lo <= row[0] <= hi):
            continue
        if item and row[4] != item:
            continue
        out.append(row)
    return out


def _export_values(row: Tuple[Any, ...]) -> Tuple[Any, ...]:
    ds, _plant, line, shift, item, plan, actual, defects = row
    return (ds, line, SHIFT_LABELS[shift], item, plan, actual, defects)


def expected_rows(plant: str, line: Optional[str], shift: Optional[str] = "ALL", date_from: str = DEFAULT_FROM,
                  date_to: str = DEFAULT_TO, item: Optional[str] = "") -> List[Tuple[str, ...]]:
    """The rows a search / an Excel export with these filters returns, in the same order.

    Each row is a tuple of strings exactly as :func:`read_xlsx_rows` returns the export's data rows
    (and as the result grid shows them): ``("2026/10/01", "L11", "日勤", "A-1001", "120", "118", "2")``.
    ``line`` / ``item`` empty or ``None`` mean "all"; ``shift`` is ``"ALL"``, ``"D"`` or ``"N"``.
    """
    return [tuple(str(v) for v in _export_values(row)) for row in _query(plant, line, shift, date_from, date_to, item)]


def export_filename(plant: str, line: str) -> str:
    """Unencoded file name of the Excel export, e.g. ``生産実績_01_L11_20261011.xlsx``."""
    return f"生産実績_{plant}_{line}_{EXPORT_DATE}.xlsx"


# --------------------------------------------------------------------------- xlsx

_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"

_CONTENT_TYPES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    '<Override PartName="/xl/worksheets/sheet1.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    '</Types>'
)
_ROOT_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    f'<Relationships xmlns="{_NS_PKG_REL}">'
    f'<Relationship Id="rId1" Type="{_NS_REL}/officeDocument" Target="xl/workbook.xml"/>'
    '</Relationships>'
)
_WORKBOOK_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    f'<Relationships xmlns="{_NS_PKG_REL}">'
    f'<Relationship Id="rId1" Type="{_NS_REL}/worksheet" Target="worksheets/sheet1.xml"/>'
    '</Relationships>'
)


def _xml_text(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _col_letters(index: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA."""
    letters = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


def _col_index(ref: str) -> int:
    """``"C12"`` -> 2."""
    n = 0
    for ch in ref:
        if not ch.isalpha():
            break
        n = n * 26 + (ord(ch.upper()) - 64)
    return n - 1


def build_xlsx(rows: Sequence[Sequence[Any]], sheet_name: str = SHEET_NAME) -> bytes:
    """A minimal real .xlsx: ints / floats become number cells, everything else an inline string."""
    out = [f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<worksheet xmlns="{_NS_MAIN}"><sheetData>']
    for r, row in enumerate(rows, start=1):
        out.append(f'<row r="{r}">')
        for c, value in enumerate(row):
            ref = f"{_col_letters(c)}{r}"
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                out.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                out.append(f'<c r="{ref}" t="inlineStr"><is><t>{_xml_text(str(value))}</t></is></c>')
        out.append("</row>")
    out.append("</sheetData></worksheet>")
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        f'<workbook xmlns="{_NS_MAIN}" xmlns:r="{_NS_REL}">'
        f'<sheets><sheet name="{_xml_text(sheet_name)}" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    parts = (
        ("[Content_Types].xml", _CONTENT_TYPES_XML),
        ("_rels/.rels", _ROOT_RELS_XML),
        ("xl/workbook.xml", workbook),
        ("xl/_rels/workbook.xml.rels", _WORKBOOK_RELS_XML),
        ("xl/worksheets/sheet1.xml", "".join(out)),
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in parts:
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 11, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, text.encode("utf-8"))
    return buf.getvalue()


def read_xlsx_rows(data: bytes) -> List[List[str]]:
    """Every row of the first worksheet of an .xlsx as a list of strings (numbers as written, e.g. "120").

    Handles inline strings, shared strings and plain values; missing cells inside a row become "".
    """
    ns = {"m": _NS_MAIN}
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = set(zf.namelist())
        shared: List[str] = []
        if "xl/sharedStrings.xml" in names:
            sroot = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in sroot.findall("m:si", ns):
                shared.append("".join(t.text or "" for t in si.iter(f"{{{_NS_MAIN}}}t")))
        sheet_path = "xl/worksheets/sheet1.xml"
        try:
            wb = ET.fromstring(zf.read("xl/workbook.xml"))
            first = wb.find("m:sheets/m:sheet", ns)
            rid = first.get(f"{{{_NS_REL}}}id") if first is not None else None
            rels = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
            for rel in rels:
                if rel.get("Id") == rid:
                    target = rel.get("Target", "")
                    sheet_path = target.lstrip("/") if target.startswith("/") else "xl/" + target
                    break
        except (KeyError, ET.ParseError):
            pass
        root = ET.fromstring(zf.read(sheet_path))
    rows: List[List[str]] = []
    for row in root.iter(f"{{{_NS_MAIN}}}row"):
        cells: Dict[int, str] = {}
        col = -1
        for c in row.findall("m:c", ns):
            ref = c.get("r")
            col = _col_index(ref) if ref else col + 1
            kind = c.get("t")
            if kind == "inlineStr":
                text = "".join(t.text or "" for t in c.iter(f"{{{_NS_MAIN}}}t"))
            else:
                v = c.find("m:v", ns)
                text = (v.text or "") if v is not None else ""
                if kind == "s" and text:
                    text = shared[int(text)]
            cells[col] = text
        width = max(cells) + 1 if cells else 0
        rows.append([cells.get(i, "") for i in range(width)])
    return rows


# --------------------------------------------------------------------------- small helpers


def parse_form(body: bytes, codec: str = CODEC) -> Dict[str, str]:
    """``application/x-www-form-urlencoded`` bytes -> ``{name: value}`` (first value wins), decoded as cp932."""
    out: Dict[str, str] = {}
    for part in body.split(b"&"):
        if not part:
            continue
        key, _sep, value = part.partition(b"=")
        k = unquote_to_bytes(key.replace(b"+", b" ")).decode(codec, "replace")
        v = unquote_to_bytes(value.replace(b"+", b" ")).decode(codec, "replace")
        out.setdefault(k, v)
    return out


def _parse_cookies(header: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (header or "").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name and name not in out:
            out[name] = value.strip()
    return out


def read_log(log_path: str) -> List[Dict[str, Any]]:
    """The JSON lines of a log file written by this site."""
    with open(log_path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class _HiddenParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: Dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag != "input":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        if a.get("type", "").lower() == "hidden" and a.get("name"):
            self.fields.setdefault(a["name"], a.get("value", ""))


def hidden_fields(html: str) -> Dict[str, str]:
    """``{name: value}`` of the ``<input type="hidden">`` elements of a page (stdlib only)."""
    parser = _HiddenParser()
    parser.feed(html)
    parser.close()
    return parser.fields


def _esc(value: Any) -> str:
    return _html_escape(str(value), quote=True)


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _prefix(token: Optional[str], n: int = 12) -> Optional[str]:
    return token[:n] if token else token


def _return_url(path: str) -> str:
    """ASP.NET style: lower-case percent escapes (``%2fMenu.aspx``)."""
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), quote(path, safe=""))


def _mask(secret: str) -> str:
    """Letters/digits -> ``*``, symbols kept: shows whether ``#`` / ``!`` arrived without logging the value."""
    return "".join("*" if ch.isalnum() else ch for ch in secret)


# --------------------------------------------------------------------------- sessions and tokens


class _Token:
    __slots__ = ("page", "ev", "state", "used")

    def __init__(self, page: str, ev: Optional[str], state: Dict[str, Any]) -> None:
        self.page = page
        self.ev = ev
        self.state = state
        self.used = False


class _Session:
    __slots__ = ("sid", "auth", "user", "navkey", "tokens", "created")

    def __init__(self, sid: str) -> None:
        self.sid = sid
        self.auth: Optional[str] = None
        self.user: Optional[str] = None
        self.navkey: Optional[str] = None
        self.tokens: "OrderedDict[str, _Token]" = OrderedDict()
        self.created = time.time()


class SiteState:
    """All server-side state (sessions and the tokens issued to them); every method is thread-safe."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.sessions: "OrderedDict[str, _Session]" = OrderedDict()

    def _new_sid(self) -> str:
        while True:
            sid = _rand(_ALNUM_LOWER, 24)
            if sid not in self.sessions:
                return sid

    def new_session(self) -> _Session:
        with self.lock:
            sess = _Session(self._new_sid())
            self.sessions[sess.sid] = sess
            while len(self.sessions) > MAX_SESSIONS:
                self.sessions.popitem(last=False)
            return sess

    def lookup(self, sid: Optional[str], auth: Optional[str]) -> Tuple[Optional[_Session], bool]:
        with self.lock:
            sess = self.sessions.get(sid) if sid else None
            ok = bool(sess is not None and sess.auth and auth and sess.auth == auth)
            return sess, ok

    def login(self, old: _Session, user: str) -> _Session:
        """Rotate the session id: the old session (and every token issued to it) is gone."""
        with self.lock:
            self.sessions.pop(old.sid, None)
            new = _Session(self._new_sid())
            new.user = user
            new.auth = secrets.token_hex(32).upper()
            new.navkey = _rand(_ALNUM, 20)
            self.sessions[new.sid] = new
            return new

    def drop(self, sid: str) -> None:
        with self.lock:
            self.sessions.pop(sid, None)

    def issue(self, sess: _Session, page: str, state: Optional[Dict[str, Any]] = None,
              with_ev: bool = True) -> Tuple[str, Optional[str]]:
        """Fresh ``(__VIEWSTATE, __EVENTVALIDATION)`` for one rendering of ``page`` in ``sess``."""
        vs = base64.b64encode(bytes((0xFF, 0x01, 0x0F, 0x0F, 0x05, 0x0A)) + secrets.token_bytes(84)).decode("ascii")
        ev = base64.b64encode(bytes((0xFF, 0x01, 0x16)) + secrets.token_bytes(42)).decode("ascii") if with_ev else None
        with self.lock:
            sess.tokens[vs] = _Token(page, ev, dict(state or {}))
            while len(sess.tokens) > MAX_TOKENS_PER_SESSION:
                sess.tokens.popitem(last=False)
        return vs, ev

    def check(self, sess: Optional[_Session], page: str,
              form: Dict[str, str]) -> Tuple[Optional[_Token], Optional[str], Optional[str]]:
        """Validate the posted tokens: ``(token, None, None)`` or ``(None, event, reason)``.

        Call with :attr:`lock` held when the token is to be marked used afterwards.
        """
        with self.lock:
            vs = form.get("__VIEWSTATE")
            if sess is None:
                return None, "viewstate_reject", "no_session"
            if not vs:
                return None, "viewstate_reject", "missing_viewstate"
            tok = sess.tokens.get(vs)
            if tok is None:
                foreign = any(vs in other.tokens for other in self.sessions.values() if other is not sess)
                return None, "viewstate_reject", "viewstate_of_other_session" if foreign else "unknown_viewstate"
            if tok.page != page:
                return None, "viewstate_reject", f"viewstate_of_page:{tok.page}"
            if tok.used:
                return None, "viewstate_reject", "viewstate_reused"
            if form.get("__VIEWSTATEGENERATOR") != VIEWSTATE_GENERATORS[page]:
                return None, "viewstate_reject", "bad_viewstategenerator"
            if tok.ev is not None:
                ev = form.get("__EVENTVALIDATION")
                if not ev:
                    return None, "eventvalidation_reject", "missing_eventvalidation"
                if ev != tok.ev:
                    return None, "eventvalidation_reject", "eventvalidation_mismatch"
            return tok, None, None


# --------------------------------------------------------------------------- HTML

_DOCTYPE = ('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" '
            '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">')

_POSTBACK_JS = """<script type="text/javascript">
//<![CDATA[
var theForm = document.forms['form1'];
if (!theForm) {
    theForm = document.forms[0];
}
function __doPostBack(eventTarget, eventArgument) {
    if (!theForm.onsubmit || (theForm.onsubmit() != false)) {
        theForm.__EVENTTARGET.value = eventTarget;
        theForm.__EVENTARGUMENT.value = eventArgument;
        theForm.submit();
    }
}
//]]>
</script>"""


def _page(title: str, body: str, head_extra: str = "") -> str:
    return (
        _DOCTYPE + "\r\n"
        '<html xmlns="http://www.w3.org/1999/xhtml">\r\n'
        '<head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS" />'
        f"<title>{_esc(title)}</title>"
        '<link href="/css/site.css" rel="stylesheet" type="text/css" />'
        '<link rel="shortcut icon" href="/favicon.ico" />' + head_extra + "</head>\r\n"
        "<body>\r\n" + body + "\r\n</body>\r\n</html>\r\n"
    )


def _header(user: Optional[str] = None) -> str:
    who = f'<span class="user">{_esc(user)} さん</span>' if user else ""
    return ('<div id="header">' + who + '<img src="/img/logo.gif" width="24" height="24" alt="" />'
            '<span class="sys">生産管理システム</span></div>')


def _hidden(name: str, value: str) -> str:
    return f'<input type="hidden" name="{name}" id="{name}" value="{_esc(value)}" />'


def _form_open(action: str, vs: str, page: str, ev: Optional[str], postback: bool = False) -> str:
    first = []
    if postback:
        first += [_hidden("__EVENTTARGET", ""), _hidden("__EVENTARGUMENT", "")]
    first.append(_hidden("__VIEWSTATE", vs))
    second = [_hidden("__VIEWSTATEGENERATOR", VIEWSTATE_GENERATORS[page])]
    if ev is not None:
        second.append(_hidden("__EVENTVALIDATION", ev))
    return (f'<form name="form1" method="post" action="{_esc(action)}" id="form1">\r\n'
            "<div>\r\n" + "\r\n".join(first) + "\r\n</div>\r\n"
            + (_POSTBACK_JS + "\r\n" if postback else "")
            + "<div>\r\n" + "\r\n".join(second) + "\r\n</div>\r\n")


def _options(choices: Sequence[Tuple[str, str]], selected: Optional[str]) -> str:
    out = []
    for value, label in choices:
        sel = ' selected="selected"' if value == selected else ""
        out.append(f'<option{sel} value="{_esc(value)}">{_esc(label)}</option>')
    return "\r\n".join(out)


def _login_html(vs: str, ev: str, user_id: str = "", message: str = "") -> str:
    body = (
        _header() + '\r\n<div id="content">\r\n'
        + _form_open("Login.aspx", vs, "Login.aspx", ev)
        + "<h2>ログイン</h2>\r\n"
        '<table class="form">\r\n'
        '<tr><th>ユーザー ID</th><td><input name="txtUserId" type="text" value="' + _esc(user_id)
        + '" maxlength="20" id="txtUserId" style="width:160px;" /></td></tr>\r\n'
        '<tr><th>パスワード</th><td><input name="txtPassword" type="password" maxlength="32" '
        'id="txtPassword" style="width:160px;" /></td></tr>\r\n'
        "</table>\r\n"
        f'<p><span id="lblMessage" class="msg">{_esc(message)}</span></p>\r\n'
        '<input type="submit" name="btnLogin" value="ログイン" id="btnLogin" />\r\n'
        "</form>\r\n</div>\r\n"
        '<script type="text/javascript">document.getElementById(\'txtUserId\').focus();</script>'
    )
    return _page("生産管理システム - ログイン", body)


def _menu_html(user: str, navkey: str, vs: str) -> str:
    search_js = (f"window.open('Search.aspx?key={navkey}','search',"
                 "'width=980,height=720,resizable=yes,scrollbars=yes');return false;")
    body = (
        _header(user) + '\r\n<div id="content">\r\n'
        + _form_open("Menu.aspx", vs, "Menu.aspx", None)
        + f'<p><span id="lblWelcome">ようこそ {_esc(user)} さん</span></p>\r\n'
        "<h2>メニュー</h2>\r\n"
        '<ul class="menu">\r\n'
        f'<li><a href="#" onclick="{search_js}" id="lnkSearch">生産実績照会</a></li>\r\n'
        '<li><a id="lnkNews" href="News.aspx" target="_blank">お知らせ</a></li>\r\n'
        '<li><a id="lnkLogout" href="Logout.aspx">ログアウト</a></li>\r\n'
        "</ul>\r\n</form>\r\n</div>"
    )
    return _page("生産管理システム - メニュー", body)


_NEWS = (
    ("2026/10/05", "システムメンテナンスのお知らせ（10/17 20:00 から 24:00 まで停止します）"),
    ("2026/09/28", "第二工場 塗装ラインの品番を追加しました。"),
    ("2026/09/15", "パスワードは 90 日ごとに変更してください。"),
)


def _news_html(user: str, vs: str) -> str:
    rows = "\r\n".join(f"<tr><td>{_esc(d)}</td><td>{_esc(t)}</td></tr>" for d, t in _NEWS)
    body = (
        _header(user) + '\r\n<div id="content">\r\n'
        + _form_open("News.aspx", vs, "News.aspx", None)
        + "<h2>お知らせ</h2>\r\n"
        '<table id="tblNews" class="grid" border="1" cellspacing="0">\r\n'
        "<tr><th>日付</th><th>内容</th></tr>\r\n" + rows + "\r\n</table>\r\n"
        '<p><input type="button" value="閉じる" onclick="window.close();" /></p>\r\n'
        "</form>\r\n</div>"
    )
    return _page("生産管理システム - お知らせ", body)


def _picker_html(user: str, plant: str, navkey: str, vs: str) -> str:
    items = ITEMS.get(plant)
    if items:
        rows = "\r\n".join(
            f'<tr><td><a href="#" id="item_{code}" onclick="window.returnValue=\'{code}\';window.close();return false;">'
            f"{code}</a></td><td>{_esc(name)}</td></tr>"
            for code, name in items
        )
        table = ('<table id="tblItems" class="grid" border="1" cellspacing="0">\r\n'
                 "<tr><th>品番</th><th>品名</th></tr>\r\n" + rows + "\r\n</table>\r\n")
        msg = ""
    else:
        table = ""
        msg = "工場が選択されていません。"
    plant_name = dict(PLANTS).get(plant, "")
    body = (
        _header(user) + '\r\n<div id="content">\r\n'
        + _form_open(f"ItemPicker.aspx?plant={plant}&key={navkey}", vs, "ItemPicker.aspx", None)
        + f"<h2>品番選択 {_esc(plant_name)}</h2>\r\n"
        + f'<p><span id="lblMessage" class="msg">{_esc(msg)}</span></p>\r\n' + table
        + '<p><input type="button" id="btnCancel" value="キャンセル" '
        "onclick=\"window.returnValue='';window.close();\" /></p>\r\n"
        "</form>\r\n</div>"
    )
    return _page("品番選択", body, head_extra='<base target="_self" />')


def _grid_html(rows: List[Tuple[Any, ...]], page: int, page_count: int) -> str:
    head = "<tr>" + "".join(f'<th scope="col">{_esc(h)}</th>' for h in EXPORT_HEADER) + "</tr>"
    if not rows:
        return ('<div>\r\n<table class="grid" cellspacing="0" rules="all" border="1" id="gvResult" '
                f'style="border-collapse:collapse;">\r\n{head}\r\n'
                f'<tr><td colspan="{len(EXPORT_HEADER)}">{MSG_NO_DATA}</td></tr>\r\n</table>\r\n</div>')
    out = []
    start = (page - 1) * PAGE_SIZE
    for i, row in enumerate(rows[start:start + PAGE_SIZE]):
        values = _export_values(row)
        cls = ' class="alt"' if i % 2 else ""
        cells = "".join(
            f'<td align="right">{v}</td>' if isinstance(v, int) else f"<td>{_esc(v)}</td>" for v in values
        )
        out.append(f"<tr{cls}>{cells}</tr>")
    if page_count > 1:
        links = []
        for n in range(1, page_count + 1):
            if n == page:
                links.append(f"<td><span>{n}</span></td>")
            else:
                links.append(f"<td><a href=\"javascript:__doPostBack('gvResult','Page${n}')\">{n}</a></td>")
        out.append(f'<tr class="pager"><td colspan="{len(EXPORT_HEADER)}"><table border="0"><tr>'
                   + "".join(links) + "</tr></table></td></tr>")
    return ('<div>\r\n<table class="grid" cellspacing="0" rules="all" border="1" id="gvResult" '
            f'style="border-collapse:collapse;">\r\n{head}\r\n' + "\r\n".join(out) + "\r\n</table>\r\n</div>")


def _search_html(user: str, navkey: str, vs: str, ev: str, ctl: Dict[str, str], message: str,
                 grid: str, count: str) -> str:
    lines = LINES.get(ctl["plant"], ())
    pick_js = (
        "var plant = document.getElementById('ddlPlant').value; "
        "if (plant == '') { alert('先に工場を選択してください。'); return false; } "
        "var r = window.showModalDialog('ItemPicker.aspx?plant=' + plant + '&key=" + navkey
        + "', window, 'dialogWidth:420px;dialogHeight:360px'); "
        "if (r) document.getElementById('txtItem').value = r; return false;"
    )
    body = (
        _header(user) + '\r\n<div id="content">\r\n'
        + _form_open(f"Search.aspx?key={navkey}", vs, "Search.aspx", ev, postback=True)
        + "<h2>生産実績照会</h2>\r\n"
        '<table class="form">\r\n'
        '<tr><th>工場</th><td><select name="ddlPlant" onchange="__doPostBack(\'ddlPlant\',\'\')" id="ddlPlant" '
        'style="width:160px;">\r\n' + _options((("", "-- 選択してください --"),) + PLANTS, ctl["plant"])
        + "\r\n</select></td></tr>\r\n"
        '<tr><th>ライン</th><td><select name="ddlLine" id="ddlLine" style="width:160px;">\r\n'
        + _options(lines, ctl["line"]) + "\r\n</select></td></tr>\r\n"
        '<tr><th>直</th><td><select name="ddlShift" id="ddlShift">\r\n' + _options(SHIFTS, ctl["shift"])
        + "\r\n</select></td></tr>\r\n"
        '<tr><th>期間</th><td><input name="txtFrom" type="text" value="' + _esc(ctl["from"])
        + '" maxlength="10" id="txtFrom" style="width:90px;" /> から '
        '<input name="txtTo" type="text" value="' + _esc(ctl["to"])
        + '" maxlength="10" id="txtTo" style="width:90px;" /> まで（yyyy/mm/dd）</td></tr>\r\n'
        '<tr><th>品番</th><td><input name="txtItem" type="text" value="' + _esc(ctl["item"])
        + '" readonly="readonly" id="txtItem" style="width:100px;" /> '
        f'<input type="button" name="btnPick" value="品番選択" id="btnPick" onclick="{pick_js}" /> '
        '<input type="button" name="btnClearItem" value="クリア" id="btnClearItem" '
        "onclick=\"document.getElementById('txtItem').value='';\" /></td></tr>\r\n"
        "</table>\r\n"
        "<p>"
        '<input type="submit" name="btnSearch" value="検索" id="btnSearch" /> '
        '<input type="submit" name="btnExcel" value="Excel出力" id="btnExcel" /> '
        '<input type="button" name="btnClose" value="閉じる" id="btnClose" onclick="window.close();" />'
        "</p>\r\n"
        f'<p><span id="lblMessage" class="msg">{_esc(message)}</span></p>\r\n'
        f'<p class="count"><span id="lblCount">{_esc(count)}</span></p>\r\n'
        + grid + "\r\n</form>\r\n</div>"
    )
    return _page("生産管理システム - 生産実績照会", body)


def _ysod_html(title: str, long_message: str, exc_type: str) -> str:
    body = (
        "<span><h1>Server Error in '/' Application.<hr width=\"100%\" size=\"1\" color=\"silver\" /></h1>\r\n"
        f"<h2> <i>{_esc(long_message)}</i> </h2></span>\r\n"
        '<font face="Arial, Helvetica, Geneva, SunSans-Regular, sans-serif ">\r\n'
        "<b> Description: </b>An unhandled exception occurred during the execution of the current web "
        "request. Please review the stack trace for more information about the error and where it "
        "originated in the code.<br /><br />\r\n"
        f"<b> Exception Details: </b>{_esc(exc_type)}: {_esc(long_message)}<br /><br />\r\n"
        "</font>\r\n"
        "<hr width=\"100%\" size=\"1\" color=\"silver\" />\r\n"
        "<b>Version Information:</b>&nbsp;Microsoft .NET Framework Version:4.0.30319; "
        "ASP.NET Version:4.0.30319.42000"
    )
    return _page(title, body)


_VIEWSTATE_LONG = (VIEWSTATE_ERROR + " If this application is hosted by a Web Farm or cluster, ensure that "
                   "<machineKey> configuration specifies the same validationKey and validation algorithm. "
                   "AutoGenerate cannot be used in a cluster.")
_POSTBACK_LONG = (POSTBACK_ERROR + "  Event validation is enabled using <pages enableEventValidation=\"true\"/> "
                  "in configuration or <%@ Page EnableEventValidation=\"true\" %> in a page.  For security "
                  "purposes, this feature verifies that arguments to postback or callback events originate "
                  "from the server control that originally rendered them.")


def _error_html(title: str, heading: str, text: str, back: str = "") -> str:
    link = f'<p><a href="{_esc(back)}">メニューへ戻る</a></p>' if back else ""
    body = (_header() + '\r\n<div id="content">\r\n'
            f'<h2>{_esc(heading)}</h2>\r\n<p class="msg">{_esc(text)}</p>\r\n{link}\r\n</div>')
    return _page(title, body)


# --------------------------------------------------------------------------- request handler


def _initial_controls() -> Dict[str, str]:
    return {"plant": "", "line": "", "shift": "ALL", "from": DEFAULT_FROM, "to": DEFAULT_TO, "item": ""}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Microsoft-IIS/8.5"
    sys_version = ""
    server: "FactoryServer"

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - silence stderr access log
        pass

    # ---- plumbing ---------------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        self._dispatch("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch("HEAD")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        self._method = method
        self._sent = False
        parts = urlsplit(self.path)
        self._path = parts.path or "/"
        self._qs = dict(parse_qsl(parts.query, keep_blank_values=True, encoding=CODEC, errors="replace"))
        self._entry: Dict[str, Any] = {
            "t": None, "method": method, "path": self._path, "query": parts.query, "session": None,
            "auth_ok": False, "event": None, "status": None, "ua": self.headers.get("User-Agent"), "details": {},
        }
        try:
            self._form = self._read_form() if method == "POST" else {}
            self._cookies = _parse_cookies(self.headers.get("Cookie"))
            sid = self._cookies.get(SESSION_COOKIE)
            self._sess, self._auth_ok = self.server.state.lookup(sid, self._cookies.get(AUTH_COOKIE))
            self._entry["session"] = self._sess.sid if self._sess is not None else None
            self._entry["auth_ok"] = self._auth_ok
            if sid and self._sess is None:
                self._entry["details"]["unknown_session"] = _prefix(sid, 8)
            self._route()
        except Exception as exc:  # pragma: no cover - diagnostics only
            self._entry["event"] = "server_error"
            self._entry["details"]["error"] = repr(exc)
            if not self._sent:
                try:
                    self._html(500, _ysod_html("Runtime Error", "Runtime Error", "System.Exception"))
                except OSError:
                    pass
        finally:
            self._entry["t"] = round(time.time(), 3)
            self.server.write_log(self._entry)

    def _read_form(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/x-www-form-urlencoded" not in ctype:
            self._entry["details"]["content_type"] = ctype
            return {}
        return parse_form(body)

    def _event(self, name: str, **details: Any) -> None:
        self._entry["event"] = name
        self._entry["details"].update(details)

    def _send(self, status: int, body: bytes, ctype: Optional[str], headers: Sequence[Tuple[str, str]] = ()) -> None:
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        if status != 304:
            self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("X-AspNet-Version", "4.0.30319")
        self.send_header("X-Powered-By", "ASP.NET")
        self.end_headers()
        if self._method != "HEAD" and status != 304:
            self.wfile.write(body)
        self._sent = True
        self._entry["status"] = status

    def _html(self, status: int, text: str, headers: Sequence[Tuple[str, str]] = ()) -> None:
        nocache = [("Cache-Control", "no-cache"), ("Pragma", "no-cache"), ("Expires", "-1")]
        self._send(status, text.encode(CODEC, "xmlcharrefreplace"), HTML_CONTENT_TYPE, nocache + list(headers))

    def _redirect(self, location: str, headers: Sequence[Tuple[str, str]] = ()) -> None:
        text = ("<html><head><title>Object moved</title></head><body>\r\n"
                f'<h2>Object moved to <a href="{_esc(location)}">here</a>.</h2>\r\n</body></html>\r\n')
        self._send(302, text.encode(CODEC), HTML_CONTENT_TYPE,
                   [("Cache-Control", "private"), ("Location", location)] + list(headers))

    def _viewstate_error(self, event: str, reason: str, form: Dict[str, str]) -> None:
        self._event(event, reason=reason, viewstate=_prefix(form.get("__VIEWSTATE")),
                    eventvalidation=_prefix(form.get("__EVENTVALIDATION")))
        self._html(500, _ysod_html(VIEWSTATE_ERROR, _VIEWSTATE_LONG, "System.Web.HttpException"))

    def _postback_error(self, reason: str, form: Dict[str, str]) -> None:
        self._event("eventvalidation_reject", reason=reason, viewstate=_prefix(form.get("__VIEWSTATE")),
                    eventvalidation=_prefix(form.get("__EVENTVALIDATION")))
        self._html(500, _ysod_html(POSTBACK_ERROR, _POSTBACK_LONG, "System.ArgumentException"))

    # ---- routing ----------------------------------------------------------------------------

    def _route(self) -> None:
        p = self._path.lower()
        if p in ("/", "/default.aspx"):
            self._event("redirect", to="/Login.aspx")
            return self._redirect("/Login.aspx")
        if p in STATIC_FILES:
            return self._static(p)
        if p == "/login.aspx":
            return self._login_post() if self._method == "POST" else self._login_get()
        if p == "/logout.aspx":
            return self._logout()
        handler = {
            "/menu.aspx": self._menu,
            "/news.aspx": self._news,
            "/search.aspx": self._search,
            "/itempicker.aspx": self._picker,
        }.get(p)
        if handler is None:
            self._event("not_found")
            return self._html(404, _error_html("404 - File or directory not found.",
                                               "404 - ファイルまたはディレクトリが見つかりません。",
                                               "検索しているリソースは、削除されたか、名前が変更されたか、"
                                               "または一時的に使用できない可能性があります。"))
        if not self._auth_ok:
            if self._sess is None:
                reason = "unknown_session" if self._cookies.get(SESSION_COOKIE) else "no_session"
            elif not self._sess.auth:
                reason = "not_logged_in"
            else:
                reason = "bad_auth_cookie" if self._cookies.get(AUTH_COOKIE) else "no_auth_cookie"
            target = "/Login.aspx?ReturnUrl=" + _return_url(self._path)
            self._event("auth_redirect", reason=reason, to=target)
            return self._redirect(target)
        return handler()

    def _static(self, p: str) -> None:
        ctype, data, etag = STATIC_FILES[p]
        headers = [("Last-Modified", STATIC_LAST_MODIFIED), ("ETag", etag), ("Accept-Ranges", "bytes")]
        if self.headers.get("If-None-Match") == etag or self.headers.get("If-Modified-Since") == STATIC_LAST_MODIFIED:
            self._event("static", not_modified=True)
            return self._send(304, b"", None, headers)
        self._event("static")
        self._send(200, data, ctype, headers)

    def _simple_postback(self, page: str) -> bool:
        """Token check for a POST to a page without postback controls; False when rejected."""
        if self._method != "POST":
            return True
        state = self.server.state
        with state.lock:
            tok, event, reason = state.check(self._sess, page, self._form)
            if tok is not None:
                tok.used = True
        if tok is None:
            self._viewstate_error(event or "viewstate_reject", reason or "", self._form)
            return False
        return True

    # ---- login / logout ---------------------------------------------------------------------

    def _login_get(self) -> None:
        sess = self._sess
        headers = []
        details: Dict[str, Any] = {}
        if sess is None:
            sess = self.server.state.new_session()
            headers.append(("Set-Cookie", f"{SESSION_COOKIE}={sess.sid}; path=/; HttpOnly"))
            details["new_session"] = sess.sid
        vs, ev = self.server.state.issue(sess, "Login.aspx")
        self._event("login_page", **details)
        self._html(200, _login_html(vs, ev or ""), headers)

    def _login_post(self) -> None:
        form = self._form
        state = self.server.state
        with state.lock:
            tok, event, reason = state.check(self._sess, "Login.aspx", form)
            if tok is not None:
                tok.used = True
        if tok is None:
            return self._viewstate_error(event or "viewstate_reject", reason or "", form)
        sess = self._sess
        assert sess is not None
        user_id = form.get("txtUserId", "")
        password = form.get("txtPassword", "")
        if "btnLogin" not in form:
            vs, ev = state.issue(sess, "Login.aspx")
            self._event("postback", reason="no_button")
            return self._html(200, _login_html(vs, ev or "", user_id))
        if (user_id, password) != CREDENTIALS:
            message = MSG_LOGIN_EMPTY if not user_id or not password else MSG_LOGIN_FAIL
            vs, ev = state.issue(sess, "Login.aspx")
            self._event("login_fail", user=user_id, password_mask=_mask(password),
                        button=form.get("btnLogin"), reason="empty" if message == MSG_LOGIN_EMPTY else "credentials")
            return self._html(200, _login_html(vs, ev or "", user_id, message))
        new = state.login(sess, user_id)
        self._event("login_ok", user=user_id, old_session=sess.sid, new_session=new.sid,
                    button=form.get("btnLogin"))
        self._redirect("/Menu.aspx", [
            ("Set-Cookie", f"{SESSION_COOKIE}={new.sid}; path=/; HttpOnly"),
            ("Set-Cookie", f"{AUTH_COOKIE}={new.auth}; path=/; HttpOnly"),
        ])

    def _logout(self) -> None:
        if self._sess is not None:
            self.server.state.drop(self._sess.sid)
        self._event("logout", was_authenticated=self._auth_ok)
        self._redirect("/Login.aspx", [
            ("Set-Cookie", f"{AUTH_COOKIE}=; expires=Mon, 11-Oct-1999 00:00:00 GMT; path=/; HttpOnly"),
        ])

    # ---- simple pages -----------------------------------------------------------------------

    def _menu(self) -> None:
        if not self._simple_postback("Menu.aspx"):
            return
        sess = self._sess
        assert sess is not None
        vs, _ev = self.server.state.issue(sess, "Menu.aspx", with_ev=False)
        self._event("menu")
        self._html(200, _menu_html(USER_NAME, sess.navkey or "", vs))

    def _news(self) -> None:
        if not self._simple_postback("News.aspx"):
            return
        sess = self._sess
        assert sess is not None
        vs, _ev = self.server.state.issue(sess, "News.aspx", with_ev=False)
        self._event("news")
        self._html(200, _news_html(USER_NAME, vs))

    def _navkey_ok(self) -> bool:
        key = self._qs.get("key", "")
        sess = self._sess
        if sess is not None and sess.navkey and key == sess.navkey:
            return True
        self._event("navkey_reject", key=_prefix(key, 8) if key else None)
        self._html(403, _error_html("エラー - 生産管理システム", "不正なアクセスです。",
                                    "画面の URL が正しくありません。メニュー画面から操作し直してください。",
                                    back="Menu.aspx"))
        return False

    def _picker(self) -> None:
        if not self._navkey_ok() or not self._simple_postback("ItemPicker.aspx"):
            return
        sess = self._sess
        assert sess is not None
        plant = self._qs.get("plant", "")
        vs, _ev = self.server.state.issue(sess, "ItemPicker.aspx", {"plant": plant}, with_ev=False)
        self._event("picker", plant=plant, items=len(ITEMS.get(plant, ())))
        self._html(200, _picker_html(USER_NAME, plant, sess.navkey or "", vs))

    # ---- Search.aspx ------------------------------------------------------------------------

    def _search(self) -> None:
        if not self._navkey_ok():
            return
        if self._method != "POST":
            return self._render_search(_initial_controls(), None, 0, "", "search_page", {})
        form = self._form
        target = form.get("__EVENTTARGET", "")
        argument = form.get("__EVENTARGUMENT", "")
        if target:
            kind = target
        elif "btnSearch" in form:
            kind = "search"
        elif "btnExcel" in form:
            kind = "excel"
        else:
            kind = "postback"
        state = self.server.state
        rendered: Dict[str, Any] = {}
        ctl: Dict[str, str] = {}
        failure: Optional[Tuple[str, str]] = None  # (event, reason)
        with state.lock:  # check + mark used atomically; respond after releasing the lock
            tok, event, reason = state.check(self._sess, "Search.aspx", form)
            if tok is None:
                failure = (event or "viewstate_reject", reason or "")
            else:
                rendered = tok.state
                ctl = {
                    "plant": form.get("ddlPlant", rendered.get("plant", "")),
                    "line": form.get("ddlLine", ""),
                    "shift": form.get("ddlShift", "ALL"),
                    "from": form.get("txtFrom", ""),
                    "to": form.get("txtTo", ""),
                    "item": form.get("txtItem", "").strip(),
                }
                bad = self._bad_postback_argument(rendered, form, target, argument)
                if bad is None and kind in ("search", "excel"):
                    plant_lines = [code for code, _name in LINES.get(ctl["plant"], ())]
                    if ctl["plant"] and ctl["line"] and ctl["line"] not in plant_lines:
                        bad = f"line_not_in_plant:{ctl['line']}@{ctl['plant']}"
                if bad is not None:
                    failure = ("eventvalidation_reject", bad)
                elif kind != "excel":
                    tok.used = True  # the download leaves the page (and its tokens) in the browser
        if failure is not None:
            if failure[0] == "eventvalidation_reject" and tok is not None:
                return self._postback_error(failure[1], form)
            return self._viewstate_error(failure[0], failure[1], form)
        if kind == "ddlPlant":
            if ctl["plant"] != rendered.get("plant", ""):
                lines = LINES.get(ctl["plant"], ())
                ctl["line"] = lines[0][0] if lines else ""
                ctl["item"] = ""
            return self._render_search(ctl, None, 0, "", "plant_change", {"plant": ctl["plant"]})
        if kind == "gvResult":
            page = int(argument.split("$", 1)[1])
            return self._render_search(ctl, rendered["result"], page, "", "page", {})
        if kind == "postback":
            return self._render_search(ctl, rendered.get("result"), rendered.get("page_index", 0), "", "postback", {})
        # decoded submit-button value ("検索" / "Excel出力"): shows whether the form came in cp932
        button = form.get("btnSearch") if kind == "search" else form.get("btnExcel")
        filters, message = self._filters(ctl)
        if message:
            return self._render_search(ctl, None, 0, message, f"{kind}_invalid",
                                       {"message": message, "button": button})
        assert filters is not None
        if kind == "search":
            return self._render_search(ctl, filters, 1, "", "search", {"button": button})
        return self._excel(filters, button)

    @staticmethod
    def _bad_postback_argument(rendered: Dict[str, Any], form: Dict[str, str], target: str,
                               argument: str) -> Optional[str]:
        """Event validation: every posted value must be one the page rendered."""
        plant = form.get("ddlPlant")
        if plant is not None and plant not in ("",) + tuple(code for code, _ in PLANTS):
            return f"ddlPlant:{plant}"
        shift = form.get("ddlShift")
        if shift is not None and shift not in tuple(code for code, _ in SHIFTS):
            return f"ddlShift:{shift}"
        line = form.get("ddlLine")
        if line is not None and line not in rendered.get("lines", ()):
            return f"ddlLine_not_rendered:{line}"
        if target == "ddlPlant":
            if argument:
                return f"ddlPlant_argument:{argument}"
        elif target == "gvResult":
            pages = {f"Page${n}" for n in range(1, int(rendered.get("page_count") or 0) + 1)}
            if argument not in pages:
                return f"gvResult_argument:{argument}"
        elif target:
            return f"__EVENTTARGET:{target}"
        return None

    @staticmethod
    def _filters(ctl: Dict[str, str]) -> Tuple[Optional[Dict[str, str]], str]:
        plant, line = ctl["plant"], ctl["line"]
        if not plant:
            return None, MSG_NEED_PLANT
        if not line:
            return None, MSG_NEED_LINE
        lo, hi = parse_date(ctl["from"]), parse_date(ctl["to"])
        if lo is None or hi is None:
            return None, MSG_BAD_DATE
        if lo > hi:
            return None, MSG_BAD_RANGE
        item = ctl["item"]
        if item and item not in [code for code, _ in ITEMS[plant]]:
            return None, MSG_BAD_ITEM
        return {"plant": plant, "line": line, "shift": ctl["shift"] or "ALL", "from": lo, "to": hi, "item": item}, ""

    def _render_search(self, ctl: Dict[str, str], result: Optional[Dict[str, str]], page: int, message: str,
                       event: str, details: Dict[str, Any]) -> None:
        sess = self._sess
        assert sess is not None
        rows = (_query(result["plant"], result["line"], result["shift"], result["from"], result["to"], result["item"])
                if result else None)
        page_count = (len(rows) + PAGE_SIZE - 1) // PAGE_SIZE if rows else 0
        if rows:
            page = min(max(page, 1), page_count)
        lines = [code for code, _name in LINES.get(ctl["plant"], ())]
        vs, ev = self.server.state.issue(sess, "Search.aspx", {
            "plant": ctl["plant"], "lines": lines, "result": result, "page_index": page, "page_count": page_count,
        })
        if rows is None:
            grid, count = "", ""
        else:
            grid = _grid_html(rows, page, page_count)
            count = f"該当件数: {len(rows)} 件（{page}/{page_count} ページ）" if rows else "該当件数: 0 件"
            details = dict(details, filters=result, rows=len(rows), page=page, page_count=page_count,
                           rows_on_page=len(rows[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]) if rows else 0)
        self._event(event, **details)
        self._html(200, _search_html(USER_NAME, sess.navkey or "", vs, ev or "", ctl, message, grid, count))

    def _excel(self, filters: Dict[str, str], button: Optional[str] = None) -> None:
        raw = _query(filters["plant"], filters["line"], filters["shift"], filters["from"], filters["to"], filters["item"])
        export_id = "EX" + secrets.token_hex(6).upper()
        sheet = [EXPORT_HEADER] + [_export_values(r) for r in raw] + [(EXPORT_ID_LABEL, export_id)]
        data = build_xlsx(sheet)
        name = export_filename(filters["plant"], filters["line"])
        self._event("excel_export", filters=filters, rows=len(raw), export_id=export_id, filename=name,
                    button=button)
        self._send(200, data, XLSX_CONTENT_TYPE, [
            ("Content-Disposition", "attachment; filename=" + quote(name, safe="")),
            ("Cache-Control", "private"),
        ])


# --------------------------------------------------------------------------- server


class FactoryServer(ThreadingHTTPServer):
    """The site.  ``serve_forever()`` / ``shutdown()`` from any thread; :attr:`state` holds the sessions."""

    daemon_threads = True
    # SO_REUSEADDR on Windows would let two servers share a port: never wanted here.
    allow_reuse_address = sys.platform != "win32"

    def __init__(self, address: Tuple[str, int], log_path: str) -> None:
        self.log_path = log_path
        self.state = SiteState()
        self._log_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        super().__init__(address, _Handler)

    def server_bind(self) -> None:
        """Like HTTPServer.server_bind without ``socket.getfqdn()`` (a reverse DNS lookup that can
        stall for seconds on PCs with a slow intranet DNS)."""
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    @property
    def host(self) -> str:
        return str(self.server_address[0])

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A browser dropping a keep-alive connection is normal: no traceback on stderr for that."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError)):
            return
        super().handle_error(request, client_address)

    def write_log(self, entry: Dict[str, Any]) -> None:
        line = json.dumps(entry, ensure_ascii=False)
        with self._log_lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def start(self) -> "FactoryServer":
        """Serve from a daemon thread."""
        if self._thread is None:
            self._thread = threading.Thread(target=self.serve_forever, name=f"factory_site:{self.port}", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        """Stop a server started with :meth:`start` and close its socket."""
        if self._thread is not None:
            self.shutdown()
            self._thread.join(timeout=10)
            self._thread = None
        self.server_close()


def make_server(log_path: str, port: int, host: str = HOST, truncate_log: bool = True) -> FactoryServer:
    """Bind the site (``port=0`` picks a free port; see :attr:`FactoryServer.port`).

    Nothing is served until ``serve_forever()`` (or :meth:`FactoryServer.start`).  ``truncate_log``
    empties ``log_path`` first.
    """
    server = FactoryServer((host, int(port)), log_path)
    if truncate_log:
        open(log_path, "w", encoding="utf-8").close()
    return server


def serve_in_thread(log_path: str, port: int = 0, host: str = HOST, truncate_log: bool = True) -> FactoryServer:
    """:func:`make_server` + :meth:`FactoryServer.start`; call ``server.stop()`` when done."""
    return make_server(log_path, port, host, truncate_log).start()


def factory_site_main(argv: Optional[Sequence[str]] = None) -> None:
    """Command line: ``ie_support.py factory-site [LOGFILE [PORT [HOST]]]``."""
    args = list(sys.argv[1:] if argv is None else argv)
    log_path = args[0] if args else DEFAULT_LOG
    port = int(args[1]) if len(args) > 1 else DEFAULT_PORT
    host = args[2] if len(args) > 2 else HOST
    server = make_server(log_path, port, host)
    print(f"factory_site listening on {server.base_url} (log: {log_path})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# ===== former tests/iehost_fixtures/factory_scenario.py: records the factory site in the real recording browser =====
# Records the factory mock site (the ``factory_site`` section above) through the real recording browser - TEST ONLY.
#
# :func:`run_factory_recording` starts the mock 生産管理システム, a recorder (mitmdump + the reqrec addon,
# the GUI's ``HTTPS_PASSTHROUGH_ARGS``) and ``RecBrowser.exe``, then operates the pages with the test driver
# (``IEDriver.cs`` / the ``iedriver`` section below) exactly like a factory user would:
#
# ==================  ==========================================================================
# step                what the user does (what the engine sends)
# ==================  ==========================================================================
# ``start``           the browser opens ``/Login.aspx`` (GET, ``ASP.NET_SessionId``)
# ``login``           types tanaka / ``Seisan#2026!`` and clicks ログイン (POST -> 302 -> /Menu.aspx)
# ``open_search``     clicks 生産実績照会 = ``window.open('Search.aspx?key=<NAVKEY>')`` -> popup tab
# ``plant``           selects 本社工場 (AutoPostBack: ``__doPostBack('ddlPlant','')`` POST)
# ``line_shift``      selects 組立1ライン and 日勤 (no request)
# ``item_picker``     clicks 品番選択 = ``showModalDialog('ItemPicker.aspx?...')`` (GET in a dialog),
#                     clicks A-1002 there; the dialog closes and txtItem becomes ``A-1002``
# ``search``          clicks 検索 (POST; 35 rows = 2 pages)
# ``page2``           clicks the pager link 2 = ``javascript:__doPostBack('gvResult','Page$2')`` (POST)
# ``excel``           clicks Excel出力 (POST answered with the .xlsx) and cancels the engine's
#                     「ファイルのダウンロード」 dialog with キャンセル
# ``news``            clicks お知らせ in the menu tab (``target=_blank`` GET in a new tab)
# ``close``           closes the browser window (WM_CLOSE, exit code 0)
# ==================  ==========================================================================
#
# Nothing is asserted here: the function only raises when a step cannot be performed in time
# (:class:`ScenarioError` / :class:`IEDriverError`).  The caller judges the run from the site log
# (:func:`read_log`), the recording JSON and the returned timings.  The search filter is
# :data:`SCENARIO_FILTER`; :func:`expected_rows(*SCENARIO_FILTER) <expected_rows>` gives the rows of the grid
# and of the Excel file.
#
# Requirements: Windows, the inbox C# compiler (for ``IEDriver.exe``), mitmproxy, a compiled
# ``RecBrowser.exe`` (``reqrec.iehost.ensure_built``) and DNS for ``127.0.0.1.nip.io`` (WinINet never
# proxies literal loopback addresses; without that name the site is addressed as ``127.0.0.1`` with the
# ``<-loopback>`` bypass override).  RecBrowser's windows appear on screen while the scenario runs.
#
# Usage::
#
#     scenario = <import tests/ie_support.py by path>
#     result = scenario.run_factory_recording(workdir, out_json, site_port=0, proxy_port=0,
#                                             recbrowser_exe=reqrec.iehost.ensure_built(workdir))
#     result["timings"]      # {"start": 1.9, "login": 1.2, ...} seconds per step
#     result["site_log"]     # factory_site JSON-lines log of this run
#
# Importing this module has no side effects (nothing is compiled, started or written).

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADDON_PATH = os.path.join(ROOT, "reqrec.py")

#: :func:`expected_rows` arguments of the search the scenario performs
#: (plant, line, shift, date_from, date_to, item); the dates are the page's defaults.
SCENARIO_FILTER = ("01", "L11", "D", "2026/09/01", "2026/10/10", "A-1002")

#: Step names, in order (keys of the returned ``timings``).
STEPS = ("start", "login", "open_search", "plant", "line_shift", "item_picker", "search", "page2",
         "excel", "news", "close")

#: Title / button of the engine's download dialog (Japanese Windows).
DOWNLOAD_DIALOG_TITLE = "ファイルのダウンロード"
DOWNLOAD_CANCEL = "キャンセル"

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class ScenarioError(RuntimeError):
    """A step could not be completed (timeout or a process that died)."""


# --------------------------------------------------------------------------- small helpers

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def site_host() -> tuple:
    """``(host, proxy_bypass)``: ``127.0.0.1.nip.io`` when it resolves to 127.0.0.1, else the literal
    address with WinINet's ``<-loopback>`` override (WinINet never proxies loopback addresses)."""
    try:
        infos = socket.getaddrinfo("127.0.0.1.nip.io", None, socket.AF_INET)
        if any(info[4][0] == "127.0.0.1" for info in infos):
            return "127.0.0.1.nip.io", ""
    except OSError:
        pass
    return "127.0.0.1", "<-loopback>"


def _wait_port(port: int, timeout: float, proc: Optional[subprocess.Popen] = None, what: str = "port") -> None:
    deadline = time.monotonic() + timeout
    while True:
        if proc is not None and proc.poll() is not None:
            raise ScenarioError(f"{what} exited early with code {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise ScenarioError(f"{what} did not listen on port {port} within {timeout:.0f}s") from None
            time.sleep(0.2)


def _kill(proc: Optional[subprocess.Popen]) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        pass


def _mitmdump_command(out_json: str, proxy_port: int) -> List[str]:
    """``mitmdump -s <addon> --set reqrec_out=<file> -p <port> --listen-host 127.0.0.1 --set flow_detail=0``
    plus the GUI's ``HTTPS_PASSTHROUGH_ARGS`` (HTTPS on every port passes through unrecorded, as in the
    recording browser started by the GUI); the venv's mitmdump next to this interpreter when present."""
    from reqrec import HTTPS_PASSTHROUGH_ARGS

    scripts = os.path.dirname(os.path.abspath(sys.executable))
    exe = os.path.join(scripts, "mitmdump.exe" if os.name == "nt" else "mitmdump")
    if os.path.isfile(exe):
        launcher = [exe]
    elif shutil.which("mitmdump"):
        launcher = [str(shutil.which("mitmdump"))]
    else:
        launcher = [sys.executable, "-c", "import sys; from mitmproxy.tools.main import mitmdump; sys.exit(mitmdump())"]
    return launcher + [
        "-s", ADDON_PATH, "--set", f"reqrec_out={os.path.abspath(out_json)}", "-p", str(int(proxy_port)),
        "--listen-host", "127.0.0.1", "--set", "flow_detail=0", *HTTPS_PASSTHROUGH_ARGS,
    ]


def _poll(what: str, probe: Callable[[], Any], timeout: float, interval: float = 0.2) -> Any:
    """Call ``probe`` until it returns something truthy; driver errors count as "not yet"."""
    deadline = time.monotonic() + timeout
    last: Any = None
    while True:
        try:
            value = probe()
        except Exception as exc:  # IEDriverError while a page is being replaced
            value, last = None, exc
        if value:
            return value
        if time.monotonic() >= deadline:
            raise ScenarioError(f"timeout ({timeout:.0f}s) waiting for {what}" + (f": {last}" if last else ""))
        time.sleep(interval)


# --------------------------------------------------------------------------- the scenario

def _operate(drv: Any, browser: subprocess.Popen, step: Callable[[str], Any], pending: List[subprocess.Popen],
             info: Dict[str, Any], timeout: float) -> None:
    user, password = info["credentials"]
    search = "/Search.aspx?key="

    def alive() -> None:
        if browser.poll() is not None:
            raise ScenarioError(f"RecBrowser exited unexpectedly (code {browser.returncode})")

    with step("start"):
        drv.wait("/Login.aspx", text="ログイン", kind="tab", timeout=max(timeout, 60.0))

    with step("login"):
        drv.value("/Login.aspx", id="txtUserId", value=user, kind="tab")
        drv.value("/Login.aspx", id="txtPassword", value=password, kind="tab")
        drv.click("/Login.aspx", id="btnLogin", kind="tab")
        drv.wait("/Menu.aspx", text="ようこそ", kind="tab", timeout=timeout)

    with step("open_search"):
        drv.click("/Menu.aspx", id="lnkSearch", kind="tab")   # window.open -> a new tab
        drv.wait(search, text="生産実績照会", kind="tab", timeout=timeout)

    with step("plant"):
        drv.select(search, id="ddlPlant", text="本社工場", kind="tab")   # onchange -> __doPostBack
        # same URL after the postback: wait until the NEW document has the line options
        _poll("the plant postback (ddlLine filled)",
              lambda: int(drv.attr(search, id="ddlLine", name="length", kind="tab", timeout=2)["value"] or 0) > 0,
              timeout)
        drv.wait(search, text="生産実績照会", kind="tab", timeout=timeout)

    with step("line_shift"):
        drv.select(search, id="ddlLine", text="組立1ライン", kind="tab")
        drv.select(search, id="ddlShift", text="日勤", kind="tab")

    with step("item_picker"):
        clicking = drv.click_async(search, id="btnPick", kind="tab")   # blocks until the modal closes
        pending.append(clicking)
        drv.wait("/ItemPicker.aspx", text="A-1002", kind="dialog", timeout=timeout)
        drv.click("/ItemPicker.aspx", id="item_A-1002", kind="dialog")   # returnValue + window.close()
        drv.finish(clicking, timeout=timeout)
        pending.remove(clicking)
        _poll("txtItem = A-1002",
              lambda: drv.attr(search, id="txtItem", name="value", kind="tab", timeout=2)["value"] == "A-1002",
              timeout)

    with step("search"):
        drv.click(search, id="btnSearch", kind="tab")
        drv.wait(search, text="1/2 ページ", kind="tab", timeout=timeout)

    with step("page2"):
        drv.click(search, link_text="2", kind="tab")   # javascript:__doPostBack('gvResult','Page$2')
        drv.wait(search, text="2/2 ページ", kind="tab", timeout=timeout)

    with step("excel"):
        drv.click(search, id="btnExcel", kind="tab")
        info["download_dialog"] = drv.dialog(title=DOWNLOAD_DIALOG_TITLE, button=DOWNLOAD_CANCEL,
                                             timeout=max(timeout, 20.0))
        alive()

    with step("news"):
        drv.click("/Menu.aspx", id="lnkNews", kind="tab")   # target=_blank -> a new tab
        drv.wait("/News.aspx", text="システムメンテナンス", kind="tab", timeout=timeout)

    with step("close"):
        info["close"] = drv.close(timeout=max(timeout, 20.0))
        try:
            info["browser_exit_code"] = browser.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise ScenarioError("RecBrowser did not exit after WM_CLOSE") from None


class _Steps:
    """``with step("name"):`` records the duration of each step (also of a failing one)."""

    def __init__(self) -> None:
        self.timings: "OrderedDict[str, float]" = OrderedDict()
        self.current: Optional[str] = None
        self._name = ""
        self._t0 = 0.0

    def __call__(self, name: str) -> "_Steps":
        self._name = name
        return self

    def __enter__(self) -> "_Steps":
        self.current = self._name
        self._t0 = time.monotonic()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.timings[self._name] = round(time.monotonic() - self._t0, 3)
        if exc_type is None:
            self.current = None


def run_factory_recording(
    workdir: str,
    out_json: str,
    site_port: int,
    proxy_port: int,
    recbrowser_exe: str,
    *,
    driver_exe: Optional[str] = None,
    timeout: float = 30.0,
    keep_site: bool = False,
    title: str = "生産管理 記録",
) -> Dict[str, Any]:
    """Run the recording scenario of the module docstring and return what happened.

    ``workdir`` receives the site log (``factory_site.log``), ``recbrowser.log``, ``mitmdump.out`` and
    (unless ``driver_exe`` is given) the compiled driver in ``iedriver_bin/``.  ``out_json`` is the
    recording the reqrec addon writes (deleted first).  ``site_port`` / ``proxy_port`` 0 = a free port.
    ``timeout`` bounds each wait of the scenario (the first page and the download dialog get at least
    60 s / 20 s).  With ``keep_site`` the mock site keeps running after the browser is closed and the
    result carries it as ``site_server`` (call ``.stop()``); otherwise it is stopped.

    Returns ``{"timings": {step: seconds}, "setup_seconds", "total_seconds", "site_log", "out_json",
    "recbrowser_log", "mitmdump_log", "base_url", "start_url", "host", "bypass", "site_port",
    "proxy_port", "browser_pid", "browser_exit_code", "close", "download_dialog", "driver_exe",
    "scenario_filter", "credentials", "site_events"}`` (+ ``"site_server"`` with ``keep_site``).
    Raises :class:`ScenarioError` / ``IEDriverError`` (with the timings so far in ``exc.timings`` and
    the step in ``exc.step``) when a step does not complete.
    """
    workdir = os.path.abspath(workdir)
    os.makedirs(workdir, exist_ok=True)
    out_json = os.path.abspath(out_json)
    if os.path.exists(out_json):
        os.remove(out_json)
    site_log = os.path.join(workdir, "factory_site.log")
    host_log = os.path.join(workdir, "recbrowser.log")
    mitm_log = os.path.join(workdir, "mitmdump.out")
    if driver_exe is None:
        driver_exe = build_driver(os.path.join(workdir, "iedriver_bin"))
    host, bypass = site_host()
    proxy_port = int(proxy_port) or free_port()

    info: Dict[str, Any] = {
        "credentials": CREDENTIALS, "scenario_filter": SCENARIO_FILTER, "driver_exe": driver_exe,
        "site_log": site_log, "out_json": out_json, "recbrowser_log": host_log, "mitmdump_log": mitm_log,
        "host": host, "bypass": bypass, "proxy_port": proxy_port, "browser_exit_code": None,
        "close": None, "download_dialog": None,
    }
    steps = _Steps()
    started = time.monotonic()
    server = recorder = browser = None
    pending: List[subprocess.Popen] = []
    ok = False
    try:
        server = make_server(site_log, int(site_port)).start()
        info["site_port"] = server.port
        base = f"http://{host}:{server.port}"
        info["base_url"] = base + "/"
        info["start_url"] = base + "/Login.aspx"
        env = dict(os.environ, PYTHONUNBUFFERED="1")  # mitmdump is killed at the end: keep its log complete
        with open(mitm_log, "w", encoding="utf-8") as out:
            recorder = subprocess.Popen(_mitmdump_command(out_json, proxy_port), stdout=out, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, env=env, creationflags=_NO_WINDOW)
        _wait_port(proxy_port, 60.0, recorder, "mitmdump")
        browser = subprocess.Popen(
            [recbrowser_exe, "--proxy", f"127.0.0.1:{proxy_port}", "--bypass", bypass, "--url", info["start_url"],
             "--title", title, "--log", host_log],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        info["browser_pid"] = browser.pid
        info["setup_seconds"] = round(time.monotonic() - started, 3)
        drv = IEDriver(driver_exe, browser.pid, timeout=timeout)
        _operate(drv, browser, steps, pending, info, timeout)
        ok = True
    except BaseException as exc:
        try:
            exc.timings = dict(steps.timings)  # type: ignore[attr-defined]
            exc.step = steps.current  # type: ignore[attr-defined]
        except Exception:
            pass
        raise
    finally:
        for proc in pending:
            _kill(proc)
        _kill(browser)       # only when the scenario failed before "close"
        _kill(recorder)      # the addon rewrites the recording after every response: nothing is lost
        if server is not None and not (ok and keep_site):
            server.stop()
    info["timings"] = dict(steps.timings)
    info["total_seconds"] = round(time.monotonic() - started, 3)
    info["site_events"] = [entry.get("event") for entry in read_log(site_log)]
    if keep_site:
        info["site_server"] = server
    return info


# ===== former tests/iehost_fixtures/iedriver.py: Python wrapper for IEDriver.exe =====
# Python wrapper for ``IEDriver.exe`` (source: ``IEDriver.cs`` next to this file) - TEST ONLY.
#
# The driver operates the pages inside a running recording browser (``RecBrowser.exe``) the way a
# user would: it finds the IE engine's documents by window handle (WM_HTML_GETOBJECT) and calls DOM
# methods on them, so every navigation, popup, POST and dialog is performed by the engine itself and
# the recorder sees the real browser's HTTP.
#
# Usage::
#
#     iedriver = <import tests/ie_support.py by path, as tests/test_real_engine.py does>
#     exe = iedriver.build_driver(str(tmp_path / "bin"))  # compiles once per source hash
#     drv = iedriver.IEDriver(exe, browser_pid)
#     drv.wait("/index.html", text="index page")
#     drv.click("/index.html", id="lnk")                  # target=_blank -> new tab
#     drv.wait("/settings.html")
#     proc = drv.click_async("/driver.html", id="modalBtn")   # that click blocks until the modal closes
#     drv.wait("/drv_modal.html", kind="dialog")
#     drv.click("/drv_modal.html", id="closeBtn", kind="dialog")
#     drv.finish(proc)                                    # result of the async click
#     drv.dialog(title="ファイルのダウンロード", button="キャンセル")
#     drv.close()                                         # -> {"exited": True, "exitCode": 0, ...}
#
# Every method runs the exe once (``subprocess.run`` with a timeout, no console window) and returns
# the parsed JSON; a failure (exit code 1 or a timeout) raises :class:`IEDriverError` whose ``result``
# holds the driver's JSON (``{"error": ..., "detail": [...documents or dialogs seen...]}``).
#
# Matching: ``url`` is a case-insensitive substring of ``document.URL`` (tabs, dialogs and frames);
# ``kind="tab"|"dialog"|"frame"`` and ``hwnd=`` narrow it further.  Element commands retry (every
# 200 ms) until ``timeout`` while the document or the element is not there yet, preferring documents
# whose readyState is ``complete``.
#
# Pitfalls (measured on Windows 11 with the IE7-mode recording browser):
#
# * Cost: one call is about 0.2-0.4 s (process start + cross-process COM).  ``IEDriver.cs`` uses plain
#   IDispatch late binding on purpose; C# ``dynamic`` made every call 3-8x slower (its COM binder
#   reads the MSHTML type library through cross-process ITypeInfo calls in every new process).
# * Navigation is asynchronous: ``click`` / ``select`` / ``navigate`` return before the new page is
#   loaded, and the old document stays ``complete`` (and may still match a broad ``url``) until it
#   is replaced.  Always ``wait`` for a url substring (or ``text``) that only the new page has, e.g.
#   ``"kind=b"`` after an autopostback of ``/driver.html``.
# * Popups: the new tab exists when the click returns (the host answers NewWindow3 synchronously);
#   ``wait`` for its url.  ``navigate`` and real users type into the *selected* tab, which is the
#   newest popup.  DOM clicks also work on background (hidden) tabs; the driver never switches tabs.
# * Modal blocking: ``element.click()`` returns only when its handler returns, i.e. after an
#   ``alert()`` / ``confirm()`` / ``showModalDialog`` it opened has been closed.  Use
#   :meth:`IEDriver.click_async`, operate the dialog (``wait(kind="dialog")`` + DOM commands for an
#   HTML dialog, :meth:`IEDriver.dialog` for a standard box), then :meth:`IEDriver.finish`.  A plain
#   ``click`` on such a button hangs until the wrapper's timeout (``timeout`` + 15 s), and killing the
#   driver then leaves the dialog open.  While a modal dialog is up the main window is disabled and
#   ``navigate`` / ``close`` refuse (a user could not use them either).
# * Standard dialogs (alert: title 「Web ページからのメッセージ」, button ``OK``; download:
#   「ファイルのダウンロード」 with 開く(&O) / 保存(&S) / キャンセル) are matched by title / static text /
#   button text with ``&`` removed; titles and captions follow the Windows display language.  The
#   download dialog appears 0.3-1.5 s after the click (``dialog`` polls; give it ``timeout=20``).
# * Focus: nothing needs the foreground.  DOM calls and WM_HTML_GETOBJECT work on background or
#   hidden windows; ``dialog`` presses buttons with WM_COMMAND/BN_CLICKED posted to the dialog
#   (``method="bmclick"`` posts BM_CLICK instead, which Windows may ignore for an inactive dialog).
#   RecBrowser's windows still pop up on screen, and a person clicking in them can interfere.
# * ``navigate`` sets the text of RecBrowser's address box (its only WinForms EDIT) and sends Enter;
#   call it when the selected tab is idle (after a ``wait``).  The engine sends no Referer for it,
#   like a typed address, while link clicks / form posts carry one.
# * From Git Bash, run the exe with ``MSYS_NO_PATHCONV=1``: otherwise ``--url /index.html`` is
#   rewritten to a Windows path.  The JSON output is pure ASCII (``\uXXXX``), so console code pages
#   do not matter.
#
# Importing this module has no side effects.

#: C# source of the driver.
DRIVER_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "IEDriver.cs")

#: Inbox C# 5 compiler (.NET Framework 4.x, 64-bit).
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

EXE_NAME = "IEDriver.exe"
HASH_NAME = "IEDriver.cs.sha256"

#: Extra seconds the Python side waits on top of the driver's own ``--timeout`` before killing it.
_MARGIN = 15.0


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


# ===== command line (the former stand-alone scripts) =====

def main(argv: Optional[Sequence[str]] = None) -> None:
    """Command line of the former stand-alone scripts::

        python -I tests/ie_support.py testsite [LOGFILE [PORT]]              # testsite_main
        python -I tests/ie_support.py factory-site [LOGFILE [PORT [HOST]]]   # factory_site_main
        python -I tests/ie_support.py iedriver [OUT_DIR]                     # build IEDriver.exe, print its path
    """
    args = list(sys.argv[1:] if argv is None else argv)
    command = args.pop(0) if args else ""
    if command == "testsite":
        testsite_main(args)
    elif command == "factory-site":
        factory_site_main(args)
    elif command == "iedriver":  # pragma: no cover - manual use
        print(build_driver(args[0] if args else os.path.join(os.getcwd(), "iedriver_bin")))
    else:
        print("usage: python -I ie_support.py testsite|factory-site|iedriver [ARGS...]", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
