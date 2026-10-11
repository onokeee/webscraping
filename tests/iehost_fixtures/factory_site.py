"""Mock legacy factory production-management intranet (生産管理システム) for reqrec / IE-host tests.

It imitates an ASP.NET WebForms site written for Internet Explorer and served by "IIS":

* **Shift_JIS everywhere** — every HTML page carries ``Content-Type: text/html; charset=Shift_JIS``
  and ``<meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS">``; form posts arrive
  percent-encoded in Shift_JIS and are decoded with cp932.  HTML/JS is ES3 / IE7-document-mode safe
  (``onclick`` / ``onchange`` attributes, ``document.getElementById``, ``document.forms``).
* **ASP.NET session + forms authentication** — ``GET /Login.aspx`` issues ``ASP.NET_SessionId``
  (24 lowercase alnum); a successful login *rotates* the session id and sets ``.ASPXAUTH`` (64 hex,
  HttpOnly).  Every page except the login page and the static files needs a valid
  ``ASP.NET_SessionId`` + ``.ASPXAUTH`` pair, otherwise ``302 /Login.aspx?ReturnUrl=<path>``.
* **One-time ``__VIEWSTATE`` / ``__EVENTVALIDATION``** — each rendered page gets fresh random
  tokens bound to the session and to the page.  A postback with a missing / foreign / stale /
  already used token is answered with HTTP 500 "Validation of viewstate MAC failed."; a posted
  value the page never rendered (e.g. a line of another plant) with HTTP 500 "Invalid postback or
  callback argument."  A postback that was *rejected* does not use up its tokens; the Excel
  download does not use them up either (the browser keeps showing the same page, so the next click
  posts the same tokens again).
* **Popups** — Menu.aspx opens 生産実績照会 (Search.aspx) with ``window.open`` and a per-session
  URL key (NAVKEY, cookieless-style; a wrong / missing key is a 403) and お知らせ (News.aspx) with
  ``target="_blank"``.  Search.aspx is a ``__doPostBack`` page: an AutoPostBack plant dropdown
  that fills the line dropdown, a ``showModalDialog`` item picker (ItemPicker.aspx, returns the
  item code through ``window.returnValue``), a paged result grid (``gvResult``, 20 rows per page,
  ``__doPostBack('gvResult','Page$2')``) and an Excel (.xlsx) download with an IE-style
  percent-encoded UTF-8 file name.

Every request is appended as one JSON line to the log file::

    {"t", "method", "path", "query", "session", "auth_ok", "event", "status", "ua", "details"}

``session`` is the server-side session the request's ``ASP.NET_SessionId`` cookie names (``null``
when there is none / it is unknown); ``event`` is e.g. ``login_page``, ``login_ok``, ``login_fail``,
``viewstate_reject``, ``eventvalidation_reject``, ``navkey_reject``, ``auth_redirect``, ``menu``,
``search_page``, ``plant_change``, ``search``, ``page``, ``excel_export``, ``picker``, ``news``,
``logout``, ``static``; ``details`` holds the filters, the export id, the rejection reason and the
first characters of rejected tokens.

Importing this module has no side effects (nothing is read from ``sys.argv``, no file or socket is
touched).  Command line::

    python -I factory_site.py LOGFILE PORT [HOST]

From a test::

    server = make_server(log_path, 0)           # port 0 = any free port; server.port / server.base_url
    threading.Thread(target=server.serve_forever, daemon=True).start()
    ...
    server.shutdown(); server.server_close()

or ``server = serve_in_thread(log_path)`` … ``server.stop()``.  Helpers: :data:`CREDENTIALS`,
:func:`expected_rows`, :func:`read_xlsx_rows`, :func:`export_filename`, :func:`read_log`,
:func:`hidden_fields`.
"""

from __future__ import annotations

import base64
import datetime as _dt
import functools
import io
import json
import random
import re
import secrets
import socketserver
import string
import struct
import sys
import threading
import time
import zipfile
from collections import OrderedDict
from html import escape as _html_escape
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, unquote_to_bytes, urlsplit
from xml.etree import ElementTree as ET

__all__ = [
    "CREDENTIALS", "USER_NAME", "PLANTS", "LINES", "SHIFTS", "ITEMS", "PAGE_SIZE", "DEFAULT_FROM",
    "DEFAULT_TO", "EXPORT_DATE", "EXPORT_HEADER", "EXPORT_ID_LABEL", "XLSX_CONTENT_TYPE",
    "VIEWSTATE_GENERATORS", "FactoryServer", "make_server", "serve_in_thread", "main", "dataset",
    "expected_rows", "export_filename", "build_xlsx", "read_xlsx_rows", "read_log", "hidden_fields",
    "parse_form",
]

# --------------------------------------------------------------------------- constants

HOST = "127.0.0.1"
DEFAULT_PORT = 8098
DEFAULT_LOG = "factory_site.log"

CHARSET = "Shift_JIS"
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


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Command line: ``factory_site.py [LOGFILE [PORT [HOST]]]``."""
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


if __name__ == "__main__":
    main()
