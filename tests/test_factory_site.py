"""Self-check of the factory mock site ``tests/iehost_fixtures/factory_site.py`` (always on, no browser).

The site is started in-process on a free port and driven with ``requests`` exactly like IE would:
forms are serialised from the HTML (successful controls only, the clicked submit button only,
``__doPostBack`` fills ``__EVENTTARGET`` / ``__EVENTARGUMENT``) and URL-encoded in Shift_JIS (cp932).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlencode, urljoin

import pytest
import requests
from bs4 import BeautifulSoup

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE_PATH = os.path.join(ROOT, "tests", "iehost_fixtures", "factory_site.py")
IE7_UA = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)"


def _load_site():
    """Import factory_site.py by path (tests/iehost_fixtures is not a package)."""
    spec = importlib.util.spec_from_file_location("reqrec_factory_site", SITE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fs = _load_site()


# --------------------------------------------------------------------------- browser-like client


class Browser:
    """A ``requests.Session`` that submits forms the way IE does on a Shift_JIS page."""

    def __init__(self, base_url: str) -> None:
        self.base = base_url
        self.session = requests.Session()
        self.session.headers["User-Agent"] = IE7_UA

    def url(self, path: str) -> str:
        return urljoin(self.base, path)

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(self.url(path), allow_redirects=False, timeout=10, **kwargs)

    def post(self, url: str, fields: Sequence[Tuple[str, str]], **kwargs) -> requests.Response:
        body = urlencode(list(fields), encoding="cp932")  # IE encodes form data in the page's charset
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        headers.update(kwargs.pop("headers", {}))
        return self.session.post(self.url(url), data=body, headers=headers, allow_redirects=False, timeout=10, **kwargs)

    def submit(self, page: "Page", click: Optional[str] = None, overrides: Optional[Dict[str, str]] = None,
               postback: Optional[Tuple[str, str]] = None) -> requests.Response:
        """Submit ``page``'s form: click a submit button, or run ``__doPostBack(target, argument)``."""
        values = dict(overrides or {})
        if postback is not None:
            values["__EVENTTARGET"], values["__EVENTARGUMENT"] = postback
        return self.post(page.action_url, page.fields(click=click, overrides=values))

    def cookie(self, name: str) -> Optional[str]:
        return self.session.cookies.get(name)


class Page:
    """A decoded HTML response."""

    def __init__(self, resp: requests.Response) -> None:
        assert resp.headers["Content-Type"] == "text/html; charset=Shift_JIS", resp.headers
        assert b'<meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS" />' in resp.content
        self.resp = resp
        self.text = resp.content.decode("shift_jis")  # strict: the page really is Shift_JIS
        self.soup = BeautifulSoup(self.text, "html.parser")

    @property
    def form(self):
        form = self.soup.find("form")
        assert form is not None
        return form

    @property
    def action_url(self) -> str:
        return urljoin(self.resp.url, self.form["action"])

    def hidden(self, name: str) -> str:
        el = self.soup.find("input", {"name": name})
        assert el is not None, name
        return el.get("value", "")

    def fields(self, click: Optional[str] = None, overrides: Optional[Dict[str, str]] = None) -> List[Tuple[str, str]]:
        """The form's successful controls in document order (what IE would post)."""
        out: List[Tuple[str, str]] = []
        for el in self.form.find_all(["input", "select", "textarea"]):
            name = el.get("name")
            if not name or el.has_attr("disabled"):
                continue
            if el.name == "input":
                kind = (el.get("type") or "text").lower()
                if kind in ("submit", "image"):
                    if name == click:
                        out.append((name, el.get("value", "")))
                    continue
                if kind in ("button", "reset", "file"):
                    continue
                if kind in ("checkbox", "radio") and not el.has_attr("checked"):
                    continue
                out.append((name, el.get("value", "")))
            elif el.name == "select":
                options = el.find_all("option")
                if not options:
                    continue  # an empty <select> is not posted
                chosen = [o for o in options if o.has_attr("selected")] or options[:1]
                out.append((name, chosen[0].get("value", chosen[0].get_text())))
            else:
                out.append((name, el.get_text()))
        if click is not None:
            assert any(name == click for name, _ in out), f"no submit button {click!r}"
        for name, value in (overrides or {}).items():
            if any(n == name for n, _ in out):
                out = [(n, value if n == name else v) for n, v in out]
            else:
                out.append((name, value))
        return out

    def select_options(self, name: str) -> List[Tuple[str, str, bool]]:
        sel = self.soup.find("select", {"name": name})
        assert sel is not None, name
        return [(o.get("value", ""), o.get_text(), o.has_attr("selected")) for o in sel.find_all("option")]

    def grid_rows(self) -> List[Tuple[str, ...]]:
        table = self.soup.find("table", id="gvResult")
        assert table is not None
        rows = []
        for tr in table.find_all("tr", recursive=False)[1:]:
            if "pager" in (tr.get("class") or []):
                continue
            rows.append(tuple(td.get_text(strip=True) for td in tr.find_all("td", recursive=False)))
        return rows

    def pager_links(self) -> List[str]:
        return [a["href"] for a in self.soup.select("#gvResult tr.pager a")]

    def message(self) -> str:
        el = self.soup.find(id="lblMessage")
        return el.get_text(strip=True) if el is not None else ""


def set_cookies(resp: requests.Response) -> List[str]:
    return list(resp.raw.headers.getlist("Set-Cookie"))


def cookie_value(headers: List[str], name: str) -> Optional[str]:
    for header in headers:
        if header.startswith(name + "="):
            return header.split(";", 1)[0].split("=", 1)[1]
    return None


def log_entries(log_path: str) -> List[dict]:
    return fs.read_log(log_path)


def events(log_path: str) -> List[str]:
    return [e["event"] for e in log_entries(log_path)]


# --------------------------------------------------------------------------- fixtures / flows


@pytest.fixture
def site(tmp_path):
    log = str(tmp_path / "factory.log")
    server = fs.serve_in_thread(log)
    try:
        yield server, log
    finally:
        server.stop()


def login(base_url: str) -> Tuple[Browser, Page]:
    """Log in like a user; returns the browser and the menu page."""
    b = Browser(base_url)
    page = Page(b.get("Login.aspx"))
    user, password = fs.CREDENTIALS
    r = b.submit(page, click="btnLogin", overrides={"txtUserId": user, "txtPassword": password})
    assert r.status_code == 302 and r.headers["Location"] == "/Menu.aspx", r.text
    menu = Page(b.get(r.headers["Location"]))
    return b, menu


def navkey_of(menu: Page) -> str:
    onclick = menu.soup.find("a", id="lnkSearch")["onclick"]
    m = re.fullmatch(r"window\.open\('Search\.aspx\?key=(\w+)','search',"
                     r"'width=980,height=720,resizable=yes,scrollbars=yes'\);return false;", onclick)
    assert m, onclick
    return m.group(1)


def open_search(b: Browser, navkey: str) -> Page:
    r = b.get(f"Search.aspx?key={navkey}")
    assert r.status_code == 200, r.text
    return Page(r)


def choose_plant(b: Browser, search: Page, plant: str) -> Page:
    r = b.submit(search, overrides={"ddlPlant": plant}, postback=("ddlPlant", ""))
    assert r.status_code == 200, r.text
    return Page(r)


# --------------------------------------------------------------------------- tests


def test_import_is_side_effect_free(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["factory_site.py", "SHOULD_NOT_BE_READ.log", "1"])
    module = _load_site()
    assert callable(module.make_server) and callable(module.main) and callable(module.serve_in_thread)
    assert module.CREDENTIALS == ("tanaka", "Seisan#2026!")
    assert list(tmp_path.iterdir()) == []


def test_dataset_and_helpers():
    rows = fs.dataset()
    assert len(rows) == 280  # 35 working days (2026/09/01-2026/10/10 without Sundays) x 8 records
    assert rows == fs.dataset()  # deterministic
    assert (fs.DEFAULT_FROM, fs.DEFAULT_TO) == ("2026/09/01", "2026/10/10")
    l11 = fs.expected_rows("01", "L11", "ALL", fs.DEFAULT_FROM, fs.DEFAULT_TO, "")
    assert len(l11) > 2 * fs.PAGE_SIZE  # the result needs more than two pages
    assert [r[0] for r in l11] == sorted(r[0] for r in l11)
    assert all(r[1] == "L11" and r[2] in ("日勤", "夜勤") for r in l11)
    # the recording scenario's filter (tests/iehost_fixtures/factory_scenario.py) has exactly two pages
    scenario = fs.expected_rows("01", "L11", "D", fs.DEFAULT_FROM, fs.DEFAULT_TO, "A-1002")
    assert scenario == [r for r in l11 if r[2] == "日勤" and r[3] == "A-1002"]
    assert fs.PAGE_SIZE < len(scenario) <= 2 * fs.PAGE_SIZE
    assert fs.expected_rows("01", "L11", "D", "2026/10/01", "2026/10/10", "A-1002") == [
        r for r in scenario if r[0] >= "2026/10/01"]
    assert fs.expected_rows("01", "L11", "ALL", "2026/10/04", "2026/10/04", "") == []  # Sunday
    sheet = [fs.EXPORT_HEADER, ("2026/10/01", "L11", "日勤", "A-1001", 120, 118, 2), ("出力ID", "EX1")]
    assert fs.read_xlsx_rows(fs.build_xlsx(sheet)) == [list(fs.EXPORT_HEADER),
                                                      ["2026/10/01", "L11", "日勤", "A-1001", "120", "118", "2"],
                                                      ["出力ID", "EX1"]]
    assert fs.export_filename("01", "L11") == "生産実績_01_L11_20261011.xlsx"
    assert fs.parse_form(b"txtUserId=%93%63%92%86&btnLogin=%83%8D%83O%83C%83%93&a=1+2") == {
        "txtUserId": "田中", "btnLogin": "ログイン", "a": "1 2"}
    assert fs.hidden_fields('<input type="hidden" name="__VIEWSTATE" value="a&amp;b" /><input name="x" value="y">') == {
        "__VIEWSTATE": "a&b"}


def test_recording_scenario_matches_the_site(tmp_path, monkeypatch):
    """tests/iehost_fixtures/factory_scenario.py (the IE-engine recording scenario) imports without side
    effects, and its search filter is the page's default period with exactly two grid pages (it clicks
    the pager link 2 and expects 「2/2 ページ」)."""
    monkeypatch.chdir(tmp_path)
    path = os.path.join(ROOT, "tests", "iehost_fixtures", "factory_scenario.py")
    spec = importlib.util.spec_from_file_location("reqrec_factory_scenario_check", path)
    assert spec is not None and spec.loader is not None
    scenario = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scenario)
    assert list(tmp_path.iterdir()) == []
    plant, line, shift, date_from, date_to, item = scenario.SCENARIO_FILTER
    assert (date_from, date_to) == (fs.DEFAULT_FROM, fs.DEFAULT_TO)
    assert dict(fs.PLANTS)[plant] == "本社工場" and dict(fs.LINES[plant])[line] == "組立1ライン"
    assert dict(fs.SHIFTS)[shift] == "日勤" and item in dict(fs.ITEMS[plant])
    rows = fs.expected_rows(*scenario.SCENARIO_FILTER)
    assert fs.PAGE_SIZE < len(rows) <= 2 * fs.PAGE_SIZE
    assert scenario.STEPS[0] == "start" and scenario.STEPS[-1] == "close"


def test_root_static_and_auth_redirects(site):
    server, log = site
    b = Browser(server.base_url)
    r = b.get("/")
    assert r.status_code == 302 and r.headers["Location"] == "/Login.aspx"
    assert r.headers["Server"] == "Microsoft-IIS/8.5"
    css = b.get("/css/site.css")
    assert css.status_code == 200 and css.headers["Content-Type"] == "text/css" and b"#header" in css.content
    gif = b.get("/img/logo.gif")
    assert gif.status_code == 200 and gif.headers["Content-Type"] == "image/gif" and gif.content.startswith(b"GIF89a")
    ico = b.get("/favicon.ico")
    assert ico.status_code == 200 and ico.headers["Content-Type"] == "image/x-icon"
    assert ico.content.startswith(b"\x00\x00\x01\x00")
    again = b.get("/img/logo.gif", headers={"If-None-Match": gif.headers["ETag"]})
    assert again.status_code == 304
    missing = b.get("/nothing.aspx")
    assert missing.status_code == 404
    Page(missing)  # still a Shift_JIS page
    for path in ("Menu.aspx", "News.aspx", "Search.aspx?key=x", "ItemPicker.aspx?plant=01&key=x"):
        r = b.get(path)
        name = path.split("?")[0]
        assert r.status_code == 302 and r.headers["Location"] == f"/Login.aspx?ReturnUrl=%2f{name}", (path, r.headers)
    assert not b.session.cookies  # no session is issued outside the login page
    entries = log_entries(log)
    assert [e["event"] for e in entries[:6]] == ["redirect", "static", "static", "static", "static", "not_found"]
    assert all(e["auth_ok"] is False and e["session"] is None for e in entries)


def test_login_page_markup_session_cookie_and_encoding(site):
    server, log = site
    b = Browser(server.base_url)
    r = b.get("Login.aspx")
    assert r.status_code == 200
    assert r.encoding.lower() == "shift_jis" and "生産管理システム" in r.text
    assert "ログイン".encode("cp932") in r.content
    cookies = set_cookies(r)
    sid = cookie_value(cookies, "ASP.NET_SessionId")
    assert sid and re.fullmatch(r"[a-z0-9]{24}", sid)
    assert "HttpOnly" in cookies[0] and "path=/" in cookies[0]
    page = Page(r)
    form = page.form
    assert form["method"] == "post" and form["action"] == "Login.aspx"
    vs = page.hidden("__VIEWSTATE")
    assert len(vs) >= 100 and re.fullmatch(r"[A-Za-z0-9+/]+=*", vs)
    assert page.hidden("__VIEWSTATEGENERATOR") == fs.VIEWSTATE_GENERATORS["Login.aspx"]
    assert re.fullmatch(r"[A-Za-z0-9+/]+=*", page.hidden("__EVENTVALIDATION"))
    assert page.soup.find("input", {"name": "txtUserId"})["type"] == "text"
    assert page.soup.find("input", {"name": "txtPassword"})["type"] == "password"
    btn = page.soup.find("input", {"name": "btnLogin"})
    assert btn["type"] == "submit" and btn["value"] == "ログイン"
    # the same session gets no new cookie but fresh tokens
    r2 = b.get("Login.aspx")
    assert cookie_value(set_cookies(r2), "ASP.NET_SessionId") is None
    page2 = Page(r2)
    assert page2.hidden("__VIEWSTATE") != vs and page2.hidden("__EVENTVALIDATION") != page.hidden("__EVENTVALIDATION")
    # a cp932 user id is decoded on the server and echoed back
    r3 = b.submit(page2, click="btnLogin", overrides={"txtUserId": "田中", "txtPassword": "x"})
    assert r3.status_code == 200
    page3 = Page(r3)
    assert page3.message() == "ユーザー ID またはパスワードが違います。"
    assert page3.soup.find("input", {"name": "txtUserId"})["value"] == "田中"
    fail = [e for e in log_entries(log) if e["event"] == "login_fail"][-1]
    assert fail["details"]["user"] == "田中" and fail["session"] == sid


def test_full_browser_flow(site):
    server, log = site
    b = Browser(server.base_url)

    # ---- login: wrong password, reused token, success with session rotation ------------
    r = b.get("/")
    assert r.status_code == 302
    login1 = Page(b.get(r.headers["Location"]))
    sid_before = b.cookie("ASP.NET_SessionId")
    user, password = fs.CREDENTIALS
    r = b.submit(login1, click="btnLogin", overrides={"txtUserId": user, "txtPassword": "seisan#2026!"})
    login2 = Page(r)
    assert r.status_code == 200 and login2.message() == "ユーザー ID またはパスワードが違います。"
    assert login2.hidden("__VIEWSTATE") != login1.hidden("__VIEWSTATE")
    r = b.submit(login1, click="btnLogin", overrides={"txtUserId": user, "txtPassword": password})
    assert r.status_code == 500 and fs.VIEWSTATE_ERROR in r.content.decode("cp932")
    r = b.submit(login2, click="btnLogin", overrides={"txtUserId": user, "txtPassword": password})
    assert r.status_code == 302 and r.headers["Location"] == "/Menu.aspx"
    cookies = set_cookies(r)
    sid_after = cookie_value(cookies, "ASP.NET_SessionId")
    auth = cookie_value(cookies, ".ASPXAUTH")
    assert sid_after and sid_after != sid_before and re.fullmatch(r"[a-z0-9]{24}", sid_after)
    assert auth and re.fullmatch(r"[0-9A-Fa-f]{64}", auth)
    assert all("HttpOnly" in c for c in cookies)
    assert b.cookie("ASP.NET_SessionId") == sid_after

    # ---- menu --------------------------------------------------------------------------
    menu = Page(b.get("Menu.aspx"))
    assert "ようこそ 田中 太郎 さん" in menu.soup.get_text()
    navkey = navkey_of(menu)
    news_link = menu.soup.find("a", id="lnkNews")
    assert news_link["href"] == "News.aspx" and news_link["target"] == "_blank"
    assert menu.soup.find("a", id="lnkLogout")["href"] == "Logout.aspx"
    assert menu.soup.find("img", src="/img/logo.gif") and menu.soup.find("link", href="/css/site.css")
    news = Page(b.get(news_link["href"]))
    assert "お知らせ" in news.soup.get_text() and news.resp.status_code == 200

    # ---- Search.aspx (the window.open popup) --------------------------------------------
    assert b.get("Search.aspx?key=WRONGKEY").status_code == 403
    assert b.get("Search.aspx").status_code == 403
    search = open_search(b, navkey)
    assert search.form["action"] == f"Search.aspx?key={navkey}"
    assert "function __doPostBack(eventTarget, eventArgument)" in search.text
    assert search.hidden("__EVENTTARGET") == "" and search.hidden("__EVENTARGUMENT") == ""
    assert search.hidden("__VIEWSTATEGENERATOR") == fs.VIEWSTATE_GENERATORS["Search.aspx"]
    plant_sel = search.soup.find("select", {"name": "ddlPlant"})
    assert plant_sel["onchange"] == "__doPostBack('ddlPlant','')"
    assert [(v, t) for v, t, _ in search.select_options("ddlPlant")] == [
        ("", "-- 選択してください --"), ("01", "本社工場"), ("02", "第二工場")]
    assert search.select_options("ddlLine") == []
    assert [(v, t) for v, t, _ in search.select_options("ddlShift")] == [("ALL", "全て"), ("D", "日勤"), ("N", "夜勤")]
    assert search.soup.find("input", {"name": "txtFrom"})["value"] == fs.DEFAULT_FROM == "2026/09/01"
    assert search.soup.find("input", {"name": "txtTo"})["value"] == fs.DEFAULT_TO == "2026/10/10"
    assert search.soup.find("input", {"name": "txtItem"})["readonly"] == "readonly"
    pick = search.soup.find("input", {"name": "btnPick"})
    assert pick["type"] == "button" and pick["value"] == "品番選択"
    assert (f"var r = window.showModalDialog('ItemPicker.aspx?plant=' + plant + '&key={navkey}', window, "
            "'dialogWidth:420px;dialogHeight:360px'); if (r) document.getElementById('txtItem').value = r;") in pick["onclick"]
    assert "alert(" in pick["onclick"]
    assert search.soup.find("input", {"name": "btnSearch"})["value"] == "検索"
    assert search.soup.find("input", {"name": "btnExcel"})["value"] == "Excel出力"
    assert search.soup.find("table", id="gvResult") is None

    # ---- AutoPostBack of the plant fills the lines ---------------------------------------
    plant01 = choose_plant(b, search, "01")
    assert [(v, t, s) for v, t, s in plant01.select_options("ddlPlant") if s] == [("01", "本社工場", True)]
    assert [(v, t) for v, t, _ in plant01.select_options("ddlLine")] == [("L11", "組立1ライン"), ("L12", "組立2ライン")]

    # ---- the modal item picker -----------------------------------------------------------
    picker = Page(b.get(f"ItemPicker.aspx?plant=01&key={navkey}"))
    links = picker.soup.select("#tblItems a")
    assert [a["id"] for a in links] == ["item_A-1001", "item_A-1002", "item_A-1003"]
    assert links[0]["onclick"] == "window.returnValue='A-1001';window.close();return false;"
    assert "ブラケット" in picker.soup.get_text()

    # ---- a line that does not belong to the plant is an invalid postback argument --------
    r = b.submit(plant01, click="btnSearch", overrides={"ddlLine": "L21"})
    assert r.status_code == 500 and fs.POSTBACK_ERROR in r.content.decode("cp932")
    r = b.submit(plant01, click="btnSearch", overrides={"ddlPlant": "02", "ddlLine": "L11"})
    assert r.status_code == 500 and fs.POSTBACK_ERROR in r.content.decode("cp932")

    # ---- search, page 2 ------------------------------------------------------------------
    expected = fs.expected_rows("01", "L11", "ALL", fs.DEFAULT_FROM, fs.DEFAULT_TO, "")
    pages = (len(expected) + fs.PAGE_SIZE - 1) // fs.PAGE_SIZE
    assert pages > 2
    r = b.submit(plant01, click="btnSearch", overrides={"ddlLine": "L11"})  # the rejected posts used up nothing
    assert r.status_code == 200
    page1 = Page(r)
    assert page1.grid_rows() == expected[:fs.PAGE_SIZE]
    assert f"{len(expected)} 件（1/{pages} ページ）" in page1.soup.find(id="lblCount").get_text()
    assert page1.pager_links() == [f"javascript:__doPostBack('gvResult','Page${n}')" for n in range(2, pages + 1)]
    # paging keeps the searched filter even when a control was changed without searching again
    r = b.submit(page1, overrides={"ddlShift": "N"}, postback=("gvResult", "Page$2"))
    assert r.status_code == 200
    page2 = Page(r)
    assert page2.grid_rows() == expected[fs.PAGE_SIZE:2 * fs.PAGE_SIZE]
    assert page2.pager_links() == [f"javascript:__doPostBack('gvResult','Page${n}')" for n in range(1, pages + 1) if n != 2]
    # page 1's tokens were used by the paging postback
    r = b.submit(page1, postback=("gvResult", "Page$2"))
    assert r.status_code == 500 and fs.VIEWSTATE_ERROR in r.content.decode("cp932")
    # a page that was never rendered is not a valid argument
    r = b.submit(page2, postback=("gvResult", "Page$9"))
    assert r.status_code == 500 and fs.POSTBACK_ERROR in r.content.decode("cp932")

    # ---- Excel出力 -------------------------------------------------------------------------
    r = b.submit(page2, click="btnExcel", overrides={"ddlShift": "ALL"})
    assert r.status_code == 200
    assert r.headers["Content-Type"] == fs.XLSX_CONTENT_TYPE
    assert r.headers["Cache-Control"] == "private"
    disposition = r.headers["Content-Disposition"]
    m = re.fullmatch(r"attachment; filename=([A-Za-z0-9%._-]+)", disposition)
    assert m, disposition
    assert unquote(m.group(1), encoding="utf-8") == "生産実績_01_L11_20261011.xlsx"
    sheet = fs.read_xlsx_rows(r.content)
    assert sheet[0] == list(fs.EXPORT_HEADER)
    assert [tuple(row) for row in sheet[1:-1]] == expected  # every matching row, not one page
    assert sheet[-1][0] == "出力ID" and re.fullmatch(r"EX[0-9A-F]{12}", sheet[-1][1])
    export_id = sheet[-1][1]
    # the download leaves the page in the browser: its tokens still work (filters as posted)
    r = b.submit(page2, click="btnExcel", overrides={"ddlShift": "D", "txtItem": "A-1002"})
    assert r.status_code == 200
    sheet2 = fs.read_xlsx_rows(r.content)
    assert [tuple(row) for row in sheet2[1:-1]] == fs.expected_rows("01", "L11", "D", fs.DEFAULT_FROM, fs.DEFAULT_TO, "A-1002")
    assert sheet2[-1][1] != export_id
    r = b.submit(page2, click="btnSearch", overrides={"ddlShift": "N"})
    assert r.status_code == 200
    assert Page(r).grid_rows() == fs.expected_rows("01", "L11", "N", fs.DEFAULT_FROM, fs.DEFAULT_TO, "")[:fs.PAGE_SIZE]

    # ---- logout -------------------------------------------------------------------------
    r = b.get("Logout.aspx")
    assert r.status_code == 302 and r.headers["Location"] == "/Login.aspx"
    r = b.get("Menu.aspx")
    assert r.status_code == 302 and r.headers["Location"].startswith("/Login.aspx?ReturnUrl=")

    # ---- log --------------------------------------------------------------------------
    entries = log_entries(log)
    for e in entries:
        assert {"t", "method", "path", "query", "session", "auth_ok", "event", "details"} <= set(e)
        assert isinstance(e["t"], float) and e["event"]
    names = [e["event"] for e in entries]
    for name in ("login_page", "login_fail", "viewstate_reject", "login_ok", "menu", "news", "navkey_reject",
                 "search_page", "plant_change", "picker", "eventvalidation_reject", "search", "page",
                 "excel_export", "logout", "auth_redirect"):
        assert name in names, (name, names)
    ok = next(e for e in entries if e["event"] == "login_ok")
    assert ok["session"] == sid_before and ok["details"]["new_session"] == sid_after
    # the Shift_JIS-encoded submit button values arrive decoded
    assert ok["details"]["button"] == "ログイン"
    assert next(e for e in entries if e["event"] == "search")["details"]["button"] == "検索"
    assert next(e for e in entries if e["event"] == "excel_export")["details"]["button"] == "Excel出力"
    exports = [e for e in entries if e["event"] == "excel_export"]
    assert exports[0]["details"]["export_id"] == export_id and exports[0]["details"]["rows"] == len(expected)
    assert exports[0]["details"]["filters"]["line"] == "L11" and exports[0]["auth_ok"] is True
    rejects = [e for e in entries if e["event"] in ("viewstate_reject", "eventvalidation_reject")]
    assert all(e["details"].get("reason") for e in rejects)
    assert any(e["details"]["reason"] == "viewstate_reused" for e in rejects)
    assert any(e["details"]["reason"].startswith("ddlLine_not_rendered:L21") for e in rejects)
    assert any(e["details"]["reason"].startswith("line_not_in_plant:L11@02") for e in rejects)
    assert all(e["ua"] == IE7_UA for e in entries)


def test_stale_session_or_auth_cookie_redirects_to_login(site, tmp_path):
    server, _log = site
    b = Browser(server.base_url)
    first = Page(b.get("Login.aspx"))
    old_sid = b.cookie("ASP.NET_SessionId")
    user, password = fs.CREDENTIALS
    r = b.submit(first, click="btnLogin", overrides={"txtUserId": user, "txtPassword": password})
    assert r.status_code == 302
    sid, auth = b.cookie("ASP.NET_SessionId"), b.cookie(".ASPXAUTH")
    url = server.base_url + "Menu.aspx"

    def menu_with(cookie_header: Optional[str]) -> requests.Response:
        headers = {"User-Agent": IE7_UA}
        if cookie_header is not None:
            headers["Cookie"] = cookie_header
        return requests.get(url, headers=headers, allow_redirects=False, timeout=10)

    assert menu_with(f"ASP.NET_SessionId={sid}; .ASPXAUTH={auth}").status_code == 200
    for cookie in (
        f"ASP.NET_SessionId={old_sid}; .ASPXAUTH={auth}",   # the pre-login session id (rotated away)
        f"ASP.NET_SessionId={sid}; .ASPXAUTH={'0' * 64}",    # wrong auth ticket
        f"ASP.NET_SessionId={sid}",                          # no auth ticket
        f".ASPXAUTH={auth}",                                 # no session
        None,
    ):
        r = menu_with(cookie)
        assert r.status_code == 302 and r.headers["Location"] == "/Login.aspx?ReturnUrl=%2fMenu.aspx", cookie
    # cookies from another run of the site are never valid
    other = fs.serve_in_thread(str(tmp_path / "other.log"))
    try:
        ob, _menu = login(other.base_url)
        r = menu_with(f"ASP.NET_SessionId={ob.cookie('ASP.NET_SessionId')}; .ASPXAUTH={ob.cookie('.ASPXAUTH')}")
        assert r.status_code == 302
    finally:
        other.stop()


def test_viewstate_must_belong_to_this_session_and_page(site, tmp_path):
    server, log = site
    a, b = Browser(server.base_url), Browser(server.base_url)
    pa, pb = Page(a.get("Login.aspx")), Page(b.get("Login.aspx"))
    pa2 = Page(a.get("Login.aspx"))
    creds = {"txtUserId": fs.CREDENTIALS[0], "txtPassword": fs.CREDENTIALS[1]}

    def rejected(r: requests.Response) -> bool:
        return r.status_code == 500 and fs.VIEWSTATE_ERROR in r.content.decode("cp932")

    assert rejected(a.post(pa.action_url, pb.fields(click="btnLogin", overrides=creds)))  # B's tokens
    assert rejected(a.submit(pa, click="btnLogin", overrides=dict(creds, __EVENTVALIDATION=pa2.hidden("__EVENTVALIDATION"))))
    assert rejected(a.submit(pa, click="btnLogin", overrides=dict(creds, __EVENTVALIDATION="")))
    assert rejected(a.submit(pa, click="btnLogin", overrides=dict(creds, __VIEWSTATEGENERATOR="00000000")))
    no_session = Browser(server.base_url)
    assert rejected(no_session.post(pa.action_url, pa.fields(click="btnLogin", overrides=creds)))
    # tokens of a previous server run are unknown
    other = fs.serve_in_thread(str(tmp_path / "other.log"))
    try:
        op = Page(Browser(other.base_url).get("Login.aspx"))
    finally:
        other.stop()
    assert rejected(a.post(pa.action_url, op.fields(click="btnLogin", overrides=creds)))
    # none of the rejected posts used up pa's tokens
    r = a.submit(pa, click="btnLogin", overrides=creds)
    assert r.status_code == 302
    # Login.aspx tokens are not accepted by Search.aspx
    menu = Page(a.get("Menu.aspx"))
    navkey = navkey_of(menu)
    search = open_search(a, navkey)
    login_again = Page(a.get("Login.aspx"))
    forged = search.fields(click="btnSearch", overrides={
        "__VIEWSTATE": login_again.hidden("__VIEWSTATE"),
        "__EVENTVALIDATION": login_again.hidden("__EVENTVALIDATION"),
    })
    assert rejected(a.post(search.action_url, forged))
    reasons = [e["details"]["reason"] for e in log_entries(log) if e["event"] in ("viewstate_reject", "eventvalidation_reject")]
    assert reasons == ["viewstate_of_other_session", "eventvalidation_mismatch", "missing_eventvalidation",
                       "bad_viewstategenerator", "no_session", "unknown_viewstate", "viewstate_of_page:Login.aspx"]


def test_navkey_is_checked(site):
    server, log = site
    b, menu = login(server.base_url)
    navkey = navkey_of(menu)
    other_b, other_menu = login(server.base_url)
    other_key = navkey_of(other_menu)
    assert other_key != navkey
    search = open_search(b, navkey)
    for path in ("Search.aspx", "Search.aspx?key=", f"Search.aspx?key={other_key}",
                 f"ItemPicker.aspx?plant=01&key={other_key}", "ItemPicker.aspx?plant=01"):
        r = b.get(path)
        assert r.status_code == 403, path
        assert "不正なアクセスです。" in Page(r).text
    r = b.post(f"Search.aspx?key={other_key}", search.fields(click="btnSearch"))
    assert r.status_code == 403
    rejects = [e for e in log_entries(log) if e["event"] == "navkey_reject"]
    assert len(rejects) == 6 and all(e["auth_ok"] for e in rejects)


def test_search_validation_messages(site):
    server, _log = site
    b, menu = login(server.base_url)
    navkey = navkey_of(menu)
    search = open_search(b, navkey)
    r = b.submit(search, click="btnSearch")
    no_plant = Page(r)
    assert r.status_code == 200 and no_plant.message() == "工場を選択してください。"
    r = b.submit(no_plant, click="btnExcel")  # no download without a plant
    assert r.status_code == 200 and Page(r).message() == "工場を選択してください。"
    page = choose_plant(b, Page(r), "02")
    assert page.select_options("ddlLine")[0][:2] == ("L21", "プレスライン")

    def search_with(current: Page, **overrides: str) -> Page:
        resp = b.submit(current, click="btnSearch", overrides=overrides)
        assert resp.status_code == 200, resp.content.decode("cp932")
        return Page(resp)

    page = search_with(page, txtFrom="2026/13/01")
    assert page.message() == "日付は yyyy/mm/dd の形式で入力してください。"
    page = search_with(page, txtFrom="2026/10/09", txtTo="2026/10/02")
    assert page.message() == "期間の開始日が終了日より後になっています。"
    page = search_with(page, txtFrom="2026/10/01", txtTo="2026/10/10", txtItem="A-1001")
    assert page.message() == "品番が正しくありません。"
    empty = search_with(page, ddlLine="L22", txtFrom="2026/10/04", txtTo="2026/10/04", txtItem="")
    assert empty.message() == ""
    assert "該当するデータがありません。" in empty.soup.find("table", id="gvResult").get_text()
    result = search_with(empty, ddlLine="L22", ddlShift="D", txtFrom="2026/10/1", txtTo="2026/10/10", txtItem="B-2002")
    assert result.grid_rows() == fs.expected_rows("02", "L22", "D", "2026/10/01", "2026/10/10", "B-2002")
    assert result.pager_links() == []
    # switching the plant resets the line and clears the item
    plant01 = choose_plant(b, result, "01")
    assert [v for v, _t, s in plant01.select_options("ddlLine") if s] == ["L11"]
    assert plant01.soup.find("input", {"name": "txtItem"})["value"] == ""
    picker = Page(b.get(f"ItemPicker.aspx?plant=&key={navkey}"))
    assert picker.message() == "工場が選択されていません。"
    # pages without postback controls still validate a posted form (and keep the URL key in the action)
    picker = Page(b.get(f"ItemPicker.aspx?plant=02&key={navkey}"))
    assert picker.form["action"] == f"ItemPicker.aspx?plant=02&key={navkey}"
    r = b.submit(picker)
    assert r.status_code == 200 and "フレーム" in Page(r).text
    r = b.submit(picker)
    assert r.status_code == 500 and fs.VIEWSTATE_ERROR in r.content.decode("cp932")


def test_concurrent_logins_and_log_lines(site):
    server, log = site
    errors: List[str] = []

    def worker() -> None:
        try:
            b, menu = login(server.base_url)
            search = open_search(b, navkey_of(menu))
            page = choose_plant(b, search, "01")
            r = b.submit(page, click="btnSearch")
            assert r.status_code == 200 and len(Page(r).grid_rows()) == fs.PAGE_SIZE
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, errors
    with open(log, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    parsed = [json.loads(line) for line in lines]
    assert sum(1 for e in parsed if e["event"] == "login_ok") == 8
    assert len({e["details"]["new_session"] for e in parsed if e["event"] == "login_ok"}) == 8


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_command_line(tmp_path):
    port = _free_port()
    log = tmp_path / "cli.log"
    proc = subprocess.Popen([sys.executable, "-I", SITE_PATH, str(log), str(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        deadline = time.monotonic() + 20
        while True:
            assert proc.poll() is None, proc.stdout.read() if proc.stdout else ""
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                assert time.monotonic() < deadline, "site did not start"
                time.sleep(0.1)
        r = requests.get(f"http://127.0.0.1:{port}/Login.aspx", timeout=10)
        assert r.status_code == 200 and "ログイン" in r.content.decode("cp932")
    finally:
        proc.kill()
        proc.wait(timeout=10)
        if proc.stdout:
            proc.stdout.close()
    assert [e["event"] for e in fs.read_log(str(log))] == ["login_page"]
