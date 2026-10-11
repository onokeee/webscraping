"""Review 3 findings for ``reqrec.deps`` / ``reqrec.plan`` (DESIGN.md §5, §7, §13.13).

* ``deps.looks_random_letters`` accepts acronym runs anywhere (``txtTokuisakiCD``,
  ``getXMLHttpRequest``) and still recognises random mixed-case letter tokens, also with ``-`` /
  ``_`` separators (base64url without digits) and before a file extension - measured here on
  seeded random tokens;
* route-like path segments (words, ``Login.aspx``, screen ids ``SC0010.aspx``) stay trace
  candidates but are only traced through exact structural matches (JSON leaf, header, cookie,
  ``<input>`` / ``<meta>``), never through markup;
* the ``Referer`` rewrite replaces whole path segments / query values only (also percent-encoded);
* every field whose name looks like a credential is read from the environment, whatever its length
  and even when it equals another field's value.

Plans are built from small recordings; the generated scripts run against ``tests.e2e.mock_adapter``.
"""

from __future__ import annotations

import json
import random
import re
import string
from pathlib import Path
from urllib.parse import quote

import pytest

from reqrec import deps
from reqrec.codegen import generate
from reqrec.model import Flow, PlanOptions, RecordedRequest, RecordedResponse, Recording, Ref
from reqrec.plan import build_plan
from tests.e2e.mock_adapter import MockAdapter, Rule, run_generated

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
FORM_CT = ("Content-Type", "application/x-www-form-urlencoded")
HTML_CT = [("Content-Type", "text/html; charset=utf-8")]
JSON_CT = [("Content-Type", "application/json")]


def _recording(host, *flows):
    """``flows``: (method, path, request headers, body, response headers, response body)."""
    out = []
    for i, (method, path, req_headers, body, resp_headers, resp_body) in enumerate(flows, start=1):
        out.append(Flow(f"f{i:04d}", RecordedRequest(method, host + path, [("User-Agent", "UA/1.0")] + list(req_headers), body),
                        RecordedResponse(200, list(resp_headers), resp_body), started_at=1_700_000_000.0 + i))
    return Recording(flows=out, meta={"source": "test"})


def _code_without_comments(source: str) -> str:
    import io
    import tokenize

    toks = [t for t in tokenize.generate_tokens(io.StringIO(source).readline) if t.type != tokenize.COMMENT]
    return tokenize.untokenize(toks)


# --------------------------------------------------------------------------- random letters: measured rates

def _random_tokens(alphabet: str, count: int, lo: int, hi: int, seed: int) -> list[str]:
    rnd = random.Random(seed)
    return ["".join(rnd.choice(alphabet) for _ in range(rnd.randint(lo, hi))) for _ in range(count)]


@pytest.mark.parametrize("alphabet,lo,hi,minimum", [
    (string.ascii_letters, 16, 24, 0.94),          # measured 0.961 (seed 2026; before: 0.985)
    (string.ascii_letters, 20, 20, 0.94),          # the factory site's key length; measured 0.962
    (string.ascii_letters + "-_", 16, 24, 0.94),   # base64url without digits; measured 0.959 (before: 0.466)
    (string.ascii_letters, 12, 15, 0.86),          # short keys; measured 0.894
])
def test_random_mixed_case_letter_tokens_are_recognised(alphabet, lo, hi, minimum):
    tokens = _random_tokens(alphabet, 20000, lo, hi, seed=2026)
    rate = sum(deps.looks_random_letters(t) for t in tokens) / len(tokens)
    assert rate >= minimum, rate
    # the same tokens are dynamic-looking (warnings) and never route names (pattern tracing allowed)
    sample = tokens[:2000]
    assert all(deps.is_dynamic_looking(t) for t in sample if deps.looks_random_letters(t))
    assert not any(deps.is_route_like(t) for t in sample if deps.looks_random_letters(t))


IDENTIFIERS = """
hdnDeleteFgList txtFromYyMmDd ddlStartHhMm txtUpdateTs lblWkTableName
txtTokuisakiCD ddlSeisanKBN hdnSearchKEY btnExportCSV CustomerIDList ProductionResultCSV OrderDateDESC DownloadAsPDF
getXMLHttpRequest XMLHttpRequest HTMLDocument getElementById getElementsByTagName getElementsByClassName
querySelectorAll addEventListener removeEventListener encodeURIComponent decodeURIComponent toLocaleDateString
onreadystatechange createElementNS insertAdjacentHTML getBoundingClientRect XMLHTTPRequest innerHTMLText
ContentPlaceHolder ScriptManagerProxy UpdatePanelTrigger ValidationSummary RequiredFieldValidator GridViewRow
txtTokuisakiCd txtTokuisakiNm hdnShohinCdList lblSeisanSuKei txtJyuchuNoFrom txtJyuchuNoTo ddlKojoCdSelect
btnSearchClear btnExcelOutput lblErrorMessage chkDeleteFlag txtUpdateUserId gvSearchResult lnkNextPage
ExportToExcelCSV ShowModalDialog GetProductionResult SaveOrderDetailByID LoadCustomerIDList
Customer_ID_List export-production-CSV SEARCH_KEY_value ProductionResultCSV.aspx getXMLHttpRequest.js
""".split()


@pytest.mark.parametrize("name", IDENTIFIERS)
def test_identifier_corpus_is_not_random(name):
    assert not deps.looks_random_letters(name)
    assert not deps.is_dynamic_looking(name)


# --------------------------------------------------------------------------- factory recordings

@pytest.mark.parametrize("fixture", ["factory_ie_recording_digit_key.json", "factory_ie_recording_letter_key.json"])
def test_factory_recordings_keep_page_names_literal_and_trace_the_url_key(fixture):
    plan = build_plan(Recording.load(str(FIXTURES / fixture)))
    pages = {}
    for st in plan.steps:
        assert st.url and st.url[0].is_literal and len(st.url) == 1, st.url  # every URL is literal
        pages.setdefault(st.url[0].value.rsplit("/", 1)[-1], []).append(st)
    assert {"Login.aspx", "Search.aspx", "News.aspx"} <= set(pages)
    for st in pages["Search.aspx"]:
        key = dict(st.params)["key"]
        assert not key.is_literal  # the per-session URL key is traced
        referer = next((r for n, r in st.headers if n.lower() == "referer"), None)
        assert referer is None or referer.is_literal or "'http://127.0.0.1.nip.io:" in referer.value
    # page names never become extractors or constants
    names = {"Login.aspx", "Search.aspx", "News.aspx", "Menu.aspx", "ItemPicker.aspx"}
    assert not any(e.sample in names for st in plan.steps for e in st.extractors)
    assert not any(c.value in names for c in plan.constants)


# --------------------------------------------------------------------------- generated scripts (end to end)

def test_percent_encoded_referer_carries_the_fresh_key(tmp_path):
    host = "http://kanri.example"
    rec = _recording(
        host,
        ("GET", "/api/session", [], None, JSON_CT, b'{"key": "Qk+9/zR8vT=="}'),
        ("GET", "/Search.aspx?key=Qk%2B9%2FzR8vT%3D%3D", [], None, HTML_CT, b"<html><title>s</title></html>"),
        ("POST", "/Search.aspx?key=Qk%2B9%2FzR8vT%3D%3D", [FORM_CT, ("Referer", host + "/Search.aspx?key=Qk%2B9%2FzR8vT%3D%3D")],
         b"q=1", HTML_CT, b"<html><title>done</title></html>"),
    )
    plan = build_plan(rec)
    referer = next(r for n, r in plan.steps[2].headers if n == "Referer")
    assert "requests.utils.quote(" in referer.value
    src = generate(plan)
    assert "Qk" not in _code_without_comments(src)
    fresh = "Zz+1/yY2xX=="
    adapter = MockAdapter([
        Rule(host + "/api/session", body={"key": fresh}),
        Rule(host + "/Search.aspx", method="GET", body="<html><title>s</title></html>", content_type="text/html"),
        Rule(host + "/Search.aspx", method="POST", body="<html><title>done</title></html>", content_type="text/html"),
    ])
    run_generated(src, adapter, env={"REQREC_OUTPUT_DIR": str(tmp_path)})
    post = adapter.calls[-1]
    assert post.method == "POST" and post.query_dict == {"key": fresh}
    assert post.header("Referer") == host + "/Search.aspx?key=" + quote(fresh, safe="")


def test_unquoted_source_spelling_is_reused_in_the_referer(tmp_path):
    host = "http://kanri.example"
    menu = b"<html><a id=\"s\" onclick=\"window.open('Search.aspx?key=Qk%2B9%2FzR8vT%3D%3D','s')\">s</a></html>"
    rec = _recording(
        host,
        ("GET", "/Menu.aspx", [], None, HTML_CT, menu),
        ("POST", "/Search.aspx?key=Qk%2B9%2FzR8vT%3D%3D", [FORM_CT, ("Referer", host + "/Search.aspx?key=Qk%2B9%2FzR8vT%3D%3D")],
         b"q=1", HTML_CT, b"<html><title>done</title></html>"),
    )
    plan = build_plan(rec)
    key = dict(plan.steps[1].params)["key"]
    assert key.kind == "expr" and key.value.startswith("unquote(")
    referer = next(r for n, r in plan.steps[1].headers if n == "Referer")
    assert "requests.utils.quote" not in referer.value and "unquote" not in referer.value
    fresh_enc = "Zz%2B1%2FyY2xX%3D%3D"
    adapter = MockAdapter([
        Rule(host + "/Menu.aspx", body=menu.decode().replace("Qk%2B9%2FzR8vT%3D%3D", fresh_enc), content_type="text/html"),
        Rule(host + "/Search.aspx", method="POST", body="<html><title>done</title></html>", content_type="text/html"),
    ])
    run_generated(generate(plan), adapter, env={"REQREC_OUTPUT_DIR": str(tmp_path)})
    assert adapter.calls[-1].header("Referer") == host + "/Search.aspx?key=" + fresh_enc


@pytest.mark.parametrize("password", ["admin", "123", "tanaka01"])
def test_short_and_user_id_equal_passwords_come_from_the_environment(password, tmp_path):
    host = "http://kanri.example"
    rec = _recording(
        host,
        ("GET", "/Login.aspx", [], None, HTML_CT, b"<html><title>login</title></html>"),
        ("POST", "/Login.aspx", [FORM_CT], f"txtUserId=tanaka01&txtPassword={password}&pin=42".encode(), HTML_CT,
         b"<html><title>menu</title></html>"),
        ("POST", "/api/confirm", [("Content-Type", "application/json")], json.dumps({"user": "tanaka01", "pin": 4321}).encode(),
         JSON_CT, b'{"ok": true}'),
    )
    plan = build_plan(rec)
    secrets = {c.env_var: c.value for c in plan.constants if c.secret}
    assert secrets == {"REQREC_TXT_PASSWORD": password, "REQREC_PIN": "42", "REQREC_PIN_2": "4321"}
    # the user id (sent twice) is a plain shared constant, never bound to the password's variable
    assert [(c.name, c.value, c.env_var) for c in plan.constants if not c.secret] == [("TXT_USER_ID", "tanaka01", None)]
    src = generate(plan)
    code = _code_without_comments(src)
    assert "REQREC_TXT_PASSWORD" in code and "'42'" not in code and "4321" not in code
    if password != "tanaka01":
        assert repr(password) not in code
    adapter = MockAdapter([
        Rule(host + "/Login.aspx", method="GET", body="<html><title>login</title></html>", content_type="text/html"),
        Rule(host + "/Login.aspx", method="POST", body="<html><title>menu</title></html>", content_type="text/html"),
        Rule(host + "/api/confirm", method="POST", body={"ok": True}),
    ])
    env = {"REQREC_OUTPUT_DIR": str(tmp_path), "REQREC_TXT_PASSWORD": "fresh-pw", "REQREC_PIN": "7", "REQREC_PIN_2": "9876"}
    run_generated(src, adapter, env=env)
    login = adapter.calls[1]
    assert login.form == {"txtUserId": "tanaka01", "txtPassword": "fresh-pw", "pin": "7"}
    assert adapter.calls[2].json() == {"user": "tanaka01", "pin": 9876}  # still a JSON number
