"""Integration test for the IE-mode / WebForms fixture (DESIGN.md §13.8).

``tests/fixtures/legacy_webforms_ntlm.har`` is an IE11 F12 style export of an intranet ASP.NET
site: an NTLM 3-leg handshake, Shift_JIS pages served as ``text/html`` without charset, a postback
whose form body is percent-encoded cp932, a results page linking to ``Report.aspx?id=1234``, the
report page with a CSV export link, the export itself, and a ``WebResource.axd`` script.

``load_recording`` -> ``build_plan`` -> ``generate`` -> replay against the mock adapter (the code
generator rebuilds the legacy form body from ``Step.form`` so fresh ``__VIEWSTATE`` values are sent).
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import parse_qsl, unquote_to_bytes, urlsplit

import pytest

from reqrec import cli
from reqrec.codegen import generate
from reqrec.importers import load_recording
from reqrec.model import GenOptions, PlanOptions, Ref, to_plain
from reqrec.plan import build_plan
from tests.e2e.mock_adapter import MockAdapter, Rule, run_generated

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGACY_HAR = os.path.join(ROOT, "tests", "fixtures", "legacy_webforms_ntlm.har")
HOST = "http://intra.example.local"
KEYWORD_CP932 = "日本".encode("cp932")  # %93%FA%96%7B
BUTTON_CP932 = "検索".encode("cp932")  # %8C%9F%8D%F5


@pytest.fixture(scope="module")
def legacy():
    recording = load_recording(LEGACY_HAR)
    plan = build_plan(recording, PlanOptions())
    return recording, plan


def hidden_inputs(html: str) -> dict[str, str]:
    return dict(re.findall(r'<input type="hidden" name="(__\w+)" id="__\w+" value="([^"]*)"', html))


def step_headers(step) -> dict[str, Ref]:
    return {name.lower(): ref for name, ref in step.headers}


# --------------------------------------------------------------------------- import

def test_fixture_imports_as_an_ie_har(legacy):
    recording, _plan = legacy
    assert recording.meta["creator"].startswith("F12 Developer Tools")
    assert recording.meta["browser"].startswith("Internet Explorer")
    assert [f.id for f in recording.flows] == [f"f{i:04d}" for i in range(1, 8)]
    assert [(f.request.method, f.request.path, f.response.status) for f in recording.flows] == [
        ("GET", "/Default.aspx", 401), ("GET", "/Default.aspx", 401), ("GET", "/Default.aspx", 200),
        ("GET", "/WebResource.axd", 200), ("POST", "/Default.aspx", 200), ("GET", "/Report.aspx", 200), ("GET", "/Export.aspx", 200),
    ]
    page = recording.flows[2]
    assert page.response.header("Content-Type") == "text/html"  # no charset on the wire ...
    assert page.request.header("User-Agent").startswith("Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0)")
    assert page.request.header("Accept-Language") == "ja-JP"
    text = page.response.text()
    assert "売上レポート検索" in text and 'charset=Shift_JIS' in text  # ... decoded through the <meta http-equiv>
    assert page.response.body.startswith(b"<!DOCTYPE") and "検索".encode("cp932") in page.response.body
    post = recording.flows[4]
    assert post.request.content_type == "application/x-www-form-urlencoded"
    assert b"ctl00%24txtKeyword=%93%FA%96%7B&ctl00%24btnSearch=%8C%9F%8D%F5" in post.request.body
    assert recording.flows[6].response.mime_type == "text/csv"
    assert recording.flows[0].response.header("WWW-Authenticate") == "Negotiate"
    assert recording.flows[1].response.header("WWW-Authenticate").startswith("NTLM TlRMTVNTUAAC")


# --------------------------------------------------------------------------- plan

def test_auth_is_ntlm_with_recorded_user(legacy):
    _recording, plan = legacy
    auth = plan.auth
    assert auth is not None
    assert (auth.kind, auth.hosts, auth.realm, auth.username) == ("ntlm", ["intra.example.local"], None, "EXAMPLE\\taro")
    assert auth.username_const is None and auth.password_const is None
    assert plan.constants == []
    assert plan.meta["auth"] == "ntlm"
    assert any("REQREC_NTLM_USER" in w and "EXAMPLE\\taro" in w for w in plan.warnings)


def test_four_steps_handshake_folded_and_script_dropped(legacy):
    _recording, plan = legacy
    assert [s.func_name for s in plan.steps] == [
        "step_01_get_default_aspx", "step_02_post_default_aspx", "step_03_get_report_aspx", "step_04_get_export_aspx",
    ]
    assert [s.source_flow_ids for s in plan.steps] == [["f0001", "f0002", "f0003"], ["f0005"], ["f0006"], ["f0007"]]
    assert [s.expected_status for s in plan.steps] == [200, 200, 200, 200]
    assert [s.response_kind for s in plan.steps] == ["html", "html", "html", "text"]
    assert [(d.flow_id, d.reason) for d in plan.dropped] == [("f0004", "static asset (mime application/x-javascript)")]
    assert plan.meta["flows_total"] == 7 and plan.meta["flows_kept"] == 6 and plan.meta["steps"] == 4
    assert plan.steps[0].literal_url() == f"{HOST}/Default.aspx"
    assert plan.steps[1].literal_url() == f"{HOST}/Default.aspx"
    assert plan.steps[2].literal_url() == f"{HOST}/Report.aspx"
    assert plan.steps[3].literal_url() == f"{HOST}/Export.aspx"
    assert plan.final_step_index is None and plan.initial_cookies == []


def test_no_authorization_header_anywhere(legacy):
    recording, plan = legacy
    for step in plan.steps:
        assert "authorization" not in step_headers(step), step.func_name
    dump = json.dumps(to_plain(plan), ensure_ascii=False)
    for flow in recording.flows[1:3]:
        token = flow.request.header("Authorization").split(" ", 1)[1]
        assert token not in dump
    assert "TlRMTVNTUAA" not in dump  # no NTLMSSP token survives
    assert {k.lower() for k, _ in plan.base_headers} == {"accept", "accept-language", "user-agent"}
    assert dict(plan.base_headers)["Accept-Language"] == "ja-JP"


def test_webforms_hidden_fields_are_html_input_extractors(legacy):
    recording, plan = legacy
    page_values = hidden_inputs(recording.flows[2].response.text())
    exts = {e.name: e for e in plan.steps[0].extractors}
    assert set(exts) == {"__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"}
    for name, ext in exts.items():
        assert ext.kind == "html_input" and ext.sample == page_values[name], name
        assert "step 2" in ext.note
    assert (exts["__VIEWSTATE"].var, exts["__VIEWSTATEGENERATOR"].var, exts["__EVENTVALIDATION"].var) == (
        "viewstate", "viewstategenerator", "eventvalidation")
    assert len(page_values["__VIEWSTATE"]) > 300 and re.fullmatch(r"[0-9A-F]{8}", page_values["__VIEWSTATEGENERATOR"])
    form = dict(plan.steps[1].form)
    assert form["__VIEWSTATE"] == Ref.var("viewstate")
    assert form["__VIEWSTATEGENERATOR"] == Ref.var("viewstategenerator")
    assert form["__EVENTVALIDATION"] == Ref.var("eventvalidation")
    assert form["__EVENTTARGET"] == Ref.lit("") and form["__EVENTARGUMENT"] == Ref.lit("")


def test_legacy_form_body_kept_raw_with_content_type(legacy):
    recording, plan = legacy
    post = plan.steps[1]
    assert post.body_kind == "raw"
    assert post.raw_body == recording.flows[4].request.body
    assert b"ctl00%24txtKeyword=%93%FA%96%7B" in post.raw_body
    headers = step_headers(post)
    assert headers["content-type"] == Ref.lit("application/x-www-form-urlencoded")
    assert headers["referer"] == Ref.lit(f"{HOST}/Default.aspx") and headers["cache-control"] == Ref.lit("no-cache")
    # the form hint lets a generator rebuild the body: cp932 values are bytes literals
    form = dict(post.form)
    assert form["ctl00$txtKeyword"] == Ref.expr(repr(KEYWORD_CP932))
    assert form["ctl00$btnSearch"] == Ref.expr(repr(BUTTON_CP932))
    assert [name for name, _ in post.form] == [
        "__EVENTTARGET", "__EVENTARGUMENT", "__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION", "ctl00$txtKeyword", "ctl00$btnSearch",
    ]
    (warning,) = [w for w in plan.warnings if w.startswith("step 2:")]
    assert "Shift_JIS" in warning and "Content-Type" in warning and "__VIEWSTATE" in warning
    assert not any("looks dynamic" in w for w in plan.warnings), plan.warnings


def test_report_id_traced_through_href_pattern(legacy):
    recording, plan = legacy
    (link,) = plan.steps[1].extractors
    assert (link.kind, link.selector, link.attr, link.sample, link.var) == ("html_attr", "a.report-link", "href", "1234", "report_id")
    assert link.pattern and re.compile(link.pattern).groups == 1 and "1234" not in link.pattern
    assert re.search(link.pattern, "Report.aspx?id=1234").group(1) == "1234"
    assert re.search(link.pattern, "Report.aspx?id=98765").group(1) == "98765"
    assert plan.steps[2].params == [("id", Ref.var("report_id"))]
    # the CSV link on the report page feeds the export step
    (csv_link,) = plan.steps[2].extractors
    assert (csv_link.kind, csv_link.selector, csv_link.attr, csv_link.var) == ("html_attr", "a.csv-link", "href", "export_id")
    assert re.search(csv_link.pattern, "Export.aspx?id=4242&fmt=csv").group(1) == "4242"
    assert plan.steps[3].params == [("id", Ref.var("export_id")), ("fmt", Ref.lit("csv"))]
    assert plan.steps[3].response_kind == "text"
    # text/csv without charset: the bytes are Shift_JIS (codegen's _text(resp) sniffs that at run time)
    assert recording.flows[6].response.body.startswith("商品,数量".encode("cp932"))


def test_overrides_apply_to_the_fixture(legacy):
    recording, _plan = legacy
    plan = build_plan(recording, PlanOptions(final_flow_id="f0002", exclude_flow_ids=["f0007"], include_flow_ids=["f0004"]))
    assert plan.final_step_index == 1  # a 401 hop names the step it was folded into
    assert [s.source_flow_ids for s in plan.steps] == [["f0001", "f0002", "f0003"], ["f0004"], ["f0005"], ["f0006"]]
    assert {d.flow_id: d.reason for d in plan.dropped} == {"f0007": "excluded by user"}
    off = build_plan(recording, PlanOptions(detect_auth=False, detect_loops=False))
    assert off.auth is None and [s.expected_status for s in off.steps] == [401, 401, 200, 200, 200, 200]


# --------------------------------------------------------------------------- generate

def test_generated_script_compiles_and_leaks_nothing(legacy):
    recording, plan = legacy
    source = generate(plan, GenOptions())
    compile(source, "legacy_scrape.py", "exec")
    assert "def step_01_get_default_aspx(" in source and "def step_04_get_export_aspx(" in source
    for flow in recording.flows[1:3]:
        assert flow.request.header("Authorization").split(" ", 1)[1] not in source
    assert "TlRMTVNTUAA" not in source
    assert "'Authorization'" not in source and '"Authorization"' not in source  # no header of the folded scheme is emitted
    assert "%93%FA%96%7B" in source  # the recorded cp932 form bytes are in the script
    assert "__VIEWSTATE" in source


def test_cli_inspect_and_generate_succeed_on_the_fixture(tmp_path, capsys):
    assert cli.main(["inspect", LEGACY_HAR]) == 0
    out = capsys.readouterr().out
    assert "WebResource.axd" in out and "Default.aspx" in out  # flow ids per row are the CLI owner's §13.1 addition
    target = tmp_path / "legacy.py"
    assert cli.main(["generate", LEGACY_HAR, "-o", str(target)]) == 0
    compile(target.read_text(encoding="utf-8"), str(target), "exec")


# --------------------------------------------------------------------------- replay against a fresh server

class LegacySite:
    """Scripted ``intra.example.local`` that issues NEW WebForms tokens and rejects the recorded ones.

    It never challenges with 401 (so no NTLM library is needed in the test process); what it
    checks is that the postback carries the fresh ``__VIEWSTATE`` / ``__EVENTVALIDATION`` and the
    cp932-encoded keyword, and that the report / export ids come from the live pages."""

    VIEWSTATE = "/wEPDwUKNEW" + "Qq9XwZ1" * 40 + "=="
    EVENTVALIDATION = "/wEdAANEW" + "kL0pZ" * 12 + "=="
    REPORT_ID = "7788"

    def __init__(self) -> None:
        self.adapter = MockAdapter([
            Rule(f"{HOST}/Default.aspx", method="GET", handler=self.page),
            Rule(f"{HOST}/Default.aspx", method="POST", handler=self.postback),
            Rule(f"{HOST}/Report.aspx", method="GET", handler=self.report),
            Rule(f"{HOST}/Export.aspx", method="GET", handler=self.export),
        ])

    def _html(self, body: str) -> tuple[int, list, bytes]:
        html = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS" /></head><body>'
                f"{body}</body></html>")
        return 200, [("Content-Type", "text/html")], html.encode("cp932")

    def page(self, request):
        return self._html(
            '<form method="post" action="./Default.aspx" id="form1">'
            f'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="{self.VIEWSTATE}" />'
            '<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="CA0B0334" />'
            f'<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="{self.EVENTVALIDATION}" />'
            '<input name="ctl00$txtKeyword" type="text" /><input type="submit" name="ctl00$btnSearch" value="検索" /></form>'
        )

    def postback(self, request):
        body = request.body if isinstance(request.body, bytes) else str(request.body or "").encode("latin-1")
        pairs = {}
        for segment in body.split(b"&"):
            name, _, value = segment.partition(b"=")
            pairs[unquote_to_bytes(name.replace(b"+", b" "))] = unquote_to_bytes(value.replace(b"+", b" "))
        ok = (pairs.get(b"__VIEWSTATE") == self.VIEWSTATE.encode() and pairs.get(b"__EVENTVALIDATION") == self.EVENTVALIDATION.encode()
              and pairs.get(b"ctl00$txtKeyword") == KEYWORD_CP932 and pairs.get(b"ctl00$btnSearch") == BUTTON_CP932
              and (request.headers.get("Content-Type") or "").startswith("application/x-www-form-urlencoded"))
        if not ok:
            return 500, [("Content-Type", "text/html")], "<html>Invalid viewstate or form</html>".encode("cp932")
        return self._html(f'<table id="ctl00_gvResults"><tr><td><a class="report-link" href="Report.aspx?id={self.REPORT_ID}">日本支社</a></td></tr></table>')

    def report(self, request):
        if dict(parse_qsl(urlsplit(request.url).query)).get("id") != self.REPORT_ID:
            return 404, [("Content-Type", "text/html")], b"<html>no such report</html>"
        return self._html(f'<a class="csv-link" href="Export.aspx?id={self.REPORT_ID}&amp;fmt=csv">CSV</a>')

    def export(self, request):
        query = dict(parse_qsl(urlsplit(request.url).query))
        if query.get("id") != self.REPORT_ID or query.get("fmt") != "csv":
            return 404, [("Content-Type", "text/plain")], b"bad export"
        return 200, [("Content-Type", "text/csv")], "商品,数量\r\n業務用プリンター,18\r\n".encode("cp932")


def test_script_replays_with_fresh_viewstate_against_mock(legacy):
    _recording, plan = legacy
    source = generate(plan, GenOptions())
    site = LegacySite()
    out = run_generated(source, site.adapter, env={})
    calls = site.adapter.calls
    assert site.adapter.unmatched == [], [c.url for c in site.adapter.unmatched]
    assert [(c.method, c.path) for c in calls] == [
        ("GET", "/Default.aspx"), ("POST", "/Default.aspx"), ("GET", "/Report.aspx"), ("GET", "/Export.aspx"),
    ]
    post = calls[1]
    assert LegacySite.VIEWSTATE.encode() in unquote_to_bytes(post.body) and KEYWORD_CP932 in unquote_to_bytes(post.body)
    assert post.header("Content-Type").startswith("application/x-www-form-urlencoded")
    assert calls[2].query_dict == {"id": LegacySite.REPORT_ID}
    assert calls[3].query_dict == {"id": LegacySite.REPORT_ID, "fmt": "csv"}
    assert "業務用プリンター" in out
    for call in calls:
        assert call.header("Authorization") is None
        assert call.header("User-Agent").startswith("Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0")
