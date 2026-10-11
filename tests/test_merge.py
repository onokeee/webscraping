"""Tests for ``importers.load_recordings`` (DESIGN.md §13.5): several recordings (one HAR per
browser tab) merged into one chronological ``Recording``."""

from __future__ import annotations

import json
import os

import pytest

from reqrec.importers import load_recording, load_recordings
from reqrec.model import Flow, PlanOptions, RecordedRequest, RecordedResponse, Recording, Ref
from reqrec.plan import build_plan

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROME_HAR = os.path.join(ROOT, "tests", "fixtures", "login_flow_chrome.har")
FIREFOX_HAR = os.path.join(ROOT, "tests", "fixtures", "api_firefox.har")


def urls(rec: Recording) -> list[str]:
    return [f.request.url for f in rec.flows]


def meta_without_time(meta: dict) -> dict:
    return {k: v for k, v in meta.items() if k != "imported_at"}


# --------------------------------------------------------------------------- the bundled fixtures

def test_two_fixtures_merge_chronologically_with_unique_ids():
    chrome, firefox = load_recording(CHROME_HAR), load_recording(FIREFOX_HAR)
    merged = load_recordings([FIREFOX_HAR, CHROME_HAR])  # deliberately out of order
    assert len(merged.flows) == len(chrome.flows) + len(firefox.flows) == 20
    assert [f.id for f in merged.flows] == [f"f{i:04d}" for i in range(1, 21)]
    stamps = [f.started_at for f in merged.flows]
    assert None not in stamps and stamps == sorted(stamps)
    # Chrome recorded at 09:15Z, Firefox at 18:20+09:00 (= 09:20Z): every Chrome flow comes first
    assert urls(merged) == urls(chrome) + urls(firefox)
    # bodies / headers travel unchanged
    assert merged.flows[0].response.body == chrome.flows[0].response.body
    assert merged.flows[14].request.headers == firefox.flows[0].request.headers


def test_merged_meta_names_every_source():
    merged = load_recordings([CHROME_HAR, FIREFOX_HAR])
    assert merged.meta["source"] == "merged"
    sources = merged.meta["sources"]
    assert [s["file"] for s in sources] == [CHROME_HAR, FIREFOX_HAR]
    assert all(s["source"] == "har" for s in sources)
    assert sources[0]["creator"].startswith("WebInspector") and sources[1]["creator"].startswith("Firefox")


def test_single_path_is_identical_to_load_recording():
    single = load_recording(CHROME_HAR)
    for arg in ([CHROME_HAR], CHROME_HAR, (CHROME_HAR,)):
        rec = load_recordings(arg)
        assert [f.to_dict() for f in rec.flows] == [f.to_dict() for f in single.flows]
        assert meta_without_time(rec.meta) == meta_without_time(single.meta)
        assert rec.meta["source"] == "har" and "sources" not in rec.meta


def test_duplicate_paths_are_loaded_once():
    rec = load_recordings([CHROME_HAR, os.path.join(os.path.dirname(CHROME_HAR), ".", "login_flow_chrome.har"), CHROME_HAR])
    assert len(rec.flows) == 14 and rec.meta["source"] == "har"


def test_errors_are_explicit(tmp_path):
    with pytest.raises(ValueError):
        load_recordings([])
    with pytest.raises(FileNotFoundError):
        load_recordings([CHROME_HAR, str(tmp_path / "missing.har")])
    bad = tmp_path / "notes.txt"
    bad.write_text("hello", encoding="utf-8")
    with pytest.raises(ValueError) as info:
        load_recordings([str(bad)])
    assert "notes.txt" in str(info.value)


def test_build_plan_on_merged_fixtures():
    plan = build_plan(load_recordings([CHROME_HAR, FIREFOX_HAR]), PlanOptions())
    hosts = {st.literal_url().split("/")[2] for st in plan.steps if st.literal_url()}
    assert {"shop.example.test", "api.example.test", "app.example.test"} <= hosts
    assert plan.meta["flows_total"] == 20 and plan.meta["source"]["source"] == "merged"
    assert len(plan.steps) >= 7


# --------------------------------------------------------------------------- synthetic multi-tab recordings

def _rec(flows: list[Flow], **meta) -> Recording:
    return Recording(flows=flows, meta=meta or {"source": "test"})


def _flow(fid, method, url, ts, req_headers=(), body=None, status=200, resp_headers=(("Content-Type", "text/html; charset=utf-8"),),
          resp_body=b"<html></html>"):
    return Flow(fid, RecordedRequest(method, url, list(req_headers), body), RecordedResponse(status, list(resp_headers), resp_body),
                started_at=ts)


def test_new_tab_dependency_is_traced_across_files(tmp_path):
    """Tab 1 lists items with a signed link; the link opens in tab 2 (saved as a second HAR)."""
    t = 1_700_000_000.0
    tab1 = _rec([
        _flow("f0001", "GET", "https://app.example/list", t,
              resp_body=b'<html><a id="open" href="/detail?sig=SIGabc123456789" target="_blank">open</a></html>'),
        _flow("f0002", "GET", "https://app.example/list?page=2", t + 20, resp_body=b"<html>page 2</html>"),
    ])
    tab2 = _rec([
        _flow("f0001", "GET", "https://app.example/detail?sig=SIGabc123456789", t + 5,
              req_headers=[("Referer", "https://app.example/list")], resp_body=b"<html>detail</html>"),
    ])
    p1, p2 = tmp_path / "tab1.json", tmp_path / "tab2.json"
    tab1.save(str(p1))
    tab2.save(str(p2))
    merged = load_recordings([str(p1), str(p2)])
    assert [(f.id, f.request.path) for f in merged.flows] == [("f0001", "/list"), ("f0002", "/detail"), ("f0003", "/list")]
    plan = build_plan(merged, PlanOptions())
    assert [st.source_flow_ids for st in plan.steps] == [["f0001"], ["f0002"], ["f0003"]]
    (ext,) = plan.steps[0].extractors
    assert ext.kind == "html_attr" and ext.selector == "#open" and ext.pattern
    assert dict(plan.steps[1].params)["sig"] == Ref.var(ext.var)
    assert plan.meta["source"]["sources"][1]["source"] == "test"


def test_har_and_json_recording_mix(tmp_path):
    as_json = tmp_path / "chrome_copy.json"
    load_recording(CHROME_HAR).save(str(as_json))
    merged = load_recordings([str(as_json), FIREFOX_HAR])
    assert len(merged.flows) == 20 and merged.meta["sources"][0]["file"] == CHROME_HAR


def test_flows_without_timestamps_keep_relative_order_at_the_end(tmp_path):
    a = _rec([_flow("f0001", "GET", "https://a.example/1", 10.0), _flow("f0002", "GET", "https://a.example/2", 30.0)])
    b = Recording(flows=[
        Flow("f0001", RecordedRequest("GET", "https://b.example/x"), RecordedResponse(200, [], b"<html></html>"), started_at=None),
        Flow("f0002", RecordedRequest("GET", "https://b.example/y"), RecordedResponse(200, [], b"<html></html>"), started_at=20.0),
    ], meta={"source": "test"})
    pa, pb = tmp_path / "a.json", tmp_path / "b.json"
    a.save(str(pa))
    b.save(str(pb))
    merged = load_recordings([pa, pb])  # PathLike accepted
    assert [f.request.url for f in merged.flows] == ["https://a.example/1", "https://b.example/y", "https://a.example/2", "https://b.example/x"]
    assert [f.id for f in merged.flows] == ["f0001", "f0002", "f0003", "f0004"]


def test_merged_recording_round_trips_through_json(tmp_path):
    merged = load_recordings([CHROME_HAR, FIREFOX_HAR])
    out = tmp_path / "merged.json"
    merged.save(str(out))
    again = load_recordings([str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["source"] == "merged"
    assert [f.to_dict() for f in again.flows] == [f.to_dict() for f in merged.flows]
