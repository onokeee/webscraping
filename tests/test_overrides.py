"""Tests for the manual overrides of DESIGN.md §13.1: ``PlanOptions.exclude_flow_ids`` /
``include_flow_ids`` (``filters.classify_noise``) and ``final_flow_id`` -> ``Plan.final_step_index``
(``plan.build_plan``)."""

from __future__ import annotations

import base64

import pytest

from reqrec import filters
from reqrec.model import Flow, PlanOptions, RecordedRequest, RecordedResponse, Recording, Ref
from reqrec.plan import build_plan

T0 = 1_700_000_000.0
BASE = [("User-Agent", "UA/1.0"), ("Accept-Language", "ja")]
HTML = [("Content-Type", "text/html; charset=utf-8")]
JSON = [("Content-Type", "application/json")]
CSS = [("Content-Type", "text/css")]


class Site:
    def __init__(self, host="https://site.example"):
        self.host = host
        self.flows: list[Flow] = []

    def add(self, method, path, req_headers=(), body=None, status=200, resp_headers=HTML, resp_body=b"<html></html>",
            rtype=None, no_response=False):
        url = path if path.startswith("http") else self.host + path
        resp = None if no_response else RecordedResponse(status, list(resp_headers), resp_body)
        flow = Flow(f"f{len(self.flows) + 1:04d}", RecordedRequest(method, url, list(BASE) + list(req_headers), body), resp,
                    started_at=T0 + len(self.flows), resource_type=rtype)
        self.flows.append(flow)
        return flow

    def recording(self):
        return Recording(flows=list(self.flows), meta={"source": "test"})

    def plan(self, **opts):
        return build_plan(self.recording(), PlanOptions(**opts))


def noisy_site():
    s = Site()
    s.add("GET", "/", resp_body=b'<html><a id="go" href="/page?token=TOKabc123456">go</a></html>')         # f0001
    s.add("GET", "/static/app.css", resp_headers=CSS, rtype="stylesheet")                                   # f0002
    s.add("GET", "https://www.google-analytics.com/collect", resp_headers=[("Content-Type", "image/gif")])  # f0003
    s.add("GET", "/page?token=TOKabc123456", resp_body=b"<html>page</html>")                                # f0004
    s.add("GET", "/api/data", resp_headers=JSON, resp_body=b'{"a": 1}')                                      # f0005
    s.add("GET", "/lost", no_response=True)                                                                 # f0006
    s.add("GET", "/redir", status=302, resp_headers=[("Location", "/final")], resp_body=b"")                # f0007
    s.add("GET", "/final", resp_body=b"<html>final</html>")                                                 # f0008
    s.add("GET", "/cached", status=304, resp_body=b"")                                                      # f0009
    return s


def reasons(plan):
    return {d.flow_id: d.reason for d in plan.dropped}


def sources(plan):
    return [st.source_flow_ids for st in plan.steps]


# --------------------------------------------------------------------------- baseline

def test_baseline_without_overrides():
    plan = noisy_site().plan()
    assert sources(plan) == [["f0001"], ["f0004"], ["f0005"], ["f0007", "f0008"]]
    assert reasons(plan) == {
        "f0002": "static asset (resource type stylesheet)", "f0003": "tracker/analytics host",
        "f0006": "no response recorded", "f0009": "304 not modified (browser cache)",
    }
    assert plan.final_step_index is None


# --------------------------------------------------------------------------- exclude

def test_exclude_drops_a_kept_flow_with_reason():
    plan = noisy_site().plan(exclude_flow_ids=["f0004"])
    assert sources(plan) == [["f0001"], ["f0005"], ["f0007", "f0008"]]
    assert reasons(plan)["f0004"] == "excluded by user"
    assert plan.steps[0].extractors == []  # nobody consumes the link token any more
    assert plan.meta["flows_kept"] == 4


def test_exclude_is_checked_before_host_rules():
    plan = noisy_site().plan(exclude_flow_ids=["f0001", "f0003"], exclude_hosts=["site.example"])
    r = reasons(plan)
    assert r["f0001"] == "excluded by user" and r["f0003"] == "excluded by user"
    assert r["f0004"] == "host excluded" and r["f0006"] == "host excluded"
    assert plan.steps == []


@pytest.mark.parametrize("spelling", ["f0004", "F0004", "f4", "4", " f0004 ", "f0004,f0005", ["f0004", "f0005"]])
def test_exclude_accepts_loose_spellings(spelling):
    excluded = spelling if isinstance(spelling, list) else [spelling]
    plan = noisy_site().plan(exclude_flow_ids=excluded)
    assert reasons(plan)["f0004"] == "excluded by user"
    assert not any(ids == ["f0004"] for ids in sources(plan))


def test_exclude_one_hop_of_a_redirect_chain_breaks_the_chain():
    plan = noisy_site().plan(exclude_flow_ids=["f0008"])
    assert sources(plan)[-1] == ["f0007"] and plan.steps[-1].expected_status == 302
    plan2 = noisy_site().plan(exclude_flow_ids=["f0007"])
    assert sources(plan2)[-1] == ["f0008"]


# --------------------------------------------------------------------------- include

def test_include_keeps_static_tracker_and_304_flows():
    plan = noisy_site().plan(include_flow_ids=["f0002", "f0003", "f0009"])
    assert sources(plan) == [["f0001"], ["f0002"], ["f0003"], ["f0004"], ["f0005"], ["f0007", "f0008"], ["f0009"]]
    assert plan.steps[1].response_kind == "text" and plan.steps[1].literal_url() == "https://site.example/static/app.css"
    assert plan.steps[-1].expected_status == 304
    assert set(reasons(plan)) == {"f0006"}


def test_include_cannot_rescue_a_flow_without_response_or_outside_host_rules():
    plan = noisy_site().plan(include_flow_ids=["f0006", "f0003"], include_hosts=["site.example"])
    r = reasons(plan)
    assert r["f0006"] == "no response recorded"
    assert r["f0003"] == "host not in --include-host"
    plan2 = noisy_site().plan(include_flow_ids=["f0002"], exclude_hosts=["site.example"])
    assert reasons(plan2)["f0002"] == "host excluded"


def test_exclude_wins_over_include_for_the_same_flow():
    plan = noisy_site().plan(include_flow_ids=["f0005"], exclude_flow_ids=["f0005"])
    assert reasons(plan)["f0005"] == "excluded by user"


def test_include_with_keep_all_is_harmless():
    plan = noisy_site().plan(include_flow_ids=["f0002"], keep_all=True)
    assert [ids[0] for ids in sources(plan)] == ["f0001", "f0002", "f0003", "f0004", "f0005", "f0007", "f0009"]


# --------------------------------------------------------------------------- classify_noise directly

def test_classify_noise_override_rules():
    css = noisy_site().flows[1]
    assert filters.classify_noise(css, PlanOptions()) == "static asset (resource type stylesheet)"
    assert filters.classify_noise(css, PlanOptions(include_flow_ids=["f0002"])) is None
    assert filters.classify_noise(css, PlanOptions(include_flow_ids=["2"])) is None
    assert filters.classify_noise(css, PlanOptions(exclude_flow_ids=["f0002"], include_flow_ids=["f0002"])) == "excluded by user"
    assert filters.classify_noise(css, PlanOptions(exclude_flow_ids=["f0003"])) == "static asset (resource type stylesheet)"
    assert filters.classify_noise(css, PlanOptions(exclude_flow_ids=[None, "", "   "])) == "static asset (resource type stylesheet)"
    lost = noisy_site().flows[5]
    assert filters.classify_noise(lost, PlanOptions(include_flow_ids=["f0006"])) == "no response recorded"


@pytest.mark.parametrize("raw,expected", [
    ("f0008", "f0008"), ("F0008", "f0008"), ("f8", "f0008"), ("8", "f0008"), ("  f08 ", "f0008"), ("f12345", "f12345"),
    ("", ""), (None, ""), ("abc", "abc"), ("f00x8", "f00x8"), (8, "f0008"),
])
def test_normalise_flow_id(raw, expected):
    assert filters.normalise_flow_id(raw) == expected


# --------------------------------------------------------------------------- final flow

def test_final_flow_in_the_middle():
    plan = noisy_site().plan(final_flow_id="f0005")
    assert plan.final_step_index == 3
    assert len(plan.steps) == 4  # every step still runs
    assert plan.warnings == []


@pytest.mark.parametrize("fid,expected", [("f0007", 4), ("f0008", 4), ("f0001", 1), ("5", 3), ("F0004", 2)])
def test_final_flow_any_hop_of_a_chain_and_loose_ids(fid, expected):
    plan = noisy_site().plan(final_flow_id=fid)
    assert plan.final_step_index == expected


def test_final_flow_dropped_warns_and_falls_back():
    plan = noisy_site().plan(final_flow_id="f0002")
    assert plan.final_step_index is None
    (warning,) = [w for w in plan.warnings if "f0002" in w]
    assert "static asset" in warning and "最後のステップ" in warning


def test_final_flow_excluded_by_user_warns():
    plan = noisy_site().plan(final_flow_id="f0005", exclude_flow_ids=["f0005"])
    assert plan.final_step_index is None
    assert any("f0005" in w and "excluded by user" in w for w in plan.warnings)


def test_final_flow_unknown_or_blank():
    plan = noisy_site().plan(final_flow_id="f9999")
    assert plan.final_step_index is None and any("f9999" in w and "存在しません" in w for w in plan.warnings)
    assert noisy_site().plan(final_flow_id="").final_step_index is None
    assert noisy_site().plan(final_flow_id=None).final_step_index is None
    assert noisy_site().plan(final_flow_id="   ").warnings == []


def test_final_flow_cut_by_max_steps_warns():
    plan = noisy_site().plan(final_flow_id="f0005", max_steps=2, detect_loops=False)
    assert len(plan.steps) == 2 and plan.final_step_index is None
    assert any("f0005" in w and "max-steps" in w for w in plan.warnings)


def test_final_flow_can_be_a_401_handshake_hop():
    s = Site()
    s.add("GET", "/secure", status=401, resp_headers=HTML + [("WWW-Authenticate", 'Basic realm="x"')], resp_body=b"<html>401</html>")
    s.add("GET", "/secure", [("Authorization", "Basic " + base64.b64encode(b"taro:pw").decode())], resp_body=b"<html>ok</html>")
    s.add("GET", "/after", resp_body=b"<html>after</html>")
    plan = s.plan(final_flow_id="f0001")
    assert sources(plan) == [["f0001", "f0002"], ["f0003"]]
    assert plan.final_step_index == 1 and plan.auth.kind == "basic"


def test_final_flow_inside_a_folded_loop():
    s = Site()
    s.add("GET", "/start", resp_body=b"<html>s</html>")
    for page in (1, 2, 3):
        s.add("GET", f"/api/items?page={page}", resp_headers=JSON, resp_body=b'{"items": []}')
    s.add("GET", "/end", resp_body=b"<html>e</html>")
    plan = s.plan(final_flow_id="f0003")
    assert plan.steps[1].loop is not None and plan.final_step_index == 2


def test_overrides_combined_recompute_cleanly():
    """GUI flow: untick a flow, tick a static one, pick a result - all in one plan."""
    s = noisy_site()
    plan = s.plan(exclude_flow_ids=["f0004"], include_flow_ids=["f0002"], final_flow_id="f0002")
    assert sources(plan) == [["f0001"], ["f0002"], ["f0005"], ["f0007", "f0008"]]
    assert plan.final_step_index == 2
    assert reasons(plan)["f0004"] == "excluded by user"
    assert dict(plan.steps[0].headers).get("Accept") is None  # nothing odd slipped into headers
    assert all(isinstance(ref, Ref) for st in plan.steps for _n, ref in st.headers)
