"""Tests for the analysis section of ``reqrec.py``: noise filters, loop folding, dependency tracing, plan building,
manual overrides, Windows authentication and the review-3 analysis fixes.

One section per former test module (headed ``# ===== former tests/<name>.py ... =====``).  Helpers
that existed in several of them under the same name but with different contents carry a section
prefix (``loops_mk``, ``OVERRIDES_BASE`` / ``OverridesSite``, ``AUTH_HTML`` / ``AUTH_PAGE`` /
``AuthSite``); identical ones are defined once, in the first section that uses them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import string
import struct
from pathlib import Path
from urllib.parse import quote, unquote

import pytest
from bs4 import BeautifulSoup

import reqrec as deps, reqrec as filters
from reqrec import build_plan, detect_loops
from reqrec import generate
from reqrec import Flow, PlanOptions, RecordedRequest, RecordedResponse, Recording, Ref
from tests.support import MockAdapter, Rule, run_generated


# ===== former tests/test_filters.py: noise filters (former reqrec/filters.py) =====
# Tests for the filters section of reqrec.analysis (DESIGN.md §4).

def mk(method="GET", url="https://site.example/", req_headers=(), status=200, resp_headers=(), body=b"<html></html>",
       resource_type=None, response=True, fid="f0001", started_at=None):
    resp = RecordedResponse(status, list(resp_headers), body) if response else None
    return Flow(fid, RecordedRequest(method, url, list(req_headers)), resp, started_at=started_at,
                resource_type=resource_type)


HTML = [("Content-Type", "text/html; charset=utf-8")]
JSON = [("Content-Type", "application/json")]


# --------------------------------------------------------------------------- classify_noise

class TestClassifyNoise:
    def test_keeps_html_document(self):
        assert filters.classify_noise(mk(resp_headers=HTML), PlanOptions()) is None

    def test_keeps_json_api_and_redirects_and_downloads(self):
        opts = PlanOptions()
        assert filters.classify_noise(mk(url="https://site.example/api/x", resp_headers=JSON, body=b"{}"), opts) is None
        assert filters.classify_noise(mk(status=302, resp_headers=[("Location", "/x")], body=b""), opts) is None
        pdf = mk(url="https://site.example/report.pdf", resp_headers=[("Content-Type", "application/pdf")], body=b"%PDF")
        assert filters.classify_noise(pdf, opts) is None
        csv = mk(url="https://site.example/export.csv", resp_headers=[("Content-Type", "text/csv")], body=b"a,b")
        assert filters.classify_noise(csv, opts) is None

    def test_include_hosts_matches_subdomains(self):
        opts = PlanOptions(include_hosts=["example.com"])
        assert filters.classify_noise(mk(url="https://api.example.com/x", resp_headers=JSON), opts) is None
        assert filters.classify_noise(mk(url="https://other.net/x", resp_headers=JSON), opts) == "host not in --include-host"

    def test_exclude_hosts(self):
        opts = PlanOptions(exclude_hosts=["cdn.example.com"])
        assert filters.classify_noise(mk(url="https://cdn.example.com/x", resp_headers=JSON), opts) == "host excluded"
        assert filters.classify_noise(mk(url="https://example.com/x", resp_headers=JSON), opts) is None

    def test_no_response(self):
        assert filters.classify_noise(mk(response=False), PlanOptions()) == "no response recorded"

    def test_options_preflight(self):
        assert filters.classify_noise(mk(method="OPTIONS", status=204, body=b""), PlanOptions()) == "CORS preflight"

    def test_tracker_host(self):
        f = mk(url="https://www.google-analytics.com/collect", resp_headers=[("Content-Type", "image/gif")])
        assert filters.classify_noise(f, PlanOptions()) == "tracker/analytics host"
        assert filters.classify_noise(f, PlanOptions(keep_trackers=True)).startswith("static asset")
        f2 = mk(url="https://o123.ingest.sentry.io/api/1/envelope/", resp_headers=JSON)
        assert filters.classify_noise(f2, PlanOptions()) == "tracker/analytics host"

    def test_tracker_list_is_conservative(self):
        for host in ("google.com", "facebook.com", "twitter.com", "github.com", "amazon.co.jp", "yahoo.co.jp"):
            assert filters.classify_noise(mk(url=f"https://{host}/", resp_headers=HTML), PlanOptions()) is None

    @pytest.mark.parametrize("url,headers,rtype,why", [
        ("https://s/a.png", [("Content-Type", "image/png")], None, "mime image/png"),
        ("https://s/a.css", [("Content-Type", "text/css")], None, "mime text/css"),
        ("https://s/a.js", [("Content-Type", "application/javascript; charset=utf-8")], None, "mime application/javascript"),
        ("https://s/a.woff2", [("Content-Type", "font/woff2")], None, "mime font/woff2"),
        ("https://s/a.mp4", [("Content-Type", "video/mp4")], None, "mime video/mp4"),
        ("https://s/a.wasm", [("Content-Type", "application/wasm")], None, "mime application/wasm"),
        ("https://s/a.woff", [("Content-Type", "application/octet-stream")], None, ".woff file"),
        ("https://s/a.js", [("Content-Type", "text/plain")], None, ".js file"),
        ("https://s/a.png", [], None, ".png file"),
        ("https://s/favicon.ico", [("Content-Type", "text/html")], None, "favicon"),
        ("https://s/data", [("Content-Type", "text/html")], "image", "resource type image"),
        ("https://s/beacon", [("Content-Type", "text/plain")], "ping", "resource type ping"),
    ])
    def test_static(self, url, headers, rtype, why):
        f = mk(url=url, resp_headers=headers, resource_type=rtype)
        assert filters.classify_noise(f, PlanOptions()) == f"static asset ({why})"
        assert filters.classify_noise(f, PlanOptions(keep_static=True)) is None

    def test_octet_stream_download_is_kept(self):
        f = mk(url="https://s/download?id=1", resp_headers=[("Content-Type", "application/octet-stream")])
        assert filters.classify_noise(f, PlanOptions()) is None

    def test_json_with_js_extension_is_kept(self):
        f = mk(url="https://s/api/data.js", resp_headers=JSON, body=b"{}")
        assert filters.classify_noise(f, PlanOptions()) is None

    def test_304_websocket_sse(self):
        opts = PlanOptions()
        assert filters.classify_noise(mk(status=304, body=b""), opts) == "304 not modified (browser cache)"
        ws = mk(url="wss://s/ws", req_headers=[("Upgrade", "websocket")], status=101, body=b"")
        assert filters.classify_noise(ws, opts) == "websocket"
        sse = mk(resp_headers=[("Content-Type", "text/event-stream")], body=b"data: x")
        assert filters.classify_noise(sse, opts) == "server-sent events stream"

    def test_keep_all_skips_only_rules_4_to_9(self):
        opts = PlanOptions(keep_all=True, include_hosts=["s"])
        assert filters.classify_noise(mk(url="https://s/a.png", resp_headers=[("Content-Type", "image/png")]), opts) is None
        assert filters.classify_noise(mk(url="https://s/x", status=304), opts) is None
        assert filters.classify_noise(mk(url="https://s/x", response=False), opts) == "no response recorded"
        assert filters.classify_noise(mk(url="https://other/x"), opts) == "host not in --include-host"

    def test_order_host_rules_before_static(self):
        f = mk(url="https://cdn.other/a.png", resp_headers=[("Content-Type", "image/png")])
        assert filters.classify_noise(f, PlanOptions(exclude_hosts=["cdn.other"])) == "host excluded"


def test_filter_flows_splits_and_reports_reasons():
    rec = Recording(flows=[
        mk(fid="f0001", resp_headers=HTML),
        mk(fid="f0002", url="https://site.example/a.css", resp_headers=[("Content-Type", "text/css")]),
        mk(fid="f0003", response=False),
    ])
    kept, dropped = filters.filter_flows(rec, PlanOptions())
    assert [f.id for f in kept] == ["f0001"]
    assert [(d.flow_id, d.reason) for d in dropped] == [
        ("f0002", "static asset (mime text/css)"),
        ("f0003", "no response recorded"),
    ]
    assert dropped[0].method == "GET" and dropped[0].url == "https://site.example/a.css"


# --------------------------------------------------------------------------- clean_request_headers

def test_clean_request_headers_drops_managed_and_pseudo_headers():
    headers = [
        (":authority", "s"), (":method", "GET"), ("Host", "s"), ("Cookie", "a=b"), ("Content-Length", "3"),
        ("Accept-Encoding", "gzip"), ("Connection", "keep-alive"), ("If-None-Match", "x"), ("Proxy-Connection", "k"),
        ("User-Agent", "UA"), ("Content-Type", "text/plain"), ("X-Custom", "1"), ("Range", "bytes=0-1"),
    ]
    assert filters.clean_request_headers(headers) == [
        ("User-Agent", "UA"), ("Content-Type", "text/plain"), ("X-Custom", "1"), ("Range", "bytes=0-1"),
    ]


# --------------------------------------------------------------------------- compute_base_headers

def test_compute_base_headers_common_pairs_first_spelling():
    f1 = mk(req_headers=[("User-Agent", "UA"), ("Accept", "text/html"), ("Referer", "https://s/"), ("X-Requested-With", "XMLHttpRequest"),
                         ("Authorization", "Bearer t"), ("Origin", "https://s"), ("Cookie", "a=1"), ("Accept-Language", "ja")])
    f2 = mk(req_headers=[("user-agent", "UA"), ("Accept", "application/json"), ("Referer", "https://s/"), ("X-Requested-With", "XMLHttpRequest"),
                         ("Authorization", "Bearer t"), ("Origin", "https://s"), ("accept-language", "ja"), ("Content-Type", "application/json")])
    assert filters.compute_base_headers([f1, f2]) == [("User-Agent", "UA"), ("Accept-Language", "ja")]


def test_compute_base_headers_empty_and_single():
    assert filters.compute_base_headers([]) == []
    f = mk(req_headers=[("User-Agent", "UA"), ("Host", "s"), ("X-A", "1")])
    assert filters.compute_base_headers([f]) == [("User-Agent", "UA")]


def test_compute_base_headers_conflicting_duplicates_excluded():
    f1 = mk(req_headers=[("Accept", "a"), ("Accept", "b")])
    f2 = mk(req_headers=[("Accept", "a")])
    assert filters.compute_base_headers([f1, f2]) == []


# --------------------------------------------------------------------------- collapse_redirects

def test_collapse_redirects_chains_multi_hop_and_ignores_fragment():
    a = mk(fid="a", method="POST", url="https://s/login", status=302, resp_headers=[("Location", "/step2#frag")], body=b"")
    b = mk(fid="b", url="https://s/step2", status=301, resp_headers=[("Location", "https://s/final?x=1")], body=b"")
    c = mk(fid="c", url="https://s/final?x=1", resp_headers=HTML)
    d = mk(fid="d", url="https://s/other", resp_headers=HTML)
    groups = filters.collapse_redirects([a, b, c, d])
    assert [[f.id for f in g] for g in groups] == [["a", "b", "c"], ["d"]]


def test_collapse_redirects_requires_get_for_302_but_same_method_for_307():
    a = mk(fid="a", method="POST", url="https://s/x", status=302, resp_headers=[("Location", "/y")], body=b"")
    b = mk(fid="b", method="POST", url="https://s/y", resp_headers=HTML)
    assert [[f.id for f in g] for g in filters.collapse_redirects([a, b])] == [["a"], ["b"]]
    a307 = mk(fid="a", method="POST", url="https://s/x", status=307, resp_headers=[("Location", "/y")], body=b"")
    assert [[f.id for f in g] for g in filters.collapse_redirects([a307, b])] == [["a", "b"]]


def test_collapse_redirects_non_matching_target_stays_singleton():
    a = mk(fid="a", status=302, resp_headers=[("Location", "/y")], body=b"")
    b = mk(fid="b", url="https://s/z", resp_headers=HTML)
    assert [[f.id for f in g] for g in filters.collapse_redirects([a, b])] == [["a"], ["b"]]
    assert filters.collapse_redirects([]) == []


# --------------------------------------------------------------------------- classify_cookies

def test_classify_cookies_pre_existing_vs_managed():
    f1 = mk(fid="1", url="https://s/a", req_headers=[("Cookie", "theme=dark; old=1")],
            resp_headers=[("Set-Cookie", "sess=abc; Path=/; HttpOnly"), ("Set-Cookie", "bad")])
    f2 = mk(fid="2", url="https://s/b", req_headers=[("Cookie", "theme=dark; sess=abc")])
    f3 = mk(fid="3", url="https://api.s/c", req_headers=[("Cookie", "theme=dark; sess=abc; other=x=y")])
    initial, managed = filters.classify_cookies([f1, f2, f3])
    assert managed == {"sess"}
    assert [(c.name, c.value, c.domain, c.path) for c in initial] == [
        ("theme", "dark", "s", "/"), ("old", "1", "s", "/"), ("theme", "dark", "api.s", "/"), ("other", "x=y", "api.s", "/"),
    ]


def test_cookie_parsers_tolerate_garbage():
    assert filters.parse_cookie_header("a=1; ; b; =x; c=d=e") == [("a", "1"), ("b", ""), ("c", "d=e")]
    assert filters.parse_cookie_header(None) == []
    assert filters.parse_set_cookie("x=y%3D; Path=/; Secure") == ("x", "y%3D")
    assert filters.parse_set_cookie("garbage") is None
    assert filters.parse_set_cookie("") is None


# --------------------------------------------------------------------------- phase 2 (DESIGN.md §13.1 / §13.2)

def test_classify_noise_manual_overrides_come_first():
    css = mk(fid="f0002", url="https://cdn.other/a.css", resp_headers=[("Content-Type", "text/css")])
    assert filters.classify_noise(css, PlanOptions(exclude_flow_ids=["f0002"], exclude_hosts=["cdn.other"])) == "excluded by user"
    assert filters.classify_noise(css, PlanOptions(include_flow_ids=["f0002"])) is None
    assert filters.classify_noise(css, PlanOptions(include_flow_ids=["f0002"], exclude_hosts=["cdn.other"])) == "host excluded"
    assert filters.classify_noise(mk(fid="f0003", response=False), PlanOptions(include_flow_ids=["f0003"])) == "no response recorded"
    rec = Recording(flows=[mk(fid="f0001", resp_headers=HTML), css])
    kept, dropped = filters.filter_flows(rec, PlanOptions(exclude_flow_ids=["1"], include_flow_ids=["2"]))
    assert [f.id for f in kept] == ["f0002"] and [(d.flow_id, d.reason) for d in dropped] == [("f0001", "excluded by user")]


def test_collapse_auth_handshakes_ignores_default_port_and_case_in_urls():
    a = mk(fid="a", url="http://Intra.Example.local:80/Default.aspx", status=401,
           resp_headers=[("WWW-Authenticate", 'Basic realm="x"'), ("Content-Type", "text/html")], body=b"")
    b = mk(fid="b", url="http://intra.example.local/Default.aspx", req_headers=[("Authorization", "Basic dXNlcjpwYXNz")], resp_headers=HTML)
    groups, auth = filters.collapse_auth_handshakes([a, b])
    assert [[f.id for f in g] for g in groups] == [["a", "b"]]
    assert auth.kind == "basic" and auth.username == "user" and auth.realm == "x"


def test_collapse_auth_handshakes_leaves_ordinary_traffic_untouched():
    flows = [mk(fid="1", resp_headers=HTML), mk(fid="2", url="https://site.example/a", status=302, resp_headers=[("Location", "/b")], body=b""),
             mk(fid="3", url="https://site.example/b", resp_headers=HTML)]
    groups, auth = filters.collapse_auth_handshakes(flows)
    assert [[f.id for f in g] for g in groups] == [["1"], ["2"], ["3"]] and auth is None
    # redirect collapsing still works on the representatives
    assert [[f.id for f in g] for g in filters.collapse_redirects([g[-1] for g in groups])] == [["1"], ["2", "3"]]


def test_www_authenticate_continuation_across_items():
    challenges = filters.parse_www_authenticate(['Digest realm="r"', 'nonce="n", opaque="o"', "NTLM"])
    assert challenges == [("digest", {"realm": "r", "nonce": "n", "opaque": "o"}, ""), ("ntlm", {}, "")]
    assert filters.SESSION_AUTH_SCHEMES == {"ntlm", "negotiate", "basic", "digest"}
    assert "collapse_auth_handshakes" in filters.__all__ and "normalise_flow_id" in filters.__all__


# ===== former tests/test_loops.py: loop folding (former reqrec/loops.py) =====
# Tests for the loops section of reqrec.analysis (DESIGN.md §6).

def loops_mk(url, method="GET", headers=(), body=None, fid=None, started_at=1700000000.0):
    fid = fid or f"f{abs(hash(url + method + str(body))) % 10000:04d}"
    return Flow(fid, RecordedRequest(method, url, [("User-Agent", "UA")] + list(headers), body),
                RecordedResponse(200, JSON, b"{}"), started_at=started_at)


def groups(*flows):
    return [[f] for f in flows]


def test_query_pagination_numeric_range():
    gs = groups(*(loops_mk(f"https://s/api/items?sort=id&page={p}", headers=[("Referer", f"https://s/p{p}")]) for p in (1, 2, 3, 4)))
    loops = detect_loops(gs, PlanOptions())
    assert len(loops) == 1
    lg = loops[0]
    assert lg.location == "query" and lg.name == "page"
    assert lg.values == ["1", "2", "3", "4"]
    assert lg.numeric_range == (1, 4)
    assert lg.groups == gs
    assert lg.occurrence == 0


def test_descending_and_non_consecutive_and_zero_padded():
    desc = detect_loops(groups(*(loops_mk(f"https://s/x?page={p}") for p in (3, 2, 1))), PlanOptions())
    assert desc[0].numeric_range == (3, 1)
    skip = detect_loops(groups(*(loops_mk(f"https://s/x?offset={p}") for p in (0, 20, 40))), PlanOptions())
    assert skip[0].numeric_range is None and skip[0].values == ["0", "20", "40"]
    padded = detect_loops(groups(*(loops_mk(f"https://s/x?page={p}") for p in ("01", "02", "03"))), PlanOptions())
    assert padded[0].numeric_range is None


def test_needs_three_consecutive_groups():
    assert detect_loops(groups(loops_mk("https://s/x?page=1"), loops_mk("https://s/x?page=2")), PlanOptions()) == []
    gs = groups(loops_mk("https://s/x?page=1"), loops_mk("https://s/x?page=2"), loops_mk("https://s/other"), loops_mk("https://s/x?page=3"))
    assert detect_loops(gs, PlanOptions()) == []


def test_two_differing_values_is_not_a_loop():
    gs = groups(*(loops_mk(f"https://s/x?page={p}&nonce=n{p}") for p in (1, 2, 3)))
    assert detect_loops(gs, PlanOptions()) == []


def test_timestamp_cache_buster_is_ignored():
    gs = groups(*(loops_mk(f"https://s/x?page={p}&_=17000000001{p:02d}") for p in (1, 2, 3)))
    loops = detect_loops(gs, PlanOptions())
    assert len(loops) == 1 and loops[0].name == "page"


def test_identical_requests_are_not_a_loop():
    gs = groups(*(loops_mk("https://s/poll?x=1") for _ in range(3)))
    assert detect_loops(gs, PlanOptions()) == []


def test_differing_headers_break_the_loop_but_referer_is_ignored():
    gs = groups(*(loops_mk(f"https://s/x?page={p}", headers=[("X-Request-Id", f"r{p}")]) for p in (1, 2, 3)))
    assert detect_loops(gs, PlanOptions()) == []
    gs = groups(*(loops_mk(f"https://s/x?page={p}", headers=[("Referer", f"https://s/{p}")]) for p in (1, 2, 3)))
    assert len(detect_loops(gs, PlanOptions())) == 1


def test_form_and_json_and_path_loops():
    form = [("Content-Type", "application/x-www-form-urlencoded")]
    gs = groups(*(loops_mk("https://s/search", "POST", form, f"q=abc&page={p}".encode()) for p in (1, 2, 3)))
    (lg,) = detect_loops(gs, PlanOptions())
    assert (lg.location, lg.name, lg.values) == ("form", "page", ["1", "2", "3"])

    gs = groups(*(loops_mk("https://s/graphql", "POST", JSON, json.dumps({"q": "x", "vars": {"page": p}}).encode()) for p in (1, 2, 3)))
    (lg,) = detect_loops(gs, PlanOptions())
    assert (lg.location, lg.name, lg.values, lg.numeric_range) == ("json", "vars.page", ["1", "2", "3"], (1, 3))

    gs = groups(*(loops_mk(f"https://s/list/page/{p}") for p in (1, 2, 3)))
    (lg,) = detect_loops(gs, PlanOptions())
    assert (lg.location, lg.name, lg.numeric_range) == ("path", "2", (1, 3))


def test_different_segment_count_or_method_breaks():
    gs = groups(loops_mk("https://s/list/1"), loops_mk("https://s/list/2"), loops_mk("https://s/list/3/x"))
    assert detect_loops(gs, PlanOptions()) == []
    gs = groups(loops_mk("https://s/x?p=1"), loops_mk("https://s/x?p=2"), loops_mk("https://s/x?p=3", method="POST"))
    assert detect_loops(gs, PlanOptions()) == []


def test_repeated_param_names_use_occurrence():
    gs = groups(*(loops_mk(f"https://s/x?id=5&id={p}") for p in (7, 8, 9)))
    (lg,) = detect_loops(gs, PlanOptions())
    assert lg.name == "id" and lg.occurrence == 1 and lg.values == ["7", "8", "9"]


def test_loop_uses_first_flow_of_redirect_chains_and_continues_after():
    chain = lambda p: [loops_mk(f"https://s/x?page={p}"), loops_mk(f"https://s/landing?page={p}")]  # noqa: E731
    gs = [chain(1), chain(2), chain(3), [loops_mk("https://s/end")], [loops_mk("https://s/y?page=1")], [loops_mk("https://s/y?page=2")], [loops_mk("https://s/y?page=3")]]
    loops = detect_loops(gs, PlanOptions())
    assert len(loops) == 2
    assert loops[0].groups == gs[:3] and loops[1].groups == gs[4:]


def test_multipart_variation_is_not_a_loop_and_empty_input():
    assert detect_loops([], PlanOptions()) == []
    ct = [("Content-Type", "multipart/form-data; boundary=B")]
    body = lambda p: f"--B\r\nContent-Disposition: form-data; name=\"page\"\r\n\r\n{p}\r\n--B--\r\n".encode()  # noqa: E731
    gs = groups(*(loops_mk("https://s/up", "POST", ct, body(p)) for p in (1, 2, 3)))
    assert detect_loops(gs, PlanOptions()) == []


def test_hash_like_values_are_not_folded():
    # cursor pagination: each cursor comes from the previous response, folding would lose that
    gs = groups(*(loops_mk(f"https://s/x?cursor={c}") for c in ("a1b2c3d4e5f6g7h8", "b2c3d4e5f6g7h8i9", "c3d4e5f6g7h8i9j0")))
    assert detect_loops(gs, PlanOptions()) == []
    gs = groups(*(loops_mk(f"https://s/items/{c}") for c in ("550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001", "550e8400-e29b-41d4-a716-446655440002")))
    assert detect_loops(gs, PlanOptions()) == []
    # word-like path values still fold
    gs = groups(*(loops_mk(f"https://s/cat/{c}") for c in ("books", "music", "games")))
    (lg,) = detect_loops(gs, PlanOptions())
    assert lg.values == ["books", "music", "games"] and lg.numeric_range is None


# ===== former tests/test_deps.py: dependency tracing (former reqrec/deps.py) =====
# Tests for the deps section of reqrec.analysis (DESIGN.md §5).

HTML_CT = [("Content-Type", "text/html; charset=utf-8")]
JSON_CT = [("Content-Type", "application/json")]


def resp_flow(body, headers=HTML_CT, status=200, url="https://s/page", fid="src"):
    return Flow(fid, RecordedRequest("GET", url), RecordedResponse(status, list(headers), body))


def req_flow(method="GET", url="https://s/x", headers=(), body=None):
    return Flow("req", RecordedRequest(method, url, list(headers), body))


def apply(ext: deps.Extractor, flow: Flow):
    """Re-extract ``ext`` from ``flow`` the way the generated script would (sanity check)."""
    resp = flow.response
    text = resp.text() or ""
    if ext.kind == "regex":
        return re.search(ext.pattern, text).group(1)
    if ext.kind == "json":
        node = json.loads(text)
        for p in ext.path:
            node = node[p]
        return node
    if ext.kind == "header":
        return resp.header(ext.name)
    soup = BeautifulSoup(text, "html.parser")
    if ext.kind == "html_input":
        return soup.find("input", {"name": ext.name})["value"]
    if ext.kind == "html_meta":
        return soup.find("meta", {"name": ext.name})["content"]
    if ext.kind == "html_attr":
        val = soup.select_one(ext.selector)[ext.attr]
        return re.search(ext.pattern, val).group(1) if ext.pattern else val
    if ext.kind == "html_text":
        val = soup.select_one(ext.selector).get_text(strip=True)
        return re.search(ext.pattern, val).group(1) if ext.pattern else val
    raise AssertionError(ext.kind)


def check(ext, flow, value):
    assert ext is not None
    assert ext.var == ""
    if ext.pattern:
        assert re.compile(ext.pattern).groups == 1
    assert str(apply(ext, flow)) == value
    return ext


# --------------------------------------------------------------------------- candidates

class TestCandidates:
    def test_query_form_path_and_filters(self):
        f = req_flow("POST", "https://s/orgs/7701/items/x?q=hello&tok=ABCDEF1&t=true&n=1234&e=",
                     [("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")], b"a=longvalue&b=json&c=%E3%81%82%E3%81%84%E3%81%86%E3%81%88")
        cands = deps.find_candidates(f, PlanOptions())
        got = {(c.location, c.name): c.value for c in cands}
        assert got == {("path", "1"): "7701", ("query", "tok"): "ABCDEF1", ("query", "n"): "1234",
                       ("form", "a"): "longvalue", ("form", "c"): "あいうえ"}
        # "hello" / "true" / "json" / "items" (short alphabetic words), "orgs", "x", "" are skipped
        assert deps.find_candidates(f, PlanOptions(min_value_length=8))[-1].value == "longvalue"

    def test_json_leaves_with_paths_and_numeric(self):
        body = json.dumps({"user": {"id": 1234, "ok": True, "none": None, "f": 2.5}, "tags": ["short", "longtag12"]}).encode()
        f = req_flow("POST", "https://s/api", JSON_CT, body)
        cands = {c.name: c for c in deps.find_candidates(f, PlanOptions())}
        assert set(cands) == {"user.id", "tags[1]"}
        assert cands["user.id"].json_path == ["user", "id"] and cands["user.id"].numeric is True
        assert cands["tags[1]"].json_path == ["tags", 1] and cands["tags[1]"].value == "longtag12"
        # 2.5 is too short, booleans/null are never candidates
        assert deps.find_candidates(f, PlanOptions(min_value_length=1)) and all(
            c.value not in ("True", "None") for c in deps.find_candidates(f, PlanOptions(min_value_length=1)))

    def test_json_without_content_type_is_sniffed(self):
        f = req_flow("POST", "https://s/api", [], b'{"token": "abcd1234"}')
        assert [(c.location, c.name, c.value) for c in deps.find_candidates(f, PlanOptions())] == [("json", "token", "abcd1234")]

    def test_headers_with_exclusions_and_bearer_prefix(self):
        f = req_flow(headers=[("Authorization", "Bearer TOKEN123456"), ("X-CSRF-Token", "csrf1234"), ("Accept", "application/json"),
                              ("User-Agent", "Mozilla/5.0"), ("Cookie", "a=verylongcookievalue"), ("Sec-Fetch-Mode", "cors"),
                              ("Referer", "https://s/long/path"), ("Origin", "https://s"), ("X-Requested-With", "XMLHttpRequest"),
                              ("Content-Type", "application/json"), (":authority", "s"), ("Cache-Control", "no-cache"), ("X-Api-Key", "KEY-0001")])
        cands = {c.name: c for c in deps.find_candidates(f, PlanOptions())}
        assert set(cands) == {"authorization", "x-csrf-token", "x-api-key"}
        assert cands["authorization"].value == "TOKEN123456" and cands["authorization"].prefix == "Bearer "
        assert cands["x-csrf-token"].prefix == ""

    @pytest.mark.parametrize("value", [
        "Basic dXNlcjpwYXNz", "basic dXNlcjpwYXNz", "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
        "Negotiate YIIGxwYGKwYBBQUCoIIGuzCCBregMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYKKwYBBAGCNwICHgYKKwYBBAGCNwICCqKCBoEEggZ9",
        'Digest username="taro", realm="intra", nonce="abc", uri="/", response="0123456789abcdef"',
    ])
    def test_session_auth_schemes_are_not_candidates(self, value):
        """DESIGN.md §13.2: NTLM / Negotiate / Basic / Digest credentials are configured through
        ``session.auth``; they are never traced to an earlier response."""
        f = req_flow(headers=[("Authorization", value), ("X-Token", "tok12345")])
        assert [c.name for c in deps.find_candidates(f, PlanOptions())] == ["x-token"]
        assert deps.is_session_auth_header(value) is True
        # the unfiltered view still exposes scheme prefix and token (the plan section counts repeated tokens with it)
        (auth, _x) = deps.header_candidates(f, skip_session_auth=False)
        prefix, token = deps.split_auth_header(value)
        assert (auth.prefix, auth.value) == (prefix, token) and prefix.strip().lower() in deps.SESSION_AUTH_SCHEMES

    def test_bearer_token_header_is_still_a_candidate(self):
        f = req_flow(headers=[("Authorization", "Bearer TOKEN123456"), ("Authorization", "Token abcdef0123"),
                              ("Authorization", "JWT eyJhbGciOiJIUzI1NiJ9.e30.x"), ("Authorization", "Basic dXNlcjpwYXNz")])
        cands = deps.find_candidates(f, PlanOptions())
        assert [(c.prefix, c.value) for c in cands] == [
            ("Bearer ", "TOKEN123456"), ("Token ", "abcdef0123"), ("JWT ", "eyJhbGciOiJIUzI1NiJ9.e30.x"),
        ]
        assert deps.is_session_auth_header("Bearer TOKEN123456") is False
        assert deps.split_auth_header("  Bearer   TOKEN123456 ") == ("Bearer   ", "TOKEN123456")
        assert deps.split_auth_header("customscheme xyz") == ("", "customscheme xyz")
        assert deps.split_auth_header(None) == ("", "") and deps.is_session_auth_header("") is False

    def test_multipart_text_fields_only(self):
        body = (b"------WebKitFormBoundaryAbC\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nmy title 1\r\n"
                b"------WebKitFormBoundaryAbC\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n"
                b"Content-Type: application/octet-stream\r\n\r\n\x00\x01\x02binarybytes\r\n------WebKitFormBoundaryAbC--\r\n")
        f = req_flow("POST", "https://s/upload", [("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryAbC")], body)
        cands = deps.find_candidates(f, PlanOptions())
        assert [(c.location, c.name, c.value) for c in cands] == [("multipart", "title", "my title 1")]
        kind, fields = deps.classify_body(f.request)
        assert kind == "multipart" and fields[1].is_file and fields[1].filename == "a.bin"
        assert fields[1].content == b"\x00\x01\x02binarybytes" and fields[1].content_type == "application/octet-stream"

    def test_multipart_garbage_does_not_crash(self):
        assert deps.parse_multipart(b"not multipart at all", "multipart/form-data; boundary=zzz") == []
        assert deps.parse_multipart(b"", "multipart/form-data") == []
        assert deps.parse_multipart(None, None) == []
        # boundary sniffed from the body when the header lacks it
        body = b"--XX\r\nContent-Disposition: form-data; name=a\r\n\r\n1\r\n--XX--"
        assert [(p.name, p.content) for p in deps.parse_multipart(body, "multipart/form-data")] == [("a", b"1")]

    def test_classify_body_kinds(self):
        assert deps.classify_body(RecordedRequest("GET", "https://s/"))[0] == "none"
        assert deps.classify_body(RecordedRequest("POST", "https://s/", [], b""))[0] == "none"
        assert deps.classify_body(RecordedRequest("POST", "https://s/", [("Content-Type", "application/json")], b"not json"))[0] == "raw"
        assert deps.classify_body(RecordedRequest("POST", "https://s/", [("Content-Type", "text/plain")], b"[1, 2]"))[0] == "json"
        assert deps.classify_body(RecordedRequest("POST", "https://s/", [], b"\x00\x01\x02\xff"))[0] == "raw"
        assert deps.classify_body(RecordedRequest("POST", "https://s/", [("Content-Type", "application/octet-stream")], b"\xff\xfe"))[0] == "raw"

    def test_non_utf8_bodies_do_not_crash(self):
        f = req_flow("POST", "https://s/", [("Content-Type", "application/x-www-form-urlencoded")], b"a=\xff\xfe\x80zzz&b=1")
        assert deps.find_candidates(f, PlanOptions(min_value_length=1))
        bad = req_flow("POST", "https://s/", [("Content-Type", "application/json; charset=shift_jis")], b"{\"k\": \"\x82\xa0\x82\xa2\x82\xa4\x82\xa6\"}")
        assert deps.find_candidates(bad, PlanOptions())[0].value == "あいうえ"


# --------------------------------------------------------------------------- is_dynamic_looking

@pytest.mark.parametrize("value", [
    "8f3a9c2d1e4b5a6f7a8b", "CSRFhidden123456", "550e8400-e29b-41d4-a716-446655440000",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc", "AbCdEfGhIjKlMnOp+/==", "a1b2c3d4e5f6", "Zx9Qw2Er5Ty8Ui1Op4As7Df",
])
def test_dynamic_positive(value):
    assert deps.is_dynamic_looking(value) is True


@pytest.mark.parametrize("value", [
    "application/json", "text/html; charset=utf-8", "hello_world_thing", "2024-01-01", "2024-01-01T10:00:00Z",
    "https://example.com/path?x=1", "/api/v2/users/list", "1234567890123", "v1.2.3", "user@example.com",
    "www.example.com", "created_at_desc", "short", "XMLHttpRequest", "item-2", "Mozilla/5.0 (X11; Linux)", "",
])
def test_dynamic_negative(value):
    assert deps.is_dynamic_looking(value) is False


# --------------------------------------------------------------------------- locate_value

PAGE = b"""<!doctype html><html><head>
<meta charset="utf-8"><meta name="csrf-token" content="METAcsrfTOKEN001">
<meta property="og:url" content="https://s/p/OGID9988">
</head><body>
<form id="login" action="/login?sig=FORMSIG7777"><input type="hidden" name="_token" value="HIDDENabc123XYZ">
<input type="radio" name="color" value="red7777"><input type="radio" name="color" value="blue8888"></form>
<a class="btn btn-logout" href="/logout?token=LINKtok987&amp;x=1">logout</a>
<a class="btn" href="/u/USERNAMEzz">me</a><a class="btn" href="/x">x</a>
<span data-role="uid">USER77id</span>
<div id="profile"><span>Welcome: name_9f8e7d6c</span></div>
<div id="TOK99887766">keyed-on-value</div>
<ul><li class="item">AAAAAAAA1</li><li class="item">BBBBBBBB2</li></ul>
<div data-token="DATATOKEN5555" data-widget="main"></div>
<script>window.API_TOKEN="SCRIPTtok555AAA";window.UID="12345";
var cfg = {"nonce":"NONCEval0000", "dup":"DUPval99"}; var other="DUPval99";</script>
</body></html>"""


class TestLocateHtml:
    flow = resp_flow(PAGE)

    def test_hidden_input(self):
        ext = check(deps.locate_value("HIDDENabc123XYZ", self.flow), self.flow, "HIDDENabc123XYZ")
        assert (ext.kind, ext.name) == ("html_input", "_token")

    def test_radio_second_value_not_html_input(self):
        ext = check(deps.locate_value("blue8888", self.flow), self.flow, "blue8888")
        assert ext.kind != "html_input"  # soup.find("input", name=color) would return the first radio

    def test_meta_name(self):
        ext = check(deps.locate_value("METAcsrfTOKEN001", self.flow), self.flow, "METAcsrfTOKEN001")
        assert (ext.kind, ext.name) == ("html_meta", "csrf-token")

    def test_meta_property_via_attr_pattern(self):
        ext = check(deps.locate_value("OGID9988", self.flow), self.flow, "OGID9988")
        assert ext.kind == "html_attr" and ext.selector == 'meta[property="og:url"]' and ext.attr == "content"
        assert ext.pattern and "OGID9988" not in ext.pattern

    def test_href_substring_with_pattern(self):
        ext = check(deps.locate_value("LINKtok987", self.flow), self.flow, "LINKtok987")
        assert ext.kind == "html_attr" and ext.attr == "href" and ext.selector == "a.btn.btn-logout"
        assert "LINKtok987" not in ext.pattern

    def test_form_action_located_by_id(self):
        ext = check(deps.locate_value("FORMSIG7777", self.flow), self.flow, "FORMSIG7777")
        assert ext.kind == "html_attr" and ext.selector == "#login" and ext.attr == "action"

    def test_text_exact_by_data_attribute(self):
        ext = check(deps.locate_value("USER77id", self.flow), self.flow, "USER77id")
        assert (ext.kind, ext.selector) == ("html_text", 'span[data-role="uid"]')

    def test_text_substring_in_descendant_of_id(self):
        ext = check(deps.locate_value("name_9f8e7d6c", self.flow), self.flow, "name_9f8e7d6c")
        assert ext.kind == "html_text" and ext.selector == "#profile span" and ext.pattern

    def test_never_keyed_on_the_value_itself(self):
        # the only locator for this div would be its id == the value -> fall back to regex
        ext = check(deps.locate_value("TOK99887766", self.flow), self.flow, "TOK99887766")
        assert ext.kind == "regex" and "TOK99887766" not in ext.pattern
        for value in ("HIDDENabc123XYZ", "LINKtok987", "USER77id", "DATATOKEN5555", "BBBBBBBB2"):
            ext = deps.locate_value(value, self.flow)
            for field in (ext.selector, ext.pattern, ext.name):
                assert not field or value not in field

    def test_data_attribute_value_located_by_other_data_attr(self):
        ext = check(deps.locate_value("DATATOKEN5555", self.flow), self.flow, "DATATOKEN5555")
        assert ext.kind == "html_attr" and ext.selector == 'div[data-widget="main"]' and ext.attr == "data-token"

    def test_non_unique_class_falls_back_to_regex(self):
        ext = check(deps.locate_value("BBBBBBBB2", self.flow), self.flow, "BBBBBBBB2")
        assert ext.kind == "regex"

    def test_inline_script_regex(self):
        ext = check(deps.locate_value("SCRIPTtok555AAA", self.flow), self.flow, "SCRIPTtok555AAA")
        assert ext.kind == "regex" and 'API_TOKEN="' in ext.pattern.replace("\\", "")
        assert "12345" not in ext.pattern  # short suffix: neighbouring dynamic values are not baked in
        ext2 = check(deps.locate_value("NONCEval0000", self.flow), self.flow, "NONCEval0000")
        assert ext2.kind == "regex"

    def test_regex_verified_against_duplicates(self):
        ext = check(deps.locate_value("DUPval99", self.flow), self.flow, "DUPval99")
        assert re.search(ext.pattern, self.flow.response.text()).group(1) == "DUPval99"

    def test_missing_value(self):
        assert deps.locate_value("notthere12345", self.flow) is None
        assert deps.locate_value("", self.flow) is None

    def test_html_escaped_variant(self):
        # the request sends a&b; the page has it HTML-escaped inside an attribute
        page = b'<html><body><input name="q" value="a&amp;b12345"><a id="lnk" href="/s?v=x&amp;y&amp;z12">l</a></body></html>'
        f = resp_flow(page)
        ext = deps.locate_value("a&b12345", f)
        assert ext.kind == "html_input" and ext.name == "q"

    def test_html_sniffed_without_content_type(self):
        f = resp_flow(b"<html><body><input name='k' value='sniffed1234'></body></html>", headers=[])
        assert deps.locate_value("sniffed1234", f).kind == "html_input"


class TestLocateJsonAndText:
    def test_json_leaf_paths(self):
        body = json.dumps({"data": {"access_token": "JWTabc.def.ghi", "id": 7701, "items": [{"id": 5}, {"id": 9900}], "f": 1.5}}).encode()
        f = resp_flow(body, JSON_CT)
        ext = check(deps.locate_value("JWTabc.def.ghi", f), f, "JWTabc.def.ghi")
        assert (ext.kind, ext.path, ext.name) == ("json", ["data", "access_token"], "data.access_token")
        assert check(deps.locate_value("7701", f), f, "7701").path == ["data", "id"]
        assert check(deps.locate_value("9900", f), f, "9900").path == ["data", "items", 1, "id"]
        assert check(deps.locate_value("1.5", f), f, "1.5").path == ["data", "f"]
        assert deps.locate_value("true", f) is None

    def test_json_in_text_plain_and_substring_regex(self):
        body = b'{"redirect": "https://s/cb?code=CODE1234567&st=1", "u": "a\\/b\\/CODE999"}'
        f = resp_flow(body, [("Content-Type", "text/plain")])
        ext = check(deps.locate_value("CODE1234567", f), f, "CODE1234567")
        assert ext.kind == "regex"
        # the parsed JSON leaf (unescaped) is preferred over a regex on the escaped text
        ext2 = check(deps.locate_value("a/b/CODE999", f), f, "a/b/CODE999")
        assert ext2.kind == "json" and ext2.path == ["u"] and ext2.sample == "a/b/CODE999"
        # a JSON-escaped spelling inside non-JSON text is reported through ``sample``
        g = resp_flow(b"var u = 'x\\/y\\/CODE999z';", [("Content-Type", "text/plain")])
        ext3 = deps.locate_value("x/y/CODE999z", g)
        assert ext3 is not None and ext3.kind == "regex" and ext3.sample == "x\\/y\\/CODE999z"

    def test_plain_text_regex_with_line_boundaries(self):
        body = b"id: 1\ntoken: TEXTtoken0001\nother: TEXTtoken0002\n"
        f = resp_flow(body, [("Content-Type", "text/plain")])
        ext = check(deps.locate_value("TEXTtoken0002", f), f, "TEXTtoken0002")
        assert ext.kind == "regex" and "\\n" not in ext.pattern

    def test_regex_skipped_for_values_with_quotes_or_whitespace(self):
        f = resp_flow(b"x = 'has space value'; y = 'q\"uote'", [("Content-Type", "text/plain")])
        assert deps.locate_value("has space value", f) is None
        assert deps.locate_value('q"uote', f) is None

    def test_binary_and_missing_response(self):
        f = resp_flow(b"\x00\x01\x02ABCDEFGH1234\xff", [("Content-Type", "application/octet-stream")])
        assert deps.locate_value("ABCDEFGH1234", f) is None
        png = resp_flow(b"\x89PNG\r\n\x1a\nABCDEFGH1234", [("Content-Type", "image/png")])
        assert deps.locate_value("ABCDEFGH1234", png) is None
        assert deps.locate_value("x", Flow("f", RecordedRequest("GET", "https://s/"), None)) is None
        empty = resp_flow(None, HTML_CT)
        assert deps.locate_value("abcd", empty) is None

    def test_bad_encoding_does_not_crash(self):
        f = resp_flow(b"<html>\xff\xfe<input name='a' value='GOOD12345'>\x80\x81</html>", [("Content-Type", "text/html; charset=nonsense")])
        assert deps.locate_value("GOOD12345", f).kind == "html_input"

    def test_huge_body(self):
        big = b"<html><body>" + b"<p>filler</p>" * 300000 + b"<input name='t' value='BIGtoken0001'></body></html>"
        f = resp_flow(big)
        ext = deps.locate_value("BIGtoken0001", f)
        assert ext is not None and ext.kind == "regex"  # too large for a soup, regex still works


class TestLocateHeadersAndUrl:
    def test_response_header(self):
        f = resp_flow(b"{}", JSON_CT + [("X-CSRF-Token", "HDRtoken0001"), ("Date", "HDRtoken0002")])
        ext = check(deps.locate_value("HDRtoken0001", f), f, "HDRtoken0001")
        assert (ext.kind, ext.name) == ("header", "X-CSRF-Token")
        assert deps.locate_value("HDRtoken0002", f) is None  # Date is never a dependency

    def test_location_on_201_is_a_header_but_on_302_is_url(self):
        created = resp_flow(b"", JSON_CT + [("Location", "/items/NEW12345")], status=201)
        assert deps.locate_value("/items/NEW12345", created).kind == "header"
        redir = Flow("r", RecordedRequest("GET", "https://s/auth"), RecordedResponse(302, [("Location", "/cb?code=CODE12345&state=st")], b""))
        ext = deps.locate_value("CODE12345", redir)
        assert ext.kind == "url"
        m = re.search(ext.pattern, "https://s/cb?code=CODE12345&state=st")
        assert m.group(1) == "CODE12345" and "CODE12345" not in ext.pattern
        whole = deps.locate_value("/cb?code=CODE12345&state=st", redir)
        assert whole.kind == "url" and re.search(whole.pattern, "https://s/cb?code=CODE12345&state=st").group(1) == "/cb?code=CODE12345&state=st"

    def test_locate_value_kinds_restriction(self):
        f = resp_flow(b'<html><input name="a" value="VAL1234567"></html>', HTML_CT + [("X-T", "VAL1234567")])
        assert deps.locate_value("VAL1234567", f).kind == "header"
        assert deps.locate_value_kinds("VAL1234567", f, frozenset({"html_input"})).kind == "html_input"
        assert deps.locate_value_kinds("VAL1234567", f, frozenset({"url"})) is None


# --------------------------------------------------------------------------- cookies

def test_find_cookie_latest_first_and_variants():
    def cookie_name(value, flows):
        hit = deps.find_cookie(value, flows)
        return hit[0] if hit else None

    f1 = resp_flow(b"", HTML_CT + [("Set-Cookie", "sess=OLD123; Path=/"), ("Set-Cookie", "XSRF-TOKEN=abc%3D%3Dxyz; Path=/")])
    f2 = resp_flow(b"", HTML_CT + [("Set-Cookie", "sess=NEW456; Path=/; HttpOnly"), ("Set-Cookie", "gone=deleted; Max-Age=0")])
    assert cookie_name("NEW456", [f1, f2]) == "sess"
    assert cookie_name("OLD123", [f1, f2]) == "sess"
    assert cookie_name("abc==xyz", [f1, f2]) == "XSRF-TOKEN"  # URL-decoded header vs encoded cookie
    assert cookie_name("abc%3D%3Dxyz", [f1, f2]) == "XSRF-TOKEN"
    assert deps.find_cookie("abc==xyz", [f1, f2]) == ("XSRF-TOKEN", "abc%3D%3Dxyz")
    assert cookie_name("deleted", [f1, f2]) is None
    assert cookie_name("nothing", [f1, f2]) is None
    assert cookie_name("x", []) is None
    assert cookie_name("x", [Flow("n", RecordedRequest("GET", "https://s/"), None)]) is None


# --------------------------------------------------------------------------- build_pattern

def test_build_pattern_properties():
    text = 'a="FIRST1234"; b="SECOND5678"; c="FIRST1234"'
    p = deps.build_pattern(text, "SECOND5678")
    assert re.compile(p).groups == 1 and re.search(p, text).group(1) == "SECOND5678"
    assert deps.build_pattern(text, "missing") is None
    assert deps.build_pattern(text, 'has"quote') is None
    assert deps.build_pattern("", "x") is None
    assert deps.build_pattern("value", "value") == '(?m)^([^"\'&<>\\s]+)$'
    url = "https://s/cb?code=C0DE&state=s"
    p = deps.build_pattern(url, "C0DE")
    assert re.search(p, url).group(1) == "C0DE" and re.search(p, "https://s/cb?code=OTHER&state=s").group(1) == "OTHER"


def test_json_helpers():
    assert deps.json_dotted(["a", "b", 0, "c"]) == "a.b[0].c"
    assert deps.json_dotted([0, "x"]) == "[0].x"
    assert list(deps.json_leaves({"a": [1, {"b": None}]})) == [(["a", 0], 1), (["a", 1, "b"], None)]
    assert deps.parse_json_text("  {\"a\": 1}") == {"a": 1}
    assert deps.parse_json_text("42") is None and deps.parse_json_text("{bad") is None and deps.parse_json_text(None) is None


# --------------------------------------------------------------------------- short ids / pattern context

def test_numeric_path_segment_is_a_candidate_even_when_short():
    """``/orgs/77/items``: an id in the path is worth tracing although 77 < min_value_length."""
    f = req_flow("GET", "https://s/v1/orgs/77/items?page=1")
    cands = deps.find_candidates(f, PlanOptions())
    assert [(c.location, c.name, c.value) for c in cands] == [("path", "2", "77")]
    assert deps.is_numeric_path_id(deps.Candidate("path", "2", "77"))
    assert not deps.is_numeric_path_id(deps.Candidate("query", "page", "77"))  # only path segments
    assert not deps.is_numeric_path_id(deps.Candidate("path", "0", "v1"))


def test_build_pattern_drops_indentation_and_partial_words():
    # the 24-char context window would start inside "<script>": the partial word "ipt" is dropped
    text = '<html><body>\n    <script>window.API_TOKEN = "TOKEN123456";</script>\n</body></html>'
    p = deps.build_pattern(text, "TOKEN123456")
    assert p.startswith(re.escape('>window.API_TOKEN = "'))
    assert re.search(p, text).group(1) == "TOKEN123456"
    # indentation is not part of the pattern, so re-indented markup still matches
    indented = 'x\n        window.API_TOKEN = "TOKEN123456";\n'
    p2 = deps.build_pattern(indented, "TOKEN123456")
    assert p2.startswith(re.escape('window.API_TOKEN = "'))
    assert re.search(p2, 'window.API_TOKEN = "OTHER9";').group(1) == "OTHER9"
    # a prefix that is nothing but whitespace is kept (there is no better context)
    p3 = deps.build_pattern("a\n    TOKEN123456 b", "TOKEN123456")
    assert p3 and re.search(p3, "a\n    TOKEN123456 b").group(1) == "TOKEN123456"


# --------------------------------------------------------------------------- legacy-charset forms (DESIGN.md §13.4)

class TestFormBytes:
    CP932_BODY = b"__VIEWSTATE=dDwt%2BabC%3D%3D&ctl00%24txtKeyword=%93%FA%96%7B&ctl00%24btnSearch=%8C%9F%8D%F5&empty=&flag"

    def test_segments_and_pairs_line_up(self):
        segments = deps.split_form_segments(self.CP932_BODY)
        assert len(segments) == 5 and segments[-1] == b"flag"
        pairs = deps.form_pairs_bytes(self.CP932_BODY)
        assert pairs[0] == (b"__VIEWSTATE", b"dDwt+abC==")
        assert pairs[1] == (b"ctl00$txtKeyword", "日本".encode("cp932"))
        assert pairs[3] == (b"empty", b"") and pairs[4] == (b"flag", b"")
        assert deps.split_form_segments(b"") == [] and deps.split_form_segments(None) == []
        assert deps.split_form_segments(b"a=1&&b=2&") == [b"a=1", b"b=2"]

    def test_utf8_detection(self):
        assert deps.form_body_is_utf8(b"a=1&b=%E3%81%82&c=plain+text") is True
        assert deps.form_body_is_utf8(b"") is True and deps.form_body_is_utf8(None) is True
        assert deps.form_body_is_utf8(self.CP932_BODY) is False
        assert deps.form_body_is_utf8(b"%93%FA=1") is False  # the *name* is cp932
        assert deps.form_body_is_utf8(b"a=\xe3\x81\x82") is True  # raw UTF-8 bytes, not percent-encoded

    def test_parse_form_bytes_matches_util_parse_form_for_utf8(self):
        body = b"a=long+value&b=%E3%81%82%E3%81%84&c=&d&a=again&=noname"
        assert deps.parse_form_bytes(body) == deps.parse_form(body.decode("utf-8"))
        assert deps.parse_form_bytes(body)[1] == ("b", "あい")

    def test_parse_form_bytes_legacy_values_stay_percent_encoded_unless_charset_declared(self):
        pairs = dict(deps.parse_form_bytes(self.CP932_BODY))
        assert pairs["ctl00$txtKeyword"] == "%93%FA%96%7B" and pairs["ctl00$btnSearch"] == "%8C%9F%8D%F5"
        assert pairs["__VIEWSTATE"] == "dDwt+abC=="
        with_charset = dict(deps.parse_form_bytes(self.CP932_BODY, charset="cp932"))
        assert with_charset["ctl00$txtKeyword"] == "日本" and with_charset["ctl00$btnSearch"] == "検索"
        # unknown / wrong charset falls back gracefully
        assert dict(deps.parse_form_bytes(self.CP932_BODY, charset="no-such-charset"))["ctl00$txtKeyword"] == "%93%FA%96%7B"
        assert dict(deps.parse_form_bytes(b"a=\xff\xfe", charset="utf-8"))["a"] == "%FF%FE"

    def test_request_form_charset_and_classify_body(self):
        plain = RecordedRequest("POST", "https://s/", [("Content-Type", "application/x-www-form-urlencoded")], self.CP932_BODY)
        assert deps.request_form_charset(plain) is None
        kind, pairs = deps.classify_body(plain)
        assert kind == "form" and dict(pairs)["ctl00$txtKeyword"] == "%93%FA%96%7B"
        declared = RecordedRequest("POST", "https://s/", [("Content-Type", "application/x-www-form-urlencoded; charset=Shift_JIS")], self.CP932_BODY)
        assert deps.request_form_charset(declared) == "cp932"
        kind, pairs = deps.classify_body(declared)
        assert kind == "form" and dict(pairs)["ctl00$txtKeyword"] == "日本"
        cands = {c.name: c.value for c in deps.find_candidates(Flow("f", declared), PlanOptions())}
        assert cands["__VIEWSTATE"] == "dDwt+abC==" and "empty" not in cands


@pytest.mark.parametrize("value,expected", [
    ("%93%FA%96%7B", False),                 # cp932 日本 typed into a form: text, not a token
    ("%8C%9F%8D%F5", False),
    ("%E3%81%82%E3%81%84%E3%81%86", False),  # UTF-8 あいう
    ("abc%2Fdef%2Fghi", False),              # a path
    ("tok%3D8f3a9c2d1e4b5a6f7a8b", True),    # a token that happens to be percent-encoded
    ("100%25", False),
])
def test_dynamic_looking_judges_percent_encoded_values_on_their_decoded_text(value, expected):
    assert deps.is_dynamic_looking(value) is expected


# --------------------------------------------------------------------------- review 3: words vs random letters, route-like segments

IDENTIFIER_WORDS = [
    # acronym runs anywhere (start, middle, end) - names of ASP.NET controls, MVC actions, DOM APIs
    "txtTokuisakiCD", "ddlSeisanKBN", "hdnSearchKEY", "btnExportCSV", "CustomerIDList", "ProductionResultCSV",
    "OrderDateDESC", "DownloadAsPDF", "getXMLHttpRequest", "XMLHttpRequest", "HTMLDocument", "getElementById",
    "getElementsByTagName", "encodeURIComponent", "toLocaleDateString", "XMLHTTPRequest",
    # Japanese-system abbreviations (two-letter words) and separators
    "txtTokuisakiCd", "hdnShohinCdList", "TokuisakiNmKana", "txtJyuchuNoFrom", "SeisanSuKei",
    "Customer_ID_List", "export-production-CSV", "ProductionResultCSV.aspx", "getXMLHttpRequest.js",
]


@pytest.mark.parametrize("value", IDENTIFIER_WORDS)
def test_identifiers_with_acronyms_are_words(value):
    assert deps.looks_random_letters(value) is False
    assert deps.is_dynamic_looking(value) is False


@pytest.mark.parametrize("value", [
    "xBBHOHpXYZgFKyNZpuWy",       # the factory site's letters-only URL key
    "EThwGCKtUHzbgRcwocKJ",
    "xBBHOH-pXYZgFKyNZpuWy",      # base64url without digits: '-' / '_' separate judged parts
    "pXYZgFKy_NZpuWyxBBHOH",
    "xBBHOHpXYZgFKyNZpuWy.pdf",   # a random file name: judged by its stem
])
def test_random_letter_tokens_are_tokens(value):
    assert deps.looks_random_letters(value) is True
    assert deps.is_dynamic_looking(value) is True
    assert deps.is_route_like(value) is False


@pytest.mark.parametrize("value", ["QZVBNMWRTYPXSDFKHJ", "qzvbnmwrtypxsdfkhj", "short", "getX", "aBcD"])
def test_single_case_or_short_letters_are_not_judged_random(value):
    assert deps.looks_random_letters(value) is False


@pytest.mark.parametrize("value,expected", [
    ("Login.aspx", True), ("News.aspx", True), ("orders", True), ("export-csv", True), ("ProductionResultCSV", True),
    ("QZVBNMWRTYPXSDFKHJ", True),                       # all uppercase: a word for the regex, traced only exactly
    ("SC0010.aspx", True), ("KJ010Search.aspx", True), ("Menu01.aspx", True), ("WebForm1.aspx", True),
    ("KJ010SearchResult.aspx", True), ("SC0010Detail.ASPX", True), ("list.do", True), ("report2.php", True),
    ("xBBHOHpXYZgFKyNZpuWy", False), ("xBBHOHpXYZgFKyNZpuWy.aspx", False), ("xBBHOH-pXYZgFKyNZpuWy", False),
    ("a8F3kQ9zP2.aspx", False), ("aB3dEfGhIjKlMn.aspx", False), ("77", False), ("abc123def456", False),
    ("logo01.png", False), ("", False), ("jquery.min.js", True), ("xBBHOHpXYZgFKyNZpuWy.min.js", False),
])
def test_is_route_like(value, expected):
    assert deps.is_route_like(value) is expected


def test_route_like_path_segments_stay_candidates_but_are_flagged():
    """Regression: letters-only path segments used to be dropped, losing exact JSON / header traces."""
    f = req_flow("GET", "https://s/s/QZVBNMWRTYPXSDFKHJ/SC0010.aspx?key=xBBHOHpXYZgFKyNZpuWy")
    cands = {(c.location, c.name): c for c in deps.find_candidates(f, PlanOptions())}
    assert cands[("path", "1")].value == "QZVBNMWRTYPXSDFKHJ" and cands[("path", "2")].value == "SC0010.aspx"
    assert deps.is_structural_path_segment(cands[("path", "1")])
    assert deps.is_structural_path_segment(cands[("path", "2")])
    assert not deps.is_structural_path_segment(cands[("query", "key")])  # only path segments
    assert not deps.is_structural_path_segment(deps.Candidate("path", "0", "xBBHOHpXYZgFKyNZpuWy"))
    assert ("path", "0") not in cands  # "s": too short to be a candidate at all


def test_selectors_use_ids_with_acronyms():
    """``_attr_ok`` rejects dynamic-looking ids; ``lblTokuisakiCD`` must not count as one."""
    f = resp_flow(b'<html><body><span id="lblTokuisakiCD">TK-2026-0042</span><span>TK-2026-0042x</span>'
                  b'<a id="lnkExportCSV" href="/Export.aspx?t=EXPtok98765">x</a></body></html>')
    ext = check(deps.locate_value("TK-2026-0042", f), f, "TK-2026-0042")
    assert (ext.kind, ext.selector) == ("html_text", "#lblTokuisakiCD")
    ext = check(deps.locate_value("EXPtok98765", f), f, "EXPtok98765")
    assert (ext.kind, ext.selector, ext.attr) == ("html_attr", "#lnkExportCSV", "href")


# ===== former tests/test_plan.py: plan building (former reqrec/plan.py) =====
# Tests for the plan section of reqrec.analysis (DESIGN.md §7).

T0 = 1_700_000_000.0
BASE = [("User-Agent", "UA/1.0"), ("Accept-Language", "ja"), ("Accept-Encoding", "gzip"), ("Connection", "keep-alive")]
FORM = ("Content-Type", "application/x-www-form-urlencoded")


class Site:
    """Tiny helper that builds Flows quickly (ids and timestamps are sequential)."""

    def __init__(self, host="https://site.example"):
        self.host = host
        self.flows: list[Flow] = []

    def add(self, method, path, req_headers=(), body=None, status=200, resp_headers=HTML, resp_body=b"", rtype=None,
            no_response=False, base=True):
        url = path if path.startswith("http") else self.host + path
        headers = (list(BASE) if base else []) + list(req_headers)
        resp = None if no_response else RecordedResponse(status, list(resp_headers), resp_body)
        f = Flow(f"f{len(self.flows) + 1:04d}", RecordedRequest(method, url, headers, body), resp,
                 started_at=T0 + len(self.flows), resource_type=rtype)
        self.flows.append(f)
        return f

    def recording(self, **meta):
        return Recording(flows=list(self.flows), meta=meta or {"source": "test"})

    def plan(self, opts=None, **meta):
        return build_plan(self.recording(**meta), opts)


def hdr(step, name):
    return next(r for n, r in step.headers if n.lower() == name.lower())


def form(step, name):
    return dict(step.form)[name]


def params(step):
    return dict(step.params)


# --------------------------------------------------------------------------- scenarios

LOGIN_HTML = (b'<html><body><form method="post" action="/login"><input type="hidden" name="_token" value="CSRFhidden123456">'
              b'<input name="username"><input name="password"></form></body></html>')
DASH_HTML = (b'<html><head><meta name="csrf-token" content="METAcsrf7890"></head><body>'
             b'<a class="export" href="/api/export?token=LINKtok44556&amp;f=csv">x</a>'
             b'<script>window.API_TOKEN="APIt0k3n99887766";</script></body></html>')


def login_site():
    s = Site()
    s.add("GET", "/login", [("Accept", "text/html")], resp_headers=HTML + [("Set-Cookie", "sess=S3SS10N; Path=/; HttpOnly"),
                                                                           ("Set-Cookie", "XSRF-TOKEN=xsrf%3D%3Dabc; Path=/")], resp_body=LOGIN_HTML)
    s.add("POST", "/login", [("Accept", "text/html"), FORM, ("Cookie", "sess=S3SS10N"), ("Origin", "https://site.example")],
          body=b"_token=CSRFhidden123456&username=alice_w&password=Secr3tPass%21", status=302, resp_headers=[("Location", "/dashboard")])
    s.add("GET", "/dashboard", [("Accept", "text/html"), ("Cookie", "sess=S3SS10N")], resp_body=DASH_HTML)
    return s


def test_login_csrf_hidden_input_and_redirect_chain():
    plan = login_site().plan()
    assert [s.func_name for s in plan.steps] == ["step_01_get_login", "step_02_post_login"]
    get_login, post_login = plan.steps
    assert get_login.index == 1 and get_login.response_kind == "html" and get_login.expected_status == 200
    (ext,) = get_login.extractors
    assert (ext.kind, ext.name, ext.var, ext.sample) == ("html_input", "_token", "token", "CSRFhidden123456")
    assert "step 2" in ext.note
    assert form(post_login, "_token") == Ref.var("token")
    assert post_login.body_kind == "form"
    # collapsed chain: final response of the chain describes the step
    assert post_login.source_flow_ids == ["f0002", "f0003"]
    assert post_login.expected_status == 200 and post_login.response_kind == "html" and post_login.allow_redirects is True
    assert "redirect chain" in post_login.comment
    # content-type dropped for form bodies, cookie never emitted, base headers removed
    names = [n.lower() for n, _ in post_login.headers]
    assert "content-type" not in names and "cookie" not in names and "user-agent" not in names
    assert hdr(post_login, "Origin") == Ref.lit("https://site.example")


def test_password_secret_constant_and_literal_username():
    plan = login_site().plan()
    post_login = plan.steps[1]
    assert form(post_login, "username") == Ref.lit("alice_w")
    (pw,) = plan.constants
    assert pw.name == "PASSWORD" and pw.secret is True and pw.env_var == "REQREC_PASSWORD" and pw.value == "Secr3tPass!"
    assert form(post_login, "password") == Ref.var("PASSWORD")
    assert "step 2" in pw.comment
    assert any("REQREC_PASSWORD" in w for w in plan.warnings)
    # --no-redact keeps the literal
    plan2 = login_site().plan(PlanOptions(redact_secrets=False))
    assert form(plan2.steps[1], "password") == Ref.lit("Secr3tPass!") and plan2.constants == []


def test_username_repeated_in_two_requests_becomes_constant():
    s = login_site()
    s.add("POST", "/api/profile", [("Accept", "application/json"), ("Content-Type", "application/json")],
          body=json.dumps({"username": "alice_w", "display": "Alice W."}).encode(), resp_headers=JSON, resp_body=b'{"ok": true}')
    plan = s.plan()
    const = {c.name: c for c in plan.constants}
    assert set(const) == {"PASSWORD", "USERNAME"}
    assert const["USERNAME"].value == "alice_w" and const["USERNAME"].secret is False and const["USERNAME"].env_var is None
    assert "step 2" in const["USERNAME"].comment and "step 3" in const["USERNAME"].comment
    assert form(plan.steps[1], "username") == Ref.var("USERNAME")
    assert plan.steps[2].json_body == {"username": Ref.var("USERNAME"), "display": "Alice W."}


def test_meta_csrf_header_and_xsrf_cookie_header():
    s = login_site()
    s.add("GET", "/api/items?page=1", [("Accept", "application/json"), ("X-CSRF-Token", "METAcsrf7890"), ("X-XSRF-TOKEN", "xsrf==abc"),
                                        ("Cookie", "sess=S3SS10N; XSRF-TOKEN=xsrf%3D%3Dabc")], resp_headers=JSON, resp_body=b'{"items": []}')
    plan = s.plan()
    api = plan.steps[2]
    assert hdr(api, "X-CSRF-Token") == Ref.var("x_csrf_token")
    meta_ext = next(e for e in plan.steps[1].extractors if e.kind == "html_meta")
    assert meta_ext.name == "csrf-token" and meta_ext.var == "x_csrf_token"
    assert hdr(api, "X-XSRF-TOKEN") == Ref.expr('unquote(session.cookies.get("XSRF-TOKEN"))')
    assert hdr(api, "Accept") == Ref.lit("application/json")
    assert params(api) == {"page": Ref.lit("1")}
    assert api.response_kind == "json"


def test_plain_cookie_value_reference():
    s = login_site()
    s.add("GET", "/api/me?sid=S3SS10N", [("Accept", "application/json")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert params(plan.steps[2])["sid"] == Ref.expr('session.cookies.get("sess")')


def test_bearer_token_from_json_login_response():
    s = Site()
    s.add("POST", "/api/login", [("Content-Type", "application/json")], body=json.dumps({"user": "bob", "password": "pw123456"}).encode(),
          resp_headers=JSON, resp_body=json.dumps({"access_token": "ACC3SSt0ken.abc.def", "expires": 3600}).encode())
    s.add("GET", "/api/me", [("Authorization", "Bearer ACC3SSt0ken.abc.def"), ("Accept", "application/json")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    (ext,) = plan.steps[0].extractors
    assert (ext.kind, ext.path, ext.var) == ("json", ["access_token"], "access_token")
    assert hdr(plan.steps[1], "Authorization") == Ref.expr('"Bearer " + access_token')
    assert plan.steps[0].body_kind == "json" and plan.steps[0].json_body["password"] == Ref.var("PASSWORD")
    assert plan.steps[0].json_body["user"] == "bob"
    names = [n.lower() for n, _ in plan.steps[0].headers]
    assert "content-type" not in names


def test_untraced_bearer_token_becomes_secret_constant_with_prefix():
    s = Site()
    s.add("GET", "/api/me", [("Authorization", "Bearer STATICtoken0001")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    (const,) = plan.constants
    assert const.name == "AUTHORIZATION" and const.secret and const.env_var == "REQREC_AUTHORIZATION" and const.value == "STATICtoken0001"
    assert hdr(plan.steps[0], "Authorization") == Ref.expr('"Bearer " + AUTHORIZATION')
    plan2 = s.plan(PlanOptions(redact_secrets=False))
    assert hdr(plan2.steps[0], "Authorization") == Ref.lit("Bearer STATICtoken0001")


def test_inline_script_token_via_regex_and_href_token_via_attr_pattern():
    s = login_site()
    s.add("POST", "/api/items", [("Accept", "application/json"), ("Authorization", "Bearer APIt0k3n99887766"), ("Content-Type", "application/json")],
          body=b'{"name": "widget"}', status=201, resp_headers=JSON, resp_body=b'{"id": 1}')
    s.add("GET", "/api/export?token=LINKtok44556&f=csv", [("Accept", "text/csv")], resp_headers=[("Content-Type", "text/csv")], resp_body=b"a,b\n1,2\n")
    plan = s.plan()
    dash_exts = {e.kind: e for e in plan.steps[1].extractors}
    assert dash_exts["regex"].var == "api_token" and "APIt0k3n99887766" not in dash_exts["regex"].pattern
    assert hdr(plan.steps[2], "Authorization") == Ref.expr('"Bearer " + api_token')
    assert plan.steps[2].expected_status == 201
    href = dash_exts["html_attr"]
    assert href.selector == "a.export" and href.attr == "href" and href.pattern and "LINKtok44556" not in href.pattern
    assert params(plan.steps[3])["token"] == Ref.var(href.var) and href.var == "token_2"  # "token" taken by _token
    assert params(plan.steps[3])["f"] == Ref.lit("csv")
    assert plan.steps[3].response_kind == "text"


def test_path_segment_from_json_response_splits_url():
    s = Site()
    s.add("GET", "/api/orgs", [("Accept", "application/json")], resp_headers=JSON, resp_body=b'{"orgs": [{"id": 7701, "name": "acme"}]}')
    s.add("GET", "/api/orgs/7701/items?limit=50", [("Accept", "application/json")], resp_headers=JSON, resp_body=b"[]")
    plan = s.plan()
    (ext,) = plan.steps[0].extractors
    assert (ext.kind, ext.path, ext.var) == ("json", ["orgs", 0, "id"], "org_id")
    step = plan.steps[1]
    assert step.url == [Ref.lit("https://site.example/api/orgs/"), Ref.var("org_id"), Ref.lit("/items")]
    assert step.literal_url() is None
    assert step.func_name == "step_02_get_orgs_items"
    assert params(step)["limit"] == Ref.lit("50")


def test_url_percent_encoding_preserved_and_trailing_slash():
    s = Site()
    s.add("GET", "/api/ids", resp_headers=JSON, resp_body=b'{"id": "ID0001"}')
    s.add("GET", "/p/%E3%81%82/ID0001/", resp_headers=HTML, resp_body=b"<html></html>")
    plan = s.plan()
    # previous segment is not a word -> generic name path_seg_N
    assert plan.steps[1].url == [Ref.lit("https://site.example/p/%E3%81%82/"), Ref.var("path_seg_2"), Ref.lit("/")]


def test_pagination_loop_numeric_range():
    s = login_site()
    for page in (1, 2, 3):
        s.add("GET", f"/api/items?page={page}&_=1700000000{page:03d}", [("Accept", "application/json"), ("X-CSRF-Token", "METAcsrf7890"),
                                                                         ("Referer", f"https://site.example/dashboard?p={page}")],
              resp_headers=JSON, resp_body=json.dumps({"items": [{"id": 1000 + page}], "next": f"NEXTcursor{page}000"}).encode())
    s.add("GET", "/api/items/1003", [("Accept", "application/json"), ("X-CSRF-Token", "METAcsrf7890")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert len(plan.steps) == 4
    loop_step = plan.steps[2]
    assert loop_step.loop is not None
    assert loop_step.loop.var == "page" and loop_step.loop.values == ["1", "2", "3"] and loop_step.loop.numeric_range == (1, 3)
    assert params(loop_step)["page"] == Ref.var("page")
    assert params(loop_step)["_"] == Ref.expr("str(int(time.time()*1000))")
    assert loop_step.source_flow_ids == ["f0004", "f0005", "f0006"]
    assert hdr(loop_step, "X-CSRF-Token") == Ref.var("x_csrf_token")
    # the response of the looped step is the LAST iteration's: 1003 is traced to it
    (ext,) = loop_step.extractors
    assert ext.path == ["items", 0, "id"] and ext.sample == "1003"
    assert plan.steps[3].url == [Ref.lit("https://site.example/api/items/"), Ref.var(ext.var)]
    assert "x3" in loop_step.comment
    plan_noloop = s.plan(PlanOptions(detect_loops=False))
    assert len(plan_noloop.steps) == 6 and all(st.loop is None for st in plan_noloop.steps)


def test_timestamp_cache_buster_expr_in_first_step_and_json_numeric():
    s = Site()
    s.add("GET", "/api/x?_=1700000000123&t=1700000000", resp_headers=JSON, resp_body=b"{}")
    s.add("POST", "/api/y", [("Content-Type", "application/json")], body=b'{"ts": 1700000000456, "s": "1700000000"}', resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert params(plan.steps[0]) == {"_": Ref.expr("str(int(time.time()*1000))"), "t": Ref.expr("str(int(time.time()))")}
    assert plan.steps[1].json_body == {"ts": Ref.expr("int(time.time()*1000)"), "s": Ref.expr("str(int(time.time()))")}


def test_initial_cookies_only_for_kept_hosts_and_base_headers():
    s = Site()
    s.add("GET", "/a", [("Cookie", "theme=dark; sess=OLD"), ("Accept", "text/html")], resp_headers=HTML + [("Set-Cookie", "sess=NEW; Path=/")])
    s.add("GET", "https://tracker.doubleclick.net/pixel", [("Cookie", "IDE=trackme")], resp_headers=[("Content-Type", "image/gif")])
    s.add("GET", "/b", [("Cookie", "theme=dark; sess=NEW"), ("Accept", "application/json")], resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert [(c.name, c.value, c.domain) for c in plan.initial_cookies] == [("theme", "dark", "site.example"), ("sess", "OLD", "site.example")]
    assert plan.base_headers == [("User-Agent", "UA/1.0"), ("Accept-Language", "ja")]
    for step in plan.steps:
        names = [n.lower() for n, _ in step.headers]
        assert names == ["accept"]
    assert any("INITIAL_COOKIES" in w for w in plan.warnings)


def test_noise_dropped_with_reasons_and_meta():
    s = Site()
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/static/app.css", resp_headers=[("Content-Type", "text/css")], rtype="stylesheet")
    s.add("GET", "https://www.googletagmanager.com/gtm.js", resp_headers=[("Content-Type", "application/javascript")])
    s.add("OPTIONS", "/api", status=204)
    s.add("GET", "/api/data", resp_headers=JSON, resp_body=b"{}", no_response=True)
    s.add("GET", "/api/data", resp_headers=JSON, resp_body=b"{}")
    plan = s.plan(source="har", file="x.har")
    assert [(d.flow_id, d.reason) for d in plan.dropped] == [
        ("f0002", "static asset (resource type stylesheet)"),
        ("f0003", "tracker/analytics host"),
        ("f0004", "CORS preflight"),
        ("f0005", "no response recorded"),
    ]
    assert [st.source_flow_ids for st in plan.steps] == [["f0001"], ["f0006"]]
    assert plan.meta["source"] == {"source": "har", "file": "x.har"}
    assert plan.meta["flows_total"] == 6 and plan.meta["flows_kept"] == 2 and plan.meta["steps"] == 2
    assert "generated_at" in plan.meta


def test_keep_all_keep_static_include_hosts():
    s = Site()
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/static/app.css", resp_headers=[("Content-Type", "text/css")])
    s.add("GET", "https://www.googletagmanager.com/gtm.js", resp_headers=[("Content-Type", "application/javascript")])
    s.add("GET", "https://cdn.other.net/lib.json", resp_headers=JSON, resp_body=b"{}")
    assert len(s.plan().steps) == 2
    assert len(s.plan(PlanOptions(keep_static=True)).steps) == 3
    assert len(s.plan(PlanOptions(keep_all=True)).steps) == 4
    inc = s.plan(PlanOptions(include_hosts=["site.example"], keep_all=True))
    assert len(inc.steps) == 2 and {d.reason for d in inc.dropped} == {"host not in --include-host"}
    exc = s.plan(PlanOptions(exclude_hosts=["other.net"]))
    assert [d.reason for d in exc.dropped if d.flow_id == "f0004"] == ["host excluded"]


def test_max_steps_truncates_with_warning():
    s = Site()
    for i in range(5):
        s.add("GET", f"/p{i}", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(max_steps=2, detect_loops=False))  # /p0../p4 would otherwise fold into a path loop
    assert len(plan.steps) == 2
    assert any("max-steps" in w for w in plan.warnings)
    assert [d.flow_id for d in plan.dropped] == ["f0003", "f0004", "f0005"]
    assert plan.meta["flows_kept"] == 2


def test_dynamic_untraced_literal_warns():
    s = Site()
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/api?sig=8f3a9c2d1e4b5a6f7a8b&sort=name", resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert params(plan.steps[1])["sig"] == Ref.lit("8f3a9c2d1e4b5a6f7a8b")
    assert any("step 2" in w and "`sig`" in w and "looks dynamic" in w for w in plan.warnings)
    assert not any("`sort`" in w for w in plan.warnings)


def test_first_step_only_has_literals_and_constants():
    s = Site()
    s.add("POST", "/login", [FORM], body=b"user=someone_long&password=pw12345678&tok=8f3a9c2d1e4b5a6f", resp_body=b"<html></html>")
    plan = s.plan()
    (step,) = plan.steps
    assert step.extractors == []
    assert form(step, "user") == Ref.lit("someone_long") and form(step, "password") == Ref.var("PASSWORD")
    assert form(step, "tok") == Ref.lit("8f3a9c2d1e4b5a6f")


def test_multipart_body():
    boundary = "----WebKitFormBoundaryX1"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nTitle 0001\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\nCSRFmp12345\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
            f"--{boundary}--\r\n").encode()
    s = Site()
    s.add("GET", "/form", resp_body=b'<html><input type="hidden" name="csrf" value="CSRFmp12345"></html>')
    s.add("POST", "/upload", [("Content-Type", f"multipart/form-data; boundary={boundary}")], body=body, resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    step = plan.steps[1]
    assert step.body_kind == "multipart"
    parts = {p.name: p for p in step.multipart}
    assert parts["title"].value == Ref.lit("Title 0001") and parts["csrf"].value == Ref.var("csrf")
    assert parts["file"].filename == "a.txt" and parts["file"].content == b"hello" and parts["file"].content_type == "text/plain"
    assert "content-type" not in [n.lower() for n, _ in step.headers]


def test_raw_body_and_binary_response_and_no_crash_on_garbage():
    s = Site()
    s.add("POST", "/soap", [("Content-Type", "text/xml")], body=b"<x>\xff\xfe</x>", resp_headers=[("Content-Type", "application/xml")], resp_body=b"<r/>")
    s.add("POST", "/bin", [("Content-Type", "application/octet-stream")], body=b"\x00\x01\x02", resp_headers=[("Content-Type", "application/pdf")], resp_body=b"%PDF\x00")
    s.add("GET", "/nothing", status=204, resp_headers=[], resp_body=None)
    s.add("GET", "/weird", resp_headers=[("Content-Type", "text/html; charset=bogus-charset")], resp_body=b"\xff\xfe\x00bad")
    s.add("GET", "/plainjson", resp_headers=[("Content-Type", "text/plain")], resp_body=b'{"a": 1}')
    s.add("GET", "/noct", resp_headers=[], resp_body=b"\x89PNG\x00\x00")
    plan = s.plan(PlanOptions(detect_loops=False))  # four "GET /<word>" requests would fold into a path loop
    kinds = [(st.body_kind, st.response_kind) for st in plan.steps]
    assert kinds == [("raw", "xml"), ("raw", "binary"), ("none", "empty"), ("none", "html"), ("none", "json"), ("none", "binary")]
    assert plan.steps[0].raw_body == b"<x>\xff\xfe</x>" and plan.steps[1].raw_body == b"\x00\x01\x02"
    assert plan.steps[2].expected_status == 204


def test_empty_recording_and_missing_responses():
    plan = build_plan(Recording(flows=[], meta={}))
    assert plan.steps == [] and plan.constants == [] and plan.base_headers == [] and plan.meta["flows_total"] == 0
    s = Site()
    s.add("GET", "/a", no_response=True)
    plan = s.plan()
    assert plan.steps == [] and plan.dropped[0].reason == "no response recorded"


def test_same_value_in_same_request_gets_same_ref_and_extractor_dedupe():
    s = Site()
    s.add("GET", "/form", resp_body=b'<html><input type="hidden" name="t" value="SAMEtoken00001"></html>')
    s.add("POST", "/a?t=SAMEtoken00001", [FORM, ("X-Token", "SAMEtoken00001")], body=b"t=SAMEtoken00001", resp_body=b"<html></html>")
    s.add("POST", "/b", [FORM], body=b"t=SAMEtoken00001", resp_body=b"<html></html>")
    plan = s.plan()
    assert len(plan.steps[0].extractors) == 1
    ext = plan.steps[0].extractors[0]
    assert "step 2" in ext.note and "step 3" in ext.note
    st = plan.steps[1]
    assert params(st)["t"] == form(st, "t") == hdr(st, "X-Token") == Ref.var(ext.var)
    assert form(plan.steps[2], "t") == Ref.var(ext.var)


def test_redirect_chain_location_value_via_url_kind():
    s = Site()
    s.add("GET", "/auth", status=302, resp_headers=[("Location", "/cb?code=AUTHcode123456&state=xyz")])
    s.add("GET", "/cb?code=AUTHcode123456&state=xyz", resp_body=b"<html>done</html>")
    s.add("POST", "/token", [FORM], body=b"code=AUTHcode123456&grant=authorization_code", resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    assert len(plan.steps) == 2 and plan.steps[0].source_flow_ids == ["f0001", "f0002"]
    (ext,) = plan.steps[0].extractors
    assert ext.kind == "url" and "AUTHcode123456" not in ext.pattern
    assert form(plan.steps[1], "code") == Ref.var(ext.var) and ext.var == "code"
    plan2 = s.plan(PlanOptions(collapse_redirects=False))
    assert len(plan2.steps) == 3 and plan2.steps[0].expected_status == 302


def test_variable_names_are_unique_and_not_reserved():
    s = Site()
    s.add("GET", "/a", resp_body=b'<html><input name="type" value="TYPEval0001"><input name="session" value="SESSval0001"><input name="data" value="DATAval0001"></html>')
    s.add("GET", "/b?type=TYPEval0001&session=SESSval0001&data=DATAval0001&data2=DATAval0001&timeout=TIMEOUTval01", resp_headers=JSON, resp_body=b"{}")
    s.add("GET", "/c?timeout=TIMEOUTval01", resp_headers=JSON, resp_body=b"{}")
    plan = s.plan()
    names = [e.var for e in plan.steps[0].extractors]
    assert len(set(names)) == len(names) and all(n not in ("type", "session", "data") for n in names)
    assert plan.constants[0].name not in ("TIMEOUT",) and plan.constants[0].value == "TIMEOUTval01"


def test_json_response_value_in_header_uses_adapted_ref_for_encoded_variant():
    s = Site()
    s.add("GET", "/a", resp_body=b'<html><a id="next" href="/go?u=a%2Fb%2Fc12345">n</a></html>')
    s.add("GET", "/go?u=a/b/c12345", resp_body=b"<html></html>")
    plan = s.plan()
    ref = params(plan.steps[1])["u"]
    (ext,) = plan.steps[0].extractors
    assert ext.kind == "html_attr" and ext.selector == "#next"
    assert ref == Ref.expr(f"unquote({ext.var})")
    assert unquote(ext.sample) == "a/b/c12345"


def test_slug_and_func_name_edge_cases():
    s = Site()
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/", resp_body=b"<html></html>")
    s.add("GET", "/very/deep/path/items.json?x=1", resp_headers=JSON, resp_body=b"{}")
    s.add("DELETE", "/items/12345", status=204, resp_headers=[], resp_body=b"")
    plan = s.plan()
    assert [st.func_name for st in plan.steps] == [
        "step_01_get_site_example", "step_02_get_site_example", "step_03_get_path_items_json", "step_04_delete_items",
    ]


# --------------------------------------------------------------------------- short ids and plain words

def test_short_numeric_path_segment_traced_to_json_leaf():
    """``/orgs/77/items`` after ``GET /me`` -> ``{"org": {"id": 77}}``: traced although 77 is short."""
    s = Site()
    s.add("GET", "/api/me", [("Accept", "application/json")], resp_headers=JSON,
          resp_body=b'{"id": 4821, "name": "Alice", "org": {"id": 77, "name": "Example Org"}}')
    s.add("GET", "/api/orgs/77/items?page=1", [("Accept", "application/json")], resp_headers=JSON, resp_body=b"[]")
    plan = s.plan()
    ext = plan.steps[0].extractors[0]
    assert (ext.kind, ext.path, ext.var, ext.sample) == ("json", ["org", "id"], "org_id", "77")
    assert plan.steps[1].url == [Ref.lit("https://site.example/api/orgs/"), Ref.var("org_id"), Ref.lit("/items")]
    assert plan.steps[1].func_name == "step_02_get_orgs_items"
    assert plan.warnings == []


def test_short_numeric_path_segment_is_never_pattern_traced():
    """A two-digit id occurs in prose by coincidence: only exact structural matches count."""
    s = Site()
    s.add("GET", "/page", resp_body=b'<html><body><p class="o">Order 77 of 1977 shipped</p><a href="/x?n=77">x</a></body></html>')
    s.add("GET", "/orders/77")
    plan = s.plan()
    assert plan.steps[0].extractors == []
    assert plan.steps[1].url == [Ref.lit("https://site.example/orders/77")]


def test_plain_word_path_segment_is_not_traced_through_patterns():
    """``dashboard`` is a path name, not a token: neither the redirect Location nor an href is used."""
    s = Site()
    s.add("POST", "/login", [FORM], body=b"username=alice_w&password=Secr3tPass%21", status=302,
          resp_headers=[("Location", "/dashboard")])
    s.add("GET", "/dashboard", resp_body=b'<html><body><a href="/dashboard" class="active">Home</a></body></html>')
    s.add("GET", "/dashboard", resp_body=b"<html><body>again</body></html>")  # explicit navigation
    plan = s.plan()
    assert [st.func_name for st in plan.steps] == ["step_01_post_login", "step_02_get_dashboard"]
    assert plan.steps[1].url == [Ref.lit("https://site.example/dashboard")]
    assert all(not e.pattern for st in plan.steps for e in st.extractors)


def test_func_name_slug_from_numeric_host_has_no_leading_underscore():
    s = Site(host="http://127.0.0.1:8000")
    s.add("GET", "/")
    assert s.plan().steps[0].func_name == "step_01_get_127_0_0_1"


# --------------------------------------------------------------------------- phase 2: legacy-charset forms (DESIGN.md §13.4)

SJIS_PAGE = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"></head><body>'
             '<form method="post" action="./Default.aspx" id="form1">'
             '<input type="hidden" name="__VIEWSTATE" value="dDwtMTI3NjU0ODE4Nzs7Pg5QcVUGkTdF" />'
             '<input type="hidden" name="__EVENTVALIDATION" value="/wEWAwLcx6TQBwKU7LvkBgLs0bLrBg==" />'
             '<input name="ctl00$txtKeyword" type="text" /><input type="submit" name="ctl00$btnSearch" value="検索" />'
             '</form></body></html>').encode("cp932")
SJIS_POST = (b"__EVENTTARGET=&__VIEWSTATE=dDwtMTI3NjU0ODE4Nzs7Pg5QcVUGkTdF&__EVENTVALIDATION=%2FwEWAwLcx6TQBwKU7LvkBgLs0bLrBg%3D%3D"
             b"&ctl00%24txtKeyword=%93%FA%96%7B&ctl00%24btnSearch=%8C%9F%8D%F5")


def test_cp932_percent_encoded_form_is_replayed_raw_with_content_type():
    s = Site()
    s.add("GET", "/Default.aspx", resp_headers=[("Content-Type", "text/html")], resp_body=SJIS_PAGE)
    s.add("POST", "/Default.aspx", [FORM, ("Referer", "https://site.example/Default.aspx")], body=SJIS_POST,
          resp_headers=[("Content-Type", "text/html")], resp_body=SJIS_PAGE)
    plan = s.plan()
    get_page, post = plan.steps
    assert post.body_kind == "raw" and post.raw_body == SJIS_POST
    assert hdr(post, "Content-Type") == Ref.lit("application/x-www-form-urlencoded")
    # dependency detection still works on the form fields ...
    exts = {e.name: e for e in get_page.extractors}
    assert set(exts) == {"__VIEWSTATE", "__EVENTVALIDATION"} and all(e.kind == "html_input" for e in exts.values())
    # ... and the form hint keeps the traced Refs plus bytes literals for the cp932 values
    form_hint = dict(post.form)
    assert form_hint["__VIEWSTATE"] == Ref.var("viewstate") and form_hint["__EVENTVALIDATION"] == Ref.var("eventvalidation")
    assert form_hint["ctl00$txtKeyword"] == Ref.expr(repr("日本".encode("cp932")))
    assert form_hint["ctl00$btnSearch"] == Ref.expr(repr("検索".encode("cp932")))
    assert form_hint["__EVENTTARGET"] == Ref.lit("")
    assert [name for name, _ in post.form] == ["__EVENTTARGET", "__VIEWSTATE", "__EVENTVALIDATION", "ctl00$txtKeyword", "ctl00$btnSearch"]
    (warning,) = [w for w in plan.warnings if "step 2" in w]
    assert "Shift_JIS" in warning and "__VIEWSTATE" in warning
    assert not any("looks dynamic" in w for w in plan.warnings)
    assert post.func_name == "step_02_post_default_aspx" and get_page.func_name == "step_01_get_default_aspx"


def test_utf8_form_with_japanese_stays_a_normal_form():
    s = Site()
    s.add("GET", "/search", resp_body=b'<html><input type="hidden" name="csrf" value="CSRFutf8abc123"></html>')
    s.add("POST", "/search", [FORM], body=b"csrf=CSRFutf8abc123&q=%E6%97%A5%E6%9C%AC&submit=%E6%A4%9C%E7%B4%A2", resp_body=b"<html></html>")
    plan = s.plan()
    post = plan.steps[1]
    assert post.body_kind == "form" and post.raw_body is None
    assert form(post, "q") == Ref.lit("日本") and form(post, "csrf") == Ref.var("csrf")
    assert "content-type" not in [n.lower() for n, _ in post.headers]
    assert not any("Shift_JIS" in w for w in plan.warnings)


def test_declared_legacy_charset_on_the_request_decodes_values_but_still_replays_raw():
    s = Site()
    s.add("GET", "/f", resp_body=b"<html></html>")
    s.add("POST", "/f", [("Content-Type", "application/x-www-form-urlencoded; charset=Shift_JIS")],
          body=b"q=%93%FA%96%7B&n=12345678", resp_body=b"<html></html>")
    plan = s.plan()
    post = plan.steps[1]
    assert post.body_kind == "raw" and hdr(post, "Content-Type") == Ref.lit("application/x-www-form-urlencoded; charset=Shift_JIS")
    assert dict(post.form)["q"] == Ref.expr(repr("日本".encode("cp932"))) and dict(post.form)["n"] == Ref.lit("12345678")


# --------------------------------------------------------------------------- phase 2: route names and reserved parameter names

def test_route_like_path_segments_are_never_constants_or_pattern_traced():
    s = Site()
    s.add("GET", "/Default.aspx", resp_body=b'<html><a id="self" href="Default.aspx?x=1">self</a><a id="next" href="Report.aspx?id=4321">r</a></html>')
    s.add("POST", "/Default.aspx", [FORM], body=b"q=hello_world", resp_body=b"<html></html>")
    s.add("GET", "/Default.aspx", resp_body=b"<html></html>")
    s.add("GET", "/Report.aspx?id=4321", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(detect_loops=False))
    assert plan.constants == []
    assert all(st.literal_url() for st in plan.steps)
    assert plan.steps[3].literal_url() == "https://site.example/Report.aspx"
    (ext,) = plan.steps[0].extractors
    assert ext.selector == "#next" and ext.var == "report_id" and params(plan.steps[3])["id"] == Ref.var("report_id")
    assert [st.func_name for st in plan.steps] == [
        "step_01_get_default_aspx", "step_02_post_default_aspx", "step_03_get_default_aspx", "step_04_get_report_aspx",
    ]


def test_reserved_parameter_names_are_qualified_with_the_route():
    s = Site()
    s.add("GET", "/api/items", resp_headers=JSON, resp_body=b'{"items": [{"id": 9001, "type": "WIDGET_X1"}]}')
    s.add("GET", "/api/items/detail?id=9001&type=WIDGET_X1", resp_headers=JSON, resp_body=b"{}")
    s.add("GET", "/?id=9001", resp_body=b"<html></html>")
    plan = s.plan()
    names = {e.var for e in plan.steps[0].extractors}
    assert names == {"detail_id", "detail_type"}
    assert params(plan.steps[1]) == {"id": Ref.var("detail_id"), "type": Ref.var("detail_type")}
    assert params(plan.steps[2]) == {"id": Ref.var("detail_id")}  # reused extractor, named after its first consumer


def test_plan_without_auth_has_no_auth_fields():
    plan = login_site().plan()
    assert plan.auth is None and plan.final_step_index is None and "auth" not in plan.meta


# --------------------------------------------------------------------------- review 3: route-like path segments

def test_all_uppercase_path_key_is_traced_to_an_exact_json_leaf():
    """Regression: letters-only path segments were removed from the candidates, so a base32 session
    key in the path (traceable to a JSON leaf) stayed a stale literal."""
    s = Site()
    s.add("GET", "/api/session", resp_headers=JSON, resp_body=b'{"session": {"key": "QZVBNMWRTYPXSDFKHJ"}}')
    s.add("GET", "/s/QZVBNMWRTYPXSDFKHJ/items", resp_headers=JSON, resp_body=b"[]")
    plan = s.plan()
    (ext,) = plan.steps[0].extractors
    assert (ext.kind, ext.path) == ("json", ["session", "key"])
    assert plan.steps[1].url == [Ref.lit("https://site.example/s/"), Ref.var(ext.var), Ref.lit("/items")]


def test_route_like_path_segment_keeps_exact_header_and_input_traces_but_never_markup():
    s = Site()
    s.add("GET", "/start", resp_headers=HTML + [("X-Next-Page", "SC0020.aspx")],
          resp_body=b'<html><a id="nx" href="SC0020.aspx">next</a><span id="pg">SC0030.aspx</span>'
                    b'<form action="KJ010Search.aspx"><input type="hidden" name="hdnNext" value="Menu01.aspx"></form></html>')
    s.add("GET", "/SC0020.aspx")        # equal to a response header -> traced (exact)
    s.add("GET", "/start", resp_headers=HTML + [("X-Next-Page", "SC0020.aspx")],
          resp_body=b'<html><form><input type="hidden" name="hdnNext" value="Menu01.aspx"></form></html>')
    s.add("GET", "/Menu01.aspx")        # equal to an <input> value -> traced (exact)
    s.add("GET", "/start", resp_body=b'<html><span id="pg">SC0030.aspx</span><form action="KJ010Search.aspx"></form></html>')
    s.add("GET", "/SC0030.aspx")        # only element text -> literal
    s.add("GET", "/start", resp_body=b'<html><span id="pg">SC0030.aspx</span><form action="KJ010Search.aspx"></form></html>')
    s.add("POST", "/KJ010Search.aspx", [FORM], body=b"q=hello_world")  # only a form action -> literal
    plan = s.plan(PlanOptions(detect_loops=False))
    steps = {st.index: st for st in plan.steps}
    assert [(e.kind, e.name) for st in plan.steps for e in st.extractors] == [("header", "X-Next-Page"), ("html_input", "hdnNext")]
    header_ext, input_ext = plan.steps[0].extractors[0], plan.steps[2].extractors[0]
    assert steps[2].url == [Ref.lit("https://site.example/"), Ref.var(header_ext.var)]
    assert steps[4].url == [Ref.lit("https://site.example/"), Ref.var(input_ext.var)]
    assert steps[6].literal_url() == "https://site.example/SC0030.aspx"
    assert steps[8].literal_url() == "https://site.example/KJ010Search.aspx"
    assert plan.constants == [] and not any("looks dynamic" in w for w in plan.warnings)


def test_screen_id_pages_are_literal_in_urls_and_referers():
    """``SC0010.aspx`` / ``KJ010Search.aspx`` / ``Menu01.aspx`` used to be traced to markup (the digits
    made them non-structural) and the Referer rewrite spread that dependency."""
    s = Site("http://intra.example")
    page = (b'<html><a id="m" href="Menu01.aspx">menu</a><form id="f" action="KJ010Search.aspx">'
            b'<input type="hidden" name="__VIEWSTATE" value="VS0123456789abc"></form></html>')
    s.add("GET", "/SC0010.aspx", resp_body=page)
    s.add("POST", "/KJ010Search.aspx", [FORM, ("Referer", "http://intra.example/SC0010.aspx")],
          body=b"__VIEWSTATE=VS0123456789abc&q=x", resp_body=page)
    s.add("GET", "/Menu01.aspx", [("Referer", "http://intra.example/KJ010Search.aspx")], resp_body=page)
    s.add("GET", "/SC0010.aspx", [("Referer", "http://intra.example/Menu01.aspx")], resp_body=page)
    plan = s.plan(PlanOptions(detect_loops=False))
    assert [st.literal_url() for st in plan.steps] == [
        "http://intra.example/SC0010.aspx", "http://intra.example/KJ010Search.aspx",
        "http://intra.example/Menu01.aspx", "http://intra.example/SC0010.aspx"]
    assert [(e.kind, e.name) for st in plan.steps for e in st.extractors] == [("html_input", "__VIEWSTATE")]
    assert all(r.is_literal for st in plan.steps for n, r in st.headers if n.lower() == "referer")
    assert plan.constants == []


def test_mvc_route_words_with_acronyms_are_not_traced_through_markup():
    s = Site()
    s.add("GET", "/Production/Index", resp_body=b'<html><a id="x" href="/Production/ProductionResultCSV">csv</a>'
                                                 b'<script>var a = "/Production/OrderDateDESC";</script></html>')
    s.add("GET", "/Production/ProductionResultCSV", resp_headers=[("Content-Type", "text/csv")], resp_body=b"a,b\n")
    s.add("GET", "/Production/OrderDateDESC", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(detect_loops=False))
    assert plan.steps[0].extractors == []
    assert [st.literal_url() for st in plan.steps[1:]] == [
        "https://site.example/Production/ProductionResultCSV", "https://site.example/Production/OrderDateDESC"]
    assert not any("looks dynamic" in w for w in plan.warnings)


def test_digit_free_base64url_key_is_a_token():
    """``xBBHOH-pXYZgFKyNZpuWy`` is not a route word: traced by pattern, and warned about otherwise."""
    s = Site()
    s.add("GET", "/menu", resp_body=b"<html><a id=\"s\" onclick=\"window.open('Search.aspx?key=xBBHOH-pXYZgFKyNZpuWy','s')\">s</a></html>")
    s.add("GET", "/Search.aspx?key=xBBHOH-pXYZgFKyNZpuWy")
    s.add("GET", "/r/pXYZgFKy_NZpuWyxBBHOH/view")
    plan = s.plan(PlanOptions(detect_loops=False))
    (ext,) = plan.steps[0].extractors
    assert ext.pattern and params(plan.steps[1])["key"] == Ref.var(ext.var)
    assert plan.constants == []
    # an untraced random path key is not a route name: the stale literal is warned about
    assert any("path segment 1" in w and "looks dynamic" in w for w in plan.warnings)
    # repeated and untraced: a shared constant (not kept in the URL like a route name), still warned about
    s.add("GET", "/r/pXYZgFKy_NZpuWyxBBHOH/view?x=1")
    plan = s.plan(PlanOptions(detect_loops=False))
    assert [c.value for c in plan.constants] == ["pXYZgFKy_NZpuWyxBBHOH"]


# --------------------------------------------------------------------------- review 3: Referer substitution

from reqrec import _referer_with_fresh_values  # noqa: E402


def _eval_ref(ref, **names):
    import requests

    return eval(ref.value, {"requests": requests, "unquote": unquote, "str": str}, names)  # noqa: S307


def test_referer_replaces_whole_tokens_only():
    refs = {("query", "key", "ABCDEFGH1234"): Ref.var("key")}
    referer = ("http://ABCDEFGH1234.example/x/ABCDEFGH1234/y?key=ABCDEFGH1234&long=ABCDEFGH12345"
               "&pre=xABCDEFGH1234&ABCDEFGH1234#ABCDEFGH1234")
    ref = _referer_with_fresh_values(referer, refs)
    assert ref.kind == "expr"
    assert _eval_ref(ref, key="NEW") == ("http://ABCDEFGH1234.example/x/NEW/y?key=NEW&long=ABCDEFGH12345"
                                          "&pre=xABCDEFGH1234&NEW#ABCDEFGH1234")
    # in the host, or inside longer tokens only -> nothing to replace
    assert _referer_with_fresh_values("http://ABCDEFGH1234.example/a?k=ABCDEFGH12345", refs) == \
        Ref.lit("http://ABCDEFGH1234.example/a?k=ABCDEFGH12345")
    # path parameters (``;jsessionid=``) are whole tokens too
    ref = _referer_with_fresh_values("http://h/app/list.do;jsessionid=ABCDEFGH1234?p=1", refs)
    assert _eval_ref(ref, key="NEW") == "http://h/app/list.do;jsessionid=NEW?p=1"
    # short values, literal refs and non-URL headers stay literal
    assert _referer_with_fresh_values("http://h/a?k=1234567", {("query", "k", "1234567"): Ref.var("k")}).is_literal
    assert _referer_with_fresh_values("http://h/a?k=ABCDEFGH1234", {("query", "k", "ABCDEFGH1234"): Ref.lit("x")}).is_literal
    assert _referer_with_fresh_values("about:blank ABCDEFGH1234", refs).is_literal


def test_referer_handles_the_percent_encoded_spelling():
    """A key with ``+ / =`` appears percent-encoded in the Referer and used to stay stale."""
    raw = "Qk+9/zR8vT=="
    referer = "http://h/Search.aspx?key=Qk%2B9%2FzR8vT%3D%3D&x=1"
    # value decoded from an encoded source (``unquote(X)``): X is the fresh encoded spelling
    ref = _referer_with_fresh_values(referer, {("query", "key", raw): Ref.expr("unquote(key)")})
    assert ref.value == "'http://h/Search.aspx?key=' + str(key) + '&x=1'"
    assert _eval_ref(ref, key="Zz%2B1%2FyY2xX%3D%3D") == "http://h/Search.aspx?key=Zz%2B1%2FyY2xX%3D%3D&x=1"
    # any other ref: quoted with requests.utils.quote (the generated script always imports requests)
    ref = _referer_with_fresh_values(referer, {("query", "key", raw): Ref.var("key")})
    assert "requests.utils.quote(str(key), safe='')" in ref.value
    assert _eval_ref(ref, key="Zz+1/yY2xX==") == "http://h/Search.aspx?key=Zz%2B1%2FyY2xX%3D%3D&x=1"
    # the verbatim spelling still wins, also for an unquote(X) ref
    ref = _referer_with_fresh_values("http://h/S.aspx?key=" + raw, {("query", "key", raw): Ref.expr("unquote(key)")})
    assert _eval_ref(ref, key="Zz%2B1") == "http://h/S.aspx?key=Zz+1"
    # '+' for a space in a query value
    ref = _referer_with_fresh_values("http://h/s?q=hello+big+world", {("query", "q", "hello big world"): Ref.var("q")})
    assert _eval_ref(ref, q="a b") == "http://h/s?q=a%20b"


def test_referer_rewrite_in_a_plan_keeps_host_and_unrelated_tokens():
    s = Site("http://kanri01")
    s.add("GET", "/Menu.aspx", resp_body=b"<html><a id=\"s\" onclick=\"window.open('Search.aspx?key=kanri01KEYxyz9','s')\">s</a></html>")
    s.add("GET", "/Search.aspx?key=kanri01KEYxyz9", [("Referer", "http://kanri01/Menu.aspx?from=kanri01KEYxyz9X")],
          resp_body=b'<html><form id="form1" action="Search.aspx?key=kanri01KEYxyz9"></form></html>')
    s.add("POST", "/Search.aspx?key=kanri01KEYxyz9", [FORM, ("Referer", "http://kanri01/Search.aspx?key=kanri01KEYxyz9")],
          body=b"q=1", resp_body=b"<html></html>")
    plan = s.plan()
    get_search, post_search = plan.steps[1], plan.steps[2]
    assert hdr(get_search, "Referer") == Ref.lit("http://kanri01/Menu.aspx?from=kanri01KEYxyz9X")
    key_var = params(post_search)["key"].value
    assert hdr(post_search, "Referer") == Ref.expr(f"'http://kanri01/Search.aspx?key=' + str({key_var})")


# --------------------------------------------------------------------------- review 3: secrets that are not trace candidates

@pytest.mark.parametrize("password", ["admin", "guest", "abc", "123", "x"])
def test_short_or_plain_word_passwords_are_still_secret(password):
    s = Site()
    s.add("GET", "/login", resp_body=b"<html></html>")
    s.add("POST", "/login", [FORM], body=f"user=taro&password={password}".encode(), resp_body=b"<html></html>")
    plan = s.plan()
    (const,) = plan.constants
    assert (const.name, const.value, const.secret, const.env_var) == ("PASSWORD", password, True, "REQREC_PASSWORD")
    assert form(plan.steps[1], "password") == Ref.var("PASSWORD") and form(plan.steps[1], "user") == Ref.lit("taro")
    assert any("REQREC_PASSWORD" in w for w in plan.warnings)
    no_redact = s.plan(PlanOptions(redact_secrets=False))
    assert form(no_redact.steps[1], "password") == Ref.lit(password) and no_redact.constants == []


def test_password_equal_to_the_user_id_is_still_secret():
    """Regression: the per-step value cache handed the user id's literal Ref to the password."""
    s = Site()
    s.add("POST", "/Login.aspx", [FORM], body=b"txtUserId=tanaka01&txtPassword=tanaka01&btnLogin=Login", resp_body=b"<html></html>")
    plan = s.plan()
    assert form(plan.steps[0], "txtUserId") == Ref.lit("tanaka01")
    assert form(plan.steps[0], "txtPassword") == Ref.var("TXT_PASSWORD")
    (const,) = plan.constants
    assert (const.value, const.secret, const.env_var) == ("tanaka01", True, "REQREC_TXT_PASSWORD")


def test_repeated_user_id_constant_is_not_turned_into_the_password():
    """The user id's shared constant stays plain; the password gets its own environment variable."""
    s = Site()
    for _ in range(2):
        s.add("POST", "/Login.aspx", [FORM], body=b"txtUserId=tanaka01&txtPassword=tanaka01", resp_body=b"<html></html>")
        s.add("GET", "/Logout.aspx", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(detect_loops=False))
    consts = {c.name: c for c in plan.constants}
    assert (consts["TXT_USER_ID"].secret, consts["TXT_USER_ID"].env_var) == (False, None)
    assert (consts["TXT_PASSWORD"].secret, consts["TXT_PASSWORD"].env_var) == (True, "REQREC_TXT_PASSWORD")
    for st in (plan.steps[0], plan.steps[2]):
        assert form(st, "txtUserId") == Ref.var("TXT_USER_ID") and form(st, "txtPassword") == Ref.var("TXT_PASSWORD")


def test_secret_fields_outside_forms_are_redacted_too():
    s = Site()
    s.add("POST", "/api/login?pwd=987", [("Content-Type", "application/json"), ("Authorization", "Bearer abc"), ("X-Api-Key", "k1")],
          body=json.dumps({"user": "taro", "pin": 123, "auth": {"password": "admin"}}).encode(), resp_headers=JSON, resp_body=b"{}")
    s.add("POST", "/upload", [("Content-Type", "multipart/form-data; boundary=XyZ")],
          body=b'--XyZ\r\nContent-Disposition: form-data; name="passwd"\r\n\r\nxyz\r\n--XyZ--\r\n', resp_body=b"<html></html>")
    plan = s.plan()
    api, upload = plan.steps
    consts = {c.name: c for c in plan.constants}
    assert all(c.secret and c.env_var == f"REQREC_{c.name}" for c in consts.values())
    assert params(api)["pwd"] == Ref.var("PWD") and consts["PWD"].value == "987"
    # a numeric leaf stays a number: int() of the environment variable
    assert api.json_body == {"user": "taro", "pin": Ref.expr("int(PIN)"), "auth": {"password": Ref.var("PASSWORD")}}
    assert (consts["PIN"].value, consts["PASSWORD"].value) == ("123", "admin")
    assert hdr(api, "Authorization") == Ref.expr('"Bearer " + AUTHORIZATION') and consts["AUTHORIZATION"].value == "abc"
    assert hdr(api, "X-Api-Key") == Ref.var("X_API_KEY") and consts["X_API_KEY"].value == "k1"
    (part,) = upload.multipart
    assert part.value == Ref.var("PASSWD") and consts["PASSWD"].value == "xyz"
    assert not any(f"'{v}'" in repr(plan.steps) for v in ("admin", "abc", "xyz", "k1", "987"))


def test_referer_never_carries_a_short_password():
    """``Login.aspx?pwd=abc`` as the previous page: the Referer of the next request reuses the secret."""
    s = Site("http://kanri01")
    s.add("GET", "/Login.aspx?user=taro&pwd=abc", resp_body=b"<html></html>")
    s.add("GET", "/Menu.aspx", [("Referer", "http://kanri01/Login.aspx?user=taro&pwd=abc&x=abc")], resp_body=b"<html></html>")
    plan = s.plan()
    assert params(plan.steps[0])["pwd"] == Ref.var("PWD")
    referer = hdr(plan.steps[1], "Referer")
    assert referer == Ref.expr("'http://kanri01/Login.aspx?user=taro&pwd=' + str(PWD) + '&x=abc'")


def test_route_like_path_segments_do_not_turn_other_values_into_constants():
    s = Site()
    s.add("GET", "/Menu.aspx", resp_body=b"<html></html>")
    s.add("POST", "/Logout.aspx", [FORM], body=b"ReturnUrl=Menu.aspx", resp_body=b"<html></html>")
    plan = s.plan(PlanOptions(detect_loops=False))
    assert plan.constants == [] and form(plan.steps[1], "ReturnUrl") == Ref.lit("Menu.aspx")


# ===== former tests/test_overrides.py: manual overrides (keep / exclude / final step) =====
# Tests for the manual overrides of DESIGN.md §13.1: ``PlanOptions.exclude_flow_ids`` /
# ``include_flow_ids`` (``filters.classify_noise``) and ``final_flow_id`` -> ``Plan.final_step_index``
# (``plan.build_plan``).

OVERRIDES_BASE = [("User-Agent", "UA/1.0"), ("Accept-Language", "ja")]
CSS = [("Content-Type", "text/css")]


class OverridesSite:
    def __init__(self, host="https://site.example"):
        self.host = host
        self.flows: list[Flow] = []

    def add(self, method, path, req_headers=(), body=None, status=200, resp_headers=HTML, resp_body=b"<html></html>",
            rtype=None, no_response=False):
        url = path if path.startswith("http") else self.host + path
        resp = None if no_response else RecordedResponse(status, list(resp_headers), resp_body)
        flow = Flow(f"f{len(self.flows) + 1:04d}", RecordedRequest(method, url, list(OVERRIDES_BASE) + list(req_headers), body), resp,
                    started_at=T0 + len(self.flows), resource_type=rtype)
        self.flows.append(flow)
        return flow

    def recording(self):
        return Recording(flows=list(self.flows), meta={"source": "test"})

    def plan(self, **opts):
        return build_plan(self.recording(), PlanOptions(**opts))


def noisy_site():
    s = OverridesSite()
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
    s = OverridesSite()
    s.add("GET", "/secure", status=401, resp_headers=HTML + [("WWW-Authenticate", 'Basic realm="x"')], resp_body=b"<html>401</html>")
    s.add("GET", "/secure", [("Authorization", "Basic " + base64.b64encode(b"taro:pw").decode())], resp_body=b"<html>ok</html>")
    s.add("GET", "/after", resp_body=b"<html>after</html>")
    plan = s.plan(final_flow_id="f0001")
    assert sources(plan) == [["f0001", "f0002"], ["f0003"]]
    assert plan.final_step_index == 1 and plan.auth.kind == "basic"


def test_final_flow_inside_a_folded_loop():
    s = OverridesSite()
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


# ===== former tests/test_auth.py: Windows / HTTP authentication (NTLM, Negotiate, Basic, Digest) =====
# Tests for HTTP authentication handshake detection (DESIGN.md §13.2).
#
# Covers the parsers in the filters section of ``reqrec.analysis`` (NTLM type-3, Basic, Digest, ``WWW-Authenticate``),
# ``filters.collapse_auth_handshakes`` on synthetic flows, and what ``plan.build_plan`` makes of
# the result (``Plan.auth``, constants, header stripping, 401 hops folded into steps).
#
# The NTLM message builders at the top are also used by the fixture generator for
# ``tests/fixtures/legacy_webforms_ntlm.har``.

# --------------------------------------------------------------------------- NTLM message builders

NTLMSSP = b"NTLMSSP\x00"
_VERSION = bytes([10, 0]) + struct.pack("<H", 19041) + b"\x00\x00\x00\x0f"  # Windows 10 / NTLMSSP revision 15
FLAGS_TYPE1 = 0xA2088207  # UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY | VERSION | 128 | 56
FLAGS_TYPE2 = 0xE28A8215
FLAGS_TYPE3_UNICODE = 0xE2888205
FLAGS_TYPE3_OEM = 0xE2888206


def _buffers(items: list[bytes], base: int) -> tuple[bytes, bytes]:
    """Security-buffer descriptors (Len, MaxLen, Offset) for ``items`` laid out from ``base``."""
    descriptors = b""
    payload = b""
    for item in items:
        descriptors += struct.pack("<HHI", len(item), len(item), base + len(payload))
        payload += item
    return descriptors, payload


def ntlm_type1(flags: int = FLAGS_TYPE1) -> bytes:
    """NEGOTIATE_MESSAGE as IE / Edge send it (no domain / workstation payload)."""
    descriptors, payload = _buffers([b"", b""], 40)
    return NTLMSSP + struct.pack("<I", 1) + struct.pack("<I", flags) + descriptors + _VERSION + payload


def ntlm_type2(target: str = "EXAMPLE", challenge: bytes = b"\x3a\x7f\x11\xc2\x59\x04\xee\x81", flags: int = FLAGS_TYPE2) -> bytes:
    """CHALLENGE_MESSAGE with a target name and a plausible AV_PAIR target-info block."""
    name = target.encode("utf-16-le")
    av = b""
    for av_id, text in ((2, target), (1, "DC01"), (4, "example.local"), (3, "dc01.example.local")):
        data = text.encode("utf-16-le")
        av += struct.pack("<HH", av_id, len(data)) + data
    av += struct.pack("<HH", 7, 8) + struct.pack("<Q", 133_866_912_000_000_000)  # MsvAvTimestamp
    av += struct.pack("<HH", 0, 0)  # MsvAvEOL
    base = 56
    target_desc = struct.pack("<HHI", len(name), len(name), base)
    info_desc = struct.pack("<HHI", len(av), len(av), base + len(name))
    return (NTLMSSP + struct.pack("<I", 2) + target_desc + struct.pack("<I", flags) + challenge + b"\x00" * 8
            + info_desc + _VERSION + name + av)


def ntlm_type3(domain: str = "EXAMPLE", user: str = "taro", workstation: str = "PC01", unicode: bool = True,
               flags: int | None = None, mic: bool = True, seed: bytes = b"reqrec") -> bytes:
    """AUTHENTICATE_MESSAGE with deterministic pseudo-random challenge responses."""
    if unicode:
        encode = lambda s: s.encode("utf-16-le")  # noqa: E731
        flags = FLAGS_TYPE3_UNICODE if flags is None else flags
    else:
        encode = lambda s: s.encode("cp932")  # noqa: E731
        flags = FLAGS_TYPE3_OEM if flags is None else flags
    lm = b"\x00" * 24
    nt = b"".join(hashlib.sha256(seed + bytes([i])).digest() for i in range(4))  # NTLMv2 response blob
    session_key = hashlib.md5(seed).digest()
    header_len = 88 if mic else 72
    descriptors, payload = _buffers([lm, nt, encode(domain), encode(user), encode(workstation), session_key], header_len)
    return (NTLMSSP + struct.pack("<I", 3) + descriptors + struct.pack("<I", flags) + _VERSION
            + (b"\x00" * 16 if mic else b"") + payload)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


TYPE1 = b64(ntlm_type1())
TYPE2 = b64(ntlm_type2())
TYPE3 = b64(ntlm_type3())


# --------------------------------------------------------------------------- flow helpers

HOST = "http://intra.example.local"
IE_HEADERS = [
    ("Accept", "text/html, application/xhtml+xml, image/jxr, */*"),
    ("Accept-Language", "ja-JP"),
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"),
    ("Accept-Encoding", "gzip, deflate"),
    ("Host", "intra.example.local"),
    ("Connection", "Keep-Alive"),
]
AUTH_HTML = [("Content-Type", "text/html")]
IIS_401 = [("Content-Type", "text/html"), ("Server", "Microsoft-IIS/10.0"), ("X-Powered-By", "ASP.NET")]
AUTH_PAGE = (b'<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"></head>'
        b'<body><form method="post" action="./Default.aspx" id="form1">'
        b'<input type="hidden" name="__VIEWSTATE" value="dDwtMTI3NjU0ODE4Nzs7Pg5QcVUGkTdF" />'
        b'<input type="hidden" name="__EVENTVALIDATION" value="/wEWAwLcx6TQBwKU7LvkBgLs0bLrBg==" />'
        b'</form></body></html>')


class AuthSite:
    def __init__(self, host: str = HOST):
        self.host = host
        self.flows: list[Flow] = []

    def add(self, method, path, req_headers=(), body=None, status=200, resp_headers=AUTH_HTML, resp_body=b"<html></html>",
            no_response=False, base=True):
        url = path if path.startswith("http") else self.host + path
        headers = (list(IE_HEADERS) if base else []) + list(req_headers)
        resp = None if no_response else RecordedResponse(status, list(resp_headers), resp_body)
        flow = Flow(f"f{len(self.flows) + 1:04d}", RecordedRequest(method, url, headers, body), resp,
                    started_at=T0 + len(self.flows))
        self.flows.append(flow)
        return flow

    def ntlm_handshake(self, path="/Default.aspx", scheme="NTLM", final_status=200, final_body=AUTH_PAGE,
                       final_headers=None, challenge=("Negotiate", "NTLM"), type3=TYPE3):
        """The three legs IE sends for Integrated Windows Authentication."""
        self.add("GET", path, status=401, resp_headers=IIS_401 + [("WWW-Authenticate", c) for c in challenge])
        self.add("GET", path, [("Authorization", f"{scheme} {TYPE1}")], status=401,
                 resp_headers=IIS_401 + [("WWW-Authenticate", f"{scheme} {TYPE2}")])
        return self.add("GET", path, [("Authorization", f"{scheme} {type3}")], status=final_status,
                        resp_headers=final_headers or (AUTH_HTML + [("Persistent-Auth", "true"),
                                                               ("Set-Cookie", "ASP.NET_SessionId=k2p4d0sx1v; path=/; HttpOnly")]),
                        resp_body=final_body)

    def basic_handshake(self, path="/", user="taro", password="p@ss:w0rd", realm="Intranet", final_body=b"<html>ok</html>"):
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        self.add("GET", path, status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", f'Basic realm="{realm}"')])
        return self.add("GET", path, [("Authorization", f"Basic {token}")], resp_body=final_body), token

    def recording(self):
        return Recording(flows=list(self.flows), meta={"source": "test"})

    def plan(self, opts=None):
        return build_plan(self.recording(), opts)


def ids(groups):
    return [[f.id for f in g] for g in groups]


def auth_headers(plan):
    return [(st.index, name, ref) for st in plan.steps for name, ref in st.headers if name.lower() == "authorization"]


# --------------------------------------------------------------------------- parsers

class TestNtlmParsing:
    def test_type3_unicode_fields(self):
        info = filters.parse_ntlm_type3(ntlm_type3("EXAMPLE", "taro", "PC01"))
        assert info == {"domain": "EXAMPLE", "user": "taro", "workstation": "PC01"}
        assert filters.ntlm_type3_user(TYPE3) == "EXAMPLE\\taro"

    def test_type3_oem_cp932(self):
        token = b64(ntlm_type3("営業部", "太郎", "PC01", unicode=False))
        assert filters.ntlm_type3_user(token) == "営業部\\太郎"

    def test_type3_without_domain_or_mic(self):
        assert filters.ntlm_type3_user(b64(ntlm_type3(domain="", user="hanako", mic=False))) == "hanako"
        assert filters.ntlm_type3_user(b64(ntlm_type3(domain="example.local", user="hanako"))) == "example.local\\hanako"

    def test_type3_inside_spnego_wrapper(self):
        wrapped = b"\x60\x82\x01\x0c\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x82\x01\x00\x30\x81\xfd" + ntlm_type3()
        assert filters.ntlm_type3_user(b64(wrapped)) == "EXAMPLE\\taro"
        assert filters.parse_ntlm_type3(wrapped)["workstation"] == "PC01"

    def test_other_message_types_and_garbage_never_raise(self):
        assert filters.ntlm_type3_user(TYPE1) is None
        assert filters.ntlm_type3_user(TYPE2) is None
        assert filters.ntlm_type3_user("not base64 at all !!") is None
        assert filters.ntlm_type3_user("") is None and filters.ntlm_type3_user(None) is None
        assert filters.parse_ntlm_type3(b"") is None and filters.parse_ntlm_type3(None) is None
        assert filters.parse_ntlm_type3(NTLMSSP + struct.pack("<I", 3) + b"\x00" * 10) is None  # truncated header
        bogus_offsets = NTLMSSP + struct.pack("<I", 3) + struct.pack("<HHI", 10, 10, 9999) * 6 + struct.pack("<I", 1) + b"\x00" * 24
        info = filters.parse_ntlm_type3(bogus_offsets)
        assert info == {"domain": "", "user": "", "workstation": ""}
        assert filters.ntlm_type3_user(b64(bogus_offsets)) is None
        # odd byte count with the Unicode flag: decoded leniently
        odd = ntlm_type3()[:-1]
        assert filters.parse_ntlm_type3(odd) is None or isinstance(filters.parse_ntlm_type3(odd), dict)
        # url-safe alphabet and missing padding are tolerated
        assert filters.ntlm_type3_user(TYPE3.rstrip("=").replace("+", "-").replace("/", "_")) == "EXAMPLE\\taro"


class TestBasicAndDigest:
    @pytest.mark.parametrize("user,password", [
        ("taro", "secret"), ("taro", "p@ss:w0rd:x"), ("太郎", "ぱすわーど"), ("DOMAIN\\taro", ""), ("", "only-password"),
    ])
    def test_basic_roundtrip(self, user, password):
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode()
        assert filters.decode_basic_credentials(token) == (user, password)

    def test_basic_latin1_fallback_and_garbage(self):
        assert filters.decode_basic_credentials(base64.b64encode(b"user:p\xe4ss").decode()) == ("user", "päss")
        assert filters.decode_basic_credentials(base64.b64encode(b"nocolon").decode()) is None
        assert filters.decode_basic_credentials("###") is None
        assert filters.decode_basic_credentials("") is None and filters.decode_basic_credentials(None) is None
        assert filters.decode_basic_credentials("dXNlcjpwYXNz") == ("user", "pass")

    def test_digest_username(self):
        creds = 'username="taro", realm="intra", nonce="abc", uri="/", response="0123456789abcdef", qop=auth, nc=00000001'
        assert filters.digest_username(creds) == "taro"
        assert filters.digest_username("username*=UTF-8''%E5%A4%AA%E9%83%8E, realm=\"x\"") == "太郎"
        assert filters.digest_username('realm="x"') is None and filters.digest_username("") is None

    def test_auth_username_dispatch(self):
        assert filters.auth_username("ntlm", TYPE3) == "EXAMPLE\\taro"
        assert filters.auth_username("negotiate", TYPE3) == "EXAMPLE\\taro"
        assert filters.auth_username("basic", "dXNlcjpwYXNz") == "user"
        assert filters.auth_username("digest", 'username="d"') == "d"
        assert filters.auth_username("bearer", "x") is None


class TestChallengeParsing:
    def test_schemes_tokens_params(self):
        got = filters.parse_www_authenticate(["Negotiate, NTLM", f"NTLM {TYPE2}", 'Basic realm="Intra, net"',
                                              'Digest realm="x", qop="auth", nonce="n1", Basic realm="y"'])
        assert got == [
            ("negotiate", {}, ""), ("ntlm", {}, ""), ("ntlm", {}, TYPE2), ("basic", {"realm": "Intra, net"}, ""),
            ("digest", {"realm": "x", "qop": "auth", "nonce": "n1"}, ""), ("basic", {"realm": "y"}, ""),
        ]

    def test_case_escapes_and_garbage(self):
        got = filters.parse_www_authenticate(['BASIC realm="a\\"b", charset="UTF-8"', "", None, "=== ???", "Bearer error=invalid_token"])
        assert got[0] == ("basic", {"realm": 'a"b', "charset": "UTF-8"}, "")
        assert got[1] == ("bearer", {"error": "invalid_token"}, "")
        assert filters.parse_www_authenticate([]) == []

    def test_authorization_scheme(self):
        assert filters.authorization_scheme("NTLM abc") == ("ntlm", "abc")
        assert filters.authorization_scheme("  Basic   dXNlcjpwYXNz ") == ("basic", "dXNlcjpwYXNz")
        assert filters.authorization_scheme("Negotiate") == ("negotiate", "")
        assert filters.authorization_scheme("") == ("", "") and filters.authorization_scheme(None) == ("", "")
        assert filters.authorization_scheme("!!bad") == ("", "")
        assert filters.auth_family("NTLM") == {"ntlm", "negotiate"} and filters.auth_family("basic") == {"basic"}
        assert filters.auth_family(None) == frozenset()


# --------------------------------------------------------------------------- collapse_auth_handshakes

class TestCollapse:
    def test_ntlm_three_legs(self):
        s = AuthSite()
        s.ntlm_handshake()
        s.add("POST", "/Default.aspx", [("Content-Type", "application/x-www-form-urlencoded")], b"a=1")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002", "f0003"], ["f0004"]]
        assert auth is not None
        assert (auth.kind, auth.hosts, auth.realm, auth.username) == ("ntlm", ["intra.example.local"], None, "EXAMPLE\\taro")
        assert auth.username_const is None and auth.password_const is None and auth.comment == ""

    def test_negotiate_with_ntlmssp_and_with_kerberos(self):
        s = AuthSite()
        s.ntlm_handshake(scheme="Negotiate")
        _groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert (auth.kind, auth.username) == ("negotiate", "EXAMPLE\\taro")
        kerberos = b64(b"\x60\x82\x06\xc3\x06\x06\x2b\x06\x01\x05\x05\x02" + hashlib.sha512(b"krb").digest() * 4)
        s2 = AuthSite()
        s2.add("GET", "/", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", "Negotiate")])
        s2.add("GET", "/", [("Authorization", f"Negotiate {kerberos}")], resp_body=b"<html>ok</html>")
        groups, auth = filters.collapse_auth_handshakes(s2.flows)
        assert ids(groups) == [["f0001", "f0002"]] and (auth.kind, auth.username) == ("negotiate", None)

    def test_basic_and_digest(self):
        s = AuthSite()
        s.basic_handshake(path="/secure/", user="taro", password="p@ss:w0rd")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002"]]
        assert (auth.kind, auth.realm, auth.username, auth.hosts) == ("basic", "Intranet", "taro", ["intra.example.local"])
        d = AuthSite()
        d.add("GET", "/d", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", 'Digest realm="intra@example", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"')])
        d.add("GET", "/d", [("Authorization", 'Digest username="hanako", realm="intra@example", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/d", response="6629fae49393a05397450978507c4ef1"')])
        groups, auth = filters.collapse_auth_handshakes(d.flows)
        assert ids(groups) == [["f0001", "f0002"]] and (auth.kind, auth.realm, auth.username) == ("digest", "intra@example", "hanako")

    def test_401_without_retry_stays_single(self):
        s = AuthSite()
        s.add("GET", "/admin", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", 'Basic realm="x"')])
        s.add("GET", "/other")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001"], ["f0002"]] and auth is None

    def test_retry_must_match_method_url_and_offered_scheme(self):
        s = AuthSite()
        s.add("GET", "/a", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", 'Basic realm="x"')])
        s.add("GET", "/a", [("Authorization", "Bearer abc")])  # wrong scheme
        s.add("GET", "/b", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", "NTLM")])
        s.add("POST", "/b", [("Authorization", f"NTLM {TYPE1}")])  # different method
        s.add("GET", "/c", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", "NTLM")])
        s.add("GET", "/c#frag", [("Authorization", f"NTLM {TYPE3}")])  # fragment ignored -> matches
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001"], ["f0002"], ["f0003"], ["f0004"], ["f0005", "f0006"]]
        assert auth.kind == "ntlm"

    def test_bearer_401_retry_is_not_a_session_handshake(self):
        s = AuthSite()
        s.add("GET", "/api", status=401, resp_headers=[("Content-Type", "application/json"), ("WWW-Authenticate", 'Bearer realm="api", error="invalid_token"')])
        s.add("GET", "/api", [("Authorization", "Bearer freshtoken12345")], resp_headers=[("Content-Type", "application/json")], resp_body=b"{}")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001"], ["f0002"]] and auth is None

    def test_interleaved_handshakes_on_parallel_connections(self):
        s = AuthSite()
        s.add("GET", "/a", status=401, resp_headers=IIS_401 + [("WWW-Authenticate", "NTLM")])                      # f1
        s.add("GET", "/b", status=401, resp_headers=IIS_401 + [("WWW-Authenticate", "NTLM")])                      # f2
        s.add("GET", "/a", [("Authorization", f"NTLM {TYPE1}")], status=401, resp_headers=IIS_401 + [("WWW-Authenticate", f"NTLM {TYPE2}")])  # f3
        s.add("GET", "/b", [("Authorization", f"NTLM {TYPE1}")], status=401, resp_headers=IIS_401 + [("WWW-Authenticate", f"NTLM {TYPE2}")])  # f4
        s.add("GET", "/b", [("Authorization", f"NTLM {TYPE3}")], resp_body=b"<html>b</html>")                       # f5
        s.add("GET", "/a", [("Authorization", f"NTLM {TYPE3}")], resp_body=b"<html>a</html>")                       # f6
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0002", "f0004", "f0005"], ["f0001", "f0003", "f0006"]]
        assert auth.kind == "ntlm" and auth.hosts == ["intra.example.local"]

    def test_unrelated_request_abandons_pending_challenge(self):
        s = AuthSite()
        s.add("GET", "/a", status=401, resp_headers=IIS_401 + [("WWW-Authenticate", "NTLM")])   # f1: cancelled dialog
        s.add("GET", "/public")                                                                  # f2: user browsed elsewhere
        s.add("GET", "/a", [("Authorization", f"NTLM {TYPE1}")], status=401, resp_headers=IIS_401 + [("WWW-Authenticate", f"NTLM {TYPE2}")])  # f3
        s.add("GET", "/a", [("Authorization", f"NTLM {TYPE3}")])                                                     # f4
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001"], ["f0002"], ["f0003", "f0004"]]
        assert auth.kind == "ntlm" and auth.username == "EXAMPLE\\taro"

    def test_rejected_then_accepted_credentials(self):
        """Wrong password: IIS answers the type-3 with a fresh challenge; the browser prompts and
        the handshake restarts on the same URL.  All six hops fold into one group."""
        s = AuthSite()
        s.add("GET", "/", status=401, resp_headers=IIS_401 + [("WWW-Authenticate", "Negotiate"), ("WWW-Authenticate", "NTLM")])
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE1}")], status=401, resp_headers=IIS_401 + [("WWW-Authenticate", f"NTLM {TYPE2}")])
        s.add("GET", "/", [("Authorization", f"NTLM {b64(ntlm_type3(user='wrong'))}")], status=401,
              resp_headers=IIS_401 + [("WWW-Authenticate", "Negotiate"), ("WWW-Authenticate", "NTLM")])
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE1}")], status=401, resp_headers=IIS_401 + [("WWW-Authenticate", f"NTLM {TYPE2}")])
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE3}")])
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002", "f0003", "f0004", "f0005"]]
        assert auth.username == "EXAMPLE\\taro"

    def test_final_attempt_rejected_without_new_challenge(self):
        s = AuthSite()
        s.add("GET", "/", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", 'Basic realm="x"')])
        s.add("GET", "/", [("Authorization", "Basic dXNlcjpiYWQ=")], status=403, resp_body=b"<html>denied</html>")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002"]] and auth.kind == "basic" and auth.username == "user"

    def test_mixed_hosts_first_scheme_wins_and_hosts_merge(self):
        s = AuthSite()
        s.ntlm_handshake(path="/Default.aspx")
        s.basic_handshake(path="http://files.example.local/share/")
        s.ntlm_handshake(path="http://reports.example.local/r.aspx", scheme="Negotiate")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002", "f0003"], ["f0004", "f0005"], ["f0006", "f0007", "f0008"]]
        assert auth.kind == "ntlm" and auth.hosts == ["intra.example.local", "reports.example.local"]

    def test_inferred_from_preemptive_headers_when_no_401_recorded(self):
        s = AuthSite()
        s.add("GET", "/", [("Authorization", "Basic dGFybzpzZWNyZXQ=")])
        s.add("GET", "/x", [("Authorization", "Basic dGFybzpzZWNyZXQ=")])
        s.add("GET", "http://other.example.local/", [("Authorization", "Basic dGFybzpzZWNyZXQ=")])
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001"], ["f0002"], ["f0003"]]
        assert (auth.kind, auth.username, auth.hosts) == ("basic", "taro", ["intra.example.local", "other.example.local"])
        assert "401" in auth.comment
        n = AuthSite()
        n.add("GET", "/", [("Authorization", f"Negotiate {TYPE3}")])
        _g, auth = filters.collapse_auth_handshakes(n.flows)
        assert (auth.kind, auth.username) == ("negotiate", "EXAMPLE\\taro")

    def test_tolerates_missing_responses_and_empty_input(self):
        assert filters.collapse_auth_handshakes([]) == ([], None)
        s = AuthSite()
        s.add("GET", "/", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", "NTLM")])
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE1}")], no_response=True)
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE3}")])
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002"], ["f0003"]]  # the response-less hop ends the chain
        assert auth.kind == "ntlm"


# --------------------------------------------------------------------------- build_plan

class TestPlanNtlm:
    def site(self):
        s = AuthSite()
        s.ntlm_handshake()
        s.add("POST", "/Default.aspx", [("Content-Type", "application/x-www-form-urlencoded"), ("Cookie", "ASP.NET_SessionId=k2p4d0sx1v"),
                                        ("Referer", HOST + "/Default.aspx")],
              body=b"__VIEWSTATE=dDwtMTI3NjU0ODE4Nzs7Pg5QcVUGkTdF&__EVENTVALIDATION=%2FwEWAwLcx6TQBwKU7LvkBgLs0bLrBg%3D%3D&q=report",
              resp_body=b'<html><a class="rpt" href="Report.aspx?id=5678">r</a></html>')
        # a new connection: IE repeats the handshake, then the authenticated request
        s.ntlm_handshake(path="/Report.aspx?id=5678", final_body=b"<html>report</html>")
        return s

    def test_hops_fold_into_steps(self):
        plan = self.site().plan()
        assert [st.func_name for st in plan.steps] == ["step_01_get_default_aspx", "step_02_post_default_aspx", "step_03_get_report_aspx"]
        assert plan.steps[0].source_flow_ids == ["f0001", "f0002", "f0003"]
        assert plan.steps[2].source_flow_ids == ["f0005", "f0006", "f0007"]
        assert plan.steps[0].expected_status == 200 and plan.steps[0].response_kind == "html"
        assert plan.dropped == []  # the 401 hops are neither steps nor noise
        assert plan.meta["flows_total"] == 7 and plan.meta["flows_kept"] == 7 and plan.meta["steps"] == 3 and plan.meta["auth"] == "ntlm"
        assert auth_headers(plan) == []
        assert plan.auth.kind == "ntlm" and plan.auth.username == "EXAMPLE\\taro" and plan.auth.hosts == ["intra.example.local"]
        assert plan.auth.username_const is None and plan.auth.password_const is None
        assert plan.constants == []
        assert any("REQREC_NTLM_USER" in w and "EXAMPLE\\taro" in w for w in plan.warnings)
        # the WebForms hidden fields are traced through the handshake's final response
        exts = {e.name: e for e in plan.steps[0].extractors}
        assert set(exts) == {"__VIEWSTATE", "__EVENTVALIDATION"} and all(e.kind == "html_input" for e in exts.values())
        assert dict(plan.steps[1].form)["__VIEWSTATE"] == Ref.var(exts["__VIEWSTATE"].var)
        (rid,) = plan.steps[1].extractors
        assert rid.kind == "html_attr" and rid.selector == "a.rpt" and dict(plan.steps[2].params)["id"] == Ref.var(rid.var)

    def test_negotiate_header_on_later_request_is_removed(self):
        s = AuthSite()
        s.ntlm_handshake(scheme="Negotiate")
        s.add("GET", "/api/data", [("Authorization", f"Negotiate {TYPE3}"), ("Accept", "application/json")],
              resp_headers=[("Content-Type", "application/json")], resp_body=b"{}")
        s.add("GET", "/api/more", [("Authorization", f"NTLM {TYPE3}")], resp_headers=[("Content-Type", "application/json")], resp_body=b"{}")
        plan = s.plan()
        assert plan.auth.kind == "negotiate"
        assert auth_headers(plan) == [] and len(plan.steps) == 3
        assert plan.constants == []

    def test_detect_auth_disabled_keeps_hops_and_never_leaks_tokens(self):
        plan = self.site().plan(PlanOptions(detect_auth=False, detect_loops=False))
        assert plan.auth is None and plan.final_step_index is None
        assert [st.expected_status for st in plan.steps] == [401, 401, 200, 200, 401, 401, 200]
        hdrs = auth_headers(plan)
        assert len(hdrs) == 4
        for _idx, _name, ref in hdrs:
            assert ref.kind == "expr" and ref.value.startswith('"NTLM " + AUTHORIZATION')
        assert all(c.secret and c.env_var and c.env_var.startswith("REQREC_AUTHORIZATION") for c in plan.constants)
        assert TYPE1 not in repr(plan.steps) and TYPE3 not in repr(plan.steps)
        # --no-redact: tokens sent by several steps become plain (non-secret) constants, as any repeated literal
        plain = self.site().plan(PlanOptions(detect_auth=False, detect_loops=False, redact_secrets=False))
        assert len(auth_headers(plain)) == 4
        assert all(ref.kind == "expr" and ref.value.startswith('"NTLM " + AUTHORIZATION') for _i, _n, ref in auth_headers(plain))
        assert all(not c.secret and c.env_var is None and c.value in (TYPE1, TYPE3) for c in plain.constants)
        assert len(plain.constants) == 2
        # a token used only once stays a literal when secrets are not redacted
        once = AuthSite()
        once.add("GET", "/", [("Authorization", f"NTLM {TYPE3}")])
        plan_once = once.plan(PlanOptions(detect_auth=False, redact_secrets=False))
        assert plan_once.auth is None and auth_headers(plan_once) == [(1, "Authorization", Ref.lit(f"NTLM {TYPE3}"))]

    def test_handshake_inside_redirect_chain(self):
        s = AuthSite()
        s.add("POST", "/login", [("Content-Type", "application/x-www-form-urlencoded")], b"u=taro&p=secret12", status=302,
              resp_headers=[("Location", "/home")])
        s.ntlm_handshake(path="/home", final_body=b"<html>home</html>")
        plan = s.plan()
        assert len(plan.steps) == 1
        assert plan.steps[0].source_flow_ids == ["f0001", "f0002", "f0003", "f0004"]
        assert plan.steps[0].expected_status == 200 and plan.auth.kind == "ntlm"

    def test_failed_handshake_warns(self):
        s = AuthSite()
        s.add("GET", "/", status=401, resp_headers=IIS_401 + [("WWW-Authenticate", "NTLM")])
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE1}")], status=401, resp_headers=IIS_401 + [("WWW-Authenticate", f"NTLM {TYPE2}")])
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE3}")], status=401, resp_headers=IIS_401)
        plan = s.plan()
        assert len(plan.steps) == 1 and plan.steps[0].expected_status == 401 and plan.auth.kind == "ntlm"
        assert any("認証が失敗" in w for w in plan.warnings)

    def test_proxy_authorization_is_never_replayed(self):
        s = AuthSite()
        s.add("GET", "/", [("Proxy-Authorization", "Basic cHJveHk6cHc="), ("Proxy-Connection", "Keep-Alive")])
        plan = s.plan()
        assert all(n.lower() not in ("proxy-authorization", "proxy-connection") for n, _ in plan.steps[0].headers)
        assert plan.auth is None


class TestPlanBasicDigest:
    def test_basic_constants_and_header_stripping(self):
        s = AuthSite()
        _final, token = s.basic_handshake(path="/", user="yamada太郎", password="p@ss:w0rd")
        s.add("GET", "/list", [("Authorization", f"Basic {token}")], resp_body=b"<html>list</html>")
        s.add("POST", "/save", [("Authorization", f"Basic {token}"), ("Content-Type", "application/x-www-form-urlencoded")],
              body=b"owner=yamada%E5%A4%AA%E9%83%8E&note=hello+world", resp_body=b"<html>saved</html>")
        plan = s.plan()
        assert [st.source_flow_ids for st in plan.steps] == [["f0001", "f0002"], ["f0003"], ["f0004"]]
        assert auth_headers(plan) == []
        auth = plan.auth
        assert (auth.kind, auth.realm, auth.username, auth.hosts) == ("basic", "Intranet", "yamada太郎", ["intra.example.local"])
        assert (auth.username_const, auth.password_const) == ("AUTH_USERNAME", "AUTH_PASSWORD")
        consts = {c.name: c for c in plan.constants}
        assert set(consts) == {"AUTH_USERNAME", "AUTH_PASSWORD"}
        assert (consts["AUTH_USERNAME"].value, consts["AUTH_USERNAME"].secret, consts["AUTH_USERNAME"].env_var) == ("yamada太郎", False, None)
        assert (consts["AUTH_PASSWORD"].value, consts["AUTH_PASSWORD"].secret, consts["AUTH_PASSWORD"].env_var) == ("p@ss:w0rd", True, "REQREC_AUTH_PASSWORD")
        assert "Basic" in consts["AUTH_USERNAME"].comment and "REQREC_AUTH_PASSWORD" in consts["AUTH_PASSWORD"].comment
        assert any("REQREC_AUTH_PASSWORD" in w for w in plan.warnings)
        # a form field carrying the same user name reuses the constant
        assert dict(plan.steps[2].form)["owner"] == Ref.var("AUTH_USERNAME")
        assert "step 3" in consts["AUTH_USERNAME"].comment
        assert "p@ss:w0rd" not in repr(plan.steps)

    def test_basic_without_redaction_keeps_password_literal(self):
        s = AuthSite()
        s.basic_handshake(user="taro", password="secret")
        plan = s.plan(PlanOptions(redact_secrets=False))
        consts = {c.name: c for c in plan.constants}
        assert (consts["AUTH_PASSWORD"].value, consts["AUTH_PASSWORD"].secret, consts["AUTH_PASSWORD"].env_var) == ("secret", False, None)
        assert plan.auth.password_const == "AUTH_PASSWORD" and auth_headers(plan) == []
        assert not any("REQREC_AUTH_PASSWORD" in w for w in plan.warnings)

    def test_basic_names_do_not_collide_with_other_constants(self):
        s = AuthSite()
        s.basic_handshake(user="taro", password="secret")
        s.add("POST", "/a", [("Content-Type", "application/x-www-form-urlencoded")], b"auth_username=someone_else&x=1", resp_body=b"<html></html>")
        s.add("POST", "/b", [("Content-Type", "application/x-www-form-urlencoded")], b"auth_username=someone_else&x=2", resp_body=b"<html></html>")
        plan = s.plan()
        names = [c.name for c in plan.constants]
        assert names[:2] == ["AUTH_USERNAME", "AUTH_PASSWORD"] and len(set(names)) == len(names)
        assert dict(plan.steps[1].form)["auth_username"] == Ref.var("AUTH_USERNAME_2")

    def test_basic_with_different_credentials_on_another_host_is_kept_as_secret(self):
        s = AuthSite()
        _final, token = s.basic_handshake(user="taro", password="secret")
        other = base64.b64encode(b"svc:other-pw").decode()
        s.add("GET", "http://files.example.local/x", [("Authorization", f"Basic {other}")], resp_body=b"<html>x</html>")
        s.add("GET", "http://files.example.local/y", [("Authorization", f"Basic {other}")], resp_body=b"<html>y</html>")
        s.add("GET", "http://mirror.example.local/z", [("Authorization", f"Basic {token}")], resp_body=b"<html>z</html>")  # same creds -> stripped
        plan = s.plan()
        hdrs = auth_headers(plan)
        assert [(i, n) for i, n, _r in hdrs] == [(2, "Authorization"), (3, "Authorization")]
        assert all(r == Ref.expr('"Basic " + AUTHORIZATION') for _i, _n, r in hdrs)
        const = next(c for c in plan.constants if c.name == "AUTHORIZATION")
        assert const.secret and const.env_var == "REQREC_AUTHORIZATION" and const.value == other
        assert sum("files.example.local" in w and "対象外" in w for w in plan.warnings) == 1

    def test_mixed_ntlm_then_basic_host(self):
        s = AuthSite()
        s.ntlm_handshake()
        s.basic_handshake(path="http://files.example.local/share/", user="svc", password="pw")
        plan = s.plan()
        assert plan.auth.kind == "ntlm" and plan.auth.hosts == ["intra.example.local"]
        assert [st.source_flow_ids for st in plan.steps] == [["f0001", "f0002", "f0003"], ["f0004", "f0005"]]
        (idx, _name, ref) = auth_headers(plan)[0]
        assert idx == 2 and ref == Ref.expr('"Basic " + AUTHORIZATION')
        assert {c.name for c in plan.constants} == {"AUTHORIZATION"}
        assert any("files.example.local" in w for w in plan.warnings)

    def test_digest_constants_password_always_from_environment(self):
        for redact in (True, False):
            s = AuthSite()
            s.add("GET", "/d", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", 'Digest realm="intra", qop="auth", nonce="n1"')])
            s.add("GET", "/d", [("Authorization", 'Digest username="hanako", realm="intra", nonce="n1", uri="/d", response="abc"')], resp_body=b"<html>d</html>")
            s.add("GET", "/e", [("Authorization", 'Digest username="hanako", realm="intra", nonce="n1", uri="/e", response="def"')], resp_body=b"<html>e</html>")
            plan = s.plan(PlanOptions(redact_secrets=redact))
            assert plan.auth.kind == "digest" and plan.auth.username == "hanako" and plan.auth.realm == "intra"
            consts = {c.name: c for c in plan.constants}
            assert consts["AUTH_USERNAME"].value == "hanako" and consts["AUTH_USERNAME"].secret is False
            assert (consts["AUTH_PASSWORD"].value, consts["AUTH_PASSWORD"].secret, consts["AUTH_PASSWORD"].env_var) == ("", True, "REQREC_AUTH_PASSWORD")
            assert auth_headers(plan) == [] and len(plan.steps) == 2
            assert any("パスワード" in w and "REQREC_AUTH_PASSWORD" in w for w in plan.warnings)

    def test_401_without_retry_is_a_normal_step(self):
        s = AuthSite()
        s.add("GET", "/")
        s.add("GET", "/admin", status=401, resp_headers=AUTH_HTML + [("WWW-Authenticate", 'Basic realm="admin"')], resp_body=b"<html>401</html>")
        s.add("GET", "/public")
        plan = s.plan()
        assert [st.expected_status for st in plan.steps] == [200, 401, 200]
        assert plan.auth is None and plan.constants == [] and plan.dropped == []

    def test_inferred_basic_without_handshake_sets_constants(self):
        s = AuthSite()
        token = base64.b64encode(b"taro:secret").decode()
        s.add("GET", "/", [("Authorization", f"Basic {token}")])
        s.add("GET", "/page", [("Authorization", f"Basic {token}")])
        plan = s.plan()
        assert plan.auth.kind == "basic" and plan.auth.username == "taro" and "401" in plan.auth.comment
        assert auth_headers(plan) == []
        assert {c.name: c.value for c in plan.constants} == {"AUTH_USERNAME": "taro", "AUTH_PASSWORD": "secret"}


# ===== former tests/test_review3_analysis.py: review-3 analysis fixes =====
# Review 3 findings for the deps / plan sections of ``reqrec.analysis`` (DESIGN.md §5, §7, §13.13).
#
# * ``deps.looks_random_letters`` accepts acronym runs anywhere (``txtTokuisakiCD``,
#   ``getXMLHttpRequest``) and still recognises random mixed-case letter tokens, also with ``-`` /
#   ``_`` separators (base64url without digits) and before a file extension - measured here on
#   seeded random tokens;
# * route-like path segments (words, ``Login.aspx``, screen ids ``SC0010.aspx``) stay trace
#   candidates but are only traced through exact structural matches (JSON leaf, header, cookie,
#   ``<input>`` / ``<meta>``), never through markup;
# * the ``Referer`` rewrite replaces whole path segments / query values only (also percent-encoded);
# * every field whose name looks like a credential is read from the environment, whatever its length
#   and even when it equals another field's value.
#
# Plans are built from small recordings; the generated scripts run against ``tests.support``.

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
FORM_CT = ("Content-Type", "application/x-www-form-urlencoded")


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
