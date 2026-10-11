"""Tests for reqrec.filters (DESIGN.md §4)."""

from __future__ import annotations

import pytest

from reqrec import filters
from reqrec.model import Flow, PlanOptions, RecordedRequest, RecordedResponse, Recording


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
