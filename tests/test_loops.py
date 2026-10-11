"""Tests for reqrec.loops (DESIGN.md §6)."""

from __future__ import annotations

import json

from reqrec.loops import detect_loops
from reqrec.model import Flow, PlanOptions, RecordedRequest, RecordedResponse

JSON = [("Content-Type", "application/json")]


def mk(url, method="GET", headers=(), body=None, fid=None, started_at=1700000000.0):
    fid = fid or f"f{abs(hash(url + method + str(body))) % 10000:04d}"
    return Flow(fid, RecordedRequest(method, url, [("User-Agent", "UA")] + list(headers), body),
                RecordedResponse(200, JSON, b"{}"), started_at=started_at)


def groups(*flows):
    return [[f] for f in flows]


def test_query_pagination_numeric_range():
    gs = groups(*(mk(f"https://s/api/items?sort=id&page={p}", headers=[("Referer", f"https://s/p{p}")]) for p in (1, 2, 3, 4)))
    loops = detect_loops(gs, PlanOptions())
    assert len(loops) == 1
    lg = loops[0]
    assert lg.location == "query" and lg.name == "page"
    assert lg.values == ["1", "2", "3", "4"]
    assert lg.numeric_range == (1, 4)
    assert lg.groups == gs
    assert lg.occurrence == 0


def test_descending_and_non_consecutive_and_zero_padded():
    desc = detect_loops(groups(*(mk(f"https://s/x?page={p}") for p in (3, 2, 1))), PlanOptions())
    assert desc[0].numeric_range == (3, 1)
    skip = detect_loops(groups(*(mk(f"https://s/x?offset={p}") for p in (0, 20, 40))), PlanOptions())
    assert skip[0].numeric_range is None and skip[0].values == ["0", "20", "40"]
    padded = detect_loops(groups(*(mk(f"https://s/x?page={p}") for p in ("01", "02", "03"))), PlanOptions())
    assert padded[0].numeric_range is None


def test_needs_three_consecutive_groups():
    assert detect_loops(groups(mk("https://s/x?page=1"), mk("https://s/x?page=2")), PlanOptions()) == []
    gs = groups(mk("https://s/x?page=1"), mk("https://s/x?page=2"), mk("https://s/other"), mk("https://s/x?page=3"))
    assert detect_loops(gs, PlanOptions()) == []


def test_two_differing_values_is_not_a_loop():
    gs = groups(*(mk(f"https://s/x?page={p}&nonce=n{p}") for p in (1, 2, 3)))
    assert detect_loops(gs, PlanOptions()) == []


def test_timestamp_cache_buster_is_ignored():
    gs = groups(*(mk(f"https://s/x?page={p}&_=17000000001{p:02d}") for p in (1, 2, 3)))
    loops = detect_loops(gs, PlanOptions())
    assert len(loops) == 1 and loops[0].name == "page"


def test_identical_requests_are_not_a_loop():
    gs = groups(*(mk("https://s/poll?x=1") for _ in range(3)))
    assert detect_loops(gs, PlanOptions()) == []


def test_differing_headers_break_the_loop_but_referer_is_ignored():
    gs = groups(*(mk(f"https://s/x?page={p}", headers=[("X-Request-Id", f"r{p}")]) for p in (1, 2, 3)))
    assert detect_loops(gs, PlanOptions()) == []
    gs = groups(*(mk(f"https://s/x?page={p}", headers=[("Referer", f"https://s/{p}")]) for p in (1, 2, 3)))
    assert len(detect_loops(gs, PlanOptions())) == 1


def test_form_and_json_and_path_loops():
    form = [("Content-Type", "application/x-www-form-urlencoded")]
    gs = groups(*(mk("https://s/search", "POST", form, f"q=abc&page={p}".encode()) for p in (1, 2, 3)))
    (lg,) = detect_loops(gs, PlanOptions())
    assert (lg.location, lg.name, lg.values) == ("form", "page", ["1", "2", "3"])

    gs = groups(*(mk("https://s/graphql", "POST", JSON, json.dumps({"q": "x", "vars": {"page": p}}).encode()) for p in (1, 2, 3)))
    (lg,) = detect_loops(gs, PlanOptions())
    assert (lg.location, lg.name, lg.values, lg.numeric_range) == ("json", "vars.page", ["1", "2", "3"], (1, 3))

    gs = groups(*(mk(f"https://s/list/page/{p}") for p in (1, 2, 3)))
    (lg,) = detect_loops(gs, PlanOptions())
    assert (lg.location, lg.name, lg.numeric_range) == ("path", "2", (1, 3))


def test_different_segment_count_or_method_breaks():
    gs = groups(mk("https://s/list/1"), mk("https://s/list/2"), mk("https://s/list/3/x"))
    assert detect_loops(gs, PlanOptions()) == []
    gs = groups(mk("https://s/x?p=1"), mk("https://s/x?p=2"), mk("https://s/x?p=3", method="POST"))
    assert detect_loops(gs, PlanOptions()) == []


def test_repeated_param_names_use_occurrence():
    gs = groups(*(mk(f"https://s/x?id=5&id={p}") for p in (7, 8, 9)))
    (lg,) = detect_loops(gs, PlanOptions())
    assert lg.name == "id" and lg.occurrence == 1 and lg.values == ["7", "8", "9"]


def test_loop_uses_first_flow_of_redirect_chains_and_continues_after():
    chain = lambda p: [mk(f"https://s/x?page={p}"), mk(f"https://s/landing?page={p}")]  # noqa: E731
    gs = [chain(1), chain(2), chain(3), [mk("https://s/end")], [mk("https://s/y?page=1")], [mk("https://s/y?page=2")], [mk("https://s/y?page=3")]]
    loops = detect_loops(gs, PlanOptions())
    assert len(loops) == 2
    assert loops[0].groups == gs[:3] and loops[1].groups == gs[4:]


def test_multipart_variation_is_not_a_loop_and_empty_input():
    assert detect_loops([], PlanOptions()) == []
    ct = [("Content-Type", "multipart/form-data; boundary=B")]
    body = lambda p: f"--B\r\nContent-Disposition: form-data; name=\"page\"\r\n\r\n{p}\r\n--B--\r\n".encode()  # noqa: E731
    gs = groups(*(mk("https://s/up", "POST", ct, body(p)) for p in (1, 2, 3)))
    assert detect_loops(gs, PlanOptions()) == []


def test_hash_like_values_are_not_folded():
    # cursor pagination: each cursor comes from the previous response, folding would lose that
    gs = groups(*(mk(f"https://s/x?cursor={c}") for c in ("a1b2c3d4e5f6g7h8", "b2c3d4e5f6g7h8i9", "c3d4e5f6g7h8i9j0")))
    assert detect_loops(gs, PlanOptions()) == []
    gs = groups(*(mk(f"https://s/items/{c}") for c in ("550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001", "550e8400-e29b-41d4-a716-446655440002")))
    assert detect_loops(gs, PlanOptions()) == []
    # word-like path values still fold
    gs = groups(*(mk(f"https://s/cat/{c}") for c in ("books", "music", "games")))
    (lg,) = detect_loops(gs, PlanOptions())
    assert lg.values == ["books", "music", "games"] and lg.numeric_range is None
