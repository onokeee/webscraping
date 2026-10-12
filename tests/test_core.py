"""Tests for the importers section of ``reqrec.py``: HAR / Recording-JSON import (+ ``flow_from_mitm``
used by the recorder addon) and merging recordings.

One section per former test module (headed ``# ===== former tests/<name>.py ... =====``).
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

import reqrec as util
from reqrec import build_plan
from reqrec import Flow, PlanOptions, RecordedRequest, RecordedResponse, Recording, Ref, header_get_all
from reqrec import (
    decode_header_fields, flow_from_mitm, infer_resource_type, load_har,
    load_recording, load_recordings, parse_har_timestamp, recording_from_har,
)


# ===== former tests/test_importers.py: HAR / Recording importers =====
# Tests for reqrec.importers (HAR importer, the load_recording dispatcher and flow_from_mitm, the
# mitmproxy flow converter used by the recorder addon).

FIXTURES = Path(__file__).parent / "fixtures"
CHROME_HAR = FIXTURES / "login_flow_chrome.har"
FIREFOX_HAR = FIXTURES / "api_firefox.har"

try:
    from mitmproxy.test import tflow

    HAVE_MITMPROXY = True
except ImportError:  # HAR tests still run without mitmproxy
    HAVE_MITMPROXY = False

needs_mitmproxy = pytest.mark.skipif(not HAVE_MITMPROXY, reason="mitmproxy not installed")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")


# =========================================================================== Chrome fixture

@pytest.fixture(scope="module")
def chrome() -> Recording:
    return load_har(str(CHROME_HAR))


@pytest.fixture(scope="module")
def firefox() -> Recording:
    return load_har(str(FIREFOX_HAR))


class TestChromeFixture:
    def test_fixture_is_valid_har_json(self):
        with open(CHROME_HAR, encoding="utf-8") as fh:
            doc = json.load(fh)
        assert doc["log"]["version"] == "1.2"
        assert doc["log"]["creator"]["name"] == "WebInspector"
        assert len(doc["log"]["entries"]) == 14
        # The google-analytics ping is deliberately stored last although it happened early.
        assert "google-analytics.com" in doc["log"]["entries"][-1]["request"]["url"]

    def test_flow_count_ids_and_chronological_order(self, chrome: Recording):
        assert len(chrome.flows) == 14
        assert [f.id for f in chrome.flows] == [f"f{i:04d}" for i in range(1, 15)]
        times = [f.started_at for f in chrome.flows]
        assert all(t is not None for t in times)
        assert times == sorted(times)
        # the physically-last GA entry has been sorted to its chronological position (4th)
        assert chrome.flows[3].request.host == "www.google-analytics.com"
        assert chrome.flows[0].request.url == "https://shop.example.test/login"
        assert chrome.flows[-1].request.url == "https://shop.example.test/export?sig=sigHJK789"

    def test_story_order(self, chrome: Recording):
        story = [(f.request.method, f.request.url_without_query) for f in chrome.flows]
        assert story == [
            ("GET", "https://shop.example.test/login"),
            ("GET", "https://shop.example.test/static/app.css"),
            ("GET", "https://shop.example.test/static/logo.png"),
            ("GET", "https://www.google-analytics.com/collect"),
            ("GET", "https://shop.example.test/favicon.ico"),
            ("GET", "https://ads.tracker.example.test/pixel.gif"),
            ("OPTIONS", "https://api.example.test/v1/login"),
            ("POST", "https://shop.example.test/login"),
            ("GET", "https://shop.example.test/dashboard"),
            ("GET", "https://api.example.test/v1/me"),
            ("GET", "https://api.example.test/v1/orgs/77/items"),
            ("GET", "https://api.example.test/v1/orgs/77/items"),
            ("GET", "https://api.example.test/v1/orgs/77/items"),
            ("GET", "https://shop.example.test/export"),
        ]

    def test_timestamps_are_utc_epoch(self, chrome: Recording):
        assert _iso(chrome.flows[0].started_at) == "2025-03-14T09:15:01.123+00:00"

    def test_pseudo_headers_kept_verbatim(self, chrome: Recording):
        headers = chrome.flows[0].request.headers
        assert headers[:4] == [
            (":authority", "shop.example.test"),
            (":method", "GET"),
            (":path", "/login"),
            (":scheme", "https"),
        ]
        assert chrome.flows[0].request.header("user-agent").startswith("Mozilla/5.0")

    def test_resource_types_and_page_refs(self, chrome: Recording):
        assert [f.resource_type for f in chrome.flows] == [
            "document", "stylesheet", "image", "ping", "other", "image", "preflight",
            "document", "document", "xhr", "fetch", "fetch", "fetch", "document",
        ]
        assert [f.page_ref for f in chrome.flows] == ["page_1"] * 7 + ["page_2"] * 6 + ["page_3"]

    def test_login_page_html_decoded(self, chrome: Recording):
        resp = chrome.flows[0].response
        assert resp is not None and resp.status == 200
        assert resp.mime_type == "text/html"
        html = resp.text()
        assert '<input type="hidden" name="_token" value="tokA1b2C3d4E5f6G7h8">' in html
        assert 'name="username"' in html and 'name="password"' in html
        assert "ログイン" in html  # UTF-8 re-encoding round-trips Japanese
        assert resp.set_cookies == ["session=s1Rk9mB2pQ7vX4zL0nH6wC3tY8aD5fG1; path=/; httponly; samesite=lax; secure"]

    def test_static_noise_realism(self, chrome: Recording):
        css = chrome.flows[1]
        assert css.response.header("content-encoding") == "gzip"  # header kept, body already decoded
        assert css.response.text().startswith(":root{--brand:")
        png = chrome.flows[2]
        assert png.response.mime_type == "image/png"
        assert png.response.body.startswith(b"\x89PNG\r\n\x1a\n")  # base64 decoded
        gif = chrome.flows[3]
        assert gif.response.body.startswith(b"GIF89a")
        assert gif.request.header("referer") == "https://shop.example.test/login"
        assert chrome.flows[4].request.url.endswith("/favicon.ico")

    def test_status_zero_gives_no_response(self, chrome: Recording):
        blocked = chrome.flows[5]
        assert blocked.request.host == "ads.tracker.example.test"
        assert blocked.response is None

    def test_cors_preflight(self, chrome: Recording):
        pre = chrome.flows[6]
        assert pre.request.method == "OPTIONS"
        assert pre.request.header("access-control-request-method") == "POST"
        assert pre.response.status == 204
        assert pre.response.body is None
        assert pre.response.mime_type is None  # "x-unknown" is not a mime type

    def test_login_post_and_redirect(self, chrome: Recording):
        post = chrome.flows[7]
        assert post.request.method == "POST"
        assert post.request.content_type == "application/x-www-form-urlencoded"
        assert post.request.body == b"_token=tokA1b2C3d4E5f6G7h8&username=alice&password=Secr3t!"
        assert util.parse_form(post.request.text()) == [
            ("_token", "tokA1b2C3d4E5f6G7h8"), ("username", "alice"), ("password", "Secr3t!"),
        ]
        assert post.request.header("cookie") == "session=s1Rk9mB2pQ7vX4zL0nH6wC3tY8aD5fG1"
        assert post.response.status == 302
        assert post.response.is_redirect
        assert post.response.location == "/dashboard"
        assert post.response.body is None
        assert post.response.set_cookies[0].startswith("session=s2Hf4kP9mW2xV7bN1qZ6cL3yT8rJ5dA0;")

    def test_dashboard_tokens(self, chrome: Recording):
        dash = chrome.flows[8]
        assert dash.request.header("cookie") == "session=s2Hf4kP9mW2xV7bN1qZ6cL3yT8rJ5dA0"
        html = dash.response.text()
        assert '<meta name="csrf-token" content="csrfQ9w8E7r6T5y4">' in html
        assert 'window.API_TOKEN = "apiZ1x2C3v4B5n6M7";' in html
        assert '<a id="export-link" href="/export?sig=sigHJK789">Export</a>' in html

    def test_api_calls(self, chrome: Recording):
        me = chrome.flows[9]
        assert me.request.header("x-csrf-token") == "csrfQ9w8E7r6T5y4"
        assert me.request.header("authorization") == "Bearer apiZ1x2C3v4B5n6M7"
        assert me.response.mime_type == "application/json"
        assert json.loads(me.response.text()) == {
            "id": 4821, "name": "Alice", "email": "alice@example.test",
            "org": {"id": 77, "name": "Example Org"}, "roles": ["member", "exporter"],
        }
        pages = chrome.flows[10:13]
        assert [f.request.query_pairs for f in pages] == [[("page", "1")], [("page", "2")], [("page", "3")]]
        nexts = [json.loads(f.response.text())["next"] for f in pages]
        assert nexts == [2, 3, None]
        for f in pages:
            assert f.request.header("authorization") == "Bearer apiZ1x2C3v4B5n6M7"
            assert f.resource_type == "fetch"
            assert json.loads(f.response.text())["items"]

    def test_csv_export(self, chrome: Recording):
        export = chrome.flows[13]
        assert export.response.mime_type == "text/csv"
        assert export.response.body == b"id,name\n1,foo\n"
        assert export.response.header("content-disposition") == 'attachment; filename="export.csv"'

    def test_meta(self, chrome: Recording):
        assert chrome.meta["source"] == "har"
        assert chrome.meta["file"].endswith("login_flow_chrome.har")
        assert chrome.meta["creator"] == "WebInspector/537.36"
        assert chrome.meta["entries"] == 14
        assert chrome.meta["skipped_entries"] == 0
        datetime.fromisoformat(chrome.meta["imported_at"])  # valid ISO timestamp

    def test_round_trip_through_recording_save_load(self, chrome: Recording, tmp_path: Path):
        out = tmp_path / "rec.json"
        chrome.save(str(out))
        again = Recording.load(str(out))
        assert again.to_dict() == chrome.to_dict()
        assert again.flows[2].response.body == chrome.flows[2].response.body  # binary survives base64


# =========================================================================== Firefox fixture

class TestFirefoxFixture:
    def test_basics(self, firefox: Recording):
        assert len(firefox.flows) == 6
        assert [f.id for f in firefox.flows] == [f"f{i:04d}" for i in range(1, 7)]
        assert firefox.meta["creator"] == "Firefox/125.0.1"
        assert firefox.meta["browser"] == "Firefox/125.0.1"
        assert all(f.resource_type is None for f in firefox.flows)  # Firefox has no _resourceType
        for f in firefox.flows:
            assert not any(k.startswith(":") for k, _ in f.request.headers)

    def test_timezone_offset_parsed(self, firefox: Recording):
        # "2025-03-14T18:20:11.512+09:00" == 09:20:11.512Z
        assert _iso(firefox.flows[0].started_at) == "2025-03-14T09:20:11.512+00:00"
        times = [f.started_at for f in firefox.flows]
        assert times == sorted(times)

    def test_mixed_case_header_names_preserved(self, firefox: Recording):
        names = [k for k, _ in firefox.flows[0].request.headers]
        assert "User-Agent" in names and "Accept-Language" in names and "TE" in names
        assert firefox.flows[0].request.header("user-agent").startswith("Mozilla/5.0 (Macintosh")

    def test_304_response(self, firefox: Recording):
        cached = firefox.flows[1]
        assert cached.response.status == 304
        assert cached.response.body is None
        assert cached.request.header("if-none-match") == '"7d8c9e0f1a2b3c4d"'

    def test_base64_png(self, firefox: Recording):
        png = firefox.flows[2]
        assert png.response.mime_type == "image/png"
        assert png.response.body.startswith(b"\x89PNG")
        assert len(png.response.body) == 68

    def test_json_post(self, firefox: Recording):
        login = firefox.flows[3]
        assert login.request.method == "POST"
        assert login.request.content_type == "application/json"
        assert json.loads(login.request.text()) == {"email": "alice@example.test", "password": "Secr3t!", "remember": True}
        body = json.loads(login.response.text())
        assert body["token_type"] == "Bearer" and body["access_token"].startswith("eyJ")
        assert login.response.mime_type == "application/json"

    def test_set_cookie_synthesised_from_cookies_array(self, firefox: Recording):
        login = firefox.flows[3]
        with open(FIREFOX_HAR, encoding="utf-8") as fh:
            raw = json.load(fh)["log"]["entries"][3]["response"]
        assert not any(h["name"].lower() == "set-cookie" for h in raw["headers"])  # really absent in the file
        assert login.response.set_cookies == [
            "refresh_token=rt_9Lk2Pq7Wz4Xv1Bn8Mc3Yt6Ra0Hd5Fg; Path=/v1/auth; Domain=.example.test; "
            "Expires=Sun, 13 Apr 2025 09:20:25 GMT; HttpOnly; Secure; SameSite=Lax"
        ]

    def test_bearer_request(self, firefox: Recording):
        orders = firefox.flows[4]
        assert orders.request.query_pairs == [("status", "open"), ("limit", "20")]
        assert orders.request.header("authorization").startswith("Bearer eyJ")
        assert json.loads(orders.response.text())["meta"]["count"] == 2

    def test_cookie_header_synthesised_and_shift_jis_reencoded(self, firefox: Recording):
        notice = firefox.flows[5]
        assert notice.request.header("cookie") == "XSRF-TOKEN=xsrf%7CAbC123; lang=ja"
        resp = notice.response
        assert resp.header("content-type") == "text/html; charset=Shift_JIS"
        assert resp.mime_type == "text/html"
        assert "メンテナンスのお知らせ".encode("cp932") in resp.body
        assert "メンテナンスのお知らせ".encode("utf-8") not in resp.body
        assert "３月２０日（木）" in resp.text()  # decode_body picks the charset back up

    def test_round_trip(self, firefox: Recording, tmp_path: Path):
        p = tmp_path / "ff.json"
        firefox.save(str(p))
        assert Recording.load(str(p)).to_dict() == firefox.to_dict()


# =========================================================================== HAR unit tests

def _har(entries, creator=None, extra_log=None):
    log = {"version": "1.2", "creator": creator or {"name": "WebInspector", "version": "537.36"}, "entries": entries}
    if extra_log:
        log.update(extra_log)
    return {"log": log}


def _entry(url="https://example.test/", method="GET", started="2024-01-05T12:34:56.789Z", status=200, **kw):
    e = {
        "startedDateTime": started,
        "request": {"method": method, "url": url, "headers": kw.pop("req_headers", []), "cookies": kw.pop("req_cookies", [])},
        "response": {"status": status, "headers": kw.pop("resp_headers", []), "cookies": kw.pop("resp_cookies", []), "content": kw.pop("content", {"size": 0, "mimeType": "x-unknown"})},
    }
    if "post" in kw:
        e["request"]["postData"] = kw.pop("post")
    e.update(kw)
    return e


class TestHarTimestamps:
    @pytest.mark.parametrize("value, expected", [
        ("2024-01-05T12:34:56.789Z", 1704458096.789),
        ("2024-01-05T21:34:56.789+09:00", 1704458096.789),
        ("2024-01-05T21:34:56.789+0900", 1704458096.789),
        ("2024-01-05T12:34:56Z", 1704458096.0),
        ("2024-01-05T12:34:56.1234567Z", 1704458096.123457),
        ("2024-01-05T12:34:56.1234567+09:00", 1704425696.123457),
        ("2024-01-05T12:34:56", 1704458096.0),  # naive -> UTC
        ("2024-01-05 12:34:56.5+00:00", 1704458096.5),
        (1704458096.789, 1704458096.789),
        (1704458096789, 1704458096.789),  # epoch milliseconds
        ("1704458096", 1704458096.0),
    ])
    def test_parse(self, value, expected):
        assert parse_har_timestamp(value) == pytest.approx(expected, abs=1e-5)

    @pytest.mark.parametrize("value", [None, "", "   ", "not a date", True, [], {}, "2024-13-45T99:00:00Z"])
    def test_garbage(self, value):
        assert parse_har_timestamp(value) is None


class TestHarEntries:
    def test_sorted_by_started_date_time(self):
        rec = recording_from_har(_har([
            _entry("https://example.test/third", started="2024-01-05T12:00:03Z"),
            _entry("https://example.test/first", started="2024-01-05T12:00:01.000+00:00"),
            _entry("https://example.test/second", started="2024-01-05T21:00:02+09:00"),
        ]))
        assert [f.request.url.rsplit("/", 1)[1] for f in rec.flows] == ["first", "second", "third"]
        assert [f.id for f in rec.flows] == ["f0001", "f0002", "f0003"]

    def test_entries_without_timestamp_keep_their_position(self):
        rec = recording_from_har(_har([
            _entry("https://example.test/a", started="2024-01-05T12:00:01Z"),
            _entry("https://example.test/a-then", started=None),
            _entry("https://example.test/b", started="2024-01-05T12:00:02Z"),
            _entry("https://example.test/early", started="2024-01-05T12:00:00Z"),
        ]))
        assert [f.request.path for f in rec.flows] == ["/early", "/a", "/a-then", "/b"]
        assert rec.flows[2].started_at is None

    def test_skips_entries_without_url_and_counts_them(self):
        rec = recording_from_har(_har([
            _entry("https://example.test/ok"),
            {"startedDateTime": "2024-01-05T12:00:00Z", "request": {"method": "GET"}, "response": {"status": 200}},
            {"request": {"method": "GET", "url": ""}},
            {"request": {"method": "GET", "url": None}},
            "not even a dict",
            None,
            {"request": "nope"},
        ]))
        assert [f.request.url for f in rec.flows] == ["https://example.test/ok"]
        assert rec.meta["entries"] == 7
        assert rec.meta["skipped_entries"] == 6

    def test_missing_response_or_status_zero(self):
        rec = recording_from_har(_har([
            _entry("https://example.test/a", status=0),
            {"request": {"method": "GET", "url": "https://example.test/b"}},
            _entry("https://example.test/c", status=None),
            _entry("https://example.test/d", status="200"),
            _entry("https://example.test/e", status=-1),
        ]))
        statuses = [None if f.response is None else f.response.status for f in rec.flows]
        assert statuses == [None, None, None, 200, None]

    def test_minimal_entry_tolerated(self):
        rec = recording_from_har({"log": {"entries": [{"request": {"url": "https://example.test/x"}}]}})
        f = rec.flows[0]
        assert f.request.method == "GET"
        assert f.request.headers == [] and f.request.body is None
        assert f.response is None and f.started_at is None and f.page_ref is None and f.resource_type is None
        assert rec.meta["creator"] == ""

    def test_resource_type_lowercased_and_pageref(self):
        rec = recording_from_har(_har([_entry(_resourceType="XHR", pageref="page_3"), _entry(_resourceType="", pageref="")]))
        assert rec.flows[0].resource_type == "xhr" and rec.flows[0].page_ref == "page_3"
        assert rec.flows[1].resource_type is None and rec.flows[1].page_ref is None

    def test_headers_with_null_values_and_method_case(self):
        rec = recording_from_har(_har([_entry(
            method="post",
            req_headers=[{"name": "X-Empty", "value": None}, {"name": None, "value": "dropped"}, {"name": "Accept", "value": "*/*"}, "junk"],
        )]))
        assert rec.flows[0].request.method == "POST"
        assert rec.flows[0].request.headers == [("X-Empty", ""), ("Accept", "*/*")]

    def test_bare_log_object_and_bad_documents(self):
        rec = recording_from_har({"entries": [_entry()]})
        assert len(rec.flows) == 1
        with pytest.raises(ValueError):
            recording_from_har([])
        with pytest.raises(ValueError):
            recording_from_har({"not": "har"})
        assert recording_from_har({"log": {"entries": "nope"}}).flows == []


class TestHarRequestBody:
    def test_post_data_text_with_charset(self):
        rec = recording_from_har(_har([_entry(
            method="POST",
            req_headers=[{"name": "Content-Type", "value": "application/x-www-form-urlencoded; charset=Shift_JIS"}],
            post={"mimeType": "application/x-www-form-urlencoded; charset=Shift_JIS", "text": "q=日本"},
        )]))
        assert rec.flows[0].request.body == "q=日本".encode("cp932")
        assert rec.flows[0].request.text() == "q=日本"

    def test_post_data_params_are_urlencoded(self):
        rec = recording_from_har(_har([_entry(
            method="POST",
            post={"mimeType": "application/x-www-form-urlencoded", "params": [{"name": "a", "value": "1 2"}, {"name": "b&c", "value": None}, {"name": "d", "value": "日本"}]},
        )]))
        req = rec.flows[0].request
        assert req.body == b"a=1+2&b%26c=&d=%E6%97%A5%E6%9C%AC"
        assert req.header("content-type") == "application/x-www-form-urlencoded"  # added from mimeType
        assert util.parse_form(req.text()) == [("a", "1 2"), ("b&c", ""), ("d", "日本")]

    def test_existing_content_type_header_not_duplicated(self):
        rec = recording_from_har(_har([_entry(
            method="POST",
            req_headers=[{"name": "content-type", "value": "application/json; charset=utf-8"}],
            post={"mimeType": "application/json", "text": '{"a": 1}'},
        )]))
        assert header_get_all(rec.flows[0].request.headers, "content-type") == ["application/json; charset=utf-8"]
        assert rec.flows[0].request.body == b'{"a": 1}'

    def test_multipart_params_rebuilt_with_header_boundary(self):
        rec = recording_from_har(_har([_entry(
            method="POST",
            req_headers=[{"name": "Content-Type", "value": "multipart/form-data; boundary=----WebKitFormBoundaryXYZ"}],
            post={"mimeType": "multipart/form-data", "params": [
                {"name": "title", "value": "hello"},
                {"name": "file", "value": "col1,col2\n", "fileName": "data.csv", "contentType": "text/csv"},
            ]},
        )]))
        body = rec.flows[0].request.body
        assert body.startswith(b"------WebKitFormBoundaryXYZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n")
        assert b'filename="data.csv"\r\nContent-Type: text/csv\r\n\r\ncol1,col2\n\r\n' in body
        assert body.endswith(b"------WebKitFormBoundaryXYZ--\r\n")

    def test_multipart_params_without_boundary_get_consistent_header(self):
        rec = recording_from_har(_har([_entry(method="POST", post={"mimeType": "multipart/form-data", "params": [{"name": "a", "value": "1"}]})]))
        req = rec.flows[0].request
        import re

        boundary = re.search(r"boundary=([^;\s]+)", req.header("content-type")).group(1)
        assert req.header("content-type").startswith("multipart/form-data; boundary=")
        assert req.body.startswith(b"--" + boundary.encode()) and req.body.endswith(b"--" + boundary.encode() + b"--\r\n")

    def test_multipart_quoted_boundary_case_preserved(self):
        rec = recording_from_har(_har([_entry(
            method="POST",
            req_headers=[{"name": "Content-Type", "value": 'multipart/form-data; boundary="MixedCase-Boundary_123"'}],
            post={"mimeType": "multipart/form-data", "params": [{"name": "a", "value": "1"}]},
        )]))
        assert rec.flows[0].request.body.startswith(b"--MixedCase-Boundary_123\r\n")

    def test_base64_post_data(self):
        rec = recording_from_har(_har([_entry(method="POST", post={"mimeType": "application/octet-stream", "text": base64.b64encode(b"\x00\x01\xff").decode(), "encoding": "base64"})]))
        assert rec.flows[0].request.body == b"\x00\x01\xff"

    def test_cookie_header_synthesised_only_when_missing(self):
        rec = recording_from_har(_har([
            _entry(req_cookies=[{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]),
            _entry(req_headers=[{"name": "Cookie", "value": "x=9"}], req_cookies=[{"name": "a", "value": "1"}]),
        ]))
        assert rec.flows[0].request.header("cookie") == "a=1; b=2"
        assert header_get_all(rec.flows[1].request.headers, "cookie") == ["x=9"]


class TestHarResponseBody:
    def test_text_absent_gives_none(self):
        rec = recording_from_har(_har([_entry(content={"size": 0, "mimeType": "text/html"})]))
        assert rec.flows[0].response.body is None
        assert rec.flows[0].response.mime_type == "text/html"

    def test_text_reencoded_with_header_charset(self):
        rec = recording_from_har(_har([_entry(
            resp_headers=[{"name": "Content-Type", "value": "text/html; charset=EUC-JP"}],
            content={"mimeType": "text/html", "text": "<p>日本語</p>"},
        )]))
        resp = rec.flows[0].response
        assert resp.body == "<p>日本語</p>".encode("euc_jp")
        assert resp.text() == "<p>日本語</p>"

    def test_text_reencoded_with_content_mime_charset(self):
        rec = recording_from_har(_har([_entry(content={"mimeType": "text/plain; charset=utf-16", "text": "hi"})]))
        resp = rec.flows[0].response
        assert resp.body == "hi".encode("utf-16")
        assert resp.mime_type == "text/plain"

    def test_meta_charset_in_document_used_when_headers_silent(self):
        html = '<html><head><meta charset="Shift_JIS"></head><body>表示</body></html>'
        rec = recording_from_har(_har([_entry(content={"mimeType": "text/html", "text": html})]))
        assert rec.flows[0].response.body == html.encode("cp932")
        assert rec.flows[0].response.text() == html

    def test_fallback_utf8_and_unencodable_characters_do_not_crash(self):
        rec = recording_from_har(_har([_entry(
            resp_headers=[{"name": "Content-Type", "value": "text/plain; charset=ascii"}],
            content={"mimeType": "text/plain", "text": "a�\udce9b"},
        )]))
        assert rec.flows[0].response.body == b"a??b"

    def test_base64_lenient(self):
        raw = b"\x89PNG\r\n\x1a\n\x00\x00binary"
        b64 = base64.b64encode(raw).decode().rstrip("=")  # padding stripped, whitespace inserted
        b64 = b64[:5] + "\n" + b64[5:]
        rec = recording_from_har(_har([_entry(content={"mimeType": "image/png", "text": b64, "encoding": "base64"})]))
        assert rec.flows[0].response.body == raw

    def test_mislabelled_base64_keeps_text(self):
        rec = recording_from_har(_har([_entry(content={"mimeType": "text/plain", "text": "not base64 at all!!", "encoding": "base64"})]))
        assert rec.flows[0].response.body == b"not base64 at all!!"

    def test_huge_body(self):
        big = "x" * (3 * 1024 * 1024)
        rec = recording_from_har(_har([_entry(content={"mimeType": "text/plain", "text": big})]))
        assert len(rec.flows[0].response.body) == len(big)

    def test_mime_type_fallbacks(self):
        rec = recording_from_har(_har([
            _entry(resp_headers=[{"name": "content-type", "value": "Application/JSON; charset=utf-8"}], content={"mimeType": "x-unknown"}),
            _entry(resp_headers=[{"name": "content-type", "value": "text/plain"}], content={"mimeType": "application/json"}),
            _entry(content={}),
            _entry(content="garbage"),
        ]))
        assert [f.response.mime_type for f in rec.flows] == ["application/json", "application/json", None, None]

    def test_set_cookie_synthesised_with_attributes(self):
        rec = recording_from_har(_har([_entry(resp_cookies=[
            {"name": "sid", "value": "abc", "path": "/", "domain": ".example.test", "expires": "2025-04-13T09:20:25.000Z", "httpOnly": True, "secure": True, "sameSite": "strict"},
            {"name": "plain", "value": "1"},
            {"name": "", "value": "ignored"},
            {"name": "odd", "value": None, "expires": "garbage-date", "httpOnly": False, "secure": "yes"},
        ])]))
        assert rec.flows[0].response.set_cookies == [
            "sid=abc; Path=/; Domain=.example.test; Expires=Sun, 13 Apr 2025 09:20:25 GMT; HttpOnly; Secure; SameSite=Strict",
            "plain=1",
            "odd=; Expires=garbage-date",
        ]

    def test_set_cookie_header_present_wins(self):
        rec = recording_from_har(_har([_entry(
            resp_headers=[{"name": "Set-Cookie", "value": "sid=real; Path=/"}],
            resp_cookies=[{"name": "sid", "value": "real"}, {"name": "other", "value": "x"}],
        )]))
        assert rec.flows[0].response.set_cookies == ["sid=real; Path=/"]


class TestLoadHar:
    def test_bom_and_utf16(self, tmp_path: Path):
        doc = json.dumps(_har([_entry("https://example.test/ボム")]), ensure_ascii=False)
        p1 = tmp_path / "bom.har"
        p1.write_bytes(b"\xef\xbb\xbf" + doc.encode("utf-8"))
        assert load_har(str(p1)).flows[0].request.url == "https://example.test/ボム"
        p2 = tmp_path / "utf16.har"
        p2.write_bytes(doc.encode("utf-16"))
        assert load_har(str(p2)).flows[0].request.url == "https://example.test/ボム"

    def test_invalid_json(self, tmp_path: Path):
        p = tmp_path / "broken.har"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(ValueError, match="JSON"):
            load_har(str(p))

    def test_meta_file_is_source(self, tmp_path: Path):
        p = tmp_path / "x.har"
        p.write_text(json.dumps(_har([_entry()])), encoding="utf-8")
        assert load_har(str(p)).meta["file"] == str(p)


# =========================================================================== load_recording dispatch

class TestLoadRecording:
    def test_har_extension(self):
        rec = load_recording(str(CHROME_HAR))
        assert rec.meta["source"] == "har" and len(rec.flows) == 14

    def test_json_sniffed_as_har(self, tmp_path: Path):
        p = tmp_path / "export.json"
        p.write_text(CHROME_HAR.read_text(encoding="utf-8"), encoding="utf-8")
        assert len(load_recording(str(p)).flows) == 14

    def test_json_sniffed_as_recording(self, tmp_path: Path, chrome: Recording):
        p = tmp_path / "rec.json"
        chrome.save(str(p))
        rec = load_recording(str(p))
        assert rec.to_dict() == chrome.to_dict()
        assert rec.meta["source"] == "har"  # meta preserved from the original import

    def test_json_unknown_shape(self, tmp_path: Path):
        p = tmp_path / "other.json"
        p.write_text('{"hello": "world"}', encoding="utf-8")
        with pytest.raises(ValueError, match="flows"):
            load_recording(str(p))
        p2 = tmp_path / "list.json"
        p2.write_text("[1, 2]", encoding="utf-8")
        with pytest.raises(ValueError):
            load_recording(str(p2))
        p3 = tmp_path / "bad.json"
        p3.write_text("{", encoding="utf-8")
        with pytest.raises(ValueError):
            load_recording(str(p3))

    def test_unknown_extension(self, tmp_path: Path):
        p = tmp_path / "traffic.pcap"
        p.write_bytes(b"\x00")
        with pytest.raises(ValueError, match=r"\.har"):
            load_recording(str(p))
        with pytest.raises(ValueError):
            load_recording(str(tmp_path / "noext"))

    @pytest.mark.parametrize("name", ["flows.mitm", "x.flows", "x.flow"])
    def test_mitmproxy_files_are_not_accepted(self, tmp_path: Path, name: str):
        """Only .har and .json are read; saved mitmproxy flow files are an unknown format."""
        p = tmp_path / name
        p.write_bytes(b"mitmproxy flow file")
        with pytest.raises(ValueError, match=r"\.har") as info:
            load_recording(str(p))
        assert ".har, .json" in str(info.value)

    def test_missing_file(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_recording(str(tmp_path / "missing.har"))


# =========================================================================== flow_from_mitm (shared with the recorder addon)

@needs_mitmproxy
class TestFlowFromMitm:
    def test_request_and_response_fields(self, tmp_path: Path):
        f = tflow.tflow(resp=True)
        f.request.host = "shop.example.test"
        f.request.port = 80
        f.request.scheme = "http"
        f.request.path = "/items?page=2"
        f.request.headers["Host"] = "shop.example.test"
        f.request.headers["Cookie"] = "session=abc"
        f.response.headers["Content-Type"] = "application/json"
        f.response.content = b'{"ok": true}'

        flow = flow_from_mitm(f, "f0001")
        assert flow.id == "f0001"
        assert flow.request.method == "GET"
        assert flow.request.url == "http://shop.example.test/items?page=2"
        assert flow.request.header("cookie") == "session=abc"
        assert flow.request.body == b"content"  # tflow requests carry a body
        assert flow.response.status == 200
        assert flow.response.mime_type == "application/json"
        assert flow.response.body == b'{"ok": true}'
        assert flow.started_at == pytest.approx(f.request.timestamp_start)

        rec = Recording(flows=[flow], meta={"source": "mitmproxy"})
        out = tmp_path / "rec.json"
        rec.save(str(out))
        assert Recording.load(str(out)).to_dict() == rec.to_dict()

    def test_non_utf8_header_bytes(self):
        f = tflow.tflow(resp=True)
        f.request.headers.fields = ((b"X-Weird", b"\xff\xfe\x80abc"), (b"Host", b"example.test"), (b"X-Utf8", "日本".encode("utf-8")))
        flow = flow_from_mitm(f, "f0001")
        assert flow.request.headers == [("X-Weird", "ÿþ\x80abc"), ("Host", "example.test"), ("X-Utf8", "日本")]
        assert flow.request.url == "http://example.test/path"  # pretty_url honours the Host header

    def test_decode_header_fields_tolerates_strings_and_junk(self):
        assert decode_header_fields([("a", "b"), (b"c", b"d"), ("broken",), (None, None)]) == [("a", "b"), ("c", "d"), ("", "")]

    def test_corrupt_content_encoding_falls_back_to_raw(self):
        f = tflow.tflow(resp=True)
        f.response.headers["Content-Encoding"] = "gzip"
        f.response.raw_content = b"definitely not gzip"
        with pytest.raises(ValueError):
            _ = f.response.content
        flow = flow_from_mitm(f, "f0001")
        assert flow.response.body == b"definitely not gzip"

    def test_decoded_content_preferred(self):
        import gzip

        f = tflow.tflow(resp=True)
        f.response.headers["Content-Encoding"] = "gzip"
        f.response.raw_content = gzip.compress(b"<html>hello</html>")
        flow = flow_from_mitm(f, "f0001")
        assert flow.response.body == b"<html>hello</html>"
        assert flow.response.header("content-encoding") == "gzip"  # headers kept exactly as captured

    def test_bodyless_get_is_none_but_typed_empty_post_is_bytes(self):
        get = tflow.tflow(resp=True)
        get.request.content = b""
        assert flow_from_mitm(get, "f1").request.body is None
        post = tflow.tflow(resp=True)
        post.request.method = "POST"
        post.request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        post.request.content = b""
        assert flow_from_mitm(post, "f2").request.body == b""
        empty_resp = tflow.tflow(resp=True)
        empty_resp.response.content = b""
        assert flow_from_mitm(empty_resp, "f3").response.body == b""

    def test_no_response_and_error_flow(self):
        f = tflow.tflow(resp=False, err=True)
        flow = flow_from_mitm(f, "f0007")
        assert flow.id == "f0007" and flow.response is None
        assert flow.page_ref is None

    def test_rejects_non_http_flow(self):
        with pytest.raises(TypeError):
            flow_from_mitm(tflow.ttcpflow(), "f0001")

    def test_resource_type_inferred_from_sec_fetch_dest(self):
        f = tflow.tflow(resp=True)
        f.request.headers["Sec-Fetch-Dest"] = "document"
        assert flow_from_mitm(f, "f1").resource_type == "document"
        f.request.headers["Sec-Fetch-Dest"] = "empty"
        assert flow_from_mitm(f, "f1").resource_type == "fetch"
        f.request.headers["X-Requested-With"] = "XMLHttpRequest"
        assert flow_from_mitm(f, "f1").resource_type == "xhr"
        del f.request.headers["Sec-Fetch-Dest"]
        assert flow_from_mitm(f, "f1").resource_type is None

    @pytest.mark.parametrize("dest, expected", [
        ("style", "stylesheet"), ("script", "script"), ("image", "image"), ("font", "font"), ("video", "media"),
        ("iframe", "document"), ("manifest", "manifest"), ("report", "csp_report"), ("worker", "script"), ("unknown-thing", None),
    ])
    def test_infer_resource_type_table(self, dest, expected):
        assert infer_resource_type([("Sec-Fetch-Dest", dest)]) == expected

    def test_status_and_mime(self):
        f = tflow.tflow(resp=True)
        f.response.status_code = 404
        f.response.headers["content-type"] = "Text/HTML; charset=utf-8"
        flow = flow_from_mitm(f, "f1")
        assert flow.response.status == 404
        assert flow.response.mime_type == "text/html"


# ===== former tests/test_merge.py: merging several recordings (load_recordings) =====
# Tests for ``importers.load_recordings`` (DESIGN.md §13.5): several recordings (one HAR per
# browser tab) merged into one chronological ``Recording``.

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MERGE_CHROME_HAR = os.path.join(ROOT, "tests", "fixtures", "login_flow_chrome.har")
MERGE_FIREFOX_HAR = os.path.join(ROOT, "tests", "fixtures", "api_firefox.har")


def urls(rec: Recording) -> list[str]:
    return [f.request.url for f in rec.flows]


def meta_without_time(meta: dict) -> dict:
    return {k: v for k, v in meta.items() if k != "imported_at"}


# --------------------------------------------------------------------------- the bundled fixtures

def test_two_fixtures_merge_chronologically_with_unique_ids():
    chrome, firefox = load_recording(MERGE_CHROME_HAR), load_recording(MERGE_FIREFOX_HAR)
    merged = load_recordings([MERGE_FIREFOX_HAR, MERGE_CHROME_HAR])  # deliberately out of order
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
    merged = load_recordings([MERGE_CHROME_HAR, MERGE_FIREFOX_HAR])
    assert merged.meta["source"] == "merged"
    sources = merged.meta["sources"]
    assert [s["file"] for s in sources] == [MERGE_CHROME_HAR, MERGE_FIREFOX_HAR]
    assert all(s["source"] == "har" for s in sources)
    assert sources[0]["creator"].startswith("WebInspector") and sources[1]["creator"].startswith("Firefox")


def test_single_path_is_identical_to_load_recording():
    single = load_recording(MERGE_CHROME_HAR)
    for arg in ([MERGE_CHROME_HAR], MERGE_CHROME_HAR, (MERGE_CHROME_HAR,)):
        rec = load_recordings(arg)
        assert [f.to_dict() for f in rec.flows] == [f.to_dict() for f in single.flows]
        assert meta_without_time(rec.meta) == meta_without_time(single.meta)
        assert rec.meta["source"] == "har" and "sources" not in rec.meta


def test_duplicate_paths_are_loaded_once():
    rec = load_recordings([MERGE_CHROME_HAR, os.path.join(os.path.dirname(MERGE_CHROME_HAR), ".", "login_flow_chrome.har"), MERGE_CHROME_HAR])
    assert len(rec.flows) == 14 and rec.meta["source"] == "har"


def test_errors_are_explicit(tmp_path):
    with pytest.raises(ValueError):
        load_recordings([])
    with pytest.raises(FileNotFoundError):
        load_recordings([MERGE_CHROME_HAR, str(tmp_path / "missing.har")])
    bad = tmp_path / "notes.txt"
    bad.write_text("hello", encoding="utf-8")
    with pytest.raises(ValueError) as info:
        load_recordings([str(bad)])
    assert "notes.txt" in str(info.value)


def test_build_plan_on_merged_fixtures():
    plan = build_plan(load_recordings([MERGE_CHROME_HAR, MERGE_FIREFOX_HAR]), PlanOptions())
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
    load_recording(MERGE_CHROME_HAR).save(str(as_json))
    merged = load_recordings([str(as_json), MERGE_FIREFOX_HAR])
    assert len(merged.flows) == 20 and merged.meta["sources"][0]["file"] == MERGE_CHROME_HAR


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
    merged = load_recordings([MERGE_CHROME_HAR, MERGE_FIREFOX_HAR])
    out = tmp_path / "merged.json"
    merged.save(str(out))
    again = load_recordings([str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["meta"]["source"] == "merged"
    assert [f.to_dict() for f in again.flows] == [f.to_dict() for f in merged.flows]
