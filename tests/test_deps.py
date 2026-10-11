"""Tests for reqrec.deps (DESIGN.md §5)."""

from __future__ import annotations

import json
import re

import pytest
from bs4 import BeautifulSoup

from reqrec import deps
from reqrec.model import Flow, PlanOptions, RecordedRequest, RecordedResponse

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
        # the unfiltered view still exposes scheme prefix and token (plan.py counts repeated tokens with it)
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

def test_locate_in_cookies_latest_first_and_variants():
    f1 = resp_flow(b"", HTML_CT + [("Set-Cookie", "sess=OLD123; Path=/"), ("Set-Cookie", "XSRF-TOKEN=abc%3D%3Dxyz; Path=/")])
    f2 = resp_flow(b"", HTML_CT + [("Set-Cookie", "sess=NEW456; Path=/; HttpOnly"), ("Set-Cookie", "gone=deleted; Max-Age=0")])
    assert deps.locate_in_cookies("NEW456", [f1, f2]) == "sess"
    assert deps.locate_in_cookies("OLD123", [f1, f2]) == "sess"
    assert deps.locate_in_cookies("abc==xyz", [f1, f2]) == "XSRF-TOKEN"  # URL-decoded header vs encoded cookie
    assert deps.locate_in_cookies("abc%3D%3Dxyz", [f1, f2]) == "XSRF-TOKEN"
    assert deps.find_cookie("abc==xyz", [f1, f2]) == ("XSRF-TOKEN", "abc%3D%3Dxyz")
    assert deps.locate_in_cookies("deleted", [f1, f2]) is None
    assert deps.locate_in_cookies("nothing", [f1, f2]) is None
    assert deps.locate_in_cookies("x", []) is None
    assert deps.locate_in_cookies("x", [Flow("n", RecordedRequest("GET", "https://s/"), None)]) is None


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
        assert deps.parse_form_bytes(body) == deps.util.parse_form(body.decode("utf-8"))
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
