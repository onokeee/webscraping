"""Tests for HTTP authentication handshake detection (DESIGN.md §13.2).

Covers the parsers in ``reqrec.filters`` (NTLM type-3, Basic, Digest, ``WWW-Authenticate``),
``filters.collapse_auth_handshakes`` on synthetic flows, and what ``plan.build_plan`` makes of
the result (``Plan.auth``, constants, header stripping, 401 hops folded into steps).

The NTLM message builders at the top are also used by the fixture generator for
``tests/fixtures/legacy_webforms_ntlm.har``.
"""

from __future__ import annotations

import base64
import hashlib
import struct

import pytest

from reqrec import filters
from reqrec.model import Flow, PlanOptions, RecordedRequest, RecordedResponse, Recording, Ref
from reqrec.plan import build_plan

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

T0 = 1_700_000_000.0
HOST = "http://intra.example.local"
IE_HEADERS = [
    ("Accept", "text/html, application/xhtml+xml, image/jxr, */*"),
    ("Accept-Language", "ja-JP"),
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"),
    ("Accept-Encoding", "gzip, deflate"),
    ("Host", "intra.example.local"),
    ("Connection", "Keep-Alive"),
]
HTML = [("Content-Type", "text/html")]
IIS_401 = [("Content-Type", "text/html"), ("Server", "Microsoft-IIS/10.0"), ("X-Powered-By", "ASP.NET")]
PAGE = (b'<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"></head>'
        b'<body><form method="post" action="./Default.aspx" id="form1">'
        b'<input type="hidden" name="__VIEWSTATE" value="dDwtMTI3NjU0ODE4Nzs7Pg5QcVUGkTdF" />'
        b'<input type="hidden" name="__EVENTVALIDATION" value="/wEWAwLcx6TQBwKU7LvkBgLs0bLrBg==" />'
        b'</form></body></html>')


class Site:
    def __init__(self, host: str = HOST):
        self.host = host
        self.flows: list[Flow] = []

    def add(self, method, path, req_headers=(), body=None, status=200, resp_headers=HTML, resp_body=b"<html></html>",
            no_response=False, base=True):
        url = path if path.startswith("http") else self.host + path
        headers = (list(IE_HEADERS) if base else []) + list(req_headers)
        resp = None if no_response else RecordedResponse(status, list(resp_headers), resp_body)
        flow = Flow(f"f{len(self.flows) + 1:04d}", RecordedRequest(method, url, headers, body), resp,
                    started_at=T0 + len(self.flows))
        self.flows.append(flow)
        return flow

    def ntlm_handshake(self, path="/Default.aspx", scheme="NTLM", final_status=200, final_body=PAGE,
                       final_headers=None, challenge=("Negotiate", "NTLM"), type3=TYPE3):
        """The three legs IE sends for Integrated Windows Authentication."""
        self.add("GET", path, status=401, resp_headers=IIS_401 + [("WWW-Authenticate", c) for c in challenge])
        self.add("GET", path, [("Authorization", f"{scheme} {TYPE1}")], status=401,
                 resp_headers=IIS_401 + [("WWW-Authenticate", f"{scheme} {TYPE2}")])
        return self.add("GET", path, [("Authorization", f"{scheme} {type3}")], status=final_status,
                        resp_headers=final_headers or (HTML + [("Persistent-Auth", "true"),
                                                               ("Set-Cookie", "ASP.NET_SessionId=k2p4d0sx1v; path=/; HttpOnly")]),
                        resp_body=final_body)

    def basic_handshake(self, path="/", user="taro", password="p@ss:w0rd", realm="Intranet", final_body=b"<html>ok</html>"):
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        self.add("GET", path, status=401, resp_headers=HTML + [("WWW-Authenticate", f'Basic realm="{realm}"')])
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
        s = Site()
        s.ntlm_handshake()
        s.add("POST", "/Default.aspx", [("Content-Type", "application/x-www-form-urlencoded")], b"a=1")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002", "f0003"], ["f0004"]]
        assert auth is not None
        assert (auth.kind, auth.hosts, auth.realm, auth.username) == ("ntlm", ["intra.example.local"], None, "EXAMPLE\\taro")
        assert auth.username_const is None and auth.password_const is None and auth.comment == ""

    def test_negotiate_with_ntlmssp_and_with_kerberos(self):
        s = Site()
        s.ntlm_handshake(scheme="Negotiate")
        _groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert (auth.kind, auth.username) == ("negotiate", "EXAMPLE\\taro")
        kerberos = b64(b"\x60\x82\x06\xc3\x06\x06\x2b\x06\x01\x05\x05\x02" + hashlib.sha512(b"krb").digest() * 4)
        s2 = Site()
        s2.add("GET", "/", status=401, resp_headers=HTML + [("WWW-Authenticate", "Negotiate")])
        s2.add("GET", "/", [("Authorization", f"Negotiate {kerberos}")], resp_body=b"<html>ok</html>")
        groups, auth = filters.collapse_auth_handshakes(s2.flows)
        assert ids(groups) == [["f0001", "f0002"]] and (auth.kind, auth.username) == ("negotiate", None)

    def test_basic_and_digest(self):
        s = Site()
        s.basic_handshake(path="/secure/", user="taro", password="p@ss:w0rd")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002"]]
        assert (auth.kind, auth.realm, auth.username, auth.hosts) == ("basic", "Intranet", "taro", ["intra.example.local"])
        d = Site()
        d.add("GET", "/d", status=401, resp_headers=HTML + [("WWW-Authenticate", 'Digest realm="intra@example", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"')])
        d.add("GET", "/d", [("Authorization", 'Digest username="hanako", realm="intra@example", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/d", response="6629fae49393a05397450978507c4ef1"')])
        groups, auth = filters.collapse_auth_handshakes(d.flows)
        assert ids(groups) == [["f0001", "f0002"]] and (auth.kind, auth.realm, auth.username) == ("digest", "intra@example", "hanako")

    def test_401_without_retry_stays_single(self):
        s = Site()
        s.add("GET", "/admin", status=401, resp_headers=HTML + [("WWW-Authenticate", 'Basic realm="x"')])
        s.add("GET", "/other")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001"], ["f0002"]] and auth is None

    def test_retry_must_match_method_url_and_offered_scheme(self):
        s = Site()
        s.add("GET", "/a", status=401, resp_headers=HTML + [("WWW-Authenticate", 'Basic realm="x"')])
        s.add("GET", "/a", [("Authorization", "Bearer abc")])  # wrong scheme
        s.add("GET", "/b", status=401, resp_headers=HTML + [("WWW-Authenticate", "NTLM")])
        s.add("POST", "/b", [("Authorization", f"NTLM {TYPE1}")])  # different method
        s.add("GET", "/c", status=401, resp_headers=HTML + [("WWW-Authenticate", "NTLM")])
        s.add("GET", "/c#frag", [("Authorization", f"NTLM {TYPE3}")])  # fragment ignored -> matches
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001"], ["f0002"], ["f0003"], ["f0004"], ["f0005", "f0006"]]
        assert auth.kind == "ntlm"

    def test_bearer_401_retry_is_not_a_session_handshake(self):
        s = Site()
        s.add("GET", "/api", status=401, resp_headers=[("Content-Type", "application/json"), ("WWW-Authenticate", 'Bearer realm="api", error="invalid_token"')])
        s.add("GET", "/api", [("Authorization", "Bearer freshtoken12345")], resp_headers=[("Content-Type", "application/json")], resp_body=b"{}")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001"], ["f0002"]] and auth is None

    def test_interleaved_handshakes_on_parallel_connections(self):
        s = Site()
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
        s = Site()
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
        s = Site()
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
        s = Site()
        s.add("GET", "/", status=401, resp_headers=HTML + [("WWW-Authenticate", 'Basic realm="x"')])
        s.add("GET", "/", [("Authorization", "Basic dXNlcjpiYWQ=")], status=403, resp_body=b"<html>denied</html>")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002"]] and auth.kind == "basic" and auth.username == "user"

    def test_mixed_hosts_first_scheme_wins_and_hosts_merge(self):
        s = Site()
        s.ntlm_handshake(path="/Default.aspx")
        s.basic_handshake(path="http://files.example.local/share/")
        s.ntlm_handshake(path="http://reports.example.local/r.aspx", scheme="Negotiate")
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002", "f0003"], ["f0004", "f0005"], ["f0006", "f0007", "f0008"]]
        assert auth.kind == "ntlm" and auth.hosts == ["intra.example.local", "reports.example.local"]

    def test_inferred_from_preemptive_headers_when_no_401_recorded(self):
        s = Site()
        s.add("GET", "/", [("Authorization", "Basic dGFybzpzZWNyZXQ=")])
        s.add("GET", "/x", [("Authorization", "Basic dGFybzpzZWNyZXQ=")])
        s.add("GET", "http://other.example.local/", [("Authorization", "Basic dGFybzpzZWNyZXQ=")])
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001"], ["f0002"], ["f0003"]]
        assert (auth.kind, auth.username, auth.hosts) == ("basic", "taro", ["intra.example.local", "other.example.local"])
        assert "401" in auth.comment
        n = Site()
        n.add("GET", "/", [("Authorization", f"Negotiate {TYPE3}")])
        _g, auth = filters.collapse_auth_handshakes(n.flows)
        assert (auth.kind, auth.username) == ("negotiate", "EXAMPLE\\taro")

    def test_tolerates_missing_responses_and_empty_input(self):
        assert filters.collapse_auth_handshakes([]) == ([], None)
        s = Site()
        s.add("GET", "/", status=401, resp_headers=HTML + [("WWW-Authenticate", "NTLM")])
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE1}")], no_response=True)
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE3}")])
        groups, auth = filters.collapse_auth_handshakes(s.flows)
        assert ids(groups) == [["f0001", "f0002"], ["f0003"]]  # the response-less hop ends the chain
        assert auth.kind == "ntlm"


# --------------------------------------------------------------------------- build_plan

class TestPlanNtlm:
    def site(self):
        s = Site()
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
        s = Site()
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
        once = Site()
        once.add("GET", "/", [("Authorization", f"NTLM {TYPE3}")])
        plan_once = once.plan(PlanOptions(detect_auth=False, redact_secrets=False))
        assert plan_once.auth is None and auth_headers(plan_once) == [(1, "Authorization", Ref.lit(f"NTLM {TYPE3}"))]

    def test_handshake_inside_redirect_chain(self):
        s = Site()
        s.add("POST", "/login", [("Content-Type", "application/x-www-form-urlencoded")], b"u=taro&p=secret12", status=302,
              resp_headers=[("Location", "/home")])
        s.ntlm_handshake(path="/home", final_body=b"<html>home</html>")
        plan = s.plan()
        assert len(plan.steps) == 1
        assert plan.steps[0].source_flow_ids == ["f0001", "f0002", "f0003", "f0004"]
        assert plan.steps[0].expected_status == 200 and plan.auth.kind == "ntlm"

    def test_failed_handshake_warns(self):
        s = Site()
        s.add("GET", "/", status=401, resp_headers=IIS_401 + [("WWW-Authenticate", "NTLM")])
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE1}")], status=401, resp_headers=IIS_401 + [("WWW-Authenticate", f"NTLM {TYPE2}")])
        s.add("GET", "/", [("Authorization", f"NTLM {TYPE3}")], status=401, resp_headers=IIS_401)
        plan = s.plan()
        assert len(plan.steps) == 1 and plan.steps[0].expected_status == 401 and plan.auth.kind == "ntlm"
        assert any("認証が失敗" in w for w in plan.warnings)

    def test_proxy_authorization_is_never_replayed(self):
        s = Site()
        s.add("GET", "/", [("Proxy-Authorization", "Basic cHJveHk6cHc="), ("Proxy-Connection", "Keep-Alive")])
        plan = s.plan()
        assert all(n.lower() not in ("proxy-authorization", "proxy-connection") for n, _ in plan.steps[0].headers)
        assert plan.auth is None


class TestPlanBasicDigest:
    def test_basic_constants_and_header_stripping(self):
        s = Site()
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
        s = Site()
        s.basic_handshake(user="taro", password="secret")
        plan = s.plan(PlanOptions(redact_secrets=False))
        consts = {c.name: c for c in plan.constants}
        assert (consts["AUTH_PASSWORD"].value, consts["AUTH_PASSWORD"].secret, consts["AUTH_PASSWORD"].env_var) == ("secret", False, None)
        assert plan.auth.password_const == "AUTH_PASSWORD" and auth_headers(plan) == []
        assert not any("REQREC_AUTH_PASSWORD" in w for w in plan.warnings)

    def test_basic_names_do_not_collide_with_other_constants(self):
        s = Site()
        s.basic_handshake(user="taro", password="secret")
        s.add("POST", "/a", [("Content-Type", "application/x-www-form-urlencoded")], b"auth_username=someone_else&x=1", resp_body=b"<html></html>")
        s.add("POST", "/b", [("Content-Type", "application/x-www-form-urlencoded")], b"auth_username=someone_else&x=2", resp_body=b"<html></html>")
        plan = s.plan()
        names = [c.name for c in plan.constants]
        assert names[:2] == ["AUTH_USERNAME", "AUTH_PASSWORD"] and len(set(names)) == len(names)
        assert dict(plan.steps[1].form)["auth_username"] == Ref.var("AUTH_USERNAME_2")

    def test_basic_with_different_credentials_on_another_host_is_kept_as_secret(self):
        s = Site()
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
        s = Site()
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
            s = Site()
            s.add("GET", "/d", status=401, resp_headers=HTML + [("WWW-Authenticate", 'Digest realm="intra", qop="auth", nonce="n1"')])
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
        s = Site()
        s.add("GET", "/")
        s.add("GET", "/admin", status=401, resp_headers=HTML + [("WWW-Authenticate", 'Basic realm="admin"')], resp_body=b"<html>401</html>")
        s.add("GET", "/public")
        plan = s.plan()
        assert [st.expected_status for st in plan.steps] == [200, 401, 200]
        assert plan.auth is None and plan.constants == [] and plan.dropped == []

    def test_inferred_basic_without_handshake_sets_constants(self):
        s = Site()
        token = base64.b64encode(b"taro:secret").decode()
        s.add("GET", "/", [("Authorization", f"Basic {token}")])
        s.add("GET", "/page", [("Authorization", f"Basic {token}")])
        plan = s.plan()
        assert plan.auth.kind == "basic" and plan.auth.username == "taro" and "401" in plan.auth.comment
        assert auth_headers(plan) == []
        assert {c.name: c.value for c in plan.constants} == {"AUTH_USERNAME": "taro", "AUTH_PASSWORD": "secret"}
