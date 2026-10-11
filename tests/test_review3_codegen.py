"""Review 3 findings for ``reqrec.codegen`` / ``reqrec.util`` (DESIGN.md §13.13).

The shared download rule (the generated scripts and the GUI's 「保存されるファイル」 list agree):

1. a response *is an attachment* when ``Content-Disposition`` (stripped, lower-cased) starts with
   ``attachment``, or contains ``filename`` and does not start with ``inline``;
2. a step's response is saved when ``response_kind == "binary"`` (always) or when it is an
   attachment at run time - for every step kind (``html`` included), non-loop steps and every
   iteration of a loop step;
3. the final (printed) step is saved right after its own call; the final block only prints;
4. names are unique within one run (``name (2).ext``, ``(3)``); a previous run's file is overwritten.

Also: the required-secret check in ``main()`` tests the *constants* (a value typed into the
constant block works) and covers the Basic / Digest password even when nothing was recorded;
RFC 2047 file names, Windows reserved names and over-long names.  Plans are built by hand and the
scripts run against ``tests.e2e.mock_adapter``; at the end every fixture recording is generated
with several option sets and compiled.
"""

from __future__ import annotations

import ast
import base64
import io
import os
import tokenize
import warnings
from pathlib import Path

import pytest
import requests

from reqrec import util
from reqrec.codegen import CodegenError, generate
from reqrec.importers import load_recording
from reqrec.model import AuthInfo, Constant, Extractor, GenOptions, Loop, Plan, PlanOptions, Ref, Step
from reqrec.plan import build_plan
from tests.e2e.mock_adapter import MockAdapter, Rule, run_generated

H = "https://example.test"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


# =========================================================================== helpers

def check_format(src: str) -> None:
    """Trailing newline, no trailing whitespace, Python 3.8 grammar, compiles with warnings as errors."""
    assert src.endswith("\n") and not src.endswith("\n\n")
    for i, line in enumerate(src.split("\n"), 1):
        assert line == line.rstrip(), f"trailing whitespace on line {i}: {line!r}"
    ast.parse(src, feature_version=(3, 8))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        compile(src, "<gen>", "exec")


def comment_tokens(src: str) -> list[str]:
    return [t.string for t in tokenize.generate_tokens(io.StringIO(src).readline) if t.type == tokenize.COMMENT]


def main_source(src: str) -> str:
    return src[src.index("def main():"):]


def step(index: int, method: str, path: str, **kw) -> Step:
    url = kw.pop("url", None) or [Ref.lit(H + path)]
    kw.setdefault("response_kind", "json")
    slug = path.strip("/").replace("/", "_").replace(".", "_").lower() or "root"
    func = kw.pop("func", None) or f"step_{index:02d}_{method.lower()}_{slug}"
    return Step(index=index, func_name=func, method=method, url=url, **kw)


def exec_module(src: str) -> dict:
    """Execute the generated module (definitions only, ``main()`` is not called)."""
    ns: dict = {"__name__": "generated_under_test"}
    exec(compile(src, "<gen>", "exec"), ns)
    return ns


def fake_response(disposition: str | None, url: str = H + "/Export.aspx", content_type: str = XLSX) -> requests.Response:
    resp = requests.Response()
    resp.status_code = 200
    resp._content = b"PK"
    resp.url = url
    resp.headers["Content-Type"] = content_type
    if disposition is not None:
        resp.headers["Content-Disposition"] = disposition
    return resp


def b64_word(text: str, charset: str = "UTF-8", codec: str = "utf-8") -> str:
    return f"=?{charset}?B?{base64.b64encode(text.encode(codec)).decode('ascii')}?="


@pytest.fixture
def outdir(tmp_path, monkeypatch):
    out = tmp_path / "out"
    monkeypatch.setenv("REQREC_OUTPUT_DIR", str(out))
    return out


def files_in(folder: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in folder.iterdir()} if folder.exists() else {}


# =========================================================================== required secrets

def password_plan(value: str = "recorded-pw") -> Plan:
    s1 = step(1, "POST", "/Login.aspx", body_kind="form", response_kind="html",
              form=[("txtUser", Ref.lit("taro")), ("txtPassword", Ref.var("TXT_PASSWORD"))])
    const = Constant("TXT_PASSWORD", value, secret=True, env_var="REQREC_TXT_PASSWORD")
    return Plan(steps=[s1], constants=[const])


def login_adapter() -> MockAdapter:
    return MockAdapter([Rule(H + "/Login.aspx", body="<html><head><title>メニュー</title></head></html>",
                             content_type="text/html; charset=utf-8")])


class TestRequiredSecrets:
    ASSIGN = "TXT_PASSWORD = os.environ.get('REQREC_TXT_PASSWORD', '')"

    def test_check_tests_the_constant(self, monkeypatch):
        monkeypatch.delenv("REQREC_TXT_PASSWORD", raising=False)
        src = generate(password_plan())
        check_format(src)
        assert "missing = [env for env, value in [('REQREC_TXT_PASSWORD', TXT_PASSWORD)] if not value]" in src
        assert "os.environ.get(name)" not in src
        adapter = login_adapter()
        with pytest.raises(SystemExit) as info:
            run_generated(src, adapter)
        assert "REQREC_TXT_PASSWORD" in str(info.value.code) and "設定されていません" in str(info.value.code)
        assert adapter.calls == []  # nothing is sent with an empty password

    @pytest.mark.parametrize("replacement", [
        "TXT_PASSWORD = 'typed-in'",                                   # the constant overwritten
        "TXT_PASSWORD = os.environ.get('REQREC_TXT_PASSWORD', 'typed-in')",  # the default filled in
    ])
    def test_value_typed_into_the_constant_block_runs(self, monkeypatch, replacement):
        monkeypatch.delenv("REQREC_TXT_PASSWORD", raising=False)
        src = generate(password_plan())
        assert src.count(self.ASSIGN) == 1
        edited = src.replace(self.ASSIGN, replacement)
        adapter = login_adapter()
        assert run_generated(edited, adapter) == "メニュー\n"
        assert adapter.calls[0].form == {"txtUser": "taro", "txtPassword": "typed-in"}

    def test_environment_variable_still_works(self):
        adapter = login_adapter()
        run_generated(generate(password_plan()), adapter, env={"REQREC_TXT_PASSWORD": "from-env"})
        assert adapter.calls[0].form["txtPassword"] == "from-env"

    def test_secret_recorded_empty_stays_optional(self, monkeypatch):
        monkeypatch.delenv("REQREC_TXT_PASSWORD", raising=False)
        src = generate(password_plan(value=""))
        assert "missing" not in src
        adapter = login_adapter()
        run_generated(src, adapter)
        assert adapter.calls[0].form["txtPassword"] == ""

    @staticmethod
    def auth_plan(kind: str, with_constants: bool = True) -> Plan:
        host = "https://intra.example.test"
        s1 = step(1, "GET", "/secure", url=[Ref.lit(host + "/secure")])
        auth = AuthInfo(kind=kind, hosts=["intra.example.test"], username="alice")
        constants: list[Constant] = []
        if with_constants:
            auth.username_const, auth.password_const = "AUTH_USERNAME", "AUTH_PASSWORD"
            constants = [Constant("AUTH_USERNAME", "alice"),
                         Constant("AUTH_PASSWORD", "", secret=True, env_var="REQREC_AUTH_PASSWORD")]
        return Plan(steps=[s1], constants=constants, auth=auth)

    @pytest.mark.parametrize("kind,with_constants", [("digest", True), ("basic", True), ("basic", False), ("digest", False)])
    def test_basic_digest_password_is_required_even_when_not_recorded(self, monkeypatch, kind, with_constants):
        """A Digest password is never on the wire and a synthesised AUTH_PASSWORD has no value:
        both are recorded as '' yet the site cannot be used without them."""
        monkeypatch.delenv("REQREC_AUTH_PASSWORD", raising=False)
        plan = self.auth_plan(kind, with_constants)
        src = generate(plan)
        check_format(src)
        assert "[('REQREC_AUTH_PASSWORD', AUTH_PASSWORD)]" in src
        adapter = MockAdapter([Rule("https://intra.example.test/secure", body={"ok": True})])
        with pytest.raises(SystemExit) as info:
            run_generated(src, adapter)
        assert "REQREC_AUTH_PASSWORD" in str(info.value.code)
        assert adapter.calls == []
        assert run_generated(src, adapter, env={"REQREC_AUTH_PASSWORD": "pw"}) == '{\n  "ok": true\n}\n'

    def test_non_secret_basic_password_is_not_checked(self):
        plan = self.auth_plan("basic")
        plan.constants[1] = Constant("AUTH_PASSWORD", "recorded", secret=False)
        src = generate(plan)
        assert "missing" not in src and "AUTH_PASSWORD = 'recorded'" in src

    @pytest.mark.parametrize("kind", ["ntlm", "negotiate"])
    def test_windows_authentication_requires_nothing(self, kind):
        plan = Plan(steps=[step(1, "GET", "/Default.aspx", response_kind="html")],
                    auth=AuthInfo(kind=kind, hosts=["example.test"], username="EXAMPLE\\taro"))
        src = generate(plan)
        check_format(src)
        assert "missing" not in src and "REQREC_NTLM_PASSWORD" in src

    def test_several_secrets_are_listed_one_per_line_and_comment_free(self, monkeypatch):
        for env in ("REQREC_A_PASSWORD", "REQREC_B_TOKEN", "REQREC_AUTH_PASSWORD"):
            monkeypatch.delenv(env, raising=False)
        plan = self.auth_plan("basic")
        plan.constants += [Constant("A_PASSWORD", "x", secret=True, env_var="REQREC_A_PASSWORD"),
                           Constant("B_TOKEN", "y", secret=True, env_var="REQREC_B_TOKEN")]
        for comments in (True, False):
            src = generate(plan, GenOptions(comments=comments))
            check_format(src)
            assert "missing = [env for env, value in [\n" in src and "] if not value]" in src
            for pair in ("('REQREC_AUTH_PASSWORD', AUTH_PASSWORD),", "('REQREC_A_PASSWORD', A_PASSWORD),",
                         "('REQREC_B_TOKEN', B_TOKEN),"):
                assert pair in src
            if not comments:
                assert comment_tokens(src) == []
        with pytest.raises(SystemExit) as info:
            run_generated(src, MockAdapter(), env={"REQREC_A_PASSWORD": "set"})
        assert str(info.value.code).startswith("環境変数 REQREC_AUTH_PASSWORD, REQREC_B_TOKEN が設定されていません")


# =========================================================================== attachment rule (1)

ATTACHMENT_CASES = [
    ("attachment", True),
    ("Attachment; filename=a.csv", True),
    ("  attachment;filename*=UTF-8''a.csv", True),
    ('filename="report.xlsx"', True),          # no disposition type, but names a file
    ("form-data; name=x; filename=a.bin", True),
    ("inline; filename=f.txt", False),         # Spring's RFD protection on every JSON response
    ("INLINE; FileName=\"x.json\"", False),
    ("  inline;filename*=UTF-8''f.txt", False),
    ("inline", False),
    ("", False),
    (None, False),
]


@pytest.mark.parametrize("value,expected", ATTACHMENT_CASES)
def test_util_is_attachment_disposition(value, expected):
    assert util.is_attachment_disposition(value) is expected


@pytest.mark.parametrize("value,expected", ATTACHMENT_CASES)
def test_generated_is_attachment_matches_util(value, expected):
    ns = exec_module(generate(Plan(steps=[step(1, "GET", "/x")])))
    assert ns["_is_attachment"](fake_response(value)) is expected


class TestInlineIsNotADownload:
    def test_final_json_with_inline_filename_is_pretty_printed_not_saved(self, outdir):
        plan = Plan(steps=[step(1, "GET", "/api/a"), step(2, "GET", "/api/b")])
        adapter = MockAdapter([
            Rule(H + "/api/a", body={"a": 1}, headers={"Content-Disposition": "inline;filename=f.txt"}),
            Rule(H + "/api/b", body={"名前": "値"}, headers={"Content-Disposition": "inline;filename=f.txt"}),
        ])
        out = run_generated(generate(plan), adapter)
        assert out == '{\n  "名前": "値"\n}\n'
        assert files_in(outdir) == {}

    def test_final_json_attachment_is_saved_and_previewed(self, outdir):
        plan = Plan(steps=[step(1, "GET", "/api/export")])
        adapter = MockAdapter([Rule(H + "/api/export", body={"rows": [1, 2]},
                                    headers={"Content-Disposition": "attachment; filename=rows.json"})])
        out = run_generated(generate(plan), adapter)
        assert files_in(outdir) == {"rows.json": b'{"rows": [1, 2]}'}
        assert out.count("に保存しました") == 1 and out.endswith('{"rows": [1, 2]}\n')


# =========================================================================== saving rule (2) / (3)

class TestEveryKindIsSaved:
    HTML_XLS = "<table><tr><td>品番</td><td>数量</td></tr><tr><td>A-1</td><td>3</td></tr></table>".encode("cp932")

    def test_html_attachment_in_the_middle_is_saved(self, outdir):
        """An "Excel export" that is really an HTML table served as text/html."""
        plan = Plan(steps=[
            step(1, "POST", "/List.aspx", response_kind="html"),
            step(2, "GET", "/Menu.aspx", response_kind="html"),
            step(3, "GET", "/api/done"),
        ])
        adapter = MockAdapter([
            Rule(H + "/List.aspx", body=self.HTML_XLS, content_type="text/html; charset=Shift_JIS",
                 headers={"Content-Disposition": "attachment; filename=list.xls"}),
            Rule(H + "/Menu.aspx", body="<html><title>menu</title></html>", content_type="text/html"),
            Rule(H + "/api/done", body={"done": True}),
        ])
        src = generate(plan)
        check_format(src)
        out = run_generated(src, adapter)
        assert files_in(outdir) == {"list.xls": self.HTML_XLS}  # the ordinary page is not saved
        assert "list.xls に保存しました" in out

    @pytest.mark.parametrize("kind", ["html", "text", "xml", "json", "empty"])
    def test_every_kind_gets_the_attachment_check(self, kind):
        plan = Plan(steps=[step(1, "GET", "/a", response_kind=kind), step(2, "GET", "/b", response_kind=kind)])
        main = main_source(generate(plan))
        assert main.count("_save_if_attachment(resp)") == 2
        assert "_save_download(" not in main

    def test_html_final_attachment_is_saved_once_and_not_parsed(self, outdir):
        plan = Plan(steps=[step(1, "POST", "/List.aspx", response_kind="html")])
        src = generate(plan)
        main = main_source(src)
        assert "final_saved = _save_if_attachment(resp)" in main
        assert main.count("_save_") == 1  # the final block never saves a second time
        adapter = MockAdapter([Rule(H + "/List.aspx", body=self.HTML_XLS, content_type="text/html",
                                    headers={"Content-Disposition": 'attachment; filename="list.xls"'})])
        out = run_generated(src, adapter)
        assert files_in(outdir) == {"list.xls": self.HTML_XLS}
        assert out.count("に保存しました") == 1 and len(out.splitlines()) == 1

    def test_html_final_page_is_still_printed(self, outdir):
        plan = Plan(steps=[step(1, "GET", "/Menu.aspx", response_kind="html")])
        adapter = MockAdapter([Rule(H + "/Menu.aspx", body="<html><title>メニュー</title></html>",
                                    content_type="text/html; charset=utf-8")])
        assert run_generated(generate(plan), adapter) == "メニュー\n"
        assert files_in(outdir) == {}

    def test_empty_final_attachment(self, outdir):
        plan = Plan(steps=[step(1, "GET", "/zero.csv", response_kind="empty")])
        adapter = MockAdapter([Rule(H + "/zero.csv", body=b"", headers={"Content-Disposition": "attachment; filename=zero.csv"})])
        out = run_generated(generate(plan), adapter)
        assert files_in(outdir) == {"zero.csv": b""} and "(0 バイト)" in out and H not in out

    def test_mid_run_final_download_survives_a_later_failure(self, outdir):
        plan = Plan(steps=[
            step(1, "POST", "/Export.aspx", response_kind="binary"),
            step(2, "GET", "/Broken.aspx", response_kind="html"),
        ], final_step_index=1)
        src = generate(plan)
        check_format(src)
        main = main_source(src)
        assert main.index("_save_download(resp)") < main.index("step_02_get_broken_aspx(")
        assert main.count("_save_") == 2  # step 1 saves, step 2 checks; the final block does not
        adapter = MockAdapter([
            Rule(H + "/Export.aspx", body=b"PK-final", content_type=XLSX,
                 headers={"Content-Disposition": "attachment; filename=final.xlsx"}),
            Rule(H + "/Broken.aspx", status=500, body="boom", content_type="text/plain"),
        ])
        with pytest.raises(requests.HTTPError):
            run_generated(src, adapter)
        assert files_in(outdir) == {"final.xlsx": b"PK-final"}

    def test_mid_run_final_text_attachment_saved_before_later_steps(self, outdir):
        plan = Plan(steps=[step(1, "GET", "/Export.aspx", response_kind="text"), step(2, "GET", "/api/next")],
                    final_step_index=1)
        csv = "品番,数量\nA-1,3\n".encode("cp932")
        adapter = MockAdapter([
            Rule(H + "/Export.aspx", body=csv, content_type="text/csv; charset=Shift_JIS",
                 headers={"Content-Disposition": "attachment; filename=list.csv"}),
            Rule(H + "/api/next", body={"x": 1}),
        ])
        out = run_generated(generate(plan), adapter)
        assert files_in(outdir) == {"list.csv": csv}
        lines = out.splitlines()
        assert lines[0].endswith(f"list.csv に保存しました ({len(csv)} バイト)") and lines[1:] == ["品番,数量", "A-1,3", ""]


# =========================================================================== loop steps

def loop_step(kind: str, path: str = "/Report.aspx") -> Step:
    return step(1, "GET", path, response_kind=kind, params=[("page", Ref.var("page"))],
                loop=Loop(var="page", values=["1", "2", "3"], numeric_range=(1, 3), note="3 回"))


def per_page(content_type: str, disposition: str | None = None, body=lambda page: f"page {page}".encode()):
    def handler(req):
        page = req.url.rsplit("page=", 1)[-1]
        headers = {"Content-Type": content_type}
        if disposition:
            headers["Content-Disposition"] = disposition
        return 200, headers, body(page)
    return handler


class TestLoopDownloads:
    def test_binary_loop_saves_every_iteration(self, outdir):
        plan = Plan(steps=[loop_step("binary")])
        src = generate(plan)
        check_format(src)
        main = main_source(src)
        assert "results.append(_save_download(resp))" in main and "_text(resp)" not in main
        adapter = MockAdapter([Rule(H + "/Report.aspx", handler=per_page("application/pdf", "attachment; filename=report.pdf",
                                                                            lambda p: b"%PDF-" + p.encode() + b"\xff\x00"))])
        out = run_generated(src, adapter)
        assert files_in(outdir) == {"report.pdf": b"%PDF-1\xff\x00", "report (2).pdf": b"%PDF-2\xff\x00",
                                    "report (3).pdf": b"%PDF-3\xff\x00"}
        lines = out.splitlines()
        assert len(lines) == 3 and all(ln.endswith("に保存しました (8 バイト)") for ln in lines)  # no binary garbage

    def test_binary_loop_in_the_middle_keeps_the_paths(self, outdir):
        plan = Plan(steps=[loop_step("binary", "/Export.aspx"), step(2, "GET", "/api/end")])
        adapter = MockAdapter([
            Rule(H + "/Export.aspx", handler=per_page(XLSX)),  # no Content-Disposition: output.xlsx
            Rule(H + "/api/end", body={"end": 1}),
        ])
        out = run_generated(generate(plan), adapter)
        assert sorted(files_in(outdir)) == ["output (2).xlsx", "output (3).xlsx", "output.xlsx"]
        assert out.endswith('{\n  "end": 1\n}\n')

    def test_text_loop_saves_attachments_and_keeps_the_text(self, outdir):
        plan = Plan(steps=[loop_step("text", "/Csv.aspx")])
        src = generate(plan)
        main = main_source(src)
        assert "_save_if_attachment(resp)" in main and "results.append(_text(resp))" in main
        adapter = MockAdapter([Rule(H + "/Csv.aspx", handler=per_page("text/csv; charset=utf-8", "attachment; filename=data.csv"))])
        out = run_generated(src, adapter)
        assert files_in(outdir) == {"data.csv": b"page 1", "data (2).csv": b"page 2", "data (3).csv": b"page 3"}
        assert [ln for ln in out.splitlines() if "保存しました" not in ln] == ["page 1", "page 2", "page 3"]

    def test_json_loop_with_inline_filename_is_not_saved(self, outdir):
        plan = Plan(steps=[loop_step("json", "/api/items")])
        adapter = MockAdapter([Rule(H + "/api/items", handler=per_page("application/json", "inline;filename=f.txt",
                                                                        lambda p: ('{"page": %s}' % p).encode()))])
        out = run_generated(generate(plan), adapter)
        assert files_in(outdir) == {}
        assert out == '[\n  {\n    "page": 1\n  },\n  {\n    "page": 2\n  },\n  {\n    "page": 3\n  }\n]\n'

    def test_html_loop_page_without_attachment_is_not_saved(self, outdir):
        plan = Plan(steps=[loop_step("html", "/Grid.aspx")])
        adapter = MockAdapter([Rule(H + "/Grid.aspx", handler=per_page("text/html; charset=utf-8"))])
        assert run_generated(generate(plan), adapter) == "page 1\npage 2\npage 3\n"
        assert files_in(outdir) == {}


# =========================================================================== unique names (4)

class TestUniqueNames:
    def plan(self, count: int = 3) -> Plan:
        return Plan(steps=[step(i, "POST", "/Grid.aspx", response_kind="binary", func=f"step_{i:02d}_export")
                           for i in range(1, count + 1)])

    def adapter(self, tag: str, disposition: str = "attachment; filename=GridViewExport.xls") -> MockAdapter:
        bodies = iter([f"{tag}-1", f"{tag}-2", f"{tag}-3"])
        return MockAdapter([Rule(H + "/Grid.aspx", handler=lambda req: (200, {
            "Content-Type": "application/vnd.ms-excel", "Content-Disposition": disposition}, next(bodies).encode()))])

    def test_same_name_twice_in_one_run_is_numbered(self, outdir):
        src = generate(self.plan())
        out = run_generated(src, self.adapter("run1"))
        assert files_in(outdir) == {"GridViewExport.xls": b"run1-1", "GridViewExport (2).xls": b"run1-2",
                                    "GridViewExport (3).xls": b"run1-3"}
        assert "GridViewExport (3).xls に保存しました" in out
        # a new run starts from the same names again and overwrites what the previous run left
        run_generated(src, self.adapter("run2"))
        assert files_in(outdir) == {"GridViewExport.xls": b"run2-1", "GridViewExport (2).xls": b"run2-2",
                                    "GridViewExport (3).xls": b"run2-3"}

    def test_name_without_extension(self, outdir):
        run_generated(generate(self.plan(2)), self.adapter("x", "attachment; filename=README"))
        assert files_in(outdir) == {"README": b"x-1", "README (2)": b"x-2"}

    def test_names_differing_only_in_case(self, outdir):
        dispositions = iter(["attachment; filename=Report.xlsx", "attachment; filename=report.xlsx"])
        adapter = MockAdapter([Rule(H + "/Grid.aspx", handler=lambda req: (
            200, {"Content-Type": XLSX, "Content-Disposition": next(dispositions)}, b"PK"))])
        run_generated(generate(self.plan(2)), adapter)
        if os.name == "nt":  # one file system name on Windows: the second one must not overwrite the first
            assert sorted(files_in(outdir)) == ["Report.xlsx", "report (2).xlsx"]
        else:
            assert sorted(files_in(outdir)) == ["Report.xlsx", "report.xlsx"]


# =========================================================================== file names

NAME_CASES = [
    # RFC 2047 encoded words (.NET's ContentDisposition for non-ASCII names)
    ('attachment; filename="' + b64_word("生産実績.xlsx") + '"', "生産実績.xlsx"),
    ("attachment; filename=" + b64_word("生産実績.xlsx", "utf-8"), "生産実績.xlsx"),
    ('attachment; filename="=?utf-8?Q?=E6=97=A5=E5=A0=B1_2026.csv?="', "日報 2026.csv"),
    ('attachment; filename="' + b64_word("①報告.xlsx", "Shift_JIS", "cp932") + '"', "①報告.xlsx"),
    ('attachment; filename="' + b64_word("生産") + " " + b64_word("実績.xlsx") + '"', "生産実績.xlsx"),
    ('attachment; filename="' + b64_word("名前.csv", "x-unknown-charset") + '"', "名前.csv"),
    # the earlier forms still work
    ("attachment; filename*=UTF-8''%E7%94%9F%E7%94%A3.xlsx", "生産.xlsx"),
    ("attachment; filename=%E7%94%9F%E7%94%A3.xlsx", "生産.xlsx"),
    ('attachment; filename="' + "日報.xlsx".encode("cp932").decode("latin-1") + '"', "日報.xlsx"),
    ('attachment; filename="a=?b?=c.xlsx"', "a=_b_=c.xlsx"),  # not an encoded word
    # Windows reserved device names, with or without an extension
    ("attachment; filename=CON.xlsx", "_CON.xlsx"),
    ("attachment; filename=nul", "_nul"),
    ("attachment; filename=com1.tar.gz", "_com1.tar.gz"),
    ("attachment; filename=Lpt9.csv", "_Lpt9.csv"),
    ('attachment; filename="aux .txt"', "_aux .txt"),
    ("attachment; filename=CONSOLE.xlsx", "CONSOLE.xlsx"),
    ("attachment; filename=com10.csv", "com10.csv"),
    ("attachment; filename*=UTF-8''COM%C2%B9.txt", "_COM" + chr(0xB9) + ".txt"),  # COM + superscript one
    # path tricks
    ('attachment; filename="..\\\\..\\\\evil.xlsx"', "evil.xlsx"),
    # over-long names keep their extension
    ("attachment; filename*=UTF-8''" + "%E3%81%82" * 200 + ".xlsx", "あ" * 145 + ".xlsx"),
    ("attachment; filename=" + "a" * 300, "a" * 150),
    ("attachment; filename=" + "a" * 140 + "." + "b" * 20, ("a" * 140 + "." + "b" * 20)[:150]),
]


@pytest.mark.parametrize("disposition,expected", NAME_CASES)
def test_util_download_filename(disposition, expected):
    assert util.download_filename(disposition) == expected
    assert len(expected) <= util.MAX_FILE_NAME


@pytest.mark.parametrize("disposition,expected", NAME_CASES)
def test_generated_download_name_matches_util(disposition, expected):
    ns = exec_module(generate(Plan(steps=[step(1, "GET", "/x")]), GenOptions(comments=False)))
    assert ns["_download_name"](fake_response(disposition)) == expected


@pytest.mark.parametrize("disposition", [None, "attachment", "inline", 'attachment; filename=""', "attachment; filename=..."])
def test_util_download_filename_without_a_name(disposition):
    assert util.download_filename(disposition) is None


def test_url_fallback_is_made_safe_too():
    ns = exec_module(generate(Plan(steps=[step(1, "GET", "/x")])))
    assert ns["_download_name"](fake_response(None, url=H + "/files/NUL.xlsx")) == "_NUL.xlsx"
    assert ns["_download_name"](fake_response(None, url=H + "/Export.aspx")) == "output.xlsx"


def test_saving_under_an_encoded_word_name(outdir):
    plan = Plan(steps=[step(1, "POST", "/Export.aspx", response_kind="binary")])
    adapter = MockAdapter([Rule(H + "/Export.aspx", body=b"PK", content_type=XLSX,
                                headers={"Content-Disposition": 'attachment; filename="' + b64_word("生産実績_01.xlsx") + '"'})])
    out = run_generated(generate(plan), adapter)
    assert files_in(outdir) == {"生産実績_01.xlsx": b"PK"} and "生産実績_01.xlsx に保存しました" in out


# =========================================================================== format / options

def kitchen_sink_plan() -> Plan:
    s1 = step(1, "GET", "/Login.aspx", response_kind="html",
              extractors=[Extractor("vs", "html_input", name="__VIEWSTATE", sample="x")])
    s2 = step(2, "POST", "/Login.aspx", body_kind="form", response_kind="html",
              form=[("__VIEWSTATE", Ref.var("vs")), ("pw", Ref.var("TXT_PASSWORD"))])
    s3 = loop_step("binary", "/Pdf.aspx")
    s3.index, s3.func_name = 3, "step_03_get_pdf"
    s4 = loop_step("json", "/api/items")
    s4.index, s4.func_name, s4.loop = 4, "step_04_get_items", Loop(var="page_2", values=["a", "b", "c"])
    s4.params = [("page", Ref.var("page_2"))]
    s5 = step(5, "GET", "/Export.aspx", response_kind="binary")
    s6 = step(6, "GET", "/x.txt", response_kind="text")
    s7 = step(7, "GET", "/none", response_kind="empty")
    constants = [Constant("TXT_PASSWORD", "pw", secret=True, env_var="REQREC_TXT_PASSWORD")]
    auth = AuthInfo(kind="digest", hosts=["example.test"], username="alice")
    return Plan(steps=[s1, s2, s3, s4, s5, s6, s7], constants=constants, auth=auth)


@pytest.mark.parametrize("final", [None, 1, 3, 4, 5, 6, 7])
@pytest.mark.parametrize("opts", [GenOptions(), GenOptions(comments=False), GenOptions(print_final=False),
                                  GenOptions(comments=False, legacy_tls=True, strict_status=True, delay=0.5)])
def test_kitchen_sink_is_well_formed(final, opts):
    plan = kitchen_sink_plan()
    plan.final_step_index = final
    src = generate(plan, opts)
    check_format(src)
    if not opts.comments:
        assert comment_tokens(src) == []
    main = main_source(src)
    assert main.count("_save_if_attachment(resp)") + main.count("_save_download(resp)") == len(plan.steps)
    assert "('REQREC_TXT_PASSWORD', TXT_PASSWORD)" in main and "AUTH_PASSWORD)" in main.split("session =")[0]


# =========================================================================== every fixture recording

FIXTURE_FILES = sorted(p for p in FIXTURES.iterdir() if p.suffix in (".har", ".json"))
PLAN_OPTION_SETS = {
    "default": PlanOptions(),
    "keep_all": PlanOptions(keep_all=True, detect_loops=False),
    "no_redact": PlanOptions(redact_secrets=False),
}
GEN_OPTION_SETS = {
    "default": GenOptions(),
    "no_comments": GenOptions(comments=False),
    "legacy": GenOptions(legacy_tls=True, strict_status=True, delay=1.0, html_parser="lxml"),
    "no_print": GenOptions(print_final=False, comments=False),
}


def test_fixture_list_includes_the_factory_recordings():
    names = {p.name for p in FIXTURE_FILES}
    assert {"factory_ie_recording_digit_key.json", "factory_ie_recording_letter_key.json"} <= names
    assert len(FIXTURE_FILES) >= 5


@pytest.mark.parametrize("fixture", FIXTURE_FILES, ids=lambda p: p.name)
@pytest.mark.parametrize("plan_opts", sorted(PLAN_OPTION_SETS))
def test_every_fixture_generates_well_formed_scripts(fixture, plan_opts):
    recording = load_recording(str(fixture))
    base = build_plan(recording, PLAN_OPTION_SETS[plan_opts])
    assert base.steps
    finals = [None] + sorted({base.steps[0].index, base.steps[len(base.steps) // 2].index})
    for final in finals:
        for gen_name, gen_opts in GEN_OPTION_SETS.items():
            plan = build_plan(recording, PLAN_OPTION_SETS[plan_opts])
            plan.final_step_index = final
            src = generate(plan, gen_opts)
            check_format(src)
            if not gen_opts.comments:
                assert comment_tokens(src) == [], (fixture.name, gen_name)
            main = main_source(src)
            saves = main.count("_save_if_attachment(resp)") + main.count("_save_download(resp)")
            assert saves == len(plan.steps), (fixture.name, gen_name, final)
            if gen_opts.print_final:
                assert main.count("final_resp = resp") + main.count("final_results = results") == 1
            ns = exec_module(src)  # module level runs (constants, helpers) without a request
            assert callable(ns["main"]) and ns["_SAVED_PATHS"] == set()


def test_loop_variable_colliding_with_a_constant_is_refused():
    """main() reads the secret constants before the loops run; a loop variable of the same name would
    make that read an UnboundLocalError, so codegen refuses such a plan like an extractor collision."""
    plan = Plan(steps=[loop_step("json")], constants=[Constant("page", "x", secret=True, env_var="REQREC_PAGE")])
    with pytest.raises(CodegenError, match="loop variable 'page' collides with a constant"):
        generate(plan)
