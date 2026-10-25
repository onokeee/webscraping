"""Tests for the cli section of ``reqrec.py`` (``reqrec`` / ``python -m reqrec``).

The pipeline (``load_recording`` / ``load_recordings`` / ``build_plan`` / ``generate``) is monkeypatched
with fakes so these tests exercise argument parsing, option -> dataclass mapping, output writing and
exit codes without depending on the other modules.  A few tests at the end run the real pipeline on
the bundled fixture (see ``tests/test_integration.py`` for the detailed expectations).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import pytest

import reqrec as cli, reqrec as model
from reqrec import __version__
from reqrec import (
    AuthInfo,
    Constant,
    Dropped,
    Extractor,
    Flow,
    GenOptions,
    InitialCookie,
    Loop,
    Plan,
    PlanOptions,
    RecordedRequest,
    RecordedResponse,
    Recording,
    Ref,
    Step,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "login_flow_chrome.har")
FIREFOX_FIXTURE = os.path.join(ROOT, "tests", "fixtures", "api_firefox.har")
LEGACY_FIXTURE = os.path.join(ROOT, "tests", "fixtures", "legacy_webforms_ntlm.har")
EXAMPLES_DIR = os.path.join(ROOT, "tests", "fixtures")  # the bundled example script (example_scrape.py)

FAKE_SCRIPT = "import sys\nprint('fake generated script')\nsys.exit(0)\n"
SECRET_VALUE = "Secr3t!-never-print-me"
LONG_URL = "https://shop.example.test/catalog/category/sub-category/another-level/items/list-of-everything?sort=price&dir=asc"


# --------------------------------------------------------------------------- hand-built data

def _flow(flow_id: str, method: str, url: str, status: int | None = 200, mime: str = "text/html",
          started: float = 1_700_000_000.0) -> Flow:
    request = RecordedRequest(method=method, url=url, headers=[("User-Agent", "test")])
    response = None
    if status is not None:
        response = RecordedResponse(status=status, headers=[("Content-Type", mime)], body=b"<html></html>")
    return Flow(id=flow_id, request=request, response=response, started_at=started)


def make_recording() -> Recording:
    return Recording(
        flows=[
            _flow("f0001", "GET", "https://shop.example.test/login"),
            _flow("f0002", "POST", "https://shop.example.test/login", status=302, started=1_700_000_001.0),
            _flow("f0003", "GET", "https://shop.example.test/dashboard", started=1_700_000_002.0),
            _flow("f0004", "GET", "https://ads.example.test/pixel.gif", status=None, started=1_700_000_003.0),
        ],
        meta={"source": "har", "creator": "WebInspector/537.36"},
    )


def make_plan() -> Plan:
    steps = [
        Step(
            index=1, func_name="step_01_get_login", method="GET",
            url=[Ref.lit("https://shop.example.test/login")],
            extractors=[Extractor(var="token", kind="html_input", name="_token", sample="tok123", note="used by step 2")],
            response_kind="html", expected_status=200, source_flow_ids=["f0001"],
        ),
        Step(
            index=2, func_name="step_02_post_login", method="POST",
            url=[Ref.lit("https://shop.example.test/login")],
            body_kind="form",
            form=[("_token", Ref.var("token")), ("username", Ref.var("USERNAME")), ("password", Ref.var("PASSWORD"))],
            extractors=[
                Extractor(var="api_token", kind="regex", pattern=r'window\.API_TOKEN = "([^"]+)"', sample="api123"),
                Extractor(var="csrf", kind="html_meta", name="csrf-token"),
                Extractor(var="sig", kind="html_attr", selector="a#export", attr="href", pattern=r"sig=([^&]+)"),
            ],
            response_kind="html", expected_status=200, source_flow_ids=["f0002", "f0003"],
        ),
        Step(
            index=3, func_name="step_03_get_items", method="GET",
            url=[Ref.lit(LONG_URL.split("?")[0])],
            params=[("page", Ref.var("page")), ("sort", Ref.lit("price"))],
            headers=[("Authorization", Ref.expr('"Bearer " + api_token'))],
            response_kind="json", expected_status=200,
            loop=Loop(var="page", values=["1", "2", "3"], numeric_range=(1, 3)),
            source_flow_ids=["f0005", "f0006", "f0007"],
        ),
        Step(
            index=4, func_name="step_04_get_users_profile", method="GET",
            url=[Ref.lit("https://api.example.test/v1/users/"), Ref.var("user_id"), Ref.lit("/profile")],
            extractors=[Extractor(var="org_id", kind="json", path=["data", "items", 0, "id"])],
            body_kind="raw", raw_body=b"\x00\xff\x10",
            response_kind="json", expected_status=201, source_flow_ids=["f0008"],
        ),
    ]
    dropped = [Dropped(f"f01{i:02d}", "GET", f"https://shop.example.test/static/img{i}.png", "static asset (image)") for i in range(7)]
    dropped += [
        Dropped("f0200", "GET", "https://www.google-analytics.com/collect", "tracker/analytics host"),
        Dropped("f0201", "POST", "https://www.google-analytics.com/g/collect", "tracker/analytics host"),
    ]
    return Plan(
        steps=steps,
        constants=[
            Constant(name="PASSWORD", value=SECRET_VALUE, secret=True, env_var="REQREC_PASSWORD", comment="secret"),
            Constant(name="USERNAME", value="alice"),
        ],
        base_headers=[("User-Agent", "Mozilla/5.0 test")],
        initial_cookies=[InitialCookie(name="lang", value="ja", domain="shop.example.test")],
        dropped=dropped,
        warnings=["step 4: value of `sig` looks dynamic but could not be traced to any earlier response"],
        meta={"flows_total": 13, "flows_kept": 7},
    )


# --------------------------------------------------------------------------- fakes

@pytest.fixture
def fakes(monkeypatch):
    """Replace the pipeline with fakes; returns a dict that records every call."""
    calls: dict = {"recording": make_recording(), "plan": make_plan(), "script": FAKE_SCRIPT}

    def fake_load_recording(path):
        calls["load_path"] = path
        return calls["recording"]

    def fake_load_recordings(paths):
        calls["load_paths"] = list(paths)
        return calls["recording"]

    def fake_build_plan(recording, opts=None):
        calls["build_recording"] = recording
        calls["plan_opts"] = opts
        calls.setdefault("plan_opts_history", []).append(opts)
        return calls["plan"]

    def fake_generate(plan, opts=None):
        calls["gen_plan"] = plan
        calls["gen_opts"] = opts
        return calls["script"]

    monkeypatch.setattr(cli, "load_recording", fake_load_recording)
    monkeypatch.setattr(cli, "load_recordings", fake_load_recordings)
    monkeypatch.setattr(cli, "build_plan", fake_build_plan)
    monkeypatch.setattr(cli, "generate", fake_generate)
    return calls


# --------------------------------------------------------------------------- top level

def test_version(capsys):
    assert cli.main(["--version"]) == 0
    out = capsys.readouterr().out
    assert out.strip() == f"reqrec {__version__}"


def test_help_is_japanese_and_exits_zero(capsys):
    assert cli.main(["-h"]) == 0
    out = capsys.readouterr().out
    assert "使い方:" in out
    assert "このヘルプを表示して終了する" in out
    assert "show this help message" not in out
    for command in ("import", "inspect", "generate", "gui", "browser"):
        assert command in out
    assert "{import,inspect,generate,gui,browser}" in out  # recording is done in the GUI only
    assert "reqrec record" not in out


def test_subcommand_help(capsys):
    assert cli.main(["generate", "--help"]) == 0
    out = capsys.readouterr().out
    for flag in ("--include-host", "--exclude-host", "--keep-static", "--keep-trackers", "--keep-all",
                 "--no-collapse-redirects", "--no-loops", "--min-value-length", "--max-steps", "--redact",
                 "--html-parser", "--no-comments", "--delay", "--timeout", "--strict-status", "--dump-plan", "--run",
                 # phase 2 (DESIGN §13.1 / §13.3)
                 "--exclude-flow", "--include-flow", "--final-flow", "--exclude-step", "--final-step",
                 "--no-detect-auth"):
        assert flag in out
    assert "--legacy-tls" not in out  # http:// only: no TLS options
    assert "INPUT [INPUT ...]" in out  # several recordings can be merged (§13.5)


def test_no_command_prints_help_and_returns_usage_error(capsys):
    assert cli.main([]) == 2
    captured = capsys.readouterr()
    assert "使い方:" in captured.err
    assert captured.out == ""


def test_main_reads_sys_argv_when_argv_is_none(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["reqrec", "--version"])
    assert cli.main() == 0
    assert capsys.readouterr().out.startswith("reqrec ")


@pytest.mark.parametrize(
    "argv",
    [
        ["bogus"],
        ["generate"],  # missing INPUT and -o
        ["generate", "in.har"],  # missing -o
        ["generate", "in.har", "-o", "x.py", "--html-parser", "regex"],
        ["generate", "in.har", "-o", "x.py", "--delay", "-1"],
        ["generate", "in.har", "-o", "x.py", "--delay", "abc"],
        ["generate", "in.har", "-o", "x.py", "--timeout", "0"],
        ["generate", "in.har", "-o", "x.py", "--min-value-length", "0"],
        ["generate", "in.har", "-o", "x.py", "--max-steps", "zero"],
        ["generate", "in.har", "-o", "x.py", "--unknown-flag"],
        ["generate", "in.har", "-o", "x.py", "--exclude-flow", "f00!8"],  # not a flow id
        ["generate", "in.har", "-o", "x.py", "--final-flow", "f0001,f0002"],  # exactly one id
        ["generate", "in.har", "-o", "x.py", "--final-flow", ""],
        ["generate", "in.har", "-o", "x.py", "--exclude-step", "0"],
        ["generate", "in.har", "-o", "x.py", "--exclude-step", "two"],
        ["generate", "in.har", "-o", "x.py", "--final-step", "-1"],
        ["generate", "in.har", "-o", "x.py", "--legacy-tls"],  # removed option (http:// only)
        ["inspect"],
        ["inspect", "in.har", "--include-host"],  # option without value
        ["import", "in.har"],  # missing -o
        ["record", "-o", "rec.json"],  # removed command: recording is done in the GUI
        ["gui", "--port", "70000"],
        ["gui", "--port", "0"],
        ["gui", "--port", "eighty"],
    ],
)
def test_usage_errors_return_2(argv, capsys, fakes):
    assert cli.main(argv) == 2
    err = capsys.readouterr().err
    assert "エラー:" in err
    assert "使い方:" in err


def test_usage_error_messages_are_translated(capsys):
    cli.main(["generate"])
    err = capsys.readouterr().err
    assert "次の引数が必要です" in err
    assert "the following arguments are required" not in err

    cli.main(["generate", "a.har", "-o", "x", "--html-parser", "nope"])
    err = capsys.readouterr().err
    assert "無効な選択です" in err
    assert "lxml" in err

    cli.main(["generate", "a.har", "-o", "x", "--delay", "-5"])
    err = capsys.readouterr().err
    assert "0 以上の数値" in err


def test_translate_argparse_message_fallback():
    assert cli.translate_argparse_message("unrecognized arguments: --foo") == "不明な引数です: --foo"
    assert cli.translate_argparse_message("argument -p/--port: expected one argument") == "引数 -p/--port: 値が 1 つ必要です"
    assert cli.translate_argparse_message("something completely different") == "something completely different"


def test_split_hosts():
    assert cli.split_hosts(None) == []
    assert cli.split_hosts([]) == []
    assert cli.split_hosts(["Example.com, api.example.com", "cdn.example.com", "example.com"]) == [
        "example.com", "api.example.com", "cdn.example.com",
    ]
    assert cli.split_hosts(["a.com;b.com c.com.", " "]) == ["a.com", "b.com", "c.com"]


def test_format_table_pads_cjk_columns():
    lines = cli._format_table(["列", "b"], [["ab", "c"], ["漢字", "dd"]])
    assert lines[0] == "列    b"
    assert lines[1] == "----  --"
    assert lines[2] == "ab    c"
    assert lines[3] == "漢字  dd"


# --------------------------------------------------------------------------- option mapping

def test_generate_defaults_map_to_default_options(fakes, capsys):
    assert cli.main(["generate", "rec.har", "-o", "-"]) == 0
    assert fakes["load_path"] == "rec.har"
    assert fakes["build_recording"] is fakes["recording"]
    assert fakes["plan_opts"] == PlanOptions()
    assert fakes["gen_opts"] == GenOptions()
    assert fakes["gen_plan"] is fakes["plan"]


def test_generate_every_flag_maps_to_options(fakes, capsys):
    argv = [
        "generate", "rec.har", "-o", "-",
        "--include-host", "Example.com, api.example.com", "--include-host", "cdn.example.com",
        "--exclude-host", "ads.example.com", "--exclude-host", "x.com,y.com",
        "--keep-static", "--keep-trackers", "--keep-all",
        "--no-collapse-redirects", "--no-loops",
        "--min-value-length", "6", "--max-steps", "10", "--redact",
        "--html-parser", "lxml", "--no-comments", "--delay", "1.5", "--timeout", "12", "--strict-status",
        "--exclude-flow", "f0002, 3", "--include-flow", "F0001", "--final-flow", "4", "--no-detect-auth",
    ]
    assert cli.main(argv) == 0
    assert fakes["plan_opts"] == PlanOptions(
        include_hosts=["example.com", "api.example.com", "cdn.example.com"],
        exclude_hosts=["ads.example.com", "x.com", "y.com"],
        keep_static=True,
        keep_trackers=True,
        keep_all=True,
        collapse_redirects=False,
        detect_loops=False,
        redact_secrets=True,
        min_value_length=6,
        max_steps=10,
        exclude_flow_ids=["f0002", "f0003"],
        include_flow_ids=["f0001"],
        final_flow_id="f0004",
        detect_auth=False,
    )
    assert fakes["gen_opts"] == GenOptions(
        html_parser="lxml", comments=False, delay=1.5, timeout=12.0, print_final=True, strict_status=True,
    )
    assert len(fakes["plan_opts_history"]) == 1  # flow ids need no resolving pass


def test_inspect_filter_flags_map_to_plan_options(fakes, capsys):
    argv = ["inspect", "rec.json", "--include-host", "shop.example.test", "--exclude-host", "a.com,b.com",
            "--keep-static", "--no-loops", "--min-value-length", "8", "--max-steps", "3", "--redact"]
    assert cli.main(argv) == 0
    assert fakes["plan_opts"] == PlanOptions(
        include_hosts=["shop.example.test"], exclude_hosts=["a.com", "b.com"], keep_static=True,
        detect_loops=False, redact_secrets=True, min_value_length=8, max_steps=3,
    )


def test_plan_options_from_namespace_without_attributes():
    import argparse

    assert cli.plan_options_from_args(argparse.Namespace()) == PlanOptions()
    assert cli.gen_options_from_args(argparse.Namespace()) == GenOptions()


# --------------------------------------------------------------------------- generate: output

def test_generate_writes_file_and_prints_summary_to_stderr(fakes, tmp_path, capsys):
    out = tmp_path / "scrape.py"
    assert cli.main(["generate", "rec.har", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == FAKE_SCRIPT
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ステップ 4 件" in captured.err
    assert "除外 9 件" in captured.err
    assert "フロー合計 4 件" in captured.err  # from the recording, not plan.meta
    assert "REQREC_PASSWORD" in captured.err
    assert "looks dynamic" in captured.err  # warnings are forwarded
    assert str(out) in captured.err
    assert SECRET_VALUE not in captured.err


def test_generate_to_stdout(fakes, capsys):
    assert cli.main(["generate", "rec.har", "-o", "-"]) == 0
    captured = capsys.readouterr()
    assert captured.out == FAKE_SCRIPT
    assert "ステップ 4 件" in captured.err


def test_generate_adds_missing_trailing_newline(fakes, tmp_path, capsys):
    fakes["script"] = "print('x')"
    out = tmp_path / "s.py"
    assert cli.main(["generate", "rec.har", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == "print('x')\n"


def test_generate_output_directory_missing_is_an_error(fakes, tmp_path, capsys):
    out = tmp_path / "missing-dir" / "scrape.py"
    assert cli.main(["generate", "rec.har", "-o", str(out)]) == 1
    err = capsys.readouterr().err
    assert err.startswith("エラー:")
    assert "ディレクトリ" in err
    assert "load_path" not in fakes  # failed before doing any work


def test_generate_output_is_directory_is_an_error(fakes, tmp_path, capsys):
    assert cli.main(["generate", "rec.har", "-o", str(tmp_path)]) == 1
    assert "エラー:" in capsys.readouterr().err


def test_generate_dump_plan_writes_valid_json(fakes, tmp_path, capsys):
    out = tmp_path / "scrape.py"
    dump = tmp_path / "plan.json"
    assert cli.main(["generate", "rec.har", "-o", str(out), "--dump-plan", str(dump)]) == 0
    text = dump.read_text(encoding="utf-8")
    data = json.loads(text)
    expected = json.loads(json.dumps(model.to_plain(fakes["plan"]), ensure_ascii=False))
    expected["constants"][0]["value"] = None  # secret constants keep their name/env var, never the recorded value
    assert data == expected
    assert SECRET_VALUE not in text
    assert len(data["steps"]) == 4
    assert data["steps"][3]["raw_body"] == {"__bytes_b64__": "AP8Q"}
    assert data["steps"][2]["loop"]["numeric_range"] == [1, 3]
    assert data["constants"][0]["env_var"] == "REQREC_PASSWORD"
    assert data["constants"][1]["value"] == "alice"  # non-secret constants are dumped as-is
    assert str(dump) in capsys.readouterr().err


def test_generate_dump_plan_directory_missing_is_an_error(fakes, tmp_path, capsys):
    assert cli.main(["generate", "rec.har", "-o", "-", "--dump-plan", str(tmp_path / "nope" / "p.json")]) == 1
    assert "--dump-plan" in capsys.readouterr().err


def test_generate_empty_plan_prints_hint(fakes, capsys):
    fakes["plan"] = Plan()
    assert cli.main(["generate", "rec.har", "-o", "-"]) == 0
    err = capsys.readouterr().err
    assert "ステップ 0 件" in err
    assert "--keep-all" in err


def test_generate_non_string_source_is_an_error(fakes, capsys):
    fakes["script"] = None
    assert cli.main(["generate", "rec.har", "-o", "-"]) == 1
    assert "エラー:" in capsys.readouterr().err


# --------------------------------------------------------------------------- generate: --run

def test_generate_run_executes_script_and_returns_its_exit_code(fakes, tmp_path, capfd):
    fakes["script"] = "import sys\nprint('hello from script')\nsys.exit(7)\n"
    out = tmp_path / "scrape.py"
    assert cli.main(["generate", "rec.har", "-o", str(out), "--run"]) == 7
    captured = capfd.readouterr()
    assert "hello from script" in captured.out
    assert "終了コード 7" in captured.err
    assert "実行します" in captured.err


def test_generate_run_inherits_environment(fakes, tmp_path, capfd, monkeypatch):
    monkeypatch.setenv("REQREC_CLI_TEST_VAR", "inherited-ok")
    fakes["script"] = "import os\nprint('VAR=' + os.environ.get('REQREC_CLI_TEST_VAR', 'missing'))\n"
    out = tmp_path / "scrape.py"
    assert cli.main(["generate", "rec.har", "-o", str(out), "--run"]) == 0
    assert "VAR=inherited-ok" in capfd.readouterr().out


def test_generate_run_with_stdout_output_is_rejected(fakes, capsys):
    assert cli.main(["generate", "rec.har", "-o", "-", "--run"]) == 1
    err = capsys.readouterr().err
    assert "エラー:" in err
    assert "--run" in err
    assert "load_path" not in fakes


def test_run_script_normalises_signal_exit_codes(monkeypatch, tmp_path, capsys):
    script = tmp_path / "s.py"
    script.write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: -9)
    assert cli.run_script(str(script)) == 1
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd: 3)
    assert cli.run_script(str(script)) == 3


# --------------------------------------------------------------------------- inspect

def test_inspect_table(fakes, capsys):
    assert cli.main(["inspect", "rec.har"]) == 0
    captured = capsys.readouterr()
    out = captured.out
    assert captured.err == ""
    # header
    assert "入力: rec.har" in out
    assert "フロー合計 4 件" in out
    assert "採用 7 件" in out  # sum of source_flow_ids
    assert "ステップ 4 件" in out
    assert "除外 9 件" in out
    # table (FLOW = the flow ids users pass to --exclude-flow / --final-flow, DESIGN §13.1)
    assert "FLOW" in out and "METHOD" in out and "STATUS" in out and "URL" in out
    assert re.search(r"^01  f0001\s+GET\s+200\s", out, re.M)
    assert re.search(r"^02  f0002\+f0003\s+POST\s+302→200\s", out, re.M)
    assert re.search(r"^03  f0005\+f0006\+f0007\s+GET ×3", out, re.M)
    assert re.search(r"^04  f0008\s+GET\s+201", out, re.M)
    assert "--exclude-flow" in out  # the legend explains what FLOW is for
    assert "302→200" in out  # collapsed redirect chain statuses
    assert "GET ×3" in out  # loop iteration count
    assert "token←html_input[_token]" in out
    assert "csrf←html_meta[csrf-token]" in out
    assert "sig←html_attr[a#export@href]" in out
    assert "org_id←json[data.items[0].id]" in out
    assert "ループ page=1..3 (3回)" in out
    assert "https://api.example.test/v1/users/{user_id}/profile" in out
    # several extractors on one step -> continuation rows (one per line, in order)
    assert out.index("api_token←regex") < out.index("csrf←html_meta") < out.index("sig←html_attr") < out.index("03  f0005")
    # long URLs are truncated with util.truncate
    long_base = LONG_URL.split("?")[0]
    assert long_base not in out
    assert long_base[:30] in out and "…" in out
    # dropped flows grouped by reason, most frequent first, at most 5 examples
    assert "除外されたリクエスト (9 件)" in out
    assert "static asset (image) — 7 件" in out
    assert "tracker/analytics host — 2 件" in out
    assert out.index("static asset (image)") < out.index("tracker/analytics host")
    assert out.count("https://shop.example.test/static/img") == 5
    assert "      f0100  https://shop.example.test/static/img0.png" in out  # dropped flows carry their id
    assert "      f0200  https://www.google-analytics.com/collect" in out
    assert "… 他 2 件" in out
    assert "認証:" not in out and "結果にするステップ" not in out  # nothing detected / selected
    # constants / cookies / warnings
    assert "PASSWORD  ← 環境変数 REQREC_PASSWORD" in out
    assert SECRET_VALUE not in out
    assert "USERNAME = 'alice'" in out
    assert "lang@shop.example.test" in out
    assert "警告 (1 件)" in out and "looks dynamic" in out


def test_inspect_json(fakes, capsys):
    assert cli.main(["inspect", "rec.json", "--json"]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert captured.err == ""
    assert report["input"] == "rec.json"
    assert report["source"] == "har, WebInspector/537.36"
    assert report["flows_total"] == 4
    assert report["flows_kept"] == 7
    assert report["steps_kept"] == 4
    assert report["dropped"] == 9
    assert [s["index"] for s in report["steps"]] == [1, 2, 3, 4]
    step2 = report["steps"][1]
    assert step2["method"] == "POST"
    assert step2["status_chain"] == [302, 200]
    assert step2["body_kind"] == "form"
    assert [e["var"] for e in step2["extractors"]] == ["api_token", "csrf", "sig"]
    step3 = report["steps"][2]
    assert step3["loop"] == {"var": "page", "count": 3, "values": ["1", "2", "3"], "numeric_range": [1, 3]}
    assert step3["params"] == ["page", "sort"]
    assert report["steps"][3]["url"] == "https://api.example.test/v1/users/{user_id}/profile"
    assert report["steps"][3]["extractors"][0]["path"] == ["data", "items", 0, "id"]
    assert report["dropped_by_reason"][0] == {
        "reason": "static asset (image)",
        "count": 7,
        "examples": [f"https://shop.example.test/static/img{i}.png" for i in range(5)],
        "example_ids": [f"f010{i}" for i in range(5)],
    }
    assert report["inputs"] == ["rec.json"]
    assert report["auth"] is None and report["final_step_index"] is None
    assert [s["flow_ids"] for s in report["steps"]] == ["f0001", "f0002+f0003", "f0005+f0006+f0007", "f0008"]
    assert [s["is_final"] for s in report["steps"]] == [False] * 4
    assert report["dropped_by_reason"][1]["count"] == 2
    assert len(report["dropped_flows"]) == 9
    assert report["dropped_flows"][0] == {
        "flow_id": "f0100", "method": "GET", "url": "https://shop.example.test/static/img0.png", "reason": "static asset (image)",
    }
    assert report["constants"][0] == {"name": "PASSWORD", "secret": True, "env_var": "REQREC_PASSWORD", "value": None, "comment": "secret"}
    assert report["constants"][1]["value"] == "alice"
    assert report["env_vars"] == ["REQREC_PASSWORD"]
    assert report["initial_cookies"] == [{"name": "lang", "domain": "shop.example.test", "path": "/"}]
    assert report["base_headers"] == [["User-Agent", "Mozilla/5.0 test"]]
    assert report["warnings"] == fakes["plan"].warnings
    assert SECRET_VALUE not in captured.out
    assert "ja" not in json.dumps(report["initial_cookies"])  # cookie values are not leaked


def test_inspect_empty_plan(fakes, capsys):
    fakes["plan"] = Plan()
    assert cli.main(["inspect", "rec.har"]) == 0
    out = capsys.readouterr().out
    assert "ステップ: なし" in out
    assert "除外されたリクエスト: なし" in out
    assert "警告: なし" in out


def test_build_inspect_report_falls_back_to_meta_for_kept_flows():
    plan = Plan(meta={"flows_kept": 5})
    report = cli.build_inspect_report(make_recording(), plan, source="x")
    assert report["flows_kept"] == 5
    assert report["steps_kept"] == 0


# --------------------------------------------------------------------------- phase 2: several INPUT files (§13.5)

def test_single_input_uses_load_recording(fakes, capsys):
    assert cli.main(["inspect", "rec.har"]) == 0
    assert fakes["load_path"] == "rec.har" and "load_paths" not in fakes


def test_several_inputs_are_merged_via_load_recordings(fakes, capsys):
    assert cli.main(["inspect", "tab1.har", "tab2.har", "tab1.har"]) == 0
    assert fakes["load_paths"] == ["tab1.har", "tab2.har"]  # de-duplicated, order kept
    assert "load_path" not in fakes
    out = capsys.readouterr().out
    assert "入力: tab1.har, tab2.har" in out

    assert cli.main(["inspect", "tab1.har", "tab2.har", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["input"] == "tab1.har, tab2.har"
    assert report["inputs"] == ["tab1.har", "tab2.har"]

    assert cli.main(["generate", "a.har", "b.har", "-o", "-"]) == 0
    assert fakes["load_paths"] == ["a.har", "b.har"]
    assert fakes["build_recording"] is fakes["recording"]


def test_import_several_inputs(fakes, tmp_path, capsys):
    out = tmp_path / "rec.json"
    assert cli.main(["import", "a.har", "b.har", "-o", str(out)]) == 0
    assert fakes["load_paths"] == ["a.har", "b.har"]
    assert Recording.load(str(out)).flows[0].id == "f0001"
    text = capsys.readouterr().out
    assert "2 ファイルを結合して" in text and "4 件" in text


def test_load_inputs_fallback_when_importer_lacks_load_recordings(monkeypatch):
    """``load_inputs`` goes through the module-level ``load_recordings`` (the importer's, or the
    merge fallback); a one-element list is identical to ``load_recording``."""
    rec = make_recording()
    monkeypatch.setattr(cli, "load_recording", lambda path: rec)
    monkeypatch.setattr(cli, "load_recordings", lambda paths: Recording.merge([rec for _ in paths]))
    assert cli.load_inputs(["one.har"]) is rec
    merged = cli.load_inputs(["one.har", "two.har"])
    assert len(merged.flows) == 8 and merged.meta["source"] == "merged"
    with pytest.raises(ValueError):
        cli.load_inputs([])


def test_describe_source_for_merged_recordings():
    meta = {"source": "merged", "sources": [{"source": "har", "creator": "WebInspector/537.36"}, {"source": "har", "creator": "Firefox/125.0"}]}
    assert cli._describe_source(meta) == "結合 2 件: har, WebInspector/537.36 / har, Firefox/125.0"
    assert cli._describe_source({"source": "merged", "sources": []}) == "結合 0 件"
    assert cli._describe_source({}) == ""
    assert cli._describe_source({"source": {"source": "har"}}) == "har"


# --------------------------------------------------------------------------- phase 2: manual overrides (§13.1)

def test_flow_id_helpers():
    assert cli.cli_normalise_flow_id("f0008") == "f0008"
    assert cli.cli_normalise_flow_id("F8") == "f0008"
    assert cli.cli_normalise_flow_id("8") == "f0008"
    assert cli.cli_normalise_flow_id("12345") == "f12345"
    assert cli.cli_normalise_flow_id(" ") is None and cli.cli_normalise_flow_id(None) is None
    assert cli.cli_normalise_flow_id("custom-id") == "custom-id"  # non-standard ids are checked against the recording later
    assert cli.split_flow_ids(["f0001, 2", "f0003;f0001", " 4 "]) == ["f0001", "f0002", "f0003", "f0004"]
    assert cli.split_flow_ids(None) == [] and cli.split_flow_ids([""]) == []
    assert cli._flow_ids_label([]) == "-"
    assert cli._flow_ids_label(["f0008", "f0009"]) == "f0008+f0009"
    assert cli._flow_ids_label([f"f{i:04d}" for i in range(11, 16)]) == "f0011+…+f0015 (5)"


def test_exclude_step_and_final_step_resolve_to_flow_ids(fakes, capsys):
    """Step numbers are looked up in a first plan built without overrides, then the plan is rebuilt."""
    assert cli.main(["generate", "rec.har", "-o", "-", "--exclude-step", "1", "--final-step", "3"]) == 0
    first, second = fakes["plan_opts_history"]
    assert first == PlanOptions()  # resolving pass: no overrides at all
    assert second == PlanOptions(exclude_flow_ids=["f0001"], final_flow_id="f0007")  # loop step -> its last flow
    assert fakes["plan_opts"] is second

    fakes["plan_opts_history"].clear()
    assert cli.main(["inspect", "rec.har", "--exclude-step", "2,4", "--exclude-step", "2", "--exclude-flow", "f0001"]) == 0
    assert fakes["plan_opts"].exclude_flow_ids == ["f0001", "f0002", "f0003", "f0008"]
    assert fakes["plan_opts"].final_flow_id is None
    assert len(fakes["plan_opts_history"]) == 2


def test_final_step_agreeing_with_final_flow_is_fine(fakes, capsys):
    assert cli.main(["inspect", "rec.har", "--final-step", "2", "--final-flow", "f0002"]) == 0
    assert fakes["plan_opts"].final_flow_id == "f0003"  # the step's last flow


@pytest.mark.parametrize(
    "extra, fragment",
    [
        (["--exclude-step", "9"], "--exclude-step 9: ステップ番号は 1〜4 の範囲"),
        (["--final-step", "5"], "--final-step 5: ステップ番号は 1〜4 の範囲"),
        (["--exclude-flow", "f9999"], "--exclude-flow f9999: 記録にそのフロー ID はありません"),
        (["--include-flow", "f0001,f0042"], "--include-flow f0042: 記録にそのフロー ID はありません"),
        (["--final-flow", "f0999"], "--final-flow f0999: 記録にそのフロー ID はありません"),
        (["--include-flow", "f0002", "--exclude-flow", "f0002"], "--include-flow と --exclude-flow の両方"),
        (["--final-flow", "f0001", "--exclude-step", "1"], "結果にするフロー f0001 が除外の対象"),
        (["--final-step", "1", "--exclude-flow", "f0001"], "結果にするフロー f0001 が除外の対象"),
        (["--final-step", "2", "--final-flow", "f0001"], "別のステップを指しています"),
    ],
)
def test_override_errors_are_japanese_and_return_1(fakes, capsys, extra, fragment):
    for argv in (["inspect", "rec.har", *extra], ["generate", "rec.har", "-o", "-", *extra]):
        assert cli.main(argv) == 1
        captured = capsys.readouterr()
        assert captured.err.startswith("エラー: ") and fragment in captured.err
        assert captured.out == ""
        assert "gen_plan" not in fakes  # generate never got that far


def test_step_numbers_with_empty_plan_is_an_error(fakes, capsys):
    fakes["plan"] = Plan()
    assert cli.main(["inspect", "rec.har", "--exclude-step", "1"]) == 1
    assert "ステップが 1 つもありません" in capsys.readouterr().err


def test_resolve_overrides_directly(fakes):
    recording = make_recording()
    opts = cli.resolve_overrides(recording, PlanOptions(exclude_flow_ids=["f0004"]), exclude_steps=[[2], [2, 4]], final_step=1)
    assert opts.exclude_flow_ids == ["f0004", "f0002", "f0003", "f0008"]
    assert opts.final_flow_id == "f0001"
    assert opts.include_flow_ids == [] and opts.detect_auth is True
    untouched = PlanOptions(include_flow_ids=["f0001"], final_flow_id="f0003")
    assert cli.resolve_overrides(recording, untouched) == untouched


def test_inspect_shows_auth_and_final_step(fakes, capsys):
    plan = make_plan()
    plan.auth = AuthInfo(kind="ntlm", hosts=["shop.example.test"], username="EXAMPLE\\taro")
    plan.final_step_index = 2
    fakes["plan"] = plan
    assert cli.main(["inspect", "rec.har"]) == 0
    out = capsys.readouterr().out
    assert "認証: NTLM (記録時のユーザー: EXAMPLE\\taro) → 生成コードは session.auth を設定します" in out
    assert "結果にするステップ: 2 (POST https://shop.example.test/login)" in out
    assert "★ 結果として表示" in out
    assert out.index("★ 結果として表示") < out.index("api_token←regex")  # marker sits on step 2's row

    assert cli.main(["inspect", "rec.har", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["auth"]["kind"] == "ntlm" and report["auth"]["username"] == "EXAMPLE\\taro"
    assert report["final_step_index"] == 2
    assert [s["is_final"] for s in report["steps"]] == [False, True, False, False]

    plan.auth = AuthInfo(kind="basic", username="alice", username_const="AUTH_USERNAME", password_const="AUTH_PASSWORD")
    plan.constants = [
        Constant("AUTH_USERNAME", "alice"),
        Constant("AUTH_PASSWORD", "", secret=True, env_var="REQREC_AUTH_PASSWORD"),
    ]
    assert cli.main(["inspect", "rec.har"]) == 0
    out = capsys.readouterr().out
    assert "認証: Basic (記録時のユーザー: alice) → 生成コードは session.auth を設定します（パスワードは環境変数 REQREC_AUTH_PASSWORD）" in out


def test_generate_summary_mentions_auth_and_final_step(fakes, capsys):
    plan = make_plan()
    plan.auth = AuthInfo(kind="negotiate", username=None)
    plan.final_step_index = 4
    fakes["plan"] = plan
    assert cli.main(["generate", "rec.har", "-o", "-"]) == 0
    err = capsys.readouterr().err
    assert "認証: Negotiate → 生成コードは session.auth を設定します" in err
    assert "結果にするステップ: 4（GET https://api.example.test/v1/users/{user_id}/profile）" in err


# --------------------------------------------------------------------------- import

def test_import_saves_recording(fakes, tmp_path, capsys):
    out = tmp_path / "rec.json"
    assert cli.main(["import", "traffic.har", "-o", str(out)]) == 0
    assert fakes["load_path"] == "traffic.har"
    loaded = Recording.load(str(out))
    assert len(loaded.flows) == 4
    assert loaded.flows[1].request.method == "POST"
    assert loaded.flows[3].response is None
    assert loaded.meta["source"] == "har"
    out_text = capsys.readouterr().out
    assert "4 件" in out_text
    assert str(out) in out_text


def test_import_to_missing_directory_is_an_error(fakes, tmp_path, capsys):
    assert cli.main(["import", "traffic.har", "-o", str(tmp_path / "nope" / "rec.json")]) == 1
    assert "エラー:" in capsys.readouterr().err


# --------------------------------------------------------------------------- runtime errors -> 1

@pytest.mark.parametrize(
    "exc, expected_fragment",
    [
        (FileNotFoundError(2, "No such file or directory", "missing.har"), "ファイルが見つかりません: missing.har"),
        (ValueError("対応していないファイル形式です (.txt)"), "対応していないファイル形式です"),
        (ImportError("bs4 がインストールされていません"), "bs4 がインストールされていません"),
        (PermissionError(13, "Permission denied", "/root/x"), "Permission denied"),
    ],
)
def test_loader_errors_return_1(fakes, monkeypatch, capsys, exc, expected_fragment):
    def raising(path):
        raise exc

    monkeypatch.setattr(cli, "load_recording", raising)
    for argv in (["inspect", "in.har"], ["generate", "in.har", "-o", "-"], ["import", "in.har", "-o", "rec.json"]):
        assert cli.main(argv) == 1
        captured = capsys.readouterr()
        assert captured.err.startswith("エラー: ")
        assert expected_fragment in captured.err
        assert captured.out == ""


def test_keyboard_interrupt_returns_130(fakes, monkeypatch, capsys):
    def interrupted(recording, opts=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "build_plan", interrupted)
    assert cli.main(["inspect", "in.har"]) == 130
    assert "中断" in capsys.readouterr().err


def test_unexpected_exceptions_propagate(fakes, monkeypatch):
    """Bugs must not be swallowed into an 'エラー:' line (NotImplementedError from stubs included)."""
    def boom(plan, opts=None):
        raise NotImplementedError

    monkeypatch.setattr(cli, "generate", boom)
    with pytest.raises(NotImplementedError):
        cli.main(["generate", "in.har", "-o", "-"])


# --------------------------------------------------------------------------- module entry point / examples

def test_python_m_entry_point():
    result = subprocess.run(
        [sys.executable, "-m", "reqrec", "--version"], cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"reqrec {__version__}"


def test_bundled_example_scripts_compile():
    scripts = [f for f in os.listdir(EXAMPLES_DIR) if f.endswith(".py")] if os.path.isdir(EXAMPLES_DIR) else []
    assert scripts, "tests/fixtures/ should hold at least one example script"
    for name in scripts:
        path = os.path.join(EXAMPLES_DIR, name)
        with open(path, encoding="utf-8") as fh:
            compile(fh.read(), path, "exec")


# --------------------------------------------------------------------------- real pipeline (integration)

def test_real_inspect_on_fixture(capsys):
    rc = cli.main(["inspect", FIXTURE])
    assert rc == 0
    out = capsys.readouterr().out
    assert "フロー合計" in out
    assert "shop.example.test/login" in out


def test_real_inspect_json_on_fixture(capsys):
    rc = cli.main(["inspect", FIXTURE, "--json"])
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["flows_total"] > 0
    assert report["steps_kept"] >= 1
    assert report["steps_kept"] + report["dropped"] <= report["flows_total"]


def test_real_generate_on_fixture_compiles(tmp_path, capsys):
    out = tmp_path / "scrape.py"
    dump = tmp_path / "plan.json"
    rc = cli.main(["generate", FIXTURE, "-o", str(out), "--dump-plan", str(dump)])
    assert rc == 0
    source = out.read_text(encoding="utf-8")
    compile(source, str(out), "exec")
    assert "requests" in source
    assert json.loads(dump.read_text(encoding="utf-8"))["steps"]


def test_real_overrides_on_fixture(tmp_path, capsys):
    """Flow ids shown by ``inspect`` feed the override options; step numbers resolve the same way."""
    assert cli.main(["inspect", FIXTURE, "--json"]) == 0
    base = json.loads(capsys.readouterr().out)
    assert base["steps"][1]["flow_ids"] == "f0008+f0009"  # the login POST + its redirect target
    assert base["final_step_index"] is None

    assert cli.main(["inspect", FIXTURE, "--json", "--final-flow", "f0009", "--exclude-step", "5"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["final_step_index"] == 2
    assert report["steps_kept"] == base["steps_kept"] - 1
    assert {d["flow_id"]: d["reason"] for d in report["dropped_flows"]}["f0014"] == "excluded by user"
    assert [s["is_final"] for s in report["steps"]] == [False, True, False, False]

    assert cli.main(["inspect", FIXTURE, "--final-step", "2"]) == 0
    out = capsys.readouterr().out
    assert "結果にするステップ: 2 (POST https://shop.example.test/login)" in out and "★ 結果として表示" in out

    target = tmp_path / "scrape.py"
    assert cli.main(["generate", FIXTURE, "-o", str(target), "--final-step", "2", "--exclude-flow", "f0014"]) == 0
    source = target.read_text(encoding="utf-8")
    compile(source, str(target), "exec")
    assert "_LegacyTLSAdapter" not in source and "VERIFY_TLS" not in source  # http:// only: no TLS code
    assert "final_resp = resp" in source and "結果を表示（ステップ 2:" in source
    assert "/export" not in source  # the excluded flow is gone
    err = capsys.readouterr().err
    assert "結果にするステップ: 2" in err


def test_real_merge_of_two_fixtures(capsys):
    assert cli.main(["inspect", FIXTURE, FIREFOX_FIXTURE, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["flows_total"] == 14 + 6
    assert report["inputs"] == [FIXTURE, FIREFOX_FIXTURE]
    assert report["source"].startswith("結合 2 件")
    assert report["steps_kept"] >= 8


def test_real_legacy_fixture_inspect_shows_auth(capsys):
    assert cli.main(["inspect", LEGACY_FIXTURE]) == 0
    out = capsys.readouterr().out
    assert "認証: NTLM (記録時のユーザー: EXAMPLE\\taro) → 生成コードは session.auth を設定します" in out
    assert re.search(r"^01  f0001\+f0002\+f0003\s+GET", out, re.M)  # the handshake hops folded into step 1
    assert "f0004  http://intra.example.local/WebResource.axd" in out
