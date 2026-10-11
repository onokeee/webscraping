"""Factory intranet scenario recorded in the real IE-engine recording browser, replayed by the
generated script against a FRESH mock server (every session id, __VIEWSTATE and URL key differs).

The two recordings in ``tests/fixtures/factory_ie_recording_*.json`` were made by
``tests/iehost_fixtures/factory_scenario.py`` (RecBrowser.exe + mitmdump + the reqrec addon): login
(ASP.NET session id rotated at login, one-time __VIEWSTATE / __EVENTVALIDATION), the menu, the
search screen opened with ``window.open`` and a per-session URL key, an autopostback plant dropdown
that fills the line dropdown, an item picked in a ``showModalDialog`` window, search, page 2 of the
grid, Excel export (``Content-Disposition`` with a percent-encoded Japanese name) and a
``target=_blank`` news page.  ``letter_key`` has a URL key made of letters only (no digit), which
used to be mistaken for a page name and was not traced.

No browser is needed here: the recordings are fixtures, the server is ``factory_site.py``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from reqrec import cli
from reqrec.model import Recording

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
RECORDINGS = {
    "digit_key": FIXTURES / "factory_ie_recording_digit_key.json",
    "letter_key": FIXTURES / "factory_ie_recording_letter_key.json",
}
SCENARIO_FILTER = ("01", "L11", "D", "2026/09/01", "2026/10/10", "A-1002")
PASSWORD_ENV = "REQREC_TXT_PASSWORD"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


fs = _load("factory_site_for_replay", ROOT / "tests" / "iehost_fixtures" / "factory_site.py")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _retarget(src: Path, dst: Path, port: int) -> str:
    """Point the recording at ``127.0.0.1:<port>`` (the recording used ``127.0.0.1.nip.io:<old>``
    because WinINet never proxies a literal loopback address; plain requests needs no DNS)."""
    text = src.read_text(encoding="utf-8")
    old = re.search(r"127\.0\.0\.1\.nip\.io:\d+", text).group(0)
    dst.write_text(text.replace(old, f"127.0.0.1:{port}"), encoding="utf-8")
    return old


@pytest.fixture(params=sorted(RECORDINGS))
def replay(request, tmp_path):
    """(script path, server, site log path, recording) for one fixture against a fresh server."""
    port = _free_port()
    rec_path = tmp_path / "rec.json"
    _retarget(RECORDINGS[request.param], rec_path, port)
    script = tmp_path / "scrape_factory.py"
    assert cli.main(["generate", str(rec_path), "-o", str(script)]) == 0
    log = tmp_path / "site.log"
    server = fs.serve_in_thread(str(log), port)
    try:
        yield script, server, log, Recording.load(str(rec_path))
    finally:
        server.stop()


def _run(script: Path, outdir: Path, password: str | None = fs.CREDENTIALS[1]) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("REQREC_")}
    env.update(PYTHONIOENCODING="utf-8", REQREC_OUTPUT_DIR=str(outdir))
    if password is not None:
        env[PASSWORD_ENV] = password
    return subprocess.run([sys.executable, str(script)], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, cwd=str(script.parent), timeout=120)


def _code_without_comments(source: str) -> str:
    import io
    import tokenize

    toks = [t for t in tokenize.generate_tokens(io.StringIO(source).readline) if t.type != tokenize.COMMENT]
    return tokenize.untokenize(toks)


def _events(log: Path) -> list:
    return [e for e in fs.read_log(str(log)) if e.get("event") not in ("static", "not_found")]


def test_generated_script_replays_the_whole_scenario_on_a_fresh_server(replay, tmp_path):
    script, _server, log, _rec = replay
    proc = _run(script, tmp_path / "out")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    names = [e["event"] for e in _events(log)]
    assert names == ["login_page", "login_ok", "menu", "search_page", "plant_change", "picker", "search", "page",
                     "excel_export", "news"], names
    assert not [e for e in fs.read_log(str(log)) if (e.get("event") or "").endswith("_reject") or e.get("status", 200) >= 400]
    # the Excel export in the middle is saved under the server's Japanese file name, with the right rows
    xlsx = tmp_path / "out" / fs.export_filename("01", "L11")
    assert xlsx.name == "生産実績_01_L11_20261011.xlsx" and xlsx.is_file(), os.listdir(tmp_path / "out")
    rows = fs.read_xlsx_rows(xlsx.read_bytes())
    assert [tuple(r) for r in rows[1:-1]] == [tuple(r) for r in fs.expected_rows(*SCENARIO_FILTER)]
    export = [e for e in fs.read_log(str(log)) if e.get("event") == "excel_export"][0]
    assert rows[-1] == ["出力ID", export["details"]["export_id"]]
    assert f"{xlsx.name} に保存しました" in proc.stdout


def test_no_recorded_session_value_is_replayed(replay):
    """Session ids, one-time tokens and the URL key of the recording must not be in the script."""
    script, _server, _log, rec = replay
    source = _code_without_comments(script.read_text(encoding="utf-8"))  # comments may quote recorded values
    secrets = set()
    for flow in rec.flows:
        for name, value in flow.request.headers:
            if name.lower() == "cookie":
                for part in value.split(";"):
                    k, _, v = part.strip().partition("=")
                    if k in ("ASP.NET_SessionId", ".ASPXAUTH") and v:
                        secrets.add(v)
        for m in re.finditer(r"[?&]key=([^&]+)", flow.request.url):
            secrets.add(m.group(1))
    assert secrets, "the fixture should contain session values"
    leaked = sorted(s for s in secrets if s in source)
    assert leaked == []
    assert fs.CREDENTIALS[1] not in source  # the password is read from the environment


def test_second_run_logs_in_again(replay, tmp_path):
    script, _server, log, _rec = replay
    assert _run(script, tmp_path / "a").returncode == 0
    assert _run(script, tmp_path / "b").returncode == 0
    logins = [e for e in fs.read_log(str(log)) if e.get("event") == "login_ok"]
    assert len(logins) == 2 and logins[0]["session"] != logins[1]["session"]
    assert (tmp_path / "b" / fs.export_filename("01", "L11")).is_file()


def test_missing_password_stops_before_any_request(replay, tmp_path):
    script, _server, log, _rec = replay
    proc = _run(script, tmp_path / "out", password=None)
    assert proc.returncode != 0
    assert PASSWORD_ENV in proc.stderr and "設定されていません" in proc.stderr and "Traceback" not in proc.stderr
    assert _events(log) == []  # not even the login page was requested


def test_wrong_password_fails_with_a_plain_message(replay, tmp_path):
    script, _server, log, _rec = replay
    proc = _run(script, tmp_path / "out", password="wrong")
    assert proc.returncode != 0
    assert "login_fail" in [e["event"] for e in _events(log)]
    # the menu's URL key cannot be found on the login page that came back
    assert "要素が見つかりません" in proc.stderr or "パターンに一致しませんでした" in proc.stderr
