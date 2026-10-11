"""Opt-in, real engine: record the factory scenario in RecBrowser.exe, generate the script, replay it
against a FRESH mock server and check the Excel file (DESIGN.md §13.13).

Runs only on Windows with ``REQREC_IEHOST_TESTS=1`` (it opens a browser window for ~15 s), the inbox
C# compiler and mitmproxy.  ``tests/e2e/test_factory_replay.py`` covers the same replay without a
browser, from recordings made by this flow.
"""

from __future__ import annotations

import importlib.util
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("REQREC_IEHOST_TESTS") != "1",
    reason="real recording-browser test: Windows + REQREC_IEHOST_TESTS=1",
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_record_generate_and_replay_the_factory_scenario(tmp_path):
    from reqrec import cli, iehost

    if not iehost.availability(str(tmp_path / "iehost_work"))["available"]:
        pytest.skip("recording browser unavailable (no csc.exe)")
    pytest.importorskip("mitmproxy")
    fs = _load("factory_site_live", ROOT / "tests" / "iehost_fixtures" / "factory_site.py")
    sc = _load("factory_scenario_live", ROOT / "tests" / "iehost_fixtures" / "factory_scenario.py")

    exe = iehost.ensure_built(str(tmp_path / "iehost_work"))
    port = _free_port()
    rec = tmp_path / "rec.json"
    result = sc.run_factory_recording(str(tmp_path / "work"), str(rec), port, 0, exe)
    assert result["browser_exit_code"] == 0
    assert result["site_events"][-1] == "news" and "excel_export" in result["site_events"]

    script = tmp_path / "scrape_factory.py"
    assert cli.main(["generate", str(rec), "-o", str(script)]) == 0

    log = tmp_path / "replay.log"
    server = fs.serve_in_thread(str(log), port)  # fresh server: new session ids, tokens and URL keys
    try:
        out = tmp_path / "outputs"
        env = {k: v for k, v in os.environ.items() if not k.startswith("REQREC_")}
        env.update(PYTHONIOENCODING="utf-8", REQREC_OUTPUT_DIR=str(out), REQREC_TXT_PASSWORD=fs.CREDENTIALS[1])
        proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", env=env, cwd=str(tmp_path), timeout=120)
    finally:
        server.stop()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    events = [e["event"] for e in fs.read_log(str(log)) if e.get("event") not in ("static", "not_found")]
    assert events == ["login_page", "login_ok", "menu", "search_page", "plant_change", "picker", "search", "page",
                      "excel_export", "news"], events
    xlsx = out / fs.export_filename("01", "L11")
    rows = fs.read_xlsx_rows(xlsx.read_bytes())
    assert [tuple(r) for r in rows[1:-1]] == [tuple(r) for r in fs.expected_rows(*sc.SCENARIO_FILTER)]
