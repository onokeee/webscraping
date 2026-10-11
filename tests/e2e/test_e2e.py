"""The end-to-end proof: capture a browsing session, build a plan, generate a script and run that
script - in a subprocess - against a **fresh** server that issues different tokens.

If the generated script merely replayed recorded literals it would be rejected at the first
protected step; it succeeds only by extracting the login token, csrf token, API bearer token and
export signature from the live responses, exactly the way a browser user would.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import pytest

from reqrec.model import GenOptions, Plan, PlanOptions, Recording
from tests.e2e.capture import capture, default_scenario
from tests.e2e.server import PASSWORD, TOKEN_KINDS, USERNAME, Site, SiteServer, restart_server, start_server, stop_server

SCRIPT_TIMEOUT = 60


# --------------------------------------------------------------------------- helpers

@dataclass
class Captured:
    """Everything the e2e tests need from the recording server (server A)."""

    recording: Recording
    base_url: str
    recorded_tokens: dict[str, set[str]]  # every token server A issued, by kind
    server: SiteServer = field(repr=False)


@pytest.fixture
def captured() -> Iterator[Captured]:
    """Start server A, capture the default scenario and hand over A (still running) for a restart."""
    server, base_url = start_server()
    try:
        recording = capture(default_scenario, base_url=base_url)
    except BaseException:
        stop_server(server)
        raise
    state = Captured(
        recording=recording,
        base_url=base_url,
        recorded_tokens={kind: server.site.issued_tokens(kind) for kind in TOKEN_KINDS},
        server=server,
    )
    try:
        yield state
    finally:
        stop_server(state.server)  # whichever server instance is current (A or its replacement)


def _fresh_server(state: Captured) -> Site:
    """Replace server A by server B on the same port: identical URLs, all-new tokens."""
    server, base_url = restart_server(state.server)
    state.server = server
    assert base_url == state.base_url
    return server.site


def _plan_and_generate(recording: Recording, plan_opts: PlanOptions) -> tuple[Plan, str]:
    from reqrec.codegen import generate
    from reqrec.plan import build_plan

    plan = build_plan(recording, plan_opts)
    source = generate(plan, GenOptions())
    assert isinstance(source, str) and source.strip()
    compile(source, "scrape.py", "exec")  # must be valid Python before we even try to run it
    return plan, source


def _write_script(tmp_path: Path, source: str) -> Path:
    script = tmp_path / "scrape.py"
    script.write_text(source, encoding="utf-8")
    return script


def _run_script(script: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    env = {**env, "PYTHONIOENCODING": "utf-8"}  # the script prints Japanese comments / CSV
    return subprocess.run(
        [sys.executable, str(script)],
        env=env,
        cwd=str(script.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=SCRIPT_TIMEOUT,
    )


def _dump(proc: subprocess.CompletedProcess, source: str) -> str:
    return (
        f"returncode={proc.returncode}\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
        f"--- generated script ---\n{source}"
    )


def _assert_fresh_tokens_used(site_b: Site, recorded: dict[str, set[str]]) -> None:
    """Server B's log shows every protected value was re-derived from B's responses."""
    fresh = {kind: site_b.issued_tokens(kind) for kind in TOKEN_KINDS}
    for kind in TOKEN_KINDS:
        assert fresh[kind].isdisjoint(recorded[kind]), kind

    # login: the hidden _token is the one B put in *its* login page, not the recorded one
    posts = site_b.requests_for("POST", "/login")
    assert len(posts) == 1, [e["path"] for e in site_b.log]
    form = posts[0]["form"]
    assert form["_token"] in fresh["login_token"]
    assert form["_token"] not in recorded["login_token"]
    assert form["username"] == USERNAME and form["password"] == PASSWORD
    assert posts[0]["cookies"]["sid"] in fresh["sid"]  # session cookie from B's Set-Cookie

    # pagination: three pages with B's csrf + bearer token
    api_gets = site_b.requests_for("GET", "/api/items")
    assert sorted(e["query"].get("page") for e in api_gets) == ["1", "2", "3"]
    for entry in api_gets:
        csrf = entry["headers"].get("x-csrf-token")
        auth = entry["headers"].get("authorization", "")
        assert csrf in fresh["csrf"] and csrf not in recorded["csrf"], entry["headers"]
        assert auth.startswith("Bearer ") and auth[len("Bearer "):] in fresh["api_token"], auth
        assert auth[len("Bearer "):] not in recorded["api_token"]
        assert entry["cookies"]["sid"] in fresh["sid"]

    # JSON POST: csrf in the body is B's as well
    api_posts = site_b.requests_for("POST", "/api/items")
    assert len(api_posts) == 1
    body = api_posts[0]["json"]
    assert body["name"] == "new-item"
    assert body["csrf"] in fresh["csrf"] and body["csrf"] not in recorded["csrf"]
    assert api_posts[0]["headers"]["content-type"].startswith("application/json")
    assert site_b.items == [{"id": 1001, "name": "new-item"}]

    # signed export link parsed out of B's dashboard
    exports = site_b.requests_for("GET", "/export")
    assert len(exports) == 1
    assert exports[0]["query"].get("sig") in fresh["export_sig"]
    assert exports[0]["query"].get("sig") not in recorded["export_sig"]

    # noise was filtered out of the script
    assert not [e for e in site_b.log if e["route"].startswith("/static") or e["route"] == "/favicon.ico"]

    # browser-like base headers travel with every request
    for entry in site_b.log:
        assert entry["headers"].get("accept-language") == "ja,en;q=0.8", entry["path"]
        assert entry["headers"].get("user-agent", "").startswith("Mozilla/5.0"), entry["path"]


def _kept_sequence(recording: Recording) -> list[tuple[str, str]]:
    """(method, route) of the recorded flows that are not static noise."""
    out = []
    for flow in recording.flows:
        path = flow.request.path
        if path.startswith("/static") or path == "/favicon.ico":
            continue
        out.append((flow.request.method, path))
    return out


# --------------------------------------------------------------------------- tests

def test_generated_script_replays_against_fresh_tokens(captured: Captured, tmp_path: Path) -> None:
    plan, source = _plan_and_generate(captured.recording, PlanOptions())

    # the plan dropped exactly the static noise and hid the password behind an env var
    dropped = {d.url.replace(captured.base_url, "") for d in plan.dropped}
    assert dropped == {"/static/app.css", "/static/logo.png", "/favicon.ico"}
    assert "Secr3t!" not in source
    assert "REQREC_PASSWORD" in source
    assert len(plan.steps) >= 5
    script = _write_script(tmp_path, source)

    site_b = _fresh_server(captured)
    proc = _run_script(script, {**os.environ, "REQREC_PASSWORD": PASSWORD})
    if proc.returncode != 0:
        print(_dump(proc, source))
        pytest.fail(f"generated script exited with {proc.returncode}")
    assert "Traceback" not in proc.stderr, proc.stderr

    # the last step is the CSV export, which main() prints
    assert proc.stdout.strip(), "the script printed nothing"
    assert "id,name" in proc.stdout
    assert "1,item-1-1" in proc.stdout and "3,item-1-3" in proc.stdout

    _assert_fresh_tokens_used(site_b, captured.recorded_tokens)
    # the script made the same conversation as the recording (minus noise), in the same order
    assert [(e["method"], e["route"]) for e in site_b.log] == _kept_sequence(captured.recording)
    assert not (tmp_path / "output.bin").exists()  # text output is printed, not saved


def test_generated_script_with_embedded_password(captured: Captured, tmp_path: Path) -> None:
    plan, source = _plan_and_generate(captured.recording, PlanOptions(redact_secrets=False))
    assert "Secr3t!" in source
    assert "REQREC_PASSWORD" not in source
    assert not any(c.secret for c in plan.constants)
    script = _write_script(tmp_path, source)

    site_b = _fresh_server(captured)
    env = {k: v for k, v in os.environ.items() if k != "REQREC_PASSWORD"}
    proc = _run_script(script, env)
    if proc.returncode != 0:
        print(_dump(proc, source))
        pytest.fail(f"generated script exited with {proc.returncode}")
    assert "id,name" in proc.stdout and "item-1-1" in proc.stdout
    _assert_fresh_tokens_used(site_b, captured.recorded_tokens)


def test_redacted_script_fails_loudly_without_the_secret(captured: Captured, tmp_path: Path) -> None:
    """Without REQREC_PASSWORD the script stops before sending anything, naming the variable."""
    _plan, source = _plan_and_generate(captured.recording, PlanOptions())
    script = _write_script(tmp_path, source)

    site_b = _fresh_server(captured)
    env = {k: v for k, v in os.environ.items() if k != "REQREC_PASSWORD"}
    proc = _run_script(script, env)
    assert proc.returncode != 0, _dump(proc, source)
    assert "REQREC_PASSWORD" in proc.stderr and "設定されていません" in proc.stderr, proc.stderr
    assert "Traceback" not in proc.stderr
    assert "id,name" not in proc.stdout
    # no request at all: an empty password is never sent
    assert site_b.requests_for("POST", "/login") == []
    assert site_b.requests_for("GET", "/dashboard") == []
    assert site_b.requests_for(route="/api/items") == []


def test_generated_script_runs_twice_in_a_row(captured: Captured, tmp_path: Path) -> None:
    """Tokens are per *session*: a second run on the same server must log in afresh and succeed."""
    _plan, source = _plan_and_generate(captured.recording, PlanOptions())
    script = _write_script(tmp_path, source)
    site_b = _fresh_server(captured)
    env = {**os.environ, "REQREC_PASSWORD": PASSWORD}
    first = _run_script(script, env)
    second = _run_script(script, env)
    for proc in (first, second):
        if proc.returncode != 0:
            print(_dump(proc, source))
            pytest.fail(f"generated script exited with {proc.returncode}")
        assert "id,name" in proc.stdout
    posts = site_b.requests_for("POST", "/login")
    assert len(posts) == 2
    assert posts[0]["form"]["_token"] != posts[1]["form"]["_token"]
    assert posts[0]["cookies"]["sid"] != posts[1]["cookies"]["sid"]
    assert len(site_b.requests_for("GET", "/export")) == 2
    assert [it["name"] for it in site_b.items] == ["new-item", "new-item"]
