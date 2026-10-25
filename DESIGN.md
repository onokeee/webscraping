# reqrec — design & module contracts

## Module layout (2026-10-12)

**2026-10-12 (3): scope reduction.** reqrec is now a tool only for legacy intranet sites used in
Edge's IE mode over plain `http://`.  Recording happens only in the GUI, in the in-app IE-engine
recording browser (`RecBrowser.exe`, §13.12): `POST /api/record/start` starts mitmdump on
`127.0.0.1` (`RECORD_LISTEN_HOST`) on a free port (`find_free_port`, the GUI's own port avoided)
with `HTTPS_PASSTHROUGH_ARGS` (`--ignore-hosts .*`) always on, and opens the recording browser
through it.  A PC that cannot run the recording browser cannot record; there is no fallback.
Importing a HAR (e.g. saved with IE11's F12 tools) or a reqrec JSON recording, the analysis, code
generation, script runs, downloads, 表示モード, the host filter, 追加モード and the CLI commands
`import` / `inspect` / `generate` / `gui` / `browser` are unchanged.  Everything that existed only
for Chrome / normal Edge / other browsers / smartphones / https recording / mitmproxy flow files
was deleted.  The history sections below still mention these names (as history); where a section
specifies a removed feature, a note dated 2026-10-12 (3) says so.

| area | removed | kept |
|---|---|---|
| Windows system proxy and CA certificate (the `winsupport` sub-section of `gui`, §13.7) | `get_system_proxy`, `set_system_proxy`, `restore_system_proxy`, `refresh_proxy_settings`, `proxy_server_for`, `status_summary`, `mitmproxy_ca_cert_path`, `cert_installed`, `install_ca_cert`, `INTERNET_SETTINGS_KEY`, `DEFAULT_PROXY_OVERRIDE`, `INTERNET_OPTION_*`; `AppState.proxy_backup` / `proxy_server` / `register_proxy_restore` (and its `atexit` hook), `_restore_proxy`, `_PROXY_OVERRIDE`, `_windows_only`; the routes `GET /api/win/status`, `POST /api/win/proxy`, `POST /api/win/proxy/restore`, `POST /api/win/cert/install`; the `windows` block of `/api/state` | `is_windows`, `NOT_WINDOWS_MESSAGE` (core section); `iehost._winreg` |
| other browsers (the `webapp/launch` sub-section) | `find_edge`, `_EDGE_CANDIDATES`, `_EDGE_APP_PATHS_KEY`, `_is_windows`, `open_url`, `DEFAULT_START_URL` | `validate_url` (an empty address is now a `ValueError`), `open_folder` |
| manual recording (記録方式 「自分でブラウザを設定する」 = browser kind `"none"`) | `_BROWSER_KINDS`, `AppState.record_browser_kind` / `record_https_passthrough`; the `record_start` fields `port`, `listen_host`, `set_system_proxy`, `browser`, `https_passthrough` (now ignored) and the response fields `instructions`, `auto_port`, `system_proxy`, `browser_kind`, `https_passthrough`; `listen_host` of `build_command` / `RecorderManager` and the wildcard-to-loopback mapping of `find_free_port` / `wait_until_listening`; the page's port, listen-address, 記録方式, HTTPS and system-proxy inputs and its 「ブラウザ側の手順」 and 「Windows の設定」 cards | the `record_start` fields `hosts`, `append`, `start_url`, `emulation`, `origin`; `RECORD_LISTEN_HOST = "127.0.0.1"`; new `_proxy_address(port)` |
| https recording | `RecBrowser.exe --https`, the C# `Options.HttpsRecorded`, `iehost.launch(https_recorded=...)` | `HTTPS_PASSTHROUGH_ARGS`, now passed to every recording |
| `reqrec record` (the recorder's `run` sub-section, §3) | `cmd_record`, `run_record`, `stop_child`, `format_instructions`, `_print_summary`, `_GRACE_FIRST_WAIT`, `_GRACE_AFTER_SIGINT` | `build_command`, `mitmdump_launcher`, `mitmproxy_available`, `_wait` |
| mitmproxy flow files (the importers' `mitm` sub-section, §2) | `load_mitm`, `_import_mitmproxy`, `_flows_in_order`, `MITM_EXTENSIONS`, `MITMPROXY_INSTALL_HINT`; `.mitm` / `.flows` / `.flow` as input and upload | `flow_from_mitm` and its helpers (used by the recorder addon); `RECORDING_EXTENSIONS = {".har", ".json"}` |
| legacy TLS (codegen, §13.3) | `GenOptions.legacy_tls`, `generate --legacy-tls`, the GUI checkbox; `VERIFY_TLS`, `session.verify`, `import ssl` / `import warnings`, `_LegacyTLSAdapter` in generated scripts | — |

The whole application is **one module, `reqrec.py`, in the repository root** (no package folder,
no data files).  The repository holds only `reqrec.py`, `pyproject.toml`, `requirements.txt` (pinned
libraries for a portable Python), `README.md`, `DESIGN.md`, `.gitignore` and `tests/`.  The layout was flattened twice on 2026-10-12: first the package with
sub-folders (HEAD 65346c2 and earlier) became one flat folder `reqrec/` with 11 files, then
(**2026-10-12 (2)**) those 11 files became `reqrec.py`.  The history sections below (§1–§13.10) were
written for the oldest layout and keep its names; read them through the table below.  The overview,
the current-state sections §13.11–§13.13 and README.md use the current names and the reduced scope
above.

`reqrec.py` from top to bottom: the module docstring, one import block, `__version__`, one `__all__`
(grouped by section), `_register_script_module()`, then one section per file of the 11-file layout,
each headed `# ===== former reqrec/<file>: … =====` (search for that heading) with the former
docstring kept as comments below it.  A file that had itself been merged from several modules keeps
them as sub-sections with the same kind of heading (`# ===== former reqrec/filters.py: …`).  Order:
`core`, `importers`, `analysis`, `codegen`, `recorder`, `iehost`, `RECBROWSER_CS`, `gui`, `GUI_HTML`,
`cli`, and the entry point (`main()` and `if __name__ == "__main__": raise SystemExit(main())`).

| step | former file | became |
|---|---|---|
| 2026-10-12 (2) | `reqrec/__init__.py` | the top of `reqrec.py`, before the first section: `__version__` and `__all__` (now one list for every section), plus `_register_script_module()` (below) |
| 2026-10-12 (2) | `reqrec/core.py` | section `core` (`former reqrec/core.py`; sub-sections `former reqrec/model.py`, `former reqrec/util.py`) |
| 2026-10-12 (2) | `reqrec/importers.py` | section `importers` (sub-sections `former reqrec/importers/__init__.py`, `…/har.py`, `…/mitm.py`); logger still `reqrec.importers`.  Since 2026-10-12 (3) the `…/mitm.py` sub-section holds only `flow_from_mitm` and its helpers (used by the recorder addon) |
| 2026-10-12 (2) | `reqrec/analysis.py` | section `analysis` (sub-sections `former reqrec/filters.py`, `deps.py`, `loops.py`, `plan.py`); bs4 is now imported inside the three functions that parse HTML |
| 2026-10-12 (2) | `reqrec/codegen.py` | section `codegen` |
| 2026-10-12 (2) | `reqrec/recorder.py` | section `recorder` (sub-sections addon, run, manager); `addons` stays, `ADDON_PATH` is now `reqrec.py` itself.  Since 2026-10-12 (3) the run sub-section holds only the mitmdump command line (`build_command`, `mitmdump_launcher`, `mitmproxy_available`, `_wait`) |
| 2026-10-12 (2) | `reqrec/iehost.py` | section `iehost`: the namespace class `iehost` (below) and the top-level classes `IEHostError` / `BrowserProcess`.  Its `main()` (`python -m reqrec.iehost build \| status`) became the CLI sub-command `reqrec browser build \| status` (`cmd_browser_build` / `cmd_browser_status` / `cmd_browser_usage` in the `cli` section) |
| 2026-10-12 (2) | `reqrec/RecBrowser.cs` | constant `RECBROWSER_CS` (raw string, heading `former reqrec/RecBrowser.cs`, right after the `iehost` section), byte for byte.  It is written to a file only to compile it: `<workdir>/bin/RecBrowser.cs`, or a temporary file for `reqrec browser build` |
| 2026-10-12 (2) | `reqrec/RecBrowser.exe` + `.sha256` (git-ignored output of `python -m reqrec.iehost build`) | `RecBrowser.exe` + `.sha256` next to `reqrec.py` (output of `reqrec browser build`; `iehost.SHIPPED_DIR`; git-ignored as `/RecBrowser.exe*`) |
| 2026-10-12 (2) | `reqrec/gui.py` | section `gui` (sub-sections winsupport, webapp/launch, webapp/state, webapp/routes, webapp/__init__).  Flask import name still `reqrec.gui`, blueprint still `reqrec` (endpoint names unchanged).  Since 2026-10-12 (3) the winsupport sub-section is gone and webapp/launch keeps only `validate_url` and `open_folder` |
| 2026-10-12 (2) | `reqrec/gui.html` | constant `GUI_HTML` (raw string, heading `former reqrec/gui.html`, right after the `gui` section), byte for byte except two lines: the Jinja comment at the top, and the AppLocker message, which now names `python -m reqrec browser build` instead of `python -m reqrec.iehost build`.  `create_app` gives it to Jinja from memory as the template `gui.html` (`DictLoader`; the `.html` name keeps autoescaping on), so the index route renders it with `render_template` and Jinja compiles it once per app, as it did the former file; the Flask app has no template / static folder |
| 2026-10-12 (2) | `reqrec/cli.py` | section `cli` (now with the `browser` sub-command); its `main()` and `_exit_code_from_system_exit` are the last section, the entry point |
| 2026-10-12 | `__init__.py`, `codegen.py`, `cli.py` | unchanged (`reqrec/__init__.py`, `reqrec/codegen.py`, `reqrec/cli.py`) |
| 2026-10-12 | `model.py`, `util.py` | `reqrec/core.py` (two sections, in this order) |
| 2026-10-12 | `importers/__init__.py`, `importers/har.py`, `importers/mitm.py` | `reqrec/importers.py` (one module `log`, logger `reqrec.importers`) |
| 2026-10-12 | `filters.py`, `deps.py`, `loops.py`, `plan.py` | `reqrec/analysis.py` (in this order: the deps section needs `DROP_REQUEST_HEADERS` at import time) |
| 2026-10-12 | `recorder/__init__.py`, `recorder/addon.py`, `recorder/run.py`, `recorder/manager.py` | `reqrec/recorder.py` (addon, run, manager).  `ADDON_PATH` became that file itself (was `recorder/addon.py`); the manager's `_GRACE_AFTER_TERMINATE` became `_MANAGER_GRACE_AFTER_TERMINATE` |
| 2026-10-12 | `winsupport.py` | the first section of `reqrec/gui.py`, except `is_windows` / `NOT_WINDOWS_MESSAGE`, which moved to `reqrec/core.py` |
| 2026-10-12 | `webapp/launch.py`, `webapp/state.py`, `webapp/routes.py`, `webapp/__init__.py` | `reqrec/gui.py` (after the winsupport section, in this order).  The Flask app's import name became `reqrec.gui` (was `reqrec.webapp`) |
| 2026-10-12 | `webapp/templates/index.html`, `webapp/static/app.css`, `webapp/static/app.js` | `reqrec/gui.html` (the CSS and JS inlined in `<style>` / `<script>` inside Jinja `raw` blocks, so `/static/*` is no longer served) |
| 2026-10-12 | `iehost/__init__.py`, `iehost/__main__.py` | `reqrec/iehost.py` (`main()`) |
| 2026-10-12 | `iehost/RecBrowser.cs` (and its build output `RecBrowser.exe` + `.sha256`) | `reqrec/RecBrowser.cs` (build output `reqrec/RecBrowser.exe` + `.sha256`) |
| 2026-10-12 | `examples/README.md`, `examples/example_scrape.py` (outside the package) | README.md 「同梱のサンプルで試す」, `tests/fixtures/example_scrape.py` |

Each `reqrec/<x>.py` of the 11-file layout (except `__init__.py`) is the section `<x>` of `reqrec.py`, so a name from the
history sections is found through its 2026-10-12 row and then the 2026-10-12 (2) row
(`webapp/routes.py` → `reqrec/gui.py` → the `gui` section, sub-section `former reqrec/webapp/routes.py`).

| former command | now |
|---|---|
| `reqrec ...` (console script `reqrec = "reqrec.cli:main"`) | `reqrec ...` (`reqrec = "reqrec:main"`; `pyproject.toml` has `py-modules = ["reqrec"]`) |
| `python -m reqrec.cli ...` | `python -m reqrec ...` (or `python path/to/reqrec.py ...`) |
| `python -m reqrec.iehost build \| status` | `reqrec browser build \| status` (`python -m reqrec browser build \| status`); plain `reqrec browser` prints the usage and exits 2, as `python -m reqrec.iehost` did |
| `mitmdump -s reqrec/recorder/addon.py` (later `-s reqrec/recorder.py`) | `mitmdump -s reqrec.py` |
| §13.9's PyInstaller example `pyinstaller … --collect-all reqrec … -m reqrec.cli` | `pyinstaller --onefile --name reqrec --collect-all mitmproxy reqrec.py` (still unverified) |

Qualified names in the history sections map onto plain top-level names: `model.X` / `util.X` /
`core.X`, `importers.X`, `filters.X` / `deps.X` / `loops.X` / `plan.X` / `analysis.X`, `codegen.X`,
`recorder.X` (`recorder.run.X`, `recorder.manager.X`), `winsupport.X` / `launch.X` / `state.X` /
`routes.X` / `gui.X` and `cli.X` are all `reqrec.X` now (`reqrec.webapp.run_gui` → `reqrec.run_gui`),
except the renamed names below and the names removed on 2026-10-12 (3) (table at the top of this
section), which have no counterpart; `iehost.X` stays `iehost.X` (`reqrec.iehost.X`).

**How the one file is used.**
* `reqrec ...` and `python -m reqrec ...`; `python reqrec.py ...` works too (it runs as `__main__`,
  and nothing in it starts `python -m reqrec` as a child process).
* **Distribution**: copy `reqrec.py` into the folder of a portable Python (the folder of `python.exe`)
  in which `requests`, `beautifulsoup4`, `flask` (and `mitmproxy` for recording) are installed:
  Windows' Python puts that folder on `sys.path`, so `<folder>\python.exe -m reqrec gui` works from any
  current directory, and the recorder starts mitmdump with the same interpreter
  (`mitmdump_launcher`), so `Scripts\` need not be on PATH.  Or `pip install` it (`py-modules`; the
  file lands in `site-packages`, or stays in the checkout with `pip install -e`).  A wheel cannot put
  `RecBrowser.exe` next to a top-level module, so the prebuilt recording browser is made after
  installation with `reqrec browser build`, wherever `reqrec.py` then is (README 「Windows での配布と exe 化」).
* `mitmdump -s reqrec.py`: `ADDON_PATH` is reqrec.py itself and the recorder section keeps `addons`.
  There are no internal imports any more, so the former import dance is gone.  mitmproxy's script
  loader executes the file as `__mitmproxy_script__.reqrec` **without** putting it in `sys.modules`,
  but `dataclasses` looks the defining module up there (the annotations are strings) and would fail;
  `_register_script_module()` at the top therefore registers the module object (found with
  `gc.get_referrers`, a few ms) under its own name, as a normal import does.  mitmproxy also
  registers the script module **itself** as an addon (next to the objects in `addons`) and calls every
  attribute named like one of its event hooks (`request`, `response`, `error`, `load`, `running`,
  `done` ...), so no top-level name may be a hook name: Flask's `request` proxy is imported as
  `flask_request` (as `request` it was skipped only because an unbound proxy happens to be falsy;
  `tests/test_recorder.py::TestScriptMode` checks every name against mitmproxy's hooks).  Importing
  is otherwise side-effect free.  bs4 is imported inside the three analysis functions that use it; Flask is
  imported at the top (mitmdump has already imported Flask for its own onboarding app, so it costs
  nothing there).  mitmproxy opens the port before it loads `-s` scripts and holds requests that
  arrive meanwhile, so they are still recorded.  Measured on the development PC (7 runs, median,
  bytecode cached; former `reqrec/recorder.py` → `reqrec.py`): start → listening 1.63 s → 1.66 s,
  start → first proxied request recorded 1.72 s → 1.76 s; loading the addon inside mitmproxy
  21–25 ms → 41–47 ms (importing bs4 eagerly would add about 150 ms).  Without a bytecode cache
  every process compiles the whole file first (about 0.55 s; the first proxied response comes about
  0.5 s later).  That happens only where `__pycache__` next to `reqrec.py` cannot be written (a
  read-only distribution folder, `PYTHONDONTWRITEBYTECODE`): `pip install` writes the cache itself,
  any start from a writable folder writes it, and for a read-only folder `python -m compileall
  reqrec.py` is run once after copying (README 「ポータブル Python のフォルダに置く」).  mitmproxy's
  script loader (`SourceFileLoader`) uses the same `__pycache__/reqrec.cpython-3XX.pyc` as an import.
* The recording browser (§13.12): `iehost.ensure_built(workdir)` writes `RECBROWSER_CS` to
  `<workdir>/bin/RecBrowser.cs` and compiles that; `reqrec browser build` compiles it from a
  temporary file into `RecBrowser.exe` + `RecBrowser.exe.sha256` **next to reqrec.py**
  (`iehost.SHIPPED_DIR`; git-ignored as `/RecBrowser.exe*`).  The build digest is SHA-256 of
  `RECBROWSER_CS` (UTF-8) plus the build settings — for an unchanged source the same value the former
  file gave, so existing work folders are not rebuilt.  A CRLF checkout (`core.autocrlf`) does not
  change it: Python reads source files with universal newlines, so the constant always has LF.
* **The embedded files** `GUI_HTML` and `RECBROWSER_CS` are raw strings (`r'''…'''`): the text is
  written exactly as in a file (`\n`, `\\` reach the HTML / C# unchanged).  They must not contain
  `'''` and must not end with a backslash; neither contains CR or NUL.  Edit them in place
  (README 開発者向け 「埋め込みの HTML / C# を直す」).  A change to `RECBROWSER_CS` changes the build
  digest, so every work folder rebuilds once and a prebuilt `RecBrowser.exe` stops matching until
  `reqrec browser build` is run again.
* **Costs of one file** (development PC): `import reqrec` always imports Flask, so the commands that
  do not use the GUI start about 0.17 s slower than at HEAD 65346c2 (median of `--version`:
  `python -m reqrec.cli` 0.81 s → `python -m reqrec` 0.98 s); the GUI starts faster than the former
  `reqrec.gui`, and mitmdump has Flask loaded already.  Importing Flask lazily would mean creating
  the blueprint `bp` and registering its 22 routes (26 before the 2026-10-12 (3) scope reduction
removed the four `/api/win/*` routes) only inside `create_app`, so it was not done.
  `GET /` costs what it did with the former file (about 17 ms with the Flask test client; the
  template is compiled once, see `GUI_HTML` above).
* **History**: `git log --follow reqrec.py` stops at the commit that created the file (it is far
  larger than any former file, so git sees no rename).  `git blame -w -C -C reqrec.py` traces
  lines across it to the former files and their commits (about 92 % of the lines, checked on a
  scratch commit of this layout), and `git log -- reqrec/` lists the former files' history.

**One namespace.** Every top-level name is bound exactly once (checked with an `ast` walk over the
module: only the optional-import fallback `_mitm_ctx` / `_mitm_http` is bound in both branches of
its `try` / `except ImportError`).  Where former modules clashed, the more widely used name was kept
and the other got a section prefix:

| former name | now |
|---|---|
| `importers.log` | `_importers_log` (logger name `reqrec.importers` unchanged; the recorder keeps `log`) |
| `importers._BOUNDARY_RE` | `_IMPORTERS_BOUNDARY_RE` (analysis keeps `_BOUNDARY_RE`) |
| `importers._b64decode_lenient` | `_importers_b64decode_lenient` (analysis keeps `_b64decode_lenient`) |
| `recorder._FLOW_ID_RE`, `gui._FLOW_ID_RE`, `cli._FLOW_ID_RE` | `_RECORDER_FLOW_ID_RE`, `_GUI_FLOW_ID_RE`, `_CLI_FLOW_ID_RE` (analysis keeps `_FLOW_ID_RE`) |
| `gui._SCHEME_RE` | `_GUI_SCHEME_RE` (analysis keeps `_SCHEME_RE`) |
| `gui._to_int` | `_gui_to_int` (importers keeps `_to_int`) |
| `cli.normalise_flow_id` (empty -> `None`) | `cli_normalise_flow_id` (analysis keeps `normalise_flow_id`, empty -> `""`) |
| `codegen._VERSION` | `__version__` |
| `cli`'s fallback `load_recordings` | removed (the importers' `load_recordings` always exists) |
| `iehost.main` | `cmd_browser_build` / `cmd_browser_status` / `cmd_browser_usage` (CLI) |
| `iehost.build_command`, `_wait`, `_winreg`, `_write_text`, `_GRACE_AFTER_TERMINATE` | unchanged inside the `iehost` namespace (they clash with recorder / gui / cli names; since 2026-10-12 (3) `_winreg` and `_GRACE_AFTER_TERMINATE` no longer have a top-level namesake, the other three still do) |
| `iehost.SOURCE_PATH` | removed: the source is `RECBROWSER_CS`.  The `source` argument of `ensure_built` / `availability` / `shipped_exe` / `build_shipped` is now the C# **text** (default `RECBROWSER_CS`); the distribution folder is `iehost.SHIPPED_DIR` or the new `folder` argument (`is_available` took `folder` instead of `source`; it was removed on 2026-10-12 (3) as unused, `availability` is the check); `iehost.SOURCE_NAME` / `iehost.source_path(workdir)` name the file written for csc; `availability()["source"]` is that path |
| each module's `__all__` | one `__all__` at the top, grouped by section |

**The `iehost` namespace.** Callers use the recording-browser functions qualified
(`iehost.launch(...)`, `iehost.availability(...)`, `iehost.EMULATION_LEVELS`), and several of its
names exist in other sections, so the section keeps its former module as a namespace:
`class iehost` with static methods and constants, never instantiated.  Inside, the functions refer
to each other (and to `is_windows`, `BUILD_PLATFORM`, `SHIPPED_DIR` ...) through `iehost.`, so
replacing one attribute behaves exactly as replacing an attribute of the former module did: tests
`monkeypatch` `iehost.csc_path` / `iehost.is_windows` / `iehost.BUILD_PLATFORM`, and
`iehost.launch` / `iehost.availability` as the GUI routes see them (`routes_mod.iehost`).  This kept
the tests simplest (their `iehost.X` calls did not change).  `IEHostError` and `BrowserProcess` are
top-level classes; `BrowserProcess` is also reachable as `iehost.BrowserProcess`.

**Monkeypatching** a top-level name now affects every section: e.g. `build_command` patched for a
GUI test is also the default `command_builder` of every `RecorderManager` created afterwards
(recorder section), where the former modules each had their own binding.
For the same reason a test must not `importlib.reload` the module (it would replace every class
other tests hold); `tests/test_gui.py` imports a fresh copy of the file instead.

`tests/` was consolidated earlier (one flat folder plus `tests/fixtures/`; each former test
module is a `# ===== former tests/<x>.py` section); the test files import everything from `reqrec`
(`import reqrec as cli`, `from reqrec import iehost` ...).  Test file names quoted in the history sections
are those of the time each section was written; read them through this table.

| former test files (under `tests/`) | now |
|---|---|
| `test_importers.py`, `test_merge.py` | `test_core.py` |
| `test_filters.py`, `test_loops.py`, `test_deps.py`, `test_plan.py`, `test_overrides.py`, `test_auth.py`, `test_review3_analysis.py` | `test_analysis.py` |
| `test_codegen.py`, `test_codegen_phase2.py`, `test_review3_codegen.py` | `test_codegen.py` |
| `test_webapp.py`, `test_webapp_easy.py`, `test_webapp_iehost.py`, `test_winsupport.py` | `test_gui.py` (of the former `test_winsupport.py` only the platform tests remain: `is_windows`, importing without `winreg`; its system-proxy and certificate tests were deleted on 2026-10-12 (3)) |
| `test_webapp_browser.py` | `test_gui_browser.py` (Playwright; `REQREC_CHROMIUM`) |
| `test_integration.py`, `test_integration_legacy.py`, `e2e/test_e2e.py`, `e2e/test_server_capture.py`, `e2e/test_factory_replay.py` | `test_integration.py` |
| `test_iehost_engine.py`, `test_iedriver.py`, `test_factory_site.py`, `e2e/test_gui_recording.py`, `e2e/test_factory_live.py` | `test_real_engine.py` (opt-in parts: `REQREC_IEHOST_TESTS=1`) |
| `e2e/mock_adapter.py`, `e2e/server.py`, `e2e/capture.py` | `support.py` |
| `iehost_fixtures/testsite.py`, `factory_site.py`, `factory_scenario.py`, `iedriver.py` | `ie_support.py` (`python -I tests/ie_support.py testsite\|factory-site\|iedriver ...`) |
| `iehost_fixtures/IEDriver.cs` | `IEDriver.cs` |
| `test_cli.py`, `test_recorder.py`, `test_iehost.py` | unchanged |

## Overview

`reqrec` records the HTTP traffic of a legacy intranet site used in Edge's IE mode over plain
`http://` and generates a **standalone Python script** (`requests` + `BeautifulSoup`) that
replays the same conversation — like a macro recorder, but at the HTTP request/response level
instead of screen elements.  Recording is done in the GUI's own IE-engine recording browser
(`RecBrowser.exe`, §13.12), whose process alone is routed through a mitmproxy-based recording proxy
(the reqrec addon); an existing HAR file (e.g. saved with IE11's F12 tools) or reqrec JSON
recording can be imported instead.

```
 RecBrowser.exe ──its own proxy setting──▶ mitmproxy addon ─┐
 HAR / reqrec JSON file ────────────────────────────────────┴──▶ Recording (JSON) ──▶ build_plan ──▶ Plan ──▶ generate ──▶ scrape.py
```

The three stages are deliberately separated so each can be tested alone:

| stage | input → output | module |
|---|---|---|
| import / record | HAR / reqrec JSON / the recording browser through the addon → `Recording` | `importers`, `recorder` sections of `reqrec.py` |
| analyse | `Recording` → `Plan` | `analysis` section (filters → deps → loops → plan sub-sections) |
| generate | `Plan` → Python source | `codegen` section |
| UI | argparse CLI; Flask GUI (§13.6, §13.11); recording browser (§13.12) | `cli`; `gui` + `GUI_HTML`; `iehost` + `RECBROWSER_CS` |

All shared types live in the **`core` section** of `reqrec.py` (its former `model.py` sub-section);
shared helpers in its former `util.py` sub-section.  Both are finished and are the single source of truth — read them first.
If you believe a field is missing, do **not** edit the model; add a module-local workaround and
report the request.

## 1. Recording layer (`model.py`)

`Recording{flows, meta}` → `Flow{id, request, response, started_at, page_ref, resource_type}`.
Flow ids are `f0001, f0002, …` in **chronological order** (sorted by `started_at`). Bodies are
`bytes | None`; `.text()` decodes using charset detection (`util.decode_body`). Request headers are
stored **exactly as captured** (including HTTP/2 pseudo-headers such as `:authority` from Chrome
HARs) — cleaning happens in `filters.clean_request_headers`.

## 2. Importers (`reqrec/importers/`)

```python
# reqrec/importers/__init__.py
def load_recording(path: str) -> Recording
```
Dispatch: `.har` → HAR; `.json` → sniff: a dict with `"log"` is HAR, a dict with `"flows"` is our
Recording. Unknown → `ValueError` with a clear message listing the supported `.har, .json`.  This
includes the mitmproxy flow files `.mitm` / `.flows` / `.flow`, whose importer was removed on
2026-10-12 (3).

```python
# reqrec/importers/har.py
def load_har(path: str) -> Recording
def recording_from_har(har: dict, source: str = "") -> Recording
```
* Sort entries by `startedDateTime` (ISO-8601, may have `Z` or `+09:00`; parse to epoch float).
* request: `method`, `url`, `headers[{name,value}]`, body from `postData.text`
  (if absent but `postData.params` present → urlencode them). If `postData.mimeType` is set and no
  `Content-Type` header exists, add one.  If `request.cookies` is present and there is no `Cookie`
  header, synthesise `Cookie: a=1; b=2`.
* response: `status` (0 / missing → `response=None`), `headers`, body from `content.text`;
  `content.encoding == "base64"` → b64decode, else encode the text with the charset from
  `content.mimeType` / `Content-Type` (fallback utf-8). If `response.cookies` is present but no
  `Set-Cookie` header, synthesise `Set-Cookie` headers (`name=value; Path=…; Domain=…; …`).
  `mime_type` from `content.mimeType` or the header.
* `_resourceType` → `resource_type` (lower-case), `pageref` → `page_ref`.
* `meta = {"source": "har", "file": source, "creator": log.creator.name/version, "imported_at": util.now_iso()}`.
* Tolerate missing/odd fields (never crash on a real-world HAR; skip an entry only if it has no URL).

```python
# reqrec/importers/mitm.py   — now only the converter the recorder addon (§3) uses
def flow_from_mitm(flow, flow_id: str) -> Flow   # HTTPFlow (or a duck-typed object) -> Flow
```
`load_mitm` (reading saved `.mitm` flow files with `mitmproxy.io.FlowReader`) was removed on
2026-10-12 (3); `flow_from_mitm` and its helpers (`decode_header_fields`, `infer_resource_type`,
`_timestamp`) stay.  Use `flow.request.pretty_url`, `headers.fields` (bytes pairs → str, latin-1/utf-8 tolerant),
`flow.request.content` / `flow.response.content` (**decoded** of Content-Encoding; fall back to
`raw_content` when decoding fails), `flow.request.timestamp_start`.

## 3. Recorder (`reqrec/recorder/`)

```python
# reqrec/recorder/addon.py   — a mitmproxy addon (importable without mitmproxy *installed* at module
#                              import time only if guarded; it's fine to require mitmproxy here)
class ReqRecAddon:   options: reqrec_out (str path), reqrec_hosts (str, comma-separated, "" = all)
    load(loader) / response(flow) / error(flow) / done()
addons = [ReqRecAddon()]
```
Append every completed HTTP flow (optionally only for the given hosts and their sub-domains) and
**flush the JSON file atomically after every response** (write temp file + `os.replace`) so a
killed session still leaves a valid recording. `meta = {"source": "mitmproxy", "started_at": …}`.

```python
# reqrec/recorder/run.py   — now only the mitmdump command line
RECORD_LISTEN_HOST = "127.0.0.1"
def mitmproxy_available() -> bool          # a mitmdump executable on PATH or an importable mitmproxy
def mitmdump_launcher() -> list[str]       # [mitmdump] when on PATH, else [sys.executable, "-c", MITMDUMP_PYTHON_STUB]
def build_command(out: str, port: int = 8080, hosts: list[str] | str | None = None,
                  extra_args: Sequence[str] = ()) -> list[str]
```
`build_command` returns (the bracketed parts only when they apply)

```
<mitmdump_launcher()> -s <ADDON_PATH> --set reqrec_out=<absolute out> [--set reqrec_hosts=a,b]
    -p PORT --listen-host 127.0.0.1 --set flow_detail=0 [extra_args...]
```
It is the default `command_builder` of `RecorderManager` (§13.6), the only way reqrec records; the
GUI always passes `extra_args=HTTPS_PASSTHROUGH_ARGS` (`--ignore-hosts .*`, §13.12).  The proxy
always listens on this PC only: its one client is the recording browser.  `run_record` (the `reqrec record` command: Japanese instructions for pointing
a browser at the proxy, installing the CA certificate / `http://mitm.it`, `Ctrl+C` to stop) was
removed on 2026-10-12 (3) together with `stop_child`, `format_instructions` and `build_command`'s
`listen_host` parameter.

## 4. Filters (`reqrec/filters.py`)

```python
TRACKER_HOSTS: list[str]                 # analytics/ads/monitoring domains (conservative; never a real content host)
STATIC_EXTENSIONS: frozenset[str]        # .png .jpg .jpeg .gif .webp .svg .ico .css .js .mjs .map .woff .woff2 .ttf .otf .eot .mp4 .webm .mp3 .wasm …
STATIC_RESOURCE_TYPES: frozenset[str]    # image stylesheet script font media manifest texttrack ping beacon csp_report prefetch preflight signedexchange other
DROP_REQUEST_HEADERS: frozenset[str]     # host cookie content-length connection accept-encoding transfer-encoding te trailer keep-alive upgrade proxy-* if-none-match if-modified-since if-range range? (keep range) expect
                                         # + any header starting with ':'  + 'content-type' is handled by plan.py (dropped for form/json/multipart bodies)

def classify_noise(flow: Flow, opts: PlanOptions) -> str | None    # reason to drop, or None to keep
def filter_flows(recording: Recording, opts: PlanOptions) -> tuple[list[Flow], list[Dropped]]
def collapse_redirects(flows: list[Flow]) -> list[list[Flow]]
def classify_cookies(flows: list[Flow]) -> tuple[list[InitialCookie], set[str]]
def compute_base_headers(flows: list[Flow]) -> Headers
def clean_request_headers(headers: Headers) -> Headers
```
`classify_noise` rules, in order (first hit wins; `keep_all` skips rules 4–9, host rules always apply):
1. `include_hosts` set and host not in it → `"host not in --include-host"`
2. host in `exclude_hosts` → `"host excluded"`
3. no response → `"no response recorded"`
4. `method == OPTIONS` → `"CORS preflight"`
5. tracker host (unless `keep_trackers`) → `"tracker/analytics host"`
6. static (unless `keep_static`): resource_type in STATIC_RESOURCE_TYPES, or response mime is
   `image/*`, `font/*`, `audio/*`, `video/*`, `text/css`, `*javascript*`, `application/wasm`,
   `application/octet-stream` **only when** the URL extension is static, or URL extension static and
   mime unknown/`text/plain`, or path ends with `/favicon.ico` → `"static asset (<why>)"`
7. status 304 → `"304 not modified (browser cache)"`
8. websocket upgrade (`Upgrade: websocket` or status 101) → `"websocket"`
9. `text/event-stream` → `"server-sent events stream"`
Everything else is kept, including HTML documents, JSON/XML APIs, text, redirects, downloads
(e.g. a CSV / PDF the user clicked — not matched by rule 6 because extension/mime are not static).

`collapse_redirects`: walk kept flows in order; when flow *i* has a 3xx response with `Location`
and the **next kept flow** *i+1* is a `GET`/same-method request whose URL equals
`urljoin(flow_i.url, location)` (compare ignoring fragment), chain them; continue while the chain's
last hop is itself a redirect. Each group is `[first, …, final]`; everything else is a singleton.

`classify_cookies`: scan flows in order; collect names from every `Set-Cookie` seen so far
(managed). A cookie in a request `Cookie` header whose name has **not** been set by any earlier
response is *pre-existing*: emit `InitialCookie(name, value, domain=request host, path="/")` once
per (name, host). Return `(initial_cookies, managed_names)`.

`compute_base_headers`: after `clean_request_headers`, the (name, value) pairs present with the
*same value* in **every** kept request (case-insensitive names; keep the first spelling). Never
includes `referer`, `content-type`, `origin`, `authorization`, or any `x-*` header (those stay
per-step so dependency detection can replace them).

## 5. Dependency detection (`reqrec/deps.py`)

The "intelligence": for each request, find which of its values were produced by an earlier response.

```python
@dataclass
class Candidate:
    location: str           # "path" | "query" | "form" | "json" | "header" | "multipart"
    name: str               # param / header / multipart field name; for "path" the 0-based segment index as str; for "json" a dotted path "a.b[0].c"
    value: str              # the recorded value (str; numbers stringified)
    json_path: list | None  # for location == "json"

def find_candidates(flow: Flow, opts: PlanOptions) -> list[Candidate]
def locate_value(value: str, source: Flow) -> Extractor | None      # var left as "" ; caller names it
def find_cookie(value: str, earlier: list[Flow]) -> tuple[str, str] | None  # (cookie name, raw cookie value) if value equals (any variant of) a Set-Cookie value from an earlier response
def is_dynamic_looking(value: str) -> bool                          # long random-ish token heuristic (for warnings)
```
* Candidates: every query value, form value, JSON leaf (str/int/float, via recursive walk),
  multipart text field, path segment, and header value **except** headers in
  `filters.DROP_REQUEST_HEADERS`, `user-agent`, `accept*`, `sec-*`, `referer`, `origin`,
  `cache-control`, `pragma`, `dnt`, `priority`, `content-type`. Skip values shorter than
  `opts.min_value_length`, and values that are purely alphabetic common words ≤ 6 chars
  (e.g. `true`, `json`, `ja`, `asc`) — keep digits-only values of ≥ 4 chars (ids).
* `locate_value(value, source)` searches `source.response` in this priority and returns the first hit,
  trying every spelling in `util.value_variants(value)`:
  1. response header equal to the value → `header`
  2. JSON body (if `util.is_json_mime` or body parses as JSON) → exact leaf match → `json` with `path`
  3. HTML (`util.is_html_mime` or body starts with `<`) — parse with BeautifulSoup(`html.parser`):
     a. `<input name=X value=V>` → `html_input(name=X)`
     b. `<meta name=X content=V>` → `html_meta(name=X)`
     c. any element attribute == V, element locatable by `#id`, `[name=…]`, `tag[data-*=…]`, or a
        unique `tag.class` selector (verify uniqueness with `select`) → `html_attr(selector, attr)`;
        if V is a *substring* of the attribute (e.g. a token inside an href), add `pattern` with
        escaped context around the match and one capture group.
     d. element whose stripped text == V and which is locatable as in (c) → `html_text(selector)`
     e. inline `<script>` / anywhere in text: `regex` with ≤ 24 chars of escaped context on each side
        and a capture group that matches `[^"'&<>\s]+?` style tokens: `re.escape(prefix) + r'([^"\'&<>\s]+?)' + re.escape(suffix)`
        — then **verify** the pattern re-matches the original value in the recorded text.
  4. Any other textual body → `regex` as in 3e.
  5. `Location` header containing the value (final URL) → `url` with a verified pattern.
  Never return a locator keyed by the dynamic value itself (that would break on the next run).
  Patterns must have exactly **one** capturing group and be verified against the recorded text.
* `find_cookie`: compare against cookie values parsed from earlier `Set-Cookie` headers (first
  `name=value` segment), including URL-decoded/encoded variants (Laravel's `XSRF-TOKEN` is sent
  URL-encoded in the cookie and decoded in the `X-XSRF-TOKEN` header).

## 6. Loop detection (`reqrec/loops.py`)

```python
@dataclass
class LoopGroup:
    groups: list[list[Flow]]   # the redirect-chains that fold into one looped step, in order
    location: str              # "query" | "form" | "json" | "path"
    name: str                  # param name / json dotted path / path segment index
    values: list[str]
    numeric_range: tuple[int, int] | None

def detect_loops(groups: list[list[Flow]], opts: PlanOptions) -> list[LoopGroup]
```
Fold **≥ 3 consecutive** kept groups with identical method, URL-without-query, parameter *names*
(query / form / json leaf paths), body kind and headers (ignoring `referer`), where **exactly one**
value differs across all of them. `numeric_range` is set when the values are consecutive integers
(step ±1). Groups that belong to a loop must not be referenced by `Extractor`s of later steps other
than through the last iteration (plan.py enforces this by running loop detection *before*
dependency detection and treating the last flow of the loop as the step's response).

## 7. Plan builder (`reqrec/plan.py`)

> 2026-10-25: `PlanOptions.redact_secrets` now defaults to **False** (the user's decision: recorded
> passwords are written into the script so the GUI's [試しに実行する] runs with one click). The
> redaction described below is the opt-in (`--redact`, GUI 詳細設定 「パスワードなどをスクリプトに書き込まず、
> 実行するときに入力する」). Digest passwords (never on the wire) are always read from the environment.

```python
def build_plan(recording: Recording, opts: PlanOptions | None = None) -> Plan
```
1. `filter_flows` → kept / dropped.
2. `collapse_redirects` → groups. `detect_loops` (if enabled) → fold groups into looped steps.
3. `classify_cookies` → `Plan.initial_cookies` (only cookies for hosts that appear in kept flows).
4. `compute_base_headers` → `Plan.base_headers`.
5. For each step in order, build a `Step` from the **first** flow of its group (request) and the
   **last** flow (response → `response_kind`, `expected_status`). Then for every `Candidate`:
   * `util.looks_like_timestamp(value, around=flow.started_at)` → `Ref.expr("str(int(time.time()*1000))")` / `"str(int(time.time()))"`.
   * `find_cookie` → `Ref.expr('session.cookies.get("NAME")')` (or `unquote(session.cookies.get("NAME"))` when the header value is the URL-decoded cookie).
   * search earlier steps' responses, **latest first**, with `locate_value` (for a collapsed chain,
     search the final response first, then intermediate hops only for `header`/`url` kinds) →
     add/reuse an `Extractor` on that step (de-duplicate by (step, kind, locator)); value → `Ref.var`.
   * else if the same value was already sent in an **earlier request** (same literal, not traced to a
     response) → one `Constant` (UPPER_SNAKE from the param name) reused everywhere; if
     `util.looks_like_secret_name(name)` and `opts.redact_secrets` → `secret=True, env_var="REQREC_<NAME>"`.
   * else if `util.looks_like_secret_name(name)` and `opts.redact_secrets` → secret `Constant`.
   * else literal `Ref.lit`. If `deps.is_dynamic_looking(value)` add a `Plan.warnings` entry
     ("step N: value of `X` looks dynamic but could not be traced to any earlier response; replaying the recorded literal may fail").
   The very first step can only have constants / literals.
6. Per-step headers = `clean_request_headers(request.headers)` minus `base_headers`; drop
   `content-type` when `body_kind in {form, json, multipart}`.
7. Body: `application/x-www-form-urlencoded` → `form`; JSON mime (or body parses as JSON object/array)
   → `json_body` with `Ref` leaves; `multipart/form-data` → parse parts (stdlib `email.parser` /
   manual boundary split) → `multipart`; other → `raw_body`.
8. `func_name = f"step_{index:02d}_{method.lower()}_{slug}"` where slug = `util.safe_identifier` of the
   last 1–2 non-empty path segments (or host when path is `/`), made unique.
   Extractor `var` names: `util.safe_identifier(param_name)` made unique across the whole plan
   (e.g. `token`, `csrf_token`, `authorization` → for `Authorization: Bearer X` the candidate value is
   `X` and the header Ref becomes `Ref.expr('"Bearer " + access_token')` — handle the `Bearer `/`Basic `
   prefix explicitly).
9. `Plan.meta = {"source": recording.meta, "generated_at": util.now_iso(), "flows_total": …, "flows_kept": …}`.
10. `opts.max_steps` truncates with a warning.

## 8. Code generator (`reqrec/codegen.py`)

> 2026-10-25: generated scripts report progress on **stderr** (stdout stays the result):
> `_step_start(no, total, "METHOD /path")` before each step call in `main()` (inside the loop for
> a looped step, label + `var=value`), `_step_ok(resp)` after it prints
> `[no/total] OK  METHOD /path (status)  「<live HTML title>」`, `main()` ends with
> `[完了] すべての手順が終わりました（N 手順）`, and the `__main__` block catches `Exception`, prints
> `[no/total] 失敗  METHOD /path` for an unfinished step and re-raises (traceback kept). The GUI's
> `ScriptRunner` matches these lines (`_PROGRESS_LINE_RE`) and reports `output_tail` (stdout + progress
> lines in arrival order, shown in the run console) and `errors_tail` (stderr without them).

```python
def generate(plan: Plan, opts: GenOptions | None = None) -> str
```
Output is a self-contained script, **valid Python 3.8+**, that:
* starts with a module docstring (generated-by, source, step count, warnings) and the fixed import
  block `json, os, re, sys, time`, `from urllib.parse import unquote, urljoin`, `requests`,
  `from bs4 import BeautifulSoup`;
* defines `TIMEOUT`, `DELAY`, constants (secrets as `os.environ.get("ENV", "")` with a comment),
  `BASE_HEADERS`, `INITIAL_COOKIES`, and helpers `_soup(resp)`, `_check(resp, expected)`,
  `_regex(text, pattern)` (raises a clear `RuntimeError` naming the pattern on miss),
  `_json_path(data, path)` (clear error naming the path), `_attr(soup, selector, attr)`, `_text(soup, selector)`;
* one function per `Step`: `def step_NN_xxx(session, <needed vars…>): -> (resp, dict_of_extracted)`;
  looped steps take the loop var as a parameter and `main()` calls them inside `for VAR in …:`,
  collecting `results`;
* `main()` builds the `Session`, applies base headers and initial cookies, runs steps in order with
  `ctx` threading, sleeps `DELAY` between steps, and finally prints the last result (JSON pretty-printed
  with `ensure_ascii=False`; HTML → title + hint comment; text → first 2000 chars; binary → saves
  `output.bin`). `if __name__ == "__main__": main()`.
* **Every literal that came from the recording is emitted with `repr()`** (or `json.dumps` for JSON
  bodies) — never by string concatenation into source. This is a security boundary: recorded content
  is attacker-controlled. `Ref.expr` is emitted verbatim, `Ref.var` as the identifier.
* query/form pairs: a `dict` when names are unique, else a `list` of tuples. JSON bodies: a Python
  literal with `Ref`s substituted (`True/False/None`, nested). Multipart: `files={name: (filename,
  content_bytes, content_type)}` + `data={…}`; file content > 64 KiB → `b""  # TODO` + warning.
* Non-literal URL pieces: `"https://h/users/" + str(user_id) + "/x"`.
* `allow_redirects=step.allow_redirects` only when False.
* Comments in **Japanese** (the end user is Japanese), identifiers in English. `GenOptions.comments=False` suppresses them.

The output must `compile()` for every Plan; tests must also *execute* generated scripts against a
local server (see §10).

## 9. CLI (`reqrec/cli.py`)

```
reqrec import   INPUT(.har|.json) -o rec.json
reqrec inspect  INPUT [filter options] [--json]
reqrec generate INPUT -o scrape.py [filter options] [--html-parser html.parser|lxml] [--redact]
                [--delay SEC] [--timeout SEC] [--no-comments] [--strict-status] [--dump-plan plan.json] [--run]
reqrec gui      [--host 127.0.0.1] [--port 8765] [--workdir DIR] [--no-browser]
reqrec browser  build | status
filter options: --include-host H (repeatable, comma ok) --exclude-host H --keep-static --keep-trackers
                --keep-all --no-collapse-redirects --no-loops --min-value-length N --max-steps N
```
(`gui` and `browser` came later: Phase 2 and the 2026-10-12 (2) layout.)  The former
`reqrec record -o rec.json [-p 8080] [--listen-host 127.0.0.1] [--hosts a.com,b.com]` was removed
on 2026-10-12 (3): recording is done only in the GUI's recording browser (§13.12), and
`reqrec record` is now an unknown command (usage error, exit 2).  `generate --legacy-tls` (§13.3) is
gone too.

`main(argv=None) -> int`. Messages in Japanese. `inspect` prints a table: kept steps (index, method,
status, url, extracted vars) then dropped flows with reasons, then warnings. `generate` prints the
plan summary + warnings to stderr and writes the script (or `-` for stdout). Exit codes: 0 / 1 (error) / 2 (usage).
`--run` executes the generated script right away with `sys.executable`.

## 10. Tests (`tests/`)

* `tests/fixtures/*.har` — hand-written realistic Chrome/Firefox HARs (login with CSRF hidden input,
  JSON API with bearer token from a login JSON, pagination, static noise, trackers, a redirect chain).
* unit tests per module.
* `tests/e2e/server.py` — a stdlib `ThreadingHTTPServer` "site": `/login` (HTML form with random
  per-session `_token` hidden input + `Set-Cookie`), `POST /login` (validates token+cookie, 302 →
  `/dashboard`), `/dashboard` (HTML with `<meta name="csrf-token">`, an inline `window.API_TOKEN="…"`
  script, a link containing a token), `/api/items?page=N` (JSON, requires `X-CSRF-Token` or
  `Authorization: Bearer`), `POST /api/items` (JSON body), static noise (`/static/app.css`,
  `/static/logo.png`, `/favicon.ico`). Tokens are **random per run** so a replayed literal fails.
* `tests/e2e/capture.py` — drives the site with `requests` and builds a `Recording` (use
  `resp.raw.headers.getlist("Set-Cookie")`, include `resp.history`).
* `tests/e2e/test_e2e.py` — capture → `build_plan` → `generate` → run the script in a **subprocess**
  (`sys.executable`, env with `REQREC_PASSWORD`) against a fresh server → assert the output contains
  the items and the server saw fresh tokens.
* `tests/e2e/mock_adapter.py` — a `requests` transport adapter that serves scripted responses, so
  HAR-fixture-generated scripts can be executed in-process against fake hosts.

## 11. Non-goals / known limits (document in README)

JavaScript-computed signatures (HMAC in JS, Akamai/Cloudflare challenges), captchas, TLS/HTTP2
fingerprinting, WebSocket flows. The tool makes the first 80% mechanical; the generated script is a
readable starting point to edit.

## 12. File ownership for parallel implementation

| owner | files |
|---|---|
| A importers/recorder | `reqrec/importers/__init__.py`, `reqrec/importers/har.py`, `reqrec/importers/mitm.py`, `reqrec/recorder/*`, `tests/test_importers.py`, `tests/test_recorder.py`, `tests/fixtures/*.har` |
| B filters | `reqrec/filters.py`, `tests/test_filters.py` |
| C deps/loops/plan | `reqrec/deps.py`, `reqrec/loops.py`, `reqrec/plan.py`, `tests/test_deps.py`, `tests/test_loops.py`, `tests/test_plan.py` |
| D codegen | `reqrec/codegen.py`, `tests/test_codegen.py`, `tests/e2e/mock_adapter.py` |
| E cli/docs | `reqrec/cli.py`, `README.md`, `examples/*`, `tests/test_cli.py` |
| F e2e | `tests/e2e/server.py`, `tests/e2e/capture.py`, `tests/e2e/test_e2e.py`, `tests/e2e/__init__.py` |

Nobody edits `model.py`, `util.py`, `pyproject.toml` or another owner's files. No `git` commands.

---

# Phase 2 — no-code GUI (Flask), Edge IE-mode support, multi-tab recordings

User requirements added after v0.1: (1) a **no-code** tool — a **Flask web app** — rather than CLI only;
(2) first-class session / cookie handling (already in v0.1, exposed in the GUI); (3) **Edge IE mode**
support: recording through the Windows system proxy (since replaced by the in-app recording
browser, §13.12; the system-proxy path was removed on 2026-10-12 (3)), Windows integrated auth
(NTLM / Negotiate), legacy TLS servers (removed on 2026-10-12 (3): reqrec targets `http://` only, §13.3),
Shift_JIS pages, ASP.NET WebForms; (4) screens that open in a **new tab**
(`target=_blank` / `window.open`) — covered by the recording browser (popups open as tabs in its
own process and are recorded), and for the HAR path by **merging several recordings**.

`model.py` already carries the new fields (do not edit it): `PlanOptions.exclude_flow_ids /
include_flow_ids / final_flow_id / detect_auth`, `GenOptions.legacy_tls` (removed on 2026-10-12 (3)), `Plan.auth: AuthInfo`,
`Plan.final_step_index`, `Recording.merge(list)`, `Recording.save(path)` (always atomic).
`cli.py` already has the `gui` sub-command calling `reqrec.webapp.run_gui(host, port, workdir, open_browser)`.

## 13.1 Manual overrides and the "result" step  (filters.py, plan.py, codegen.py, cli.py)

* `filters.classify_noise`: a flow whose id is in `opts.exclude_flow_ids` → reason
  `"excluded by user"` (checked **first**, before host rules). A flow in `opts.include_flow_ids`
  is kept regardless of rules 3–9 (but still needs a response: a response-less flow cannot be a
  step → reason `"no response recorded"`).
* `plan.build_plan`: when `opts.final_flow_id` names a flow that ended up in a step (as any of its
  `source_flow_ids`), set `Plan.final_step_index = that step's index`; if the flow was dropped,
  add a warning and leave `None`.
* `codegen`: `main()` still runs every step in order; the printed result is the step named by
  `Plan.final_step_index` (fall back to the last step). Implementation: after that step's call,
  `final_resp = resp`; the final print block uses `final_resp` and that step's `response_kind`.
* `cli`: `inspect` / `generate` gain `--exclude-flow ID` (repeatable, comma ok), `--include-flow ID`,
  `--final-flow ID`, plus conveniences `--exclude-step N` / `--final-step N` that resolve step
  numbers to flow ids by building the plan once without overrides, then rebuilding. `inspect` shows
  the flow id(s) of every step (`f0008+f0009`) and of every dropped flow so users can refer to them.

## 13.2 HTTP authentication handshakes  (filters.py, plan.py, codegen.py)

Intranet sites used through IE mode typically use **Integrated Windows Authentication**. On the wire:

```
GET /            → 401  WWW-Authenticate: Negotiate, NTLM
GET /  Authorization: NTLM TlRMTVNTUAAB…   → 401  WWW-Authenticate: NTLM TlRMTVNTUAAC…
GET /  Authorization: NTLM TlRMTVNTUAAD…   → 200
```
(Basic: one 401 then the same request with `Authorization: Basic …`; Digest similar with a nonce.)

* `filters.collapse_auth_handshakes(flows) -> tuple[list[list[Flow]], Optional[AuthInfo]]` (new):
  detect, **before** `collapse_redirects`, a run of flows with the same method + URL (ignoring
  fragment) where every hop but the last is a 401 whose `WWW-Authenticate` names a scheme and the
  next hop carries `Authorization:` with that scheme; fold the run into one group whose *request* is
  the **last** attempt (the one that got through) and whose response chain is the final response
  only. Return `AuthInfo(kind, hosts, realm, username)` for the first scheme seen (`negotiate` when
  the client answered with Negotiate, `ntlm` when with NTLM, else `basic` / `digest`). For NTLM,
  parse the Type-3 message (base64 NTLMSSP, message type 3) to recover `DOMAIN\user` when possible
  (fields are UTF-16LE when the Unicode flag is set) — informational only, never a secret. For
  Basic, decode `user:password` and expose `username`; the password goes into a **secret**
  `Constant` (`AUTH_PASSWORD`, env `REQREC_AUTH_PASSWORD`) and the username into a plain
  `Constant` (`AUTH_USERNAME`); set `AuthInfo.username_const / password_const` accordingly.
  Any later request carrying `Authorization` with the same scheme (NTLM is connection-oriented,
  Basic is repeated on every request) has that header **removed** from the step headers.
* `plan.build_plan` runs it when `opts.detect_auth`; sets `Plan.auth`; the 401 hops never become
  steps. `deps.header_candidates` must not treat NTLM/Negotiate/Basic/Digest `Authorization` values
  as traceable candidates once `Plan.auth` exists (Bearer tokens are unaffected).
* `codegen` (when `plan.auth` is set), right after `session = requests.Session()`:
  * basic → `session.auth = (AUTH_USERNAME, AUTH_PASSWORD)`;
  * digest → `session.auth = requests.auth.HTTPDigestAuth(AUTH_USERNAME, AUTH_PASSWORD)` (constants as for basic);
  * ntlm / negotiate →
    ```python
    # 統合 Windows 認証（NTLM / Negotiate）: 記録時のユーザー: DOMAIN\user
    try:
        from requests_negotiate_sspi import HttpNegotiateAuth  # Windows: 今ログインしているユーザーで認証（pip install "reqrec[sspi]"）
        session.auth = HttpNegotiateAuth()
    except ImportError:
        from requests_ntlm import HttpNtlmAuth  # 他の OS / 別ユーザーで認証する場合（pip install "reqrec[ntlm]"）
        session.auth = HttpNtlmAuth(os.environ.get("REQREC_NTLM_USER", r"DOMAIN\user"), os.environ.get("REQREC_NTLM_PASSWORD", ""))
    ```
    The docstring "注意" lists the required package and env vars. No `Authorization` header of that
    scheme appears anywhere in the emitted steps.

## 13.3 Legacy TLS and certificate verification  (removed)

**Removed on 2026-10-12 (3)**: reqrec targets plain `http://` sites only.  This section used to
require `VERIFY_TLS = True` plus `session.verify = VERIFY_TLS` in every generated script and, with
`GenOptions.legacy_tls` (`generate --legacy-tls`, a GUI checkbox), a `_LegacyTLSAdapter` mounted
for `https://` (TLS 1.0, `@SECLEVEL=1`, `OP_LEGACY_SERVER_CONNECT`).  All of it is gone:
generated scripts contain no `VERIFY_TLS`, `session.verify`, `import ssl`, `import warnings`,
`_LegacyTLSAdapter` or `session.mount("https://", ...)`, and those names are no longer reserved
identifiers.  An `https://` URL in an imported HAR is replayed with `requests`' default certificate
verification.

## 13.4 Character encoding of responses  (codegen.py)

`requests` falls back to ISO-8859-1 for `text/*` without a charset — Shift_JIS pages become mojibake.
* `_soup(resp)` must parse **bytes**: `BeautifulSoup(resp.content, PARSER)` (bs4 sniffs `<meta charset>` /
  BOM / falls back to chardet-like detection).
* New helper `_text(resp)`: if the `Content-Type` has a charset → `resp.text`; else sniff
  `<meta charset=…>` / `<meta http-equiv content=…charset=…>` / `<?xml encoding=…>` in the first 4 KiB
  of `resp.content` (set `resp.encoding`), else `resp.encoding = resp.apparent_encoding`; return `resp.text`.
  Normalise `shift_jis`/`sjis`/`x-sjis`/`windows-31j` to `cp932`, `euc-jp` stays. Every `_regex(resp.text …)`,
  the final print of text/html and `results.append(resp.text)` use `_text(resp)` instead.
* Form bodies that were recorded percent-encoded in a legacy charset (e.g. `%93%FA%96%7B` = cp932
  「日本」) must round-trip: when a form field value is not valid UTF-8 after unquoting, plan keeps the
  **raw percent-encoded body** (`body_kind = "raw"` with the original `Content-Type`) and warns.
  (Check `util.parse_form` / `deps.classify_body`; add a test with a cp932-encoded form.)

## 13.5 Multi-recording merge  (importers/__init__.py, cli.py)

* `importers.load_recordings(paths: list[str]) -> Recording`: `load_recording` each, then
  `Recording.merge`. One path → identical to `load_recording` (same meta).
* CLI: `import`, `inspect`, `generate` accept one or more `INPUT` (`nargs="+"`). `inspect` header
  names every source. README explains the new-tab case (see §13.9).

## 13.6 Flask GUI  (reqrec/webapp/, reqrec/recorder/manager.py)

```python
# reqrec/webapp/__init__.py
def create_app(workdir: str | None = None, **config) -> flask.Flask   # no arguments = the factory `flask --app reqrec run` finds
def run_gui(host="127.0.0.1", port=8765, workdir="reqrec_work", open_browser=True) -> int
```
Layout: `reqrec/webapp/__init__.py` (factory + run), `routes.py` (blueprint), `state.py` (per-process
session state: loaded recording, current plan/options, recorder, runner), `templates/index.html`,
`static/app.js`, `static/app.css` (vanilla JS, **no CDN / no external resources**; the GUI must work
offline). UI language: **Japanese**. Served only on the bind address; default `127.0.0.1`.

**Security (the user's browser visits arbitrary sites while this GUI runs):**
* every state-changing request (`POST`) must carry header `X-Reqrec-Token` equal to a per-process
  random token (`secrets.token_urlsafe(32)`) that the page receives via the template; missing/wrong
  token → 403 JSON `{"error": "..."}`.
* requests from this PC (loopback) need no login; their `Host` header must be `127.0.0.1[:port]` /
  `localhost[:port]` / the bound host (DNS-rebinding guard) → else 403.
* requests from other PCs (added 2026-10-25 for a personal GUI on a LAN server, e.g. started from a
  JupyterLab terminal with `flask --app reqrec run`) need a login with the GUI password: the module
  constant `GUI_PASSWORD` (plain text at the top of reqrec.py, initial value `adminpass`; a start-up
  warning is printed while it is unchanged), overridden by env `REQREC_GUI_PASSWORD`, or
  `create_app(..., password=...)`. An empty password refuses other PCs (403), and `run_gui` then
  refuses a non-loopback `--host`. With a password every page and API from another PC needs a login
  session. `GET/POST /login` (plain form, `Referrer-Policy:
  same-origin` so the form post carries a real `Origin`; cross-origin or `null` Origin → 403),
  `GET /logout`. Session = Flask signed cookie `reqrec_session_<hash of workdir>`, HttpOnly,
  SameSite=Strict, 12 h, secret key per process. 5 wrong passwords in a row lock that address for 60 s
  (429); each wrong password waits `LOGIN_FAIL_DELAY` (1 s). Not logged in: `/api/*` and POST → 401
  `{"error", "login": true}` (the page JS then goes to `/login`), pages → redirect to `/login`. The Host
  check is skipped (the session cookie is the guard). The password is removed from the environment of
  scripts run by `ScriptRunner`.
* reject cross-origin `Origin` on POST.
* file names from the client are reduced to a basename and must match `^[\w.\-]+$`; everything is
  read/written **inside `workdir`** (resolve + check prefix). Uploaded files are stored under
  `workdir/uploads/`. Generated scripts under `workdir/scripts/`. Recordings under `workdir/recordings/`.
* secrets typed in the 実行 panel (env values) are passed to the subprocess only; never written to disk, never logged.
* `debug=False`; no `flask run` reloader.

**JSON API** (all return JSON; errors `{"error": "<日本語>"}` with 4xx):
* `GET /` → page. `GET /api/state` → `{version, workdir, gui_address, mitmproxy_available,
  recorder: {...}, recording: {loaded: bool, sources: [...], flows: n, ...}, plan_loaded, plan_options,
  gen_options, run, iehost, browser, record_origin, last_script, secrets}` (the `windows: {is_windows,
  proxy, cert}` block and `record_browser_kind` were removed on 2026-10-12 (3)).
* Recording (current contract since 2026-10-12 (3); every recording opens the recording browser,
  §13.12): `POST /api/record/start {hosts: [...] | "a,b", append: bool, start_url, emulation: "keep" |
  <iehost.EMULATION_LEVELS key>, origin: "easy" | "advanced"}`, all optional; the former keys `port`,
  `listen_host`, `set_system_proxy`, `browser` and `https_passthrough` are ignored.  Order: validate
  `hosts`, `start_url` (`_iehost_start_url`), `emulation`, `origin` (400) → 409 when already
  recording → 400 when mitmproxy is missing (only with the default command builder) →
  `_require_iehost` (400 with `iehost.availability()["reason"]`) → `port = find_free_port("127.0.0.1",
  preferred=8080, avoid=(GUI port,))` → close a leftover recording browser,
  `RecorderManager.start(out, port=port, hosts=hosts, extra_args=list(HTTPS_PASSTHROUGH_ARGS))` (output
  `workdir/recordings/rec_YYYYmmdd_HHMMSS.json`) → when the child is running: `wait_until_listening`
  (500 `kind: "proxy"` on timeout), 表示モード (500 `kind: "emulation"`) and
  `_launch_iehost(state, "127.0.0.1:PORT", start_url)` (500 `kind: "iehost"`); each of these three
  failures stops the recorder and forgets the file (`_abandon_start`).  Returns `{out, out_path, port,
  proxy_address: "127.0.0.1:PORT", status, browser, emulation, origin, warnings,
  self_excluded_hosts}`.  `GET /api/record/status` → `RecorderManager.status()` (`{running, flows,
  out, out_name, pid, exit_code, started_at, stopped_at, port, hosts, stdout_tail, stderr_tail, error,
  command}`; counts flows by reading the flushed JSON, tolerant of a file mid-write) plus
  `mitmproxy_available`, `browser: {kind, running, pid, exit_code}` and `origin`.
  `POST /api/record/stop {append?, discard?}` → closes the recording browser, stops the recorder,
  **loads the recording** as current (merging with already loaded ones only when `append`, by
  default the choice made at start), returns the recording summary plus `{out, out_path, exit_code,
  browser_exit_code}`; nothing recorded → 400 「何も記録されませんでした。…」 with `empty: true`;
  `{discard: true}` loads nothing and deletes the file (§13.11).  The former `instructions`,
  `auto_port`, `system_proxy`, `browser_kind`, `https_passthrough`, `listen_host`,
  `proxy_backup_active` and `proxy_error` fields are gone.
* Loading: `POST /api/recordings/upload` (multipart, field `files`, several allowed: `.har` / `.json`
  = `RECORDING_EXTENSIONS`, anything else 400 (`.mitm` since 2026-10-12 (3));
  `append` form field) → saves to `uploads/`, `load_recordings`, sets/merges current; returns summary.
  `GET /api/recordings` lists files in `recordings/` and `uploads/` (name, size, mtime, flows if cheap).
  `POST /api/recordings/open {names: [...], append}` opens server-side files by name.
  `POST /api/recordings/clear`.
* Analysis: `POST /api/plan {plan_options}` → runs `build_plan`, stores plan+options, returns
  `cli.build_inspect_report(...)` **plus** `flows: [{id, started_at, method, status, mime, url, referer,
  kept, reason, step_index, resource_type}]` for *every* flow, `constants`, `auth`, `warnings`,
  `final_step_index`. `GET /api/flow/<id>` → request/response headers and decoded bodies (bodies
  truncated to 200 KiB with a flag; JSON pretty-printed; binary → size + mime only).
* Generation: `POST /api/generate {plan_options, gen_options}` → `{code, summary, warnings, secrets:
  [{name, env_var}]}`; `POST /api/scripts/save {name, code}` → writes `scripts/<name>.py`, returns path;
  `GET /api/scripts/<name>/download`; `GET /api/scripts` list.
* Run: `POST /api/run {name, env: {VAR: value}}` → starts `sys.executable scripts/<name>.py` in a
  thread (cwd `workdir/scripts/`, env = os.environ + given), max one at a time; `GET /api/run/status`
  → `{running, exit_code, stdout_tail, stderr_tail, output_tail, errors_tail, started_at}`; `POST /api/run/stop`.
  `POST /api/run/save_output {name}` writes the last stdout to `workdir/outputs/<name>`.
* Windows: the endpoints `GET /api/win/status`, `POST /api/win/proxy`, `POST /api/win/proxy/restore`
  and `POST /api/win/cert/install` (system proxy and `certutil` CA install, §13.7) were removed on
  2026-10-12 (3); reqrec never changes the Windows proxy or installs a certificate.

**RecorderManager** (recorder section, former `reqrec/recorder/manager.py`): wraps `build_command`
(or an injected `command_builder`, called as `command_builder(out_abs, port=..., hosts=[...])`, plus
`extra_args=[...]` when there are any) + `subprocess.Popen` (stdout / stderr drained by reader
threads into bounded ring buffers); `start(out, port=8080, hosts=None, extra_args=()) -> status()`;
`wait_until_listening(timeout=20.0)` (dials `127.0.0.1:port`, i.e. `RECORD_LISTEN_HOST`; `False` when
the child exits first or the time runs out); `stop(timeout) -> exit_code` (SIGINT, or
`CTRL_BREAK_EVENT` on Windows where the child runs in its own process group → wait → `terminate()` →
wait → `kill()`); `forget()`; `status()` (keys listed above); `flow_count()` (reads the JSON file;
returns last good count while the file is mid-write); `load_recording()`.  There is no `listen_host`
attribute or parameter any more: the proxy always listens on `127.0.0.1`.  Must be testable with a
fake command (inject `command_builder`).

**UI** (single page, sections as tabs or a vertical flow):
1. 記録 — 記録するサイト (ホスト名)、追加モード、最初に開くアドレス、表示モード (記録用ブラウザ)、
   [記録開始] (記録用プロキシを空きポートで起動し、記録用ブラウザを開く) / [記録停止して読み込む]、記録の状態
   (ライブ件数、プロキシのアドレス、出力ファイル、記録用ブラウザの状態、プロキシのログ)。記録用ブラウザが使えない PC
   では [記録開始] は無効で、理由を表示する (`#rec-unavailable`)。The port input, the 手順カード (proxy
   `127.0.0.1:8080`, CA certificate, `http://mitm.it`, Internet Options) and the Windows card
   ([システムプロキシを設定する], [CA 証明書をインストール]) were removed on 2026-10-12 (3).
2. 読み込み — ファイル選択(複数: .har/.json)、IE の F12 開発者ツールで保存した HAR の案内、作業フォルダ内ファイル一覧から開く、「追加して結合」トグル。
3. ステップ — フィルタ設定(静的ファイル/トラッカー/全て残す、リダイレクト統合、ループ検出、秘密情報の環境変数化、
   ホスト include/exclude、認証検出)、全フローの表(チェック=採用、判定理由、ステップ番号、メソッド、
   ステータス、種類、URL、参照元)、「結果として使う」ラジオ、クリックで詳細ドロワー(リクエスト/レスポンスのヘッダー・本文)。
   表の変更は即 `/api/plan` 再計算。
4. コード — [生成] → プレビュー(`<pre>` + 行番号は任意)、ファイル名入力、[保存]、[ダウンロード]、警告と環境変数の一覧。
5. 実行 — 検出された秘密情報の環境変数ごとの入力欄(type=password)、[実行]/[停止]、標準出力/標準エラーのコンソール、
   [結果を保存]。
Status bar with the last message. Keep the JS modular (`api()`, render functions); no build step.

**Tests**: `tests/test_webapp.py` (Flask test client; every endpoint; token/Host/Origin enforcement;
path traversal attempts; plan/generate on `tests/fixtures/login_flow_chrome.har`; run endpoint with a
tiny script; RecorderManager with a fake "mitmdump" python stub
that writes a recording file and exits on SIGINT/terminate; since 2026-10-12 (3) the record endpoints
run with a faked recording browser, see §13.12; the Windows-endpoint and `test_winsupport.py`
system-proxy / certificate tests were deleted with those features), `tests/test_webapp_browser.py` (Playwright, Chromium at
`/opt/pw-browsers/chromium` with fallback to default; skipped when unavailable): start the app on a
free port in a thread, upload the fixture HAR, wait for the steps table, uncheck one flow and see the
plan refresh, pick a final step, click 生成, assert the code preview contains `def step_01_`, save,
and run against `tests/e2e/mock_adapter.py`? — no: run is tested with a trivial script; the fixture
script can't reach the fake hosts.

## 13.7 Windows support module  (removed)

**Removed on 2026-10-12 (3).**  The module (later the `winsupport` sub-section of the `gui` section)
read and changed the Windows system proxy (`get_system_proxy` / `set_system_proxy` /
`restore_system_proxy` / `refresh_proxy_settings`, `HKCU\…\Internet Settings`) and installed
mitmproxy's CA certificate with `certutil` (`mitmproxy_ca_cert_path` / `cert_installed` /
`install_ca_cert`), so that Edge IE mode could be recorded through the system proxy and https
through the mitmproxy CA.  Factory PCs forbid both changes, and on PCs with a PAC / auto-detect
configuration the system proxy did not even take effect (§13.12 "Why").  The recording browser
needs neither, and https is never recorded, so all of it was deleted together with the
`/api/win/*` endpoints (§13.6).  Only `is_windows()` and `NOT_WINDOWS_MESSAGE` remain, in the
platform part of the core section.  The only registry value reqrec still writes is the recording
browser's 表示モード (`iehost.set_emulation`, §13.12).

## 13.8 Legacy fixture  (tests/fixtures/legacy_webforms_ntlm.har)

An IE-mode style intranet recording for `http://intra.example.local/`: the NTLM 3-leg handshake on
`GET /Default.aspx`, a **Shift_JIS** WebForms page (`Content-Type: text/html` **without** charset,
`<meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS">`, hidden `__VIEWSTATE`,
`__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`), a `POST /Default.aspx` postback (`__EVENTTARGET`,
`ctl00$txtKeyword=%93%FA%96%7B` (cp932 日本), `ctl00$btnSearch=%8C%9F%8D%F5`), a results page with
`<a href="Report.aspx?id=1234">`, then `GET /Report.aspx?id=1234` (`1234` traced to that href), and a
static `GET /WebResource.axd?d=…` (script) to drop. HAR content for Shift_JIS pages is stored as
base64 (`"encoding": "base64"`) so bytes survive. Expected plan: `auth.kind == "ntlm"`, 4 steps, no
`Authorization` headers, `__VIEWSTATE` etc. as `html_input` extractors, raw percent-encoded form body
kept, `id` traced via `html_attr` + pattern, generated script compiles and replays against the mock
adapter with fresh `__VIEWSTATE` values.

## 13.9 Documentation additions  (README.md, examples/)

New sections: GUI (`reqrec gui`) walkthrough with the five panels; 「Edge IE モードで記録する」 (why the
proxy path works for IE mode, Windows プロキシ設定とCA証明書, IE11 F12 の HAR 保存も可能だがプロキシ記録を推奨,
統合 Windows 認証 → 生成コードの `session.auth`, `pip install "reqrec[sspi]"` / `"reqrec[ntlm]"`,
レガシー TLS オプション, Shift_JIS, WebForms の `__VIEWSTATE`); 「別タブで開く画面」 (proxy records all tabs;
HAR: DevTools 設定「ポップアップに対して DevTools を自動的に開く」→ タブごとに保存 → 複数ファイルを指定して結合);
手動の取捨選択 (`--exclude-flow` 等 / GUI のチェック) と「結果にするステップ」; Windows での配布
(`pip install .` と `reqrec gui`、PyInstaller での exe 化の例 `pyinstaller --onefile --name reqrec --collect-all reqrec --collect-all mitmproxy -m reqrec.cli` は検証していない旨を明記);
更新したオプション表・FAQ (文字化け, 401 が続く, 証明書エラー, IE モードのサイトで TLS エラー).

**Superseded on 2026-10-12 (3)** (the features are gone): why the proxy path works for IE mode,
Windows プロキシ設定とCA証明書, 「IE11 F12 … プロキシ記録を推奨」 (the recording browser is now the
recommended way, IE11 F12 HAR the alternative), レガシー TLS オプション, the DevTools steps for
「別タブで開く画面」 (the recording browser opens popups / new windows as tabs and records them;
several HARs can still be merged) and the FAQ entries 証明書エラー (記録時) and
IE モードのサイトで TLS エラー.

## 13.10 File ownership for phase 2

| owner | files |
|---|---|
| G gui | `reqrec/webapp/**`, `reqrec/recorder/manager.py`, `reqrec/winsupport.py`, `tests/test_webapp.py`, `tests/test_webapp_browser.py`, `tests/test_winsupport.py` |
| H1 analysis | `reqrec/filters.py`, `reqrec/plan.py`, `reqrec/deps.py`, `reqrec/importers/__init__.py`, `tests/test_filters.py`, `tests/test_plan.py`, `tests/test_deps.py`, `tests/test_auth.py`, `tests/test_overrides.py`, `tests/test_merge.py`, `tests/fixtures/legacy_webforms_ntlm.har`, `tests/test_integration_legacy.py` |
| H2 codegen+cli | `reqrec/codegen.py`, `reqrec/cli.py`, `tests/test_codegen.py`, `tests/test_cli.py`, `tests/test_codegen_phase2.py` |
| I docs | `README.md`, `examples/**` |

Nobody edits `model.py`, `util.py`, `pyproject.toml` or another owner's files. No `git` commands.
`tests/test_integration.py` and `tests/e2e/**` belong to the integrator.

## 13.11 かんたんモード (easy mode)  (reqrec.py: gui section, GUI_HTML)

Target users are factory-floor staff who must not have to know what a port, a proxy or a CA
certificate is.  The GUI therefore opens in **easy mode** by default: one screen with
**[記録をはじめる] → operate the site in the browser → [記録をおわる]**, and everything else is
automatic.  The five detailed panels of §13.6 stay intact behind the **[詳細設定を表示]** toggle
in the top bar (`body.easy-mode` hides the nav + panels via CSS; the choice is kept in
`localStorage["reqrec.mode"]`).  No new state lives in the browser: the easy screen is a thin
client over the existing API plus the three endpoints below, and it keeps the advanced panels in
sync (`Record.render`, `Load.applySummary`, `Steps.replan`, `Code.renderSecrets`, `Run`).

**Flow (the script in GUI_HTML, module `Easy`):**
1. **start** — `POST /api/record/start {hosts: [], append: false, start_url: <address box>,
   emulation: "keep", origin: "easy"}`.  The server always picks a free port on `127.0.0.1`
   (`find_free_port("127.0.0.1", preferred=8080, avoid=(gui port,))`), waits for the proxy and opens
   the in-app recording browser itself (§13.12): no certificate, no system proxy, no Edge.  The
   response carries `port`, `proxy_address`, `browser`, `origin` and `warnings`.  `emulation: "keep"`
   = the easy screen never touches 表示モード (only 詳細設定 does).  (Until 2026-10-12 (3) the body
   also had `port: "auto"`, `listen_host`, `set_system_proxy`, `https_passthrough` and
   `browser: "iehost" | "none"`, with a manual-proxy flow on other OSes.)
2. **no recording browser = no recording** — [記録をはじめる] is rendered disabled unless mitmproxy
   and the recording browser are available (`data-mitm-available` / `data-iehost-available`), and the
   readiness list (`#easy-ready`) shows the reason (`data-iehost-reason`: not Windows, or neither
   `csc.exe` nor a prebuilt `RecBrowser.exe`) with 「この PC では記録できません」.  There is no fallback:
   no system proxy, no certificate, no other browser; loading a HAR in 詳細設定 still works.  A launch
   failure at run time (e.g. the exe blocked by AppLocker) is shown with guidance for the
   administrator (`python -m reqrec browser build` + allow that folder) and kept in
   `/api/state` → `iehost.last_error` for the readiness list.
3. **browser** — [ブラウザをもう一度開く] = `POST /api/browser/open {url}` (re)opens the recording
   browser of the running recording: while it still runs nothing happens (`relaunched: false`);
   otherwise it is started again against the recorder's proxy (`127.0.0.1:<recorder port>`) at the
   optional address (`_iehost_start_url` → `validate_url`: `http(s)://` only, bare host names and
   `host:port` get `http://`, other schemes such as `javascript:` or `edge://` are rejected with
   400), `relaunched: true`.  409 when nothing is being recorded; `_require_iehost` as for start; a
   `browser` key in the body is ignored.
4. **recording** — live count from the `Record` poller (`Record.subscribe`), [記録をおわる],
   [ブラウザをもう一度開く], [やめる] (`POST /api/record/stop {discard: true}`: nothing is loaded and
   the file is deleted).  Closing the recording browser stops automatically (once it was seen
   running; exit code 4 = its proxy could not be set → discard + message).  Switching back from
   詳細設定 re-reads `/api/record/status` so a recording started there is followed.
5. **stop** — `POST /api/record/stop {}` (the append choice stored at start applies; closes the
   recording browser, stops the recorder and loads the recording;
   no recording file at all = 「何も記録されませんでした」 400 with `empty: true`),
   then **`POST /api/easy/build`**: `build_plan` with the current `PlanOptions` → `generate` →
   save to `scripts/<scrape_<host>_YYYYmmdd_HHMM>.py` (or `{"name": ...}`), returns
   `{name, path, download_url, steps, steps_view: [{index, method, url, loop, extracts}],
   final_step_index, final_url, final_method, flows_total, warnings, secrets, auth, summary,
   code, sources}`.  A plan with no steps is a 400 with a plain-language explanation.
6. **done** — file name / path / step list / warnings (common English warnings are shown in
   Japanese server-side by `gui.warning_message` → `warning_details` / `note_details`), [ダウンロード], [保存先フォルダを開く] (`POST /api/folder/open
   {folder: "scripts"|"outputs"|"recordings"|"uploads"|"workdir"}` → `gui.open_folder`:
   `os.startfile` / `open` / `xdg-open`; anything else is a 400), [試しに実行する] (env inputs
   for `secrets`, `Run.start` / `Run.stop`, output console, a plain-language hint for the common
   failures via `errorHint`, [結果をファイルに保存]), [もう一度記録する].
   A recording loaded from the advanced panels (a HAR) can be built from the idle screen
   too ([読み込み済みの記録からスクリプトを作る]).

**Security:** the new endpoints are `POST` and therefore covered by the token / Host / Origin
hook of `create_app`.  `/api/browser/open` only ever (re)starts the recording browser, with a start
URL that passed `_iehost_start_url` (`validate_url`); `/api/folder/open` only opens the fixed
work-folder subdirectories.

**Tests:** `tests/test_gui.py` (its former `test_webapp_easy.py` section) — page markup, `find_free_port`, the automatic port of
`/api/record/start` (fake recorder and fake recording browser; the GUI's own port is avoided),
`/api/easy/build` on `login_flow_chrome.har` (file written, secrets reported,
`last_script` updated, unsafe names rejected, token required), `/api/browser/open` (bad start URL
rejected; relaunch in the iehost section) and `/api/folder/open`, and the helpers `validate_url` and
`open_folder` with injected fakes (URL validation, the opener per OS).

## 13.12 In-app IE-engine recording browser  (reqrec.py: iehost section, RECBROWSER_CS, gui section)

**Why.** Factory PCs commonly use Edge IE mode for legacy intranet sites, have a PAC / auto-detect
proxy configuration, and forbid installing certificates or changing Internet Options.  Edge IE mode
only honours the *system* proxy, and on such PCs the Windows proxy auto-configuration wins over a
manually written proxy, so the former system-proxy flow (§13.6 / §13.7, removed on 2026-10-12 (3))
recorded nothing.  Instead reqrec ships a tiny browser
that hosts **the same engine** (the WebBrowser control: ieframe / MSHTML / Trident 7) in its own
process and routes **only that process** through the recorder.  Nothing in Windows, Internet
Options or Edge changes, and no certificate is needed because only plain `http://` is recorded.

**Proven facts (Windows 11, verified on the development PC; keep them):**
* Per-process proxy: `InternetSetOptionA(NULL, INTERNET_OPTION_PROXY=38, INTERNET_PROXY_INFOA{3, "127.0.0.1:PORT", ""})`
  with **ANSI** strings, before any WebBrowser control exists.  The W variant (and
  `UrlMkSetSessionOption` with UTF-16 strings) returns TRUE but installs a bogus proxy.  It
  overrides the user's auto-detect / PAC for this process only; the registry is untouched
  (checked by export before/after).  `INTERNET_OPTION_PER_CONNECTION_OPTION` with a NULL handle
  writes the registry and must never be used.
* Bypass list is **empty**: `<local>` would exclude dotless intranet hosts (`http://kanri/`).
  WinINet always bypasses the proxy for literal loopback addresses; tests therefore use
  `127.0.0.1.nip.io` (or `--bypass "<-loopback>"` offline).
* New windows: a `[ComImport]` `DWebBrowserEvents2` sink (`NewWindow3` 273, `NewWindow2` 251)
  answers with a fresh, handle-created control's `ActiveXInstance` in `ppDisp`; the engine then
  navigates it itself, so `window.opener`, `window.name`, `<form target=_blank>` POST bodies and the
  session survive.  `showModalDialog` / `showModelessDialog` (`dialogArguments`, `returnValue`)
  work in-process without host code.  All of it goes through the per-process proxy.
* `window.close()` arrives as `OLECMDID_CLOSE` (45) at the control site's `IOleCommandTarget`
  (`CreateWebBrowserSiteBase` override), **not** as `DWebBrowserEvents2.WindowClosing` (kept as a
  fallback).  Closing the last tab opens a fresh `about:blank` tab.
* Without `FEATURE_BROWSER_EMULATION` the control renders in IE7 mode and sends an `MSIE 7.0 ...
  Trident/7.0` user agent (like IE mode's Compatibility View for intranet sites); Enterprise Mode
  is not available to hosted controls.
* `INTERNET_OPTION_END_BROWSER_SESSION` + `INTERNET_SUPPRESS_COOKIE_PERSIST` at start-up: every
  recording starts from an empty session, so the login is always recorded.

**`RECBROWSER_CS`** (the former `RecBrowser.cs`; C# 5, compiled by `iehost.build_command`: `csc -nologo -target:winexe
-platform:x86 -r:System.Windows.Forms.dll -r:System.Drawing.dll` — always 32-bit, like IE mode's content process, so 32-bit in-process ActiveX controls load; the former rule was x86 only when only the 32-bit
`Framework` compiler exists, i.e. on 32-bit Windows): command line `--proxy HOST:PORT [--bypass ""]
[--url URL] [--title T] [--log PATH] [--selftest] [--seconds N]`.  Window title
`<title> — 記録中`; toolbar 戻る / 進む / 更新 / address box / タブを閉じる / red **■ 記録をおわる**;
tabs for popups; status strip that always says
「● 記録中 — このウィンドウで開いた http:// のページの通信を記録しています（https:// は記録されません）」
and announces an `https://` page / download as
「記録されません」 (`static bool IsUnrecordedHttps(Uri url)`: the scheme is `https`).  The former
`--https` option (C# `Options.HttpsRecorded`: the recorder intercepts HTTPS) was removed on
2026-10-12 (3); the changed source changes the build digest, so every work folder rebuilds once.  Not
`Silent` (`ScriptErrorsSuppressed = false`): Silent would also hide the 「Windows セキュリティ」
credential prompt of Basic / Windows authentication; only `OLECMDID_SHOWSCRIPTERROR` (40, group
`CGID_DocHostCommandHandler`) is answered at the site (no dialog, keep running scripts).  Exit
codes: 0 normal close (X, 記録をおわる, WM_CLOSE), 2 bad arguments (e.g. no `--proxy`), 3
`--seconds` guard, 4 the per-process proxy could not be set (a message box explains; nothing would
be recorded).  Log lines `HH:mm:ss.fff text` (UTF-8, no BOM, auto-flushed); one of the first lines
is `proxy <server> -> ok|FAILED`.  No registry access.

**The `iehost` namespace** (section of reqrec.py, importable everywhere; `reqrec browser build|status`
in the CLI; injectable `exists` / `run` / `popen` / `winreg`, and `source` (C# text, default
`RECBROWSER_CS`) / `folder` (distribution folder, default `iehost.SHIPPED_DIR` = the folder of
reqrec.py)): `iehost.csc_path`, `availability(workdir) -> {available, reason, exe, built, source, csc,
prebuilt}` (`source` = `<workdir>/bin/RecBrowser.cs`), `exe_path(workdir) = <workdir>/bin/RecBrowser.exe`,
`ensure_built` (writes `RECBROWSER_CS` to `<workdir>/bin/RecBrowser.cs` and compiles it when the
exe is missing, the digest in `bin/RecBrowser.cs.sha256` differs (`_build_digest`: SHA-256 of the source text (UTF-8) **plus the build settings**, e.g. `platform=x86`, so changing build options alone rebuilds once), or `force`; a prebuilt exe in
the distribution folder (`RecBrowser.exe` next to reqrec.py) is copied when there is no `csc.exe`; a **shipped** exe — built
there by `reqrec browser build` (from a temporary copy of the source) with `RecBrowser.exe.sha256` matching the source — is run in
place, so an AppLocker / SRP policy only has to allow the distribution folder), `launch(workdir,
proxy_address, url=None, title=None) -> BrowserProcess` (argv `RecBrowser.exe --proxy <addr>
--bypass "" --log <log> [--url URL] [--title T]`; the `https_recorded` parameter was removed on
2026-10-12 (3); log under
`<workdir>/logs/recbrowser_<timestamp>.log`; job object `KILL_ON_JOB_CLOSE | SILENT_BREAKAWAY_OK`:
the browser dies with the GUI, programs it starts such as Excel do not), `BrowserProcess.close()`
(`taskkill /PID` = WM_CLOSE → wait → `terminate` → `kill`; releases the job handle),
`EMULATION_LEVELS = {default: None,
ie8: 8000, ie11: 11000, ie11_force: 11001}`, `set_emulation` / `get_emulation` (the only registry
value reqrec ever writes: `HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\
FEATURE_BROWSER_EMULATION\RecBrowser.exe`, and only for a non-default 表示モード; `default`
deletes it, after a read-only check; `record_start` also accepts `emulation: "keep"` = no registry
access at all, which the easy screen always sends; `/api/state` → `iehost.emulation` reports the
current preset so the 詳細設定 select starts there).

**GUI / API.** Since 2026-10-12 (3) every recording uses the recording browser (§13.6 has the
full `record_start` order).  `POST /api/record/start` takes `start_url` and `emulation` (besides
`hosts`, `append`, `origin`); there is no `browser` kind, no `set_system_proxy` and no
`https_passthrough` switch any more.  It requires `iehost.availability()["available"]`
(`_require_iehost`: 400 with the reason, off Windows
「記録用ブラウザ (IE エンジン) は Windows でのみ使えます。」), starts the recorder on `127.0.0.1` on a
free port, always with `HTTPS_PASSTHROUGH_ARGS`
(mitmdump `--ignore-hosts .*`: in regular proxy mode mitmproxy checks `ignore_hosts` only for CONNECT tunnels, so every HTTPS port is passed through untouched while plain `http://` is recorded — verified with mitmdump 12.2.3),
then `set_emulation` and `launch` (`_launch_iehost(state, "127.0.0.1:PORT", start_url)` →
`iehost.launch(workdir, proxy_address, url=start_url, title=BROWSER_TITLE)`); any failure stops the
recorder.  `GET /api/record/status` reports `browser: {kind, running, pid, exit_code}`;
`POST /api/record/stop` closes the browser **before** the recorder and reports
`browser_exit_code`; `POST /api/browser/open {url}` relaunches it against the running recorder
(§13.11).  `AppState.browser` / `close_browser()`; `AppState.close()` closes it on exit (the GUI's
shutdown only calls `AppState.close()`).  The page gets `data-iehost-available` /
`data-iehost-reason`; [記録開始] and [記録をはじめる] are rendered disabled unless mitmproxy and the
recording browser are available.  `record_start` waits (without the lock, up
to `PROXY_READY_TIMEOUT` = 20 s) for `RecorderManager.wait_until_listening()` before opening the
browser and re-checks under the lock that the same recording is still running (the former
`AppState.record_browser_kind` and the `browser_kind` / `record_browser_kind` fields are gone: every
recording is an iehost recording).  For 表示モード 既定 nothing is
opened for writing unless a leftover value exists, and failing to remove it is only a warning.
`POST /api/record/stop {discard: true}` (easy screen [やめる]) closes and stops everything but loads
nothing and deletes the half-made file.  `iehost.launch` puts the browser in a Windows job object
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (`kill_on_close_job`), so it dies with the GUI process.
The easy screen (§13.11) records only through the recording browser (no certificate step, no
system proxy) and stops automatically when the recording browser is closed.  Where the recording
browser cannot be used, that PC cannot record: the easy screen and 「1 記録」 (`#rec-unavailable`)
explain why; there is no fallback to the system proxy, a certificate or another browser, and HAR
import still works.  詳細設定 exposes 最初に開くアドレス and 表示モード.

**Tests.** `tests/test_iehost.py` (pure logic with fakes), `tests/test_gui.py` (former
`test_webapp_iehost.py` section: API with a fake recorder and a fake `BrowserProcess`),
`tests/test_real_engine.py` (former `test_iehost_engine.py` section, opt-in real engine:
`REQREC_IEHOST_TESTS=1`; compiles the host, runs the fixture site (`testsite` section of
`tests/ie_support.py`) and mitmdump on free ports, runs `--selftest`, checks the recording and that the registry is
unchanged).  Since every `/api/record/start` opens the recording browser (2026-10-12 (3)), the GUI
tests that start a recording fake it (`iehost.availability` / `launch` / `set_emulation` /
`get_emulation`, and `mitmproxy_available` where mitmproxy may be missing), and with a stub
mitmdump that never binds a port they also fake `RecorderManager.wait_until_listening`; the GUI
recording e2e with a real mitmdump uses a faked recording browser and drives the site through the
proxy with `requests`.

## 13.13 Factory scenario findings (reqrec.py: analysis, codegen, gui sections)

End-to-end runs of a realistic legacy intranet (`factory_site` section of `tests/ie_support.py`: Shift_JIS
WebForms, session id rotated at login, one-time `__VIEWSTATE` / `__EVENTVALIDATION`, a per-session
URL key in `window.open`, autopostback dropdowns, a `showModalDialog` picker, grid paging, an Excel
export with a percent-encoded Japanese file name) recorded in the recording browser and replayed
against a fresh server led to these rules:

* **Route-like path segments** (`analysis.is_route_like` / `is_structural_path_segment`): words, page /
  file names and screen ids (`Login.aspx`, `orders`, `SC0010.aspx`, `KJ010Search.aspx`) stay trace
  candidates, but only exact header / JSON / `<input>` / `<meta>` / cookie matches are accepted for
  them (never `html_attr`, `html_text`, regex or URL patterns — the URL must not depend on
  `action="Login.aspx"` markup), and they never become Constants.  An all-uppercase session key in the
  path (`/s/QZVBNMWRTYPXSDFKHJ/items`) is still traced to the JSON leaf that produced it.
* **Random letters** (`analysis.looks_random_letters`): letters-only values (parts split at `-` / `_`, the
  stem before one extension) of ≥ 12 characters are judged by their case runs: identifiers with
  acronyms anywhere (`txtTokuisakiCD`, `hdnSearchKEY`, `getXMLHttpRequest`, `getElementById`) are
  words; irregular mixed case (`xBBHOHpXYZgFKyNZpuWy`, `xBBHOH-pXYZgFKyNZpuWy`) is a token (dynamic-
  looking, not route-like, may be traced by regex).  Measured on 20 000 random tokens: 96 % of 16–24
  character letter tokens and 96 % of digit-free base64url tokens are detected.
* **Referer** (`analysis._referer_with_fresh_values`): the recorded `Referer` is split into scheme+host,
  path, query and fragment; only whole path segments, `;name=value` path parameters and whole query
  values equal to a value traced for the same step (≥ 8 characters) are substituted — host / scheme
  stay literal; the percent-encoded spelling is handled (`str(X)` when the ref is `unquote(X)`, else
  `requests.utils.quote(str(ref), safe='')`); secret query items are replaced by their secret constant.
* **Secrets** (`analysis`, plan section): every field whose name looks secret becomes a secret constant whatever its
  length or the candidate filters (`admin`, `123`), and the value cache is keyed by (value, secret-
  looking name), so a password equal to the user id is never emitted as a literal.
* **Required secrets** (`codegen._required_secret_envs`): `main()` first checks the CONSTANTS it uses
  (`missing = [env for env, value in [(ENV, CONST), …] if not value]`) — secrets recorded non-empty
  plus the Basic / Digest auth password, never NTLM / Negotiate — and exits with 「環境変数 … が
  設定されていません」 before any request; a value typed into the constant block works.
* **Downloads** (`codegen._DOWNLOAD_HELPERS_SRC`, `core.is_attachment_disposition`,
  `core.download_filename`): a response is an attachment when `Content-Disposition` starts with
  `attachment`, or contains `filename` and does not start with `inline`.  Every step (any kind,
  including HTML-table exports, loop iterations and the final step) saves binary bodies and
  attachments right after its call (`_save_if_attachment` / `_save_download`, `REQREC_OUTPUT_DIR` or
  cwd; the GUI run sets `<workdir>/outputs`).  Names: RFC 6266 / IE percent-encoding / raw UTF-8 or
  Shift_JIS / RFC 2047 encoded words; Windows reserved names get `_`, names over 150 characters are
  shortened; unique within a run (`name (2).ext`).  `gui._downloads_of` lists exactly the steps the
  script saves (verified on both factory recordings × 8 option variants).
* **Easy build payload** adds `downloads: [{index, method, url, filename, mime}]` (shown as
  「保存されるファイル」), and splits plan warnings into `warnings` (actionable) and `notes`
  (Shift_JIS re-encoding, "looks like a credential" — informational, not shown under 確認してください);
  every warning gets a plain-Japanese `message` (`gui.warning_message`; a test checks all warnings
  `build_plan` produces on the fixtures).  Error kinds are distinct (`proxy` / `emulation` / `iehost`
  launch); only a launch failure gets the AppLocker / `python -m reqrec browser build` guidance.
  Recordings remember their `origin` (`easy` / `advanced`); only easy-started recordings auto-stop
  in easy mode.  The 試しに実行 inputs use friendly labels (「パスワード (入力欄: txtPassword)」;
  NTLM / Negotiate entries keep their "leave blank with sspi" instruction).

Tests: `tests/test_integration.py`, former `test_factory_replay.py` section (always on; the two recordings in
`tests/fixtures/factory_ie_recording_{digit,letter}_key.json` are generated and replayed against a
fresh `factory_site` — full event sequence, Excel rows and name, no recorded session value in the
code, second run, missing / wrong password), and `tests/test_real_engine.py`: the always-on former
`test_factory_site.py` section, the opt-in former `test_iedriver.py` section (external driver
`tests/IEDriver.cs` / the `iedriver` section of `tests/ie_support.py` operating RecBrowser via
`WM_HTML_GETOBJECT`) and the opt-in former `e2e/test_factory_live.py` section, which records the
scenario in the real recording browser with the `factory_scenario` section of `tests/ie_support.py`.
