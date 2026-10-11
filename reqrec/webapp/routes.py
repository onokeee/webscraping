"""JSON API + page of the GUI.  Contract: DESIGN.md §13.6.

All endpoints return JSON (errors as ``{"error": "<日本語>"}`` with a 4xx / 5xx status) except
``GET /`` (the page) and ``GET /api/scripts/<name>/download`` (a file).  Security rules (token,
Host, Origin) live in :func:`reqrec.webapp.create_app`'s ``before_request`` hook, so every route
here can assume the caller is the page served by this process.

Analysis is delegated to the existing pipeline (``importers`` → ``plan.build_plan`` →
``codegen.generate`` and ``cli.build_inspect_report`` / ``format_plan_summary``); this module only
maps HTTP to those calls.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from typing import Any, Optional

from flask import Blueprint, Response, current_app, jsonify, render_template, request, send_from_directory

from .. import __version__, iehost, model, util, winsupport
from ..cli import build_inspect_report, format_plan_summary
from ..codegen import generate
from ..plan import build_plan
from ..recorder.manager import RecorderError
from ..recorder.run import format_instructions, mitmproxy_available
from . import launch
from .state import (
    RECORDING_EXTENSIONS,
    ApiError,
    AppState,
    exclude_netlocs,
    find_free_port,
    gen_options_from_json,
    gui_netlocs,
    load_sources,
    options_to_plain,
    plan_options_from_json,
    safe_name,
    sanitise_upload_name,
    unique_path,
)

__all__ = ["bp", "get_state", "ApiError"]

bp = Blueprint("reqrec", __name__)

#: Response / request bodies returned by ``/api/flow/<id>`` are cut here (characters).
BODY_LIMIT = 200 * 1024
#: Flow count is only computed for listed files up to this size (it means parsing the file).
CHEAP_COUNT_MAX_BYTES = 3 * 1024 * 1024
#: Shape of a generated / saved script name (``.py`` optional).
_SCRIPT_NAME_RE = re.compile(r"^[\w.\-]+$", re.UNICODE)
_FLOW_ID_RE = re.compile(r"^f\d{4,}$")

#: Default proxy bypass list for the Windows system proxy (the GUI itself must not be proxied).
_PROXY_OVERRIDE = winsupport.DEFAULT_PROXY_OVERRIDE

#: Window title of the in-app recording browser (DESIGN.md §13.12); the host appends 「— 記録中」.
BROWSER_TITLE = "reqrec 記録用ブラウザ"
#: Extra mitmdump arguments that tunnel HTTPS untouched (no CA certificate needed; only http:// is recorded).
#: A catch-all pattern: ``:443$`` matched port 443 only, so ``https://kanri:8443/`` was intercepted with
#: the untrusted mitmproxy CA (certificate error) although the status line says HTTPS is not recorded.
#: In regular (explicit proxy) mode mitmproxy applies ``ignore_hosts`` only when deciding the layer of a
#: ``CONNECT`` tunnel; plain ``http://`` requests (absolute-form, what WinINet sends to a proxy) never
#: reach that check and are still recorded.  Measured with mitmdump 12.2.3 (see
#: tests/test_webapp_iehost.py::TestHttpsPassthroughWithRealMitmdump): http:// recorded, https on a
#: non-443 port tunnelled with the origin server's own certificate and not recorded.
HTTPS_PASSTHROUGH_ARGS = ("--ignore-hosts", ".*")
#: Seconds ``record_start`` waits for mitmdump to accept connections before opening the recording browser.
PROXY_READY_TIMEOUT = 20.0
#: Accepted values of ``browser`` on ``POST /api/record/start``.
_BROWSER_KINDS = ("none", "iehost")
#: Accepted values of ``origin`` on ``POST /api/record/start``: the screen that started the recording.
_ORIGINS = ("advanced", "easy")


# --------------------------------------------------------------------------- helpers

def get_state() -> AppState:
    return current_app.extensions["reqrec"]


def _json_body(required: bool = True) -> dict[str, Any]:
    """Parsed JSON object body (``{}`` for an empty body when not required)."""
    raw = request.get_data(cache=True)
    if not raw or not raw.strip():
        if required:
            raise ApiError("JSON のリクエスト本文が必要です")
        return {}
    data = request.get_json(silent=True, force=True)
    if data is None:
        raise ApiError("リクエスト本文を JSON として解析できません")
    if not isinstance(data, dict):
        raise ApiError("リクエスト本文は JSON オブジェクトである必要があります")
    return data


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off", ""):
            return False
    raise ApiError("true / false で指定してください")


def _ok(**data: Any) -> Response:
    data.setdefault("ok", True)
    return jsonify(data)


def _windows_only() -> None:
    if not winsupport.is_windows():
        raise ApiError(winsupport.NOT_WINDOWS_MESSAGE, status=400, is_windows=False)


def _options_from_body(body: dict[str, Any]) -> tuple[model.PlanOptions, model.GenOptions]:
    """``{"plan_options": {...}, "gen_options": {...}}``; a body without those keys is taken as the
    plan options themselves; missing parts keep the current state."""
    state = get_state()
    if "plan_options" in body or "gen_options" in body:
        plan_src = body.get("plan_options")
        gen_src = body.get("gen_options")
    else:
        plan_src = body if body else None
        gen_src = None
    plan_opts = plan_options_from_json(plan_src) if plan_src is not None else state.plan_options
    gen_opts = gen_options_from_json(gen_src) if gen_src is not None else state.gen_options
    return plan_opts, gen_opts


def _rebuild_plan(state: AppState, plan_opts: model.PlanOptions) -> model.Plan:
    recording = state.require_recording()
    try:
        plan = build_plan(recording, plan_opts)
    except Exception as exc:  # the analysis must never take the GUI down
        current_app.logger.exception("build_plan failed")
        raise ApiError(f"解析に失敗しました: {exc.__class__.__name__}: {exc}", status=500) from exc
    with state.lock:
        state.plan = plan
        state.plan_options = plan_opts
    return plan


def _flow_rows(recording: model.Recording, plan: model.Plan) -> list[dict[str, Any]]:
    """One row per recorded flow: kept / step index or drop reason (sorted by time, then id)."""
    step_of: dict[str, int] = {}
    for step in plan.steps:
        for fid in step.source_flow_ids:
            step_of.setdefault(fid, step.index)
    reason_of = {d.flow_id: d.reason for d in plan.dropped}
    rows = []
    for flow in recording.flows:
        resp = flow.response
        step_index = step_of.get(flow.id)
        kept = step_index is not None
        if kept:
            reason = None
        else:
            reason = reason_of.get(flow.id) or "not used (folded into another step or beyond --max-steps)"
        rows.append({
            "id": flow.id,
            "started_at": flow.started_at,
            "method": flow.request.method,
            "status": resp.status if resp is not None else None,
            "mime": resp.mime_type if resp is not None else None,
            "url": flow.request.url,
            "host": flow.request.host,
            "referer": flow.request.header("referer"),
            "resource_type": flow.resource_type,
            "page_ref": flow.page_ref,
            "kept": kept,
            "reason": reason,
            "step_index": step_index,
            "has_body": flow.request.body is not None and len(flow.request.body) > 0,
            "response_size": len(resp.body) if resp is not None and resp.body is not None else 0,
            "is_final": plan.final_step_index is not None and step_index == plan.final_step_index,
        })
    rows.sort(key=lambda r: (r["started_at"] is None, r["started_at"] if r["started_at"] is not None else 0.0, r["id"]))
    return rows


def _plan_payload(state: AppState, plan: model.Plan) -> dict[str, Any]:
    recording = state.require_recording()
    report = build_inspect_report(recording, plan, source=", ".join(state.sources))
    report["flows"] = _flow_rows(recording, plan)
    report["auth"] = model.to_plain(plan.auth) if plan.auth is not None else None
    report["final_step_index"] = plan.final_step_index
    report["loops"] = [
        {"step_index": s.index, "var": s.loop.var, "count": len(s.loop.values), "numeric_range": list(s.loop.numeric_range) if s.loop.numeric_range else None}
        for s in plan.steps if s.loop is not None
    ]
    report["summary"] = format_plan_summary(plan, flows_total=len(recording.flows))
    report["plan_options"] = options_to_plain(state.plan_options)
    report["sources"] = list(state.sources)
    report["excluded_self_flows"] = int(recording.meta.get("excluded_self_flows", 0) or 0)
    return report


def _secrets_of(plan: model.Plan) -> list[dict[str, Any]]:
    """Environment variables the generated script reads: secret constants plus, for NTLM /
    Negotiate (DESIGN.md §13.2), ``REQREC_NTLM_USER`` / ``REQREC_NTLM_PASSWORD`` which the script
    uses when ``requests_negotiate_sspi`` is unavailable (not a Windows box / another user)."""
    out = []
    seen: set[str] = set()
    for c in plan.constants:
        if c.secret and c.env_var and c.env_var not in seen:
            seen.add(c.env_var)
            out.append({"name": c.name, "env_var": c.env_var, "comment": c.comment})
    auth = plan.auth
    if auth is not None and str(auth.kind or "").lower() in ("ntlm", "negotiate"):
        # ``auth`` marks the Windows-authentication entries: the easy screen keeps their own
        # instruction (the logged-in Windows user via reqrec[sspi] needs neither value) instead of
        # 「記録したときと同じ値を入れてください」, and does not count the user name (written into the
        # script as its default) among the values 「スクリプトに書き込まれていません」.
        kind = str(auth.kind).lower()
        label = "NTLM" if kind == "ntlm" else "Negotiate"
        who = f"記録時のユーザー: {auth.username}" if auth.username else "記録からユーザー名は特定できませんでした"
        if "REQREC_NTLM_USER" not in seen:
            seen.add("REQREC_NTLM_USER")
            out.append({
                "name": f"{label} 認証のユーザー名 (DOMAIN\\user)", "env_var": "REQREC_NTLM_USER", "secret": False,
                "default": auth.username or "", "auth": kind,
                "comment": f"{who}。Windows で今ログインしているユーザーのまま認証する場合 (reqrec[sspi]) は空欄のまま (使われません)",
            })
        if "REQREC_NTLM_PASSWORD" not in seen:
            seen.add("REQREC_NTLM_PASSWORD")
            out.append({
                "name": f"{label} 認証のパスワード", "env_var": "REQREC_NTLM_PASSWORD", "secret": True, "auth": kind,
                "comment": "Windows 以外 / 別のユーザーで実行する場合 (reqrec[ntlm]) に必要。"
                           "Windows で今ログインしているユーザーのまま認証する場合 (reqrec[sspi]) は空欄のまま",
            })
    return out


def _body_view(body: Optional[bytes], content_type: Optional[str], mime: Optional[str]) -> dict[str, Any]:
    """Decoded body for the detail drawer (JSON pretty-printed, binary summarised, long bodies cut)."""
    if body is None or len(body) == 0:
        return {"kind": "none", "size": 0, "text": "", "truncated": False, "mime": mime}
    size = len(body)
    mime = (mime or util.parse_content_type(content_type)[0] or "").lower() or None
    textual = util.is_textual_mime(mime) or mime is None or mime in ("application/octet-stream",)
    text: Optional[str] = None
    if textual:
        decoded = util.decode_body(body, content_type)
        if "\x00" in decoded[:4096] or (mime in (None, "application/octet-stream") and _looks_binary(body)):
            textual = False
        else:
            text = decoded
    if not textual or text is None:
        return {"kind": "binary", "size": size, "text": None, "truncated": False, "mime": mime}
    kind = "text"
    stripped = text.lstrip()
    if util.is_json_mime(mime) or (stripped[:1] in ("{", "[") and len(stripped) < 4 * 1024 * 1024):
        try:
            parsed = json.loads(text)
            text = json.dumps(parsed, ensure_ascii=False, indent=2)
            kind = "json"
        except ValueError:
            pass
    elif mime == "application/x-www-form-urlencoded":
        kind = "form"
    elif util.is_html_mime(mime):
        kind = "html"
    truncated = len(text) > BODY_LIMIT
    if truncated:
        text = text[:BODY_LIMIT]
    view: dict[str, Any] = {"kind": kind, "size": size, "text": text, "truncated": truncated, "mime": mime}
    if kind == "form":
        view["pairs"] = [list(p) for p in util.parse_form(util.decode_body(body, content_type))]
    return view


def _looks_binary(body: bytes) -> bool:
    sample = body[:2048]
    if not sample:
        return False
    control = sum(1 for b in sample if b < 9 or 13 < b < 32)
    return control > len(sample) * 0.05


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts)).isoformat(timespec="milliseconds")
    except (OverflowError, OSError, ValueError):
        return None


def _timestamp_name(prefix: str, ext: str) -> str:
    return f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"


def _script_name(raw: Any) -> str:
    """``scrape`` / ``scrape.py`` -> ``scrape.py`` (validated)."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raw = _timestamp_name("scrape", "")
    name = safe_name(raw, "スクリプト名")
    if not name.lower().endswith(".py"):
        name += ".py"
    if name.lower() == ".py":
        raise ApiError("スクリプト名が指定されていません")
    return name


def _file_entry_with_flows(entry: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in entry.items() if k != "path"}
    out["flows"] = None
    ext = os.path.splitext(entry["name"])[1].lower()
    if entry["size"] <= CHEAP_COUNT_MAX_BYTES and ext in (".json", ".har"):
        try:
            with open(entry["path"], "rb") as fh:
                data = json.loads(fh.read().decode("utf-8-sig", errors="replace"))
            if isinstance(data, dict):
                if isinstance(data.get("flows"), list):
                    out["flows"] = len(data["flows"])
                elif isinstance(data.get("log"), dict) and isinstance(data["log"].get("entries"), list):
                    out["flows"] = len(data["log"]["entries"])
        except (OSError, ValueError):
            out["flows"] = None
    return out


def _resolve_recording_name(state: AppState, item: Any) -> tuple[str, str]:
    """``"x.har"`` / ``{"folder": "uploads", "name": "x.har"}`` -> ``(path, display name)``."""
    folder: Optional[str] = None
    name: Any = item
    if isinstance(item, dict):
        folder = item.get("folder")
        name = item.get("name")
    clean = safe_name(name, "記録ファイル名")
    if os.path.splitext(clean)[1].lower() not in RECORDING_EXTENSIONS:
        raise ApiError(f"対応していないファイル形式です: {clean} (対応: {', '.join(sorted(RECORDING_EXTENSIONS))})")
    folders = [folder] if folder else ["recordings", "uploads"]
    for sub in folders:
        if sub not in ("recordings", "uploads"):
            raise ApiError(f"不正なフォルダです: {sub}")
        path = state.path_in(sub, clean, "記録ファイル名")
        if os.path.isfile(path):
            return path, f"{sub}/{clean}"
    raise ApiError(f"ファイルが見つかりません: {clean}", status=404)


def _iehost_info(state: AppState) -> dict[str, Any]:
    """``reqrec.iehost.availability`` reduced to what the page / ``/api/state`` expose, plus the
    current 表示モード (preset name of the HKCU value, ``"default"`` when unset) and the last launch
    error of this GUI session (shown on the easy screen so a blocked exe is explained)."""
    info = iehost.availability(state.workdir)
    out = {k: info.get(k) for k in ("available", "reason", "exe", "built", "shipped")}
    out["emulation"] = "default"
    if info.get("available"):
        try:
            value = iehost.get_emulation()
        except Exception:
            value = None
        if value is not None:
            names = [k for k, v in iehost.EMULATION_LEVELS.items() if v == value]
            out["emulation"] = names[0] if names else "custom"
    out["last_error"] = state.iehost_error
    return out


def _require_iehost(state: AppState) -> None:
    """400 unless the in-app recording browser can be used on this PC (Windows + csc.exe or a prebuilt exe)."""
    _windows_only()
    info = iehost.availability(state.workdir)
    if not info.get("available"):
        raise ApiError(info.get("reason") or "記録用ブラウザ (IE エンジン) はこの PC では使えません。", status=400, iehost=info)


def _iehost_start_url(raw: Any) -> Optional[str]:
    """The optional first page of the recording browser: ``None`` when blank, else a validated
    ``http(s)://`` URL (a bare host name gets ``http://``; ``edge://`` and other schemes are refused)."""
    text = str(raw or "").strip()
    if not text:
        return None
    if text.lower().startswith("edge://"):
        raise ApiError("記録用ブラウザで開けるのは http:// または https:// のアドレスだけです")
    try:
        return launch.validate_url(text)
    except ValueError as exc:
        raise ApiError(str(exc)) from exc


def _browser_payload(proc: Any) -> dict[str, Any]:
    """``{"kind": "iehost", "pid", "running", "log", "exit_code"}`` for a ``BrowserProcess``."""
    code = proc.poll()
    return {
        "kind": "iehost",
        "pid": getattr(proc, "pid", None),
        "running": code is None,
        "exit_code": code,
        "log": getattr(proc, "log_path", None),
    }


def _browser_status(state: AppState) -> dict[str, Any]:
    """``{"kind": "iehost"|None, "running": bool, "pid": ...|None, "exit_code": ...|None}``."""
    proc = state.browser
    if proc is None:
        return {"kind": None, "running": False, "pid": None, "exit_code": None}
    payload = _browser_payload(proc)
    payload.pop("log", None)
    return payload


#: ``kind`` of the 500 errors of ``record_start`` (the easy screen explains each one differently):
#: ``proxy`` = mitmdump never accepted connections, ``emulation`` = 表示モード (HKCU value) could not be
#: written, ``iehost`` = the recording browser could not be built or started (only this one gets the
#: 「RecBrowser.exe が止められた可能性」 guidance and is remembered as ``iehost.last_error``).
ERROR_KIND_PROXY = "proxy"
ERROR_KIND_EMULATION = "emulation"
ERROR_KIND_IEHOST = "iehost"


def _remove_quietly(path: Optional[str]) -> bool:
    """Delete ``path`` if it is a file; ``True`` when something was removed.  Never raises."""
    if not path or not os.path.isfile(path):
        return False
    try:
        os.remove(path)
        return True
    except OSError:
        return False


def _forget_recording(state: AppState) -> None:
    """Make the recorder forget its output file (``RecorderManager.forget``; tolerated when absent)."""
    forget = getattr(state.recorder, "forget", None)
    if callable(forget):
        try:
            forget()
        except Exception:
            current_app.logger.exception("recorder.forget failed")


def _abandon_start(state: AppState, out: str) -> None:
    """Undo a ``record_start`` that failed after mitmdump was spawned (proxy never listened, 表示モード
    or the recording browser failed): stop the recorder, delete the half-made file (normally absent:
    no browser ever used the proxy) and forget it, so 詳細設定 does not report 「記録は保存されました」
    and [記録停止] is not left enabled.  Does nothing when another recording owns the recorder by now."""
    with state.lock:
        current = getattr(state.recorder, "out", out)
        if current and os.path.abspath(current) != os.path.abspath(out):
            return
        state.recorder.stop()
        _remove_quietly(out)
        _forget_recording(state)
        state.record_browser_kind = None
        state.record_origin = None


def _launch_iehost(state: AppState, proxy_address: str, start_url: Optional[str], https_recorded: bool = False) -> Any:
    """Start ``RecBrowser.exe`` (building it first when needed) and remember it as ``state.browser``.

    Raises :class:`ApiError` 500 (``kind: "iehost"``) with a Japanese message; the compiler's output
    is part of the message when the build failed (``IEHostError`` carries it).
    """
    try:
        kwargs: dict[str, Any] = {"url": start_url, "title": BROWSER_TITLE}
        if https_recorded:
            kwargs["https_recorded"] = True
        proc = iehost.launch(state.workdir, proxy_address, **kwargs)
    except Exception as exc:
        current_app.logger.exception("iehost launch failed")
        state.iehost_error = str(exc)
        raise ApiError(f"記録用ブラウザを起動できませんでした: {exc}", status=500, kind=ERROR_KIND_IEHOST) from exc
    state.iehost_error = None
    state.browser = proc
    return proc


def _apply_loaded(state: AppState, recording: model.Recording, sources: list[str], append: bool, from_gui_recorder: bool) -> dict[str, Any]:
    excluded = 0
    if from_gui_recorder:
        recording, excluded = exclude_netlocs(recording, gui_netlocs(state.host, state.port, request.host))
    state.set_recording(recording, sources, append)
    summary = state.recording_summary()
    summary["excluded_self"] = excluded
    summary["appended"] = bool(append)
    return summary


# --------------------------------------------------------------------------- page

@bp.get("/")
def index() -> str:
    state = get_state()
    return render_template(
        "index.html",
        token=state.token,
        version=__version__,
        is_windows=winsupport.is_windows(),
        gui_address=f"{request.host}",
        workdir=state.workdir,
        mitmproxy_available=mitmproxy_available(),
        iehost=_iehost_info(state),
    )


@bp.get("/api/state")
def api_state() -> Response:
    state = get_state()
    windows = winsupport.status_summary() if winsupport.is_windows() else {"is_windows": False, "proxy": None, "cert": {"installed": None, "path": None}, "error": None}
    windows["proxy_backup_active"] = state.proxy_backup is not None
    return jsonify({
        "version": __version__,
        "workdir": state.workdir,
        "gui_address": request.host,
        "mitmproxy_available": mitmproxy_available(),
        "recorder": state.recorder.status(),
        "recording": state.recording_summary(),
        "plan_loaded": state.plan is not None,
        "plan_options": options_to_plain(state.plan_options),
        "gen_options": options_to_plain(state.gen_options),
        "run": state.runner.status(),
        "windows": windows,
        "iehost": _iehost_info(state),
        "browser": _browser_status(state),
        "record_browser_kind": state.record_browser_kind,
        "record_origin": state.record_origin,
        "last_script": state.last_script_name,
        "secrets": list(state.last_secrets),
    })


# --------------------------------------------------------------------------- recording (live)

@bp.post("/api/record/start")
def record_start() -> Response:
    state = get_state()
    body = _json_body(required=False)
    raw_port = body.get("port", 8080)
    if raw_port is None or (isinstance(raw_port, str) and not raw_port.strip()):
        raw_port = 8080
    auto_port = isinstance(raw_port, str) and raw_port.strip().lower() == "auto"  # かんたんモード: 空きポートを自動選択
    if auto_port:
        port = 0  # resolved below, once listen_host is known
    else:
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            raise ApiError("ポート番号は数値で指定してください") from None
        if not 1 <= port <= 65535:
            raise ApiError("ポート番号は 1〜65535 で指定してください")
    hosts_raw = body.get("hosts", [])
    if isinstance(hosts_raw, str):
        hosts = [h for h in re.split(r"[,\s;]+", hosts_raw) if h]
    elif isinstance(hosts_raw, list):
        hosts = [str(h).strip() for h in hosts_raw if str(h).strip()]
    else:
        raise ApiError("対象ホストは配列か文字列で指定してください")
    listen_host = str(body.get("listen_host") or "127.0.0.1").strip() or "127.0.0.1"
    set_proxy = _bool(body.get("set_system_proxy"), False)
    append = _bool(body.get("append"), False)
    # --- in-app recording browser (DESIGN.md §13.12) ---
    browser_kind = str(body.get("browser") or "none").strip().lower()
    if browser_kind not in _BROWSER_KINDS:
        raise ApiError(f"記録方式 (browser) は {' / '.join(_BROWSER_KINDS)} のどちらかで指定してください")
    use_iehost = browser_kind == "iehost"
    # the first page only matters for the recording browser; a stale value from a hidden field must
    # not make an Edge / manual recording fail
    start_url = _iehost_start_url(body.get("start_url")) if use_iehost else None
    https_passthrough = _bool(body.get("https_passthrough"), use_iehost)
    emulation = str(body.get("emulation") or "keep").strip().lower()
    if emulation != "keep" and emulation not in iehost.EMULATION_LEVELS:
        raise ApiError(f"表示モード (emulation) は keep / {' / '.join(iehost.EMULATION_LEVELS)} のいずれかで指定してください")
    # which screen started it: only an easy-started recording is stopped automatically by the easy
    # screen when its recording browser closes (kept on the server so a page reload knows it too)
    origin = str(body.get("origin") or "advanced").strip().lower()
    if origin not in _ORIGINS:
        raise ApiError(f"origin は {' / '.join(_ORIGINS)} のどちらかで指定してください")

    if state.recorder.running:
        raise ApiError("すでに記録中です。先に [記録停止] を押してください。", status=409)
    if state.recorder.command_builder is _default_command_builder() and not mitmproxy_available():
        raise ApiError(
            "mitmproxy がインストールされていないため記録できません。コマンドプロンプトで "
            'pip install "reqrec[record]" を実行してから GUI を再起動してください。', status=400,
        )
    if use_iehost:
        _require_iehost(state)
        if set_proxy:
            raise ApiError("アプリ内の記録用ブラウザを使うときは、システムプロキシの自動設定は使えません (必要もありません)。")
    if set_proxy:
        _windows_only()
    if auto_port:
        try:
            port = find_free_port(listen_host, preferred=8080, avoid=(state.port,))
        except OSError as exc:
            raise ApiError(f"記録用の空きポートが見つかりません: {exc}", status=500) from exc
    if port == state.port and listen_host in ("127.0.0.1", "localhost", state.host, "0.0.0.0", "::"):
        raise ApiError(f"ポート {port} はこの GUI が使用中です。別のポート (例: 8080) を指定してください。")

    out = os.path.join(state.subdir("recordings"), _timestamp_name("rec", ".json"))
    start_kwargs: dict[str, Any] = {}
    if https_passthrough:
        start_kwargs["extra_args"] = list(HTTPS_PASSTHROUGH_ARGS)
    with state.lock:
        state.close_browser()  # a browser left over from an earlier session must not record into the new one
        try:
            status = state.recorder.start(out, port=port, hosts=hosts, listen_host=listen_host, **start_kwargs)
        except RecorderError as exc:
            raise ApiError(str(exc), status=400) from exc
        state.record_append = append
        state.record_browser_kind = browser_kind
        state.record_https_passthrough = https_passthrough
        state.record_origin = origin
        proxy_address = winsupport.proxy_server_for(listen_host, port)
        proxy_result: Optional[dict[str, Any]] = None
        if set_proxy:
            try:
                backup = winsupport.set_system_proxy(proxy_address, enable=True, override=_PROXY_OVERRIDE)
            except Exception as exc:
                _abandon_start(state, out)
                raise ApiError(f"システムプロキシを設定できませんでした: {exc}", status=500) from exc
            if state.proxy_backup is None:  # keep the oldest backup when restarted without restore
                state.proxy_backup = backup
            state.proxy_server = proxy_address
            state.register_proxy_restore(winsupport.restore_system_proxy)
            proxy_result = {"set": True, "server": proxy_address, "backup": backup}
    time.sleep(0.15)  # give an immediately failing child (port in use) the chance to report
    status = state.recorder.status()
    browser_result: Optional[dict[str, Any]] = None
    warnings: list[str] = []
    if use_iehost and status.get("running"):
        # mitmdump needs a second or two before it accepts connections; a browser pointed at it
        # earlier shows 「ページを表示できません」 for the first page.  Wait without the lock.
        wait = getattr(state.recorder, "wait_until_listening", None)
        if wait is not None and not wait(timeout=PROXY_READY_TIMEOUT):
            failed = state.recorder.status()
            _abandon_start(state, out)
            tail = (failed.get("stderr_tail") or "").strip().splitlines()
            detail = failed.get("error") or (tail[-1] if tail else "時間内に待ち受けを開始しませんでした")
            raise ApiError(f"記録用プロキシを起動できませんでした: {detail}", status=500, kind=ERROR_KIND_PROXY)
        # The recorder is up: point the recording browser at it.  Document mode first (a per-exe
        # HKCU value read by the engine at start-up), then the process itself.
        with state.lock:
            if not state.recorder.running or os.path.abspath(state.recorder.out or "") != os.path.abspath(out):
                raise ApiError("記録用ブラウザを開く前に記録が止まりました。もう一度 [記録をはじめる] を押してください。", status=409)
            level = iehost.EMULATION_LEVELS.get(emulation)
            if emulation == "keep":
                pass  # かんたん画面: whatever 表示モード was chosen in 詳細設定 stays; the registry is not touched
            elif level is None:
                # 既定 (IE7 相当): nothing to write.  Only a value left by an earlier non-default
                # choice is removed, and failing to remove it never blocks the recording.
                try:
                    if iehost.get_emulation() is not None:
                        iehost.set_emulation(None)
                except Exception as exc:
                    warnings.append(f"表示モードの設定を既定に戻せませんでした（記録は続けます）: {exc}")
            else:
                try:
                    iehost.set_emulation(level)
                except Exception as exc:
                    _abandon_start(state, out)
                    raise ApiError(f"記録用ブラウザの表示モードを設定できませんでした: {exc}", status=500,
                                   kind=ERROR_KIND_EMULATION) from exc
            try:
                proc = _launch_iehost(state, proxy_address, start_url, https_recorded=not https_passthrough)
            except ApiError:
                _abandon_start(state, out)
                raise
            browser_result = _browser_payload(proc)
    return _ok(
        instructions=format_instructions(out, port, hosts, listen_host),
        out=os.path.basename(out),
        out_path=out,
        port=port,
        auto_port=auto_port,
        proxy_address=proxy_address,
        system_proxy=proxy_result,
        status=status,
        browser=browser_result,
        browser_kind=browser_kind,
        https_passthrough=https_passthrough,
        emulation=emulation,
        origin=origin,
        warnings=warnings,
        self_excluded_hosts=sorted(gui_netlocs(state.host, state.port, request.host)),
    )


def _default_command_builder():
    from ..recorder.run import build_command

    return build_command


@bp.get("/api/record/status")
def record_status() -> Response:
    state = get_state()
    status = state.recorder.status()
    status["proxy_backup_active"] = state.proxy_backup is not None
    status["mitmproxy_available"] = mitmproxy_available()
    status["browser"] = _browser_status(state)
    status["browser_kind"] = state.record_browser_kind
    status["origin"] = state.record_origin
    return jsonify(status)


def _restore_proxy(state: AppState) -> Optional[str]:
    """Put the Windows proxy back if we changed it; returns an error message instead of raising."""
    backup = state.proxy_backup
    if backup is None:
        return None
    try:
        winsupport.restore_system_proxy(backup)
    except Exception as exc:
        return f"システムプロキシを元に戻せませんでした: {exc}"
    state.proxy_backup = None
    state.proxy_server = None
    return None


@bp.post("/api/record/stop")
def record_stop() -> Response:
    state = get_state()
    body = _json_body(required=False)
    append = _bool(body.get("append"), state.record_append)
    discard = _bool(body.get("discard"), False)
    with state.lock:
        was_running = state.recorder.running
        if not was_running and state.recorder.out is None:
            raise ApiError("記録は開始されていません", status=409)
        # The recording browser goes first so its in-flight requests reach the proxy before mitmdump
        # flushes and exits; ``close_browser`` never raises and forgets the process either way.
        had_browser = state.browser is not None
        browser_exit_code = state.close_browser(timeout=5.0)
        exit_code = state.recorder.stop()
        proxy_error = _restore_proxy(state)
        state.record_browser_kind = None
        state.record_origin = None
        if discard:
            # [やめる]: nothing is loaded (the recording already loaded stays as it was) and the
            # half-made file is removed so it does not show up in 「作業フォルダ内のファイル」; the
            # recorder forgets it so 詳細設定 does not say 「記録は保存されました」 for a deleted file.
            removed = _remove_quietly(state.recorder.out)
            _forget_recording(state)
            return _ok(discarded=True, removed=removed, exit_code=exit_code, proxy_error=proxy_error,
                       browser_exit_code=browser_exit_code, recording=state.recording_summary())
        out_path = state.recorder.out
        try:
            recording = state.recorder.load_recording()
        except RecorderError as exc:
            if not (out_path and not os.path.exists(out_path) and exit_code is not None):
                raise ApiError(str(exc), status=400, exit_code=exit_code, proxy_error=proxy_error,
                               browser_exit_code=browser_exit_code, stderr_tail=state.recorder.status()["stderr_tail"]) from exc
            # The addon writes the file after the first response only, and on Windows the stop
            # (CTRL_BREAK) ends mitmdump before its final flush: no file = nothing was recorded.
            recording = model.Recording(flows=[], meta={})
        if not recording.flows:
            if had_browser:
                message = (
                    "何も記録されませんでした。記録用ブラウザでページを開く前にブラウザが閉じられたか、"
                    "https:// のページ（記録されません）だけを開いた可能性があります。"
                    "もう一度 [記録をはじめる] を押し、http:// のページを開いて操作してください。"
                )
            else:
                message = (
                    "何も記録されませんでした。ブラウザのプロキシ設定（と https:// のサイトなら CA 証明書）を確認し、"
                    "記録中にページを開いてください。"
                )
            raise ApiError(
                message,
                status=400, exit_code=exit_code, proxy_error=proxy_error, browser_exit_code=browser_exit_code,
                out=os.path.basename(state.recorder.out or ""), empty=True,
            )
        summary = _apply_loaded(state, recording, [f"recordings/{os.path.basename(state.recorder.out or '')}"], append, from_gui_recorder=True)
    summary.update(out=os.path.basename(state.recorder.out or ""), out_path=state.recorder.out, exit_code=exit_code,
                   proxy_error=proxy_error, browser_exit_code=browser_exit_code)
    return _ok(**summary)


# --------------------------------------------------------------------------- recordings (files)

@bp.post("/api/recordings/upload")
def recordings_upload() -> Response:
    state = get_state()
    files = request.files.getlist("files") or request.files.getlist("file")
    files = [f for f in files if f and f.filename]
    if not files:
        raise ApiError("ファイルが選択されていません (.har / .json / .mitm)")
    append = _bool(request.form.get("append"), False)
    saved: list[str] = []
    display: list[str] = []
    for storage in files:
        name = sanitise_upload_name(storage.filename)
        ext = os.path.splitext(name)[1].lower()
        if ext not in RECORDING_EXTENSIONS:
            raise ApiError(f"対応していないファイル形式です: {storage.filename} (対応: .har / .json / .mitm)")
        target = unique_path(state.path_in("uploads", name, "アップロードファイル名"))
        try:
            storage.save(target)
        except OSError as exc:
            raise ApiError(f"ファイルを保存できません: {exc}", status=500) from exc
        saved.append(target)
        display.append(f"uploads/{os.path.basename(target)}")
    recording = load_sources(saved)
    with state.lock:
        summary = _apply_loaded(state, recording, display, append, from_gui_recorder=False)
    summary["saved"] = [os.path.basename(p) for p in saved]
    return _ok(**summary)


@bp.get("/api/recordings")
def recordings_list() -> Response:
    state = get_state()
    files = [_file_entry_with_flows(e) for sub in ("recordings", "uploads") for e in state.list_files(sub, RECORDING_EXTENSIONS)]
    return jsonify({"files": files, "current": state.recording_summary()})


@bp.post("/api/recordings/open")
def recordings_open() -> Response:
    state = get_state()
    body = _json_body()
    names = body.get("names")
    if isinstance(names, (str, dict)):
        names = [names]
    if not isinstance(names, list) or not names:
        raise ApiError("開くファイルを選択してください")
    append = _bool(body.get("append"), False)
    paths: list[str] = []
    display: list[str] = []
    for item in names:
        path, label = _resolve_recording_name(state, item)
        paths.append(path)
        display.append(label)
    recording = load_sources(paths)
    from_recorder = all(label.startswith("recordings/") for label in display)
    with state.lock:
        summary = _apply_loaded(state, recording, display, append, from_gui_recorder=from_recorder)
    return _ok(**summary)


@bp.post("/api/recordings/clear")
def recordings_clear() -> Response:
    state = get_state()
    state.clear_recording()
    return _ok(recording=state.recording_summary())


# --------------------------------------------------------------------------- analysis

@bp.post("/api/plan")
def api_plan() -> Response:
    state = get_state()
    body = _json_body(required=False)
    plan_opts, _gen = _options_from_body(body)
    with state.lock:
        plan = _rebuild_plan(state, plan_opts)
        payload = _plan_payload(state, plan)
    return jsonify(payload)


@bp.get("/api/flow/<flow_id>")
def api_flow(flow_id: str) -> Response:
    state = get_state()
    if not _FLOW_ID_RE.match(flow_id or ""):
        raise ApiError(f"フロー ID が不正です: {flow_id}", status=404)
    with state.lock:
        recording = state.require_recording()
        flow = recording.flow_by_id(flow_id)
        if flow is None:
            raise ApiError(f"フロー {flow_id} はありません", status=404)
        plan = state.plan
        step_index = None
        reason = None
        if plan is not None:
            for step in plan.steps:
                if flow_id in step.source_flow_ids:
                    step_index = step.index
                    break
            if step_index is None:
                reason = next((d.reason for d in plan.dropped if d.flow_id == flow_id), None)
        req = flow.request
        resp = flow.response
        payload = {
            "id": flow.id,
            "started_at": flow.started_at,
            "started_at_iso": _iso(flow.started_at),
            "resource_type": flow.resource_type,
            "page_ref": flow.page_ref,
            "step_index": step_index,
            "reason": reason,
            "request": {
                "method": req.method,
                "url": req.url,
                "host": req.host,
                "path": req.path,
                "query": [list(p) for p in req.query_pairs],
                "headers": [list(h) for h in req.headers],
                "body": _body_view(req.body, req.header("content-type"), req.content_type),
            },
            "response": None if resp is None else {
                "status": resp.status,
                "headers": [list(h) for h in resp.headers],
                "mime": resp.mime_type,
                "body": _body_view(resp.body, resp.header("content-type"), resp.mime_type),
            },
        }
    return jsonify(payload)


# --------------------------------------------------------------------------- generation

@bp.post("/api/generate")
def api_generate() -> Response:
    state = get_state()
    body = _json_body(required=False)
    plan_opts, gen_opts = _options_from_body(body)
    with state.lock:
        plan = _rebuild_plan(state, plan_opts)
        try:
            code = generate(plan, gen_opts)
        except Exception as exc:
            current_app.logger.exception("generate failed")
            raise ApiError(f"コード生成に失敗しました: {exc}", status=500) from exc
        state.gen_options = gen_opts
        state.last_code = code
        secrets = _secrets_of(plan)
        state.last_secrets = secrets
        recording = state.require_recording()
        payload = {
            "code": code,
            "summary": format_plan_summary(plan, flows_total=len(recording.flows)),
            "warnings": list(plan.warnings),
            "secrets": secrets,
            "env_vars": [s["env_var"] for s in secrets],
            "steps": len(plan.steps),
            "final_step_index": plan.final_step_index,
            "auth": model.to_plain(plan.auth) if plan.auth is not None else None,
            "suggested_name": _suggest_script_name(state, plan),
            "plan_options": options_to_plain(plan_opts),
            "gen_options": options_to_plain(gen_opts),
        }
    return jsonify(payload)


def _suggest_script_name(state: AppState, plan: model.Plan) -> str:
    host = ""
    for step in plan.steps:
        url = step.literal_url()
        if url:
            host = model.RecordedRequest("GET", url).host
            break
    slug = util.safe_identifier(host.replace(".", "_"), default="site").strip("_") if host else "site"
    return f"scrape_{slug or 'site'}"[:60]


#: Plan / codegen notes that describe what the script does for the user rather than a risk
#: (Shift_JIS form bodies are re-encoded faithfully): shown as information, not under 「確認してください」.
_INFO_NOTE_MARKERS = ("UTF-8 以外の文字コード", "looks like a credential")


def _split_warnings(warnings: list[str]) -> tuple[list[str], list[str]]:
    actionable: list[str] = []
    notes: list[str] = []
    for w in warnings:
        bucket = notes if any(m in w for m in _INFO_NOTE_MARKERS) else actionable
        if w not in bucket:
            bucket.append(w)
    return actionable, notes


def _path_part(label: str) -> str:
    """``path segment 2`` (0-based index from deps.request_params) -> 「URL の / で区切った 3 番目の部分」,
    any other parameter name -> 「「name」の値」."""
    m = re.fullmatch(r"path segment (\d+)", label)
    if m:
        return f"URL の / で区切った {int(m.group(1)) + 1} 番目の部分"
    return f"「{label}」の値"


#: The English plan warnings (reqrec/plan.py) in plain Japanese for the easy screen.  The patterns
#: follow plan.py's wording exactly; tests/test_webapp_easy.py runs build_plan + generate on every
#: fixture and checks that each produced warning comes out in Japanese.
_WARNING_TRANSLATIONS: tuple[tuple[Any, Any], ...] = (
    (re.compile(r"step (\d+): value of `(.+)` looks dynamic but could not be traced to any earlier "
                r"response; replaying the recorded literal may fail", re.S),
     lambda m: (f"手順 {m.group(1)}: {_path_part(m.group(2))}は毎回変わるもののようですが、それより前の画面の"
                f"どこから来たのか分かりませんでした。記録したときの値をそのまま送るため、実行すると失敗することがあります。")),
    (re.compile(r"step (\d+): `(.+)` looks like a credential; the script reads it from the environment "
                r"variable (\S+) \(set it before running\)", re.S),
     lambda m: (f"手順 {m.group(1)}: 「{m.group(2)}」はパスワードなどの秘密の値と思われるため、スクリプトには"
                f"書き込まず、実行するときに入力します (環境変数 {m.group(3)})。")),
    (re.compile(r"recording has (\d+) steps; truncated to --max-steps (\d+) \((\d+) step\(s\) ignored\)", re.S),
     lambda m: (f"記録には {m.group(1)} 手順ありましたが、上限の {m.group(2)} 手順で打ち切りました "
                f"(残りの {m.group(3)} 手順は使っていません)。詳細設定の「ステップ数の上限」で変えられます。")),
    (re.compile(r"(\d+) cookie\(s\) existed before the recording started \((.*)\); they are replayed as "
                r"INITIAL_COOKIES and may have expired", re.S),
     lambda m: (f"記録を始める前からあった Cookie が {m.group(1)} 個あります ({m.group(2)})。スクリプトは"
                f"これを最初からそのまま送るため、期限が切れていると失敗することがあります。"
                f"そのときは、ブラウザを開き直してからもう一度記録してください。")),
    # Japanese warnings keep their text; only the step prefix is made readable
    (re.compile(r"step (\d+): (.*)", re.S), lambda m: f"手順 {m.group(1)}: {m.group(2)}"),
    (re.compile(r"step_(\d+)_\w*: (.*)", re.S), lambda m: f"手順 {int(m.group(1))}: {m.group(2)}"),
)


def warning_message(text: str) -> str:
    """Plain-Japanese version of one plan / codegen warning (unchanged when it is not recognised)."""
    raw = str(text or "")
    for pattern, render in _WARNING_TRANSLATIONS:
        m = pattern.fullmatch(raw.strip())
        if m:
            return render(m)
    return raw


def _warning_details(warnings: list[str]) -> list[dict[str, str]]:
    """``[{"text": <original>, "message": <plain Japanese>}]`` for the easy screen."""
    return [{"text": w, "message": warning_message(w)} for w in warnings]


def _is_attachment(content_disposition: Optional[str]) -> bool:
    """Shared download rule (1): ``Content-Disposition`` starting with ``attachment``, or naming a
    ``filename`` without being ``inline`` (:func:`reqrec.util.is_attachment_disposition`, the same
    rule as the generated scripts' ``_is_attachment``)."""
    return util.is_attachment_disposition(content_disposition)


def _downloads_of(recording: model.Recording, plan: model.Plan) -> list[dict[str, Any]]:
    """What the generated script will save, shown on the easy screen as 「保存されるファイル」.

    Shared download rule (5): every step whose **recorded** response is binary
    (``response_kind == "binary"``) or an attachment per :func:`_is_attachment` (html / text steps
    included); loop steps too, marked ``loop: true`` (one file per iteration).  ``filename`` comes
    from :func:`reqrec.util.download_filename` (``None`` when the header names no file).
    """
    by_id = {f.id: f for f in recording.flows}
    out: list[dict[str, Any]] = []
    for step in plan.steps:
        if not step.source_flow_ids:
            continue
        flow = by_id.get(step.source_flow_ids[-1])
        resp = flow.response if flow is not None else None
        disposition = resp.header("content-disposition") if resp is not None else None
        if step.response_kind != "binary" and not _is_attachment(disposition):
            continue
        out.append({
            "index": step.index,
            "method": step.method,
            "url": step.literal_url() or (flow.request.url_without_query if flow is not None else ""),
            "filename": util.download_filename(disposition),
            "mime": resp.mime_type if resp is not None else None,
            "loop": step.loop is not None,
        })
    return out


@bp.post("/api/scripts/save")
def scripts_save() -> Response:
    state = get_state()
    body = _json_body()
    code = body.get("code")
    if code is None:
        code = state.last_code
    if not isinstance(code, str) or not code.strip():
        raise ApiError("保存するコードがありません。先に [生成] を押してください。")
    name = _script_name(body.get("name"))
    path = state.path_in("scripts", name, "スクリプト名")
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code if code.endswith("\n") else code + "\n")
    except OSError as exc:
        raise ApiError(f"スクリプトを保存できません: {exc}", status=500) from exc
    state.last_script_name = name
    return _ok(name=name, path=path, size=os.path.getsize(path), download_url=f"/api/scripts/{name}/download")


@bp.get("/api/scripts")
def scripts_list() -> Response:
    state = get_state()
    files = [{k: v for k, v in e.items() if k != "path"} for e in state.list_files("scripts", {".py"})]
    return jsonify({"files": files, "last": state.last_script_name})


@bp.get("/api/scripts/<name>/download")
def scripts_download(name: str) -> Response:
    state = get_state()
    clean = _script_name(name)
    path = state.path_in("scripts", clean, "スクリプト名")
    if not os.path.isfile(path):
        raise ApiError(f"スクリプトが見つかりません: {clean}", status=404)
    return send_from_directory(state.subdir("scripts"), clean, as_attachment=True, download_name=clean, mimetype="text/x-python")


# --------------------------------------------------------------------------- run

@bp.post("/api/run")
def run_start() -> Response:
    state = get_state()
    body = _json_body()
    name = _script_name(body.get("name") or state.last_script_name)
    env = body.get("env") or {}
    if not isinstance(env, dict):
        raise ApiError("env はオブジェクト {\"VAR\": \"value\"} で指定してください")
    path = state.path_in("scripts", name, "スクリプト名")
    child_env = {str(k): v for k, v in env.items()}
    # downloaded files (Excel / CSV export ...) land in <workdir>/outputs unless the user chose otherwise
    child_env.setdefault("REQREC_OUTPUT_DIR", state.subdir("outputs"))
    status = state.runner.start(path, env=child_env, cwd=state.subdir("scripts"))
    state.last_script_name = name
    return _ok(**status)


@bp.get("/api/run/status")
def run_status() -> Response:
    return jsonify(get_state().runner.status())


@bp.post("/api/run/stop")
def run_stop() -> Response:
    state = get_state()
    if not state.runner.running:
        return _ok(**state.runner.status(), stopped=False)
    status = state.runner.stop()
    return _ok(**status, stopped=True)


@bp.post("/api/run/save_output")
def run_save_output() -> Response:
    state = get_state()
    body = _json_body(required=False)
    raw = body.get("name") or _timestamp_name("output", ".txt")
    name = safe_name(raw, "出力ファイル名")
    if "." not in name:
        name += ".txt"
    output = state.runner.last_stdout()
    if not output and state.runner.started_at is None:
        raise ApiError("保存できる出力がありません。先にスクリプトを実行してください。", status=409)
    path = state.path_in("outputs", name, "出力ファイル名")
    try:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(output)
    except OSError as exc:
        raise ApiError(f"出力を保存できません: {exc}", status=500) from exc
    return _ok(name=name, path=path, size=len(output.encode("utf-8")), truncated=state.runner.status()["stdout_truncated"])


# --------------------------------------------------------------------------- Windows

@bp.get("/api/win/status")
def win_status() -> Response:
    state = get_state()
    if not winsupport.is_windows():
        return jsonify({"is_windows": False, "proxy": None, "cert": {"installed": None, "path": None}, "error": None,
                        "proxy_backup_active": False, "message": winsupport.NOT_WINDOWS_MESSAGE})
    info = winsupport.status_summary()
    info["proxy_backup_active"] = state.proxy_backup is not None
    info["proxy_server_set"] = state.proxy_server
    return jsonify(info)


@bp.post("/api/win/proxy")
def win_proxy() -> Response:
    _windows_only()
    state = get_state()
    body = _json_body()
    enable = _bool(body.get("enable"), True)
    server = str(body.get("server") or "").strip()
    if enable and not server:
        raise ApiError("プロキシのアドレス (例: 127.0.0.1:8080) を指定してください")
    try:
        backup = winsupport.set_system_proxy(server, enable=enable, override=str(body.get("override") or _PROXY_OVERRIDE))
    except ValueError as exc:
        raise ApiError(str(exc)) from exc
    except Exception as exc:
        raise ApiError(f"システムプロキシを設定できませんでした: {exc}", status=500) from exc
    if state.proxy_backup is None:
        state.proxy_backup = backup
    state.proxy_server = server if enable else None
    state.register_proxy_restore(winsupport.restore_system_proxy)
    return _ok(proxy=winsupport.get_system_proxy(), backup=backup)


@bp.post("/api/win/proxy/restore")
def win_proxy_restore() -> Response:
    _windows_only()
    state = get_state()
    if state.proxy_backup is None:
        return _ok(restored=False, proxy=winsupport.get_system_proxy(), message="この GUI で変更したプロキシ設定はありません")
    error = _restore_proxy(state)
    if error:
        raise ApiError(error, status=500)
    return _ok(restored=True, proxy=winsupport.get_system_proxy())


@bp.post("/api/win/cert/install")
def win_cert_install() -> Response:
    _windows_only()
    body = _json_body(required=False)
    path = body.get("path")
    if path is not None:
        path = str(path)
    ok, output = winsupport.install_ca_cert(path)
    if not ok:
        raise ApiError(output or "証明書の登録に失敗しました", status=400, output=output)
    return _ok(output=output, installed=winsupport.cert_installed(), path=path or winsupport.mitmproxy_ca_cert_path())


# --------------------------------------------------------------------------- かんたんモード (DESIGN.md §13.11)

#: Folders of the work directory the easy mode may open in the file manager.
_OPENABLE_FOLDERS = ("workdir", "scripts", "outputs", "recordings", "uploads")


@bp.post("/api/browser/open")
def browser_open() -> Response:
    """Open Edge (or the default browser) at ``{"url": ...}`` (blank = new tab).

    With ``{"browser": "iehost"}`` the in-app recording browser is (re)opened instead: when it is
    still running nothing happens (``relaunched: false``); when the recorder is running it is started
    again against the recorder's proxy (``relaunched: true``); otherwise 409.
    """
    body = _json_body(required=False)
    if str(body.get("browser") or "").strip().lower() == "iehost":
        return _browser_open_iehost(body)
    try:
        result = launch.open_url(body.get("url"), prefer_edge=_bool(body.get("prefer_edge"), True))
    except ValueError as exc:
        raise ApiError(str(exc)) from exc
    except RuntimeError as exc:
        raise ApiError(str(exc), status=500) from exc
    return _ok(**result)


def _browser_open_iehost(body: dict[str, Any]) -> Response:
    state = get_state()
    start_url = _iehost_start_url(body.get("url"))
    with state.lock:
        proc = state.browser
        if proc is not None and proc.poll() is None:
            return _ok(running=True, relaunched=False, browser=_browser_payload(proc))
        if not state.recorder.running:
            raise ApiError("記録が開始されていません", status=409)
        if state.record_browser_kind != "iehost":
            # an Edge / manual recording intercepts HTTPS and has no emulation set up for the
            # recording browser; opening one now would only confuse (and auto-stop) that recording
            raise ApiError("この記録は記録用ブラウザを使わない方式で始められています。記録用ブラウザは開けません。", status=409)
        _require_iehost(state)
        recorder_status = state.recorder.status()
        listen_host = getattr(state.recorder, "listen_host", None) or recorder_status.get("listen_host") or "127.0.0.1"
        port = getattr(state.recorder, "port", None) or recorder_status.get("port")
        if not port:
            raise ApiError("記録用プロキシのポートが分かりません", status=500)
        proxy_address = winsupport.proxy_server_for(str(listen_host), int(port))
        state.close_browser(timeout=2.0)  # an exited process object is dropped before the new one starts
        proc = _launch_iehost(state, proxy_address, start_url, https_recorded=not state.record_https_passthrough)
    return _ok(running=True, relaunched=True, browser=_browser_payload(proc))


@bp.post("/api/folder/open")
def folder_open() -> Response:
    """Show one of the work folders in Explorer / Finder: ``{"folder": "scripts"}``."""
    state = get_state()
    body = _json_body(required=False)
    folder = str(body.get("folder") or "scripts").strip().lower()
    if folder not in _OPENABLE_FOLDERS:
        raise ApiError(f"開けるフォルダは {', '.join(_OPENABLE_FOLDERS)} のいずれかです")
    path = state.workdir if folder == "workdir" else state.subdir(folder)
    try:
        result = launch.open_folder(path)
    except FileNotFoundError as exc:
        raise ApiError(str(exc), status=404) from exc
    except RuntimeError as exc:
        raise ApiError(str(exc), status=500) from exc
    return _ok(**result)


@bp.post("/api/easy/build")
def easy_build() -> Response:
    """One shot for the easy mode: analyse the loaded recording with the current (or given)
    options, generate the script and save it under ``scripts/``.

    Body (all optional): ``{"name": "...", "plan_options": {...}, "gen_options": {...}}``.
    Returns what the easy screen shows: file name / path / download URL, step count, the final
    step's URL, warnings, the secrets the user must type before running, and the code itself.
    """
    state = get_state()
    body = _json_body(required=False)
    plan_opts, gen_opts = _options_from_body(body)
    with state.lock:
        plan = _rebuild_plan(state, plan_opts)
        if not plan.steps:
            raise ApiError(
                "スクリプトにできる通信が記録にありませんでした。記録中にサイトの画面を開いたか、"
                "ブラウザが記録用プロキシを通っているか (証明書の登録を含む) を確認してください。",
                status=400,
            )
        try:
            code = generate(plan, gen_opts)
        except Exception as exc:
            current_app.logger.exception("generate failed")
            raise ApiError(f"コード生成に失敗しました: {exc}", status=500) from exc
        state.gen_options = gen_opts
        state.last_code = code
        secrets = _secrets_of(plan)
        state.last_secrets = secrets
        raw_name = body.get("name")
        if raw_name is None or not str(raw_name).strip():
            raw_name = f"{_suggest_script_name(state, plan)}_{datetime.now().strftime('%Y%m%d_%H%M')}"
        name = _script_name(raw_name)
        path = state.path_in("scripts", name, "スクリプト名")
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(code if code.endswith("\n") else code + "\n")
        except OSError as exc:
            raise ApiError(f"スクリプトを保存できません: {exc}", status=500) from exc
        state.last_script_name = name
        recording = state.require_recording()
        final_index = plan.final_step_index or (plan.steps[-1].index if plan.steps else None)
        final_step = next((s for s in plan.steps if s.index == final_index), None)
        actionable, notes = _split_warnings(list(plan.warnings))
        steps_view = [
            {
                "index": s.index,
                "method": s.method,
                "url": s.literal_url() or "".join(r.value if r.is_literal else "{…}" for r in s.url),
                "loop": s.loop is not None,
                "extracts": len(s.extractors),
            }
            for s in plan.steps
        ]
        payload = {
            "name": name,
            "path": path,
            "download_url": f"/api/scripts/{name}/download",
            "steps": len(plan.steps),
            "steps_view": steps_view,
            "final_step_index": final_index,
            "final_url": final_step.literal_url() if final_step is not None else None,
            "final_method": final_step.method if final_step is not None else None,
            "flows_total": len(recording.flows),
            "warnings": actionable,
            "notes": notes,
            # the same lists with a plain-Japanese ``message`` per entry (what the easy screen shows)
            "warning_details": _warning_details(actionable),
            "note_details": _warning_details(notes),
            "downloads": _downloads_of(recording, plan),
            "secrets": secrets,
            "auth": model.to_plain(plan.auth) if plan.auth is not None else None,
            "summary": format_plan_summary(plan, flows_total=len(recording.flows)),
            "code": code,
            "sources": list(state.sources),
        }
    return _ok(**payload)
