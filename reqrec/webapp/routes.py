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

from .. import __version__, model, util, winsupport
from ..cli import build_inspect_report, format_plan_summary
from ..codegen import generate
from ..plan import build_plan
from ..recorder.manager import RecorderError
from ..recorder.run import format_instructions, mitmproxy_available
from .state import (
    RECORDING_EXTENSIONS,
    ApiError,
    AppState,
    exclude_netlocs,
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
        label = "NTLM" if str(auth.kind).lower() == "ntlm" else "Negotiate"
        who = f"記録時のユーザー: {auth.username}" if auth.username else "記録からユーザー名は特定できませんでした"
        if "REQREC_NTLM_USER" not in seen:
            seen.add("REQREC_NTLM_USER")
            out.append({
                "name": f"{label} 認証のユーザー名 (DOMAIN\\user)", "env_var": "REQREC_NTLM_USER", "secret": False,
                "default": auth.username or "",
                "comment": f"{who}。Windows で今ログインしているユーザーのまま認証する場合 (reqrec[sspi]) は空欄のまま",
            })
        if "REQREC_NTLM_PASSWORD" not in seen:
            seen.add("REQREC_NTLM_PASSWORD")
            out.append({
                "name": f"{label} 認証のパスワード", "env_var": "REQREC_NTLM_PASSWORD", "secret": True,
                "comment": "Windows 以外 / 別のユーザーで実行する場合 (reqrec[ntlm]) に必要。sspi で認証する場合は空欄のまま",
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

    if state.recorder.running:
        raise ApiError("すでに記録中です。先に [記録停止] を押してください。", status=409)
    if state.recorder.command_builder is _default_command_builder() and not mitmproxy_available():
        raise ApiError(
            "mitmproxy がインストールされていないため記録できません。コマンドプロンプトで "
            'pip install "reqrec[record]" を実行してから GUI を再起動してください。', status=400,
        )
    if set_proxy:
        _windows_only()
    if port == state.port and listen_host in ("127.0.0.1", "localhost", state.host, "0.0.0.0", "::"):
        raise ApiError(f"ポート {port} はこの GUI が使用中です。別のポート (例: 8080) を指定してください。")

    out = os.path.join(state.subdir("recordings"), _timestamp_name("rec", ".json"))
    with state.lock:
        try:
            status = state.recorder.start(out, port=port, hosts=hosts, listen_host=listen_host)
        except RecorderError as exc:
            raise ApiError(str(exc), status=400) from exc
        state.record_append = append
        proxy_address = winsupport.proxy_server_for(listen_host, port)
        proxy_result: Optional[dict[str, Any]] = None
        if set_proxy:
            try:
                backup = winsupport.set_system_proxy(proxy_address, enable=True, override=_PROXY_OVERRIDE)
            except Exception as exc:
                state.recorder.stop()
                raise ApiError(f"システムプロキシを設定できませんでした: {exc}", status=500) from exc
            if state.proxy_backup is None:  # keep the oldest backup when restarted without restore
                state.proxy_backup = backup
            state.proxy_server = proxy_address
            state.register_proxy_restore(winsupport.restore_system_proxy)
            proxy_result = {"set": True, "server": proxy_address, "backup": backup}
    time.sleep(0.15)  # give an immediately failing child (port in use) the chance to report
    status = state.recorder.status()
    return _ok(
        instructions=format_instructions(out, port, hosts, listen_host),
        out=os.path.basename(out),
        out_path=out,
        proxy_address=proxy_address,
        system_proxy=proxy_result,
        status=status,
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
    with state.lock:
        was_running = state.recorder.running
        if not was_running and state.recorder.out is None:
            raise ApiError("記録は開始されていません", status=409)
        exit_code = state.recorder.stop()
        proxy_error = _restore_proxy(state)
        try:
            recording = state.recorder.load_recording()
        except RecorderError as exc:
            raise ApiError(str(exc), status=400, exit_code=exit_code, proxy_error=proxy_error,
                           stderr_tail=state.recorder.status()["stderr_tail"]) from exc
        if not recording.flows:
            raise ApiError(
                "記録にフローが 1 件もありません。ブラウザのプロキシ設定と CA 証明書を確認し、記録中にページを開いてください。",
                status=400, exit_code=exit_code, proxy_error=proxy_error, out=os.path.basename(state.recorder.out or ""),
            )
        summary = _apply_loaded(state, recording, [f"recordings/{os.path.basename(state.recorder.out or '')}"], append, from_gui_recorder=True)
    summary.update(out=os.path.basename(state.recorder.out or ""), out_path=state.recorder.out, exit_code=exit_code, proxy_error=proxy_error)
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
    slug = util.safe_identifier(host.replace(".", "_"), default="site") if host else "site"
    return f"scrape_{slug}"[:60]


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
    status = state.runner.start(path, env={k: v for k, v in env.items()}, cwd=state.subdir("scripts"))
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
