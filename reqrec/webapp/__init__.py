"""Flask based no-code GUI for reqrec.  Contract: DESIGN.md §13.6.

``create_app(workdir)`` builds the Flask application; ``run_gui`` starts it (and opens a browser).

Security model (the user's browser visits arbitrary sites while this GUI runs):

* every ``POST`` / ``PUT`` / ``DELETE`` must carry ``X-Reqrec-Token`` equal to a per-process random
  token the page receives through the template (``<body data-token>``);
* every request's ``Host`` must be the bound address / ``127.0.0.1`` / ``localhost`` / ``::1``
  (DNS-rebinding guard), and a state-changing request with an ``Origin`` header must come from the
  page itself;
* file names from the browser only ever map to files inside ``workdir`` (``state.safe_name``).
"""

from __future__ import annotations

import errno
import hmac
import ipaddress
import os
import socket
import sys
import threading
import time
import webbrowser
from typing import Any, Optional
from urllib.parse import urlsplit

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from .state import ApiError, AppState

__all__ = ["create_app", "run_gui", "TOKEN_HEADER", "ApiError"]

TOKEN_HEADER = "X-Reqrec-Token"

_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_WILDCARD_HOSTS = frozenset({"0.0.0.0", "::", "[::]", "*", ""})
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Uploads (HAR files can be large). 1 GiB by default; override with ``create_app(..., MAX_CONTENT_LENGTH=...)``.
_DEFAULT_MAX_UPLOAD = 1024 * 1024 * 1024

_BROWSER_OPEN_DELAY = 0.8


# --------------------------------------------------------------------------- host / origin checks

def _split_host(value: str) -> str:
    """``[::1]:8765`` -> ``[::1]``, ``LocalHost:80`` -> ``localhost`` (port removed, lower-case)."""
    v = (value or "").strip().lower()
    if not v:
        return ""
    if v.startswith("["):
        end = v.find("]")
        return v[: end + 1] if end != -1 else v
    if v.count(":") == 1:
        v = v.split(":", 1)[0]
    return v


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def host_allowed(host_header: str, bind_host: str) -> bool:
    """Is this ``Host`` header one of ours?  (bound host, loopback names; any IP literal for a
    wildcard bind, because DNS rebinding needs a *name*)."""
    host = _split_host(host_header)
    if not host:
        return False
    if host in _LOCAL_HOSTS:
        return True
    bind = (bind_host or "").strip().lower()
    if bind and bind not in _WILDCARD_HOSTS:
        bind_norm = bind if not (":" in bind and not bind.startswith("[")) else f"[{bind}]"
        if host == bind_norm:
            return True
        if _is_ip_literal(host) and _is_ip_literal(bind_norm) and ipaddress.ip_address(host.strip("[]")) == ipaddress.ip_address(bind_norm.strip("[]")):
            return True
        return False
    return _is_ip_literal(host)


def origin_allowed(origin: Optional[str], host_header: str, scheme: str = "http") -> bool:
    """A browser ``Origin`` is accepted only when it names this very page (scheme + host[:port])."""
    if origin is None:
        return True  # non-browser client; the token still protects the endpoint
    o = origin.strip()
    if not o or o.lower() == "null":
        return False
    parts = urlsplit(o)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return False
    return _normalise_netloc(parts.netloc, parts.scheme) == _normalise_netloc(host_header, scheme)


def _normalise_netloc(netloc: str, scheme: str) -> str:
    n = (netloc or "").strip().lower()
    default = {"http": ":80", "https": ":443"}.get(scheme or "http")
    if default and n.endswith(default):
        n = n[: -len(default)]
    return n


# --------------------------------------------------------------------------- factory

def create_app(workdir: str, **config: Any) -> Flask:
    """Build the Flask app.

    ``config`` may hold ``host`` / ``port`` (what the server binds; used for the Host check and
    for excluding the GUI's own traffic from recordings), ``token`` (per-process CSRF token;
    generated when omitted), ``recorder`` / ``runner`` (test doubles) and any upper-case Flask
    config key (``MAX_CONTENT_LENGTH``, ``TESTING``, ...).
    """
    host = str(config.pop("host", "127.0.0.1") or "127.0.0.1")
    port = int(config.pop("port", 8765) or 8765)
    token = config.pop("token", None)
    recorder = config.pop("recorder", None)
    runner = config.pop("runner", None)

    here = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        "reqrec.webapp",
        template_folder=os.path.join(here, "templates"),
        static_folder=os.path.join(here, "static"),
        static_url_path="/static",
    )
    app.config.update(
        MAX_CONTENT_LENGTH=_DEFAULT_MAX_UPLOAD,
        JSON_SORT_KEYS=False,
        SEND_FILE_MAX_AGE_DEFAULT=0,
        TEMPLATES_AUTO_RELOAD=False,
    )
    for key, value in config.items():
        app.config[key.upper()] = value
    app.json.ensure_ascii = False  # Japanese stays readable in responses / logs
    app.json.sort_keys = False

    state = AppState(workdir, host=host, port=port, token=token, recorder=recorder, runner=runner)
    app.extensions["reqrec"] = state
    app.config.update(REQREC_WORKDIR=state.workdir, REQREC_TOKEN=state.token, REQREC_HOST=host, REQREC_PORT=port)

    from .routes import bp

    app.register_blueprint(bp)

    # ---------------------------------------------------------------- security hook
    @app.before_request
    def _guard():  # type: ignore[no-untyped-def]
        if not host_allowed(request.host, host):
            return jsonify({"error": f"この Host ヘッダーからのアクセスは許可されていません: {request.host}"}), 403
        if request.method in _UNSAFE_METHODS:
            if not origin_allowed(request.headers.get("Origin"), request.host, request.scheme):
                return jsonify({"error": "別のオリジンからのリクエストは拒否しました (CSRF 対策)"}), 403
            sent = request.headers.get(TOKEN_HEADER, "")
            if not sent or not hmac.compare_digest(sent, state.token):
                return jsonify({"error": "認証トークンが一致しません。GUI のページを再読み込みしてください。"}), 403
        return None

    @app.after_request
    def _headers(resp):  # type: ignore[no-untyped-def]
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------------------------------------------------------------- errors -> JSON
    @app.errorhandler(ApiError)
    def _api_error(exc: ApiError):  # type: ignore[no-untyped-def]
        return jsonify(exc.to_dict()), exc.status

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):  # type: ignore[no-untyped-def]
        if request.path.startswith("/api/") or request.method in _UNSAFE_METHODS:
            messages = {
                404: "指定された API はありません",
                405: "この HTTP メソッドは使えません",
                413: "ファイルが大きすぎます (上限を超えました)",
                400: "リクエストが不正です",
            }
            msg = messages.get(exc.code or 0, exc.name)
            return jsonify({"error": msg, "status": exc.code}), exc.code or 500
        return exc

    @app.errorhandler(Exception)
    def _unexpected(exc: Exception):  # type: ignore[no-untyped-def]
        if app.testing or app.debug:
            raise exc
        app.logger.exception("unhandled error")
        return jsonify({"error": f"内部エラーが発生しました: {exc.__class__.__name__}: {exc}"}), 500

    return app


# --------------------------------------------------------------------------- running

def _display_host(host: str) -> str:
    return "127.0.0.1" if host in _WILDCARD_HOSTS else host


def _port_free(host: str, port: int) -> Optional[str]:
    """None when ``host:port`` can be bound, else a Japanese explanation."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            if os.name != "nt":
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", 10048)):
            return f"ポート {port} は既に使われています。別のポートを --port で指定するか、起動中の reqrec gui を終了してください。"
        if exc.errno in (errno.EACCES, getattr(errno, "WSAEACCES", 10013)):
            return f"ポート {port} を開く権限がありません。--port で 1024 以上のポートを指定してください。"
        if exc.errno == errno.EADDRNOTAVAIL:
            return f"アドレス {host} はこの PC に存在しません。--host を確認してください。"
        return f"{host}:{port} で待ち受けできません: {exc}"
    return None


def _open_browser_later(url: str, host: str, port: int, delay: float = _BROWSER_OPEN_DELAY) -> threading.Thread:
    """Open the browser once the server answers (so a failed start never pops an error page)."""

    def _worker() -> None:
        deadline = time.time() + 10.0
        time.sleep(delay)
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            return
        try:
            webbrowser.open(url)
        except Exception:
            pass

    t = threading.Thread(target=_worker, name="reqrec-open-browser", daemon=True)
    t.start()
    return t


def run_gui(host: str = "127.0.0.1", port: int = 8765, workdir: str = "reqrec_work", open_browser: bool = True) -> int:
    """Start the GUI server (blocking) and return a process exit code (``0`` after Ctrl+C)."""
    port = int(port)
    try:
        app = create_app(workdir, host=host, port=port)
    except (RuntimeError, OSError) as exc:
        print(f"GUI を起動できません: {exc}", file=sys.stderr)
        return 1
    url = f"http://{_display_host(host)}:{port}"
    problem = _port_free(host, port)
    if problem:
        print(f"GUI を起動できません: {problem}", file=sys.stderr)
        return 1
    print(f"GUI を起動しました: {url}  (Ctrl+C で終了)", flush=True)
    print(f"作業フォルダ: {app.extensions['reqrec'].workdir}", flush=True)
    if open_browser:
        _open_browser_later(url, _display_host(host), port)
    state: AppState = app.extensions["reqrec"]
    try:
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        print("\nGUI を終了します", flush=True)
        return 0
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", 10048)):
            print(f"GUI を起動できません: ポート {port} は既に使われています。--port で別のポートを指定してください。", file=sys.stderr)
        else:
            print(f"GUI を起動できません: {exc}", file=sys.stderr)
        return 1
    finally:
        _shutdown(state)
    return 0


def _shutdown(state: AppState) -> None:
    """Stop children and put the Windows proxy back (also registered via atexit)."""
    try:
        state.close()
    except Exception:
        pass
    if state.proxy_backup is not None:
        try:
            from .. import winsupport

            winsupport.restore_system_proxy(state.proxy_backup)
            state.proxy_backup = None
            print("システムプロキシの設定を元に戻しました", flush=True)
        except Exception as exc:  # pragma: no cover - Windows only
            print(f"システムプロキシを元に戻せませんでした: {exc}", file=sys.stderr)
