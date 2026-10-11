"""argparse CLI.  Contract: DESIGN.md §9.

Sub-commands::

    reqrec record   -o rec.json [-p 8080] [--listen-host 127.0.0.1] [--hosts a.com,b.com]
    reqrec import   INPUT... -o rec.json
    reqrec inspect  INPUT... [filter options] [override options] [--json]
    reqrec generate INPUT... -o scrape.py [filter options] [override options] [codegen options]
                    [--legacy-tls] [--dump-plan plan.json] [--run]
    reqrec gui      [--host 127.0.0.1] [--port 8765] [--workdir DIR] [--no-browser]

Several ``INPUT`` files (one HAR per browser tab, say) are merged by time stamp (DESIGN.md §13.5).
Override options (§13.1): ``--exclude-flow`` / ``--include-flow`` / ``--final-flow`` take the flow
ids ``inspect`` shows (``f0008``, comma separated / repeatable); ``--exclude-step N`` /
``--final-step N`` take step numbers of the plan built *without* overrides and are resolved to flow
ids by building the plan once more.

All user-facing messages are Japanese (the end user is Japanese); identifiers and comments are
English.  Exit codes: ``0`` success, ``1`` runtime error (missing / unsupported input file, ...),
``2`` usage error.

This module only parses arguments, maps them onto ``PlanOptions`` / ``GenOptions`` and formats
results.  The pipeline functions are bound to module-level names (``load_recording``,
``load_recordings``, ``build_plan``, ``generate``, ``run_record``) so tests can monkeypatch them.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import unicodedata
from dataclasses import replace
from typing import Any, Iterable, Optional, Sequence

from . import __version__, model, util
from .codegen import generate
from .importers import load_recording
from .model import GenOptions, Plan, PlanOptions, Recording, Step
from .plan import build_plan
from .recorder.run import run_record

try:
    from .importers import load_recordings  # DESIGN.md §13.5: several files -> one merged Recording
except ImportError:  # pragma: no cover - until the importer owner's work is integrated
    def load_recordings(paths: Iterable[str]) -> Recording:  # type: ignore[misc]
        """Fallback: load every file and merge them (``importers.load_recordings`` missing)."""
        recordings = [load_recording(p) for p in paths]
        if not recordings:
            raise ValueError("入力ファイルが指定されていません")
        return recordings[0] if len(recordings) == 1 else Recording.merge(recordings)

__all__ = [
    "EXIT_OK", "EXIT_ERROR", "EXIT_USAGE",
    "main", "build_parser", "add_filter_options", "add_generate_options",
    "plan_options_from_args", "gen_options_from_args", "split_hosts", "split_flow_ids", "normalise_flow_id",
    "load_inputs", "resolve_overrides",
    "build_inspect_report", "format_inspect_report", "format_plan_summary", "run_script",
]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

#: Defaults are read from the dataclasses so the CLI never drifts from ``model.py``.
_PLAN_DEFAULTS = PlanOptions()
_GEN_DEFAULTS = GenOptions()

HTML_PARSERS = ("html.parser", "lxml")

#: How many example URLs ``inspect`` shows per drop reason.
INSPECT_EXAMPLES_PER_REASON = 5
#: Column truncation widths for the ``inspect`` table.
INSPECT_URL_WIDTH = 72
INSPECT_EXTRACT_WIDTH = 60


# --------------------------------------------------------------------------- output helpers

def _info(message: str) -> None:
    """Informational message (never part of machine-readable output) -> stderr."""
    print(message, file=sys.stderr, flush=True)


def _error(message: str) -> None:
    print(f"エラー: {message}", file=sys.stderr, flush=True)


def _display_width(text: str) -> int:
    """Terminal column width of ``text`` (CJK characters take two columns)."""
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _display_width(text))


def _format_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    """Plain-text table (two-space column gap, CJK-aware padding)."""
    columns = len(headers)
    widths = [_display_width(h) for h in headers]
    for row in rows:
        for i in range(columns):
            widths[i] = max(widths[i], _display_width(row[i]))
    lines = ["  ".join(_pad(h, widths[i]) for i, h in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(_pad(row[i], widths[i]) for i in range(columns)).rstrip())
    return lines


# --------------------------------------------------------------------------- argparse plumbing (Japanese)

_ARGPARSE_TRANSLATIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^the following arguments are required: (.*)$"), "次の引数が必要です: {0}"),
    (re.compile(r"^unrecognized arguments: (.*)$"), "不明な引数です: {0}"),
    (re.compile(r"^argument (.+?): invalid choice: (.*) \(choose from (.*)\)$"),
     "引数 {0}: 無効な選択です: {1}（選択肢: {2}）"),
    (re.compile(r"^argument (.+?): invalid (\S+) value: (.*)$"), "引数 {0}: {1} として解釈できない値です: {2}"),
    (re.compile(r"^argument (.+?): expected one argument$"), "引数 {0}: 値が 1 つ必要です"),
    (re.compile(r"^argument (.+?): expected at least one argument$"), "引数 {0}: 値が 1 つ以上必要です"),
    (re.compile(r"^argument (.+?): expected (\d+) arguments?$"), "引数 {0}: 値が {1} 個必要です"),
    (re.compile(r"^argument (.+?): not allowed with argument (.*)$"), "引数 {0}: {1} と同時には指定できません"),
    (re.compile(r"^argument (.+?): ignored explicit argument (.*)$"), "引数 {0}: 余分な値が指定されました: {1}"),
    (re.compile(r"^ambiguous option: (.*)$"), "オプションが曖昧です: {0}"),
    # ``argparse.ArgumentTypeError`` raised by our own converters: the text is already Japanese.
    (re.compile(r"^argument (.+?): (.*)$"), "引数 {0}: {1}"),
]


def translate_argparse_message(message: str) -> str:
    """Translate argparse's English error text to Japanese where we know the phrase."""
    for pattern, template in _ARGPARSE_TRANSLATIONS:
        m = pattern.match(message)
        if m:
            return template.format(*m.groups())
    return message


class _JapaneseHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """``usage:`` -> ``使い方:``; keeps description/epilog line breaks."""

    def add_usage(self, usage, actions, groups, prefix=None):  # type: ignore[override]
        if prefix is None:
            prefix = "使い方: "
        return super().add_usage(usage, actions, groups, prefix)


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser whose generated text (group titles, usage, errors) is Japanese.

    ``error`` still exits with ``SystemExit(2)`` like argparse does; ``main`` converts that into a
    return code so the function can be used from tests without catching ``SystemExit``.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", _JapaneseHelpFormatter)
        kwargs.setdefault("allow_abbrev", False)
        add_help = kwargs.pop("add_help", True)
        kwargs["add_help"] = False  # we add our own -h with Japanese help text
        super().__init__(*args, **kwargs)
        # Group titles are not reachable through the public API.
        self._positionals.title = "引数"
        self._optionals.title = "オプション"
        if add_help:
            self.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="このヘルプを表示して終了する")

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: エラー: {translate_argparse_message(message)}\n")


# --------------------------------------------------------------------------- value converters

def _int_value(text: str) -> int:
    try:
        return int(text, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"整数を指定してください: {text!r}") from None


def _float_value(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"数値を指定してください: {text!r}") from None
    if value != value or value in (float("inf"), float("-inf")):
        raise argparse.ArgumentTypeError(f"有限の数値を指定してください: {text!r}")
    return value


def _port(text: str) -> int:
    n = _int_value(text)
    if not 1 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"ポート番号は 1〜65535 の範囲で指定してください: {n}")
    return n


def _positive_int(text: str) -> int:
    n = _int_value(text)
    if n < 1:
        raise argparse.ArgumentTypeError(f"1 以上の整数を指定してください: {n}")
    return n


def _non_negative_float(text: str) -> float:
    value = _float_value(text)
    if value < 0:
        raise argparse.ArgumentTypeError(f"0 以上の数値を指定してください: {text}")
    return value


def _positive_float(text: str) -> float:
    value = _float_value(text)
    if value <= 0:
        raise argparse.ArgumentTypeError(f"0 より大きい数値を指定してください: {text}")
    return value


_FLOW_ID_RE = re.compile(r"^f?(\d+)$", re.I)
_FLOW_TOKEN_RE = re.compile(r"^[\w.\-]+$")


def normalise_flow_id(text: Optional[str]) -> Optional[str]:
    """``"f0008"`` / ``"F8"`` / ``"8"`` -> ``"f0008"``.  Other non-empty tokens are returned as typed
    (they are checked against the recording later); an empty token gives ``None``."""
    token = str(text or "").strip()
    if not token:
        return None
    m = _FLOW_ID_RE.match(token)
    if m:
        return f"f{int(m.group(1)):04d}"
    return token


def split_flow_ids(values: Optional[Iterable[str]]) -> list[str]:
    """Repeated ``--exclude-flow`` values (each may be comma / semicolon / space separated) ->
    normalised, de-duplicated flow ids in order."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values or ():
        for item in re.split(r"[,;\s]+", str(value)):
            fid = normalise_flow_id(item)
            if fid and fid not in seen:
                seen.add(fid)
                out.append(fid)
    return out


def _flow_id_list(text: str) -> str:
    """argparse type for repeatable flow-id options: validates every token, returns the raw text
    (``split_flow_ids`` flattens the repeated values later)."""
    ids = split_flow_ids([text])
    if not ids:
        raise argparse.ArgumentTypeError(f"フロー ID を指定してください（例: f0008）: {text!r}")
    for fid in ids:
        if not _FLOW_TOKEN_RE.match(fid):
            raise argparse.ArgumentTypeError(f"フロー ID として解釈できません: {fid!r}（例: f0008。inspect で確認できます）")
    return text


def _flow_id(text: str) -> str:
    ids = split_flow_ids([text])
    if len(ids) != 1 or not _FLOW_TOKEN_RE.match(ids[0]):
        raise argparse.ArgumentTypeError(f"フロー ID を 1 つ指定してください（例: f0008）: {text!r}")
    return ids[0]


def _step_numbers(text: str) -> list[int]:
    """argparse type for ``--exclude-step``: ``"2,3"`` -> ``[2, 3]`` (positive integers)."""
    out: list[int] = []
    for item in re.split(r"[,;\s]+", str(text)):
        if item:
            out.append(_positive_int(item))
    if not out:
        raise argparse.ArgumentTypeError(f"ステップ番号を指定してください（例: 3）: {text!r}")
    return out


def split_hosts(values: Optional[Iterable[str]]) -> list[str]:
    """``["a.com, B.com", "c.com"]`` -> ``["a.com", "b.com", "c.com"]`` (lower-case, de-duplicated).

    Accepts the repeated ``--include-host`` values; each may itself be a comma / semicolon /
    whitespace separated list.  ``None`` / empty -> ``[]``.
    """
    out: list[str] = []
    seen: set[str] = set()
    for value in values or ():
        for item in re.split(r"[,;\s]+", str(value)):
            host = item.strip().lower().rstrip(".")
            if host and host not in seen:
                seen.add(host)
                out.append(host)
    return out


# --------------------------------------------------------------------------- option groups -> dataclasses


def add_filter_options(parser: argparse.ArgumentParser) -> None:
    """Add the filter / analysis options shared by ``inspect`` and ``generate``."""
    group = parser.add_argument_group(
        "フィルタ / 解析オプション",
        "記録のどのリクエストをステップとして残すか、どう解析するかを調整します。",
    )
    group.add_argument(
        "--include-host", action="append", metavar="HOST", default=None,
        help="このホスト（とそのサブドメイン）へのリクエストだけを残す。繰り返し指定・カンマ区切り可",
    )
    group.add_argument(
        "--exclude-host", action="append", metavar="HOST", default=None,
        help="このホスト（とそのサブドメイン）へのリクエストを除外する。繰り返し指定・カンマ区切り可",
    )
    group.add_argument("--keep-static", action="store_true", help="画像・CSS・JS・フォントなどの静的ファイルも残す")
    group.add_argument("--keep-trackers", action="store_true", help="アクセス解析・広告などのトラッカーへのリクエストも残す")
    group.add_argument("--keep-all", action="store_true", help="ノイズ除去をすべて無効にする（ホストの指定だけ適用）")
    group.add_argument("--no-collapse-redirects", action="store_true", help="リダイレクトの連鎖を 1 ステップにまとめない")
    group.add_argument("--no-loops", action="store_true", help="ページ送りなどの繰り返しをループとして折りたたまない")
    group.add_argument(
        "--min-value-length", type=_positive_int, metavar="N", default=_PLAN_DEFAULTS.min_value_length,
        help=f"依存関係の検出対象にする値の最小文字数（既定: {_PLAN_DEFAULTS.min_value_length}）",
    )
    group.add_argument(
        "--max-steps", type=_positive_int, metavar="N", default=None,
        help="ステップ数の上限（巨大な記録の安全弁。超えた分は警告付きで切り捨て）",
    )
    group.add_argument(
        "--no-redact", action="store_true",
        help="パスワード等を環境変数に置き換えず、記録した値をそのままコードに埋め込む（取り扱い注意）",
    )
    group.add_argument(
        "--no-detect-auth", action="store_true",
        help="NTLM / Negotiate / Basic / Digest 認証のやり取り（401 → Authorization）を検出して session.auth にまとめる処理を行わない",
    )

    manual = parser.add_argument_group(
        "手動の取捨選択",
        "inspect が表示するフロー ID（f0008 など。カンマ区切り・繰り返し指定可）やステップ番号で、"
        "除外する / 必ず残す / 結果にするリクエストを指定します。",
    )
    manual.add_argument(
        "--exclude-flow", action="append", metavar="ID", default=None, type=_flow_id_list,
        help="このフローを必ず除外する（除外理由: excluded by user）",
    )
    manual.add_argument(
        "--include-flow", action="append", metavar="ID", default=None, type=_flow_id_list,
        help="ノイズ判定に関わらずこのフローをステップとして残す（レスポンスが記録されていないものは残せない）",
    )
    manual.add_argument(
        "--final-flow", metavar="ID", default=None, type=_flow_id,
        help="このフローを含むステップの結果を、生成コードの main() が最後に表示する（既定: 最後のステップ）",
    )
    manual.add_argument(
        "--exclude-step", action="append", metavar="N", default=None, type=_step_numbers,
        help="inspect（オーバーライド指定なし）で表示されたステップ番号 N のリクエストを除外する。カンマ区切り・繰り返し指定可",
    )
    manual.add_argument(
        "--final-step", metavar="N", default=None, type=_positive_int,
        help="inspect（オーバーライド指定なし）で表示されたステップ番号 N の結果を表示する（--final-flow のステップ番号版）",
    )


def plan_options_from_args(args: argparse.Namespace) -> PlanOptions:
    """Map the parsed filter options onto a ``PlanOptions`` (missing attributes -> defaults).

    ``--exclude-step`` / ``--final-step`` are *not* mapped here (they need the recording); see
    :func:`resolve_overrides`.
    """
    include = split_hosts(getattr(args, "include_host", None))
    final_flow = getattr(args, "final_flow", None)
    return PlanOptions(
        include_hosts=include or None,
        exclude_hosts=split_hosts(getattr(args, "exclude_host", None)),
        keep_static=bool(getattr(args, "keep_static", False)),
        keep_trackers=bool(getattr(args, "keep_trackers", False)),
        keep_all=bool(getattr(args, "keep_all", False)),
        collapse_redirects=not getattr(args, "no_collapse_redirects", False),
        detect_loops=not getattr(args, "no_loops", False),
        redact_secrets=not getattr(args, "no_redact", False),
        min_value_length=getattr(args, "min_value_length", None) or _PLAN_DEFAULTS.min_value_length,
        max_steps=getattr(args, "max_steps", None),
        exclude_flow_ids=split_flow_ids(getattr(args, "exclude_flow", None)),
        include_flow_ids=split_flow_ids(getattr(args, "include_flow", None)),
        final_flow_id=normalise_flow_id(final_flow) if final_flow else None,
        detect_auth=not getattr(args, "no_detect_auth", False),
    )


def _flatten_steps(values: Any) -> list[int]:
    """``--exclude-step`` values (``[[2, 3], [5]]`` or ``[2]``) -> sorted unique step numbers."""
    out: set[int] = set()
    for value in values or ():
        if isinstance(value, (list, tuple)):
            out.update(int(v) for v in value)
        elif value is not None:
            out.add(int(value))
    return sorted(out)


def resolve_overrides(recording: Recording, opts: PlanOptions, exclude_steps: Any = None,
                      final_step: Optional[int] = None) -> PlanOptions:
    """Check the flow-id overrides against the recording and turn step numbers into flow ids.

    Step numbers refer to the plan built **without** overrides (what a plain ``inspect`` shows),
    so when any is given the plan is built once more here and the step's ``source_flow_ids`` are
    used.  Raises ``ValueError`` (Japanese) for unknown ids, out-of-range steps and contradictions.
    """
    known = {flow.id for flow in recording.flows}

    def check(ids: Iterable[str], flag: str) -> None:
        for fid in ids:
            if fid not in known:
                raise ValueError(f"{flag} {fid}: 記録にそのフロー ID はありません（inspect でフロー ID を確認してください）")

    check(opts.exclude_flow_ids, "--exclude-flow")
    check(opts.include_flow_ids, "--include-flow")
    if opts.final_flow_id:
        check([opts.final_flow_id], "--final-flow")

    exclude_ids = list(opts.exclude_flow_ids)
    final_id = opts.final_flow_id or None
    steps = _flatten_steps(exclude_steps)
    if steps or final_step is not None:
        base = replace(opts, exclude_flow_ids=[], include_flow_ids=[], final_flow_id=None)
        base_plan: Plan = build_plan(recording, base)
        by_index = {step.index: step for step in base_plan.steps}

        def lookup(n: int, flag: str) -> Step:
            step = by_index.get(n)
            if step is None:
                if not by_index:
                    raise ValueError(f"{flag} {n}: ステップが 1 つもありません（inspect でフィルタ設定を確認してください）")
                raise ValueError(
                    f"{flag} {n}: ステップ番号は {min(by_index)}〜{max(by_index)} の範囲で指定してください（inspect で確認できます）"
                )
            return step

        for n in steps:
            for fid in lookup(n, "--exclude-step").source_flow_ids:
                if fid not in exclude_ids:
                    exclude_ids.append(fid)
        if final_step is not None:
            step = lookup(final_step, "--final-step")
            if not step.source_flow_ids:
                raise ValueError(f"--final-step {final_step}: このステップにはフロー ID がありません")
            if final_id and final_id not in step.source_flow_ids:
                raise ValueError("--final-step と --final-flow が別のステップを指しています。どちらか一方だけ指定してください")
            final_id = step.source_flow_ids[-1]

    overlap = sorted(set(exclude_ids) & set(opts.include_flow_ids))
    if overlap:
        raise ValueError(f"同じフローを --include-flow と --exclude-flow の両方に指定しています: {', '.join(overlap)}")
    if final_id and final_id in exclude_ids:
        raise ValueError(f"結果にするフロー {final_id} が除外の対象になっています（--exclude-flow / --exclude-step を確認してください）")
    return replace(opts, exclude_flow_ids=exclude_ids, final_flow_id=final_id)


def add_generate_options(parser: argparse.ArgumentParser) -> None:
    """Add the code-generation options of ``generate``."""
    group = parser.add_argument_group("コード生成オプション")
    group.add_argument(
        "--html-parser", choices=HTML_PARSERS, default=_GEN_DEFAULTS.html_parser, metavar="PARSER",
        help=f"生成コードが BeautifulSoup に渡すパーサー: {' / '.join(HTML_PARSERS)}（既定: {_GEN_DEFAULTS.html_parser}）",
    )
    group.add_argument("--no-comments", action="store_true", help="生成コードに説明コメントを入れない")
    group.add_argument(
        "--delay", type=_non_negative_float, metavar="SEC", default=_GEN_DEFAULTS.delay,
        help=f"ステップ間の待ち時間（秒）。サーバーへの負荷を抑えるため（既定: {_GEN_DEFAULTS.delay:g}）",
    )
    group.add_argument(
        "--timeout", type=_positive_float, metavar="SEC", default=_GEN_DEFAULTS.timeout,
        help=f"各リクエストのタイムアウト（秒）（既定: {_GEN_DEFAULTS.timeout:g}）",
    )
    group.add_argument(
        "--strict-status", action="store_true",
        help="記録時と同じステータスコードでなければエラーにする（既定は 4xx/5xx のみエラー）",
    )
    group.add_argument(
        "--legacy-tls", action="store_true",
        help="古い TLS（1.0/1.1）や弱い暗号しか使えないサーバー（IE モードで使っている社内サーバーなど）向けの"
             "接続設定を生成コードに入れる",
    )


def gen_options_from_args(args: argparse.Namespace) -> GenOptions:
    """Map the parsed code-generation options onto a ``GenOptions``."""
    return GenOptions(
        html_parser=getattr(args, "html_parser", None) or _GEN_DEFAULTS.html_parser,
        comments=not getattr(args, "no_comments", False),
        delay=getattr(args, "delay", _GEN_DEFAULTS.delay),
        timeout=getattr(args, "timeout", _GEN_DEFAULTS.timeout),
        print_final=_GEN_DEFAULTS.print_final,
        strict_status=bool(getattr(args, "strict_status", False)),
        legacy_tls=bool(getattr(args, "legacy_tls", False)),
    )


# --------------------------------------------------------------------------- parser

_DESCRIPTION = """\
reqrec - Web サイトの HTTP 通信を記録して、同じ操作を再現する Python スクレイピングスクリプトを生成します。
画面の要素をつかむのではなく、ブラウザが実際に送受信した HTTP リクエスト/レスポンスを元に
「HTTP レベルのマクロ記録」を行います。"""

_EPILOG = """\
典型的な流れ:
  1. 記録する   reqrec record -o rec.json            （または DevTools で HAR を保存）
  2. 確認する   reqrec inspect rec.json
  3. 生成する   reqrec generate rec.json -o scrape.py
  4. 実行する   REQREC_PASSWORD=... python scrape.py

別タブで開いた画面の HAR は複数指定して結合できます:  reqrec generate tab1.har tab2.har -o scrape.py
手動で取捨選択:  reqrec generate rec.json -o scrape.py --exclude-flow f0012 --final-step 3
コードを書かずに使う GUI:  reqrec gui

各コマンドの詳細: reqrec <コマンド> -h"""


_INPUT_HELP = ("入力ファイル（.har / .mitm / .flows / .json）。複数指定すると時刻順に結合して 1 つの記録として扱います"
               "（別タブで開いた画面の HAR など）")


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level parser with its sub-commands (record / import / inspect / generate / gui)."""
    parser = _ArgumentParser(prog="reqrec", description=_DESCRIPTION, epilog=_EPILOG)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}", help="バージョンを表示して終了する")

    subparsers = parser.add_subparsers(dest="command", title="コマンド")

    # -- record -----------------------------------------------------------------------------------
    p_record = subparsers.add_parser(
        "record",
        help="mitmproxy ベースのプロキシを起動してブラウザ（やアプリ）の通信を記録する",
        description="mitmproxy ベースの記録用プロキシを起動します。ブラウザのプロキシ設定を指定のアドレスに向け、\n"
                    "操作が終わったら Ctrl+C で停止すると記録ファイル（JSON）が保存されます。\n"
                    'mitmproxy が必要です: pip install "reqrec[record]"',
    )
    p_record.add_argument("-o", "--out", required=True, metavar="FILE", help="記録の保存先（JSON）")
    p_record.add_argument("-p", "--port", type=_port, default=8080, metavar="PORT", help="プロキシの待ち受けポート（既定: 8080）")
    p_record.add_argument("--listen-host", default="127.0.0.1", metavar="HOST",
                          help="プロキシの待ち受けアドレス（既定: 127.0.0.1。スマホから使うなら 0.0.0.0）")
    p_record.add_argument("--hosts", action="append", metavar="HOST", default=None,
                          help="記録対象をこのホスト（とそのサブドメイン）に限定する。繰り返し指定・カンマ区切り可")
    p_record.add_argument("-v", "--verbose", action="store_true", help="mitmdump 自体の出力も表示する")
    p_record.add_argument("--mitm-arg", action="append", metavar="ARG", default=None,
                          help="mitmdump にそのまま渡す追加引数（例: --mitm-arg=--ssl-insecure）。繰り返し指定可")
    p_record.set_defaults(func=cmd_record)

    # -- import -----------------------------------------------------------------------------------
    p_import = subparsers.add_parser(
        "import",
        help="HAR / mitmproxy フローファイルを reqrec の記録形式（JSON）に変換する",
        description="DevTools の HAR（.har）、mitmproxy のフローファイル（.mitm / .flows）、または reqrec の記録（.json）を\n"
                    "読み込み、reqrec の記録形式（JSON）で保存します。inspect / generate は HAR を直接読めるので、\n"
                    "変換は必須ではありません（記録を 1 つの形式でまとめて保管したい場合などに使います）。",
    )
    p_import.add_argument("input", metavar="INPUT", nargs="+", help=_INPUT_HELP)
    p_import.add_argument("-o", "--out", required=True, metavar="FILE", help="保存先（JSON）")
    p_import.set_defaults(func=cmd_import)

    # -- inspect ----------------------------------------------------------------------------------
    p_inspect = subparsers.add_parser(
        "inspect",
        help="記録を解析し、どのリクエストがステップとして残り、どれが捨てられたかを表示する",
        description="記録を解析して、生成されるステップの一覧（メソッド・ステータス・URL・抽出される変数・ループ）と、\n"
                    "ノイズとして捨てられたリクエストを理由ごとに表示します。generate の前に必ず確認してください。",
    )
    p_inspect.add_argument("input", metavar="INPUT", nargs="+", help=_INPUT_HELP)
    add_filter_options(p_inspect)
    p_inspect.add_argument("--json", action="store_true", help="人が読む表の代わりに JSON で出力する")
    p_inspect.set_defaults(func=cmd_inspect)

    # -- generate ---------------------------------------------------------------------------------
    p_generate = subparsers.add_parser(
        "generate",
        help="記録から Python スクレイピングスクリプト（requests + BeautifulSoup）を生成する",
        description="記録を解析し、同じ HTTP の会話を再現する単体で動く Python スクリプトを生成します。\n"
                    "解析結果の要約と警告は標準エラー出力に、スクリプトは -o で指定したファイル（- で標準出力）に書きます。",
    )
    p_generate.add_argument("input", metavar="INPUT", nargs="+", help=_INPUT_HELP)
    p_generate.add_argument("-o", "--out", required=True, metavar="FILE", help="生成するスクリプトのパス（- で標準出力）")
    add_filter_options(p_generate)
    add_generate_options(p_generate)
    p_generate.add_argument("--dump-plan", metavar="FILE", default=None,
                            help="解析結果（Plan）を JSON で書き出す（デバッグ・検証用）")
    p_generate.add_argument("--run", action="store_true",
                            help="生成したスクリプトをすぐに実行する（同じ Python で実行し、その終了コードを返す）")
    p_generate.set_defaults(func=cmd_generate)

    # -- gui --------------------------------------------------------------------------------------
    p_gui = subparsers.add_parser(
        "gui",
        help="ブラウザで操作する GUI（Flask）を起動する。記録・読み込み・ステップ選択・コード生成・実行をボタンで行える",
        description="ローカルの Web GUI（Flask）を起動し、既定ではブラウザを自動で開きます。\n"
                    "記録の開始/停止、HAR 等の読み込み（複数可）、ステップの取捨選択、コード生成、生成コードの実行を\n"
                    "コードを書かずに行えます。",
    )
    p_gui.add_argument("--host", default="127.0.0.1", metavar="HOST", help="待ち受けアドレス（既定: 127.0.0.1。他の端末からは使わせない）")
    p_gui.add_argument("--port", type=_port, default=8765, metavar="PORT", help="待ち受けポート（既定: 8765）")
    p_gui.add_argument("--workdir", default="reqrec_work", metavar="DIR",
                       help="記録ファイルや生成スクリプトを保存する作業フォルダ（既定: ./reqrec_work）")
    p_gui.add_argument("--no-browser", action="store_true", help="ブラウザを自動で開かない")
    p_gui.set_defaults(func=cmd_gui)

    return parser


# --------------------------------------------------------------------------- shared file helpers

def _check_output_path(path: str, what: str) -> None:
    """Fail early (``ValueError``) when an output path can not be written to."""
    if os.path.isdir(path):
        raise ValueError(f"{what}にディレクトリは指定できません: {path}")
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        raise ValueError(f"{what}のディレクトリがありません: {parent}")


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _describe_source(meta: dict[str, Any]) -> str:
    """``"har, WebInspector/537.36"`` style one-liner from ``Recording.meta`` (may be empty).

    A merged recording (``{"source": "merged", "sources": [...]}``) lists every part.
    """
    if not isinstance(meta, dict):
        return ""
    parts = []
    source = meta.get("source")
    if isinstance(source, dict):  # Plan.meta["source"] holds the recording meta
        return _describe_source(source)
    if source == "merged" and isinstance(meta.get("sources"), list):
        inner = [_describe_source(m) for m in meta["sources"] if isinstance(m, dict)]
        inner = [d for d in inner if d]
        label = f"結合 {len(meta['sources'])} 件"
        return label + (f": {' / '.join(inner)}" if inner else "")
    if source:
        parts.append(str(source))
    creator = meta.get("creator")
    if creator:
        parts.append(str(creator))
    return ", ".join(parts)


def load_inputs(paths: Sequence[str]) -> Recording:
    """Load the ``INPUT`` arguments: one file -> ``load_recording`` (unchanged meta), several ->
    ``load_recordings`` (merged by time stamp, re-numbered flow ids; DESIGN.md §13.5)."""
    unique: list[str] = []
    for path in paths or ():
        if path not in unique:
            unique.append(path)
    if not unique:
        raise ValueError("入力ファイルが指定されていません")
    if len(unique) == 1:
        return load_recording(unique[0])
    return load_recordings(unique)


def _input_label(paths: Sequence[str]) -> str:
    return ", ".join(str(p) for p in paths)


# --------------------------------------------------------------------------- record / import

def cmd_record(args: argparse.Namespace) -> int:
    """``reqrec record``: delegate to the mitmproxy launcher."""
    hosts = split_hosts(args.hosts)
    return int(run_record(
        out=args.out,
        port=args.port,
        hosts=hosts or None,
        listen_host=args.listen_host,
        quiet=not args.verbose,
        extra_args=list(args.mitm_arg or ()),
    ))


def cmd_gui(args: argparse.Namespace) -> int:
    """``reqrec gui``: start the Flask GUI (see reqrec/webapp)."""
    from .webapp import run_gui

    return int(run_gui(host=args.host, port=args.port, workdir=args.workdir, open_browser=not args.no_browser))


def cmd_import(args: argparse.Namespace) -> int:
    """``reqrec import``: any supported input -> reqrec recording JSON."""
    _check_output_path(args.out, "保存先")
    inputs = list(args.input)
    recording: Recording = load_inputs(inputs)
    recording.save(args.out)
    source = _describe_source(recording.meta)
    detail = f"（{source}）" if source else ""
    merged = f"{len(inputs)} ファイルを結合して " if len(inputs) > 1 else ""
    print(f"{merged}{len(recording.flows)} 件のフローを取り込みました{detail} → {args.out}")
    return EXIT_OK


# --------------------------------------------------------------------------- inspect

def _json_path_label(path: Optional[list[Any]]) -> str:
    """``["data", "items", 0, "id"]`` -> ``data.items[0].id``."""
    if not path:
        return ""
    out = ""
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += ("." if out else "") + str(part)
    return out


def _extractor_label(e: dict[str, Any]) -> str:
    """``csrf_token←html_input[_token]`` from an extractor entry of the inspect report."""
    kind = e.get("kind") or "?"
    if kind == "json":
        detail = _json_path_label(e.get("path"))
    elif e.get("name"):
        detail = str(e["name"])
    elif e.get("selector"):
        detail = str(e["selector"]) + (f"@{e['attr']}" if e.get("attr") else "")
    elif e.get("pattern"):
        detail = util.truncate(str(e["pattern"]), 24)
    else:
        detail = ""
    return f"{e.get('var')}←{kind}" + (f"[{detail}]" if detail else "")


def _loop_label(loop: dict[str, Any]) -> str:
    """``ループ page=1..3 (3回)`` from a loop entry of the inspect report."""
    count = int(loop.get("count") or 0)
    rng = loop.get("numeric_range")
    if rng:
        return f"ループ {loop['var']}={rng[0]}..{rng[1]} ({count}回)"
    values = list(loop.get("values") or [])
    preview = ", ".join(util.truncate(str(v), 12) for v in values[:3])
    if count > 3:
        preview += ", …"
    return f"ループ {loop['var']} ({count}回: {preview})"


def _url_label(step: Step) -> str:
    """Display form of the step URL; non-literal pieces are shown as ``{expr}``."""
    literal = step.literal_url()
    if literal is not None:
        return literal
    return "".join(ref.value if ref.is_literal else "{" + ref.value + "}" for ref in step.url)


def _status_chain(step: Step, flows_by_id: dict[str, model.Flow]) -> list[int]:
    """Recorded statuses of a collapsed redirect chain, e.g. ``[302, 200]`` (empty for loops)."""
    if step.loop is not None or len(step.source_flow_ids) < 2:
        return []
    statuses: list[int] = []
    for flow_id in step.source_flow_ids:
        flow = flows_by_id.get(flow_id)
        if flow is not None and flow.response is not None:
            statuses.append(flow.response.status)
    return statuses if len(statuses) > 1 else []


def _flow_ids_label(ids: Sequence[str]) -> str:
    """``["f0008", "f0009"]`` -> ``"f0008+f0009"``; long loops -> ``"f0011+…+f0015 (5)"``."""
    ids = [str(i) for i in ids]
    if not ids:
        return "-"
    if len(ids) <= 3:
        return "+".join(ids)
    return f"{ids[0]}+…+{ids[-1]} ({len(ids)})"


def _auth_label(auth: Optional[dict[str, Any]], constants: Sequence[dict[str, Any]] = ()) -> Optional[str]:
    """``認証: NTLM (記録時のユーザー: EXAMPLE\\taro) → 生成コードは session.auth を設定します``."""
    if not auth:
        return None
    kind = str(auth.get("kind") or "").lower()
    label = {"ntlm": "NTLM", "negotiate": "Negotiate", "basic": "Basic", "digest": "Digest"}.get(kind, kind or "?")
    text = f"認証: {label}"
    if auth.get("username"):
        text += f" (記録時のユーザー: {auth['username']})"
    text += " → 生成コードは session.auth を設定します"
    pw_const = auth.get("password_const")
    if pw_const:
        for c in constants:
            if c.get("name") == pw_const and c.get("secret") and c.get("env_var"):
                text += f"（パスワードは環境変数 {c['env_var']}）"
                break
    if kind in ("ntlm", "negotiate"):
        text += '（pip install "reqrec[sspi]" / "reqrec[ntlm]"）'
    return text


def build_inspect_report(recording: Recording, plan: Plan, source: str = "",
                         inputs: Optional[Sequence[str]] = None) -> dict[str, Any]:
    """Machine-readable summary of a plan (what ``inspect --json`` prints).

    Secret constant values and cookie values are deliberately *not* included.  ``inputs`` lists
    the input files (``source`` is their display form); every step carries its ``source_flow_ids``
    and a ``flow_ids`` label (``"f0008+f0009"``) so users can refer to flows in the override options.
    """
    flows_by_id = {flow.id: flow for flow in recording.flows}
    flows_kept = sum(len(step.source_flow_ids) for step in plan.steps)
    if not flows_kept and plan.meta.get("flows_kept") is not None:
        flows_kept = int(plan.meta["flows_kept"])

    steps: list[dict[str, Any]] = []
    for step in plan.steps:
        loop = None
        if step.loop is not None:
            loop = {
                "var": step.loop.var,
                "count": len(step.loop.values),
                "values": list(step.loop.values),
                "numeric_range": list(step.loop.numeric_range) if step.loop.numeric_range is not None else None,
            }
        steps.append({
            "index": step.index,
            "func_name": step.func_name,
            "method": step.method,
            "status": step.expected_status,
            "status_chain": _status_chain(step, flows_by_id),
            "url": _url_label(step),
            "params": [name for name, _ref in step.params],
            "body_kind": step.body_kind,
            "response_kind": step.response_kind,
            "extractors": [
                {
                    "var": e.var,
                    "kind": e.kind,
                    "name": e.name,
                    "path": e.path,
                    "selector": e.selector,
                    "attr": e.attr,
                    "pattern": e.pattern,
                    "sample": e.sample,
                    "note": e.note,
                }
                for e in step.extractors
            ],
            "loop": loop,
            "source_flow_ids": list(step.source_flow_ids),
            "flow_ids": _flow_ids_label(step.source_flow_ids),
            "is_final": plan.final_step_index is not None and step.index == plan.final_step_index,
            "comment": step.comment,
        })

    by_reason: dict[str, list[model.Dropped]] = {}
    for dropped in plan.dropped:
        by_reason.setdefault(dropped.reason, []).append(dropped)
    dropped_by_reason = [
        {
            "reason": reason,
            "count": len(items),
            "examples": [d.url for d in items[:INSPECT_EXAMPLES_PER_REASON]],
            "example_ids": [d.flow_id for d in items[:INSPECT_EXAMPLES_PER_REASON]],
        }
        for reason, items in sorted(by_reason.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ]

    constants = [
        {
            "name": c.name,
            "secret": bool(c.secret),
            "env_var": c.env_var,
            "value": None if c.secret else c.value,
            "comment": c.comment,
        }
        for c in plan.constants
    ]

    return {
        "input": source,
        "inputs": [str(p) for p in inputs] if inputs is not None else ([source] if source else []),
        "source": _describe_source(recording.meta),
        "auth": model.to_plain(plan.auth) if plan.auth is not None else None,
        "final_step_index": plan.final_step_index,
        "flows_total": len(recording.flows),
        "flows_kept": flows_kept,
        "steps_kept": len(plan.steps),
        "dropped": len(plan.dropped),
        "steps": steps,
        "dropped_by_reason": dropped_by_reason,
        "dropped_flows": [
            {"flow_id": d.flow_id, "method": d.method, "url": d.url, "reason": d.reason} for d in plan.dropped
        ],
        "constants": constants,
        "env_vars": sorted({c.env_var for c in plan.constants if c.secret and c.env_var}),
        "initial_cookies": [{"name": c.name, "domain": c.domain, "path": c.path} for c in plan.initial_cookies],
        "base_headers": [[name, value] for name, value in plan.base_headers],
        "warnings": list(plan.warnings),
    }


def format_inspect_report(report: dict[str, Any]) -> str:
    """Human-readable rendering of ``build_inspect_report``'s output."""
    lines: list[str] = []
    header = f"入力: {report.get('input') or '-'}"
    if report.get("source"):
        header += f"  ({report['source']})"
    lines.append(header)
    lines.append(
        f"フロー合計 {report['flows_total']} 件 / 採用 {report['flows_kept']} 件 → "
        f"ステップ {report['steps_kept']} 件 / 除外 {report['dropped']} 件"
    )
    steps = report["steps"]
    auth_line = _auth_label(report.get("auth"), report.get("constants") or [])
    if auth_line:
        lines.append(auth_line)
    final_index = report.get("final_step_index")
    if final_index is not None:
        final_step = next((s for s in steps if s["index"] == final_index), None)
        detail = f" ({final_step['method']} {util.truncate(final_step['url'], INSPECT_URL_WIDTH)})" if final_step else ""
        lines.append(f"結果にするステップ: {final_index}{detail}")
    lines.append("")

    if steps:
        lines.append(f"ステップ ({len(steps)} 件):")
        rows: list[list[str]] = []
        for step in steps:
            method = step["method"]
            if step["loop"]:
                method += f" ×{step['loop']['count']}"
            chain = step.get("status_chain") or []
            status = "→".join(str(s) for s in chain) if chain else str(step["status"])
            extras = [_extractor_label(e) for e in step["extractors"]]
            if step["loop"]:
                extras.append(_loop_label(step["loop"]))
            if step.get("is_final"):
                extras.insert(0, "★ 結果として表示")
            # One extractor / loop per line: the first shares the step row, the rest get
            # continuation rows so nothing is hidden behind a truncation.
            rows.append([
                f"{step['index']:02d}",
                step.get("flow_ids") or _flow_ids_label(step.get("source_flow_ids") or []),
                method,
                status,
                util.truncate(step["url"], INSPECT_URL_WIDTH),
                util.truncate(extras[0], INSPECT_EXTRACT_WIDTH) if extras else "-",
            ])
            for extra in extras[1:]:
                rows.append(["", "", "", "", "", util.truncate(extra, INSPECT_EXTRACT_WIDTH)])
        lines.extend(_format_table(["#", "FLOW", "METHOD", "STATUS", "URL", "抽出する変数 / ループ"], rows))
        lines.append("  （FLOW はフロー ID。--exclude-flow / --include-flow / --final-flow で指定できます）")
    else:
        lines.append("ステップ: なし（残ったリクエストがありません。--include-host や --keep-all などのフィルタオプションを確認してください）")
    lines.append("")

    dropped_groups = report["dropped_by_reason"]
    if dropped_groups:
        lines.append(f"除外されたリクエスト ({report['dropped']} 件):")
        for group in dropped_groups:
            lines.append(f"  {group['reason']} — {group['count']} 件")
            ids = list(group.get("example_ids") or [])
            for i, url in enumerate(group["examples"]):
                fid = ids[i] if i < len(ids) else ""
                lines.append(f"      {fid + '  ' if fid else ''}{util.truncate(url, 100)}")
            if group["count"] > len(group["examples"]):
                lines.append(f"      … 他 {group['count'] - len(group['examples'])} 件（--json で全件表示）")
    else:
        lines.append("除外されたリクエスト: なし")
    lines.append("")

    constants = report.get("constants") or []
    if constants:
        lines.append(f"定数 ({len(constants)} 件):")
        for c in constants:
            if c["secret"]:
                env = c["env_var"] or "(環境変数名なし)"
                lines.append(f"  {c['name']}  ← 環境変数 {env}（秘密情報: 実行前に設定してください）")
            else:
                lines.append(f"  {c['name']} = {util.truncate(repr(c['value']), 60)}")
        lines.append("")

    cookies = report.get("initial_cookies") or []
    if cookies:
        names = ", ".join(f"{c['name']}@{c['domain']}" for c in cookies[:8])
        if len(cookies) > 8:
            names += ", …"
        lines.append(f"記録開始前からブラウザにあった Cookie ({len(cookies)} 件): {names}")
        lines.append("  （値は生成コードに埋め込まれます。期限切れになったら記録し直してください）")
        lines.append("")

    warnings = report.get("warnings") or []
    if warnings:
        lines.append(f"警告 ({len(warnings)} 件):")
        for w in warnings:
            lines.append(f"  - {w}")
    else:
        lines.append("警告: なし")
    return "\n".join(lines) + "\n"


def cmd_inspect(args: argparse.Namespace) -> int:
    """``reqrec inspect``: analyse and print what would be generated."""
    inputs = list(args.input)
    recording: Recording = load_inputs(inputs)
    opts = resolve_overrides(recording, plan_options_from_args(args),
                             getattr(args, "exclude_step", None), getattr(args, "final_step", None))
    plan: Plan = build_plan(recording, opts)
    report = build_inspect_report(recording, plan, source=_input_label(inputs), inputs=inputs)
    if args.json:
        sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
    else:
        sys.stdout.write(format_inspect_report(report))
    sys.stdout.flush()
    return EXIT_OK


# --------------------------------------------------------------------------- generate

def format_plan_summary(plan: Plan, flows_total: Optional[int] = None) -> str:
    """Short summary + warnings that ``generate`` prints to stderr."""
    if flows_total is None:
        flows_total = plan.meta.get("flows_total")
    total = f"フロー合計 {flows_total} 件 / " if flows_total is not None else ""
    loops = sum(1 for s in plan.steps if s.loop is not None)
    extracted = sum(len(s.extractors) for s in plan.steps)
    lines = [
        f"ステップ {len(plan.steps)} 件を生成します（{total}除外 {len(plan.dropped)} 件 / "
        f"抽出する変数 {extracted} 個 / ループ {loops} 個）"
    ]
    if plan.auth is not None:
        constants = [{"name": c.name, "secret": c.secret, "env_var": c.env_var} for c in plan.constants]
        auth_line = _auth_label(model.to_plain(plan.auth), constants)
        if auth_line:
            lines.append(auth_line)
    if plan.final_step_index is not None:
        final_step = next((s for s in plan.steps if s.index == plan.final_step_index), None)
        detail = f"（{final_step.method} {util.truncate(_url_label(final_step), INSPECT_URL_WIDTH)}）" if final_step else ""
        lines.append(f"結果にするステップ: {plan.final_step_index}{detail}")
    env_vars = sorted({c.env_var for c in plan.constants if c.secret and c.env_var})
    if env_vars:
        lines.append("秘密情報は環境変数から読み込みます。実行前に設定してください: " + ", ".join(env_vars))
    if plan.warnings:
        lines.append(f"警告 ({len(plan.warnings)} 件):")
        lines.extend(f"  - {w}" for w in plan.warnings)
    return "\n".join(lines)


def run_script(path: str) -> int:
    """Execute a generated script with the current interpreter; returns its exit code."""
    command = [sys.executable, os.path.abspath(path)]
    _info("生成したスクリプトを実行します: " + " ".join(shlex.quote(c) for c in command))
    sys.stdout.flush()
    try:
        # The child inherits our environment (REQREC_* secrets) and working directory.
        returncode = subprocess.call(command)
    except OSError as exc:
        raise OSError(f"スクリプトを実行できません: {exc}") from exc
    if returncode != 0:
        _info(f"スクリプトは終了コード {returncode} で終了しました")
    return returncode if 0 <= returncode <= 255 else EXIT_ERROR


def _plan_dump(plan: Plan) -> dict:
    """``--dump-plan`` JSON: ``model.to_plain(plan)`` with the recorded value of every *secret*
    constant removed (the generated script reads it from the environment; the dump must not keep it)."""
    data = model.to_plain(plan)
    for const, plain in zip(plan.constants, data.get("constants", [])):
        if const.secret:
            plain["value"] = None
    return data


def cmd_generate(args: argparse.Namespace) -> int:
    """``reqrec generate``: recording -> plan -> script (-> optional run)."""
    to_stdout = args.out == "-"
    if args.run and to_stdout:
        raise ValueError("--run を使う場合は -o にファイル名を指定してください（- は使えません）")
    if not to_stdout:
        _check_output_path(args.out, "出力先")
    if args.dump_plan:
        _check_output_path(args.dump_plan, "--dump-plan の出力先")

    inputs = list(args.input)
    recording: Recording = load_inputs(inputs)
    opts = resolve_overrides(recording, plan_options_from_args(args),
                             getattr(args, "exclude_step", None), getattr(args, "final_step", None))
    plan: Plan = build_plan(recording, opts)

    if args.dump_plan:
        _write_text(args.dump_plan, json.dumps(_plan_dump(plan), ensure_ascii=False, indent=2, default=str) + "\n")
        _info(f"解析結果 (Plan) を書き出しました: {args.dump_plan}")

    source = generate(plan, gen_options_from_args(args))
    if not isinstance(source, str):
        raise ValueError("コード生成器が文字列を返しませんでした")
    if not source.endswith("\n"):
        source += "\n"

    _info(format_plan_summary(plan, flows_total=len(recording.flows)))
    if not plan.steps:
        _info("注意: ステップが 1 つもありません。inspect で除外理由を確認し、--include-host / --keep-all などを調整してください。")

    if to_stdout:
        sys.stdout.write(source)
        sys.stdout.flush()
    else:
        _write_text(args.out, source)
        _info(f"スクリプトを書き出しました: {args.out}")

    if args.run:
        return run_script(args.out)
    return EXIT_OK


# --------------------------------------------------------------------------- entry point

def _exit_code_from_system_exit(code: Any) -> int:
    """Normalise ``SystemExit.code`` (argparse uses ints; ``None`` means success)."""
    if code is None:
        return EXIT_OK
    if isinstance(code, bool):
        return int(code)
    if isinstance(code, int):
        return code
    print(str(code), file=sys.stderr)
    return EXIT_USAGE


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return the process exit code (0 ok, 1 error, 2 usage)."""
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:  # argparse: --help / --version (0) or usage error (2)
        return _exit_code_from_system_exit(exc.code)

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    try:
        return int(func(args))
    except FileNotFoundError as exc:
        missing = exc.filename if getattr(exc, "filename", None) else str(exc)
        _error(f"ファイルが見つかりません: {missing}")
        return EXIT_ERROR
    except (ValueError, ImportError, OSError) as exc:
        _error(str(exc) or exc.__class__.__name__)
        return EXIT_ERROR
    except KeyboardInterrupt:
        _error("中断されました")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
