"""Load a Recording from a HAR file, a mitmproxy flow file, or a reqrec JSON recording.

Contract: see DESIGN.md §2.

Dispatch is by extension: ``.har`` -> HAR importer, ``.mitm`` / ``.flows`` / ``.flow`` ->
mitmproxy importer, ``.json`` -> sniffed (a HAR document has a top-level ``"log"``; a reqrec
recording has ``"flows"``).  Anything else raises ``ValueError``.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Iterable, Union

from ..model import Recording
from .har import load_har, recording_from_har
from .mitm import load_mitm

__all__ = ["load_recording", "load_recordings", "load_har", "recording_from_har", "load_mitm",
           "HAR_EXTENSIONS", "MITM_EXTENSIONS"]

log = logging.getLogger(__name__)

HAR_EXTENSIONS = frozenset({".har"})
MITM_EXTENSIONS = frozenset({".mitm", ".flows", ".flow"})
JSON_EXTENSIONS = frozenset({".json"})


def load_recording(path: str) -> Recording:
    """Dispatch on extension / content (see DESIGN.md §2).

    Raises ``ValueError`` for unsupported extensions or unrecognised JSON, ``ImportError`` (with an
    install hint) for a mitmproxy file when mitmproxy is not installed, and the usual ``OSError``
    family when the file cannot be read.
    """
    path = os.fspath(path)
    ext = os.path.splitext(path)[1].lower()
    if ext in HAR_EXTENSIONS:
        return load_har(path)
    if ext in MITM_EXTENSIONS:
        return load_mitm(path)
    if ext in JSON_EXTENSIONS:
        return _load_json_sniffed(path)
    supported = ", ".join(sorted(HAR_EXTENSIONS | MITM_EXTENSIONS | JSON_EXTENSIONS))
    raise ValueError(
        f"{path}: 対応していないファイル形式です ({ext or '拡張子なし'})。対応形式: {supported}\n"
        f"unsupported input file type {ext or '(no extension)'}; supported: {supported}"
    )


def load_recordings(paths: Union[str, "os.PathLike[str]", Iterable[Union[str, "os.PathLike[str]"]]]) -> Recording:
    """Load one or more files and merge them into a single ``Recording`` (DESIGN.md §13.5).

    Typical use: one HAR per browser tab (DevTools saves each tab separately), merged so that a
    screen opened in a new tab becomes part of the same conversation.  Flows are re-ordered by
    their timestamps across files and re-numbered ``f0001``...; ``meta`` becomes
    ``{"source": "merged", "sources": [<meta of each file>]}``.  A single path (or a one-element
    list) behaves exactly like ``load_recording`` (same flows, same ``meta``).  The same file
    listed twice is loaded once (a duplicate would double every step).

    Raises ``ValueError`` for an empty list and whatever ``load_recording`` raises per file, with
    the offending file named.
    """
    if isinstance(paths, (str, bytes, os.PathLike)):
        paths = [paths]
    unique: list[str] = []
    seen: set[str] = set()
    for p in paths:
        text = os.fsdecode(p) if isinstance(p, bytes) else os.fspath(p)
        key = os.path.normcase(os.path.realpath(text))
        if key in seen:
            log.warning("%s: 同じファイルが複数回指定されました（1 回だけ読み込みます）", text)
            continue
        seen.add(key)
        unique.append(text)
    if not unique:
        raise ValueError("読み込むファイルが指定されていません / no input files given")
    recordings = [load_recording(p) for p in unique]
    if len(recordings) == 1:
        return recordings[0]
    return Recording.merge(recordings)


def _load_json_sniffed(path: str) -> Recording:
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: JSONを解析できません / not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: JSONのトップレベルがオブジェクトではありません / top-level JSON value is not an object")
    if isinstance(data.get("log"), dict):
        return recording_from_har(data, source=path)
    if "flows" in data:
        return Recording.from_dict(data)
    raise ValueError(
        f'{path}: HAR ("log") でも reqrec の記録 ("flows") でもないJSONです\n'
        f'JSON file is neither a HAR document ("log") nor a reqrec recording ("flows")'
    )
