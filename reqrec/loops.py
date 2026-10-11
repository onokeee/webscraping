"""Pagination / repetition detection.  Contract: DESIGN.md §6.

Three or more *consecutive* kept groups (redirect chains) whose first requests are identical
except for exactly one parameter value fold into a single looped step.  Comparison covers method,
scheme + host, path segment count, parameter names (path / query / form / JSON leaf paths /
multipart text fields), body kind, raw body and request headers (after
``filters.clean_request_headers``, ignoring ``Referer``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from . import deps, util
from .filters import clean_request_headers
from .model import Flow, PlanOptions

_LOOPABLE_LOCATIONS = frozenset({"query", "form", "json", "path"})
_MIN_ITERATIONS = 3
_INT_RE = re.compile(r"^-?\d+$")


@dataclass
class LoopGroup:
    """Consecutive groups that fold into one looped step.

    ``occurrence`` disambiguates repeated parameter names (``id=1&id=2``): it is the 0-based index
    of the varying pair among the pairs sharing ``(location, name)``."""

    groups: list[list[Flow]]
    location: str  # "query" | "form" | "json" | "path"
    name: str  # param name / json dotted path / path segment index
    values: list[str]
    numeric_range: Optional[tuple[int, int]] = None
    occurrence: int = 0


@dataclass
class _Signature:
    shape: tuple  # everything that must be identical
    keys: list[tuple[str, str, int]]  # (location, name, occurrence) per parameter position
    values: list[str]


def _signature(flow: Flow) -> Optional[_Signature]:
    req = flow.request
    try:
        parts = urlsplit(req.url)
    except ValueError:
        return None
    params = deps.request_params(flow)
    counter: dict[tuple[str, str], int] = {}
    keys: list[tuple[str, str, int]] = []
    values: list[str] = []
    for p in params:
        occ = counter.get((p.location, p.name), 0)
        counter[(p.location, p.name)] = occ + 1
        keys.append((p.location, p.name, occ))
        # cache-busters (``_=1700000000123``) become clock expressions in the plan, so they must
        # not count as the "one differing value"
        values.append("<timestamp>" if util.looks_like_timestamp(p.value, around=flow.started_at) else p.value)
    kind, _parsed = deps.classify_body(req)
    headers = tuple(sorted((k.lower(), v) for k, v in clean_request_headers(req.headers) if k.lower() != "referer"))
    raw = req.body if kind == "raw" else None
    shape = ((req.method or "").upper(), parts.scheme.lower(), parts.netloc.lower(), tuple(keys), kind, headers, raw)
    return _Signature(shape=shape, keys=keys, values=values)


def _numeric_range(values: list[str]) -> Optional[tuple[int, int]]:
    """``(first, last)`` when the values are consecutive integers (step +1 or -1), else None."""
    if len(values) < 2 or not all(_INT_RE.match(v) for v in values):
        return None
    ints = [int(v) for v in values]
    if any(str(n) != v for n, v in zip(ints, values)):
        return None  # zero padded ("01") -> keep the literal list
    step = ints[1] - ints[0]
    if step not in (1, -1):
        return None
    if all(b - a == step for a, b in zip(ints, ints[1:])):
        return ints[0], ints[-1]
    return None


def detect_loops(groups: list[list[Flow]], opts: PlanOptions) -> list[LoopGroup]:
    """Find runs of >= 3 consecutive groups differing in exactly one parameter value."""
    sigs = [_signature(g[0]) if g else None for g in groups]
    out: list[LoopGroup] = []
    i = 0
    n = len(groups)
    while i < n:
        base = sigs[i]
        if base is None:
            i += 1
            continue
        pos: Optional[int] = None
        j = i + 1
        while j < n:
            sig = sigs[j]
            if sig is None or sig.shape != base.shape:
                break
            diffs = [k for k, (a, b) in enumerate(zip(base.values, sig.values)) if a != b]
            if len(diffs) != 1:
                break
            if pos is None:
                pos = diffs[0]
            elif diffs[0] != pos:
                break
            j += 1
        if pos is not None and j - i >= _MIN_ITERATIONS:
            location, name, occurrence = base.keys[pos]
            values = [sigs[k].values[pos] for k in range(i, j)]
            # Hash-like values (cursors, ids from a listing) are each traceable to an earlier
            # response; folding them into a literal list would break that chain, so only
            # counter-like / word-like values are folded.
            if location in _LOOPABLE_LOCATIONS and not any(deps.is_dynamic_looking(v) for v in values):
                out.append(LoopGroup(
                    groups=list(groups[i:j]),
                    location=location,
                    name=name,
                    values=values,
                    numeric_range=_numeric_range(values),
                    occurrence=occurrence,
                ))
                i = j
                continue
        i += 1
    return out


__all__ = ["LoopGroup", "detect_loops"]
