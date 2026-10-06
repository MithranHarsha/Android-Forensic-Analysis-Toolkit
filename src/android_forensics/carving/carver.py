"""The carver (Phase 6): raw bytes in, ``CarvedCandidate`` objects out.

What comes out is a *candidate*: a pattern that matched at a byte offset. Its status is the literal string ``CARVED CANDIDATE``
(fixed by the model, and by a CHECK constraint in the case database) and stays that until correlation says something else
about it -- and even then it is scored, never promoted: nothing in this package produces or touches an ``Artifact``.

Every candidate carries the file it came from, the byte offset and length of the hit, the rule that matched, the matched text
(or a rendering of the record), the encoding, 24 bytes of context on each side, whether the neighbours delimit it, and where
it was found (loose file bytes, or the non-record space of a parsed database).

Scanning is windowed (1 MiB plus an overlap) so a large file is never held whole, with results identical to scanning the file
in one piece. Hits that overlap a supplied *exclusion* -- the live cells of a database, the raw bytes of a record recovery
already reported -- are dropped and counted, because those bytes are somebody else's evidence.
"""

from __future__ import annotations

import bisect
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from android_forensics.carving.records import scan_records
from android_forensics.carving.rules import RULES, Rule
from android_forensics.carving.sms import find_sms_like
from android_forensics.models import CarvedCandidate, CarveKind
from android_forensics.readonly import open_readonly

CONTEXT = 24
WINDOW = 1 << 20
OVERLAP = 4096
LEAD = 64
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e\t\r\n]\x00){6,}")


@dataclass(frozen=True)
class CarveSource:
    """The file being carved."""

    evidence_file_id: int
    source_file: str
    source_sha256: str
    container: str = "file"  # "file" | "sqlite_free_space"


@dataclass
class CarveResult:
    candidates: list[CarvedCandidate] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _Hit:
    start: int  # within the scanned buffer
    end: int
    kind: CarveKind
    pattern: str
    matched: str
    encoding: str
    context_valid: bool
    notes: tuple[str, ...] = ()


class Exclusions:
    """Byte ranges (absolute file offsets, half-open) that a hit must not overlap."""

    def __init__(self, ranges: Iterable[tuple[int, int]] = ()):
        merged: list[list[int]] = []
        for a, b in sorted((a, b) for a, b in ranges if b > a):
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        self._starts = [a for a, _ in merged]
        self._ends = [b for _, b in merged]

    def overlaps(self, a: int, b: int) -> bool:
        i = bisect.bisect_right(self._ends, a)
        return i < len(self._starts) and self._starts[i] < b

    def __len__(self) -> int:
        return len(self._starts)


def _alnum(byte: int) -> bool:
    return 48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122


def _delimited(data: bytes, start: int, end: int, unit: int) -> bool:
    """True when neither neighbour is an ASCII letter or digit (a hit glued to more of the same token is not delimited)."""
    def glued(at: int) -> bool:
        if at < 0 or at + unit > len(data):
            return False
        return _alnum(data[at]) if unit == 1 else (data[at + 1] == 0 and _alnum(data[at]))

    return not glued(start - unit) and not glued(end)


def _text_hits(data: bytes, lo: int, hi: int, now: datetime | None, rules: Sequence[Rule]) -> list[_Hit]:
    hits: list[_Hit] = []
    for rule in rules:
        for m in rule.regex.finditer(data):
            s = m.start()
            if s < lo:
                continue
            if s >= hi:
                break
            text = m.group().decode("ascii")
            if rule.trim:
                text = rule.trim(text)
            if text and rule.validate(text, now):
                hits.append(_Hit(s, s + len(text), rule.kind, rule.name, text, "ascii", _delimited(data, s, s + len(text), 1)))
    for run in _UTF16_RUN.finditer(data):
        rs, decoded = run.start(), run.group()[::2]
        if rs >= hi or run.end() <= lo:
            continue
        for rule in rules:
            for m in rule.regex.finditer(decoded):
                s = rs + 2 * m.start()
                if not lo <= s < hi:
                    continue
                text = m.group().decode("ascii")
                if rule.trim:
                    text = rule.trim(text)
                if text and rule.validate(text, now):
                    e = s + 2 * len(text)
                    hits.append(_Hit(s, e, rule.kind, rule.name, text, "utf-16le", _delimited(data, s, e, 2)))
    return hits


def _dedupe(hits: list[_Hit]) -> list[_Hit]:
    """Two hits of one kind and encoding that overlap are the same finding: keep the earlier (then the longer)."""
    kept: list[_Hit] = []
    last_end: dict[tuple[CarveKind, str], int] = {}
    for h in sorted(hits, key=lambda h: (h.start, -(h.end - h.start), h.pattern)):
        key = (h.kind, h.encoding)
        if h.start < last_end.get(key, -1):
            continue
        kept.append(h)
        last_end[key] = h.end
    return kept


def _scan(data: bytes, lo: int, hi: int, now: datetime | None, kinds: frozenset[CarveKind] | None) -> list[_Hit]:
    """Every hit whose first byte is in ``data[lo:hi]`` (the rest of ``data`` is context for lookbehind / lookahead)."""
    rules = [r for r in RULES if kinds is None or r.kind in kinds]
    hits = _dedupe(_text_hits(data, lo, hi, now, rules))
    records = scan_records(data, lo, hi) if kinds is None or CarveKind.SQLITE_RECORD in kinds else []
    if kinds is None or CarveKind.SMS_LIKE_TEXT in kinds:
        # spans always come from the phone / millisecond rules, even when those kinds were not asked for
        support = _text_hits(data, 0, len(data), now, [r for r in RULES if r.kind in (CarveKind.PHONE_NUMBER, CarveKind.TIMESTAMP_UNIX_MILLIS)])
        phones = [(h.start, h.end) for h in support if h.kind is CarveKind.PHONE_NUMBER and h.encoding == "ascii"]
        millis = [(h.start, h.end) for h in support if h.kind is CarveKind.TIMESTAMP_UNIX_MILLIS and h.encoding == "ascii"]
        by_start = sorted(records, key=lambda r: r.start)
        rec_starts = [r.start for r in by_start]
        furthest_end: list[int] = []                     # furthest_end[i] = max end among the i+1 earliest-starting records
        for r in by_start:
            furthest_end.append(max(r.end, furthest_end[-1]) if furthest_end else r.end)
        for s in find_sms_like(data, lo, hi, phones, millis):
            k = bisect.bisect_right(rec_starts, s.start) - 1    # a record starting at or before the text, ending at or after it?
            if k >= 0 and furthest_end[k] >= s.end:
                continue  # a text column of a record-shaped sequence: the record candidate already carries it
            hits.append(_Hit(s.start, s.end, CarveKind.SMS_LIKE_TEXT, s.pattern, s.text, "ascii", True, s.notes))
    for r in records:
        hits.append(_Hit(r.start, r.end, CarveKind.SQLITE_RECORD, "sqlite_record_shape", r.render(), "binary", True,
                         (f"{len(r.values)} columns; serial types {list(r.serial_types)}",)))
    return hits


def _candidate(h: _Hit, data: bytes, base: int, source: CarveSource, context: int) -> CarvedCandidate:
    return CarvedCandidate(
        evidence_file_id=source.evidence_file_id, source_file=source.source_file, source_sha256=source.source_sha256,
        offset=base + h.start, length=h.end - h.start, kind=h.kind, pattern=h.pattern, matched=h.matched, encoding=h.encoding,
        container=source.container, context_valid=h.context_valid,
        context_before_hex=data[max(0, h.start - context):h.start].hex(), context_after_hex=data[h.end:h.end + context].hex(),
        notes=list(h.notes),
    )


def _finish(result: CarveResult, hits: list[tuple[int, CarvedCandidate]], limit: int | None) -> CarveResult:
    ordered = sorted((c for _, c in hits), key=lambda c: (c.offset, c.kind.value, c.pattern, c.encoding))
    if limit is not None and len(ordered) > limit:
        ordered = ordered[:limit]
        result.stats["truncated"] = True
    result.candidates = ordered
    counts: dict[str, int] = {}
    for c in ordered:
        counts[c.pattern] = counts.get(c.pattern, 0) + 1
    result.stats["hits_by_pattern"] = dict(sorted(counts.items()))
    result.stats["candidates"] = len(ordered)
    return result


def carve_bytes(
    data: bytes, source: CarveSource, *, base_offset: int = 0, exclude: Exclusions | Iterable[tuple[int, int]] = (),
    now: datetime | None = None, kinds: Iterable[CarveKind] | None = None, context: int = CONTEXT, limit: int | None = None,
) -> CarveResult:
    """Carve ``data``. ``base_offset`` is where ``data`` starts in the file (offsets and ``exclude`` are file offsets)."""
    ex = exclude if isinstance(exclude, Exclusions) else Exclusions(exclude)
    kset = frozenset(kinds) if kinds is not None else None
    result = CarveResult(stats={"bytes_scanned": len(data), "excluded_overlaps": 0, "truncated": False})
    kept: list[tuple[int, CarvedCandidate]] = []
    for h in _scan(data, 0, len(data), now, kset):
        if ex.overlaps(base_offset + h.start, base_offset + h.end):
            result.stats["excluded_overlaps"] += 1
            continue
        kept.append((h.start, _candidate(h, data, base_offset, source, context)))
    return _finish(result, kept, limit)


def carve_file(
    path: str | Path, source: CarveSource, *, exclude: Exclusions | Iterable[tuple[int, int]] = (), now: datetime | None = None,
    kinds: Iterable[CarveKind] | None = None, context: int = CONTEXT, limit: int | None = None, window: int = WINDOW,
    overlap: int = OVERLAP,
) -> CarveResult:
    """Carve a file in windows; the result equals ``carve_bytes`` over its whole content. The file is opened read-only."""
    ex = exclude if isinstance(exclude, Exclusions) else Exclusions(exclude)
    kset = frozenset(kinds) if kinds is not None else None
    kept: list[tuple[int, CarvedCandidate]] = []
    with open_readonly(Path(path)) as fh:
        size = os.fstat(fh.fileno()).st_size
        result = CarveResult(stats={"bytes_scanned": size, "excluded_overlaps": 0, "truncated": False})
        pos = 0
        while pos < size:
            start = max(0, pos - LEAD)
            fh.seek(start)
            buf = fh.read(min(size, pos + window + overlap) - start)
            lo = pos - start
            for h in _scan(buf, lo, lo + window, now, kset):
                if ex.overlaps(start + h.start, start + h.end):
                    result.stats["excluded_overlaps"] += 1
                    continue
                kept.append((start + h.start, _candidate(h, buf, start, source, context)))
            pos += window
    return _finish(result, kept, limit)
