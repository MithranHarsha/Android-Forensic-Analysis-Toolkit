"""Loose SQLite-record-shaped byte sequences (Phase 6).

A SQLite record is ``[header size][serial type]...[serial type][value]...[value]``: the header size counts itself and the type
varints, and the types say exactly how many bytes each value takes. That is a lot of structure for a byte sequence to have by
accident, so a run of bytes that satisfies all of it -- and decodes to text that reads like text -- is worth reporting even when
nothing around it is a database page: a cell in a file that is not a database at all, a page released by a table whose schema
cannot be read, a record fragment in a WAL or journal that survived without its cell header.

What is required (all of it, otherwise nothing is reported):

* a header size of 4-63 bytes whose serial-type varints end *exactly* at that size, no reserved types (10, 11);
* at least three columns and a body that fits inside the data and is at most 16 KiB;
* every text value valid UTF-8, and at least one of them four or more characters that are mostly printable and mostly
  letters or digits (random bytes essentially never satisfy this);
* not more than all-but-one column NULL.

This is a *shape*, not a schema match: it says nothing about which table the record belonged to.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from android_forensics.models import encode_value
from android_forensics.sqlite.records import RecordError, decode_value, read_varint, serial_type_size

MIN_COLUMNS = 3
MAX_HEADER = 63
MAX_BODY = 16384


@dataclass(frozen=True)
class RecordHit:
    start: int
    end: int
    values: tuple[Any, ...]
    serial_types: tuple[int, ...]

    def render(self, limit: int = 1000) -> str:
        text = json.dumps([encode_value(v) for v in self.values], ensure_ascii=False)
        return text if len(text) <= limit else text[: limit - 1] + "…"


def _reads_as_text(value: str) -> bool:
    if len(value) < 4:
        return False
    printable = sum(1 for c in value if c.isprintable() or c in "\t\r\n")
    alnum = sum(1 for c in value if c.isalnum())
    return printable >= 0.9 * len(value) and alnum >= 0.5 * len(value)


def parse_record_at(data: bytes, pos: int) -> RecordHit | None:
    """The record whose header size byte is at ``pos``, if the bytes there satisfy every requirement above."""
    n = len(data)
    header_size = data[pos]
    if not MIN_COLUMNS + 1 <= header_size <= MAX_HEADER or pos + header_size >= n:
        return None
    types: list[int] = []
    p, header_end = pos + 1, pos + header_size
    try:
        while p < header_end:
            t, used = read_varint(data, p)
            serial_type_size(t)  # rejects the reserved types
            types.append(t)
            p += used
        if p != header_end or len(types) < MIN_COLUMNS:
            return None
        sizes = [serial_type_size(t) for t in types]
        body = sum(sizes)
        if body > MAX_BODY or header_end + body > n:
            return None
        values: list[Any] = []
        at = header_end
        for t, size in zip(types, sizes):
            values.append(decode_value(t, memoryview(data)[at:at + size], "UTF-8"))
            at += size
    except RecordError:
        return None
    if sum(v is None for v in values) > len(values) - 2:
        return None
    if not any(isinstance(v, str) and _reads_as_text(v) for v in values):
        return None
    return RecordHit(pos, header_end + body, tuple(values), tuple(types))


def scan_records(data: bytes, lo: int, hi: int) -> list[RecordHit]:
    """Non-overlapping record-shaped sequences whose header starts in ``[lo, hi)``, earliest first."""
    hits: list[RecordHit] = []
    i = lo
    stop = min(hi, len(data))
    while i < stop:
        if MIN_COLUMNS + 1 <= data[i] <= MAX_HEADER:
            hit = parse_record_at(data, i)
            if hit is not None:
                hits.append(hit)
                i = hit.end
                continue
        i += 1
    return hits
