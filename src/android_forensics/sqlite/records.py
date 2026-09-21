"""The SQLite record format, decoded from bytes without the SQLite library.

Reference: https://www.sqlite.org/fileformat2.html (sections 1.6 "Record format", 1.5 "B-tree pages", 2.1 "Varints").

A **record** is ``[header][body]``:

* header — a varint ``header size`` (counting itself), then one varint **serial type** per column;
* body — the column values, back to back, each as many bytes as its serial type says.

Serial types:  0 NULL · 1 int8 · 2 int16 · 3 int24 · 4 int32 · 5 int48 · 6 int64 (all big-endian, two's complement) ·
7 IEEE-754 float64 · 8 the integer 0 · 9 the integer 1 · 10, 11 reserved · N ≥ 12 even: BLOB of (N-12)/2 bytes ·
N ≥ 13 odd: TEXT of (N-13)/2 bytes (in the database's text encoding).

A **varint** is 1–9 bytes, big-endian, 7 payload bits per byte with the high bit set on every byte but the last; the ninth
byte, if reached, contributes all 8 bits.

Everything here is strict: malformed input raises ``RecordError``. The recovery engine relies on that strictness — a byte
sequence only counts as a record if it parses *exactly*.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Sequence

SERIAL_FIXED_SIZE = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}
_TEXT_CODECS = {"UTF-8": "utf-8", "UTF-16le": "utf-16-le", "UTF-16be": "utf-16-be"}


class RecordError(ValueError):
    """Bytes that are not a well-formed record (or cell)."""


# ------------------------------------------------------------------ varints


def read_varint(buf: bytes | bytearray | memoryview, pos: int) -> tuple[int, int]:
    """Decode the varint at ``pos``: returns ``(value, length)``. Raises ``RecordError`` if it runs off the buffer."""
    value = 0
    end = len(buf)
    for i in range(8):
        if pos + i >= end:
            raise RecordError(f"varint at {pos} runs past the end of the buffer")
        byte = buf[pos + i]
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, i + 1
    if pos + 8 >= end:
        raise RecordError(f"varint at {pos} runs past the end of the buffer")
    return (value << 8) | buf[pos + 8], 9  # the 9th byte contributes all 8 bits


def varint_length(value: int) -> int:
    """How many bytes ``value`` occupies as a varint."""
    if value < 0 or value >= 1 << 64:
        raise ValueError("a varint holds an unsigned 64-bit value")
    if value >= 1 << 56:
        return 9
    n = 1
    while value >= 1 << (7 * n):
        n += 1
    return n


def encode_varint(value: int) -> bytes:
    """Inverse of ``read_varint`` (used to build test cells and journal/WAL fixtures)."""
    if value < 0 or value >= 1 << 64:
        raise ValueError("a varint holds an unsigned 64-bit value")
    if value >= 1 << 56:
        out = [value & 0xFF]
        value >>= 8
        for _ in range(8):
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        return bytes(reversed(out))
    out = [value & 0x7F]
    value >>= 7
    while value:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    return bytes(reversed(out))


# ------------------------------------------------------------------ serial types


def serial_type_size(serial_type: int) -> int:
    """Body bytes taken by a value of this serial type."""
    if serial_type in SERIAL_FIXED_SIZE:
        return SERIAL_FIXED_SIZE[serial_type]
    if serial_type in (10, 11):
        raise RecordError(f"serial type {serial_type} is reserved")
    if serial_type < 0:
        raise RecordError("negative serial type")
    return (serial_type - 12) // 2 if serial_type % 2 == 0 else (serial_type - 13) // 2


def serial_type_class(serial_type: int) -> str:
    """The storage class a serial type encodes: ``null``, ``integer``, ``real``, ``blob`` or ``text``."""
    if serial_type == 0:
        return "null"
    if serial_type in (1, 2, 3, 4, 5, 6, 8, 9):
        return "integer"
    if serial_type == 7:
        return "real"
    if serial_type in (10, 11):
        raise RecordError(f"serial type {serial_type} is reserved")
    return "blob" if serial_type % 2 == 0 else "text"


def text_codec(encoding: str) -> str:
    try:
        return _TEXT_CODECS[encoding]
    except KeyError:
        raise RecordError(f"unknown text encoding {encoding!r}") from None


def decode_value(serial_type: int, data: bytes | memoryview, encoding: str = "UTF-8") -> Any:
    """Decode one column value. TEXT is decoded strictly: bytes that are not valid in ``encoding`` raise ``RecordError``."""
    size = serial_type_size(serial_type)
    if len(data) < size:
        raise RecordError(f"serial type {serial_type} needs {size} bytes, {len(data)} available")
    raw = bytes(data[:size])
    if serial_type == 0:
        return None
    if serial_type == 8:
        return 0
    if serial_type == 9:
        return 1
    if serial_type in (1, 2, 3, 4, 5, 6):
        return int.from_bytes(raw, "big", signed=True)
    if serial_type == 7:
        return struct.unpack(">d", raw)[0]
    if serial_type % 2 == 0:
        return raw
    try:
        return raw.decode(text_codec(encoding))
    except UnicodeDecodeError as exc:
        raise RecordError(f"text is not valid {encoding}: {exc.reason}") from None


# ------------------------------------------------------------------ records


@dataclass(frozen=True)
class Record:
    """A record decoded from ``buf[start:end]``. Offsets are positions in the buffer it was read from."""

    start: int
    header_size: int
    serial_types: tuple[int, ...]
    values: tuple[Any, ...]
    header_end: int  # first body byte
    end: int  # one past the last body byte

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def body_length(self) -> int:
        return self.end - self.header_end


def parse_record_header(buf: bytes | memoryview, start: int, limit: int | None = None) -> tuple[int, list[int], int]:
    """Parse a record header at ``start``: returns ``(header_size, serial_types, header_end)``.

    ``limit`` bounds every read (default: the end of the buffer). The header must be exactly ``header_size`` bytes long."""
    limit = len(buf) if limit is None else min(limit, len(buf))
    header_size, n = read_varint(buf, start)
    if header_size < n or start + header_size > limit:
        raise RecordError(f"record header size {header_size} at {start} does not fit")
    end = start + header_size
    types: list[int] = []
    pos = start + n
    while pos < end:
        t, length = read_varint(buf, pos)
        if pos + length > end:
            raise RecordError("a serial type straddles the end of the record header")
        serial_type_size(t)  # rejects the reserved types
        types.append(t)
        pos += length
    return header_size, types, end


def parse_record(buf: bytes | memoryview, start: int, end: int | None = None, encoding: str = "UTF-8") -> Record:
    """Decode the record at ``buf[start:]``. If ``end`` is given the record must fit within it (it may be shorter)."""
    limit = len(buf) if end is None else min(end, len(buf))
    header_size, types, header_end = parse_record_header(buf, start, limit)
    pos = header_end
    values: list[Any] = []
    for t in types:
        size = serial_type_size(t)
        if pos + size > limit:
            raise RecordError(f"column body of {size} bytes at {pos} runs past the record limit {limit}")
        values.append(decode_value(t, memoryview(buf)[pos:pos + size], encoding))
        pos += size
    return Record(start=start, header_size=header_size, serial_types=tuple(types), values=tuple(values), header_end=header_end, end=pos)


def body_length(serial_types: Sequence[int]) -> int:
    return sum(serial_type_size(t) for t in serial_types)


# ------------------------------------------------------------------ payload spill (overflow) arithmetic


def local_payload_size(payload_size: int, usable_size: int, *, index: bool) -> int:
    """Bytes of a cell's payload kept on the b-tree page (the rest spills to overflow pages).

    With ``U`` the usable page size and ``P`` the payload size: table leaf cells may keep ``X = U-35`` bytes, index cells
    ``X = ((U-12)*64/255) - 23``; when ``P > X`` the local size is ``K = M + ((P-M) mod (U-4))`` if that is ≤ X, else
    ``M = ((U-12)*32/255) - 23``. (fileformat2, "B-tree Pages", cell payload)."""
    x = ((usable_size - 12) * 64 // 255) - 23 if index else usable_size - 35
    if payload_size <= x:
        return payload_size
    m = ((usable_size - 12) * 32 // 255) - 23
    k = m + ((payload_size - m) % (usable_size - 4))
    return k if k <= x else m


def to_signed64(value: int) -> int:
    """Rowids are stored as unsigned varints holding a two's-complement 64-bit value."""
    return value - (1 << 64) if value >= 1 << 63 else value


# ------------------------------------------------------------------ encoding (test fixtures and the deletion lab's ground truth)


def serial_type_for(value: Any) -> int:
    """The serial type SQLite (schema format 4) writes for ``value``: 0/1 use the zero-byte types 8 and 9, other integers
    the narrowest width that holds them."""
    if value is None:
        return 0
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        if value == 0:
            return 8
        if value == 1:
            return 9
        for t, bits in ((1, 8), (2, 16), (3, 24), (4, 32), (5, 48), (6, 64)):
            if -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
                return t
        raise ValueError("integer does not fit in 64 bits")
    if isinstance(value, float):
        return 7
    if isinstance(value, str):
        return 13 + 2 * len(value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray)):
        return 12 + 2 * len(value)
    raise TypeError(f"cannot store {type(value).__name__}")


def encode_value(serial_type: int, value: Any) -> bytes:
    if serial_type in (0, 8, 9):
        return b""
    if serial_type in (1, 2, 3, 4, 5, 6):
        return int(value).to_bytes(serial_type_size(serial_type), "big", signed=True)
    if serial_type == 7:
        return struct.pack(">d", value)
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def encode_record(values: Sequence[Any]) -> bytes:
    """A record for ``values`` exactly as SQLite lays it out (UTF-8 text)."""
    types = [serial_type_for(v) for v in values]
    types_bytes = b"".join(encode_varint(t) for t in types)
    size = len(types_bytes) + 1
    while varint_length(size) + len(types_bytes) != size:  # the header size counts its own varint
        size = varint_length(size) + len(types_bytes)
    return encode_varint(size) + types_bytes + b"".join(encode_value(t, v) for t, v in zip(types, values))


def encode_table_leaf_cell(rowid: int, record: bytes) -> bytes:
    """``[payload size][rowid][payload]`` — a table-leaf cell whose payload fits on the page."""
    return encode_varint(len(record)) + encode_varint(rowid & ((1 << 64) - 1)) + record
