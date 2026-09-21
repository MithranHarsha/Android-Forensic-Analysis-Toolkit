"""Pure-Python SQLite database header parser (first 100 bytes).

Implemented without the ``sqlite3`` module on purpose: it must work on damaged files that
the SQLite library refuses to open, and Review 2's page-level engine builds on it.
Reference: https://www.sqlite.org/fileformat2.html#the_database_header
"""

from __future__ import annotations

import struct
from pathlib import Path

from pydantic import BaseModel, Field

from android_forensics.filesystem.classifier import SQLITE_MAGIC
from android_forensics.readonly import open_readonly

HEADER_SIZE = 100
_ENCODINGS = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}


class SQLiteHeader(BaseModel):
    magic_ok: bool
    page_size: int | None = None
    write_version: int | None = None
    read_version: int | None = None
    reserved_bytes: int | None = None
    max_payload_fraction: int | None = None
    min_payload_fraction: int | None = None
    leaf_payload_fraction: int | None = None
    file_change_counter: int | None = None
    page_count: int | None = None
    first_freelist_trunk: int | None = None
    freelist_page_count: int | None = None
    schema_cookie: int | None = None
    schema_format: int | None = None
    largest_root_page: int | None = None
    text_encoding: str | None = None
    user_version: int | None = None
    incremental_vacuum: int | None = None
    auto_vacuum: str | None = None
    application_id: int | None = None
    version_valid_for: int | None = None
    sqlite_version_number: int | None = None
    journal_mode: str | None = None
    fatal: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.magic_ok and not self.fatal


class HeaderReport(BaseModel):
    header: SQLiteHeader
    actual_size: int
    expected_size: int | None = None
    size_consistent: bool | None = None
    notes: list[str] = Field(default_factory=list)


def parse_header(data: bytes) -> SQLiteHeader:
    if len(data) < HEADER_SIZE:
        return SQLiteHeader(magic_ok=data.startswith(SQLITE_MAGIC), fatal=[f"header truncated ({len(data)} < 100 bytes)"])
    if not data.startswith(SQLITE_MAGIC):
        return SQLiteHeader(magic_ok=False, fatal=["SQLite magic string absent"])

    (page_raw,) = struct.unpack(">H", data[16:18])
    write_v, read_v, reserved, max_f, min_f, leaf_f = struct.unpack(">6B", data[18:24])
    (change, pages, trunk, free_pages, cookie, fmt, _cache, largest_root, enc, user_v, incr, app_id) = struct.unpack(
        ">12I", data[24:72]
    )
    (valid_for, sqlite_ver) = struct.unpack(">2I", data[92:100])

    fatal: list[str] = []
    warnings: list[str] = []
    page_size = 65536 if page_raw == 1 else page_raw
    if page_raw != 1 and (page_raw < 512 or page_raw & (page_raw - 1)):
        fatal.append(f"invalid page size {page_raw}")
        page_size = None
    # A database that has never had a table (only a pragma set) leaves both fields 0 until its first schema is written;
    # SQLite opens it happily. Either field being 0 *alone*, or any other unknown value, is corruption.
    no_schema_yet = enc == 0 and fmt == 0
    if no_schema_yet:
        warnings.append("text encoding and schema format are both 0: the database has never had a schema (newly created and still empty)")
    if enc not in _ENCODINGS and not no_schema_yet:
        fatal.append(f"invalid text encoding code {enc}")
    if fmt not in (1, 2, 3, 4) and not no_schema_yet:
        fatal.append(f"invalid schema format number {fmt}")
    if (max_f, min_f, leaf_f) != (64, 32, 32):
        fatal.append(f"payload fractions {max_f}/{min_f}/{leaf_f} != 64/32/32")
    if write_v not in (1, 2) or read_v not in (1, 2):
        warnings.append(f"unusual file-format versions write={write_v} read={read_v}")
    if page_size and page_size - reserved < 480:
        fatal.append(f"usable page size {page_size - reserved} < 480")
    if free_pages and not trunk:
        warnings.append("freelist page count > 0 but no freelist trunk page pointer")
    if pages and free_pages > pages:
        fatal.append(f"freelist count {free_pages} exceeds page count {pages}")

    return SQLiteHeader(
        magic_ok=True,
        page_size=page_size,
        write_version=write_v,
        read_version=read_v,
        reserved_bytes=reserved,
        max_payload_fraction=max_f,
        min_payload_fraction=min_f,
        leaf_payload_fraction=leaf_f,
        file_change_counter=change,
        page_count=pages,
        first_freelist_trunk=trunk,
        freelist_page_count=free_pages,
        schema_cookie=cookie,
        schema_format=fmt,
        largest_root_page=largest_root,
        text_encoding=_ENCODINGS.get(enc),
        user_version=user_v,
        incremental_vacuum=incr,
        auto_vacuum="none" if largest_root == 0 else ("incremental" if incr else "full"),
        application_id=app_id,
        version_valid_for=valid_for,
        sqlite_version_number=sqlite_ver,
        journal_mode="wal" if (write_v == 2 and read_v == 2) else "rollback",
        fatal=fatal,
        warnings=warnings,
    )


def inspect_database_file(path: Path) -> HeaderReport:
    actual = path.stat().st_size
    with open_readonly(path) as fh:
        header = parse_header(fh.read(HEADER_SIZE))
    report = HeaderReport(header=header, actual_size=actual)
    if not header.valid or not header.page_size:
        return report
    ps = header.page_size
    if header.version_valid_for == header.file_change_counter and header.page_count:
        report.expected_size = header.page_count * ps
        report.size_consistent = report.expected_size == actual
        if not report.size_consistent:
            kind = "truncated" if actual < report.expected_size else "has trailing data"
            report.notes.append(
                f"header declares {header.page_count} pages ({report.expected_size} bytes) but file is {actual} bytes — {kind}"
            )
    else:
        report.expected_size = (actual // ps) * ps
        report.size_consistent = actual % ps == 0
        report.notes.append(
            "in-header page count is stale (version-valid-for != change counter; normal for WAL-mode "
            "databases); size checked as a multiple of the page size only"
        )
        if not report.size_consistent:
            report.notes.append(f"file size {actual} is not a multiple of page size {ps} — truncated or damaged")
    return report
