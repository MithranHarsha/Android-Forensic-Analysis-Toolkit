"""The scan-speed rewrite (``cell_header`` once per offset, dispatch by column count) must find *exactly* what the original
per-model ``try_full`` found. The original is kept below verbatim as the oracle."""

from __future__ import annotations

import sqlite3

from hypothesis import given, settings
from hypothesis import strategies as st

from android_forensics.models.unknown import UNKNOWN
from android_forensics.sqlite.ddl import parse_create_table
from android_forensics.sqlite.parser import SQLiteDatabase
from android_forensics.sqlite.records import RecordError, parse_record, read_varint, serial_type_size, to_signed64  # noqa: F401
from android_forensics.sqlite.recovery import (
    _RANK,
    MAX_ROWID_BYTES,
    MIN_FIT,
    Candidate,
    RecoveredRow,
    TableModel,
    _fit_and_decode,
    _subsumes,
    scan_page_detailed,
    schema_consistent,
    try_full,
)
from tests.unit.recovery_fixtures import CALLS_DDL, NOTES_DDL, SMS_DDL


def reference_try_full(data: bytes | memoryview, start: int, limit: int, model: TableModel, encoding: str) -> Candidate | None:
    """``[payload size][rowid][record]`` at ``start``, ending no later than ``limit``, and *exactly* filling its payload size."""
    try:
        plen, n1 = read_varint(data, start)
        if plen < model.width or start + n1 + plen > limit:
            return None
        rowid_raw, n2 = read_varint(data, start + n1)
        if n2 > MAX_ROWID_BYTES:
            return None
        pos = start + n1 + n2
        end = pos + plen
        if end > limit:
            return None  # the payload starts after the rowid: check the whole cell against the limit
        header_size, hn = read_varint(data, pos)
        if header_size < 1 + model.width or header_size > plen:
            return None
        types: list[int] = []
        p = pos + hn
        while p < pos + header_size:
            t, tn = read_varint(data, p)
            if p + tn > pos + header_size:
                return None
            serial_type_size(t)
            types.append(t)
            p += tn
        if len(types) != model.width or header_size + sum(serial_type_size(t) for t in types) != plen:
            return None
    except RecordError:
        return None
    values, fit, issues, corrupted = _fit_and_decode(model, types, memoryview(data)[pos + header_size:end], encoding)
    if not values or fit < MIN_FIT or not schema_consistent(model, values):
        return None
    rowid = to_signed64(rowid_raw)
    if model.alias_index is not None:
        values[model.alias_index] = rowid
    return Candidate(model.name, "full", start, end - start, rowid, values, fit, issues, corrupted)




def models() -> list[TableModel]:
    return [m for m in (TableModel.from_sql(parse_create_table(d)) for d in (SMS_DDL, CALLS_DDL, NOTES_DDL,
            "CREATE TABLE t3(a TEXT, b INTEGER, c TEXT)", "CREATE TABLE t4(a INTEGER, b TEXT, c TEXT, d INTEGER)")) if m is not None]


def pages(tmp_path) -> list[bytes]:
    db = tmp_path / "e.db"
    c = sqlite3.connect(db)
    c.executescript(SMS_DDL + ";" + CALLS_DDL + ";" + NOTES_DDL + ";")
    c.executemany("INSERT INTO sms(_id,address,date,type,body) VALUES(?,?,?,?,?)", [(i, f"+1202555{i:04d}", 1709280000000 + i, 1 + i % 2, f"body {i} " * 5) for i in range(1, 400)])
    c.executemany("INSERT INTO calls(_id,number,date,duration,type) VALUES(?,?,?,?,?)", [(i, f"+1202556{i:04d}", 1709280000000 + i, i, 1 + i % 3) for i in range(1, 300)])
    c.executemany("INSERT INTO notes(_id,title,content,created_at,modified_at) VALUES(?,?,?,?,?)", [(i, f"title {i}", "x" * (i % 80), i, i) for i in range(1, 200)])
    c.commit()
    c.execute("DELETE FROM sms WHERE _id % 3 = 0")
    c.execute("DELETE FROM calls WHERE _id % 4 = 0")
    c.commit()
    c.close()
    with SQLiteDatabase.open(db) as d:
        return [d.read_page(n) for n in range(1, d.page_count + 1)]


def same(a: Candidate | None, b: Candidate | None) -> bool:
    return a == b


def test_every_offset_of_real_pages_agrees_with_the_oracle(tmp_path):
    ms = models()
    checked = 0
    for page in pages(tmp_path):
        for s in range(0, len(page) - 4):
            for m in ms:
                assert same(try_full(page, s, len(page), m, "UTF-8"), reference_try_full(page, s, len(page), m, "UTF-8")), (s, m.name)
            checked += 1
    assert checked > 10_000


@settings(max_examples=200, deadline=None)
@given(st.binary(min_size=16, max_size=600), st.integers(0, 20))
def test_random_bytes_agree_with_the_oracle(data, start):
    for m in models():
        assert same(try_full(data, start, len(data), m, "UTF-8"), reference_try_full(data, start, len(data), m, "UTF-8"))


def test_scan_page_finds_the_same_candidates_as_scanning_with_the_oracle(tmp_path):
    ms = models()
    for number, page in enumerate(pages(tmp_path), 1):
        kept, _page, _unparsed = scan_page_detailed(number, page, ms, "UTF-8")
        # the optimised scan visits each offset once and dispatches by column count; every candidate it reports must be
        # reproducible by the oracle at the same offset for the same table
        for c in kept:
            if c.kind == "full":
                model = next(m for m in ms if m.name == c.table)
                ref = reference_try_full(page, c.offset, len(page), model, "UTF-8")
                assert ref is not None and ref.values == c.values and ref.length == c.length


# ---------------------------------------------------------------------------- de-duplication: indexed == linear scan

def reference_merge_duplicates(rows: list[RecoveredRow], aliases: dict[str, str | None] | None = None) -> list[RecoveredRow]:
    """The same row in several places is one deleted record: keep the most complete instance and list the other locations.
    A partial row merges into a more complete one when everything it knows agrees with it."""
    aliases = aliases or {}
    ordered = sorted(rows, key=lambda r: (-_RANK[r.status], -sum(v is not UNKNOWN for v in r.values.values()), -r.fit,
                                         r.source != "main", r.page_number, r.page_offset))
    kept: list[RecoveredRow] = []
    for r in ordered:
        home = next((k for k in kept if _subsumes(k, r, aliases.get(r.table)) or (k.values == r.values and k.table == r.table)), None)
        if home is None:
            kept.append(r)
            continue
        if r.location not in home.also_found_at:
            home.also_found_at.append(r.location)
        if r.rowid is not None and home.rowid is None:
            home.also_found_at.append(f"rowid {r.rowid} known from {r.location}")
    return sorted(kept, key=lambda r: (r.table, r.source, r.page_number, r.page_offset))



def _row(i: int, table: str, values: dict, status="RECOVERED", rowid=None, page=1, off=0, source="main", fit=1.0):
    from android_forensics.models import ArtifactStatus
    return RecoveredRow(table=table, values=values, rowid=rowid, status=ArtifactStatus(status), method="RAW_PAGE_SCAN", source=source,
                        source_path="x", page_number=page, page_offset=off, file_offset=i, length=10, raw=b"", page_type=None, region="r",
                        cell_index=None, fit=fit, issues=[], unknown_columns=[], frame=None)


_VAL = st.one_of(st.integers(-3, 3), st.sampled_from(["a", "b", "c"]), st.none(), st.just(b"\x01"), st.floats(allow_nan=False, width=16))


@settings(max_examples=300, deadline=None)
@given(st.lists(st.tuples(st.sampled_from(["t1", "t2"]), st.sampled_from(["RECOVERED", "PARTIAL", "CORRUPTED"]),
                          st.lists(st.one_of(_VAL, st.just("UNKNOWN")), min_size=3, max_size=4), st.integers(1, 3), st.integers(0, 40),
                          st.sampled_from(["main", "wal"])), max_size=40))
def test_indexed_merge_equals_the_linear_scan(items):
    from android_forensics.sqlite.recovery import _merge_duplicates

    def build():
        rows = []
        for i, (table, status, vals, page, off, source) in enumerate(items):
            cols = {f"c{n}": (UNKNOWN if v == "UNKNOWN" else v) for n, v in enumerate(vals)}
            rows.append(_row(i, table, cols, status, rowid=None if status == "PARTIAL" else i, page=page, off=off, source=source))
        return rows

    aliases = {"t1": "c0", "t2": None}
    new = _merge_duplicates(build(), aliases)
    old = reference_merge_duplicates(build(), aliases)
    key = lambda rs: [(r.table, r.source, r.page_number, r.page_offset, r.status, r.rowid, tuple(sorted(r.also_found_at)), repr(sorted(r.values.items(), key=lambda kv: kv[0]))) for r in rs]  # noqa: E731
    assert key(new) == key(old)


def test_merge_is_no_longer_quadratic():
    import time

    from android_forensics.sqlite.recovery import _merge_duplicates

    def run(n):
        rows = [_row(i, "q", {"a": f"row{i:06d}", "b": i, "c": "x" * 20}, rowid=i, page=1 + i // 40, off=(i % 40) * 20) for i in range(n)]
        t = time.perf_counter()
        out = _merge_duplicates(rows, {})
        assert len(out) == n
        return time.perf_counter() - t

    run(500)   # warm up
    t_big = run(8000)
    # the linear scan needs ~n²/2 = 32 million predicate calls here (many seconds, minutes on a slow runner); the index needs milliseconds
    assert t_big < 2.0, f"merging 8,000 rows took {t_big:.2f}s: the de-duplication has become quadratic again"
