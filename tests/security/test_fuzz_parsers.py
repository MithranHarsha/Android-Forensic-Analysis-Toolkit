"""Property-based fuzzing: hostile bytes must produce a *declared* error or a result — never an unexpected exception,
a hang or an unbounded allocation. Run a longer campaign with  HYPOTHESIS_PROFILE=ci  (or =soak)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from android_forensics.acquisition.safety import UnsafePathError, normalize_member_path
from android_forensics.sqlite.ddl import DdlError, parse_create_table
from android_forensics.sqlite.header import parse_header
from android_forensics.sqlite.records import RecordError, parse_record, read_varint

FIX = Path(__file__).resolve().parents[1] / "fixtures"
BLOB = st.binary(max_size=4096)


# ---------------------------------------------------------------------------- pure functions


@given(st.text(max_size=200))
def test_member_paths_are_safe_or_rejected(name):
    try:
        out = normalize_member_path(name)
    except UnsafePathError:
        return
    parts = out.split("/")
    assert ".." not in parts and "" not in parts and "." not in parts
    assert not out.startswith("/") and "\x00" not in out and "\\" not in out
    assert not (len(out) >= 2 and out[1] == ":" and out[0].isascii() and out[0].isalpha())


@given(st.lists(st.sampled_from(["..", ".", "", "a", "b c", "ü", "\\", "C:", "\x00", "…"]), max_size=12).map("/".join))
def test_traversal_shaped_member_paths(name):
    try:
        out = normalize_member_path(name)
    except UnsafePathError:
        return
    assert ".." not in out.split("/") and not out.startswith("/")


@given(BLOB, st.integers(min_value=0, max_value=5000))
def test_varint_never_over_reads(buf, pos):
    try:
        value, length = read_varint(buf, pos)
    except RecordError:
        return
    assert 0 <= value < 2**64 and 1 <= length <= 9 and pos + length <= len(buf)


@given(BLOB)
def test_record_parser_only_raises_its_own_error(buf):
    try:
        parse_record(buf, 0)
    except RecordError:
        pass


@given(BLOB)
def test_header_parser_never_raises(buf):
    parse_header(buf)


@given(st.text(max_size=300))
def test_ddl_parser(sql):
    try:
        parse_create_table("CREATE TABLE " + sql)
    except DdlError:
        pass


_DDL_PIECES = st.sampled_from(["(", ")", ",", ".", "a", "b INTEGER", "PRIMARY KEY", "PRIMARY", "KEY", "CONSTRAINT", "c", "NOT NULL",
                               "DEFAULT", "'x'", '"q"', "[r]", "`s`", "GENERATED ALWAYS AS (", "AUTOINCREMENT", "UNIQUE", "CHECK(", " ", "--", "/*"])


@given(st.lists(_DDL_PIECES, max_size=25).map(" ".join))
def test_ddl_parser_on_structured_garbage(body):
    for prefix in ("CREATE TABLE t(", "CREATE TABLE s.t(", "CREATE TABLE IF NOT EXISTS t (", "CREATE VIRTUAL TABLE v USING "):
        try:
            parse_create_table(prefix + body)
        except DdlError:
            pass


@pytest.mark.parametrize("sql", ["CREATE TABLE :.", "CREATE TABLE s.", "CREATE TABLE t(", "CREATE TABLE", "CREATE"])
def test_ddl_regressions_found_by_fuzzing(sql):
    with pytest.raises(DdlError):
        parse_create_table(sql)


@pytest.mark.parametrize("sql", ["CREATE TABLE t(a,,b)", "CREATE TABLE t(,)", "CREATE TABLE t(PRIMARY KEY())", "CREATE TABLE t(a, PRIMARY KEY(,))"])
def test_ddl_odd_but_survivable(sql):
    try:
        parse_create_table(sql)
    except DdlError:
        pass
