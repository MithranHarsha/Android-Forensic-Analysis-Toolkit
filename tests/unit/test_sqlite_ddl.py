"""The CREATE TABLE reader agrees with SQLite's own PRAGMA table_xinfo — on hand-written and real Android schemas."""

import re
import sqlite3
from pathlib import Path

import pytest

from android_forensics.sqlite.ddl import DdlError, parse_create_table, tokenize

STATEMENTS = [
    "CREATE TABLE t(a, b, c)",
    "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INT DEFAULT 18, score REAL, photo BLOB)",
    "CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)",
    'CREATE TABLE "we""ird [name]"("select" TEXT, "with space" INT, [bracketed] REAL, `back` BLOB)',
    "CREATE TABLE t(a VARCHAR(20), b DECIMAL(10, 5), c UNSIGNED BIG INT, d DOUBLE PRECISION, e NATIVE CHARACTER(70))",
    "CREATE TABLE t(a INT, b TEXT, PRIMARY KEY(b, a))",
    "CREATE TABLE t(a INTEGER, b INTEGER, PRIMARY KEY(a, b))",
    "CREATE TABLE t(a INTEGER, PRIMARY KEY(a))",
    "CREATE TABLE t(a INTEGER, PRIMARY KEY(a DESC))",
    "CREATE TABLE t(a INTEGER PRIMARY KEY DESC, b)",
    "CREATE TABLE t(a INT PRIMARY KEY, b)",
    "CREATE TABLE t(a integer PRIMARY KEY, b)",
    "CREATE TABLE t(a INTEGER PRIMARY KEY ASC ON CONFLICT REPLACE, b)",
    "CREATE TABLE t(a TEXT PRIMARY KEY, b) WITHOUT ROWID",
    "CREATE TABLE t(id INTEGER PRIMARY KEY, v) WITHOUT ROWID",
    "CREATE TABLE t(a INT NOT NULL DEFAULT (1+2), b TEXT DEFAULT 'x, y', c REAL DEFAULT -1.5, d DEFAULT CURRENT_TIMESTAMP)",
    "CREATE TABLE t(a INT, b INT GENERATED ALWAYS AS (a*2) VIRTUAL, c INT GENERATED ALWAYS AS (a+1) STORED, d INT AS (a) )",
    "CREATE TABLE t(a INT CHECK (a > 0 AND a < (10)), b TEXT COLLATE NOCASE, c INT REFERENCES o(id) ON DELETE CASCADE, d UNIQUE)",
    "CREATE TABLE t(a, b, CONSTRAINT pk PRIMARY KEY (a), CONSTRAINT u UNIQUE (b), CHECK (a != b), FOREIGN KEY(b) REFERENCES o(id))",
    "CREATE TABLE t(a INTEGER CONSTRAINT pkc PRIMARY KEY, b)",
    "CREATE TABLE IF NOT EXISTS main.t(a, b)",
    "CREATE TEMP TABLE t(a, b)",
    "CREATE TABLE t(-- comment, with commas\n a INT, /* block, comment */ b TEXT)",
    "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT) STRICT" if sqlite3.sqlite_version_info >= (3, 37, 0) else "CREATE TABLE t(a INTEGER PRIMARY KEY, b)",
    "CREATE TABLE t(\"quoted pk\" INTEGER PRIMARY KEY, b)",
    "CREATE TABLE t(a INT, a2 INT, PRIMARY KEY(a2))",
]


def norm_type(t: str) -> str:
    return re.sub(r"\s+", "", t or "").upper()


@pytest.mark.parametrize("sql", STATEMENTS)
def test_columns_match_pragma_table_xinfo(sql):
    if "GENERATED" in sql or " AS (" in sql:
        if sqlite3.sqlite_version_info < (3, 31, 0):
            pytest.skip("generated columns need SQLite 3.31")
    conn = sqlite3.connect(":memory:")
    conn.execute(sql)
    name = parse_create_table(sql).name
    quoted = name.replace('"', '""')
    truth = conn.execute(f'PRAGMA table_xinfo("{quoted}")').fetchall()  # cid, name, type, notnull, dflt, pk, hidden
    parsed = parse_create_table(sql)
    assert [(c.name, norm_type(c.declared_type), c.not_null, c.primary_key_position) for c in parsed.columns] == [
        (r[1], norm_type(r[2]), bool(r[3]), r[5]) for r in truth]
    assert [c.generated for c in parsed.columns] == [{2: "virtual", 3: "stored"}.get(r[6]) for r in truth]
    assert [c.default_sql is not None for c in parsed.columns] == [r[4] is not None for r in truth]
    # a rowid alias is exactly what SQLite says is one: INTEGER PRIMARY KEY without an autoindex for the key
    indexes = conn.execute(f'PRAGMA index_list("{quoted}")').fetchall()
    pk_columns = [r for r in truth if r[5]]
    sqlite_alias = (
        not parsed.without_rowid and len(pk_columns) == 1 and norm_type(pk_columns[0][2]) == "INTEGER" and not any(ix[3] == "pk" for ix in indexes)
    )
    assert (parsed.rowid_alias is not None) == sqlite_alias, sql
    assert parsed.without_rowid == ("WITHOUT ROWID" in sql.upper())
    assert parsed.autoincrement == ("AUTOINCREMENT" in sql.upper())


def test_stored_columns_exclude_virtual_generated_ones():
    if sqlite3.sqlite_version_info < (3, 31, 0):
        pytest.skip("generated columns need SQLite 3.31")
    t = parse_create_table("CREATE TABLE t(a INT, b INT AS (a*2), c INT AS (a+1) STORED)")
    assert [c.name for c in t.stored_columns] == ["a", "c"]


def test_primary_key_order_and_names():
    t = parse_create_table("CREATE TABLE t(a INT, b TEXT, c, PRIMARY KEY(b, a))")
    assert t.primary_key == ("b", "a") and t.rowid_alias is None


def test_virtual_tables_are_recognised_but_have_no_columns():
    t = parse_create_table("CREATE VIRTUAL TABLE docs USING fts5(title, body)")
    assert t.virtual and t.name == "docs" and t.columns == ()


@pytest.mark.parametrize("bad", ["SELECT 1", "CREATE INDEX i ON t(a)", "CREATE TABLE", "CREATE TABLE t AS SELECT 1", "CREATE TABLE t(a, b"])
def test_things_that_are_not_create_table_statements_are_refused(bad):
    with pytest.raises(DdlError):
        parse_create_table(bad)


def test_tokenizer_handles_quotes_comments_and_numbers():
    toks = tokenize("a 'it''s' \"q\"\"x\" [br] -- c\n 1.5e3 0x1F /* x */ ;")
    assert [(t.kind, t.text) for t in toks] == [
        ("word", "a"), ("string", "it's"), ("quoted", 'q"x'), ("quoted", "br"), ("number", "1.5e3"), ("number", "0x1F"), ("punct", ";")]


def test_every_table_of_the_synthetic_android_databases(synth):
    out, _ = synth
    checked = 0
    for db in sorted(Path(out / "android_dump").rglob("*")):
        if not db.is_file() or not (db.suffix == ".db" or db.name == "History"):
            continue
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            rows = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL").fetchall()
        except sqlite3.DatabaseError:
            continue  # the deliberately truncated / encrypted databases
        for name, sql in rows:
            parsed = parse_create_table(sql)
            truth = conn.execute(f'PRAGMA table_xinfo("{name}")').fetchall()
            assert [(c.name, c.primary_key_position) for c in parsed.columns] == [(r[1], r[5]) for r in truth], (db.name, name)
            checked += 1
    assert checked >= 20
