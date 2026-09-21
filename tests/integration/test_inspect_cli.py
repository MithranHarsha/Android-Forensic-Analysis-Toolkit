"""``android-forensics inspect``: normal inspection of one database from the command line."""

import os
import sqlite3

import pytest
from typer.testing import CliRunner

from android_forensics.cli.app import app
from android_forensics.sqlite.inspection import DatabaseInspection
from tests.conftest import tree_hash
from tests.unit.sqlite_helpers import build, numbered_db, wal_snapshot

runner = CliRunner()
WIDE = {"COLUMNS": "220"}


def run(*args, expect=0):
    r = runner.invoke(app, ["inspect", *[str(a) for a in args]], env=WIDE, catch_exceptions=False)
    assert r.exit_code == expect, r.output
    return r


@pytest.fixture()
def db(tmp_path):
    return build(tmp_path / "ev" / "app.db", """
        CREATE TABLE people(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INT, photo BLOB, seen DATETIME);
        CREATE INDEX idx_name ON people(name);
        CREATE TABLE tags(k TEXT PRIMARY KEY, v) WITHOUT ROWID;
        INSERT INTO people(name, age, photo, seen) VALUES('Ann', 30, x'00ff10', 1709280000), ('Bob', NULL, NULL, '2024-03-01 08:00:00');
        INSERT INTO tags VALUES('a', 1), ('b', 2.5);
    """)


def test_the_text_view_shows_metadata_schema_and_rows(db):
    out = run(db).stdout
    for expected in ("SQLite database", "SHA-256", "VALID", "Page size", "4,096 B", "Last written by", "SQLite 3.", "Schema format",
                     "Tables (3)", "people", "id INTEGER", "name TEXT NOT NULL", "AUTOINCREMENT", "rowid = id", "idx_name",
                     "WITHOUT ROWID", "NULL", "<blob 3 B 00ff10>", "Deleted-data recovery is Review 2"):
        assert expected in out, expected
    assert "Ann" in out and "Bob" in out and "2024-03-01 08:00:00" in out


def test_json_is_the_complete_typed_inspection(db):
    result = DatabaseInspection.model_validate_json(run(db, "--json").stdout)
    assert result.file.path == str(db.resolve()) and result.table("people").row_count == 2 and len(result.table("people").records) == 2
    assert [r.rowid for r in result.table("people").records] == [1, 2] and result.table("tags").without_rowid
    assert result.table("people").records[0].values[3].data == bytes([0, 0xFF, 0x10])


def test_rows_option_caps_records_and_says_so(db):
    result = DatabaseInspection.model_validate_json(run(db, "--json", "--rows", "1").stdout)
    people = result.table("people")
    assert len(people.records) == 1 and people.row_count == 2 and people.records_truncated
    assert "1 of 2 rows" in run(db, "--rows", "1").stdout


def test_no_records_gives_schema_and_counts_only(db):
    result = DatabaseInspection.model_validate_json(run(db, "--json", "--no-records").stdout)
    assert result.record_count == 0 and result.table("people").row_count == 2 and result.header.valid
    assert "of 2 rows" not in run(db, "--no-records").stdout


def test_table_option_restricts_the_rows_not_the_schema(db):
    result = DatabaseInspection.model_validate_json(run(db, "--json", "--table", "tags").stdout)
    assert len(result.table("tags").records) == 2 and result.table("people").records == [] and result.table("people").columns


def test_wide_tables_are_shown_one_record_at_a_time(tmp_path):
    cols = ", ".join(f"c{i} INTEGER" for i in range(15))
    p = build(tmp_path / "w.db", f"CREATE TABLE wide(id INTEGER PRIMARY KEY, {cols}); INSERT INTO wide VALUES(1, {', '.join(str(i) for i in range(15))});")
    out = run(p).stdout
    assert "wide · rowid 1" in out and "c14 INTEGER" in out and "integer" in out


def test_the_wal_is_applied_by_default_and_left_out_on_request(tmp_path):
    p = wal_snapshot(tmp_path / "ev")
    with_wal = DatabaseInspection.model_validate_json(run(p, "--json").stdout)
    without = DatabaseInspection.model_validate_json(run(p, "--json", "--no-sidecars").stdout)
    assert (with_wal.table("t").row_count, without.table("t").row_count) == (8, 5)
    assert "main file + committed WAL frames" in run(p).stdout and "WAL" in run(p).stdout


def test_a_damaged_database_is_described_not_refused(tmp_path):
    p = numbered_db(tmp_path / "a.db", 300)
    p.write_bytes(p.read_bytes()[:5000])
    out = run(p).stdout
    assert "TRUNCATED" in out and "database_truncated" in out
    p2 = tmp_path / "vault.db"
    p2.write_bytes(os.urandom(8192))
    assert "ENCRYPTED_SUSPECT" in run(p2).stdout
    p3 = tmp_path / "notes.db"
    p3.write_text("just text\n" * 50)
    assert "NOT_SQLITE" in run(p3).stdout


@pytest.mark.parametrize("target,message", [("missing.db", "does not exist"), ("", "is a directory")])
def test_unusable_paths_are_clean_errors(tmp_path, target, message):
    r = runner.invoke(app, ["inspect", str(tmp_path / target)], env=WIDE)
    assert r.exit_code == 2 and message in r.output and "Traceback" not in r.output


def test_the_evidence_is_not_modified(tmp_path):
    p = wal_snapshot(tmp_path / "ev")
    before = tree_hash(tmp_path / "ev")
    run(p)
    run(p, "--json")
    assert tree_hash(tmp_path / "ev") == before


def test_evidence_text_is_shown_verbatim(tmp_path):
    """Table names and values are untrusted: Rich would swallow ``[backup]`` and choke on ``[/]``."""
    p = tmp_path / "h.db"
    c = sqlite3.connect(p)
    c.execute('CREATE TABLE "[backup]notes"("[bold red]col" TEXT)')
    c.executemany('INSERT INTO "[backup]notes" VALUES(?)', [("[Bank] Your OTP is 123456",), ("close [/] tag",), ("[link=x]y[/link]",)])
    c.commit()
    c.close()
    out = run(p).stdout
    for expected in ("[backup]notes", "[bold red]col", "[Bank] Your OTP is 123456", "close [/] tag", "[link=x]y[/link]"):
        assert expected in out, expected


def test_the_inspect_command_needs_no_case(db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path / "ev")
    run(db)
    assert sorted(x.name for x in (tmp_path / "ev").iterdir()) == ["app.db"], "nothing is written beside the database"
