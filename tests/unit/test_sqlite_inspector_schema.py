"""SQLiteInspector: header, page size, version, tables, columns, primary keys, indexes — on generated databases."""

import hashlib
import re
import sqlite3

import pytest

import android_forensics.sqlite.inspector as inspector_module
from android_forensics.models.enums import OpenStatus, SqliteStatus, TableKind, TypeAffinity
from android_forensics.sqlite.inspector import SQLiteInspector
from tests.unit.sqlite_helpers import build, fts5_available, numbered_db

RUNTIME = sqlite3.sqlite_version_info


def inspect(path, **kw):
    return SQLiteInspector.inspect(path, **kw)


def by_name(items):
    return {i.name: i for i in items}


# ------------------------------------------------------------------ header, page size, metadata


class TestHeaderAndMetadata:
    @pytest.mark.parametrize("page_size", [512, 1024, 2048, 4096, 16384, 32768, 65536])
    def test_page_size_from_the_header_and_the_engine_agree(self, tmp_path, page_size):
        r = inspect(numbered_db(tmp_path / "a.db", 60, page_size))
        assert r.header.valid and r.header.page_size == page_size and r.engine.pragmas["page_size"] == page_size
        assert r.status is SqliteStatus.VALID and r.size.consistent is True and r.size.actual_size == r.size.expected_size

    def test_page_count_matches_the_file(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 300)
        r = inspect(p)
        assert r.header.page_count == r.engine.pragmas["page_count"] == p.stat().st_size // 4096

    def test_valid_database_is_reported_valid_and_opened(self, tmp_path):
        r = inspect(numbered_db(tmp_path / "a.db"))
        assert (r.status, r.engine.open_status, r.integrity.status) == (SqliteStatus.VALID, OpenStatus.OK, "ok")
        assert r.integrity.messages == ["ok"] and r.issues == [] and r.is_readable_by_sqlite

    def test_file_facts(self, tmp_path):
        p = numbered_db(tmp_path / "sub" / "my db.db")
        r = inspect(p)
        assert r.file.path == str(p.resolve()) and r.file.name == "my db.db" and r.file.size == p.stat().st_size
        assert r.file.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", r.file.mtime)
        assert r.tool_version and r.inspected_at

    def test_relative_paths_and_str_and_path_inputs(self, tmp_path, monkeypatch):
        numbered_db(tmp_path / "a.db")
        monkeypatch.chdir(tmp_path)
        assert inspect("a.db").file.path == str((tmp_path / "a.db").resolve()) == inspect(tmp_path / "a.db").file.path

    @pytest.mark.parametrize("encoding,expected", [("UTF-8", "UTF-8"), ("UTF-16le", "UTF-16le"), ("UTF-16be", "UTF-16be")])
    def test_text_encoding_and_text_is_read_correctly(self, tmp_path, encoding, expected):
        p = build(tmp_path / "e.db", f"PRAGMA encoding='{encoding}'; CREATE TABLE t(a TEXT); INSERT INTO t VALUES('héllo wörld 😀');")
        r = inspect(p)
        assert r.header.text_encoding == expected and r.engine.pragmas["encoding"] == expected
        assert r.table("t").records[0].values == ["héllo wörld 😀"]

    def test_user_version_and_application_id(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", "PRAGMA user_version=42; PRAGMA application_id=1234567; CREATE TABLE t(a);"))
        assert (r.header.user_version, r.engine.pragmas["user_version"]) == (42, 42)
        assert (r.header.application_id, r.engine.pragmas["application_id"]) == (1234567, 1234567)

    @pytest.mark.parametrize("mode", ["NONE", "FULL", "INCREMENTAL"])
    def test_auto_vacuum(self, tmp_path, mode):
        r = inspect(build(tmp_path / "a.db", f"PRAGMA auto_vacuum={mode}; CREATE TABLE t(a); INSERT INTO t VALUES(1);"))
        assert r.header.auto_vacuum == r.engine.pragmas["auto_vacuum"] == mode.lower()

    def test_schema_cookie_grows_with_schema_changes(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE t(a);")
        first = inspect(p).header.schema_cookie
        c = sqlite3.connect(p)
        c.execute("CREATE TABLE u(b)")
        c.commit()
        c.close()
        second = inspect(p).header
        assert second.schema_cookie > first and second.schema_cookie == inspect(p).engine.pragmas["schema_version"]

    def test_freelist_is_reported_as_a_fact_after_deletion(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 400)
        c = sqlite3.connect(p)
        c.execute("DELETE FROM t WHERE id > 20")
        c.commit()
        c.close()
        r = inspect(p)
        assert r.header.freelist_page_count > 0 and r.header.freelist_page_count == r.engine.pragmas["freelist_count"]
        assert r.table("t").row_count == 20  # a *fact about free pages*, not a recovery: the deleted rows are absent

    def test_journal_mode_wal_is_read_from_the_header(self, tmp_path):
        p = build(tmp_path / "w.db", "PRAGMA journal_mode=WAL; CREATE TABLE t(a); INSERT INTO t VALUES(1);")
        r = inspect(p)
        assert r.header.journal_mode == "wal" and r.version.write_format == "WAL" and r.version.read_format == "WAL"
        assert inspect(numbered_db(tmp_path / "r.db")).version.write_format == "rollback journal"

    def test_an_empty_database_has_a_header_and_no_tables(self, tmp_path):
        p = tmp_path / "empty.db"
        c = sqlite3.connect(p)
        c.execute("PRAGMA user_version=1")  # forces the header to be written
        c.commit()
        c.close()
        r = inspect(p)
        assert r.status is SqliteStatus.VALID and r.tables == [] and r.schema_entries == [] and r.record_count == 0


class TestVersionInformation:
    def test_last_writer_version_is_the_library_that_created_the_file(self, tmp_path):
        r = inspect(numbered_db(tmp_path / "a.db"))
        assert r.header.sqlite_version_number == RUNTIME[0] * 1_000_000 + RUNTIME[1] * 1000 + RUNTIME[2]
        assert r.version.last_writer_version == sqlite3.sqlite_version
        assert r.version.last_writer_version_reliable is True and r.version.notes == []

    def test_inspecting_library_is_recorded_for_reproducibility(self, tmp_path):
        r = inspect(numbered_db(tmp_path / "a.db"))
        assert r.version.inspecting_library_version == r.engine.sqlite_library_version == sqlite3.sqlite_version

    def test_schema_format(self, tmp_path):
        v = inspect(numbered_db(tmp_path / "a.db")).version
        assert v.schema_format == 4 and v.schema_format_min_version == "3.3.0"

    def test_change_counter_and_version_valid_for(self, tmp_path):
        v = inspect(numbered_db(tmp_path / "a.db")).version
        assert v.file_change_counter and v.version_valid_for == v.file_change_counter

    def test_an_older_writer_stamp_is_decoded(self, tmp_path):
        p = numbered_db(tmp_path / "a.db")
        data = bytearray(p.read_bytes())
        data[96:100] = (3008010).to_bytes(4, "big")  # as if last written by SQLite 3.8.10
        p.write_bytes(bytes(data))
        v = inspect(p).version
        assert v.last_writer_version == "3.8.10" and v.last_writer_version_number == 3008010

    def test_a_stale_stamp_is_flagged_unreliable(self, tmp_path):
        p = numbered_db(tmp_path / "a.db")
        data = bytearray(p.read_bytes())
        data[92:96] = (999).to_bytes(4, "big")
        p.write_bytes(bytes(data))
        v = inspect(p).version
        assert v.last_writer_version_reliable is False and "may not name the latest writer" in v.notes[0]


# ------------------------------------------------------------------ tables


class TestTables:
    SCRIPT = """
        CREATE TABLE people(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INT);
        CREATE TABLE orders(id INTEGER PRIMARY KEY, person_id INT REFERENCES people(id), total REAL);
        CREATE TABLE notes(title, body);
        CREATE INDEX idx_name ON people(name);
        CREATE VIEW adults AS SELECT name FROM people WHERE age >= 18;
        CREATE TRIGGER trg AFTER INSERT ON orders BEGIN UPDATE people SET age = age WHERE id = NEW.person_id; END;
        INSERT INTO people(name, age) VALUES('Ann', 30), ('Bob', 12);
        INSERT INTO orders(person_id, total) VALUES(1, 9.5), (1, 20.0), (2, 1.25);
        INSERT INTO notes VALUES('t', 'b');
    """

    def test_every_table_is_enumerated_with_its_row_count(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", self.SCRIPT))
        counts = {t.name: t.row_count for t in r.tables}
        assert counts == {"people": 2, "orders": 3, "notes": 1, "sqlite_sequence": 1}

    def test_tables_appear_in_creation_order(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", self.SCRIPT))
        assert [t.name for t in r.tables] == ["people", "sqlite_sequence", "orders", "notes"]

    def test_views_and_triggers_are_schema_entries_not_tables(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", self.SCRIPT))
        assert [v.name for v in r.views] == ["adults"] and [t.name for t in r.triggers] == ["trg"]
        assert r.table("adults") is None and r.triggers[0].table == "orders"
        assert "SELECT name FROM people" in r.views[0].sql

    def test_schema_entries_are_sqlite_master_verbatim(self, tmp_path):
        p = build(tmp_path / "a.db", self.SCRIPT)
        r = inspect(p)
        c = sqlite3.connect(p)
        expected = c.execute("SELECT rowid, type, name, tbl_name, rootpage, sql FROM sqlite_master ORDER BY rowid").fetchall()
        c.close()
        got = [(e.rowid, e.type, e.name, e.table, e.root_page or 0, e.sql) for e in r.schema_entries]
        assert got == expected

    def test_create_statement_and_root_page_are_kept(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", self.SCRIPT)).table("people")
        assert t.sql.startswith("CREATE TABLE people(id INTEGER PRIMARY KEY AUTOINCREMENT") and t.root_page >= 2

    def test_internal_tables_are_flagged(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", self.SCRIPT + "ANALYZE;"))
        internal = {t.name for t in r.tables if t.internal}
        assert {"sqlite_sequence", "sqlite_stat1"} <= internal, "ANALYZE adds sqlite_stat1 (and stat4 on builds that have it)"
        assert all(name.startswith("sqlite_") for name in internal) and not r.table("people").internal

    def test_indexes_are_listed_with_their_table(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", self.SCRIPT))
        assert [i.name for i in r.indexes] == ["idx_name"] and r.indexes[0].table == "people"
        assert {e.name for e in r.schema_entries if e.type == "index"} == {"idx_name"}

    def test_a_table_with_no_rows_still_counts(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", "CREATE TABLE e(a, b);")).table("e")
        assert t.row_count == 0 and t.records == [] and not t.records_truncated and t.read_error is None

    def test_many_tables(self, tmp_path):
        script = "".join(f"CREATE TABLE t{i}(a INTEGER, b TEXT); INSERT INTO t{i} VALUES({i}, 'v{i}');" for i in range(40))
        r = inspect(build(tmp_path / "a.db", script))
        assert len(r.tables) == 40 and all(t.records[0].values == [int(t.name[1:]), f"v{t.name[1:]}"] for t in r.tables)

    def test_table_names_are_looked_up_case_insensitively_by_the_helper_only_as_stored(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", "CREATE TABLE MixedCase(a);"))
        assert r.table("MixedCase") is not None and r.tables[0].name == "MixedCase"

    def test_hostile_and_unusual_names_survive_exactly(self, tmp_path):
        script = '''
            CREATE TABLE "we""ird [name]"("select" TEXT, "with space" INT, "ünï" REAL, "a'b" BLOB);
            INSERT INTO "we""ird [name]" VALUES('s', 1, 2.5, x'ab');
            CREATE TABLE "order"(a);
            INSERT INTO "order" VALUES(1);
        '''
        r = inspect(build(tmp_path / "a.db", script))
        t = r.table('we"ird [name]')
        assert t is not None and [c.name for c in t.columns] == ["select", "with space", "ünï", "a'b"]
        assert t.record_dicts()[0]["ünï"] == 2.5 and r.table("order").row_count == 1

    def test_a_column_named_rowid_does_not_hide_the_real_rowid(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE t(rowid TEXT, v); INSERT INTO t VALUES('shadow', 1), ('again', 2);")
        rec = inspect(p).table("t").records
        assert [r.rowid for r in rec] == [1, 2] and [r.values[0] for r in rec] == ["shadow", "again"]

    def test_all_three_rowid_names_shadowed_leaves_the_rowid_unknown_and_says_so(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE t(rowid, oid, _rowid_); INSERT INTO t VALUES(1, 2, 3);")
        r = inspect(p)
        assert r.table("t").records[0].rowid is None and r.table("t").records[0].values == [1, 2, 3]
        assert any(i.kind == "rowid_unavailable" and i.table == "t" for i in r.issues)


class TestSpecialTables:
    def test_without_rowid(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", "CREATE TABLE w(k TEXT PRIMARY KEY, v) WITHOUT ROWID; INSERT INTO w VALUES('a', 1);")).table("w")
        assert t.without_rowid and t.primary_key == ["k"] and t.rowid_alias is None and t.records[0].rowid is None

    def test_autoincrement(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", "CREATE TABLE a(id INTEGER PRIMARY KEY AUTOINCREMENT); CREATE TABLE b(id INTEGER PRIMARY KEY);"))
        assert r.table("a").autoincrement and not r.table("b").autoincrement

    def test_keywords_inside_strings_and_comments_are_not_mistaken_for_table_options(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", "CREATE TABLE t(a TEXT DEFAULT 'WITHOUT ROWID AUTOINCREMENT', b); -- AUTOINCREMENT STRICT")).table("t")
        assert not (t.autoincrement or t.without_rowid or t.strict)

    @pytest.mark.skipif(RUNTIME < (3, 37, 0), reason="STRICT tables need SQLite 3.37")
    def test_strict_tables(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", "CREATE TABLE s(a INTEGER, b TEXT) STRICT; CREATE TABLE n(a);"))
        assert r.table("s").strict and not r.table("n").strict

    @pytest.mark.skipif(RUNTIME < (3, 31, 0), reason="generated columns need SQLite 3.31")
    def test_generated_columns_are_flagged_and_their_values_are_rows_data(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE g(a INT, b INT GENERATED ALWAYS AS (a*2) VIRTUAL, c INT GENERATED ALWAYS AS (a+1) STORED); INSERT INTO g(a) VALUES(5);")
        t = inspect(p).table("g")
        assert [(c.name, c.hidden, c.is_generated) for c in t.columns] == [("a", 0, False), ("b", 2, True), ("c", 3, True)]
        assert t.records[0].values == [5, 10, 6]

    @pytest.mark.skipif(not fts5_available(), reason="SQLite built without FTS5")
    def test_virtual_tables_and_their_shadow_tables(self, tmp_path):
        p = build(tmp_path / "f.db", "CREATE VIRTUAL TABLE docs USING fts5(title, body); INSERT INTO docs VALUES('T1', 'hello world'), ('T2', 'bye');")
        r = inspect(p)
        docs = r.table("docs")
        assert docs.kind is TableKind.VIRTUAL and docs.data_columns == ["title", "body"] and docs.row_count == 2
        assert [x.values for x in docs.records] == [["T1", "hello world"], ["T2", "bye"]] and [x.rowid for x in docs.records] == [1, 2]
        assert any(c.hidden == 1 for c in docs.columns), "FTS5's hidden columns are described but are not part of a row"
        if RUNTIME >= (3, 37, 0):
            shadows = {t.name for t in r.tables if t.kind is TableKind.SHADOW}
            assert {"docs_data", "docs_content", "docs_idx"} <= shadows

    def test_a_virtual_table_whose_module_is_missing_is_reported_and_the_rest_carries_on(self, tmp_path):
        p = build(tmp_path / "g.db", "CREATE TABLE ok(a); INSERT INTO ok VALUES(1);")
        c = sqlite3.connect(p)
        c.execute("PRAGMA writable_schema=ON")
        c.execute("INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql) VALUES('table','ghost','ghost',0,'CREATE VIRTUAL TABLE ghost USING nosuchmodule(a)')")
        c.commit()
        c.close()
        r = inspect(p)
        ghost = r.table("ghost")
        assert r.engine.open_status is OpenStatus.OK and r.table("ok").records[0].values == [1]
        assert ghost.kind is TableKind.VIRTUAL and "no such module" in ghost.read_error and ghost.columns == [] and ghost.row_count is None
        assert any(i.kind == "schema_read_error" and i.table == "ghost" for i in r.issues)

    def test_the_fallback_without_table_list_reads_the_create_statement(self, tmp_path, monkeypatch):
        script = ("CREATE TABLE plain(a); CREATE TABLE w(k PRIMARY KEY, v) WITHOUT ROWID; CREATE VIRTUAL TABLE r USING rtree(id, x1, x2);"
                  + ("CREATE TABLE s(a INTEGER) STRICT; CREATE TABLE ws(k TEXT PRIMARY KEY) WITHOUT ROWID, STRICT;" if RUNTIME >= (3, 37, 0) else ""))
        p = build(tmp_path / "a.db", script)
        normal = inspect(p)
        monkeypatch.setattr(inspector_module, "_table_list", lambda conn: None)
        fallback = inspect(p)
        shadows = {"r_node", "r_parent", "r_rowid"}  # the R-Tree module's own tables
        flags = lambda r: {t.name: (t.kind, t.without_rowid, t.strict) for t in r.tables if t.name not in shadows}  # noqa: E731
        assert flags(fallback) == flags(normal)
        assert flags(normal)["w"][1] and flags(normal)["r"][0] is TableKind.VIRTUAL
        # Only PRAGMA table_list knows a table belongs to a virtual-table module; without it they read as ordinary tables.
        assert {t.kind for t in normal.tables if t.name in shadows} == {TableKind.SHADOW}
        assert {t.kind for t in fallback.tables if t.name in shadows} == {TableKind.TABLE}


# ------------------------------------------------------------------ columns


class TestColumns:
    def test_declared_types_and_affinities(self, tmp_path):
        script = ("CREATE TABLE c(a INTEGER, b TEXT, c REAL, d BLOB, e NUMERIC, f, g VARCHAR(20), h BIGINT, i DOUBLE, j DATETIME, "
                  "k BOOLEAN, l DECIMAL(10,2), m POINT);")
        cols = inspect(build(tmp_path / "a.db", script)).table("c").columns
        assert [(c.name, c.declared_type, c.affinity.value) for c in cols] == [
            ("a", "INTEGER", "INTEGER"), ("b", "TEXT", "TEXT"), ("c", "REAL", "REAL"), ("d", "BLOB", "BLOB"), ("e", "NUMERIC", "NUMERIC"),
            ("f", "", "BLOB"), ("g", "VARCHAR(20)", "TEXT"), ("h", "BIGINT", "INTEGER"), ("i", "DOUBLE", "REAL"), ("j", "DATETIME", "NUMERIC"),
            ("k", "BOOLEAN", "NUMERIC"), ("l", "DECIMAL(10,2)", "NUMERIC"), ("m", "POINT", "INTEGER")]

    def test_column_ids_and_order_follow_the_table(self, tmp_path):
        cols = inspect(build(tmp_path / "a.db", "CREATE TABLE c(z, y, x, w);")).table("c").columns
        assert [(c.cid, c.name) for c in cols] == [(0, "z"), (1, "y"), (2, "x"), (3, "w")]

    def test_not_null_and_defaults(self, tmp_path):
        script = ("CREATE TABLE d(a, b INTEGER DEFAULT 5, c TEXT DEFAULT 'x', e DEFAULT (1+2), f DEFAULT CURRENT_TIMESTAMP, "
                  "g DEFAULT NULL, h TEXT NOT NULL, i INT NOT NULL DEFAULT 0);")
        cols = by_name(inspect(build(tmp_path / "a.db", script)).table("d").columns)
        assert {n: c.default for n, c in cols.items()} == {"a": None, "b": "5", "c": "'x'", "e": "1+2", "f": "CURRENT_TIMESTAMP", "g": "NULL", "h": None, "i": "0"}
        assert {n for n, c in cols.items() if c.not_null} == {"h", "i"}

    def test_a_table_whose_columns_have_no_type_at_all(self, tmp_path):
        cols = inspect(build(tmp_path / "a.db", "CREATE TABLE u(a, b);")).table("u").columns
        assert all(c.declared_type == "" and c.affinity is TypeAffinity.BLOB for c in cols)


# ------------------------------------------------------------------ primary keys


class TestPrimaryKeys:
    def test_integer_primary_key_is_the_rowid_alias(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", "CREATE TABLE t(id INTEGER PRIMARY KEY, v);")).table("t")
        assert t.primary_key == ["id"] and t.rowid_alias == "id" and t.columns[0].is_rowid_alias and t.columns[0].primary_key_position == 1
        assert t.indexes == [], "an INTEGER PRIMARY KEY needs no index of its own"

    def test_other_single_column_keys_are_not_aliases_and_have_an_index(self, tmp_path):
        r = inspect(build(tmp_path / "a.db", "CREATE TABLE a(id INT PRIMARY KEY, v); CREATE TABLE b(id TEXT PRIMARY KEY, v); CREATE TABLE c(id INTEGER PRIMARY KEY DESC, v);"))
        for name in "abc":
            t = r.table(name)
            assert t.primary_key == ["id"] and t.rowid_alias is None
            assert [i.origin for i in t.indexes] == ["pk"], name

    def test_composite_key_in_key_order(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", "CREATE TABLE t(a INT, b TEXT, c, PRIMARY KEY(b, a));")).table("t")
        assert t.primary_key == ["b", "a"] and t.rowid_alias is None
        assert {c.name: c.primary_key_position for c in t.columns} == {"a": 2, "b": 1, "c": 0}

    def test_composite_integer_key_has_no_alias(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", "CREATE TABLE t(a INTEGER, b INTEGER, PRIMARY KEY(a, b));")).table("t")
        assert t.primary_key == ["a", "b"] and t.rowid_alias is None

    def test_a_table_with_no_primary_key(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", "CREATE TABLE t(a, b);")).table("t")
        assert t.primary_key == [] and t.rowid_alias is None and not any(c.is_primary_key for c in t.columns)

    def test_without_rowid_composite_key(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", "CREATE TABLE w(a INT, b TEXT, v, PRIMARY KEY(a, b)) WITHOUT ROWID;")).table("w")
        assert t.primary_key == ["a", "b"] and t.without_rowid and t.rowid_alias is None
        [ix] = t.indexes
        assert ix.origin == "pk" and ix.root_page is None and [c.name for c in ix.columns] == ["a", "b"]

    def test_integer_primary_key_in_a_without_rowid_table_is_just_a_key(self, tmp_path):
        t = inspect(build(tmp_path / "a.db", "CREATE TABLE w(id INTEGER PRIMARY KEY, v) WITHOUT ROWID;")).table("w")
        assert t.primary_key == ["id"] and t.rowid_alias is None


# ------------------------------------------------------------------ indexes and foreign keys


class TestIndexes:
    SCRIPT = """
        CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, b INT, c TEXT UNIQUE, d, UNIQUE(a, b));
        CREATE INDEX i_plain ON t(a);
        CREATE UNIQUE INDEX i_unique ON t(b);
        CREATE INDEX i_multi ON t(a COLLATE NOCASE, b DESC);
        CREATE INDEX i_partial ON t(d) WHERE d IS NOT NULL;
        CREATE INDEX i_expr ON t(lower(a), b);
    """

    def indexes(self, tmp_path):
        return by_name(inspect(build(tmp_path / "a.db", self.SCRIPT)).table("t").indexes)

    def test_every_index_is_found_with_its_origin(self, tmp_path):
        ix = self.indexes(tmp_path)
        assert {n: i.origin for n, i in ix.items() if not n.startswith("sqlite_")} == {
            "i_plain": "c", "i_unique": "c", "i_multi": "c", "i_partial": "c", "i_expr": "c"}
        assert sorted(i.origin for n, i in ix.items() if n.startswith("sqlite_autoindex")) == ["u", "u"], "the two UNIQUE constraints"

    def test_unique_and_partial_flags(self, tmp_path):
        ix = self.indexes(tmp_path)
        assert ix["i_unique"].unique and not ix["i_plain"].unique
        assert ix["i_partial"].partial and not ix["i_plain"].partial

    def test_key_columns_in_order_with_direction_and_collation(self, tmp_path):
        multi = self.indexes(tmp_path)["i_multi"]
        assert [(c.name, c.descending, c.collation) for c in multi.columns] == [("a", False, "NOCASE"), ("b", True, "BINARY")]
        assert [c.position for c in multi.columns] == [0, 1] and [c.cid for c in multi.columns] == [1, 2]

    def test_expression_columns_have_no_name(self, tmp_path):
        expr = self.indexes(tmp_path)["i_expr"]
        assert [(c.cid, c.name) for c in expr.columns] == [(-2, None), (2, "b")]

    def test_create_statement_and_root_page_come_from_the_schema(self, tmp_path):
        ix = self.indexes(tmp_path)
        assert ix["i_plain"].sql == "CREATE INDEX i_plain ON t(a)" and ix["i_plain"].root_page >= 2
        auto = next(i for n, i in ix.items() if n.startswith("sqlite_autoindex"))
        assert auto.sql is None and auto.root_page >= 2 and auto.table == "t"

    def test_a_table_can_have_no_indexes(self, tmp_path):
        assert inspect(build(tmp_path / "a.db", "CREATE TABLE t(a);")).table("t").indexes == []


class TestForeignKeys:
    SCRIPT = """
        CREATE TABLE parent(id INTEGER PRIMARY KEY, a INT, b INT, UNIQUE(a, b));
        CREATE TABLE child(id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent(id) ON DELETE CASCADE ON UPDATE SET NULL,
                           x INT, y INT, other REFERENCES parent, FOREIGN KEY(x, y) REFERENCES parent(a, b));
    """

    def test_single_column_action_and_implicit_reference(self, tmp_path):
        child = inspect(build(tmp_path / "a.db", self.SCRIPT)).table("child")
        fks = {tuple(f.columns): f for f in child.foreign_keys}
        pid = fks[("pid",)]
        assert (pid.referenced_table, pid.referenced_columns, pid.on_delete, pid.on_update) == ("parent", ["id"], "CASCADE", "SET NULL")
        assert fks[("other",)].referenced_columns == [None], "REFERENCES parent with no column names means the parent's primary key"

    def test_composite_foreign_key_is_one_entry(self, tmp_path):
        child = inspect(build(tmp_path / "a.db", self.SCRIPT)).table("child")
        [composite] = [f for f in child.foreign_keys if len(f.columns) == 2]
        assert composite.columns == ["x", "y"] and composite.referenced_columns == ["a", "b"] and composite.on_delete == "NO ACTION"

    def test_tables_without_foreign_keys(self, tmp_path):
        assert inspect(build(tmp_path / "a.db", self.SCRIPT)).table("parent").foreign_keys == []
