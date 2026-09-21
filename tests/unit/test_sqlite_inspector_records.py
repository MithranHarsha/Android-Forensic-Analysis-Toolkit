"""SQLiteInspector: active records — every value exactly as stored, with rowids, storage classes and provenance."""

import hashlib
import json
import math
import random
import sqlite3

import pytest

from android_forensics.errors import InspectionError
from android_forensics.models.enums import StorageClass
from android_forensics.sqlite.inspection import BlobValue, DatabaseInspection, SpecialFloat
from android_forensics.sqlite.inspector import InspectionOptions, SQLiteInspector
from tests.unit.sqlite_helpers import build, numbered_db

BIG = 10**7  # blob_inline_limit large enough to keep every blob whole


def inspect(path, **kw):
    return SQLiteInspector.inspect(path, **kw)


def direct(path, table):
    """The rows an independent connection returns: (rowid, values…) with typeof() of each value."""
    c = sqlite3.connect(path)
    cols = [r[1] for r in c.execute(f'PRAGMA table_info("{table}")')]
    rows = c.execute(f'SELECT rowid, * FROM "{table}" ORDER BY rowid').fetchall()
    types = c.execute("SELECT " + ", ".join(f'typeof("{col}")' for col in cols) + f' FROM "{table}" ORDER BY rowid').fetchall()
    c.close()
    return rows, types


def plain(v):
    return v.data if isinstance(v, BlobValue) else v


def values_of(record):
    return [plain(v) for v in record.values]


# ------------------------------------------------------------------ several tables, cross-checked


class TestMultipleTables:
    @pytest.fixture()
    def db(self, tmp_path):
        rng = random.Random(7)
        p = build(tmp_path / "multi.db", """
            CREATE TABLE people(id INTEGER PRIMARY KEY, name TEXT, age INTEGER, score REAL, avatar BLOB);
            CREATE TABLE orders(order_id INTEGER PRIMARY KEY, person_id INTEGER, total NUMERIC, placed DATETIME, note);
            CREATE TABLE tags(person_id INT, tag TEXT, PRIMARY KEY(person_id, tag)) WITHOUT ROWID;
            CREATE TABLE log(msg TEXT, level INT);
        """)
        c = sqlite3.connect(p)
        c.executemany("INSERT INTO people VALUES(?,?,?,?,?)", [(i, f"Person {i}", rng.randint(1, 90), rng.random() * 100, rng.randbytes(rng.randint(0, 40))) for i in range(1, 51)])
        c.executemany("INSERT INTO orders VALUES(?,?,?,?,?)", [(i, rng.randint(1, 50), rng.choice([9.99, 20, "12.50", None]), 1709280000 + i * 60, rng.choice([None, "gift", 7, b"\x01"])) for i in range(1, 121)])
        c.executemany("INSERT INTO tags VALUES(?,?)", [(i % 50, t) for i, t in enumerate("abcdef" * 8)])
        c.executemany("INSERT INTO log VALUES(?,?)", [(f"message {i}", i % 4) for i in range(30)])
        c.commit()
        c.close()
        return p

    def test_every_table_is_read_completely(self, db):
        r = inspect(db, blob_inline_limit=BIG)
        assert {t.name: (t.row_count, len(t.records)) for t in r.tables} == {"people": (50, 50), "orders": (120, 120), "tags": (48, 48), "log": (30, 30)}
        assert r.record_count == 248 and not any(t.records_truncated for t in r.tables)

    @pytest.mark.parametrize("table", ["people", "orders", "log"])
    def test_records_equal_an_independent_query_value_for_value(self, db, table):
        rows, types = direct(db, table)
        t = inspect(db, blob_inline_limit=BIG).table(table)
        assert [[r.rowid, *values_of(r)] for r in t.records] == [list(x) for x in rows]
        assert [[c.value for c in r.storage_classes] for r in t.records] == [list(x) for x in types]

    def test_without_rowid_table_matches_the_independent_query_as_a_set(self, db):
        c = sqlite3.connect(db)
        expected = c.execute("SELECT person_id, tag FROM tags ORDER BY person_id, tag").fetchall()
        c.close()
        t = inspect(db).table("tags")
        assert [tuple(values_of(r)) for r in t.records] == expected and all(r.rowid is None for r in t.records)

    def test_ordinals_and_table_names_on_every_record(self, db):
        for t in inspect(db).tables:
            assert [r.ordinal for r in t.records] == list(range(len(t.records))) and {r.table for r in t.records} <= {t.name}

    def test_flattened_export_carries_database_table_rowid_and_named_values(self, db):
        r = inspect(db)
        flat = list(r.iter_records())
        assert len(flat) == r.record_count
        first = next(x for x in flat if x["table"] == "people" and x["rowid"] == 1)
        assert first["database"] == r.file.path and first["sha256"] == r.file.sha256 and first["state"] == "ACTIVE"
        assert set(first["values"]) == {"id", "name", "age", "score", "avatar"} and first["values"]["id"] == 1

    def test_the_whole_result_survives_json_unchanged(self, db):
        r = inspect(db)
        assert DatabaseInspection.model_validate_json(r.model_dump_json()) == r
        json.loads(r.model_dump_json())  # and is plain, standard JSON


# ------------------------------------------------------------------ data types


class TestDataTypes:
    def one_column(self, tmp_path, declared, values):
        c = sqlite3.connect(tmp_path / "t.db")
        c.execute(f"CREATE TABLE t(v {declared})")
        c.executemany("INSERT INTO t VALUES(?)", [(v,) for v in values])
        c.commit()
        c.close()
        return inspect(tmp_path / "t.db", blob_inline_limit=BIG).table("t")

    @pytest.mark.parametrize("value", [0, 1, -1, 127, 128, 255, 256, 65535, 65536, 2**31 - 1, 2**31, -2**31, 2**53, 2**63 - 1, -2**63])
    def test_integers_of_every_width(self, tmp_path, value):
        [rec] = self.one_column(tmp_path, "INTEGER", [value]).records
        assert rec.values == [value] and type(rec.values[0]) is int and rec.storage_classes == [StorageClass.INTEGER]

    @pytest.mark.parametrize("value", [0.5, 3.14159265358979, -2.5, 1e-300, 1.7976931348623157e308, 5e-324, 1 / 3])
    def test_reals_are_exact(self, tmp_path, value):
        [rec] = self.one_column(tmp_path, "REAL", [value]).records
        assert rec.values == [value] and type(rec.values[0]) is float and rec.storage_classes == [StorageClass.REAL]

    def test_a_real_that_is_a_whole_number_is_still_a_real(self, tmp_path):
        [rec] = self.one_column(tmp_path, "REAL", [3]).records  # 3 goes in as an int, REAL affinity stores and returns 3.0
        assert rec.values == [3.0] and type(rec.values[0]) is float

    @pytest.mark.parametrize("value,label", [(float("inf"), "inf"), (float("-inf"), "-inf")])
    def test_infinities_are_kept_and_survive_json(self, tmp_path, value, label):
        t = self.one_column(tmp_path, "REAL", [value])
        assert t.records[0].values == [SpecialFloat(value=label)] and t.records[0].storage_classes == [StorageClass.REAL]
        assert type(t.records[0]).model_validate_json(t.records[0].model_dump_json()) == t.records[0]

    def test_nan_is_stored_by_sqlite_as_null_and_reported_as_null(self, tmp_path):
        assert self.one_column(tmp_path, "REAL", [float("nan")]).records[0].values == [None]

    @pytest.mark.parametrize("text", ["", " ", "plain", "ünïcödé", "日本語のテキスト", "😀🚀", "line\nbreak\ttab\r\n", "quote'quote\"", "a" * 200_000, "0123", "1e5", "NULL"])
    def test_text_of_every_kind(self, tmp_path, text):
        [rec] = self.one_column(tmp_path, "TEXT", [text]).records
        assert rec.values == [text] and type(rec.values[0]) is str and rec.storage_classes == [StorageClass.TEXT]

    @pytest.mark.parametrize("size", [0, 1, 31, 32, 33, 255, 256, 257, 4000])
    def test_blob_sizes_around_the_head_and_inline_boundaries(self, tmp_path, size):
        data = bytes(i % 251 for i in range(size))
        c = sqlite3.connect(tmp_path / "b.db")
        c.execute("CREATE TABLE t(v BLOB)")
        c.execute("INSERT INTO t VALUES(?)", (data,))
        c.commit()
        c.close()
        [rec] = inspect(tmp_path / "b.db").table("t").records  # default inline limit: 256 bytes
        b = rec.values[0]
        assert isinstance(b, BlobValue) and b.length == size and b.sha256 == hashlib.sha256(data).hexdigest() and b.hex_head == data[:32].hex()
        assert (b.data == data) if size <= 256 else (b.data is None)

    def test_blob_inline_limit_is_configurable(self, tmp_path):
        p = build(tmp_path / "b.db", "CREATE TABLE t(v BLOB); INSERT INTO t VALUES(x'0102030405');")
        assert inspect(p, blob_inline_limit=0).table("t").records[0].values[0].data is None
        assert inspect(p, blob_inline_limit=5).table("t").records[0].values[0].data == bytes([1, 2, 3, 4, 5])
        assert inspect(p, blob_inline_limit=4).table("t").records[0].values[0].data is None
        assert inspect(p, blob_inline_limit=0).table("t").records[0].values[0].sha256 == hashlib.sha256(bytes([1, 2, 3, 4, 5])).hexdigest()

    def test_an_untyped_column_holds_all_five_storage_classes(self, tmp_path):
        t = self.one_column(tmp_path, "", [1, "a", 2.5, b"z", None])
        assert [r.storage_classes[0] for r in t.records] == [StorageClass.INTEGER, StorageClass.TEXT, StorageClass.REAL, StorageClass.BLOB, StorageClass.NULL]
        assert [plain(r.values[0]) for r in t.records] == [1, "a", 2.5, b"z", None]

    def test_python_booleans_are_stored_as_integers(self, tmp_path):
        assert [r.values for r in self.one_column(tmp_path, "BOOLEAN", [True, False]).records] == [[1], [0]]

    def test_a_wide_table(self, tmp_path):
        cols = ", ".join(f"c{i} INTEGER" for i in range(120))
        p = build(tmp_path / "w.db", f"CREATE TABLE w({cols}); INSERT INTO w VALUES({', '.join(str(i) for i in range(120))});")
        t = inspect(p).table("w")
        assert len(t.columns) == 120 and t.records[0].values == list(range(120))

    @pytest.mark.parametrize("declared,stored,expected_class,expected_value", [
        ("INTEGER", "42", StorageClass.INTEGER, 42),  # numeric text is converted by INTEGER affinity when it is stored…
        ("INTEGER", "abc", StorageClass.TEXT, "abc"),  # …text that is not numeric is not
        ("INTEGER", 4.0, StorageClass.INTEGER, 4),
        ("INTEGER", 4.5, StorageClass.REAL, 4.5),
        ("TEXT", 123, StorageClass.TEXT, "123"),
        ("TEXT", 1.5, StorageClass.TEXT, "1.5"),
        ("REAL", "2.5", StorageClass.REAL, 2.5),
        ("NUMERIC", "3.0", StorageClass.INTEGER, 3),
        ("NUMERIC", "3.5", StorageClass.REAL, 3.5),
        ("NUMERIC", "hello", StorageClass.TEXT, "hello"),
        ("BLOB", "text", StorageClass.TEXT, "text"),  # BLOB affinity converts nothing
        ("", "007", StorageClass.TEXT, "007"),
    ])
    def test_the_record_shows_what_sqlite_stored_never_what_the_column_declares(self, tmp_path, declared, stored, expected_class, expected_value):
        [rec] = self.one_column(tmp_path, declared, [stored]).records
        assert rec.storage_classes == [expected_class] and rec.values == [expected_value]

    def test_storage_classes_agree_with_typeof_for_a_deliberately_messy_table(self, tmp_path):
        rng = random.Random(3)
        c = sqlite3.connect(tmp_path / "m.db")
        c.execute("CREATE TABLE m(a INTEGER, b TEXT, c REAL, d BLOB, e NUMERIC, f)")
        pool = [None, 0, 1, -7, 2**40, 1.5, -0.25, "", "x", "12", "3.5", "2024-03-01", b"", b"\x00\xff", "é"]
        c.executemany("INSERT INTO m VALUES(?,?,?,?,?,?)", [tuple(rng.choice(pool) for _ in range(6)) for _ in range(500)])
        c.commit()
        c.close()
        rows, types = direct(tmp_path / "m.db", "m")
        t = inspect(tmp_path / "m.db", blob_inline_limit=BIG).table("m")
        assert [[c.value for c in r.storage_classes] for r in t.records] == [list(x) for x in types]
        assert [[r.rowid, *values_of(r)] for r in t.records] == [list(x) for x in rows]


# ------------------------------------------------------------------ NULL values


class TestNulls:
    def test_null_is_distinct_from_empty_zero_and_empty_blob(self, tmp_path):
        p = build(tmp_path / "n.db", "CREATE TABLE t(a, b, c, d, e); INSERT INTO t VALUES(NULL, '', 0, x'', 'NULL');")
        [rec] = inspect(p, blob_inline_limit=BIG).table("t").records
        assert [c.value for c in rec.storage_classes] == ["null", "text", "integer", "blob", "text"]
        assert values_of(rec) == [None, "", 0, b"", "NULL"]

    def test_a_row_of_nothing_but_nulls(self, tmp_path):
        p = build(tmp_path / "n.db", "CREATE TABLE t(a, b, c); INSERT INTO t VALUES(NULL, NULL, NULL);")
        [rec] = inspect(p).table("t").records
        assert rec.values == [None, None, None] and rec.rowid == 1 and set(rec.storage_classes) == {StorageClass.NULL}

    def test_nulls_in_the_middle_of_typed_columns(self, tmp_path):
        p = build(tmp_path / "n.db", "CREATE TABLE t(id INTEGER PRIMARY KEY, a INT, b TEXT, c REAL); INSERT INTO t VALUES(1, NULL, 'x', NULL), (2, 5, NULL, 1.5), (3, NULL, NULL, NULL);")
        assert [r.values for r in inspect(p).table("t").records] == [[1, None, "x", None], [2, 5, None, 1.5], [3, None, None, None]]

    def test_rows_with_a_null_key_in_a_rowid_table(self, tmp_path):
        """SQLite (for historical reasons) lets a non-INTEGER PRIMARY KEY of a rowid table hold NULL — the rowid still identifies the row."""
        p = build(tmp_path / "n.db", "CREATE TABLE t(k TEXT PRIMARY KEY, v); INSERT INTO t VALUES(NULL, 1), (NULL, 2), ('a', 3);")
        recs = inspect(p).table("t").records
        assert [(r.rowid, r.values) for r in recs] == [(1, [None, 1]), (2, [None, 2]), (3, ["a", 3])]

    def test_defaults_are_applied_by_sqlite_and_the_record_holds_the_stored_result(self, tmp_path):
        p = build(tmp_path / "n.db", "CREATE TABLE t(a INT DEFAULT 5, b TEXT DEFAULT 'dflt', c DEFAULT NULL); INSERT INTO t DEFAULT VALUES;")
        assert inspect(p).table("t").records[0].values == [5, "dflt", None]

    def test_a_table_of_nulls_reads_the_same_with_and_without_a_value_index(self, tmp_path):
        p = build(tmp_path / "n.db", "CREATE TABLE t(a); CREATE INDEX i ON t(a); INSERT INTO t VALUES(NULL), (1), (NULL), ('x');")
        assert [r.values for r in inspect(p).table("t").records] == [[None], [1], [None], ["x"]], "rows come in rowid order, not index order"


# ------------------------------------------------------------------ timestamps


class TestTimestamps:
    """The inspector does not interpret timestamps (that is the artifact layer's job); it must not disturb them."""

    def events(self, tmp_path):
        p = build(tmp_path / "ev.db", """
            CREATE TABLE events(id INTEGER PRIMARY KEY, unix_s INTEGER, unix_ms INTEGER, webkit_us INTEGER, iso TEXT,
                                julian REAL, created DATETIME DEFAULT CURRENT_TIMESTAMP, ts TIMESTAMP, note TEXT);
            INSERT INTO events(unix_s, unix_ms, webkit_us, iso, julian, ts, note) VALUES
                (1709280000, 1709280000123, 13348753000000000, '2024-03-01T08:00:00Z', 2460370.5, '2024-03-01 08:00:00', 'typical'),
                (0, 0, 0, '1970-01-01T00:00:00Z', 0.0, NULL, 'zero is not null'),
                (-1, -1000, -11644473600000000, '1969-12-31T23:59:59Z', -0.5, '', 'before the epoch'),
                (4102444800, 4102444800000, 24000000000000000, '2100-01-01T00:00:00Z', 2488069.5, '2100-01-01', 'far future'),
                (NULL, NULL, NULL, NULL, NULL, NULL, 'all null');
        """)
        return inspect(p).table("events")

    def test_every_format_is_returned_exactly_as_stored(self, tmp_path):
        rows = self.events(tmp_path).record_dicts()
        first = rows[0]
        assert (first["unix_s"], first["unix_ms"], first["webkit_us"]) == (1709280000, 1709280000123, 13348753000000000)
        assert (first["iso"], first["julian"], first["ts"]) == ("2024-03-01T08:00:00Z", 2460370.5, "2024-03-01 08:00:00")
        assert re_match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", first["created"])  # CURRENT_TIMESTAMP default, as text

    def test_zero_negative_and_far_future_values_are_kept_not_judged(self, tmp_path):
        rows = self.events(tmp_path).record_dicts()
        assert (rows[1]["unix_s"], rows[1]["unix_ms"], rows[1]["julian"]) == (0, 0, 0.0)
        assert (rows[2]["unix_s"], rows[2]["unix_ms"], rows[2]["webkit_us"]) == (-1, -1000, -11644473600000000)
        assert (rows[3]["unix_s"], rows[3]["iso"]) == (4102444800, "2100-01-01T00:00:00Z")

    def test_null_zero_and_empty_string_timestamps_stay_distinct(self, tmp_path):
        t = self.events(tmp_path)
        col = t.data_columns.index
        assert t.records[1].values[col("unix_s")] == 0 and t.records[1].storage_classes[col("unix_s")] is StorageClass.INTEGER
        assert t.records[1].values[col("ts")] is None and t.records[2].values[col("ts")] == ""
        nullable = [i for i, name in enumerate(t.data_columns) if name not in ("id", "created", "note")]  # created has a DEFAULT
        assert all(t.records[4].values[i] is None for i in nullable) and t.records[4].values[col("created")] is not None

    def test_declared_datetime_types_are_preserved_with_numeric_affinity(self, tmp_path):
        cols = {c.name: c for c in self.events(tmp_path).columns}
        assert (cols["created"].declared_type, cols["created"].affinity.value, cols["created"].default) == ("DATETIME", "NUMERIC", "CURRENT_TIMESTAMP")
        assert (cols["ts"].declared_type, cols["ts"].affinity.value) == ("TIMESTAMP", "NUMERIC")

    def test_storage_class_tells_integer_epoch_from_text_date_in_the_same_column(self, tmp_path):
        p = build(tmp_path / "mix.db", """
            CREATE TABLE t(when_ DATETIME);
            INSERT INTO t VALUES(1709280000), ('1709280000'), ('2024-03-01 08:00:00'), (1709280000.5), ('1709280000.5'), (NULL);
        """)
        recs = inspect(p).table("t").records
        assert [(r.values[0], r.storage_classes[0].value) for r in recs] == [
            (1709280000, "integer"), (1709280000, "integer"),  # numeric text became an integer when stored (NUMERIC affinity)
            ("2024-03-01 08:00:00", "text"), (1709280000.5, "real"), (1709280000.5, "real"), (None, "null")]

    def test_millisecond_and_microsecond_text_timestamps_keep_every_digit(self, tmp_path):
        texts = ["2024-03-01T08:00:00.123456Z", "2024-03-01 08:00:00.5", "20240301T080000", "Fri, 01 Mar 2024 08:00:00 GMT"]
        p = build(tmp_path / "t.db", "CREATE TABLE t(a TEXT); " + "".join(f"INSERT INTO t VALUES('{x}');" for x in texts))
        assert [r.values[0] for r in inspect(p).table("t").records] == texts


def re_match(pattern, text):
    import re

    return re.fullmatch(pattern, text) is not None


# ------------------------------------------------------------------ deleted rows: only their absence is checked


class TestDeletedRowsAreAbsent:
    """SQLite marks a deleted row's space free but leaves the bytes. Normal inspection must not show them — and does not go looking."""

    def make(self, tmp_path, secure_delete="OFF"):
        p = tmp_path / "d.db"
        c = sqlite3.connect(p)
        c.execute(f"PRAGMA secure_delete={secure_delete}")
        c.execute("CREATE TABLE msgs(id INTEGER PRIMARY KEY, body TEXT)")
        c.executemany("INSERT INTO msgs VALUES(?,?)", [(i, (f"DELETED-MARKER-{i:04d} " if i % 2 == 0 else f"KEEP-{i:04d} ") + "padding " * 8) for i in range(1, 201)])
        c.commit()
        c.execute("DELETE FROM msgs WHERE id % 2 = 0")
        c.commit()
        c.close()
        return p

    def test_deleted_rows_do_not_appear_in_the_records(self, tmp_path):
        r = inspect(self.make(tmp_path))
        t = r.table("msgs")
        assert t.row_count == 100 and len(t.records) == 100
        assert all(rec.values[1].startswith("KEEP-") for rec in t.records)
        assert [rec.rowid for rec in t.records] == list(range(1, 201, 2)), "surviving rows keep their rowids; the gaps are just gaps"

    def test_the_bytes_are_still_in_the_file_but_nowhere_in_the_result(self, tmp_path):
        p = self.make(tmp_path)
        assert b"DELETED-MARKER-0100" in p.read_bytes(), "precondition: the deleted content physically remains in the file"
        r = inspect(p)
        dumped = r.model_dump_json()
        assert "DELETED-MARKER" not in dumped and "DELETED-MARKER" not in json.dumps(list(r.iter_records()))

    def test_the_result_makes_no_claim_about_what_was_deleted(self, tmp_path):
        r = inspect(self.make(tmp_path))
        assert r.header.freelist_page_count is not None  # a header fact, as the header states it
        assert not any("deleted" in i.kind or "recover" in i.kind for i in r.issues)
        assert {rec.state for t in r.tables for rec in t.records} == {"ACTIVE"}

    def test_with_secure_delete_on_the_result_is_the_same(self, tmp_path):
        sub = tmp_path / "s"
        sub.mkdir()
        r = inspect(self.make(sub, "ON"))
        assert [rec.rowid for rec in r.table("msgs").records] == list(range(1, 201, 2))

    def test_deleting_every_row_leaves_an_empty_table(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 300)
        c = sqlite3.connect(p)
        c.execute("DELETE FROM t")
        c.commit()
        c.close()
        r = inspect(p)
        assert r.table("t").row_count == 0 and r.table("t").records == [] and r.header.freelist_page_count > 0

    def test_a_dropped_table_is_gone_from_the_schema(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE keep(a); CREATE TABLE gone(secret TEXT); INSERT INTO gone VALUES('DROPPED-SECRET'); INSERT INTO keep VALUES(1); DROP TABLE gone;")
        r = inspect(p)
        assert [t.name for t in r.tables] == ["keep"] and "DROPPED-SECRET" not in r.model_dump_json()

    def test_updated_rows_show_only_their_current_values(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES(1, 'old value that is quite long'); UPDATE t SET v = 'new' WHERE id = 1;")
        assert inspect(p).table("t").records[0].values == [1, "new"]

    def test_a_deleted_row_in_a_without_rowid_table(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE w(k TEXT PRIMARY KEY, v) WITHOUT ROWID; INSERT INTO w VALUES('a', 1), ('b', 2), ('c', 3); DELETE FROM w WHERE k = 'b';")
        assert [r.values for r in inspect(p).table("w").records] == [["a", 1], ["c", 3]]

    def test_the_autoincrement_high_water_mark_is_an_ordinary_internal_table(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT, v); INSERT INTO t(v) VALUES(1), (2), (3); DELETE FROM t WHERE id = 3;")
        r = inspect(p)
        seq = r.table("sqlite_sequence")
        assert seq.internal and seq.records[0].values == ["t", 3] and [x.rowid for x in r.table("t").records] == [1, 2]

    def test_rows_deleted_inside_the_wal_are_absent_too(self, tmp_path):
        from tests.unit.sqlite_helpers import wal_snapshot

        p = wal_snapshot(tmp_path / "w", in_main=5, only_in_wal=3)
        assert [r.values[1] for r in inspect(p).table("t").records][-3:] == ["wal-0", "wal-1", "wal-2"]


# ------------------------------------------------------------------ rowids, ordering and options


class TestRowidsAndOrdering:
    def test_records_come_in_rowid_order_whatever_the_insertion_order(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE t(id INTEGER PRIMARY KEY, v); INSERT INTO t VALUES(5,'e'),(3,'c'),(9,'i'),(1,'a');")
        assert [(r.rowid, r.values) for r in inspect(p).table("t").records] == [(1, [1, "a"]), (3, [3, "c"]), (5, [5, "e"]), (9, [9, "i"])]

    def test_a_rowid_alias_column_equals_the_record_rowid(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE t(id INTEGER PRIMARY KEY, v); INSERT INTO t VALUES(-5,'n'),(0,'z'),(2**40,'big');".replace("2**40", "1099511627776"))
        assert all(r.rowid == r.values[0] for r in inspect(p).table("t").records)

    def test_rowids_of_tables_without_an_alias_are_the_implicit_ones(self, tmp_path):
        p = build(tmp_path / "a.db", "CREATE TABLE t(a); INSERT INTO t VALUES('x'),('y'),('z'); DELETE FROM t WHERE a = 'y';")
        assert [r.rowid for r in inspect(p).table("t").records] == [1, 3]

    def test_a_large_table_is_read_completely_and_in_order(self, tmp_path):
        r = inspect(numbered_db(tmp_path / "a.db", 5000))
        t = r.table("t")
        assert t.row_count == len(t.records) == 5000 and [x.rowid for x in t.records] == list(range(1, 5001))
        assert t.records[4999].values == [5000, "row 04999 " + "x" * 90]


class TestOptions:
    @pytest.fixture()
    def db(self, tmp_path):
        return build(tmp_path / "o.db", """
            CREATE TABLE people(id INTEGER PRIMARY KEY, name TEXT); CREATE TABLE cities(id INTEGER PRIMARY KEY, name TEXT);
            INSERT INTO people VALUES(1,'a'),(2,'b'),(3,'c'),(4,'d'),(5,'e'); INSERT INTO cities VALUES(1,'x'),(2,'y');
        """)

    def test_schema_only(self, db):
        r = inspect(db, include_records=False)
        assert [t.row_count for t in r.tables] == [5, 2] and all(t.records == [] and not t.records_truncated for t in r.tables)
        assert r.record_count == 0 and r.tables[0].columns and r.header.valid

    def test_a_per_table_cap_keeps_the_first_rows_and_says_it_left_some_out(self, db):
        r = inspect(db, max_records_per_table=3)
        people, cities = r.table("people"), r.table("cities")
        assert (people.row_count, len(people.records), people.records_truncated) == (5, 3, True)
        assert [x.rowid for x in people.records] == [1, 2, 3]
        assert (cities.row_count, len(cities.records), cities.records_truncated) == (2, 2, False)

    @pytest.mark.parametrize("cap,kept,truncated", [(0, 0, True), (5, 5, False), (6, 5, False), (100, 5, False)])
    def test_cap_boundaries(self, db, cap, kept, truncated):
        people = inspect(db, max_records_per_table=cap).table("people")
        assert (len(people.records), people.records_truncated) == (kept, truncated)

    def test_only_the_named_tables_are_read_case_insensitively(self, db):
        r = inspect(db, tables=("PEOPLE",))
        assert len(r.table("people").records) == 5 and r.table("cities").records == [] and r.table("cities").row_count == 2

    def test_options_object_and_keyword_overrides(self, db):
        opts = InspectionOptions(max_records_per_table=1)
        assert len(inspect(db, options=opts).table("people").records) == 1
        assert len(inspect(db, options=opts, max_records_per_table=4).table("people").records) == 4

    def test_integrity_check_can_be_skipped(self, db):
        assert inspect(db, integrity_check=False).integrity.status == "not_run" and inspect(db).integrity.status == "ok"

    def test_hashing_can_be_skipped(self, db):
        r = inspect(db, hash_files=False)
        assert r.file.sha256 is None and inspect(db).file.sha256

    @pytest.mark.parametrize("bad", [dict(max_records_per_table=-1), dict(blob_inline_limit=-1), dict(sidecars={"-bak": "x"})])
    def test_invalid_options_are_refused(self, db, bad):
        with pytest.raises(ValueError):
            inspect(db, **bad)

    def test_unknown_option_names_are_refused(self, db):
        with pytest.raises(TypeError):
            inspect(db, include_deleted=True)  # there is no such thing in Review 1


# ------------------------------------------------------------------ text that is not valid UTF-8


class TestUndecodableText:
    def make(self, tmp_path):
        p = tmp_path / "u.db"
        c = sqlite3.connect(p)
        c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, b TEXT)")
        c.execute("INSERT INTO t VALUES(1, 'fine', 'also fine')")
        c.execute("INSERT INTO t VALUES(2, CAST(? AS TEXT), 'neighbour')", (b"\xff\xfeA\x80",))
        c.commit()
        c.close()
        return p

    def test_the_lossy_text_and_the_original_bytes_are_both_kept(self, tmp_path):
        r = inspect(self.make(tmp_path))
        ok, bad = r.table("t").records
        assert ok.undecodable_text == {} and ok.values == [1, "fine", "also fine"]
        assert bad.undecodable_text == {"a": "fffe4180"} and "\ufffd" in bad.values[1] and bad.values[2] == "neighbour"
        assert bad.storage_classes[1] is StorageClass.TEXT and type(bad.values[1]) is str

    def test_it_is_counted_and_reported(self, tmp_path):
        r = inspect(self.make(tmp_path))
        assert r.engine.decode_errors == 1
        [issue] = [i for i in r.issues if i.kind == "undecodable_text"]
        assert issue.table == "t" and "1 TEXT value" in issue.detail

    def test_it_survives_json(self, tmp_path):
        r = inspect(self.make(tmp_path))
        assert DatabaseInspection.model_validate_json(r.model_dump_json()) == r


# ------------------------------------------------------------------ streaming


class TestStreaming:
    def test_the_stream_equals_the_records_of_a_full_inspection(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 700)
        assert list(SQLiteInspector.iter_records(p, "t")) == inspect(p).table("t").records

    def test_it_is_lazy_and_cleans_up_when_closed_early(self, tmp_path):
        p = numbered_db(tmp_path / "evidence" / "a.db", 700)
        scratch = tmp_path / "scratch"
        it = SQLiteInspector.iter_records(p, "t", scratch_dir=scratch)
        first = next(it)
        assert first.rowid == 1 and any(scratch.iterdir()), "the working copy exists while the stream is open"
        it.close()
        assert not any(scratch.iterdir()), "and is gone once it is closed"

    def test_it_cleans_up_when_exhausted(self, tmp_path):
        p = numbered_db(tmp_path / "evidence" / "a.db", 50)
        scratch = tmp_path / "scratch"
        assert len(list(SQLiteInspector.iter_records(p, "t", scratch_dir=scratch))) == 50
        assert not any(scratch.iterdir())

    def test_a_table_larger_than_you_would_want_in_memory(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 20000)
        assert sum(1 for _ in SQLiteInspector.iter_records(p, "t")) == 20000

    def test_the_cap_applies(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 100)
        assert len(list(SQLiteInspector.iter_records(p, "t", max_records_per_table=7))) == 7

    def test_table_names_are_case_insensitive(self, tmp_path):
        assert len(list(SQLiteInspector.iter_records(numbered_db(tmp_path / "a.db", 3), "T"))) == 3

    def test_unknown_table_and_unusable_databases_raise_on_first_use(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 3)
        with pytest.raises(InspectionError, match="no table named 'nope'"):
            next(SQLiteInspector.iter_records(p, "nope"))
        junk = tmp_path / "junk.db"
        junk.write_bytes(b"x" * 5000)
        with pytest.raises(InspectionError, match="valid SQLite header"):
            SQLiteInspector.iter_records(junk, "t")
        with pytest.raises(InspectionError, match="does not exist"):
            SQLiteInspector.iter_records(tmp_path / "missing.db", "t")


# ------------------------------------------------------------------ determinism


def test_two_inspections_of_the_same_file_are_identical_apart_from_their_timestamp(tmp_path):
    p = numbered_db(tmp_path / "a.db", 120)
    a, b = inspect(p), inspect(p)
    assert a.model_copy(update={"inspected_at": b.inspected_at}) == b


def test_math_special_values_do_not_break_json_dumps(tmp_path):
    p = build(tmp_path / "a.db", "CREATE TABLE t(a REAL); INSERT INTO t VALUES(1e999), (-1e999), (0.1);")
    r = inspect(p)
    assert [v for rec in r.table("t").records for v in rec.values][2] == 0.1 and math.isfinite(0.1)
    assert DatabaseInspection.model_validate_json(r.model_dump_json()) == r
