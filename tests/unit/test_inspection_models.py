"""The typed inspection results and the pure helpers behind them: values, affinity, versions, invariants, JSON."""

import hashlib
import struct

import pytest
from pydantic import ValidationError

from android_forensics.models.enums import OpenStatus, SidecarKind, SqliteStatus, StorageClass, TableKind, TypeAffinity
from android_forensics.sqlite.header import parse_header
from android_forensics.sqlite.inspection import (
    ActiveRecord,
    BlobValue,
    ColumnSchema,
    DatabaseInspection,
    EngineInfo,
    FileFacts,
    InspectedSidecar,
    IntegrityResult,
    SchemaEntry,
    SizeCheck,
    SpecialFloat,
    TableInspection,
    affinity_of,
    decode_version_number,
    storage_class_of,
    version_info,
)

SHA = "0" * 64


def blob(data: bytes, inline: bool = True) -> BlobValue:
    return BlobValue(length=len(data), sha256=hashlib.sha256(data).hexdigest(), hex_head=data[:32].hex(), hex=data.hex() if inline else None)


def col(name, declared="", pk=0, hidden=0, cid=0, **kw):
    return ColumnSchema(cid=cid, name=name, declared_type=declared, affinity=affinity_of(declared), not_null=False,
                        primary_key_position=pk, hidden=hidden, **kw)


def header_bytes(**fields) -> bytes:
    """A 100-byte database header with sensible defaults, overridable per field."""
    f = dict(page_size=4096, write=1, read=1, reserved=0, change=7, pages=3, trunk=0, free=0, cookie=1, fmt=4,
             largest_root=0, enc=1, user_version=0, incr=0, app_id=0, valid_for=7, version=3039004)
    f.update(fields)
    h = bytearray(b"SQLite format 3\x00" + bytes(84))
    h[16:18] = struct.pack(">H", f["page_size"] if f["page_size"] != 65536 else 1)
    h[18:24] = bytes([f["write"], f["read"], f["reserved"], 64, 32, 32])
    h[24:72] = struct.pack(">12I", f["change"], f["pages"], f["trunk"], f["free"], f["cookie"], f["fmt"], 0, f["largest_root"], f["enc"],
                           f["user_version"], f["incr"], f["app_id"])
    h[92:100] = struct.pack(">2I", f["valid_for"], f["version"])
    return bytes(h)


# ------------------------------------------------------------------ values


class TestBlobValue:
    def test_small_blob_is_kept_whole_and_bound_to_its_digest(self):
        b = blob(b"\x00\x01\xff")
        assert b.data == b"\x00\x01\xff" and b.length == 3 and b.hex_head == "0001ff"

    def test_large_blob_keeps_length_digest_and_head_only(self):
        data = bytes(range(256)) * 4
        b = blob(data, inline=False)
        assert b.data is None and b.length == 1024 and b.hex_head == data[:32].hex()

    def test_empty_blob_is_valid(self):
        assert blob(b"").data == b"" and blob(b"", inline=False).hex_head == ""

    @pytest.mark.parametrize("bad", [
        dict(length=3, sha256=SHA, hex_head="00"),  # head shorter than min(length, 32)
        dict(length=3, sha256=SHA, hex_head="000000", hex="0000"),  # inline hex the wrong length
        dict(length=3, sha256=SHA, hex_head="000000", hex="000000"),  # inline hex that is not what the digest names
        dict(length=3, sha256=hashlib.sha256(b"\x01\x01\x01").hexdigest(), hex_head="000000", hex="010101"),  # head not the start
        dict(length=1, sha256="xyz", hex_head="00"),
    ])
    def test_inconsistent_summaries_are_refused(self, bad):
        with pytest.raises(ValidationError):
            BlobValue(**bad)

    def test_is_immutable_and_rejects_unknown_fields(self):
        b = blob(b"a")
        with pytest.raises(ValidationError):
            b.length = 2
        with pytest.raises(ValidationError):
            BlobValue(length=0, sha256=hashlib.sha256(b"").hexdigest(), hex_head="", extra=1)


@pytest.mark.parametrize("value,expected", [
    (None, StorageClass.NULL), (0, StorageClass.INTEGER), (-5, StorageClass.INTEGER), (1.5, StorageClass.REAL), (0.0, StorageClass.REAL),
    ("", StorageClass.TEXT), ("5", StorageClass.TEXT), (blob(b""), StorageClass.BLOB), (SpecialFloat(value="inf"), StorageClass.REAL),
])
def test_storage_class_of(value, expected):
    assert storage_class_of(value) is expected


class TestActiveRecord:
    def rec(self, **kw):
        base = dict(table="t", rowid=1, ordinal=0, values=[1, "a", None, 2.5, blob(b"x")])
        return ActiveRecord(**{**base, **kw})

    def test_state_is_always_active(self):
        assert self.rec().state == "ACTIVE"
        with pytest.raises(ValidationError):
            self.rec(state="RECOVERED")  # recovered rows are a different type in Review 2

    def test_storage_classes_follow_the_values(self):
        assert [c.value for c in self.rec().storage_classes] == ["integer", "text", "null", "real", "blob"]

    def test_as_dict_needs_one_name_per_value(self):
        r = self.rec()
        assert r.as_dict(["a", "b", "c", "d", "e"])["b"] == "a"
        with pytest.raises(ValueError):
            r.as_dict(["a"])

    def test_a_null_rowid_is_allowed_for_without_rowid_tables(self):
        assert self.rec(rowid=None).rowid is None

    def test_ordinal_cannot_be_negative(self):
        with pytest.raises(ValidationError):
            self.rec(ordinal=-1)

    def test_undecodable_text_is_kept_as_hex(self):
        r = self.rec(undecodable_text={"body": "fffe"})
        assert r.undecodable_text == {"body": "fffe"}
        with pytest.raises(ValidationError):
            self.rec(undecodable_text={"body": "not hex"})

    def test_values_survive_json_with_their_types(self):
        r = ActiveRecord(table="t", rowid=9, ordinal=3, values=[1, 1.0, "1", None, blob(b"\x00"), SpecialFloat(value="-inf"), 2**63 - 1])
        back = ActiveRecord.model_validate_json(r.model_dump_json())
        assert back == r
        assert [c.value for c in back.storage_classes] == ["integer", "real", "text", "null", "blob", "real", "integer"]
        assert type(back.values[0]) is int and type(back.values[1]) is float


# ------------------------------------------------------------------ affinity


@pytest.mark.parametrize("declared,expected", [
    ("INTEGER", TypeAffinity.INTEGER), ("int", TypeAffinity.INTEGER), ("BIGINT", TypeAffinity.INTEGER), ("UNSIGNED BIG INT", TypeAffinity.INTEGER),
    ("POINT", TypeAffinity.INTEGER),  # contains "INT" — the classic surprise in the SQLite documentation
    ("TEXT", TypeAffinity.TEXT), ("VARCHAR(255)", TypeAffinity.TEXT), ("NCHAR(10)", TypeAffinity.TEXT), ("CLOB", TypeAffinity.TEXT),
    ("BLOB", TypeAffinity.BLOB), ("", TypeAffinity.BLOB), (None, TypeAffinity.BLOB),
    ("REAL", TypeAffinity.REAL), ("DOUBLE", TypeAffinity.REAL), ("DOUBLE PRECISION", TypeAffinity.REAL), ("FLOAT", TypeAffinity.REAL),
    ("NUMERIC", TypeAffinity.NUMERIC), ("DECIMAL(10,5)", TypeAffinity.NUMERIC), ("BOOLEAN", TypeAffinity.NUMERIC),
    ("DATETIME", TypeAffinity.NUMERIC), ("TIMESTAMP", TypeAffinity.NUMERIC), ("STRING", TypeAffinity.NUMERIC),
    ("INTEGER TEXT", TypeAffinity.INTEGER),  # rules apply in order: INT wins over TEXT
    ("CHARINT", TypeAffinity.INTEGER),
])
def test_affinity_follows_sqlites_rules(declared, expected):
    assert affinity_of(declared) is expected


# ------------------------------------------------------------------ versions


@pytest.mark.parametrize("number,text", [(3039004, "3.39.4"), (3008010, "3.8.10"), (3000000, "3.0.0"), (3045001, "3.45.1"), (3053003, "3.53.3")])
def test_version_number_decoding(number, text):
    assert decode_version_number(number) == text


class TestVersionInfo:
    def info(self, **fields):
        return version_info(parse_header(header_bytes(**fields)), "3.99.0")

    def test_reliable_when_valid_for_matches_the_change_counter(self):
        v = self.info(change=7, valid_for=7, version=3039004)
        assert (v.last_writer_version, v.last_writer_version_number, v.last_writer_version_reliable) == ("3.39.4", 3039004, True)
        assert v.inspecting_library_version == "3.99.0" and v.notes == []

    def test_flagged_when_the_file_changed_since_the_version_was_stored(self):
        v = self.info(change=9, valid_for=7)
        assert v.last_writer_version == "3.39.4" and v.last_writer_version_reliable is False
        assert "WAL" in v.notes[0] and "may not name the latest writer" in v.notes[0]

    def test_zero_means_no_version_was_recorded(self):
        v = self.info(version=0)
        assert v.last_writer_version is None and v.last_writer_version_reliable is None and "no version number" in v.notes[0]

    @pytest.mark.parametrize("fmt,minimum", [(1, "3.0.0"), (2, "3.1.3"), (3, "3.1.4"), (4, "3.3.0")])
    def test_schema_format_names_the_oldest_reader(self, fmt, minimum):
        v = self.info(fmt=fmt)
        assert (v.schema_format, v.schema_format_min_version) == (fmt, minimum)

    def test_journal_formats(self):
        assert (self.info(write=1, read=1).write_format, self.info(write=1, read=1).read_format) == ("rollback journal", "rollback journal")
        v = self.info(write=2, read=2)
        assert (v.write_format, v.read_format) == ("WAL", "WAL")
        assert self.info(write=3, read=9).write_format == "unknown (3)"

    def test_an_invalid_header_gives_no_facts_but_still_names_the_library(self):
        v = version_info(parse_header(b"not a database" * 10), "3.50.0")
        assert v.last_writer_version is None and v.schema_format is None and v.inspecting_library_version == "3.50.0"


# ------------------------------------------------------------------ table and database invariants


def table(**kw) -> TableInspection:
    base = dict(name="t", kind=TableKind.TABLE, internal=False, columns=[col("id", "INTEGER", pk=1), col("v", "TEXT", cid=1)],
                primary_key=["id"])
    return TableInspection(**{**base, **kw})


class TestTableInspection:
    def test_primary_key_must_agree_with_the_columns(self):
        with pytest.raises(ValidationError, match="primary_key"):
            table(primary_key=["v"])

    def test_composite_key_is_in_key_position_order(self):
        cols = [col("b", "TEXT", pk=2), col("a", "TEXT", pk=1, cid=1), col("c", cid=2)]
        assert table(columns=cols, primary_key=["a", "b"]).primary_key == ["a", "b"]
        with pytest.raises(ValidationError):
            table(columns=cols, primary_key=["b", "a"])

    def test_rowid_alias_rules(self):
        assert table(rowid_alias="id").rowid_alias == "id"
        with pytest.raises(ValidationError, match="must name a column"):
            table(rowid_alias="nope")
        with pytest.raises(ValidationError, match="WITHOUT ROWID"):
            table(rowid_alias="id", without_rowid=True)

    def test_records_must_match_the_data_columns(self):
        with pytest.raises(ValidationError, match="values"):
            table(records=[ActiveRecord(table="t", rowid=1, ordinal=0, values=[1])])

    def test_hidden_virtual_table_columns_are_not_part_of_a_row(self):
        t = table(columns=[col("title", "TEXT"), col("rank", hidden=1, cid=1)], primary_key=[],
                  records=[ActiveRecord(table="t", rowid=1, ordinal=0, values=["a"])])
        assert t.data_columns == ["title"] and t.record_dicts() == [{"title": "a"}]

    def test_generated_columns_are_part_of_a_row(self):
        c = col("b", "INT", hidden=3)
        assert c.is_generated and table(columns=[col("a", "INT"), c], primary_key=[]).data_columns == ["a", "b"]

    def test_record_dicts_and_records_read(self):
        t = table(records=[ActiveRecord(table="t", rowid=1, ordinal=0, values=[1, "x"]), ActiveRecord(table="t", rowid=2, ordinal=1, values=[2, None])])
        assert t.records_read == 2 and t.record_dicts() == [{"id": 1, "v": "x"}, {"id": 2, "v": None}]

    def test_column_flags(self):
        assert col("id", "INTEGER", pk=1).is_primary_key and not col("v").is_primary_key
        with pytest.raises(ValidationError):
            col("x", hidden=4)


def inspection(**kw) -> DatabaseInspection:
    header = parse_header(header_bytes())
    base = dict(
        inspected_at="2026-01-01T00:00:00.000Z", tool_version="0.1.0",
        file=FileFacts(path="/x/a.db", name="a.db", size=12288, sha256=SHA, mtime="2026-01-01T00:00:00.000Z"),
        status=SqliteStatus.VALID, header=header, size=SizeCheck(actual_size=12288, expected_size=12288, consistent=True),
        version=version_info(header, "3.50.0"),
        engine=EngineInfo(open_status=OpenStatus.OK, sqlite_library_version="3.50.0"), integrity=IntegrityResult(status="ok", messages=["ok"]),
        schema_entries=[SchemaEntry(rowid=1, type="table", name="t", table="t", root_page=2, sql="CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")],
        tables=[table()],
    )
    return DatabaseInspection(**{**base, **kw})


class TestDatabaseInspection:
    def test_conveniences(self):
        r = inspection()
        assert r.path == "/x/a.db" and r.is_readable_by_sqlite and r.table("t") is not None and r.table("nope") is None
        assert r.views == [] and r.triggers == [] and r.indexes == [] and r.record_count == 0

    def test_tables_must_match_the_schema(self):
        with pytest.raises(ValidationError, match="match the table entries"):
            inspection(tables=[])
        with pytest.raises(ValidationError, match="duplicate"):
            inspection(tables=[table(), table()])

    def test_a_database_sqlite_did_not_open_has_no_schema(self):
        engine = EngineInfo(open_status=OpenStatus.UNOPENABLE, open_error="malformed", sqlite_library_version="3.50.0")
        with pytest.raises(ValidationError, match="did not open"):
            inspection(engine=engine)
        assert inspection(engine=engine, schema_entries=[], tables=[]).is_readable_by_sqlite is False

    def test_at_most_one_sidecar_per_kind(self):
        s = InspectedSidecar(kind=SidecarKind.WAL, path="/x/a.db-wal", size=10)
        with pytest.raises(ValidationError, match="one sidecar per kind"):
            inspection(sidecars=[s, s])
        assert inspection(sidecars=[s]).sidecar("wal") == s and inspection(sidecars=[s]).sidecar("shm") is None

    def test_iter_records_carries_full_provenance(self):
        t = table(records=[ActiveRecord(table="t", rowid=5, ordinal=0, values=[5, "x"])])
        [row] = list(inspection(tables=[t]).iter_records())
        assert row == {"database": "/x/a.db", "sha256": SHA, "table": "t", "rowid": 5, "ordinal": 0, "state": "ACTIVE", "values": {"id": 5, "v": "x"}}

    def test_json_round_trip_is_lossless(self):
        t = table(records=[ActiveRecord(table="t", rowid=1, ordinal=0, values=[1, "é😀"])])
        r = inspection(tables=[t])
        assert DatabaseInspection.model_validate_json(r.model_dump_json()) == r

    def test_results_are_immutable(self):
        r = inspection()
        with pytest.raises(ValidationError):
            r.status = SqliteStatus.TRUNCATED

    def test_sha256_must_be_well_formed(self):
        with pytest.raises(ValidationError):
            FileFacts(path="/x/a.db", name="a.db", size=1, sha256="abc")


class TestIntegrityResult:
    @pytest.mark.parametrize("status", ["ok", "partial", "failed", "not_run"])
    def test_statuses(self, status):
        assert IntegrityResult(status=status).status == status

    def test_an_error_status_does_not_exist_an_aborted_check_is_a_failed_one(self):
        with pytest.raises(ValidationError):
            IntegrityResult(status="error")

    def test_a_partial_result_carries_its_reason(self):
        r = IntegrityResult(status="partial", messages=["row 1 missing from index i"], caveats=["i uses LOCALIZED"])
        assert IntegrityResult.model_validate_json(r.model_dump_json()) == r
