import hashlib

import pytest
from pydantic import ValidationError

from android_forensics.models import (
    ConfidenceFactor,
    ParserInfo,
    PhysicalLocation,
    Provenance,
    RawKind,
    RawReference,
    TimestampFormat,
    TimestampInfo,
)
from tests.unit.models.factories import DB_PATH, SHA, prov


class TestPhysicalLocation:
    def test_page_or_offset_is_enough(self):
        assert PhysicalLocation(page_number=1).byte_offset is None
        assert PhysicalLocation(byte_offset=0).page_number is None

    def test_must_locate_something(self):
        with pytest.raises(ValidationError, match="page number or a byte offset"):
            PhysicalLocation(cell_index=3, region="freeblock")

    @pytest.mark.parametrize("kw", [dict(page_number=0), dict(page_number=-1), dict(byte_offset=-1), dict(page_number=1, cell_index=-1)])
    def test_bounds(self, kw):
        with pytest.raises(ValidationError):
            PhysicalLocation(**kw)

    def test_immutable(self):
        loc = PhysicalLocation(page_number=2)
        with pytest.raises(ValidationError):
            loc.page_number = 3


class TestProvenance:
    def test_active_row_provenance(self):
        p = prov()
        assert (p.source_file, p.source_database, p.source_table, p.source_rowid) == (DB_PATH, DB_PATH, "sms", 5)
        assert p.physical is None, "Review 1 locates active rows logically; page/offset is Review 2"

    def test_source_file_can_differ_from_source_database_for_sidecar_data(self):
        p = prov(source_file=DB_PATH + "-wal", source_sha256="cd" * 32, source_database=DB_PATH)
        assert p.source_file != p.source_database

    def test_hash_must_be_sha256_hex(self):
        for bad in ("a", "A" * 64, "z" * 64):
            with pytest.raises(ValidationError):
                prov(source_sha256=bad)

    def test_evidence_file_id_must_be_positive(self):
        with pytest.raises(ValidationError):
            prov(evidence_file_id=0)

    def test_table_requires_database_and_rowid_requires_table(self):
        with pytest.raises(ValidationError, match="requires source_database"):
            prov(source_database=None)
        with pytest.raises(ValidationError, match="requires source_table"):
            prov(source_table=None)

    def test_file_level_provenance_needs_no_table(self):
        p = prov(source_database=None, source_table=None, source_rowid=None)
        assert p.source_table is None

    def test_negative_rowids_are_legal_in_sqlite(self):
        assert prov(source_rowid=-7).source_rowid == -7

    def test_empty_path_rejected(self):
        with pytest.raises(ValidationError):
            prov(source_file="  ")

    def test_immutable_and_forbids_extras(self):
        p = prov()
        with pytest.raises(ValidationError):
            p.source_table = "x"
        with pytest.raises(ValidationError):
            Provenance(evidence_file_id=1, source_file="a", source_sha256=SHA, sneaky=True)


class TestRawReference:
    def test_row_digest_is_computed_and_independent_of_key_order(self):
        a = RawReference(row={"a": 1, "b": [1, 2], "c": {"x": None}})
        b = RawReference(row={"c": {"x": None}, "b": [1, 2], "a": 1})
        assert a.sha256 == b.sha256 and len(a.sha256) == 64 and a.sha256_of == "row_json"
        assert a.sha256 == hashlib.sha256(b'{"a":1,"b":[1,2],"c":{"x":null}}').hexdigest()

    def test_different_rows_have_different_digests(self):
        assert RawReference(row={"a": 1}).sha256 != RawReference(row={"a": 2}).sha256

    def test_declared_digest_is_verified(self):
        good = RawReference(row={"a": 1})
        assert RawReference(row={"a": 1}, sha256=good.sha256).sha256 == good.sha256
        with pytest.raises(ValidationError, match="digest mismatch"):
            RawReference(row={"a": 2}, sha256=good.sha256)

    def test_byte_reference_digest_is_of_the_bytes(self):
        r = RawReference(kind=RawKind.PAGE_BYTES, raw_bytes_hex="0a1b2c")
        assert r.sha256 == hashlib.sha256(bytes.fromhex("0a1b2c")).hexdigest()
        assert r.sha256_of == "raw_bytes" and r.byte_length == 3

    def test_empty_bytes_are_a_legal_reference(self):
        r = RawReference(kind=RawKind.WAL_FRAME, raw_bytes_hex="")
        assert r.byte_length == 0 and r.sha256 == hashlib.sha256(b"").hexdigest()

    @pytest.mark.parametrize("hex_", ["zz", "abc", "0A1B"])
    def test_bytes_must_be_lowercase_even_length_hex(self, hex_):
        with pytest.raises(ValidationError):
            RawReference(kind=RawKind.PAGE_BYTES, raw_bytes_hex=hex_)

    @pytest.mark.parametrize("kw,msg", [
        (dict(kind=RawKind.SQLITE_ROW), "requires the source row"),
        (dict(kind=RawKind.PAGE_BYTES), "requires raw_bytes_hex"),
        (dict(kind=RawKind.SQLITE_ROW, row={"a": 1}, raw_bytes_hex="00"), "must not carry raw bytes"),
        (dict(kind=RawKind.PAGE_BYTES, row={"a": 1}, raw_bytes_hex="00"), "must not carry a row"),
    ])
    def test_kind_must_match_content(self, kw, msg):
        with pytest.raises(ValidationError, match=msg):
            RawReference(**kw)


class TestParserAndFactor:
    def test_score_bounds(self):
        assert ParserInfo(name="sms", version="1", schema_match_score=0.0).schema_match_score == 0.0
        for bad in (-0.1, 1.01):
            with pytest.raises(ValidationError):
                ParserInfo(name="sms", version="1", schema_match_score=bad)

    def test_factor_needs_an_explanation(self):
        assert ConfidenceFactor(name="schema", satisfied=False, explanation="columns differ").satisfied is False
        for bad in ({"explanation": ""}, {"name": " "}, {"weight": -1}):
            with pytest.raises(ValidationError):
                ConfidenceFactor(**({"name": "n", "satisfied": True, "explanation": "e"} | bad))


class TestTimestampInfo:
    def test_valid_interpretation(self):
        t = TimestampInfo(raw=1709280000000, format="unix_ms", utc="2024-03-01T08:00:00.000Z", plausible=True)
        assert t.format is TimestampFormat.UNIX_MS and t.as_datetime.year == 2024

    def test_unset_value_has_no_interpretation(self):
        t = TimestampInfo(raw=0, format=TimestampFormat.UNIX_MS, note="zero/negative value: treated as unset")
        assert t.utc is None and t.as_datetime is None

    def test_implausible_without_interpretation_is_allowed_but_plausible_is_not(self):
        assert TimestampInfo(raw="x", format=TimestampFormat.UNIX_MS, plausible=False).plausible is False
        with pytest.raises(ValidationError, match="cannot be plausible"):
            TimestampInfo(raw=1, format=TimestampFormat.UNIX_MS, plausible=True)

    def test_utc_must_be_canonical_and_format_required(self):
        with pytest.raises(ValidationError):
            TimestampInfo(raw=1, format=TimestampFormat.UNIX_MS, utc="2024-03-01T08:00:00Z")
        with pytest.raises(ValidationError):
            TimestampInfo(raw=1)
        with pytest.raises(ValidationError):
            TimestampInfo(raw=1, format="julian_day")

    def test_raw_keeps_its_type(self):
        assert isinstance(TimestampInfo(raw=1, format="unix_s").raw, int)
        assert isinstance(TimestampInfo(raw=1.5, format="unix_s").raw, float)
        assert isinstance(TimestampInfo(raw="1", format="unix_s").raw, str)
