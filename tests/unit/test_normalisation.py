from datetime import UTC, datetime

from android_forensics.artifacts.schema_probe import FieldSpec, best_matches, probe_table
from android_forensics.artifacts.timestamps import convert, is_plausible, plausible_formats, to_datetime
from android_forensics.normalization.phone import classify_address, normalize_number, phone_key
from android_forensics.sqlite.reader import ColumnInfo, SchemaObject

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_unix_ms_and_webkit_known_values():
    t = convert(1709280000000, "unix_ms", NOW)
    assert t.utc == "2024-03-01T08:00:00.000Z" and t.plausible is True
    # Chromium: 2024-03-01T08:28:12.947Z
    w = convert(13353755292947000, "webkit_us", NOW)
    assert w.utc == "2024-03-01T08:28:12.947Z"
    assert convert(1709280000, "unix_s", NOW).utc == "2024-03-01T08:00:00.000Z"


def test_unset_null_garbage_never_invented():
    assert convert(0, "unix_ms", NOW).utc is None
    assert convert(-5, "unix_ms", NOW).utc is None
    assert convert(None, "unix_ms", NOW).utc is None and convert(None, "unix_ms", NOW).note == "NULL"
    assert convert("abc", "unix_ms", NOW).utc is None
    assert convert(True, "unix_ms", NOW).utc is None
    assert convert(10**30, "unix_ms", NOW).utc is None
    assert convert("1709280000000", "unix_ms", NOW).utc == "2024-03-01T08:00:00.000Z"


def test_plausibility_window():
    old = convert(1000000000000, "unix_ms", NOW)  # 2001
    assert old.utc and old.plausible is False
    future = convert(int(datetime(2030, 1, 1, tzinfo=UTC).timestamp() * 1000), "unix_ms", NOW)
    assert future.plausible is False
    assert is_plausible(to_datetime(1709280000000, "unix_ms"), NOW)


def test_plausible_formats_for_generic_hints():
    assert "unix_ms" in plausible_formats(1709280000000, NOW)
    assert "webkit_us" in plausible_formats(13353755292947000, NOW)
    assert plausible_formats(7, NOW) == [] and plausible_formats("x", NOW) == []


def test_phone_keys_match_across_formats_and_skip_non_numbers():
    variants = ["+1 (202) 555-0123", "202-555-0123", "12025550123", "+12025550123", "(202) 555-0123"]
    assert len({phone_key(v) for v in variants}) == 1
    assert phone_key("+12025550123") == "2025550123"
    assert phone_key("72000") is None and classify_address("72000") == "shortcode"
    assert phone_key("AX-BANKOS") is None and classify_address("AX-BANKOS") == "alphanumeric"
    assert phone_key("") is None and phone_key(None) is None and classify_address(None) == "empty"
    assert normalize_number("+1 202 555 0123") == "+12025550123"


def _table(name, cols):
    return SchemaObject("table", name, name, 2, None, [ColumnInfo(c, "", False, 0) for c in cols])


SPECS = [FieldSpec("a", ("a", "alpha"), True, 2.0), FieldSpec("b", ("b",), False, 1.0), FieldSpec("c", ("c",), False, 1.0)]


def test_schema_probe_scoring_and_required():
    full = probe_table(_table("t", ["ALPHA", "b", "c"]), SPECS)
    assert full.score == 1.0 and full.column_map["a"] == "ALPHA" and full.is_candidate
    partial = probe_table(_table("t", ["a"]), SPECS)
    assert partial.score == 0.5 and partial.missing_optional == ["b", "c"] and partial.is_candidate
    missing_req = probe_table(_table("t", ["b", "c"]), SPECS)
    assert missing_req.missing_required == ["a"] and not missing_req.is_candidate


def test_best_matches_ignores_virtual_and_internal():
    tables = [_table("sqlite_sequence", ["a", "b", "c"]), _table("good", ["a", "b"]), _table("nope", ["x"])]
    tables[0].obj_type = "table"
    v = _table("vt", ["a", "b", "c"])
    v.is_virtual = True
    cands, _ = best_matches(tables + [v], SPECS)
    assert [m.table for m in cands] == ["good"]
