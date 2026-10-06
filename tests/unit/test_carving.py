"""Phase 6: raw carving. Strings planted at known offsets in a binary blob must all be found, byte-accurately, and stay candidates."""

from __future__ import annotations

import ast
import hashlib
import random
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from android_forensics.carving import CarveSource, Exclusions, carve_bytes, carve_file
from android_forensics.carving.records import parse_record_at, scan_records
from android_forensics.carving.rules import trim_url
from android_forensics.models import CARVED_CANDIDATE, CarvedCandidate, CarveKind, Confidence, ExtractionMethod
from android_forensics.sqlite.records import encode_record

NOW = datetime(2026, 1, 1, tzinfo=UTC)
PATTERNS = {  # what a planted string of each kind must be reported as
    "phone_e164": CarveKind.PHONE_NUMBER, "phone_nanp_formatted": CarveKind.PHONE_NUMBER, "url_http": CarveKind.URL,
    "url_android": CarveKind.URL, "email": CarveKind.EMAIL, "timestamp_unix_seconds": CarveKind.TIMESTAMP_UNIX_SECONDS,
    "timestamp_unix_millis": CarveKind.TIMESTAMP_UNIX_MILLIS, "timestamp_webkit_micros": CarveKind.TIMESTAMP_WEBKIT_MICROS,
    "timestamp_iso8601": CarveKind.TIMESTAMP_TEXT, "timestamp_medium_date": CarveKind.TIMESTAMP_TEXT,
}
RECORD = encode_record(("+12025550111", 1709280000000, 1, "meet me at the station at noon", None))


NOISE = bytes(range(0x80, 0xC2)) + bytes(range(0xF5, 0x100))  # no ASCII, and no byte that can begin a UTF-8 character


def filler(rng: random.Random, n: int) -> bytes:
    """Bytes that can match nothing: none is ASCII (no rule fits), none is a header-size byte, none can start a UTF-8 character."""
    return bytes(rng.choice(NOISE) for _ in range(n))


def build_blob() -> tuple[bytes, list[dict]]:
    """A blob of filler with known strings planted at known offsets. Returns the bytes and the plan."""
    rng = random.Random(20260922)
    plan = [
        dict(text="+12025550101", pattern="phone_e164"),
        dict(text="(415) 555-2671", pattern="phone_nanp_formatted"),
        dict(text="+442079460958", pattern="phone_e164"),
        dict(text="https://www.example.com/path/page.html?q=1&r=2", pattern="url_http"),
        dict(text="content://com.android.contacts/contacts/lookup/3r3", pattern="url_android"),
        dict(text="ann.lee@example.org", pattern="email"),
        dict(text="1709280000", pattern="timestamp_unix_seconds"),
        dict(text="1709280000123", pattern="timestamp_unix_millis"),
        dict(text="13353753600000000", pattern="timestamp_webkit_micros"),
        dict(text="2024-03-01 08:00:00", pattern="timestamp_iso8601"),
        dict(text="Mar 1, 2024 8:00:00 AM", pattern="timestamp_medium_date"),
        dict(text="+14155552671", pattern="phone_e164", encoding="utf-16le"),
        dict(text="bob@example.net", pattern="email", encoding="utf-16le"),
    ]
    blob = bytearray(filler(rng, 200))
    for item in plan:
        raw = item["text"].encode("utf-16le" if item.get("encoding") == "utf-16le" else "ascii")
        item.update(offset=len(blob), raw=raw, encoding=item.get("encoding", "ascii"))
        blob += raw + filler(rng, rng.randrange(40, 120))
    # an SMS body with its sender's number just before it, an OTP message, and a SQLite record
    sender = b"+12025550199"
    body = b"Hi, are you coming to dinner tonight at eight?"
    plan.append(dict(text=sender.decode(), pattern="phone_e164", offset=len(blob), raw=sender, encoding="ascii"))
    blob += sender + b"\x00\x00\x01\x8d" + filler(rng, 6)
    plan.append(dict(text=body.decode(), pattern="sms_body_near_address", offset=len(blob), raw=body, encoding="ascii"))
    blob += body + filler(rng, 300)  # far enough that the next item is not "near" this sender
    otp = b"Your verification code is 482913. Do not share it with anyone."
    plan.append(dict(text=otp.decode(), pattern="sms_otp_text", offset=len(blob), raw=otp, encoding="ascii"))
    blob += otp + filler(rng, 300)
    plan.append(dict(text=None, pattern="sqlite_record_shape", offset=len(blob), raw=RECORD, encoding="binary"))
    blob += RECORD + filler(rng, 60)
    # the phone number inside the record's text column is a phone hit too (a different kind of finding, found where it really is)
    plan.append(dict(text="+12025550111", pattern="phone_e164", offset=plan[-1]["offset"] + RECORD.index(b"+12025550111"),
                     raw=b"+12025550111", encoding="ascii"))
    return bytes(blob), plan


@pytest.fixture(scope="module")
def blob():
    return build_blob()


SOURCE = CarveSource(evidence_file_id=3, source_file="data/data/x/cache/blob.bin", source_sha256="ab" * 32)


def key(c: CarvedCandidate) -> tuple[int, str]:
    return c.offset, c.pattern


# ------------------------------------------------------------------ the planted-string fixture


def test_every_planted_string_is_found_at_its_exact_offset(blob):
    data, plan = blob
    found = {key(c): c for c in carve_bytes(data, SOURCE, now=NOW).candidates}
    for item in plan:
        c = found.get((item["offset"], item["pattern"]))
        assert c is not None, f"{item['pattern']} planted at {item['offset']} was not found"
        assert c.length == len(item["raw"]) and data[c.offset:c.offset + c.length] == item["raw"], "offset and length are byte-accurate"
        assert c.encoding == item["encoding"] and c.kind is (PATTERNS.get(item["pattern"]) or c.kind)
        if item["text"] is not None:
            assert c.matched == item["text"]


def test_nothing_but_the_planted_strings_is_found(blob):
    """The filler matches no rule: every candidate is one of the planted findings (no false positives in 3 KB of noise)."""
    data, plan = blob
    assert {key(c) for c in carve_bytes(data, SOURCE, now=NOW).candidates} == {(i["offset"], i["pattern"]) for i in plan}


def test_a_hit_carries_its_source_its_context_and_its_method(blob):
    data, plan = blob
    for c in carve_bytes(data, SOURCE, now=NOW).candidates:
        assert (c.evidence_file_id, c.source_file, c.source_sha256) == (3, "data/data/x/cache/blob.bin", "ab" * 32)
        assert c.extraction_method is ExtractionMethod.CARVING and c.container == "file"
        assert bytes.fromhex(c.context_before_hex) == data[max(0, c.offset - 24):c.offset]
        assert bytes.fromhex(c.context_after_hex) == data[c.offset + c.length:c.offset + c.length + 24]
        assert c.pattern and c.kind


def test_the_surrounding_bytes_decide_whether_a_hit_is_delimited(blob):
    data, _ = blob
    assert all(c.context_valid for c in carve_bytes(data, SOURCE, now=NOW).candidates), "filler never continues a token"
    glued = b"\xff\xffname+12025550101trailer\xff"
    (c,) = carve_bytes(glued, SOURCE, now=NOW).candidates
    assert c.matched == "+12025550101" and c.context_valid is False, "glued to letters on both sides: reported, but flagged"


# ------------------------------------------------------------------ nothing is promoted


def test_every_candidate_is_a_carved_candidate_with_no_confidence_yet(blob):
    data, _ = blob
    found = carve_bytes(data, SOURCE, now=NOW).candidates
    assert found and all(c.status == CARVED_CANDIDATE == "CARVED CANDIDATE" for c in found)
    assert all(c.confidence is None and not c.confidence_factors and not c.corroborated_by for c in found), "unscored until correlation"


@pytest.mark.parametrize("status", ["ACTIVE", "RECOVERED", "PARTIAL", "CARVED", "confirmed", "VALID", ""])
def test_a_candidate_cannot_hold_any_other_status(blob, status):
    data, _ = blob
    c = carve_bytes(data, SOURCE, now=NOW).candidates[0]
    with pytest.raises(ValidationError):
        CarvedCandidate(**{**c.model_dump(), "status": status})


def test_a_candidate_can_never_be_high_confidence(blob):
    data, _ = blob
    c = carve_bytes(data, SOURCE, now=NOW).candidates[0]
    with pytest.raises(ValidationError):
        CarvedCandidate(**{**c.model_dump(), "confidence": Confidence.HIGH})


SRC = Path(__file__).resolve().parents[2] / "src" / "android_forensics"
PROMOTING = {"ACTIVE", "RECOVERED", "PARTIAL", "CORRUPTED", "CARVED"}
# where ArtifactStatus values legitimately appear next to CarvedCandidate: the model module that defines both invariants
ALLOWED_TOGETHER = {"models/recovery.py"}


def _references(tree: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name or isinstance(n, ast.alias) and (n.asname or n.name) == name
               or isinstance(n, ast.Attribute) and n.attr == name for n in ast.walk(tree))


def test_no_module_that_handles_carved_candidates_assigns_an_evidence_status():
    """The code-level check the spec asks for: a module that mentions CarvedCandidate must not also name a status a confirmed
    artifact carries (``ArtifactStatus.ACTIVE`` / ``RECOVERED`` / ...). Promotion would need both in one place."""
    offenders = []
    handled = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        tree = ast.parse(path.read_text())
        if not _references(tree, "CarvedCandidate") or rel in ALLOWED_TOGETHER:
            continue
        handled.append(rel)
        for n in ast.walk(tree):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "ArtifactStatus" and n.attr in PROMOTING:
                offenders.append(f"{rel}:{n.lineno} ArtifactStatus.{n.attr}")
    assert "carving/carver.py" in handled and "storage/recovery_store.py" in handled, "the check must actually be looking at the carver"
    assert not offenders, offenders


def test_the_carving_package_never_touches_the_artifact_model():
    """Carving imports nothing that can build an artifact: it can only produce candidates."""
    for path in sorted((SRC / "carving").glob("*.py")):
        for n in ast.walk(ast.parse(path.read_text())):
            if isinstance(n, ast.ImportFrom) and n.module:
                assert not n.module.startswith(("android_forensics.artifacts.base", "android_forensics.artifacts.recovered",
                                                "android_forensics.artifacts.registry", "android_forensics.confidence")), f"{path.name}: {n.module}"
                names = {a.name for a in n.names}
                assert not names & {"Artifact", "ArtifactStatus", "SMSMessage", "CallRecord", "GenericRecord", "RecoveredRecord"}, f"{path.name}: {names}"


# ------------------------------------------------------------------ windowed scanning

def test_scanning_a_file_in_small_windows_gives_the_same_result_as_scanning_it_whole(blob, tmp_path):
    data, _ = blob
    path = tmp_path / "blob.bin"
    path.write_bytes(data)
    whole = carve_bytes(data, SOURCE, now=NOW).candidates
    for window, overlap in ((257, 300), (1000, 400), (len(data) + 5, 100)):
        windowed = carve_file(path, SOURCE, now=NOW, window=window, overlap=overlap).candidates
        assert [c.model_dump() for c in windowed] == [c.model_dump() for c in whole], (window, overlap)


def test_carving_never_modifies_the_evidence(blob, tmp_path):
    data, _ = blob
    path = tmp_path / "blob.bin"
    path.write_bytes(data)
    before = (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
    carve_file(path, SOURCE, now=NOW)
    assert (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns) == before
    assert [p.name for p in tmp_path.iterdir()] == ["blob.bin"]


def test_carving_is_deterministic(blob):
    data, _ = blob
    a = [c.model_dump() for c in carve_bytes(data, SOURCE, now=NOW).candidates]
    assert a == [c.model_dump() for c in carve_bytes(data, SOURCE, now=NOW).candidates]
    assert a == sorted(a, key=lambda c: (c["offset"], c["kind"], c["pattern"], c["encoding"]))


def test_base_offset_shifts_every_hit(blob):
    data, _ = blob
    plain = carve_bytes(data, SOURCE, now=NOW).candidates
    shifted = carve_bytes(data, SOURCE, now=NOW, base_offset=4096).candidates
    assert [c.offset + 0 for c in shifted] == [c.offset + 4096 for c in plain]


# ------------------------------------------------------------------ exclusions and options


def test_hits_inside_excluded_ranges_are_dropped_and_counted(blob):
    data, plan = blob
    first = plan[0]
    result = carve_bytes(data, SOURCE, now=NOW, exclude=[(first["offset"] + 3, first["offset"] + 5)])
    assert (first["offset"], first["pattern"]) not in {key(c) for c in result.candidates}
    assert result.stats["excluded_overlaps"] == 1
    assert len(result.candidates) == len(carve_bytes(data, SOURCE, now=NOW).candidates) - 1


def test_a_hit_that_only_touches_an_excluded_range_is_kept(blob):
    data, plan = blob
    a = plan[0]
    result = carve_bytes(data, SOURCE, now=NOW, exclude=[(a["offset"] - 10, a["offset"]), (a["offset"] + len(a["raw"]), a["offset"] + len(a["raw"]) + 10)])
    assert (a["offset"], a["pattern"]) in {key(c) for c in result.candidates}


def test_exclusions_merge_and_answer_overlap_questions():
    ex = Exclusions([(10, 20), (15, 30), (50, 60), (5, 5)])
    assert len(ex) == 2
    assert [ex.overlaps(a, b) for a, b in ((0, 10), (0, 11), (29, 31), (30, 50), (49, 51), (60, 70), (25, 26))] == [False, True, True, False, True, False, True]


def test_kinds_restricts_what_is_looked_for(blob):
    data, _ = blob
    only = carve_bytes(data, SOURCE, now=NOW, kinds=[CarveKind.EMAIL]).candidates
    assert {c.kind for c in only} == {CarveKind.EMAIL} and len(only) == 2


def test_the_limit_truncates_deterministically_and_says_so(blob):
    data, _ = blob
    full = carve_bytes(data, SOURCE, now=NOW).candidates
    cut = carve_bytes(data, SOURCE, now=NOW, limit=5)
    assert cut.stats["truncated"] and [key(c) for c in cut.candidates] == [key(c) for c in full[:5]]


def test_stats_report_what_was_scanned_and_found(blob):
    data, plan = blob
    stats = carve_bytes(data, SOURCE, now=NOW).stats
    assert stats["bytes_scanned"] == len(data) and stats["candidates"] == len(plan) and stats["truncated"] is False
    assert sum(stats["hits_by_pattern"].values()) == len(plan)


# ------------------------------------------------------------------ what is *not* reported


@pytest.mark.parametrize("text", [
    b"12025550101", b"+1202555010", b"+11025550101", b"+1 (911) 555-0101", b"1000000000", b"2100000000", b"17092800001",
    b"2024-02-30 08:00:00", b"2024-13-01 08:00:00", b"1995-03-01 08:00:00", b"https://nodots/x", b"http://999.1.1.1/",
    b"a..b@example.com", b"a@b", b"user@example.c", b"Foo 1, 2024 8:00 AM", b"4111111111111111",
])
def test_shapes_that_fail_their_own_validation_are_not_reported(text):
    assert carve_bytes(b"\xff\xfe" + text + b"\xff\xfe", SOURCE, now=NOW).candidates == []


def test_a_date_after_now_is_not_plausible():
    future = b"\xff" + b"2999-01-01 00:00:00" + b"\xff"
    assert carve_bytes(future, SOURCE, now=NOW).candidates == []
    assert carve_bytes(b"\xff" + b"2025-06-01 00:00:00" + b"\xff", SOURCE, now=NOW).candidates


def test_url_punctuation_around_a_link_is_not_part_of_it():
    (c,) = carve_bytes(b"\xffsee (https://en.wikipedia.org/wiki/Foo_(bar)), ok\xff", SOURCE, now=NOW).candidates
    assert c.matched == "https://en.wikipedia.org/wiki/Foo_(bar)"
    assert trim_url("https://a.com/x).") == "https://a.com/x"


def test_the_last_byte_of_a_file_is_scanned():
    (c,) = carve_bytes(b"\xff\xfe+12025550101", SOURCE, now=NOW).candidates
    assert c.offset == 2 and c.length == 12 and c.context_after_hex == "" and c.context_valid


def test_empty_and_tiny_inputs_are_fine():
    assert carve_bytes(b"", SOURCE, now=NOW).candidates == [] and carve_bytes(b"\x00", SOURCE, now=NOW).candidates == []


# ------------------------------------------------------------------ SMS-like text


def test_an_sms_backup_xml_element_yields_its_body_with_the_address_and_date_as_notes():
    xml = b'<sms protocol="0" address="+12025550101" date="1709280000000" type="1" body="Running late, start without me" read="1" />'
    hits = [c for c in carve_bytes(xml, SOURCE, now=NOW).candidates if c.kind is CarveKind.SMS_LIKE_TEXT]
    assert len(hits) == 1 and hits[0].pattern == "sms_backup_xml" and hits[0].matched == "Running late, start without me"
    assert xml[hits[0].offset:hits[0].offset + hits[0].length] == b"Running late, start without me"
    assert hits[0].notes == ["address=+12025550101", "date=1709280000000"]


def test_a_sentence_with_nothing_around_it_is_not_an_sms():
    text = b"\xff\xff" + b"The quick brown fox jumps over the lazy dog and keeps running" + b"\xff\xff"
    assert [c for c in carve_bytes(text, SOURCE, now=NOW).candidates if c.kind is CarveKind.SMS_LIKE_TEXT] == []


def test_an_sms_body_touching_its_address_is_supported_by_it():
    text = b"\xff\xff+12025550101Are you free for lunch on friday\xff\xff"
    found = [c for c in carve_bytes(text, SOURCE, now=NOW).candidates if c.kind is CarveKind.SMS_LIKE_TEXT]
    assert len(found) == 1 and found[0].pattern == "sms_body_near_address"


def test_a_number_quoted_inside_the_text_does_not_make_it_a_message():
    text = b"\xff\xff" + b"The office can be reached on +12025550101 during opening hours today" + b"\xff\xff"
    assert [c for c in carve_bytes(text, SOURCE, now=NOW).candidates if c.kind is CarveKind.SMS_LIKE_TEXT] == []


def test_a_body_beside_a_millisecond_timestamp_is_supported_by_it():
    text = b"1709280000123 " + b"\xff\xff\xff" + b"Please call me back when you get this message" + b"\xff"
    found = [c for c in carve_bytes(text, SOURCE, now=NOW).candidates if c.kind is CarveKind.SMS_LIKE_TEXT]
    assert len(found) == 1 and found[0].pattern == "sms_body_near_timestamp"


# ------------------------------------------------------------------ SQLite record shapes


def test_a_record_is_recognised_and_decoded():
    data = b"\xff" * 9 + RECORD + b"\xff" * 9
    (hit,) = scan_records(data, 0, len(data))
    assert (hit.start, hit.end) == (9, 9 + len(RECORD))
    assert hit.values == ("+12025550111", 1709280000000, 1, "meet me at the station at noon", None)
    assert hit.render().startswith('["+12025550111", 1709280000000')


def test_random_bytes_are_not_records():
    rng = random.Random(1)
    noise = bytes(rng.randrange(256) for _ in range(200_000))
    assert scan_records(noise, 0, len(noise)) == []


def test_a_record_needs_real_text_three_columns_and_a_consistent_header():
    no_text = encode_record((1, 2, 3, 4, 1709280000000))
    two_cols = encode_record(("hello world", 5))
    all_null = encode_record((None, None, None, "abcd"))
    mostly_binary = encode_record((1, b"\x00\x01\x02\x03\x04", 3))
    bad_header = bytearray(RECORD)
    bad_header[0] += 1  # header claims one more byte than its types use
    for candidate in (no_text, two_cols, all_null, mostly_binary, bytes(bad_header)):
        assert parse_record_at(b"\xff" + candidate + b"\xff", 1) is None


def test_a_record_that_runs_off_the_end_is_not_reported():
    assert parse_record_at(RECORD[:-5], 0) is None
    assert scan_records(RECORD[:-5], 0, len(RECORD)) == []


def test_records_are_reported_once_and_do_not_overlap():
    data = RECORD + b"\xff\xff" + RECORD
    hits = scan_records(data, 0, len(data))
    assert [(h.start, h.end) for h in hits] == [(0, len(RECORD)), (len(RECORD) + 2, 2 * len(RECORD) + 2)]


def test_utf16_text_is_carved_with_offsets_in_bytes():
    raw = "+14155552671".encode("utf-16le")
    data = b"\xff" * 7 + raw + b"\xff" * 7
    (c,) = carve_bytes(data, SOURCE, now=NOW).candidates
    assert (c.offset, c.length, c.encoding, c.matched) == (7, len(raw), "utf-16le", "+14155552671")
