"""Validation checks. Each check yields ``ValidationResult`` models; failures are recorded with an explanation, never dropped."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from android_forensics.acquisition.hashing import hash_file
from android_forensics.models import ValidationResult
from android_forensics.models import ValidationStatus as VS
from android_forensics.models.types import canonical_json
from android_forensics.progress import NullProgress, Progress
from android_forensics.storage.case_store import CaseStore

FAILURE_ROW_CAP = 200


@dataclass
class Options:
    rehash_originals: bool = True
    progress: Progress = field(default_factory=NullProgress)


# ---------------------------------------------------------------- integrity of evidence


def _sha256_or_none(p: Path) -> str | None:
    """SHA-256 of a file, or None if it cannot be read (missing, permission denied, or now a symlink)."""
    try:
        return hash_file(p).sha256
    except OSError:
        return None


def check_hash_consistency(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    total = store.scalar("SELECT COUNT(*) FROM evidence_files") or 0
    opts.progress.start("Re-verifying SHA-256 hashes", total)
    for src in store.sources():
        label = f"source s{src.id} {src.original_name}"
        orig = Path(src.original_path)
        if src.container_hashes is not None:
            recorded = src.container_hashes.sha256
            if not opts.rehash_originals:
                yield ValidationResult.of("source", src.id, label, "hash_consistency", VS.UNVERIFIED, "original re-hash skipped by option")
            elif not orig.is_file() or (now := _sha256_or_none(orig)) is None:
                yield ValidationResult.of("source", src.id, label, "hash_consistency", VS.UNVERIFIED,
                                          f"original container no longer available (or unreadable) at {orig}; cannot re-verify against the recorded SHA-256")
            else:
                ok = now == recorded
                yield ValidationResult.of("source", src.id, label, "hash_consistency", VS.VALID if ok else VS.INVALID,
                                          "container SHA-256 matches ingest-time hash" if ok else
                                          f"container SHA-256 CHANGED since ingest: recorded {recorded}, now {now}",
                                          {"recorded": recorded, "current": now})
        else:
            bad, missing, checked = [], [], 0
            for f in store.evidence_files(src.id):
                if not opts.rehash_originals:
                    break
                p = orig / f.path if orig.is_dir() else orig.parent / f.path
                digest = _sha256_or_none(p) if p.is_file() else None
                if digest is None:
                    missing.append(f.path)
                    continue
                checked += 1
                if digest != f.hashes.sha256:
                    bad.append(f.path)
            if not opts.rehash_originals:
                yield ValidationResult.of("source", src.id, label, "hash_consistency", VS.UNVERIFIED, "original re-hash skipped by option")
            elif bad:
                yield ValidationResult.of("source", src.id, label, "hash_consistency", VS.INVALID,
                                          f"{len(bad)} original file(s) changed since ingest", {"changed": bad[:FAILURE_ROW_CAP]})
            elif missing:
                yield ValidationResult.of("source", src.id, label, "hash_consistency", VS.PARTIAL,
                                          f"{checked} originals verified; {len(missing)} no longer available for re-verification",
                                          {"missing": missing[:FAILURE_ROW_CAP]})
            else:
                yield ValidationResult.of("source", src.id, label, "hash_consistency", VS.VALID,
                                          f"all {checked} original files re-hashed and match ingest-time SHA-256")
    bad_copies, checked = [], 0
    for f in store.evidence_files():
        if not f.is_preserved or f.preserved_copy is None:
            continue
        p = store.evidence_dir / f"s{f.source_id}" / f.preserved_copy
        opts.progress.advance()
        if not p.is_file():
            bad_copies.append((f.id, f.path, "preserved copy missing"))
        elif _sha256_or_none(p) != f.hashes.sha256:
            bad_copies.append((f.id, f.path, "preserved copy is unreadable or its hash differs from the recorded SHA-256"))
        checked += 1
    opts.progress.stop()
    for fid, path, why in bad_copies[:FAILURE_ROW_CAP]:
        yield ValidationResult.of("file", fid, path, "hash_consistency", VS.INVALID, why)
    yield ValidationResult.of("case", None, "preserved evidence copies", "hash_consistency",
                              VS.INVALID if bad_copies else VS.VALID,
                              f"{len(bad_copies)} of {checked} preserved copies failed verification" if bad_copies
                              else f"all {checked} write-protected preserved copies match their recorded SHA-256")

    ok, msg = store.verify_custody_chain()
    yield ValidationResult.of("case", None, "chain-of-custody log", "custody_chain", VS.VALID if ok else VS.INVALID, msg)
    last = store.one("SELECT detail_json FROM custody_log WHERE action='ingest_completed' ORDER BY id DESC LIMIT 1")
    if last and store.manifest_path.is_file():
        recorded = json.loads(last["detail_json"]).get("manifest_sha256")
        actual = hashlib.sha256(store.manifest_path.read_bytes()).hexdigest()
        yield ValidationResult.of("case", None, "evidence_manifest.json", "manifest_integrity",
                                  VS.VALID if recorded == actual else VS.INVALID,
                                  "manifest matches the hash recorded in the custody log" if recorded == actual
                                  else "manifest file differs from the hash logged at ingest — it was modified after ingestion",
                                  {"recorded": recorded, "current": actual})
    elif last:
        yield ValidationResult.of("case", None, "evidence_manifest.json", "manifest_integrity", VS.INVALID, "manifest file is missing")


def check_acquisition(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    for src in store.sources():
        issues = store.q("SELECT issue_type, COUNT(*) n FROM scan_issues WHERE source_id=? AND stage='ingest' GROUP BY issue_type", (src.id,))
        label = f"source s{src.id} {src.original_name}"
        counts = {r["issue_type"]: r["n"] for r in issues}
        if not src.complete:
            yield ValidationResult.of("source", src.id, label, "acquisition_completeness", VS.INVALID,
                                      "acquisition is INCOMPLETE (archive truncated/unreadable or a safety budget was exceeded)", counts)
        elif counts:
            yield ValidationResult.of("source", src.id, label, "acquisition_completeness", VS.PARTIAL,
                                      "acquisition finished but some entries were skipped: " + ", ".join(f"{k}×{v}" for k, v in counts.items()), counts)
        else:
            yield ValidationResult.of("source", src.id, label, "acquisition_completeness", VS.VALID,
                                      f"all {src.file_count} entries acquired; none skipped")


# ---------------------------------------------------------------- SQLite level


_EXPECTED_BY_NAME = {"mmssms.db": "sms", "calllog.db": "call", "contacts2.db": "contact", "history": "browser_visit", "logs.db": "call"}


def check_sqlite(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    rows = store.q("SELECT d.*, f.path FROM databases d JOIN evidence_files f ON f.id=d.evidence_file_id ORDER BY d.id")
    for d in rows:
        label = d["path"]
        if d["open_status"] == "encrypted_suspect":
            yield ValidationResult.of("database", d["id"], label, "sqlite_header", VS.UNVERIFIED, d["open_error"] or "encrypted", {})
            yield ValidationResult.of("database", d["id"], label, "sqlite_integrity", VS.UNVERIFIED, "not attempted: file appears encrypted")
            continue
        if d["open_status"] == "not_preserved":
            yield ValidationResult.of("database", d["id"], label, "sqlite_header", VS.UNVERIFIED, d["open_error"])
            yield ValidationResult.of("database", d["id"], label, "sqlite_integrity", VS.UNVERIFIED, "not attempted: no working copy to open")
            continue
        if not d["header_valid"]:
            yield ValidationResult.of("database", d["id"], label, "sqlite_header", VS.INVALID, d["open_error"] or "invalid header")
        else:
            warnings = json.loads(d["warnings_json"] or "[]")
            if d["size_consistent"] == 0:
                yield ValidationResult.of("database", d["id"], label, "sqlite_header", VS.PARTIAL,
                              "header valid but file size is inconsistent: " + "; ".join(warnings), {"warnings": warnings})
            else:
                yield ValidationResult.of("database", d["id"], label, "sqlite_header", VS.VALID,
                              f"valid SQLite 3 header (page size {d['page_size']}, {d['text_encoding']}, {d['journal_mode']} mode)",
                              {"warnings": warnings})
        st = d["integrity_status"]
        yield ValidationResult.of("database", d["id"], label, "sqlite_integrity", VS(st) if st in VS.__members__ else VS.UNVERIFIED,
                      d["integrity_detail"] or ("database could not be opened" if d["open_status"] != "ok" else "PRAGMA integrity_check: ok"))
        if d["decode_errors"]:
            yield ValidationResult.of("database", d["id"], label, "text_decoding", VS.PARTIAL,
                          f"{d['decode_errors']} text value(s) were not valid UTF-8 and were decoded with U+FFFD replacement; "
                          "original bytes are examined by the Review 2 raw analysis")
        if d["open_status"] == "ok":
            expected = _EXPECTED_BY_NAME.get(label.rsplit("/", 1)[-1].lower())
            if expected:
                n = store.scalar("SELECT COUNT(*) FROM artifacts WHERE database_id=? AND artifact_type=?", (d["id"], expected))
                tables = store.scalar("SELECT COUNT(*) FROM db_tables WHERE database_id=? AND parsed_by IS NOT NULL", (d["id"],))
                if not tables:
                    yield ValidationResult.of("database", d["id"], label, "filename_schema_agreement", VS.PARTIAL,
                                  f"file name suggests {expected} data but no table matched a {expected} schema")
                else:
                    yield ValidationResult.of("database", d["id"], label, "filename_schema_agreement", VS.VALID,
                                  f"file name and content agree ({n} {expected} artifacts)")


def check_schema(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    for t in store.q(
        "SELECT t.*, f.path FROM db_tables t JOIN databases d ON d.id=t.database_id JOIN evidence_files f ON f.id=d.evidence_file_id "
        "WHERE t.parsed_by IS NOT NULL ORDER BY t.id"
    ):
        label = f"{t['path']} :: {t['name']}"
        if t["read_error"]:
            yield ValidationResult.of("table", t["id"], label, "schema_consistency", VS.PARTIAL,
                          f"table matched {t['parsed_by']} ({t['schema_variant']}) but reading stopped early: {t['read_error']}")
            continue
        unknown = set()
        for r in store.q("SELECT unknown_fields_json FROM artifacts WHERE database_id=? AND source_table=? LIMIT 500", (t["database_id"], t["name"])):
            unknown.update(json.loads(r[0] or "[]"))
        if (t["schema_score"] or 0) >= 0.999:
            yield ValidationResult.of("table", t["id"], label, "schema_consistency", VS.VALID,
                          f"all fields known to the {t['parsed_by']} parser are present ({t['schema_variant']})")
        else:
            yield ValidationResult.of("table", t["id"], label, "schema_consistency", VS.PARTIAL,
                          f"schema match score {t['schema_score']} for {t['parsed_by']} ({t['schema_variant']}); fields absent from this "
                          f"schema version are reported as UNKNOWN, not guessed: {sorted(unknown) or 'see parser field list'}",
                          {"unknown_fields": sorted(unknown)})


# ---------------------------------------------------------------- artifact level


def _group_by_table(store: CaseStore, where: str = "1=1") -> dict[tuple, list]:
    groups: dict[tuple, list] = defaultdict(list)
    for r in store.q(
        f"SELECT id, database_id, source_table, artifact_type, flags_json, ts_utc, ts_raw, ts_plausible, ts_note FROM artifacts "
        f"WHERE artifact_type!='app_summary' AND {where}"
    ):
        groups[(r["database_id"], r["source_table"], r["artifact_type"])].append(r)
    return groups


def _label(store: CaseStore, key: tuple) -> str:
    row = store.one("SELECT f.path FROM databases d JOIN evidence_files f ON f.id=d.evidence_file_id WHERE d.id=?", (key[0],))
    return f"{row['path'] if row else '?'} :: {key[1]} ({key[2]})"


def check_record_structure(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    for key, rows in _group_by_table(store).items():
        label = _label(store, key)
        flagged = [(r["id"], json.loads(r["flags_json"] or "[]")) for r in rows]
        flagged = [(i, f) for i, f in flagged if f]
        if not flagged:
            yield ValidationResult.of("table", None, label, "record_structure", VS.VALID,
                          f"{len(rows)} records: field types consistent with the schema", {"records": len(rows)})
            continue
        ratio = len(flagged) / len(rows)
        yield ValidationResult.of("table", None, label, "record_structure", VS.INVALID if ratio >= 0.5 else VS.PARTIAL,
                      f"{len(flagged)} of {len(rows)} records have structural/datatype anomalies",
                      {"anomalous": len(flagged), "records": len(rows)})
        for aid, flags in flagged[:FAILURE_ROW_CAP]:
            yield ValidationResult.of("artifact", aid, label, "record_structure", VS.PARTIAL, "; ".join(flags))


def check_timestamps(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    for key, rows in _group_by_table(store).items():
        label = _label(store, key)
        bad = [r for r in rows if r["ts_raw"] is not None and (r["ts_plausible"] == 0 or (r["ts_utc"] is None and r["ts_note"] not in (None, "NULL")))]
        with_ts = [r for r in rows if r["ts_utc"]]
        if not bad:
            yield ValidationResult.of("table", None, label, "timestamp_plausibility", VS.VALID if with_ts else VS.UNVERIFIED,
                          f"{len(with_ts)} of {len(rows)} records carry a plausible timestamp (2008-01-01 … now)" if with_ts
                          else "records carry no timestamp to check")
            continue
        yield ValidationResult.of("table", None, label, "timestamp_plausibility", VS.PARTIAL,
                      f"{len(bad)} of {len(rows)} timestamps are implausible or unparseable (outside 2008-01-01…now+2d, non-numeric, or out of range)",
                      {"implausible": len(bad)})
        for r in bad[:FAILURE_ROW_CAP]:
            yield ValidationResult.of("artifact", r["id"], label, "timestamp_plausibility", VS.PARTIAL,
                          f"raw={r['ts_raw']} interpreted as {r['ts_utc']}: {r['ts_note'] or 'outside plausible window'}")


_DUP_KEYS = {
    "sms": ("address", "body", "type_code"),
    "call": ("number", "type_code", "duration_seconds"),
    "browser_visit": ("url", "transition"),
    "contact": ("display_name",),
}


def check_duplicates(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    for atype, keys in _DUP_KEYS.items():
        groups: dict[tuple, list] = defaultdict(list)
        total = 0
        for r in store.q("SELECT id, database_id, source_table, ts_raw, fields_json, phone_key FROM artifacts WHERE artifact_type=?", (atype,)):
            f = json.loads(r["fields_json"])
            k = (r["ts_raw"],) + tuple(json.dumps(f.get(x)) for x in keys)
            if atype == "contact":
                k = k + (r["phone_key"],)
            groups[k].append(r)
            total += 1
        dups = [g for g in groups.values() if len(g) > 1]
        if not dups:
            if total:
                yield ValidationResult.of("case", None, f"{atype} artifacts", "duplicate_detection", VS.VALID, f"no duplicate {atype} records among {total}")
            continue
        yield ValidationResult.of("case", None, f"{atype} artifacts", "duplicate_detection", VS.PARTIAL,
                      f"{len(dups)} duplicate group(s) covering {sum(len(g) for g in dups)} of {total} records", {"groups": len(dups)})
        for g in dups[:FAILURE_ROW_CAP]:
            spans = {(r["database_id"], r["source_table"]) for r in g}
            where = "same table" if len(spans) == 1 else f"{len(spans)} different tables/databases (e.g. backup copy)"
            yield ValidationResult.of("artifact", g[0]["id"], f"{atype} duplicate group", "duplicate_detection", VS.PARTIAL,
                          f"{len(g)} records with identical timestamp and content in {where}", {"artifact_ids": [r["id"] for r in g]})


def check_cross_artifact(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    contacts: dict[str, set[str]] = defaultdict(set)
    for r in store.q("SELECT fields_json, marked_deleted FROM artifacts WHERE artifact_type='contact'"):
        f = json.loads(r["fields_json"])
        for p in f.get("phones", []):
            if p.get("phone_key") and f.get("display_name"):
                contacts[p["phone_key"]].add(f["display_name"].strip().lower())
    n_calls = store.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='call'") or 0
    if n_calls:
        mism = []
        matched = 0
        for r in store.q("SELECT id, phone_key, fields_json FROM artifacts WHERE artifact_type='call' AND phone_key IS NOT NULL"):
            f = json.loads(r["fields_json"])
            names = contacts.get(r["phone_key"])
            if names:
                matched += 1
            if names and f.get("cached_name") and f["cached_name"].strip().lower() not in names:
                mism.append((r["id"], f["cached_name"], sorted(names)))
        yield ValidationResult.of("case", None, "call log vs contacts", "cross_artifact_consistency",
                      VS.PARTIAL if mism else (VS.VALID if contacts else VS.UNVERIFIED),
                      (f"{len(mism)} call(s) carry a cached name that differs from the contact stored for the same number"
                       if mism else ("cached call names agree with contacts" if contacts else "no contacts artifact available to compare"))
                      + f"; {matched} of {n_calls} calls have a number present in contacts",
                      {"mismatches": len(mism), "calls_with_contact": matched})
        for aid, cached, contact_names in mism[:FAILURE_ROW_CAP]:
            yield ValidationResult.of("artifact", aid, "call cached name", "cross_artifact_consistency", VS.PARTIAL,
                          f"cached name '{cached}' vs contact name(s) {contact_names}")
        odd = store.q(
            "SELECT id, summary FROM artifacts WHERE artifact_type='call' AND json_extract(fields_json,'$.call_type') IN ('MISSED','REJECTED','BLOCKED') "
            "AND json_extract(fields_json,'$.duration_seconds') > 0"
        )
        if odd:
            yield ValidationResult.of("case", None, "call type vs duration", "cross_artifact_consistency", VS.PARTIAL,
                          f"{len(odd)} missed/rejected/blocked call(s) report a non-zero duration", {"artifact_ids": [r['id'] for r in odd][:FAILURE_ROW_CAP]})
    multi = store.q(
        "SELECT json_extract(fields_json,'$.thread_id') t, COUNT(DISTINCT json_extract(fields_json,'$.address')) n FROM artifacts "
        "WHERE artifact_type='sms' AND json_extract(fields_json,'$.address') IS NOT NULL GROUP BY t HAVING n>1"
    )
    if store.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='sms'"):
        yield ValidationResult.of("case", None, "SMS thread consistency", "cross_artifact_consistency",
                      VS.PARTIAL if multi else VS.VALID,
                      f"{len(multi)} thread(s) contain messages from more than one address (possible group conversation or damage)"
                      if multi else "every SMS thread maps to a single address")


def check_provenance(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    total = store.scalar("SELECT COUNT(*) FROM artifacts") or 0
    if not total:
        return
    missing = store.q(
        "SELECT id FROM artifacts WHERE source_sha256='' OR evidence_file_id IS NULL OR "
        "(artifact_type!='app_summary' AND source_table IS NULL)"
    )
    mismatch = store.q(
        "SELECT a.id FROM artifacts a JOIN evidence_files f ON f.id=a.evidence_file_id WHERE a.source_sha256 != f.sha256"
    )
    # Each artifact's raw reference is bound to its source row by a digest; a stored row edited after
    # extraction no longer matches it.
    tampered = []
    verified = 0
    for r in store.conn.execute("SELECT id, raw_row_json, raw_sha256 FROM artifacts WHERE raw_row_json IS NOT NULL"):
        digest = hashlib.sha256(canonical_json(json.loads(r["raw_row_json"])).encode("utf-8")).hexdigest()
        if digest == r["raw_sha256"]:
            verified += 1
        else:
            tampered.append(r["id"])
    norowid = store.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type!='app_summary' AND source_rowid IS NULL") or 0
    bad = len(missing) + len(mismatch) + len(tampered)
    if bad:
        detail = (f"{len(missing)} artifact(s) lack complete provenance, {len(mismatch)} cite a hash that differs from the evidence "
                  f"inventory, {len(tampered)} have a raw row that no longer matches its recorded digest")
    else:
        detail = (f"all {total} artifacts trace to an evidence file, SHA-256, table and row; {verified} raw source rows match their digests"
                  + (f" ({norowid} from WITHOUT ROWID tables carry no rowid)" if norowid else ""))
    yield ValidationResult.of("case", None, "artifact provenance", "provenance_completeness", VS.INVALID if bad else VS.VALID, detail,
                              {"incomplete": [r["id"] for r in missing][:FAILURE_ROW_CAP],
                               "hash_mismatch": [r["id"] for r in mismatch][:FAILURE_ROW_CAP],
                               "raw_digest_mismatch": tampered[:FAILURE_ROW_CAP]})


# ---------------------------------------------------------------- Review 2: recovered / carved data


def check_recovery_integrity(store: CaseStore, opts: Options) -> Iterator[ValidationResult]:
    """A recovered record's raw bytes match their stored digest, and its reconstructed artifact (if any) still carries the
    same bytes; a carved candidate is still, in the database itself, exactly the unconfirmed candidate it was created as."""
    total_recovered = store.scalar("SELECT COUNT(*) FROM recovered_records") or 0
    if total_recovered:
        bad_digest = []
        bad_link = []
        for r in store.q("SELECT id, raw_hex, raw_sha256, artifact_id FROM recovered_records"):
            if hashlib.sha256(bytes.fromhex(r["raw_hex"])).hexdigest() != r["raw_sha256"]:
                bad_digest.append(r["id"])
                continue
            if r["artifact_id"] is not None:
                art = store.one("SELECT raw_hex FROM artifacts WHERE id=?", (r["artifact_id"],))
                if art is None or art["raw_hex"] != r["raw_hex"]:
                    bad_link.append(r["id"])
        label = "recovered records"
        if bad_digest or bad_link:
            yield ValidationResult.of("case", None, label, "record_structure",
                          VS.INVALID, f"{len(bad_digest)} recovered record(s) have raw bytes that no longer match their recorded "
                          f"digest, {len(bad_link)} are linked to an artifact whose raw bytes differ from the record's own",
                          {"digest_mismatch": bad_digest[:FAILURE_ROW_CAP], "link_mismatch": bad_link[:FAILURE_ROW_CAP]})
        else:
            reconstructed = store.scalar("SELECT COUNT(*) FROM recovered_records WHERE artifact_id IS NOT NULL") or 0
            yield ValidationResult.of("case", None, label, "record_structure", VS.VALID,
                          f"all {total_recovered} recovered records' raw bytes match their recorded digest"
                          + (f"; {reconstructed} reconstructed artifacts carry the same bytes" if reconstructed else ""))
    total_carved = store.scalar("SELECT COUNT(*) FROM carved_candidates") or 0
    if total_carved:
        bad_status = store.scalar("SELECT COUNT(*) FROM carved_candidates WHERE status != 'CARVED CANDIDATE'") or 0
        bad_confidence = store.scalar("SELECT COUNT(*) FROM carved_candidates WHERE confidence = 'HIGH'") or 0
        label = "carved candidates"
        if bad_status or bad_confidence:
            yield ValidationResult.of("case", None, label, "record_structure", VS.INVALID,
                          f"{bad_status} carved row(s) do not carry the literal status 'CARVED CANDIDATE', "
                          f"{bad_confidence} carry HIGH confidence: a carved candidate is never confirmed evidence",
                          {"bad_status": bad_status, "bad_confidence": bad_confidence})
        else:
            yield ValidationResult.of("case", None, label, "record_structure", VS.VALID,
                          f"all {total_carved} carved candidates remain unconfirmed ('CARVED CANDIDATE', never HIGH confidence)")


CHECKS: list[Callable[[CaseStore, Options], Iterator[ValidationResult]]] = [
    check_hash_consistency,
    check_acquisition,
    check_sqlite,
    check_schema,
    check_record_structure,
    check_timestamps,
    check_duplicates,
    check_cross_artifact,
    check_provenance,
    check_recovery_integrity,
]
