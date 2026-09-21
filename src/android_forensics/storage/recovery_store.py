"""Persist and load the Review 2 evidence: recovered records, unrecovered regions, carved candidates, correlation edges."""

from __future__ import annotations

import json
from typing import Any, Iterable, Iterator

from android_forensics.models import (
    ArtifactStatus,
    CarvedCandidate,
    Confidence,
    ConfidenceFactor,
    CorrelationEdge,
    ExtractionMethod,
    RecoveredRecord,
    UnrecoveredRegion,
    decode_value,
    encode_value,
)
from android_forensics.storage.case_store import CaseStore


# ------------------------------------------------------------------ values <-> JSON (bytes survive as {"$blob": hex})


def encode_values(values: dict[str, Any]) -> str:
    return json.dumps({k: encode_value(v) for k, v in values.items()}, ensure_ascii=False)


def decode_values(text: str) -> dict[str, Any]:
    return {k: decode_value(v) for k, v in json.loads(text).items()}


# ------------------------------------------------------------------ recovered records


def insert_recovered(store: CaseStore, run_id: int, records: Iterable[RecoveredRecord]) -> list[int]:
    ids: list[int] = []
    with store.transaction():
        for r in records:
            ids.append(store.insert("recovered_records", {
                "run_id": run_id, "database_id": r.database_id, "database_file_id": r.database_file_id, "source": r.source,
                "source_file_id": r.source_file_id, "source_path": r.source_path, "source_sha256": r.source_sha256,
                "table_name": r.table, "rowid_value": r.rowid, "status": r.status.value, "method": r.method.value,
                "page_number": r.page_number, "page_offset": r.page_offset, "file_offset": r.file_offset, "length": r.length,
                "page_type": r.page_type, "region": r.region, "cell_index": r.cell_index, "frame": r.frame, "raw_hex": r.raw_hex,
                "raw_sha256": r.raw_sha256, "fit": r.fit, "values_json": encode_values(r.values),
                "unknown_columns_json": json.dumps(r.unknown_columns), "issues_json": json.dumps(r.issues),
                "also_found_at_json": json.dumps(r.also_found_at),
            }))
    return ids


def recovered_from_row(row: Any) -> RecoveredRecord:
    return RecoveredRecord(
        id=row["id"], database_id=row["database_id"], database_file_id=row["database_file_id"], source=row["source"],
        source_file_id=row["source_file_id"], source_path=row["source_path"], source_sha256=row["source_sha256"], table=row["table_name"],
        values=decode_values(row["values_json"]), unknown_columns=json.loads(row["unknown_columns_json"]), rowid=row["rowid_value"],
        status=ArtifactStatus(row["status"]), method=ExtractionMethod(row["method"]), page_number=row["page_number"],
        page_offset=row["page_offset"], file_offset=row["file_offset"], length=row["length"], page_type=row["page_type"],
        region=row["region"], cell_index=row["cell_index"], frame=row["frame"], raw_hex=row["raw_hex"], raw_sha256=row["raw_sha256"],
        fit=row["fit"], issues=json.loads(row["issues_json"]), also_found_at=json.loads(row["also_found_at_json"]),
        artifact_id=row["artifact_id"],
    )


def load_recovered(store: CaseStore, where: str = "1=1", params: tuple = ()) -> Iterator[RecoveredRecord]:
    for row in store.q(f"SELECT * FROM recovered_records WHERE {where} ORDER BY id", params):
        yield recovered_from_row(row)


def link_artifact(store: CaseStore, recovered_id: int, artifact_id: int) -> None:
    store.conn.execute("UPDATE recovered_records SET artifact_id=? WHERE id=?", (artifact_id, recovered_id))


# ------------------------------------------------------------------ unrecovered regions, inventories


def insert_unrecovered(store: CaseStore, run_id: int, regions: Iterable[UnrecoveredRegion]) -> None:
    with store.transaction():
        for u in regions:
            store.insert("unrecovered_regions", {
                "run_id": run_id, "database_id": u.database_id, "source": u.source, "source_path": u.source_path,
                "page_number": u.page_number, "page_offset": u.page_offset, "file_offset": u.file_offset, "length": u.length,
                "region": u.region, "reason": u.reason, "raw_sha256": u.raw_sha256, "frame": u.frame,
            })


def load_unrecovered(store: CaseStore) -> Iterator[UnrecoveredRegion]:
    for r in store.q("SELECT * FROM unrecovered_regions ORDER BY id"):
        yield UnrecoveredRegion(
            id=r["id"], database_id=r["database_id"], source=r["source"], source_path=r["source_path"], page_number=r["page_number"],
            page_offset=r["page_offset"], file_offset=r["file_offset"], length=r["length"], region=r["region"], reason=r["reason"],
            raw_sha256=r["raw_sha256"], frame=r["frame"],
        )


# ------------------------------------------------------------------ carved candidates


def insert_carved(store: CaseStore, run_id: int, candidates: Iterable[CarvedCandidate]) -> list[int]:
    ids = []
    with store.transaction():
        for c in candidates:
            ids.append(store.insert("carved_candidates", {
                "run_id": run_id, "evidence_file_id": c.evidence_file_id, "source_file": c.source_file, "source_sha256": c.source_sha256,
                "byte_offset": c.offset, "length": c.length, "kind": c.kind.value, "pattern": c.pattern, "matched": c.matched,
                "encoding": c.encoding, "container": c.container, "context_valid": int(c.context_valid),
                "context_before_hex": c.context_before_hex, "context_after_hex": c.context_after_hex,
                "status": c.status, "confidence": c.confidence.value if c.confidence else None,
                "confidence_factors_json": json.dumps([f.model_dump(mode="json") for f in c.confidence_factors]),
                "explanation": c.explanation, "corroborated_by_json": json.dumps(c.corroborated_by), "notes_json": json.dumps(c.notes),
            }))
    return ids


def carved_from_row(r: Any) -> CarvedCandidate:
    return CarvedCandidate(
        id=r["id"], evidence_file_id=r["evidence_file_id"], source_file=r["source_file"], source_sha256=r["source_sha256"],
        offset=r["byte_offset"], length=r["length"], kind=r["kind"], pattern=r["pattern"], matched=r["matched"], encoding=r["encoding"],
        container=r["container"], context_valid=bool(r["context_valid"]), context_before_hex=r["context_before_hex"], context_after_hex=r["context_after_hex"],
        confidence=Confidence(r["confidence"]) if r["confidence"] else None,
        confidence_factors=[ConfidenceFactor(**f) for f in json.loads(r["confidence_factors_json"])], explanation=r["explanation"],
        corroborated_by=json.loads(r["corroborated_by_json"]), notes=json.loads(r["notes_json"]),
    )


def load_carved(store: CaseStore, where: str = "1=1", params: tuple = ()) -> Iterator[CarvedCandidate]:
    for r in store.q(f"SELECT * FROM carved_candidates WHERE {where} ORDER BY id", params):
        yield carved_from_row(r)


def update_carved_scoring(store: CaseStore, cid: int, c: CarvedCandidate) -> None:
    store.conn.execute(
        "UPDATE carved_candidates SET confidence=?, confidence_factors_json=?, explanation=?, corroborated_by_json=?, notes_json=? WHERE id=?",
        (c.confidence.value if c.confidence else None, json.dumps([f.model_dump(mode="json") for f in c.confidence_factors]),
         c.explanation, json.dumps(c.corroborated_by), json.dumps(c.notes), cid),
    )


# ------------------------------------------------------------------ correlation edges


def insert_edges(store: CaseStore, run_id: int, edges: Iterable[CorrelationEdge]) -> int:
    n = 0
    with store.transaction():
        for e in edges:
            store.insert("correlations", {
                "run_id": run_id, "source_kind": e.source_kind.value, "source_ref": e.source_ref, "target_kind": e.target_kind.value,
                "target_ref": e.target_ref, "relation": e.relation.value, "strength": e.strength, "explanation": e.explanation,
                "evidence_json": json.dumps(e.evidence, default=str),
            })
            n += 1
    return n


def load_edges(store: CaseStore, where: str = "1=1", params: tuple = ()) -> Iterator[CorrelationEdge]:
    for r in store.q(f"SELECT * FROM correlations WHERE {where} ORDER BY id", params):
        yield CorrelationEdge(
            id=r["id"], source_kind=r["source_kind"], source_ref=r["source_ref"], target_kind=r["target_kind"], target_ref=r["target_ref"],
            relation=r["relation"], strength=r["strength"], explanation=r["explanation"], evidence=json.loads(r["evidence_json"]),
        )
