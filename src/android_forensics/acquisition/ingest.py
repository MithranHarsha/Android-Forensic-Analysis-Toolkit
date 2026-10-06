"""Evidence ingestion into a case: the ``IngestionSession`` engine plus persistence in the case database.

The acquisition itself (read-only reading, hashing, classification, preserved copies) lives in ``session.py`` and has no
database dependency; this module streams a session's output into ``case.db``, writes the manifest and extends the
chain-of-custody log.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from android_forensics.acquisition.base import AcquisitionIssue, PreservePolicy
from android_forensics.acquisition.manifest import make_manifest, write_manifest_file
from android_forensics.acquisition.safety import ExtractionBudget
from android_forensics.acquisition.session import IngestionSession
from android_forensics.models import EvidenceFile, Manifest, SourceType
from android_forensics.progress import NullProgress, Progress
from android_forensics.storage.case_store import CaseStore, utcnow

_BATCH = 1000


@dataclass
class IngestSummary:
    source_id: int
    source_type: SourceType
    files: int
    total_bytes: int
    preserved_copies: int
    issues: int
    complete: bool
    container_sha256: str | None
    manifest_path: Path
    manifest_sha256: str
    seconds: float


def manifest_from_store(store: CaseStore) -> Manifest:
    """The manifest for everything ingested into the case so far (all sources)."""
    case = store.case()
    return make_manifest(case.id, case.name, [(s, list(store.evidence_files(s.id))) for s in store.sources()])


def write_case_manifest(store: CaseStore) -> tuple[Path, str]:
    return store.manifest_path, write_manifest_file(manifest_from_store(store), store.manifest_path)


def ingest_source(
    store: CaseStore,
    source_path: Path,
    acquired_at: str | None = None,
    progress: Progress | None = None,
    budget: ExtractionBudget | None = None,
    preserve: PreservePolicy = PreservePolicy.ANALYSIS,
    mount_point: str | None = None,
) -> IngestSummary:
    """Ingest evidence (directory, zip, tar, tar.gz or a single database) into the case."""
    t0 = time.monotonic()
    progress = progress or NullProgress()
    session = IngestionSession(
        source_path, store.workspace, case_id=store.case_id, acquired_at=acquired_at, budget=budget,
        preserve=preserve, progress=progress, mount_point=mount_point,
    )
    source = session.prepare()
    source_id = store.add_source(source)
    session.bind_source_id(source_id)
    container_sha = source.container_hashes.sha256 if source.container_hashes else None
    store.log(
        "ingest_started",
        str(session.resolved),
        {"source_id": source_id, "source_type": source.source_type.value, "container_sha256": container_sha},
    )

    file_batch: list[EvidenceFile] = []
    issue_rows: list[tuple] = []

    def flush() -> None:
        store.add_files(file_batch)
        with store.transaction():
            store.conn.executemany(
                "INSERT INTO scan_issues(source_id,path,issue_type,detail,stage,created_at) VALUES(?,?,?,?,?,?)",
                issue_rows,
            )
        file_batch.clear()
        issue_rows.clear()

    for item in session.run():
        if isinstance(item, AcquisitionIssue):
            issue_rows.append((source_id, item.path, item.issue_type, item.detail, "ingest", utcnow()))
        else:
            file_batch.append(item)
        if len(file_batch) + len(issue_rows) >= _BATCH:
            flush()
    flush()

    final = session.finalized_source()
    store.update_source_totals(source_id, final.file_count, final.total_bytes, final.complete)
    manifest_path, manifest_sha = write_case_manifest(store)
    totals = session.totals
    store.log(
        "ingest_completed",
        str(session.resolved),
        {
            "source_id": source_id,
            "files": totals.files,
            "bytes": totals.bytes,
            "preserved_copies": totals.preserved,
            "issues": totals.issues,
            "complete": totals.complete,
            "manifest_sha256": manifest_sha,
        },
    )
    return IngestSummary(
        source_id=source_id,
        source_type=source.source_type,
        files=totals.files,
        total_bytes=totals.bytes,
        preserved_copies=totals.preserved,
        issues=totals.issues,
        complete=totals.complete,
        container_sha256=container_sha,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha,
        seconds=time.monotonic() - t0,
    )
