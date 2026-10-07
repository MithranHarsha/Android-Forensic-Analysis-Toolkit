"""Evidence ingestion as a reusable, database-independent library.

    result = ingest_evidence("./acquisition.tar.gz", workdir="./work", case_id="…")

An ``IngestionSession`` reads the evidence exactly once, read-only; hashes every file (SHA-256 anchor, MD5 and SHA-1 for
reference compatibility); records size and the timestamps the source provides; copies only what the analysis engine must
open into the write-protected working directory; and yields ``EvidenceFile`` models and ``AcquisitionIssue``s as it goes,
so evidence of any size streams through bounded memory. ``ingest_evidence`` drains a session into memory and writes
``evidence_manifest.json`` for convenience; the case database path (``ingest.ingest_source``) drains the same session
into SQLite instead.

Supported inputs: a directory, a ``.zip``, a ``.tar`` (optionally gzip/bzip2/xz compressed) or a single SQLite file.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from android_forensics.acquisition.base import AcquireContext, AcquiredFile, AcquisitionIssue, PreservePolicy
from android_forensics.acquisition.factory import make_acquirer
from android_forensics.acquisition.hashing import hash_file
from android_forensics.acquisition.manifest import make_manifest, write_manifest_file
from android_forensics.acquisition.safety import ExtractionBudget
from android_forensics.errors import IngestionError
from android_forensics.models import EvidenceFile, EvidenceSource, FileHashes, Manifest, SourceType
from android_forensics.progress import NullProgress, Progress
from android_forensics.util import now_iso, safe_text
from android_forensics.workspace import Workspace


@dataclass
class IngestionTotals:
    files: int = 0
    bytes: int = 0
    preserved: int = 0
    issues: int = 0
    complete: bool = True


class IngestionSession:
    """One evidence source → hashed, classified, optionally preserved files. Nothing here touches a database."""

    def __init__(
        self,
        source_path: str | Path,
        workspace: Workspace,
        *,
        case_id: str,
        acquired_at: str | None = None,
        budget: ExtractionBudget | None = None,
        preserve: PreservePolicy = PreservePolicy.ANALYSIS,
        progress: Progress | None = None,
        mount_point: str | None = None,
    ):
        path = Path(source_path).expanduser()
        if not path.exists():
            raise IngestionError(f"Evidence path does not exist: {path}")
        self.resolved = path.resolve()
        workspace.assert_disjoint_from(self.resolved)
        self.workspace = workspace
        self.case_id = case_id
        self.acquired_at = acquired_at
        self.budget = budget or ExtractionBudget()
        self.preserve = preserve
        self.progress = progress or NullProgress()
        self.totals = IngestionTotals()
        self._acquirer = make_acquirer(self.resolved, mount_point)
        self._source: EvidenceSource | None = None
        self._source_id: int | None = None
        self._finished = False

    # ------------------------------------------------------------------ preparation

    def prepare(self) -> EvidenceSource:
        """Detect the source type and hash the container (archives only). No evidence file is read yet."""
        if self._source is None:
            stype = self._acquirer.source_type
            container = None
            if self.resolved.is_file() and stype in (SourceType.ZIP, SourceType.TAR, SourceType.DISK_IMAGE):
                self.progress.start(f"Hashing container {self.resolved.name}", None)
                try:
                    container = hash_file(self.resolved)
                finally:
                    self.progress.stop()
            try:
                self._source = EvidenceSource(
                    case_id=self.case_id,
                    original_path=safe_text(str(self.resolved)),
                    original_name=safe_text(self.resolved.name),
                    source_type=stype,
                    container_size=container.size if container else None,
                    container_hashes=FileHashes(md5=container.md5, sha1=container.sha1, sha256=container.sha256) if container else None,
                    acquisition_time=self.acquired_at,
                    ingested_at=now_iso(),
                )
            except ValidationError as exc:
                raise IngestionError(f"Invalid evidence metadata: {exc.errors()[0]['msg']}") from exc
        return self._source

    def bind_source_id(self, source_id: int) -> None:
        """Assign the source id (the case database does this); standalone use picks the next free id automatically."""
        if source_id < 1:
            raise IngestionError("source ids start at 1")
        self._source_id = source_id

    @property
    def source_id(self) -> int | None:
        return self._source_id

    # ------------------------------------------------------------------ acquisition

    def run(self) -> Iterator[EvidenceFile | AcquisitionIssue]:
        """Stream the evidence. The generator must be exhausted for ``totals`` and ``finalized_source`` to be complete."""
        self.prepare()
        if self._source_id is None:
            self._source_id = self.workspace.next_source_id()
        target = self.workspace.source_dir(self._source_id)
        if target.exists() and any(target.iterdir()):
            raise IngestionError(f"{target} already holds preserved evidence for source s{self._source_id}; refusing to mix")
        self.workspace.create()
        ctx = AcquireContext(evidence_dir=target, budget=self.budget, preserve=self.preserve)
        self.progress.start(f"Acquiring {self.resolved.name}", None)
        try:
            for item in self._acquirer.acquire(ctx):
                if isinstance(item, AcquisitionIssue):
                    self.totals.issues += 1
                    if item.incomplete:
                        self.totals.complete = False
                    yield item
                else:
                    assert isinstance(item, AcquiredFile)
                    try:
                        entry = item.to_evidence_file(self._source_id)
                    except ValidationError as exc:
                        self.totals.issues += 1
                        yield AcquisitionIssue(item.rel_path, "invalid_evidence_entry", exc.errors()[0]["msg"])
                    else:
                        self.totals.files += 1
                        self.totals.bytes += item.size
                        self.totals.preserved += item.preserved_copy is not None
                        yield entry
                self.progress.advance()
            self._finished = True
        finally:
            self.progress.stop()

    def finalized_source(self) -> EvidenceSource:
        """The source with its assigned id and final totals. Available once ``run`` has been exhausted."""
        if not self._finished or self._source is None or self._source_id is None:
            raise RuntimeError("finalized_source() needs the run() generator to be exhausted first")
        return EvidenceSource.model_validate({
            **self._source.model_dump(), "id": self._source_id, "file_count": self.totals.files,
            "total_bytes": self.totals.bytes, "complete": self.totals.complete,
        })


@dataclass
class IngestionResult:
    source: EvidenceSource
    files: list[EvidenceFile]
    issues: list[AcquisitionIssue]
    manifest: Manifest
    manifest_path: Path | None
    manifest_sha256: str | None
    workspace: Workspace
    totals: IngestionTotals
    seconds: float

    @property
    def complete(self) -> bool:
        return self.totals.complete

    @property
    def preserved_files(self) -> list[EvidenceFile]:
        return [f for f in self.files if f.is_preserved]


def ingest_evidence(
    source_path: str | Path,
    workdir: str | Path,
    *,
    case_id: str | None = None,
    case_name: str = "ingestion",
    acquired_at: str | None = None,
    budget: ExtractionBudget | None = None,
    preserve: PreservePolicy = PreservePolicy.ANALYSIS,
    progress: Progress | None = None,
    write_manifest: bool = True,
) -> IngestionResult:
    """Ingest one evidence source into ``workdir`` and (by default) write ``<workdir>/evidence_manifest.json``.

    Holds every ``EvidenceFile`` in memory — ideal for libraries, scripts and small/medium acquisitions. For very
    large evidence use ``IngestionSession`` directly and stream the results.
    """
    t0 = time.monotonic()
    workspace = Workspace(Path(workdir))
    session = IngestionSession(source_path, workspace, case_id=case_id or uuid.uuid4().hex, acquired_at=acquired_at,
                               budget=budget, preserve=preserve, progress=progress)
    session.prepare()
    files: list[EvidenceFile] = []
    issues: list[AcquisitionIssue] = []
    for item in session.run():
        if isinstance(item, AcquisitionIssue):
            issues.append(item)
        else:
            files.append(item)
    source = session.finalized_source()
    manifest = make_manifest(session.case_id, case_name, [(source, files)])
    manifest_path = manifest_sha = None
    if write_manifest:
        manifest_path = workspace.manifest_path
        manifest_sha = write_manifest_file(manifest, manifest_path)
    return IngestionResult(source=source, files=files, issues=issues, manifest=manifest, manifest_path=manifest_path,
                           manifest_sha256=manifest_sha, workspace=workspace, totals=session.totals,
                           seconds=time.monotonic() - t0)


__all__ = ["IngestionResult", "IngestionSession", "IngestionTotals", "ingest_evidence"]
