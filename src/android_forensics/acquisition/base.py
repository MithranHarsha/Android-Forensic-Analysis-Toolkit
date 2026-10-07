"""Acquirer contract and the shared stream-ingest routine.

Every byte of evidence is read exactly once through a read-only handle: it is
hashed (MD5/SHA-1/SHA-256), classified from its first bytes, and — only for
files the analysis engine must open — tee-copied into the case's evidence store
(files are then chmod 0444). Originals are never opened for writing.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import IO, BinaryIO, Protocol

from android_forensics.acquisition.hashing import Digests, MultiHasher
from android_forensics.acquisition.safety import ExtractionBudget
from android_forensics.config import CHUNK_SIZE, HEAD_BYTES
from android_forensics.filesystem.classifier import classify, should_preserve
from android_forensics.models import EvidenceFile, FileHashes, FileKind, FileTimes, SourceType
from android_forensics.readonly import fingerprint, open_readonly
from android_forensics.util import safe_basename


@dataclass
class AcquiredFile:
    ordinal: int
    rel_path: str
    size: int
    digests: Digests
    kind: FileKind
    kind_detail: str
    times: FileTimes
    preserved_copy: str | None = None

    def to_evidence_file(self, source_id: int) -> EvidenceFile:
        d = self.digests
        return EvidenceFile(
            source_id=source_id, ordinal=self.ordinal, path=self.rel_path, size=self.size,
            hashes=FileHashes(md5=d.md5, sha1=d.sha1, sha256=d.sha256), kind=self.kind, kind_detail=self.kind_detail,
            times=self.times, preserved_copy=self.preserved_copy,
        )


@dataclass
class AcquisitionIssue:
    path: str
    issue_type: str
    detail: str
    incomplete: bool = False


class PreservePolicy(StrEnum):
    """Which files are copied into the working directory (everything is always *hashed*)."""

    ANALYSIS = "analysis"  # SQLite databases + sidecars and small text/XML/JSON — what the engine must open
    ALL = "all"  # every file (needs disk space for the whole acquisition)
    NONE = "none"  # hash only; nothing is copied


@dataclass
class AcquireContext:
    evidence_dir: Path
    budget: ExtractionBudget = field(default_factory=ExtractionBudget)
    preserve: PreservePolicy = PreservePolicy.ANALYSIS


class Acquirer(Protocol):
    source_type: SourceType

    def acquire(self, ctx: AcquireContext) -> Iterator[AcquiredFile | AcquisitionIssue]: ...


def ingest_stream(
    ctx: AcquireContext,
    ordinal: int,
    rel_path: str,
    src: IO[bytes],
    size_hint: int,
    times: FileTimes,
) -> AcquiredFile:
    head = src.read(HEAD_BYTES)
    cls = classify(rel_path, head, max(size_hint, len(head)))
    if ctx.preserve is PreservePolicy.ALL:
        preserve = True
    elif ctx.preserve is PreservePolicy.NONE:
        preserve = False
    else:
        preserve = should_preserve(cls, max(size_hint, len(head)))

    dest_path: Path | None = None
    dest_fh: BinaryIO | None = None
    if preserve:
        ctx.evidence_dir.mkdir(parents=True, exist_ok=True)
        dest_path = ctx.evidence_dir / f"{ordinal:07d}_{safe_basename(rel_path.rsplit('/', 1)[-1])}"
        dest_fh = open(dest_path, "wb")

    hasher = MultiHasher()
    try:
        chunk = head
        while chunk:
            hasher.update(chunk)
            if dest_fh is not None:
                dest_fh.write(chunk)
            ctx.budget.charge_bytes(len(chunk), hasher.size)
            chunk = src.read(CHUNK_SIZE)
    except BaseException:
        if dest_fh is not None:
            dest_fh.close()
        if dest_path is not None and dest_path.exists():
            dest_path.unlink()
        raise
    if dest_fh is not None:
        dest_fh.close()
        os.chmod(dest_path, 0o444)  # type: ignore[arg-type]

    return AcquiredFile(
        ordinal=ordinal,
        rel_path=rel_path,
        size=hasher.size,
        digests=hasher.digests(),
        kind=cls.kind,
        kind_detail=cls.detail,
        times=times,
        preserved_copy=dest_path.name if dest_path else None,
    )


def read_local_file(
    ctx: AcquireContext, ordinal: int, rel_path: str, path: str | os.PathLike[str], enumerated: os.stat_result, times: FileTimes
) -> tuple[AcquiredFile | None, list[AcquisitionIssue]]:
    """Read one local file exactly once, read-only, and report anything odd that happened while doing so.

    A file whose size, modification time or inode differs between enumeration, the start of the read and the end of the
    read was changing under us; it is still recorded (with the hash of the bytes actually read) but flagged
    ``changed_during_read`` so the examiner knows that hash is not a stable identity for the file.
    """
    ctx.budget.charge_entry()
    try:
        with open_readonly(path) as fh:
            before = os.fstat(fh.fileno())
            acquired = ingest_stream(ctx, ordinal, rel_path, fh, before.st_size, times)
            after = os.fstat(fh.fileno())
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, [AcquisitionIssue(rel_path, "symlink_skipped", "path became a symlink after enumeration; not followed")]
        return None, [AcquisitionIssue(rel_path, "read_error", f"{type(exc).__name__}: {exc}")]
    issues: list[AcquisitionIssue] = []
    if not (fingerprint(enumerated) == fingerprint(before) == fingerprint(after)) or acquired.size != before.st_size:
        issues.append(AcquisitionIssue(
            rel_path, "changed_during_read",
            f"file changed while being acquired (read {acquired.size} bytes; size at open {before.st_size}); "
            "the recorded hash covers the bytes read, not a stable version",
        ))
    return acquired, issues
