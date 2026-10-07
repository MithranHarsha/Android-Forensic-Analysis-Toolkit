"""evidence_manifest.json: the portable, database-independent record of every hashed evidence file.

Per source: original path, type, container hashes (archives), acquisition and ingest times. Per file: original path,
relative path, size, MD5 / SHA-1 / SHA-256, kind, timestamps with their basis, and the preserved-copy location.
Top level: case ID, analysis timestamp and tool version. ``verify_manifest`` re-checks the evidence against it.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from android_forensics import TOOL_NAME, __version__
from android_forensics.acquisition.hashing import hash_file
from android_forensics.models import EvidenceFile, EvidenceSource, Manifest, ManifestSource, SourceType
from android_forensics.util import now_iso
from android_forensics.workspace import Workspace


def make_manifest(
    case_id: str,
    case_name: str,
    sources: Sequence[tuple[EvidenceSource, Sequence[EvidenceFile]]],
    *,
    analysis_timestamp: str | None = None,
) -> Manifest:
    return Manifest(
        case_id=case_id,
        case_name=case_name,
        analysis_timestamp=analysis_timestamp or now_iso(),
        tool_name=TOOL_NAME,
        tool_version=__version__,
        sources=[ManifestSource.from_source(s, files) for s, files in sources],
    )


def write_manifest_file(manifest: Manifest, path: Path) -> str:
    """Write atomically (temp file + rename) and return the manifest's SHA-256.

    A ``<name>.sha256`` sidecar in ``sha256sum`` format is written beside it so the manifest can itself be verified.
    """
    data = manifest.model_dump_json(indent=2).encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n")
    return digest


def read_manifest(path: Path) -> Manifest:
    return Manifest.model_validate(json.loads(Path(path).read_text()))


@dataclass(frozen=True)
class Discrepancy:
    kind: str  # container_missing|modified|unreadable · original_missing|modified|unreadable|unlisted · preserved_missing|modified|unreadable
    path: str
    detail: str


@dataclass
class VerificationReport:
    checked: int = 0
    discrepancies: list[Discrepancy] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.discrepancies


_SIDECARS = ("-wal", "-shm", "-journal")


def verify_manifest(manifest: Manifest, workspace: Workspace | None = None) -> VerificationReport:
    """Re-hash the evidence (and, if ``workspace`` is given, the preserved copies) and compare with the manifest.

    Detects: a changed or missing container / original file, a file added to a directory source after ingest,
    and a changed or missing preserved copy. Read-only.
    """
    report = VerificationReport()

    def note(kind: str, path: str, detail: str) -> None:
        report.discrepancies.append(Discrepancy(kind, path, detail))

    def check(p: Path, expected: str | None, subject: str, shown: str) -> None:
        """Compare one file's SHA-256 with the manifest; a file that cannot be read is reported, not fatal."""
        try:
            actual = hash_file(p).sha256
        except OSError as exc:
            note(f"{subject}_unreadable", shown, f"cannot be re-read ({type(exc).__name__}: {exc}); a symlink counts as a change")
            return
        if actual != expected:
            note(f"{subject}_modified", shown, "SHA-256 differs from the manifest")

    for src in manifest.sources:
        if src.source_type in (SourceType.ZIP, SourceType.TAR, SourceType.DISK_IMAGE):
            p = Path(src.original_path)
            report.checked += 1
            if not p.is_file():
                note("container_missing", src.original_path, "the original archive is no longer available")
            else:
                check(p, src.container_sha256, "container", src.original_path)
        else:
            listed = set()
            for entry in src.files:
                listed.add(os.path.normpath(entry.original_path))
                p = Path(entry.original_path)
                report.checked += 1
                if not p.is_file() and not p.is_symlink():
                    note("original_missing", entry.original_path, "file no longer present")
                else:
                    check(p, entry.sha256, "original", entry.original_path)
            for extra in _unlisted(src, listed):
                note("original_unlisted", extra, "present now but not in the manifest (added after ingestion, or skipped at ingest)")

        if workspace is not None:
            for entry in src.files:
                if not entry.preserved_copy:
                    continue
                copy = workspace.root / entry.preserved_copy
                report.checked += 1
                if not copy.is_file() and not copy.is_symlink():
                    note("preserved_missing", entry.preserved_copy, "preserved copy is missing")
                else:
                    check(copy, entry.sha256, "preserved", entry.preserved_copy)
    return report


def _unlisted(src: ManifestSource, listed: set[str]) -> list[str]:
    root = Path(src.original_path)
    found: list[str] = []
    if src.source_type is SourceType.DIRECTORY and root.is_dir():
        for dirpath, _dirs, files in os.walk(root, followlinks=False):
            for name in files:
                full = os.path.join(dirpath, name)
                if os.path.islink(full) or not os.path.isfile(full) or not os.access(full, os.R_OK):
                    continue  # symlinks, special and unreadable files were never ingested
                if os.path.normpath(full) not in listed:
                    found.append(full)
    elif src.source_type is SourceType.SINGLE_FILE:
        for suffix in _SIDECARS:
            side = root.with_name(root.name + suffix)
            if side.is_file() and os.path.normpath(str(side)) not in listed:
                found.append(str(side))
    return sorted(found)
