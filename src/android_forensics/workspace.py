"""The working analysis directory.

A ``Workspace`` is where everything the tool *writes* lives, so that nothing is ever written to the evidence:

    <root>/evidence/s<N>/   write-protected (0444) preserved copies of the files the engine must open
    <root>/scratch/         disposable copies used by SQLite sessions
    <root>/reports/         generated reports
    <root>/evidence_manifest.json

It is independent of any database, so ingestion can be used as a plain library.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from android_forensics.errors import IngestionError

_SOURCE_DIR = re.compile(r"^s(\d+)$")


@dataclass(frozen=True)
class Workspace:
    root: Path = field()

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root).expanduser().resolve())

    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence"

    @property
    def scratch_dir(self) -> Path:
        return self.root / "scratch"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def manifest_path(self) -> Path:
        return self.root / "evidence_manifest.json"

    def create(self) -> "Workspace":
        if self.root.exists() and not self.root.is_dir():
            raise IngestionError(f"Working directory {self.root} exists and is not a directory")
        for d in (self.root, self.evidence_dir, self.scratch_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)
        return self

    def source_dir(self, source_id: int) -> Path:
        return self.evidence_dir / f"s{source_id}"

    def next_source_id(self) -> int:
        """One more than the highest source directory already present (1 for a fresh workspace)."""
        highest = 0
        if self.evidence_dir.is_dir():
            for child in self.evidence_dir.iterdir():
                m = _SOURCE_DIR.match(child.name)
                if m and child.is_dir():
                    highest = max(highest, int(m.group(1)))
        return highest + 1

    def assert_disjoint_from(self, source: Path) -> None:
        """The workspace and the evidence must not overlap in either direction.

        Evidence inside the workspace could be mistaken for our own output; a workspace inside an evidence
        directory would be walked and ingested into itself.
        """
        src = Path(source).resolve()
        if src == self.root:
            raise IngestionError("The working directory cannot be the evidence itself")
        if self.root in src.parents:
            raise IngestionError(f"Evidence must not live inside the working directory ({self.root})")
        if src.is_dir() and src in self.root.parents:
            raise IngestionError(f"The working directory must not be inside the evidence directory ({src})")
