"""Results of Android filesystem discovery: what is in the evidence tree and how it is laid out.

Discovery only *observes*: it classifies files, attributes them to the Android filesystem, associates SQLite sidecars
with their databases and records anything odd. It never interprets database content and never recovers anything.
"""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from android_forensics.models.enums import FileKind, SidecarKind, SqliteStatus
from android_forensics.models.types import NonBlankStr, Sha256Hex, UtcIso


class ScanIssue(BaseModel):
    """Something the examiner should know about: a skipped, unreadable, damaged or oddly placed item."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: NonBlankStr
    issue_type: NonBlankStr
    detail: str = ""


class ScannedFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: NonBlankStr  # relative to the scanned root, '/'-separated
    size: int = Field(ge=0)
    kind: FileKind
    kind_detail: str | None = None
    sha256: Sha256Hex | None = None
    mtime: UtcIso | None = None
    readable: bool = True
    logical_path: str | None = None  # where the device would show it, e.g. /data/data/com.x/databases/a.db
    android_root: str | None = None  # data/data · data/user · sdcard · storage/emulated · …
    area: str | None = None  # app_internal · app_external · shared_storage · system · …
    user_id: int | None = None
    package: str | None = None

    @property
    def category(self) -> str:
        return self.kind.category


class Sidecar(BaseModel):
    """A WAL, shared-memory or rollback-journal file, associated with a database by name."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: SidecarKind
    path: NonBlankStr
    size: int = Field(ge=0)
    sha256: Sha256Hex | None = None
    header_valid: bool | None = None  # None: not determinable (e.g. empty, or a shm file which has no magic)
    note: str | None = None
    evidence_file_id: int | None = None


class DiscoveredDatabase(BaseModel):
    """A database-like file: its identity, what the scanner could establish about it from bytes alone, and its sidecars."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: NonBlankStr
    size: int = Field(ge=0)
    sha256: Sha256Hex | None = None
    status: SqliteStatus
    detail: str = ""
    logical_path: str | None = None
    package: str | None = None
    area: str | None = None
    user_id: int | None = None
    page_size: int | None = None
    page_count: int | None = None
    text_encoding: str | None = None
    journal_mode: str | None = None  # "wal" or "rollback", from the header
    freelist_pages: int | None = None
    sidecars: list[Sidecar] = Field(default_factory=list)
    evidence_file_id: int | None = None

    @model_validator(mode="after")
    def _one_sidecar_per_kind(self) -> Self:
        kinds = [s.kind for s in self.sidecars]
        if len(set(kinds)) != len(kinds):
            raise ValueError("a database has at most one sidecar of each kind")
        return self

    def sidecar(self, kind: SidecarKind) -> Sidecar | None:
        return next((s for s in self.sidecars if s.kind is kind), None)

    @property
    def wal(self) -> Sidecar | None:
        return self.sidecar(SidecarKind.WAL)

    @property
    def shm(self) -> Sidecar | None:
        return self.sidecar(SidecarKind.SHM)

    @property
    def journal(self) -> Sidecar | None:
        return self.sidecar(SidecarKind.JOURNAL)

    @property
    def is_sqlite(self) -> bool:
        return self.status in (SqliteStatus.VALID, SqliteStatus.TRUNCATED, SqliteStatus.UNVERIFIED, SqliteStatus.CORRUPT_HEADER)


class AndroidAppDirectory(BaseModel):
    """An application's data directory, e.g. ``/data/data/com.example.app`` — even if it holds no files."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    package: NonBlankStr
    path: NonBlankStr  # relative to the scanned root
    logical_path: str | None = None
    root: str | None = None  # data/data · data/user · data/user_de · storage/emulated · sdcard · data/app …
    area: str | None = None  # app_internal · app_internal_de · app_external · app_binary · app_directory_dump
    user_id: int | None = None
    known_app: str | None = None
    subdirectories: list[str] = Field(default_factory=list)  # standard application subdirectories present
    file_count: int = Field(default=0, ge=0)
    total_bytes: int = Field(default=0, ge=0)
    database_count: int = Field(default=0, ge=0)
    kind_counts: dict[str, int] = Field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return self.file_count == 0


class DumpRoot(BaseModel):
    """One dump inside the evidence tree (the folder path preceding its Android root; '' if it starts at the root)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prefix: str
    files: int = Field(ge=0)
    markers: list[str] = Field(default_factory=list)


class LayoutInfo(BaseModel):
    """How the evidence is laid out. Absent standard roots are reported for information, never as errors."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    layout: NonBlankStr  # android_root · android_root_with_prefix · multiple_roots · app_directories · loose_files · single_file
    detail: str = ""
    matched: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)
    roots: list[DumpRoot] = Field(default_factory=list)
    roots_present: list[str] = Field(default_factory=list)
    roots_absent: list[str] = Field(default_factory=list)


class FilesystemScan(BaseModel):
    """Everything discovery learned about one evidence tree."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    root: str | None = None
    scanned_at: UtcIso
    layout: LayoutInfo
    files: list[ScannedFile] = Field(default_factory=list)
    directories: int = Field(default=0, ge=0)
    total_files: int = Field(default=0, ge=0)
    total_bytes: int = Field(default=0, ge=0)
    kind_counts: dict[str, int] = Field(default_factory=dict)
    category_counts: dict[str, int] = Field(default_factory=dict)
    databases: list[DiscoveredDatabase] = Field(default_factory=list)
    orphan_sidecars: list[Sidecar] = Field(default_factory=list)
    app_directories: list[AndroidAppDirectory] = Field(default_factory=list)
    issues: list[ScanIssue] = Field(default_factory=list)

    def files_of(self, kind: FileKind) -> list[ScannedFile]:
        return [f for f in self.files if f.kind is kind]

    @property
    def media_files(self) -> list[ScannedFile]:
        return [f for f in self.files if f.kind.is_media]

    def database(self, path: str) -> DiscoveredDatabase | None:
        return next((d for d in self.databases if d.path == path), None)

    def issues_of(self, issue_type: str) -> list[ScanIssue]:
        return [i for i in self.issues if i.issue_type == issue_type]
