"""Evidence models: sources, files, hashes, times and the manifest."""

from __future__ import annotations

import os
from typing import Any, Mapping, Self, Sequence

from pydantic import BaseModel, ConfigDict, Field, model_validator

from android_forensics.models.enums import FileKind, SourceType
from android_forensics.models.types import CaseId, IsoInput, Md5Hex, NonBlankStr, Sha1Hex, Sha256Hex, UtcIso


class FileHashes(BaseModel):
    """MD5/SHA-1 are recorded for compatibility with legacy reference sets only; SHA-256 is the integrity anchor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    md5: Md5Hex
    sha1: Sha1Hex
    sha256: Sha256Hex


EMPTY_HASHES = FileHashes(
    md5="d41d8cd98f00b204e9800998ecf8427e",
    sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
    sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
)


class FileTimes(BaseModel):
    """File-system times plus the *basis* that says how trustworthy they are (stat, tar header, zip DOS time, …)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mtime: UtcIso | None = None
    atime: UtcIso | None = None
    ctime: UtcIso | None = None
    basis: str | None = None

    @model_validator(mode="after")
    def _times_need_a_basis(self) -> Self:
        if (self.mtime or self.atime or self.ctime) and not self.basis:
            raise ValueError("file times must state their basis (how they were obtained)")
        return self


class EvidenceSource(BaseModel):
    """One ingested input: a directory, an archive, or a single file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int | None = None
    case_id: CaseId
    original_path: NonBlankStr
    original_name: NonBlankStr
    source_type: SourceType
    container_size: int | None = Field(default=None, ge=0)
    container_hashes: FileHashes | None = None
    acquisition_time: IsoInput | None = None
    ingested_at: UtcIso
    file_count: int = Field(default=0, ge=0)
    total_bytes: int = Field(default=0, ge=0)
    complete: bool = True

    @model_validator(mode="after")
    def _container_hash_iff_archive(self) -> Self:
        is_archive = self.source_type in (SourceType.ZIP, SourceType.TAR)
        if is_archive and (self.container_hashes is None or self.container_size is None):
            raise ValueError(f"a {self.source_type.value} source must record its container size and hashes")
        if not is_archive and (self.container_hashes is not None or self.container_size is not None):
            raise ValueError(f"a {self.source_type.value} source has no container to hash")
        return self

    def original_path_of(self, relative_path: str) -> str:
        """Where a file of this source lives in the original evidence.

        Directory: ``<dir>/<relative>``. Single file: beside the main file (its sidecars). Archive: the jar-style
        ``<archive>!/<member>``, which names the container and the member without implying an extracted copy.
        """
        if self.source_type is SourceType.DIRECTORY:
            return os.path.join(self.original_path, relative_path)
        if self.source_type is SourceType.SINGLE_FILE:
            return os.path.join(os.path.dirname(self.original_path), relative_path)
        return f"{self.original_path}!/{relative_path}"

    def to_record(self) -> dict[str, Any]:
        h = self.container_hashes
        return {
            "case_id": self.case_id,
            "original_path": self.original_path,
            "original_name": self.original_name,
            "source_type": self.source_type.value,
            "container_size": self.container_size,
            "container_md5": h.md5 if h else None,
            "container_sha1": h.sha1 if h else None,
            "container_sha256": h.sha256 if h else None,
            "acquisition_time": self.acquisition_time,
            "ingested_at": self.ingested_at,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "complete": int(self.complete),
        }

    @classmethod
    def from_record(cls, r: Mapping[str, Any]) -> Self:
        hashes = None
        if r["container_sha256"]:
            hashes = FileHashes(md5=r["container_md5"], sha1=r["container_sha1"], sha256=r["container_sha256"])
        return cls(
            id=r["id"], case_id=r["case_id"], original_path=r["original_path"], original_name=r["original_name"],
            source_type=r["source_type"], container_size=r["container_size"], container_hashes=hashes,
            acquisition_time=r["acquisition_time"], ingested_at=r["ingested_at"], file_count=r["file_count"],
            total_bytes=r["total_bytes"], complete=bool(r["complete"]),
        )


class EvidenceFile(BaseModel):
    """A hashed file inside an evidence source. ``path`` is relative to the source root, exactly as it appears there."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int | None = None
    source_id: int = Field(ge=1)
    ordinal: int = Field(ge=0)
    path: NonBlankStr
    size: int = Field(ge=0)
    hashes: FileHashes
    kind: FileKind
    kind_detail: str | None = None
    times: FileTimes = Field(default_factory=FileTimes)
    preserved_copy: str | None = None  # basename in the case evidence store; only files the engine must open
    logical_path: str | None = None  # Android path once the layout is detected
    android_root: str | None = None
    user_id: int | None = None
    package: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        parts = self.path.split("/")
        if self.path.startswith("/") or any(p in ("", ".", "..") for p in parts):
            raise ValueError(f"evidence path must be relative and normalised, got {self.path!r}")
        if self.size == 0 and self.hashes != EMPTY_HASHES:
            raise ValueError("a zero-length file must carry the hashes of empty input")
        if self.preserved_copy is not None and ("/" in self.preserved_copy or "\\" in self.preserved_copy):
            raise ValueError("preserved_copy is a file name inside the evidence store, not a path")
        return self

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def is_preserved(self) -> bool:
        return self.preserved_copy is not None

    def to_record(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id, "ordinal": self.ordinal, "path": self.path, "name": self.name,
            "size": self.size, "md5": self.hashes.md5, "sha1": self.hashes.sha1, "sha256": self.hashes.sha256,
            "kind": self.kind.value, "kind_detail": self.kind_detail, "mtime": self.times.mtime,
            "atime": self.times.atime, "ctime": self.times.ctime, "time_basis": self.times.basis,
            "preserved_copy": self.preserved_copy, "logical_path": self.logical_path,
            "android_root": self.android_root, "user_id": self.user_id, "package": self.package,
        }

    @classmethod
    def from_record(cls, r: Mapping[str, Any]) -> Self:
        return cls(
            id=r["id"], source_id=r["source_id"], ordinal=r["ordinal"], path=r["path"], size=r["size"],
            hashes=FileHashes(md5=r["md5"], sha1=r["sha1"], sha256=r["sha256"]), kind=r["kind"],
            kind_detail=r["kind_detail"],
            times=FileTimes(mtime=r["mtime"], atime=r["atime"], ctime=r["ctime"], basis=r["time_basis"]),
            preserved_copy=r["preserved_copy"], logical_path=r["logical_path"], android_root=r["android_root"],
            user_id=r["user_id"], package=r["package"],
        )


# ---------------------------------------------------------------- manifest (the portable integrity record)


class ManifestEntry(BaseModel):
    """One evidence file. Hash fields are flat on purpose: external tools verify with ``jq '.sources[].files[].sha256'``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    original_path: NonBlankStr
    relative_path: NonBlankStr
    size: int = Field(ge=0)
    md5: Md5Hex
    sha1: Sha1Hex
    sha256: Sha256Hex
    kind: FileKind
    times: FileTimes = Field(default_factory=FileTimes)
    preserved_copy: str | None = None

    @classmethod
    def from_evidence_file(cls, f: EvidenceFile, original_path: str) -> Self:
        return cls(
            original_path=original_path, relative_path=f.path, size=f.size, md5=f.hashes.md5, sha1=f.hashes.sha1,
            sha256=f.hashes.sha256, kind=f.kind, times=f.times,
            preserved_copy=f"evidence/s{f.source_id}/{f.preserved_copy}" if f.preserved_copy else None,
        )


class ManifestSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: int = Field(ge=1)
    original_path: NonBlankStr
    original_name: NonBlankStr
    source_type: SourceType
    container_size: int | None = None
    container_md5: Md5Hex | None = None
    container_sha1: Sha1Hex | None = None
    container_sha256: Sha256Hex | None = None
    acquisition_time: UtcIso | None = None
    ingested_at: UtcIso
    complete: bool = True
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    files: list[ManifestEntry]

    @classmethod
    def from_source(cls, s: EvidenceSource, files: Sequence[EvidenceFile]) -> Self:
        if s.id is None:
            raise ValueError("a manifest source needs its assigned source id")
        h = s.container_hashes
        return cls(
            source_id=s.id, original_path=s.original_path, original_name=s.original_name, source_type=s.source_type,
            container_size=s.container_size, container_md5=h.md5 if h else None, container_sha1=h.sha1 if h else None,
            container_sha256=h.sha256 if h else None, acquisition_time=s.acquisition_time, ingested_at=s.ingested_at,
            complete=s.complete, file_count=s.file_count, total_bytes=s.total_bytes,
            files=[ManifestEntry.from_evidence_file(f, s.original_path_of(f.path)) for f in files],
        )


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_version: int = 2
    case_id: CaseId
    case_name: NonBlankStr
    analysis_timestamp: UtcIso
    tool_name: NonBlankStr
    tool_version: NonBlankStr
    sources: list[ManifestSource]
    note: str = (
        "Hashes are computed over the bytes of the original evidence read through a "
        "read-only interface. The original evidence is never modified."
    )
