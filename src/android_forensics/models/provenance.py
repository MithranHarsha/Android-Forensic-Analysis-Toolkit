"""Traceability value objects: where a result came from, exactly which bytes, and why it is trusted.

Review 1 locates active rows *logically* (file, table, rowid). ``PhysicalLocation`` is the Review 2 counterpart —
page, cell and byte offset — and is ``None`` on every Review 1 artifact.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from android_forensics.models.enums import RawKind
from android_forensics.models.types import HexBytes, NonBlankStr, Sha256Hex, canonical_json


class PhysicalLocation(BaseModel):
    """Where in a file's bytes a record lives. Offsets are relative to ``Provenance.source_file``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    page_number: int | None = Field(default=None, ge=1)
    cell_index: int | None = Field(default=None, ge=0)
    byte_offset: int | None = Field(default=None, ge=0)
    page_type: str | None = None
    region: str | None = None  # e.g. "freeblock", "unallocated", "wal_frame"

    @model_validator(mode="after")
    def _must_locate_something(self) -> Self:
        if self.page_number is None and self.byte_offset is None:
            raise ValueError("a physical location needs a page number or a byte offset")
        return self


class Provenance(BaseModel):
    """The trace from a result back to evidence.

    ``source_file`` is the file the bytes were read from; ``source_database`` is the database the record belongs to.
    They are the same for an active row but differ for data recovered from a sidecar (a ``-wal`` or ``-journal``
    belongs to a database but is a different file with a different hash).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_file_id: int = Field(ge=1)
    source_file: NonBlankStr
    source_sha256: Sha256Hex
    source_database: NonBlankStr | None = None
    source_table: NonBlankStr | None = None
    source_rowid: int | None = None
    view_includes_wal: bool | None = None
    physical: PhysicalLocation | None = None

    @model_validator(mode="after")
    def _table_and_row_need_their_parents(self) -> Self:
        if self.source_table is not None and self.source_database is None:
            raise ValueError("source_table requires source_database")
        if self.source_rowid is not None and self.source_table is None:
            raise ValueError("source_rowid requires source_table")
        return self


class RawReference(BaseModel):
    """A pointer to the raw source of an artifact, with a digest that binds the two together.

    * Row kinds (``SQLITE_ROW``, ``INVENTORY``): ``row`` holds the source row verbatim (blobs summarised).
    * Byte kinds (Review 2): ``raw_bytes_hex`` holds the raw record bytes.

    ``sha256`` is the digest of the raw bytes, or — for row kinds — of the canonical JSON of ``row``. It is computed
    when omitted and *verified* when supplied, so an edited raw reference cannot pass as the original.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: RawKind = RawKind.SQLITE_ROW
    row: dict[str, Any] | None = None
    raw_bytes_hex: HexBytes | None = None
    sha256: Sha256Hex | None = None

    @model_validator(mode="after")
    def _consistent_and_digested(self) -> Self:
        if self.kind.is_bytes:
            if self.raw_bytes_hex is None:
                raise ValueError(f"{self.kind.value} reference requires raw_bytes_hex")
            if self.row is not None:
                raise ValueError(f"{self.kind.value} reference must not carry a row")
        else:
            if self.row is None:
                raise ValueError(f"{self.kind.value} reference requires the source row")
            if self.raw_bytes_hex is not None:
                raise ValueError(f"{self.kind.value} reference must not carry raw bytes")
        expected = self.compute_digest()
        if self.sha256 is None:
            object.__setattr__(self, "sha256", expected)  # frozen model: fill the derived digest once, at construction
        elif self.sha256 != expected:
            raise ValueError(f"raw reference digest mismatch: declared {self.sha256}, computed {expected}")
        return self

    @property
    def sha256_of(self) -> Literal["raw_bytes", "row_json"]:
        return "raw_bytes" if self.kind.is_bytes else "row_json"

    @property
    def byte_length(self) -> int | None:
        return None if self.raw_bytes_hex is None else len(self.raw_bytes_hex) // 2

    def compute_digest(self) -> str:
        if self.kind.is_bytes:
            return hashlib.sha256(bytes.fromhex(self.raw_bytes_hex or "")).hexdigest()
        return hashlib.sha256(canonical_json(self.row).encode("utf-8")).hexdigest()


class ParserInfo(BaseModel):
    """Which parser produced an artifact and how well the schema matched it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: NonBlankStr
    version: NonBlankStr
    schema_variant: str | None = None
    schema_match_score: float | None = Field(default=None, ge=0.0, le=1.0)


class ConfidenceFactor(BaseModel):
    """One explainable reason contributing to a confidence level (used by the Review 2 scorer)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: NonBlankStr
    satisfied: bool
    weight: float = Field(default=1.0, ge=0.0)
    explanation: NonBlankStr
