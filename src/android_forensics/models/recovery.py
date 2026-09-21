"""Review 2 evidence models: recovered records, carved candidates, correlation edges, and the confidence assessment.

* ``RecoveredRecord`` — a deleted or superseded record exactly as the recovery engine found it: where (file, page, byte
  offset), by what method, the raw bytes (digest-bound), the table it was fitted to and the values the bytes determine.
  It is the *staging* form of recovered evidence: the ``reconstruct`` stage turns it into a typed ``Artifact`` once it has
  been correlated and scored.
* ``CarvedCandidate`` — a pattern hit in raw bytes. It is never confirmed evidence: its status is the literal
  ``"CARVED CANDIDATE"`` and its confidence can never be HIGH.
* ``CorrelationEdge`` — one link of the evidence graph.
* ``ConfidenceAssessment`` — a level with the factors and the sentence that justify it.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from android_forensics.models.enums import (
    ArtifactStatus,
    CarveKind,
    Confidence,
    EntityKind,
    ExtractionMethod,
    Relation,
)
from android_forensics.models.provenance import ConfidenceFactor
from android_forensics.models.types import HexBytes, NonBlankStr, Sha256Hex

_FROZEN = ConfigDict(extra="forbid", frozen=True)
RECOVERY_STATUSES = frozenset({ArtifactStatus.RECOVERED, ArtifactStatus.PARTIAL, ArtifactStatus.CORRUPTED})
CARVED_CANDIDATE = "CARVED CANDIDATE"


def encode_value(value: Any) -> Any:
    """A column value in the JSON-safe form ``RecoveredRecord.values`` uses: blobs as ``{"$blob": hex}``, NaN/inf as ``{"$float": repr}``."""
    if isinstance(value, (bytes, bytearray)):
        return {"$blob": bytes(value).hex()}
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return {"$float": repr(value)}
    return value


def decode_value(value: Any) -> Any:
    """Inverse of ``encode_value``."""
    if isinstance(value, dict) and "$blob" in value:
        return bytes.fromhex(value["$blob"])
    if isinstance(value, dict) and "$float" in value:
        return float(value["$float"])
    return value


class ConfidenceAssessment(BaseModel):
    """A confidence level and everything that justifies it. Deterministic: the same inputs give the same assessment."""

    model_config = _FROZEN

    level: Confidence
    score: float = Field(ge=0.0, le=1.0)
    factors: list[ConfidenceFactor] = Field(min_length=1)
    explanation: NonBlankStr

    @model_validator(mode="after")
    def _explanation_names_the_level(self) -> Self:
        if not self.explanation.startswith(self.level.value):
            raise ValueError("the explanation must begin with the level it justifies")
        return self


class RecoveredRecord(BaseModel):
    """A record found in freed space, a stale page image, a WAL frame or a journal page (see ``sqlite/recovery.py``)."""

    model_config = _FROZEN

    id: int | None = None
    database_id: int | None = None
    database_file_id: int = Field(ge=1)  # the database's evidence file
    source: Literal["main", "wal", "journal"]
    source_file_id: int = Field(ge=1)  # the evidence file whose bytes these are (the database, or its -wal / -journal)
    source_path: NonBlankStr
    source_sha256: Sha256Hex
    table: NonBlankStr
    values: dict[str, Any]  # the values the bytes determine (blobs as {"$blob": hex}); undetermined columns are absent
    unknown_columns: list[str] = Field(default_factory=list)  # columns the bytes do not determine (never guessed)
    rowid: int | None = None
    status: ArtifactStatus
    method: ExtractionMethod
    page_number: int = Field(ge=1)
    page_offset: int = Field(ge=0)
    file_offset: int = Field(ge=0)  # absolute offset of ``raw`` in ``source_path``
    length: int = Field(gt=0)
    page_type: str | None = None
    region: str
    cell_index: int | None = None
    frame: int | None = None
    raw_hex: HexBytes
    raw_sha256: Sha256Hex | None = None
    fit: float = Field(ge=0.0, le=1.0)
    issues: list[str] = Field(default_factory=list)
    also_found_at: list[str] = Field(default_factory=list)
    artifact_id: int | None = None  # set once the record has been reconstructed into an artifact

    @model_validator(mode="after")
    def _forensic_invariants(self) -> Self:
        if self.status not in RECOVERY_STATUSES:
            raise ValueError(f"a recovered record is RECOVERED, PARTIAL or CORRUPTED, not {self.status.value}")
        if self.method.is_active or self.method is ExtractionMethod.CARVING:
            raise ValueError(f"{self.method.value} is not a page-level recovery method")
        raw = bytes.fromhex(self.raw_hex)
        if len(raw) != self.length:
            raise ValueError("length does not match the raw bytes")
        digest = hashlib.sha256(raw).hexdigest()
        if self.raw_sha256 is None:
            object.__setattr__(self, "raw_sha256", digest)
        elif self.raw_sha256 != digest:
            raise ValueError("raw_sha256 does not match the raw bytes")
        if self.source != "main" and self.method not in (ExtractionMethod.WAL_FRAME, ExtractionMethod.JOURNAL_PAGE):
            raise ValueError("a record taken from a sidecar must say so in its method")
        if set(self.unknown_columns) & set(self.values):
            raise ValueError("a column cannot be both known and unknown")
        if self.status is ArtifactStatus.RECOVERED and self.unknown_columns:
            raise ValueError("a RECOVERED record has no unknown columns; that is what PARTIAL is for")
        return self

    @property
    def raw(self) -> bytes:
        return bytes.fromhex(self.raw_hex)


class UnrecoveredRegion(BaseModel):
    """Freed space that proves a record existed but holds none (zero-filled, or not a record of any known table)."""

    model_config = _FROZEN

    id: int | None = None
    database_id: int | None = None
    source: Literal["main", "wal", "journal"]
    source_path: NonBlankStr
    page_number: int = Field(ge=1)
    page_offset: int = Field(ge=0)
    file_offset: int = Field(ge=0)
    length: int = Field(gt=0)
    region: str
    reason: NonBlankStr
    raw_sha256: Sha256Hex
    frame: int | None = None


class CarvedCandidate(BaseModel):
    """A pattern hit in raw bytes. Unconfirmed by definition: nothing here may be presented as evidence until correlated."""

    model_config = _FROZEN

    id: int | None = None
    evidence_file_id: int = Field(ge=1)
    source_file: NonBlankStr
    source_sha256: Sha256Hex
    offset: int = Field(ge=0)
    length: int = Field(gt=0)
    kind: CarveKind
    pattern: NonBlankStr  # the rule that matched
    matched: str  # the matched text (or a hex rendering for binary hits)
    encoding: Literal["ascii", "utf-16le", "binary"] = "ascii"
    context_before_hex: HexBytes = ""
    context_after_hex: HexBytes = ""
    status: Literal["CARVED CANDIDATE"] = CARVED_CANDIDATE
    extraction_method: Literal[ExtractionMethod.CARVING] = ExtractionMethod.CARVING
    confidence: Confidence | None = None
    confidence_factors: list[ConfidenceFactor] = Field(default_factory=list)
    explanation: str = ""
    corroborated_by: list[int] = Field(default_factory=list)  # ids of artifacts that carry the same value
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _never_confirmed(self) -> Self:
        if self.confidence is Confidence.HIGH:
            raise ValueError("a carved candidate can never be HIGH confidence: it is not confirmed evidence")
        if self.confidence is not None and not self.confidence_factors:
            raise ValueError("a scored candidate must carry the factors that justify its level")
        return self


class CorrelationEdge(BaseModel):
    """One link of the evidence graph: ``source --relation--> target``."""

    model_config = _FROZEN

    id: int | None = None
    source_kind: EntityKind
    source_ref: NonBlankStr  # "artifact:12", "phone:2025550101", "database:3" …
    target_kind: EntityKind
    target_ref: NonBlankStr
    relation: Relation
    strength: float = Field(default=1.0, ge=0.0, le=1.0)
    explanation: NonBlankStr
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _no_self_loops(self) -> Self:
        if (self.source_kind, self.source_ref) == (self.target_kind, self.target_ref):
            raise ValueError("an entity cannot correlate with itself")
        return self
