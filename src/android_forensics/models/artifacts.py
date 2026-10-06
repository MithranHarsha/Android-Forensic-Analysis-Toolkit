"""The artifact model: one base envelope, one typed subclass per artifact type.

An ``Artifact`` says *what* was found (the subclass payload), *how it was obtained* (``extraction_method``), *how far it
can be trusted* (``status`` + ``confidence`` + ``confidence_factors``), and *where it came from* (``provenance`` and
``raw``). Review 1 produces only ``ArtifactStatus.ACTIVE`` artifacts, but the model already represents everything the
Review 2 recovery engine will emit — and the invariants below stop recovered data being represented carelessly:

* an ACTIVE artifact comes from an active extraction method and points at a source row (or the file inventory);
* anything not ACTIVE must carry a physical location and the raw bytes it was reconstructed from;
* RECOVERED / PARTIAL / CARVED / CORRUPTED must state a confidence level *and* the factors that justify it;
* a CARVED candidate can never be HIGH confidence on its own;
* an INVALID candidate must say why;
* a field marked UNKNOWN must actually be unset, and must exist.

Artifacts are immutable. To change one (for example to promote a candidate), ``evolve`` builds a new, re-validated instance.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from functools import cache, lru_cache
from typing import Annotated, Any, Literal, Self, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from android_forensics.models.enums import (
    AddressKind,
    ArtifactStatus,
    ArtifactType,
    CallPresentation,
    CallType,
    Confidence,
    DownloadState,
    ExtractionMethod,
    MessageDirection,
    PageTransition,
    TransitionQualifier,
)
from android_forensics.models.provenance import ConfidenceFactor, ParserInfo, Provenance, RawReference
from android_forensics.models.timestamp import TimestampInfo
from android_forensics.models.types import UtcIso
from android_forensics.models.unknown import UNKNOWN


class Artifact(BaseModel):
    """Common envelope. Instantiate a concrete subclass (``SMSMessage``, ``CallRecord``, …), never this class."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int | None = None
    artifact_type: ArtifactType
    status: ArtifactStatus = ArtifactStatus.ACTIVE
    confidence: Confidence | None = None
    confidence_factors: list[ConfidenceFactor] = Field(default_factory=list)
    extraction_method: ExtractionMethod = ExtractionMethod.ACTIVE_QUERY
    validation_notes: list[str] = Field(default_factory=list)
    application: str | None = None
    provenance: Provenance
    raw: RawReference
    parser: ParserInfo
    timestamp: TimestampInfo | None = None
    summary: str = ""
    flags: list[str] = Field(default_factory=list)
    unknown_fields: list[str] = Field(default_factory=list)
    phone_key: str | None = None
    marked_deleted: bool = False  # flagged deleted by the application yet still present (not a recovery)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: UtcIso | None = None

    # ------------------------------------------------------------------ invariants

    @model_validator(mode="after")
    def _forensic_invariants(self) -> Self:
        if type(self) is Artifact:
            raise ValueError("Artifact is abstract: instantiate a concrete subclass such as SMSMessage")
        active_method = self.extraction_method.is_active
        if self.status.is_active and not active_method:
            raise ValueError(f"ACTIVE artifact cannot use recovery method {self.extraction_method.value}")
        if self.status.is_recovery_state and active_method:
            raise ValueError(f"{self.status.value} artifact cannot use active method {self.extraction_method.value}")
        if active_method and self.raw.kind.is_bytes:
            raise ValueError("an actively extracted artifact must reference a row, not raw bytes")
        if not active_method and not self.raw.kind.is_bytes:
            raise ValueError(f"{self.status.value} artifact must preserve the raw bytes it was reconstructed from")
        if self.status.is_recovery_state and self.provenance.physical is None:
            raise ValueError(f"{self.status.value} artifact requires a physical location (page / byte offset)")
        if self.status.requires_confidence:
            if self.confidence is None:
                raise ValueError(f"{self.status.value} artifact requires a confidence level")
            if not self.confidence_factors:
                raise ValueError(f"{self.status.value} artifact requires confidence_factors explaining the level")
        if self.status.is_candidate and self.confidence is Confidence.HIGH:
            raise ValueError("a CARVED candidate cannot be HIGH confidence: it is not confirmed evidence")
        if self.status is ArtifactStatus.INVALID and not self.validation_notes:
            raise ValueError("an INVALID artifact must carry validation_notes saying why")
        self._check_unknown_fields()
        return self

    def _check_unknown_fields(self) -> None:
        unknown = self.unknown_fields
        if not unknown:
            return
        if len(set(unknown)) != len(unknown):
            raise ValueError("unknown_fields contains duplicates")
        defaults = _payload_defaults(type(self))
        for name in unknown:
            if name not in defaults:
                raise ValueError(f"unknown_fields names '{name}', which is not a field of {type(self).__name__}")
            if getattr(self, name) != defaults[name]:
                raise ValueError(f"field '{name}' is marked UNKNOWN but holds a value")

    # ------------------------------------------------------------------ construction

    @classmethod
    def build(cls, values: Mapping[str, Any], **envelope: Any) -> Self:
        """Build from a parser's value map, in which ``UNKNOWN`` marks a field that cannot be determined.

        ``UNKNOWN`` is recorded in ``unknown_fields`` (distinct from a stored NULL) and the field is left unset.
        """
        unknown = sorted(k for k, v in values.items() if v is UNKNOWN)
        known = {k: v for k, v in values.items() if v is not UNKNOWN}
        return cls(**known, unknown_fields=unknown, **envelope)

    def evolve(self, **changes: Any) -> Self:
        """Return a new, fully re-validated artifact with ``changes`` applied (artifacts are immutable)."""
        data = {name: getattr(self, name) for name in type(self).model_fields}
        data.update(changes)
        return type(self).model_validate(data)

    # ------------------------------------------------------------------ payload / persistence

    @classmethod
    def payload_fields(cls) -> tuple[str, ...]:
        """Names of the type-specific fields (everything except the common envelope)."""
        return tuple(_payload_defaults(cls))

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", include=set(_payload_names(type(self))))

    def to_record(self) -> dict[str, Any]:
        """Flat column values for the ``artifacts`` table (the caller adds run_id / database_id)."""
        p, ts, raw = self.provenance, self.timestamp, self.raw
        phys = p.physical
        factors = json.dumps([f.model_dump(mode="json") for f in self.confidence_factors]) if self.confidence_factors else "[]"
        return {
            "artifact_type": self.artifact_type.value,
            "status": self.status.value,
            "confidence": self.confidence.value if self.confidence else None,
            "confidence_factors_json": factors,
            "extraction_method": self.extraction_method.value,
            "validation_notes_json": json.dumps(self.validation_notes) if self.validation_notes else "[]",
            "application": self.application,
            "evidence_file_id": p.evidence_file_id,
            "source_file": p.source_file,
            "source_sha256": p.source_sha256,
            "source_database": p.source_database,
            "source_table": p.source_table,
            "source_rowid": p.source_rowid,
            "view_includes_wal": None if p.view_includes_wal is None else int(p.view_includes_wal),
            "page_number": phys.page_number if phys else None,
            "cell_index": phys.cell_index if phys else None,
            "byte_offset": phys.byte_offset if phys else None,
            "page_type": phys.page_type if phys else None,
            "region": phys.region if phys else None,
            "raw_kind": raw.kind.value,
            "raw_row_json": None if raw.row is None else json.dumps(raw.row, default=str),
            "raw_hex": raw.raw_bytes_hex,
            "raw_sha256": raw.sha256,
            "parser": self.parser.name,
            "parser_version": self.parser.version,
            "schema_variant": self.parser.schema_variant,
            "schema_match_score": self.parser.schema_match_score,
            "ts_utc": ts.utc if ts else None,
            "ts_raw": None if ts is None or ts.raw is None else json.dumps(ts.raw),
            "ts_format": ts.format.value if ts else None,
            "ts_plausible": None if ts is None or ts.plausible is None else int(ts.plausible),
            "ts_note": ts.note if ts else None,
            "summary": self.summary,
            "fields_json": json.dumps(self.payload()),
            "unknown_fields_json": json.dumps(self.unknown_fields) if self.unknown_fields else "[]",
            "phone_key": self.phone_key,
            "marked_deleted": int(self.marked_deleted),
            "flags_json": json.dumps(self.flags) if self.flags else "[]",
            "metadata_json": json.dumps(self.metadata, default=str) if self.metadata else "{}",
            "created_at": self.created_at,
        }

    @staticmethod
    def from_record(record: Mapping[str, Any] | sqlite3.Row) -> Artifact:
        """Rebuild the correct concrete subclass from an ``artifacts`` row (inverse of ``to_record``)."""
        return artifact_from_record(record)  # type: ignore[arg-type]


_ENVELOPE_FIELDS = frozenset(Artifact.model_fields)


@cache
def _payload_defaults(cls: type[Artifact]) -> dict[str, Any]:
    """Type-specific field name → default value, computed once per class (an UNKNOWN field must equal its default)."""
    return {n: f.get_default(call_default_factory=True) for n, f in cls.model_fields.items() if n not in _ENVELOPE_FIELDS}


@cache
def _payload_names(cls: type[Artifact]) -> frozenset[str]:
    return frozenset(_payload_defaults(cls))


# ---------------------------------------------------------------- concrete artifacts


class SMSMessage(Artifact):
    artifact_type: Literal[ArtifactType.SMS] = ArtifactType.SMS
    msg_id: int | None = None
    address: str | None = None
    address_kind: AddressKind | None = None
    body: str | None = None
    direction: MessageDirection | None = None
    type_code: int | None = None
    read: bool | None = None
    seen: bool | None = None
    thread_id: int | None = None
    date_sent_utc: UtcIso | None = None
    date_sent_raw: int | float | str | None = None
    service_center: str | None = None
    subscription_id: int | None = None
    delivery_status: int | None = None
    protocol: int | None = None
    locked: bool | None = None
    subject: str | None = None


class CallRecord(Artifact):
    artifact_type: Literal[ArtifactType.CALL] = ArtifactType.CALL
    call_id: int | None = None
    number: str | None = None
    call_type: CallType | None = None
    type_code: int | None = None
    duration_seconds: int | None = None  # stored as found: a negative value is flagged by the parser, not rejected
    presentation: CallPresentation | None = None
    presentation_code: int | None = None
    cached_name: str | None = None
    lookup_uri: str | None = None
    subscription_id: str | None = None
    phone_account_address: str | None = None
    phone_account_id: str | None = None
    geocoded_location: str | None = None
    country_iso: str | None = None
    is_read: bool | None = None


class ContactPhone(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    number: str
    label: str | None = None
    primary: bool | None = None
    number_normalized: str | None = None
    phone_key: str | None = None


class ContactEmail(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    address: str
    label: str | None = None
    primary: bool | None = None


class Contact(Artifact):
    artifact_type: Literal[ArtifactType.CONTACT] = ArtifactType.CONTACT
    contact_id: int | None = None
    raw_contact_id: int | None = None
    display_name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    phones: list[ContactPhone] = Field(default_factory=list)
    emails: list[ContactEmail] = Field(default_factory=list)
    organization: str | None = None
    account_name: str | None = None
    account_type: str | None = None
    starred: bool | None = None
    times_contacted: int | None = None
    last_time_contacted_utc: UtcIso | None = None
    last_updated_utc: UtcIso | None = None


class BrowserHistoryEntry(Artifact):
    """A browser history entry: one visit, or (``url_level_only``) a URL row that has no visit rows."""

    artifact_type: Literal[ArtifactType.BROWSER_VISIT] = ArtifactType.BROWSER_VISIT
    visit_id: int | None = None
    url_id: int | None = None
    url: str | None = None
    title: str | None = None
    visit_count: int | None = None
    typed_count: int | None = None
    transition: PageTransition | None = None
    transition_code: int | None = None
    transition_qualifiers: list[TransitionQualifier] = Field(default_factory=list)
    visit_duration_us: int | None = None
    from_visit: int | None = None
    hidden: bool | None = None
    url_level_only: bool = False


class BrowserDownload(Artifact):
    artifact_type: Literal[ArtifactType.BROWSER_DOWNLOAD] = ArtifactType.BROWSER_DOWNLOAD
    download_id: int | None = None
    target_path: str | None = None
    current_path: str | None = None
    tab_url: str | None = None
    referrer: str | None = None
    mime_type: str | None = None
    received_bytes: int | None = None
    total_bytes: int | None = None
    download_state: DownloadState | None = None
    download_state_code: int | None = None
    end_time_utc: UtcIso | None = None


class ApplicationSummary(Artifact):
    """One Android package, aggregated from the hashed inventory (``raw.row['derived_from']`` lists the members)."""

    artifact_type: Literal[ArtifactType.APP_SUMMARY] = ArtifactType.APP_SUMMARY
    extraction_method: ExtractionMethod = ExtractionMethod.FILESYSTEM_METADATA
    package: str
    file_count: int
    total_bytes: int
    database_count: int
    sidecar_count: int
    shared_pref_files: list[str] = Field(default_factory=list)
    shared_pref_keys: dict[str, list[str]] = Field(default_factory=dict)
    first_modified_utc: UtcIso | None = None
    last_modified_utc: UtcIso | None = None
    known_app: str | None = None


class GenericRecord(Artifact):
    """A row of a table no parser recognises, kept without semantic labelling (Review 2: recovered rows).

    ``columns`` holds the values the bytes determined; a column the bytes did not determine is *absent* and named in
    ``unknown_columns`` (distinct from a column whose stored value is NULL)."""

    artifact_type: Literal[ArtifactType.GENERIC_RECORD] = ArtifactType.GENERIC_RECORD
    table: str
    columns: dict[str, Any] = Field(default_factory=dict)
    unknown_columns: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- polymorphic loading

_ARTIFACT_CLASSES: dict[ArtifactType, type[Artifact]] = {}


@lru_cache(maxsize=1)
def artifact_adapter() -> TypeAdapter[Any]:
    """Discriminated-union adapter over every registered artifact class (selects the subclass by ``artifact_type``)."""
    union = Union[tuple(_ARTIFACT_CLASSES.values())]  # type: ignore[valid-type]
    return TypeAdapter(Annotated[union, Field(discriminator="artifact_type")])


def register_artifact(cls: type[Artifact]) -> type[Artifact]:
    """Register a concrete artifact class so records of its type can be loaded polymorphically."""
    _ARTIFACT_CLASSES[cls.model_fields["artifact_type"].default] = cls
    artifact_adapter.cache_clear()
    return cls


for _cls in (SMSMessage, CallRecord, Contact, BrowserHistoryEntry, BrowserDownload, ApplicationSummary, GenericRecord):
    register_artifact(_cls)


def artifact_class(artifact_type: ArtifactType) -> type[Artifact]:
    return _ARTIFACT_CLASSES[artifact_type]


def artifact_from_record(record: Mapping[str, Any]) -> Artifact:
    r = record
    physical = None
    if any(r[k] is not None for k in ("page_number", "cell_index", "byte_offset")):
        physical = {k: r[k] for k in ("page_number", "cell_index", "byte_offset", "page_type", "region")}
    timestamp = None
    if r["ts_format"] is not None:
        timestamp = {
            "raw": None if r["ts_raw"] is None else json.loads(r["ts_raw"]),
            "format": r["ts_format"],
            "utc": r["ts_utc"],
            "plausible": None if r["ts_plausible"] is None else bool(r["ts_plausible"]),
            "note": r["ts_note"],
        }
    data: dict[str, Any] = {
        "id": r["id"] if "id" in r.keys() else None,
        "artifact_type": r["artifact_type"],
        "status": r["status"],
        "confidence": r["confidence"],
        "confidence_factors": json.loads(r["confidence_factors_json"] or "[]"),
        "extraction_method": r["extraction_method"],
        "validation_notes": json.loads(r["validation_notes_json"] or "[]"),
        "application": r["application"],
        "provenance": {
            "evidence_file_id": r["evidence_file_id"],
            "source_file": r["source_file"],
            "source_sha256": r["source_sha256"],
            "source_database": r["source_database"],
            "source_table": r["source_table"],
            "source_rowid": r["source_rowid"],
            "view_includes_wal": None if r["view_includes_wal"] is None else bool(r["view_includes_wal"]),
            "physical": physical,
        },
        "raw": {
            "kind": r["raw_kind"],
            "row": None if r["raw_row_json"] is None else json.loads(r["raw_row_json"]),
            "raw_bytes_hex": r["raw_hex"],
            "sha256": r["raw_sha256"],
        },
        "parser": {
            "name": r["parser"],
            "version": r["parser_version"],
            "schema_variant": r["schema_variant"],
            "schema_match_score": r["schema_match_score"],
        },
        "timestamp": timestamp,
        "summary": r["summary"] or "",
        "flags": json.loads(r["flags_json"] or "[]"),
        "unknown_fields": json.loads(r["unknown_fields_json"] or "[]"),
        "phone_key": r["phone_key"],
        "marked_deleted": bool(r["marked_deleted"]),
        "metadata": json.loads(r["metadata_json"] or "{}"),
        "created_at": r["created_at"],
        **json.loads(r["fields_json"]),
    }
    return artifact_adapter().validate_python(data)


__all__ = [
    "ApplicationSummary", "Artifact", "BrowserDownload", "BrowserHistoryEntry", "CallRecord", "Contact",
    "ContactEmail", "ContactPhone", "GenericRecord", "SMSMessage", "artifact_adapter", "artifact_class", "artifact_from_record",
    "register_artifact",
]
