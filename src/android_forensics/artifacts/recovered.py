"""Recovered rows -> typed artifacts (Phase 5).

A recovered record becomes an artifact through the *same* parser code that reads active rows (``ArtifactParser.from_row``);
only the envelope differs. A column the bytes did not determine is absent from the row, which every parser already reads as
``UNKNOWN`` (never NULL, never a default). What a parser cannot build from one row -- a contact (several tables), a browser
visit whose URL row is gone -- stays a ``GenericRecord``: the values are kept, no meaning is attached.

Parsers used per table: ``sms`` and ``calls`` (their main table), Chromium ``urls`` (a URL-level entry), ``visits`` (a visit;
its URL is looked up in the *active* ``urls`` table when that row still exists, and the artifact says so -- the URL text is
not among the recovered bytes), ``downloads``, and the legacy flat browser-history table.

The artifact's status, extraction method, raw bytes, physical location and confidence come from the recovery record and the
scorer (``confidence.scorer``); the parser contributes the typed payload, the timestamp and the summary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Sequence

from android_forensics.artifacts.base import ArtifactParser, DbContext, RowSource, jsonable
from android_forensics.artifacts.registry import get_parsers
from android_forensics.artifacts.schema_probe import SchemaMatch
from android_forensics.confidence.scorer import RecoveryEvidence, score_recovered
from android_forensics.models import (
    UNKNOWN,
    Artifact,
    ExtractionMethod,
    GenericRecord,
    ParserInfo,
    PhysicalLocation,
    Provenance,
    RawKind,
    RawReference,
    RecoveredRecord,
    decode_value,
    encode_value,
)
from android_forensics.sqlite.reader import ColumnInfo, SchemaObject
from android_forensics.sqlite.recover_db import RecoveryReport
from android_forensics.sqlite.recovery import RecoveredRow, TableModel

# Roles a parser can turn into an artifact from one row alone.
_ROW_ROLES = {"sms": {"main"}, "calls": {"main"}, "browser": {"urls", "visits", "downloads", "main"}}
_BROWSER_KIND = {"urls": "url", "visits": "visit", "downloads": "download", "main": "legacy"}
_RAW_KIND = {ExtractionMethod.WAL_FRAME: RawKind.WAL_FRAME, ExtractionMethod.JOURNAL_PAGE: RawKind.JOURNAL_PAGE}
_GENERIC_INFO = ("generic", "1.0", "declared_schema")


@dataclass
class DatabaseContext:
    """What reconstruction needs to know about one database (built once, used for every recovered record of it)."""

    database_file_id: int
    database_path: str
    database_sha256: str
    application: str | None
    models: Sequence[TableModel]
    now: datetime | None = None
    urls: Mapping[Any, tuple[str | None, str | None]] = field(default_factory=dict)  # active url id -> (url, title)
    wal_frame_status: Mapping[int, str] = field(default_factory=dict)  # WAL frame index -> committed / stale_generation / ...
    journal_checksum_ok: Mapping[int, bool] = field(default_factory=dict)  # journal record index -> its checksum verified
    _routes: dict[str, tuple[ArtifactParser, SchemaMatch, str]] | None = field(default=None, repr=False)

    @classmethod
    def from_report(cls, report: "RecoveryReport", *, database_file_id: int, database_sha256: str, application: str | None,
                    now: datetime | None = None, urls: Mapping[Any, tuple[str | None, str | None]] | None = None) -> "DatabaseContext":
        return cls(database_file_id, report.database, database_sha256, application, report.models, now, urls or {},
                   report.wal_frame_status, report.journal_checksum_ok)

    def schema_objects(self) -> list[SchemaObject]:
        return [
            SchemaObject("table", m.name, m.name, None, None,
                         columns=[ColumnInfo(c.name, c.declared_type, c.not_null, c.primary_key_position) for c in m.columns])
            for m in self.models
        ]

    def parser_context(self) -> DbContext:
        return DbContext(database_id=0, evidence_file_id=self.database_file_id, source_path=self.database_path,
                         sha256=self.database_sha256, application=self.application, view_includes_wal=False, tables={}, now=self.now)

    def routes(self) -> dict[str, tuple[ArtifactParser, SchemaMatch, str]]:
        """table name -> (parser, schema match, role), for every table a parser can convert row by row."""
        if self._routes is None:
            objects, ctx = self.schema_objects(), self.parser_context()
            routes: dict[str, tuple[ArtifactParser, SchemaMatch, str]] = {}
            for parser in get_parsers():
                allowed = _ROW_ROLES.get(parser.name, set())
                for match in parser.identify(objects, ctx) if allowed else ():
                    for role_name, role in match.roles.items():
                        if role_name in allowed:
                            routes.setdefault(role.table, (parser, match, role_name))
            self._routes = routes
        return self._routes


def _provenance(record: RecoveredRecord, dc: DatabaseContext) -> Provenance:
    return Provenance(
        evidence_file_id=record.source_file_id, source_file=record.source_path, source_sha256=record.source_sha256,
        source_database=dc.database_path, source_table=record.table, source_rowid=record.rowid,
        physical=PhysicalLocation(page_number=record.page_number, cell_index=record.cell_index, byte_offset=record.file_offset,
                                  page_type=record.page_type, region=record.region),
    )


def _raw(record: RecoveredRecord) -> RawReference:
    return RawReference(kind=_RAW_KIND.get(record.method, RawKind.PAGE_BYTES), raw_bytes_hex=record.raw_hex)


def _row_source(record: RecoveredRecord, values: dict[str, Any], match: SchemaMatch, role_name: str, parser: ArtifactParser,
                dc: DatabaseContext) -> tuple[RowSource, list[str]]:
    """The parser's view of the recovered row. Only columns the bytes determine are present; the rest read as UNKNOWN."""
    role = match.roles[role_name]
    mapped = {fld: values[col] for fld, col in role.column_map.items() if col in values}
    notes: list[str] = []
    if parser.name == "browser":
        mapped["_kind"] = _BROWSER_KIND[role_name]
        id_col = role.column_map.get("id")
        if role_name == "urls":
            mapped["url_id"] = values.get(id_col, UNKNOWN) if id_col else UNKNOWN
        elif role_name == "visits":
            fk = values.get(role.column_map["url"], UNKNOWN)
            mapped.update(url_id=fk, url=UNKNOWN, title=UNKNOWN)
            known = dc.urls.get(fk) if fk is not UNKNOWN else None
            if known is not None and known[0] is not None:
                mapped["url"] = known[0]
                if known[1] is not None:
                    mapped["title"] = known[1]
                notes.append("url_from_active_urls_table: the visit row holds only a url id; the URL text comes from the "
                             "urls table's active row, not from the recovered bytes")
    return RowSource(values=mapped, raw=values, table=record.table, rowid=record.rowid), notes


def _count_locations(record: RecoveredRecord) -> int:
    return sum(1 for loc in record.also_found_at if not loc.startswith("rowid "))


def _evidence(record: RecoveredRecord, dc: DatabaseContext, draft: Artifact | None, corroborations: Sequence[str]) -> RecoveryEvidence:
    ts = draft.timestamp if draft is not None else None
    return RecoveryEvidence(
        status=record.status,
        source=record.source,
        frame_status=dc.wal_frame_status.get(record.frame) if record.source == "wal" and record.frame else None,
        journal_verified=dc.journal_checksum_ok.get(record.frame, True) if record.source == "journal" and record.frame else True,
        fit=record.fit,
        schema_matched=True,  # the record was fitted to a table whose CREATE statement was read
        parser_score=draft.parser.schema_match_score if draft is not None else None,
        exact_structure=True,  # the engine only emits records whose header, body and cell end agree (sqlite/recovery.py)
        unknown_fields=tuple(record.unknown_columns),
        rowid_known=record.rowid is not None,
        field_problems=tuple(f for f in (draft.flags if draft is not None else ()) if f.startswith("type_mismatch")),
        timestamp_plausible=ts.plausible if ts is not None else None,  # None (NULL / unset / absent): nothing to judge
        page_valid=record.page_type is not None,
        corroborations=tuple(corroborations),
        other_locations=_count_locations(record),
        untouched_cell=record.rowid is not None,  # a rowid means the cell's first bytes survived: the whole cell is intact
    )


def reconstruct(record: RecoveredRecord, dc: DatabaseContext, corroborations: Sequence[str] = ()) -> Artifact:
    """The typed artifact for ``record``: a parser-built payload wrapped in the recovery envelope, scored by the scorer.

    ``corroborations`` are the independent sources the correlation stage found for it ("contact Ann Lee", ...)."""
    values = {k: decode_value(v) for k, v in record.values.items()}
    route = dc.routes().get(record.table)
    draft: Artifact | None = None
    notes: list[str] = []
    if route is not None:
        parser, match, role_name = route
        row, notes = _row_source(record, values, match, role_name, parser, dc)
        draft = parser.from_row(row, match, dc.parser_context())
    assessment = score_recovered(_evidence(record, dc, draft, corroborations))
    common: dict[str, Any] = dict(
        status=record.status, extraction_method=record.method, confidence=assessment.level, confidence_factors=list(assessment.factors),
        validation_notes=[*record.issues, assessment.explanation], provenance=_provenance(record, dc), raw=_raw(record),
        application=dc.application,
        metadata=dict(recovered_record_id=record.id, also_found_at=list(record.also_found_at), confidence_score=assessment.score,
                      confidence_explanation=assessment.explanation, unknown_columns=list(record.unknown_columns)),
    )
    if draft is None:
        return _generic(record, values, common)
    return draft.evolve(**common, flags=[*draft.flags, *notes], marked_deleted=False)


def _generic(record: RecoveredRecord, values: dict[str, Any], common: dict[str, Any]) -> GenericRecord:
    columns = jsonable(values)
    shown = ", ".join(f"{k}={str(v)[:24]}" for k, v in list(columns.items())[:4])
    name, version, variant = _GENERIC_INFO
    return GenericRecord(
        **common, parser=ParserInfo(name=name, version=version, schema_variant=variant, schema_match_score=record.fit),
        table=record.table, columns=columns, unknown_columns=list(record.unknown_columns),
        summary=f"Row of table {record.table}" + (f": {shown}" if shown else ""),
    )


def record_from_row(row: RecoveredRow, *, database_file_id: int, source_file_id: int, source_sha256: str,
                    database_id: int | None = None) -> RecoveredRecord:
    """Stage an engine row as a ``RecoveredRecord``: undetermined columns are dropped from ``values`` (they are named in
    ``unknown_columns``), blobs are encoded, and the raw bytes are bound to their digest."""
    return RecoveredRecord(
        database_id=database_id, database_file_id=database_file_id, source=row.source, source_file_id=source_file_id,
        source_path=row.source_path, source_sha256=source_sha256, table=row.table,
        values={k: encode_value(v) for k, v in row.values.items() if v is not UNKNOWN},
        unknown_columns=list(row.unknown_columns), rowid=row.rowid, status=row.status, method=row.method,
        page_number=row.page_number, page_offset=row.page_offset, file_offset=row.file_offset, length=row.length,
        page_type=row.page_type, region=row.region, cell_index=row.cell_index, frame=row.frame, raw_hex=row.raw.hex(),
        fit=row.fit, issues=list(row.issues), also_found_at=list(row.also_found_at),
    )


__all__ = ["DatabaseContext", "reconstruct", "record_from_row"]
