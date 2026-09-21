"""Parser contract.

Design rule for Review 2: parsers turn *rows* into artifacts. ``from_row`` is a pure function over a
``RowSource`` (a mapping plus provenance) and never sees a ``sqlite3`` cursor. Records reconstructed
from raw pages by the recovery engine flow through the very same ``from_row`` code — with missing
fields marked ``UNKNOWN`` — so recovered and active artifacts are normalised identically.
"""

from __future__ import annotations

import hashlib
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import lru_cache
from datetime import datetime
from typing import Any, Iterator, Mapping

from android_forensics.artifacts.schema_probe import RoleMatch, SchemaMatch
from android_forensics.models import UNKNOWN, Artifact, ParserInfo, Provenance, RawKind, RawReference
from android_forensics.sqlite.reader import SchemaObject, SQLiteSession


@dataclass
class DbContext:
    database_id: int
    evidence_file_id: int
    source_path: str
    sha256: str
    application: str | None
    view_includes_wal: bool
    tables: dict[str, SchemaObject] = field(default_factory=dict)
    now: datetime | None = None


@dataclass
class RowSource:
    values: Mapping[str, Any]
    raw: Mapping[str, Any]
    table: str
    rowid: int | None


def jsonable(raw: Mapping[str, Any], blob_head: int = 32) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in raw.items():
        if isinstance(v, (bytes, bytearray)):
            out[k] = {
                "__blob__": True,
                "length": len(v),
                "sha256": hashlib.sha256(v).hexdigest(),
                "hex_head": bytes(v[:blob_head]).hex(),
            }
        elif isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            out[k] = str(v)
        elif isinstance(v, (list, dict)):
            out[k] = v
        else:
            out[k] = v
    return out


class FieldReader:
    """Typed access to a row's mapped fields. Type violations become flags, never silent coercion."""

    def __init__(self, row: RowSource):
        self.row = row
        self.flags: list[str] = []

    def has(self, name: str) -> bool:
        return name in self.row.values

    def raw(self, name: str) -> Any:
        return self.row.values.get(name, UNKNOWN)

    def int(self, name: str) -> Any:
        v = self.raw(name)
        if v is UNKNOWN or v is None:
            return v
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, int):
            return v
        if isinstance(v, float) and v.is_integer():
            return int(v)
        if isinstance(v, str) and v.strip().lstrip("-").isdigit():
            return int(v)
        self.flags.append(f"type_mismatch:{name} expected integer, found {type(v).__name__}")
        return None

    def text(self, name: str) -> Any:
        v = self.raw(name)
        if v is UNKNOWN or v is None:
            return v
        if isinstance(v, str):
            return v
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return str(v)
        self.flags.append(f"type_mismatch:{name} expected text, found {type(v).__name__}")
        return None

    def bool(self, name: str) -> Any:
        v = self.int(name)
        if v is UNKNOWN or v is None:
            return v
        if v in (0, 1):
            return bool(v)
        self.flags.append(f"type_mismatch:{name} expected 0/1, found {v}")
        return None


@lru_cache(maxsize=None)
def _parser_info(name: str, version: str, variant: str | None, score: float | None) -> ParserInfo:
    """ParserInfo is immutable and identical for every row of a table, so build it once."""
    return ParserInfo(name=name, version=version, schema_variant=variant, schema_match_score=score)


def build_envelope(ctx: DbContext, match: SchemaMatch, row: RowSource, parser: "ArtifactParser", flags: list[str]) -> dict[str, Any]:
    """Everything an active-row artifact shares: where it came from, the raw row, and which parser read it."""
    return dict(
        application=ctx.application,
        parser=_parser_info(parser.name, parser.version, match.variant, match.score),
        raw=RawReference(kind=RawKind.SQLITE_ROW, row=jsonable(row.raw)),
        flags=flags,
        provenance=Provenance(
            evidence_file_id=ctx.evidence_file_id,
            source_file=ctx.source_path,
            source_sha256=ctx.sha256,
            source_database=ctx.source_path,
            source_table=row.table,
            source_rowid=row.rowid,
            view_includes_wal=ctx.view_includes_wal,
        ),
    )


class ArtifactParser(ABC):
    name: str
    version: str = "1.0"

    @abstractmethod
    def identify(self, tables: list[SchemaObject], ctx: DbContext) -> list[SchemaMatch]:
        """Score the database's tables against this parser's schema knowledge."""

    @abstractmethod
    def extract(self, session: SQLiteSession, match: SchemaMatch, ctx: DbContext) -> Iterator[Artifact]:
        """Read rows for a matched schema and yield normalised artifacts."""

    @abstractmethod
    def from_row(self, row: RowSource, match: SchemaMatch, ctx: DbContext) -> Artifact | None:
        """Pure row → artifact conversion (Review 2 feeds recovered rows through this)."""

    @staticmethod
    def map_row(rowid: int | None, raw: dict[str, Any], role: RoleMatch) -> RowSource:
        values = {fld: raw[col] for fld, col in role.column_map.items() if col in raw}
        return RowSource(values=values, raw=raw, table=role.table, rowid=rowid)

    def rows(self, session: SQLiteSession, ctx: DbContext, role: RoleMatch) -> Iterator[RowSource]:
        table = ctx.tables[role.table]
        for rowid, raw in session.iter_rows(table):
            yield self.map_row(rowid, raw, role)
