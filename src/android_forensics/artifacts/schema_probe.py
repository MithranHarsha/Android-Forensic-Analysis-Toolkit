"""Schema-driven table identification.

Artifact parsers never trust a filename: they score how well a table's columns match the fields
they know how to interpret. The score (matched weight / total weight) is stored with every
artifact so an examiner can see how confident the *parsing* was.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from android_forensics.config import SCHEMA_MATCH_THRESHOLD
from android_forensics.sqlite.reader import SchemaObject


@dataclass(frozen=True)
class FieldSpec:
    field: str
    aliases: tuple[str, ...]
    required: bool = False
    weight: float = 1.0


@dataclass
class TableMatch:
    table: str
    score: float
    column_map: dict[str, str]
    missing_required: list[str]
    missing_optional: list[str]
    name_hint: bool = False

    @property
    def is_candidate(self) -> bool:
        return not self.missing_required and self.score >= SCHEMA_MATCH_THRESHOLD


def probe_table(table: SchemaObject, specs: list[FieldSpec], name_hints: tuple[str, ...] = ()) -> TableMatch:
    cols = {c.name.lower(): c.name for c in table.columns}
    cmap: dict[str, str] = {}
    matched = total = 0.0
    missing_req: list[str] = []
    missing_opt: list[str] = []
    for spec in specs:
        total += spec.weight
        actual = next((cols[a.lower()] for a in spec.aliases if a.lower() in cols), None)
        if actual is not None:
            cmap[spec.field] = actual
            matched += spec.weight
        elif spec.required:
            missing_req.append(spec.field)
        else:
            missing_opt.append(spec.field)
    score = matched / total if total else 0.0
    hint = table.name.lower() in name_hints
    if hint and not missing_req:
        score = min(1.0, score + 0.05)
    return TableMatch(table.name, round(score, 3), cmap, missing_req, missing_opt, hint)


def best_matches(
    tables: list[SchemaObject], specs: list[FieldSpec], name_hints: tuple[str, ...] = ()
) -> tuple[list[TableMatch], list[TableMatch]]:
    """Return (candidates, near_misses). Virtual tables and internal shadow tables are ignored."""
    cands: list[TableMatch] = []
    near: list[TableMatch] = []
    for t in tables:
        if t.obj_type != "table" or t.is_virtual or t.name.startswith("sqlite_"):
            continue
        m = probe_table(t, specs, name_hints)
        if m.is_candidate:
            cands.append(m)
        elif m.score >= 0.4 and len(m.column_map) >= 2:
            near.append(m)
    cands.sort(key=lambda m: (-m.score, not m.name_hint, m.table))
    return cands, near


@dataclass
class RoleMatch:
    table: str
    column_map: dict[str, str]
    score: float
    missing_optional: list[str] = field(default_factory=list)


@dataclass
class SchemaMatch:
    parser: str
    variant: str
    roles: dict[str, RoleMatch]
    score: float

    @property
    def primary(self) -> RoleMatch:
        return next(iter(self.roles.values()))
