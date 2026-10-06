"""Example parser plugin: an imaginary OEM ("Acme") call-log database.

    android-forensics --plugin examples/plugins/acme_calls.py analyze /path/to/evidence

The OEM keeps calls in ``call_history(phone, started, secs, direction)`` with Unix *seconds* and direction 'in'/'out'/'miss'.
The plugin maps that onto the standard ``CallRecord`` so validation, correlation, confidence scoring, the timeline and the
report treat it like any other call.
"""

from __future__ import annotations

from collections.abc import Iterator

from android_forensics.models import CallType
from android_forensics.plugin_api import (
    UNKNOWN,
    ArtifactParser,
    CallRecord,
    DbContext,
    FieldReader,
    FieldSpec,
    RoleMatch,
    RowSource,
    SchemaMatch,
    SchemaObject,
    SQLiteSession,
    TimestampFormat,
    best_matches,
    build_envelope,
    convert,
    phone_key,
    register,
)

SPECS = [
    FieldSpec("number", ("phone",), True, 2.0),
    FieldSpec("date", ("started",), True, 2.0),
    FieldSpec("duration", ("secs",), True, 2.0),
    FieldSpec("direction", ("direction",), True, 2.0),
    FieldSpec("call_id", ("id", "_id"), False, 0.5),
]
_DIRECTION = {"in": CallType.INCOMING, "out": CallType.OUTGOING, "miss": CallType.MISSED}


@register
class AcmeCalls(ArtifactParser):
    name = "acme_calls"
    version = "0.1"

    def identify(self, tables: list[SchemaObject], ctx: DbContext) -> list[SchemaMatch]:
        cands, _ = best_matches(tables, SPECS, name_hints=("call_history",))
        return [SchemaMatch(self.name, "acme_call_history", {"main": RoleMatch(m.table, m.column_map, m.score, m.missing_optional)}, m.score)
                for m in cands]

    def extract(self, session: SQLiteSession, match: SchemaMatch, ctx: DbContext) -> Iterator[CallRecord]:
        for row in self.rows(session, ctx, match.roles["main"]):
            art = self.from_row(row, match, ctx)
            if art is not None:
                yield art

    def from_row(self, row: RowSource, match: SchemaMatch, ctx: DbContext) -> CallRecord | None:
        r = FieldReader(row)
        number = r.text("number")
        word = r.text("direction")
        call_type = _DIRECTION.get(word, CallType.UNRECOGNISED) if isinstance(word, str) else UNKNOWN
        if call_type is CallType.UNRECOGNISED:
            r.flags.append(f"unknown_direction:{word}")
        ts = convert(r.raw("date"), TimestampFormat.UNIX_S, ctx.now)
        values = {"call_id": r.int("call_id"), "number": number, "call_type": call_type, "duration_seconds": r.int("duration")}
        who = number if isinstance(number, str) and number else "unknown number"
        return CallRecord.build(values, timestamp=ts, summary=f"Call ({word}) with {who}", phone_key=phone_key(number) if isinstance(number, str) else None,
                                **build_envelope(ctx, match, row, self, r.flags))
