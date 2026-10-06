"""Call-log parser (AOSP ``calls`` table and compatible schemas)."""

from __future__ import annotations

from collections.abc import Iterator

from android_forensics.artifacts.base import ArtifactParser, DbContext, FieldReader, RowSource, build_envelope
from android_forensics.artifacts.registry import register
from android_forensics.artifacts.schema_probe import FieldSpec, RoleMatch, SchemaMatch, best_matches
from android_forensics.artifacts.timestamps import convert
from android_forensics.models import UNKNOWN, CallPresentation, CallRecord, CallType, TimestampFormat
from android_forensics.normalization.phone import phone_key
from android_forensics.sqlite.reader import SchemaObject, SQLiteSession

SPECS = [
    FieldSpec("number", ("number", "phone_number"), True, 2.0),
    FieldSpec("date", ("date",), True, 2.0),
    FieldSpec("duration", ("duration",), True, 2.0),
    FieldSpec("type", ("type", "call_type"), True, 2.0),
    FieldSpec("presentation", ("presentation",), False, 1.0),
    FieldSpec("name", ("name", "cached_name", "cachedname"), False, 1.0),
    FieldSpec("lookup_uri", ("lookup_uri",), False, 0.75),
    FieldSpec("subscription_id", ("subscription_id", "sub_id"), False, 0.5),
    FieldSpec("phone_account_address", ("phone_account_address",), False, 0.5),
    FieldSpec("phone_account_id", ("phone_account_id",), False, 0.5),
    FieldSpec("geocoded_location", ("geocoded_location",), False, 0.25),
    FieldSpec("countryiso", ("countryiso",), False, 0.25),
    FieldSpec("is_read", ("is_read",), False, 0.25),
    FieldSpec("call_id", ("_id", "id"), False, 0.5),
]


@register
class CallsParser(ArtifactParser):
    name = "calls"
    version = "1.0"

    def identify(self, tables: list[SchemaObject], ctx: DbContext) -> list[SchemaMatch]:
        cands, _ = best_matches(tables, SPECS, name_hints=("calls",))
        return [
            SchemaMatch(self.name, "aosp_calls", {"main": RoleMatch(m.table, m.column_map, m.score, m.missing_optional)}, m.score)
            for m in cands
        ]

    def extract(self, session: SQLiteSession, match: SchemaMatch, ctx: DbContext) -> Iterator[CallRecord]:
        for row in self.rows(session, ctx, match.roles["main"]):
            art = self.from_row(row, match, ctx)
            if art is not None:
                yield art

    def from_row(self, row: RowSource, match: SchemaMatch, ctx: DbContext) -> CallRecord | None:
        r = FieldReader(row)
        number = r.text("number")
        type_code = r.int("type")
        call_type = CallType.from_code(type_code) if type_code is not UNKNOWN else UNKNOWN
        if call_type is CallType.UNRECOGNISED:
            r.flags.append(f"unknown_type_code:{type_code}")
        pres_code = r.int("presentation")
        presentation = CallPresentation.from_code(pres_code) if pres_code is not UNKNOWN else UNKNOWN

        duration = r.int("duration")
        if isinstance(duration, int) and duration < 0:
            r.flags.append(f"invalid_duration:{duration}")
        ts = convert(r.raw("date"), TimestampFormat.UNIX_MS, ctx.now) if r.has("date") else None
        if ts is not None and ts.utc is None and ts.note != "NULL":
            r.flags.append(f"timestamp:date {ts.note}")

        values = {
            "call_id": r.int("call_id"),
            "number": number,
            "call_type": call_type,
            "type_code": type_code,
            "duration_seconds": duration,
            "presentation": presentation,
            "presentation_code": pres_code,
            "cached_name": r.text("name"),
            "lookup_uri": r.text("lookup_uri"),
            "subscription_id": r.text("subscription_id"),
            "phone_account_address": r.text("phone_account_address"),
            "phone_account_id": r.text("phone_account_id"),
            "geocoded_location": r.text("geocoded_location"),
            "country_iso": r.text("countryiso"),
            "is_read": r.bool("is_read"),
        }
        who = number if isinstance(number, str) and number else "private/unknown number"
        dur = f" ({duration}s)" if isinstance(duration, int) else ""
        label = call_type.value if isinstance(call_type, CallType) else "call"
        direction_word = "from" if isinstance(call_type, CallType) and call_type in (
            CallType.INCOMING, CallType.MISSED, CallType.REJECTED, CallType.BLOCKED) else "to"
        summary = f"Call {label} {direction_word} {who}{dur}"
        return CallRecord.build(
            values,
            timestamp=ts,
            summary=summary,
            phone_key=phone_key(number) if isinstance(number, str) else None,
            **build_envelope(ctx, match, row, self, r.flags),
        )
