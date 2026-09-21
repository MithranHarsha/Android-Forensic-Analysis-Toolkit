"""SMS parser (AOSP telephony provider ``sms`` table and compatible schemas)."""

from __future__ import annotations

from typing import Iterator

from android_forensics.artifacts.base import ArtifactParser, DbContext, FieldReader, RowSource, build_envelope
from android_forensics.artifacts.registry import register
from android_forensics.artifacts.schema_probe import FieldSpec, RoleMatch, SchemaMatch, best_matches
from android_forensics.artifacts.timestamps import convert
from android_forensics.models import UNKNOWN, AddressKind, MessageDirection, SMSMessage, TimestampFormat
from android_forensics.normalization.phone import classify_address, phone_key, snippet
from android_forensics.sqlite.reader import SchemaObject, SQLiteSession

SPECS = [
    FieldSpec("address", ("address", "sender", "phone_number"), True, 2.0),
    FieldSpec("body", ("body", "message_body", "text"), True, 2.0),
    FieldSpec("date", ("date", "date_received"), True, 2.0),
    FieldSpec("type", ("type", "msg_type", "message_type"), False, 1.5),
    FieldSpec("date_sent", ("date_sent",), False, 1.0),
    FieldSpec("read", ("read", "is_read"), False, 1.0),
    FieldSpec("thread_id", ("thread_id",), False, 1.0),
    FieldSpec("service_center", ("service_center",), False, 0.5),
    FieldSpec("sub_id", ("sub_id", "subscription_id"), False, 0.5),
    FieldSpec("msg_id", ("_id", "id"), False, 0.5),
    FieldSpec("status", ("status",), False, 0.5),
    FieldSpec("protocol", ("protocol",), False, 0.5),
    FieldSpec("locked", ("locked",), False, 0.25),
    FieldSpec("subject", ("subject",), False, 0.25),
    FieldSpec("seen", ("seen",), False, 0.25),
]


@register
class SmsParser(ArtifactParser):
    name = "sms"
    version = "1.0"

    def identify(self, tables: list[SchemaObject], ctx: DbContext) -> list[SchemaMatch]:
        cands, _ = best_matches(tables, SPECS, name_hints=("sms",))
        return [
            SchemaMatch(self.name, "aosp_sms", {"main": RoleMatch(m.table, m.column_map, m.score, m.missing_optional)}, m.score)
            for m in cands
        ]

    def extract(self, session: SQLiteSession, match: SchemaMatch, ctx: DbContext) -> Iterator[SMSMessage]:
        for row in self.rows(session, ctx, match.roles["main"]):
            art = self.from_row(row, match, ctx)
            if art is not None:
                yield art

    def from_row(self, row: RowSource, match: SchemaMatch, ctx: DbContext) -> SMSMessage | None:
        r = FieldReader(row)
        address = r.text("address")
        body = r.text("body")
        type_code = r.int("type")
        direction = MessageDirection.from_code(type_code) if type_code is not UNKNOWN else UNKNOWN
        if direction is MessageDirection.UNRECOGNISED:
            r.flags.append(f"unknown_type_code:{type_code}")

        ts = convert(r.raw("date"), TimestampFormat.UNIX_MS, ctx.now) if r.has("date") else None
        if ts is not None and ts.utc is None and ts.note not in ("NULL",):
            r.flags.append(f"timestamp:date {ts.note}")

        sent_raw = r.raw("date_sent")
        sent_utc: object = UNKNOWN
        if r.has("date_sent"):
            sent_utc = convert(sent_raw, TimestampFormat.UNIX_MS, ctx.now).utc

        values = {
            "msg_id": r.int("msg_id"),
            "address": address,
            "address_kind": classify_address(address) if isinstance(address, str) or address is None else AddressKind.UNKNOWN,
            "body": body,
            "direction": direction,
            "type_code": type_code,
            "read": r.bool("read"),
            "seen": r.bool("seen"),
            "thread_id": r.int("thread_id"),
            "date_sent_utc": sent_utc,
            "date_sent_raw": sent_raw if r.has("date_sent") else UNKNOWN,
            "service_center": r.text("service_center"),
            "subscription_id": r.int("sub_id"),
            "delivery_status": r.int("status"),
            "protocol": r.int("protocol"),
            "locked": r.bool("locked"),
            "subject": r.text("subject"),
        }
        who = address if isinstance(address, str) and address else "unknown address"
        verb = {MessageDirection.RECEIVED: "from", MessageDirection.SENT: "to"}.get(direction, "with")
        label = direction.value if isinstance(direction, MessageDirection) else "message"
        summary = f"SMS {label} {verb} {who}: {snippet(body if isinstance(body, str) else None)}"
        return SMSMessage.build(
            values,
            timestamp=ts,
            summary=summary,
            phone_key=phone_key(address) if isinstance(address, str) else None,
            **build_envelope(ctx, match, row, self, r.flags),
        )
