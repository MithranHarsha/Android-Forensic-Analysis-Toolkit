"""Google Messages (``com.google.android.apps.messaging``, database ``bugle_db``) — the default SMS/RCS app on Pixels.

Messages live in three tables: ``messages`` (one row per message: status, timestamps, sender), ``parts`` (one row per part of a
message; the text is ``parts.text`` where ``content_type`` is ``text/plain``) and ``conversations`` (the counterpart's number in
``participant_normalized_destination``). This parser joins them in Python and yields the ordinary :class:`SMSMessage`, so
correlation, confidence, the timeline and the report treat these messages like any other.

Direction comes from ``message_status``: values below 100 are outgoing states (1 sent, 2 queued, 3 sending … 8 delivered) and
100 and above are incoming ones (100 is a complete incoming message; 2xx are RCS / media / system states) — checked against the
author's own message list of the public Digital Corpora Android 9 image. A message with no text part (media, RCS system events) is
still reported, with ``body`` unset and the content types listed in a flag, rather than silently dropped.

Recovered rows of these tables are *not* converted row by row: a deleted ``parts`` row has the text but not the sender, and a
deleted ``messages`` row the sender but not the text. They surface as generic records, which keeps every value and claims no meaning.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from typing import Any

from android_forensics.artifacts.base import ArtifactParser, DbContext, FieldReader, RowSource, build_envelope
from android_forensics.artifacts.registry import register
from android_forensics.artifacts.schema_probe import FieldSpec, RoleMatch, SchemaMatch, best_matches
from android_forensics.artifacts.timestamps import convert
from android_forensics.models import UNKNOWN, AddressKind, MessageDirection, SMSMessage, TimestampFormat
from android_forensics.normalization.phone import classify_address, phone_key, snippet
from android_forensics.sqlite.reader import SchemaObject, SQLiteSession

MESSAGES = [
    FieldSpec("id", ("_id",), True, 1.0),
    FieldSpec("conversation_id", ("conversation_id",), True, 2.0),
    FieldSpec("received_timestamp", ("received_timestamp",), True, 2.0),
    FieldSpec("message_status", ("message_status",), True, 2.0),
    FieldSpec("sent_timestamp", ("sent_timestamp",), False, 1.0),
    FieldSpec("sender_id", ("sender_id",), False, 1.0),
    FieldSpec("read", ("read",), False, 0.5),
    FieldSpec("seen", ("seen",), False, 0.5),
    FieldSpec("protocol", ("message_protocol",), False, 0.5),
    FieldSpec("subject", ("mms_subject",), False, 0.25),
]
PARTS = [
    FieldSpec("message_id", ("message_id",), True, 2.0),
    FieldSpec("text", ("text",), True, 2.0),
    FieldSpec("content_type", ("content_type",), True, 2.0),
    FieldSpec("id", ("_id",), False, 0.5),
]
CONVERSATIONS = [
    FieldSpec("id", ("_id",), True, 1.0),
    FieldSpec("destination", ("participant_normalized_destination",), True, 2.0),
    FieldSpec("sms_thread_id", ("sms_thread_id",), False, 0.5),
    FieldSpec("name", ("name",), False, 0.5),
]
PARTICIPANTS = [
    FieldSpec("id", ("_id",), True, 1.0),
    FieldSpec("destination", ("normalized_destination",), True, 2.0),
]
INCOMING_FROM = 100


def _best(tables: list[SchemaObject], specs: list[FieldSpec], hints: tuple[str, ...]) -> RoleMatch | None:
    cands, _ = best_matches(tables, specs, hints)
    if not cands:
        return None
    m = cands[0]
    return RoleMatch(m.table, m.column_map, m.score, m.missing_optional)


@register
class GoogleMessagesParser(ArtifactParser):
    name = "google_messages"
    version = "1.0"

    def identify(self, tables: list[SchemaObject], ctx: DbContext) -> list[SchemaMatch]:
        messages, parts, conversations = _best(tables, MESSAGES, ("messages",)), _best(tables, PARTS, ("parts",)), _best(tables, CONVERSATIONS, ("conversations",))
        # AOSP's own ``sms`` table has none of message_status / conversation_id, so this cannot claim a telephony database
        if not (messages and parts and conversations) or messages.table == parts.table:
            return []
        roles = {"messages": messages, "parts": parts, "conversations": conversations}
        participants = _best([t for t in tables if t.name not in (messages.table, parts.table, conversations.table)], PARTICIPANTS, ("participants",))
        if participants:
            roles["participants"] = participants
        score = round(sum(r.score for r in roles.values()) / len(roles), 3)
        return [SchemaMatch(self.name, "google_messages_bugle", roles, score)]

    def extract(self, session: SQLiteSession, match: SchemaMatch, ctx: DbContext) -> Iterator[SMSMessage]:
        destinations = {r.values.get("id"): r.values.get("destination") for r in self.rows(session, ctx, match.roles["conversations"])}
        people = ({r.values.get("id"): r.values.get("destination") for r in self.rows(session, ctx, match.roles["participants"])}
                  if "participants" in match.roles else {})
        text_parts: dict[Any, list[str]] = defaultdict(list)
        other_types: dict[Any, list[str]] = defaultdict(list)
        for p in self.rows(session, ctx, match.roles["parts"]):
            ctype, text = p.values.get("content_type"), p.values.get("text")
            if isinstance(ctype, str) and ctype.startswith("text/") and isinstance(text, str):
                text_parts[p.values.get("message_id")].append(text)
            elif ctype:
                other_types[p.values.get("message_id")].append(str(ctype))
        for row in self.rows(session, ctx, match.roles["messages"]):
            mid = row.values.get("id") if row.values.get("id") is not None else row.rowid
            values = dict(row.values)
            conv = values.get("conversation_id")
            values["_address"] = destinations.get(conv) or people.get(values.get("sender_id"))
            values["_body"] = "\n".join(text_parts[mid]) if mid in text_parts else None
            values["_other_types"] = other_types.get(mid, [])
            art = self.from_row(RowSource(values, row.raw, row.table, row.rowid), match, ctx)
            if art is not None:
                yield art

    def from_row(self, row: RowSource, match: SchemaMatch, ctx: DbContext) -> SMSMessage | None:
        r = FieldReader(row)
        status = r.int("message_status")
        if status is UNKNOWN or status is None:
            direction: Any = UNKNOWN
            type_code: Any = UNKNOWN
        else:
            incoming = status >= INCOMING_FROM
            direction = MessageDirection.RECEIVED if incoming else MessageDirection.SENT
            type_code = 1 if incoming else 2
        address = row.values.get("_address")
        body = row.values.get("_body")
        other = row.values.get("_other_types") or []
        if body is None and other:
            r.flags.append("no_text_part:" + ",".join(sorted(set(other))))
        elif body is None:
            r.flags.append("no_text_part")
        r.flags.append(f"bugle_status:{status}")
        ts = convert(r.raw("received_timestamp"), TimestampFormat.UNIX_MS, ctx.now) if r.has("received_timestamp") else None
        if ts is not None and ts.utc is None and ts.note not in ("NULL",):
            r.flags.append(f"timestamp:received_timestamp {ts.note}")
        sent_raw = r.raw("sent_timestamp")
        sent_utc: object = UNKNOWN
        if r.has("sent_timestamp") and isinstance(sent_raw, int) and sent_raw > 0:
            sent_utc = convert(sent_raw, TimestampFormat.UNIX_MS, ctx.now).utc
        values = {
            "msg_id": r.int("id"), "address": address,
            "address_kind": classify_address(address) if isinstance(address, str) or address is None else AddressKind.UNKNOWN,
            "body": body, "direction": direction, "type_code": type_code, "read": r.bool("read"), "seen": r.bool("seen"),
            "thread_id": r.int("conversation_id"), "date_sent_utc": sent_utc, "date_sent_raw": sent_raw if r.has("sent_timestamp") else UNKNOWN,
            "service_center": UNKNOWN, "subscription_id": UNKNOWN, "delivery_status": status, "protocol": r.int("protocol"),
            "locked": UNKNOWN, "subject": r.text("subject"),
        }
        who = address if isinstance(address, str) and address else "unknown address"
        verb = {MessageDirection.RECEIVED: "from", MessageDirection.SENT: "to"}.get(direction, "with")
        label = direction.value if isinstance(direction, MessageDirection) else "message"
        return SMSMessage.build(
            values, timestamp=ts, summary=f"Google Messages {label} {verb} {who}: {snippet(body if isinstance(body, str) else None)}",
            phone_key=phone_key(address) if isinstance(address, str) else None, **build_envelope(ctx, match, row, self, r.flags),
        )
