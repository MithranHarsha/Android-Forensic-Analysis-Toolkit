"""Contacts parser.

AOSP stores a contact across several tables (``raw_contacts`` ⨝ ``data`` ⨝ ``mimetypes`` ⨝ ``accounts``),
so this parser joins them in Python and hands the composed row to ``from_row``. A flat single-table
variant (name + number columns in a table whose *name* suggests contacts) is also supported.

Rows flagged ``deleted=1`` by Android are still physically present until the next sync. They are
reported as ACTIVE rows carrying ``marked_deleted=True`` — they are not "recovered" data.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterator

from android_forensics.artifacts.base import ArtifactParser, DbContext, FieldReader, RowSource, build_envelope, jsonable
from android_forensics.artifacts.registry import register
from android_forensics.artifacts.schema_probe import FieldSpec, RoleMatch, SchemaMatch, best_matches
from android_forensics.artifacts.timestamps import convert
from android_forensics.models import UNKNOWN, Contact, ContactEmail, ContactPhone, TimestampFormat
from android_forensics.normalization.phone import normalize_number, phone_key
from android_forensics.sqlite.reader import SchemaObject, SQLiteSession

RAW = [
    FieldSpec("id", ("_id", "id"), True, 1.0),
    FieldSpec("display_name", ("display_name",), True, 2.0),
    FieldSpec("contact_id", ("contact_id",), False, 1.0),
    FieldSpec("account_id", ("account_id",), False, 0.5),
    FieldSpec("deleted", ("deleted",), False, 1.0),
    FieldSpec("starred", ("starred",), False, 0.5),
    FieldSpec("times_contacted", ("times_contacted",), False, 0.5),
    FieldSpec("last_time_contacted", ("last_time_contacted",), False, 0.5),
]
DATA = [
    FieldSpec("raw_contact_id", ("raw_contact_id",), True, 2.0),
    FieldSpec("mimetype_id", ("mimetype_id",), True, 2.0),
    FieldSpec("data1", ("data1",), True, 2.0),
    FieldSpec("data2", ("data2",), False, 1.0),
    FieldSpec("data3", ("data3",), False, 0.5),
    FieldSpec("is_primary", ("is_primary",), False, 0.5),
    FieldSpec("id", ("_id",), False, 0.5),
]
MIME = [FieldSpec("id", ("_id",), True, 1.0), FieldSpec("mimetype", ("mimetype",), True, 2.0)]
ACCOUNTS = [
    FieldSpec("id", ("_id",), True, 1.0),
    FieldSpec("account_name", ("account_name",), True, 2.0),
    FieldSpec("account_type", ("account_type",), False, 1.0),
]
CONTACTS = [
    FieldSpec("id", ("_id",), True, 1.0),
    FieldSpec("updated", ("contact_last_updated_timestamp",), False, 2.0),
    FieldSpec("last_time_contacted", ("last_time_contacted",), False, 1.0),
    FieldSpec("times_contacted", ("times_contacted",), False, 1.0),
    FieldSpec("starred", ("starred",), False, 0.5),
    FieldSpec("lookup", ("lookup",), False, 0.5),
]
FLAT = [
    FieldSpec("display_name", ("display_name", "name", "contact_name"), True, 2.0),
    FieldSpec("number", ("number", "phone", "phone_number", "mobile"), True, 2.0),
    FieldSpec("email", ("email", "email_address"), False, 1.0),
    FieldSpec("id", ("_id", "id"), False, 0.5),
    FieldSpec("account_name", ("account_name", "account"), False, 0.5),
]
FLAT_NAME_HINTS = ("contacts", "contact", "phonebook", "people")

PHONE_TYPE = {1: "HOME", 2: "MOBILE", 3: "WORK", 4: "FAX_WORK", 5: "FAX_HOME", 6: "PAGER", 7: "OTHER", 12: "MAIN"}
EMAIL_TYPE = {1: "HOME", 2: "WORK", 3: "OTHER", 4: "MOBILE"}
MIME_NAME = "vnd.android.cursor.item/name"
MIME_PHONE = "vnd.android.cursor.item/phone_v2"
MIME_EMAIL = "vnd.android.cursor.item/email_v2"
MIME_ORG = "vnd.android.cursor.item/organization"


def _label(table: dict[int, str], code: object) -> str | None:
    if code is None:
        return None
    return table.get(code, f"UNMAPPED({code})") if isinstance(code, int) else f"UNMAPPED({code})"


def _best(tables: list[SchemaObject], specs: list[FieldSpec], hints: tuple[str, ...]) -> RoleMatch | None:
    cands, _ = best_matches(tables, specs, hints)
    if not cands:
        return None
    m = cands[0]
    return RoleMatch(m.table, m.column_map, m.score, m.missing_optional)


@register
class ContactsParser(ArtifactParser):
    name = "contacts"
    version = "1.0"

    def identify(self, tables: list[SchemaObject], ctx: DbContext) -> list[SchemaMatch]:
        raw = _best(tables, RAW, ("raw_contacts",))
        data = _best(tables, DATA, ("data",))
        mime = _best(tables, MIME, ("mimetypes",))
        if raw and data and mime:
            roles: dict[str, RoleMatch] = {"raw_contacts": raw, "data": data, "mimetypes": mime}
            for role, specs, hints in (("accounts", ACCOUNTS, ("accounts",)), ("contacts", CONTACTS, ("contacts",))):
                found = _best([t for t in tables if t.name != raw.table], specs, hints)
                if found:
                    roles[role] = found
            score = round(sum(r.score for r in roles.values()) / len(roles), 3)
            return [SchemaMatch(self.name, "aosp_contacts2", roles, score)]
        out = []
        cands, _ = best_matches(tables, FLAT, FLAT_NAME_HINTS)
        for m in cands:
            if m.name_hint:
                out.append(SchemaMatch(self.name, "flat_contacts", {"main": RoleMatch(m.table, m.column_map, m.score, m.missing_optional)}, m.score))
        return out

    def extract(self, session: SQLiteSession, match: SchemaMatch, ctx: DbContext) -> Iterator[Contact]:
        if match.variant == "flat_contacts":
            for row in self.rows(session, ctx, match.roles["main"]):
                v = dict(row.values)
                num = v.get("number")
                v["phones"] = [{"number": num, "label": None}] if num else []
                em = v.get("email")
                v["emails"] = [{"address": em, "label": None}] if em else []
                art = self.from_row(RowSource(v, row.raw, row.table, row.rowid), match, ctx)
                if art:
                    yield art
            return

        mimes = {rid: r.values.get("mimetype") for r in self.rows(session, ctx, match.roles["mimetypes"]) for rid in [r.values.get("id")]}
        accounts: dict[Any, dict] = {}
        if "accounts" in match.roles:
            for r in self.rows(session, ctx, match.roles["accounts"]):
                accounts[r.values.get("id")] = r.values
        contacts_tbl: dict[Any, dict] = {}
        if "contacts" in match.roles:
            for r in self.rows(session, ctx, match.roles["contacts"]):
                contacts_tbl[r.values.get("id")] = r.values

        data_by_raw: dict[Any, list[RowSource]] = defaultdict(list)
        for r in self.rows(session, ctx, match.roles["data"]):
            data_by_raw[r.values.get("raw_contact_id")].append(r)

        for row in self.rows(session, ctx, match.roles["raw_contacts"]):
            v: dict[str, Any] = dict(row.values)
            phones, emails, org = [], [], None
            given = family = struct_name = None
            joined_raw = []
            for d in data_by_raw.get(row.rowid if row.values.get("id") is None else row.values.get("id"), []):
                mt = mimes.get(d.values.get("mimetype_id"))
                joined_raw.append({"_rowid": d.rowid, "mimetype": mt, **jsonable(d.raw)})
                if mt == MIME_PHONE:
                    t = d.values.get("data2")
                    tcode = int(t) if isinstance(t, str) and t.isdigit() else t
                    phones.append({"number": d.values.get("data1"), "label": _label(PHONE_TYPE, tcode), "primary": bool(d.values.get("is_primary"))})
                elif mt == MIME_EMAIL:
                    t = d.values.get("data2")
                    tcode = int(t) if isinstance(t, str) and t.isdigit() else t
                    emails.append({"address": d.values.get("data1"), "label": _label(EMAIL_TYPE, tcode), "primary": bool(d.values.get("is_primary"))})
                elif mt == MIME_NAME:
                    struct_name, given, family = d.values.get("data1"), d.values.get("data2"), d.values.get("data3")
                elif mt == MIME_ORG:
                    org = d.values.get("data1")
            acct = accounts.get(v.get("account_id"), {})
            ct = contacts_tbl.get(v.get("contact_id"), {})
            v.update(
                phones=phones, emails=emails, organization=org, given_name=given, family_name=family,
                structured_name=struct_name, account_name=acct.get("account_name", UNKNOWN if "accounts" not in match.roles else None),
                account_type=acct.get("account_type", UNKNOWN if "accounts" not in match.roles else None),
                updated=ct.get("updated", UNKNOWN), contacts_last_contacted=ct.get("last_time_contacted", UNKNOWN),
            )
            raw = {"raw_contacts": jsonable(row.raw), "data": joined_raw}
            art = self.from_row(RowSource(v, raw, row.table, row.rowid), match, ctx)
            if art:
                yield art

    def from_row(self, row: RowSource, match: SchemaMatch, ctx: DbContext) -> Contact | None:
        r = FieldReader(row)
        display = r.text("display_name")
        if display is UNKNOWN and row.values.get("structured_name"):
            display = row.values["structured_name"]
        phones = [
            ContactPhone(
                number=str(p["number"]), label=p.get("label"), primary=p.get("primary"),
                number_normalized=normalize_number(str(p["number"])), phone_key=phone_key(str(p["number"])),
            )
            for p in row.values.get("phones", [])
            if p.get("number")
        ]
        emails = [
            ContactEmail(address=str(e["address"]), label=e.get("label"), primary=e.get("primary"))
            for e in row.values.get("emails", [])
            if e.get("address")
        ]

        updated = row.values.get("updated", UNKNOWN)
        last_contacted = row.values.get("last_time_contacted", row.values.get("contacts_last_contacted", UNKNOWN))
        upd_ts = convert(updated, TimestampFormat.UNIX_MS, ctx.now) if updated is not UNKNOWN else None
        lc_ts = convert(last_contacted, TimestampFormat.UNIX_MS, ctx.now) if last_contacted is not UNKNOWN else None
        primary_ts = upd_ts if (upd_ts and upd_ts.utc) else lc_ts
        if primary_ts is not None:
            primary_ts = primary_ts.model_copy(
                update={"note": "contact_last_updated_timestamp" if primary_ts is upd_ts else "last_time_contacted"}
            )
        if primary_ts is not None and primary_ts.utc is None:
            primary_ts = None

        deleted = r.bool("deleted")
        values = {
            "contact_id": r.int("contact_id") if r.has("contact_id") else r.int("id"),
            "raw_contact_id": r.int("id"),
            "display_name": display,
            "given_name": row.values.get("given_name", UNKNOWN),
            "family_name": row.values.get("family_name", UNKNOWN),
            "phones": phones,
            "emails": emails,
            "organization": row.values.get("organization", UNKNOWN),
            "account_name": row.values.get("account_name", UNKNOWN),
            "account_type": row.values.get("account_type", UNKNOWN),
            "starred": r.bool("starred"),
            "times_contacted": r.int("times_contacted"),
            "last_time_contacted_utc": lc_ts.utc if lc_ts else UNKNOWN,
            "last_updated_utc": upd_ts.utc if upd_ts else UNKNOWN,
        }
        name = display if isinstance(display, str) and display else "(no display name)"
        flag = " [flagged deleted by Android, still present in database]" if deleted is True else ""
        num = f" — {phones[0].number}" if phones else ""
        summary = f"Contact {name}{num}{flag}"
        return Contact.build(
            values,
            timestamp=primary_ts,
            summary=summary,
            phone_key=phones[0].phone_key if phones else None,
            marked_deleted=deleted is True,
            **build_envelope(ctx, match, row, self, r.flags),
        )
