"""Browser parser: Chromium ``History`` (Chrome / Chromium-based Android browsers) and a flat legacy table.

Chromium stores times as microseconds since 1601-01-01 UTC (WebKit epoch).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from android_forensics.artifacts.base import ArtifactParser, DbContext, FieldReader, RowSource, build_envelope
from android_forensics.artifacts.registry import register
from android_forensics.artifacts.schema_probe import FieldSpec, RoleMatch, SchemaMatch, best_matches
from android_forensics.artifacts.timestamps import convert
from android_forensics.models import (
    UNKNOWN,
    BrowserDownload,
    BrowserHistoryEntry,
    DownloadState,
    PageTransition,
    TimestampFormat,
    TransitionQualifier,
)
from android_forensics.sqlite.reader import SchemaObject, SQLiteSession

URLS = [
    FieldSpec("id", ("id",), True, 1.0),
    FieldSpec("url", ("url",), True, 2.0),
    FieldSpec("title", ("title",), False, 1.0),
    FieldSpec("visit_count", ("visit_count",), False, 1.0),
    FieldSpec("typed_count", ("typed_count",), False, 0.5),
    FieldSpec("last_visit_time", ("last_visit_time",), False, 1.5),
    FieldSpec("hidden", ("hidden",), False, 0.25),
]
VISITS = [
    FieldSpec("id", ("id",), False, 0.5),
    FieldSpec("url", ("url", "url_id"), True, 2.0),
    FieldSpec("visit_time", ("visit_time",), True, 2.0),
    FieldSpec("from_visit", ("from_visit",), False, 0.5),
    FieldSpec("transition", ("transition",), False, 1.5),
    FieldSpec("visit_duration", ("visit_duration",), False, 0.75),
    FieldSpec("segment_id", ("segment_id",), False, 0.25),
]
DOWNLOADS = [
    FieldSpec("id", ("id",), False, 0.5),
    FieldSpec("target_path", ("target_path", "full_path"), True, 2.0),
    FieldSpec("start_time", ("start_time",), True, 2.0),
    FieldSpec("current_path", ("current_path",), False, 1.0),
    FieldSpec("received_bytes", ("received_bytes",), False, 1.0),
    FieldSpec("total_bytes", ("total_bytes",), False, 1.0),
    FieldSpec("state", ("state",), False, 1.0),
    FieldSpec("end_time", ("end_time",), False, 1.0),
    FieldSpec("tab_url", ("tab_url",), False, 1.0),
    FieldSpec("referrer", ("referrer",), False, 0.75),
    FieldSpec("mime_type", ("mime_type",), False, 0.75),
]
STOCK = [
    FieldSpec("url", ("url",), True, 2.0),
    FieldSpec("date", ("date", "created", "last_visit_time", "visit_time"), True, 2.0),
    FieldSpec("title", ("title",), False, 1.0),
    FieldSpec("visits", ("visits", "visit_count"), False, 1.0),
    FieldSpec("id", ("_id", "id"), False, 0.5),
]

def decode_transition(code: int) -> tuple[PageTransition, list[TransitionQualifier]]:
    """Split a Chromium transition value into its core type and qualifier flags."""
    return PageTransition.from_code(code), TransitionQualifier.from_flags(code)


def _role(tables: list[SchemaObject], specs: list[FieldSpec], hints: tuple[str, ...], exclude: set[str] = frozenset()) -> RoleMatch | None:
    cands, _ = best_matches([t for t in tables if t.name not in exclude], specs, hints)
    if not cands:
        return None
    m = cands[0]
    return RoleMatch(m.table, m.column_map, m.score, m.missing_optional)


@register
class BrowserParser(ArtifactParser):
    name = "browser"
    version = "1.0"

    def identify(self, tables: list[SchemaObject], ctx: DbContext) -> list[SchemaMatch]:
        urls = _role(tables, URLS, ("urls",))
        visits = _role(tables, VISITS, ("visits",), exclude={urls.table} if urls else set())
        downloads = _role(tables, DOWNLOADS, ("downloads",))
        roles: dict[str, RoleMatch] = {}
        if urls and visits:
            roles["urls"], roles["visits"] = urls, visits
        if downloads:
            roles["downloads"] = downloads
        if roles:
            score = round(sum(r.score for r in roles.values()) / len(roles), 3)
            return [SchemaMatch(self.name, "chromium_history", roles, score)]
        cands, _ = best_matches(tables, STOCK, ("history", "browser_history"))
        return [
            SchemaMatch(self.name, "legacy_flat_history", {"main": RoleMatch(m.table, m.column_map, m.score, m.missing_optional)}, m.score)
            for m in cands
            if m.name_hint
        ]

    def extract(self, session: SQLiteSession, match: SchemaMatch, ctx: DbContext) -> Iterator[BrowserHistoryEntry | BrowserDownload]:
        if match.variant == "legacy_flat_history":
            for row in self.rows(session, ctx, match.roles["main"]):
                v = dict(row.values, _kind="legacy")
                art = self.from_row(RowSource(v, row.raw, row.table, row.rowid), match, ctx)
                if art:
                    yield art
            return

        urls: dict[Any, RowSource] = {}
        if "urls" in match.roles:
            for row in self.rows(session, ctx, match.roles["urls"]):
                urls[row.values.get("id")] = row
        seen: set[Any] = set()
        if "visits" in match.roles:
            for vrow in self.rows(session, ctx, match.roles["visits"]):
                uid = vrow.values.get("url")
                u = urls.get(uid)
                v: dict[str, Any] = dict(vrow.values, _kind="visit", url_id=uid)
                v["url"] = u.values.get("url") if u else UNKNOWN
                for k in ("title", "visit_count", "typed_count", "hidden"):
                    v[k] = u.values.get(k, UNKNOWN) if u else UNKNOWN
                v["_dangling"] = u is None
                raw = {"visits": dict(vrow.raw), "urls": dict(u.raw) if u else None}
                art = self.from_row(RowSource(v, raw, vrow.table, vrow.rowid), match, ctx)
                seen.add(uid)
                if art:
                    yield art
            for uid, u in urls.items():
                if uid in seen:
                    continue
                v = dict(u.values, _kind="url", url_id=uid)
                art = self.from_row(RowSource(v, {"urls": dict(u.raw)}, u.table, u.rowid), match, ctx)
                if art:
                    yield art
        if "downloads" in match.roles:
            for row in self.rows(session, ctx, match.roles["downloads"]):
                art = self.from_row(RowSource(dict(row.values, _kind="download"), row.raw, row.table, row.rowid), match, ctx)
                if art:
                    yield art

    def from_row(self, row: RowSource, match: SchemaMatch, ctx: DbContext) -> BrowserHistoryEntry | BrowserDownload | None:
        kind = row.values.get("_kind")
        r = FieldReader(row)
        env = build_envelope(ctx, match, row, self, r.flags)
        if kind == "download":
            return self._download(r, row, ctx, env)
        return self._visit(r, row, ctx, env, kind)

    def _visit(self, r: FieldReader, row: RowSource, ctx: DbContext, env: dict, kind: str | None) -> BrowserHistoryEntry:
        url = r.text("url")
        title = r.text("title")
        transition: object = UNKNOWN
        transition_code: object = UNKNOWN
        qualifiers: list[TransitionQualifier] = []
        if kind == "visit":
            ts = convert(r.raw("visit_time"), TimestampFormat.WEBKIT_US, ctx.now) if r.has("visit_time") else None
            code = r.int("transition")
            transition_code = code
            if isinstance(code, int):
                transition, qualifiers = decode_transition(code)
            elif code is None:
                transition = None
            if row.values.get("_dangling"):
                r.flags.append("dangling_url_reference: visit points to a url id absent from the urls table")
        elif kind == "url":
            ts = convert(r.raw("last_visit_time"), TimestampFormat.WEBKIT_US, ctx.now) if r.has("last_visit_time") else None
        else:
            ts = convert(r.raw("date"), TimestampFormat.UNIX_MS, ctx.now) if r.has("date") else None
        if ts is not None and ts.utc is None and ts.note not in ("NULL",):
            r.flags.append(f"timestamp: {ts.note}")
        values = {
            "visit_id": r.int("id") if kind == "visit" else UNKNOWN,
            "url_id": row.values.get("url_id", UNKNOWN),
            "url": url,
            "title": title,
            "visit_count": r.int("visit_count") if kind != "legacy" else r.int("visits"),
            "typed_count": r.int("typed_count"),
            "transition": transition,
            "transition_code": transition_code,
            "transition_qualifiers": qualifiers,
            "visit_duration_us": r.int("visit_duration"),
            "from_visit": r.int("from_visit"),
            "hidden": r.bool("hidden"),
            "url_level_only": kind in ("url", "legacy"),
        }
        shown = title if isinstance(title, str) and title else (url if isinstance(url, str) else "unknown URL")
        prefix = "Last visit to" if kind in ("url", "legacy") else "Visited"
        return BrowserHistoryEntry.build(values, timestamp=ts, summary=f"{prefix} {shown}", **{**env, "flags": r.flags})

    def _download(self, r: FieldReader, row: RowSource, ctx: DbContext, env: dict) -> BrowserDownload:
        state_code = r.int("state")
        state: object = UNKNOWN
        if state_code is not UNKNOWN:
            state = DownloadState.from_code(state_code)
        ts = convert(r.raw("start_time"), TimestampFormat.WEBKIT_US, ctx.now) if r.has("start_time") else None
        end = convert(r.raw("end_time"), TimestampFormat.WEBKIT_US, ctx.now) if r.has("end_time") else None
        if ts is not None and ts.utc is None and ts.note != "NULL":
            r.flags.append(f"timestamp: {ts.note}")
        target = r.text("target_path")
        values = {
            "download_id": r.int("id"),
            "target_path": target,
            "current_path": r.text("current_path"),
            "tab_url": r.text("tab_url"),
            "referrer": r.text("referrer"),
            "mime_type": r.text("mime_type"),
            "received_bytes": r.int("received_bytes"),
            "total_bytes": r.int("total_bytes"),
            "download_state": state,
            "download_state_code": state_code,
            "end_time_utc": end.utc if end else UNKNOWN,
        }
        name = target.rsplit("/", 1)[-1] if isinstance(target, str) else "unknown file"
        size = f" ({values['total_bytes']} bytes)" if isinstance(values["total_bytes"], int) else ""
        return BrowserDownload.build(values, timestamp=ts, summary=f"Downloaded {name}{size}", **{**env, "flags": r.flags})
