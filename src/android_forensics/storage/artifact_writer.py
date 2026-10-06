"""Persist artifacts: the model's own flat record into ``artifacts`` plus a typed projection table per artifact type."""

from __future__ import annotations

import json
from collections.abc import Iterable

from android_forensics.models import (
    Artifact,
    BrowserDownload,
    BrowserHistoryEntry,
    CallRecord,
    Contact,
    SMSMessage,
)
from android_forensics.storage.case_store import CaseStore, utcnow


def _b(v: object) -> int | None:
    return None if v is None else int(bool(v))


def _typed_insert(store: CaseStore, art: Artifact, aid: int) -> None:
    if isinstance(art, SMSMessage):
        store.conn.execute(
            "INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, art.address, art.address_kind, art.body, art.direction, art.type_code, _b(art.read),
             art.thread_id, art.date_sent_utc, art.service_center, art.subscription_id, art.phone_key),
        )
    elif isinstance(art, CallRecord):
        store.conn.execute(
            "INSERT INTO calls VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (aid, art.number, art.call_type, art.type_code, art.duration_seconds, art.presentation,
             art.cached_name, art.lookup_uri, art.subscription_id, art.phone_account_address, art.phone_key),
        )
    elif isinstance(art, Contact):
        store.conn.execute(
            "INSERT INTO contacts VALUES(?,?,?,?,?,?,?,?,?)",
            (aid, art.contact_id, art.display_name, json.dumps([p.model_dump(mode="json") for p in art.phones]),
             json.dumps([e.model_dump(mode="json") for e in art.emails]), art.account_name, art.account_type,
             art.last_updated_utc, _b(art.marked_deleted)),
        )
    elif isinstance(art, BrowserHistoryEntry):
        store.conn.execute(
            "INSERT INTO browser_history VALUES(?,?,?,?,?,?,?,?,?)",
            (aid, "url" if art.url_level_only else "visit", art.url, art.title, art.visit_count, art.transition,
             None, None, None),
        )
    elif isinstance(art, BrowserDownload):
        store.conn.execute(
            "INSERT INTO browser_history VALUES(?,?,?,?,?,?,?,?,?)",
            (aid, "download", art.tab_url, None, None, None, art.target_path, art.total_bytes, art.download_state),
        )


def insert_artifacts_with_ids(store: CaseStore, run_id: int, database_id: int | None, artifacts: Iterable[Artifact]) -> list[int]:
    """Store ``artifacts`` and return their row ids, in order (the reconstruct stage links recovered records to them)."""
    ids: list[int] = []
    now = utcnow()
    with store.transaction():
        for a in artifacts:
            record = a.to_record()
            record["created_at"] = record["created_at"] or now
            record["run_id"] = run_id
            record["database_id"] = database_id
            aid = store.insert("artifacts", record)
            _typed_insert(store, a, aid)
            ids.append(aid)
    return ids


def insert_artifacts(store: CaseStore, run_id: int, database_id: int | None, artifacts: Iterable[Artifact]) -> int:
    return len(insert_artifacts_with_ids(store, run_id, database_id, artifacts))
