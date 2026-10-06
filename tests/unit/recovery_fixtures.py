"""Android-shaped databases with deletions, for the recovery -> artifact tests (Phase 5 onward).

Each builder writes a database with ``secure_delete`` off (as Android does), deletes some rows and returns the rows that
existed *before* the deletion, so a test can compare what recovery returns with what was really there.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from android_forensics.artifacts.recovered import DatabaseContext, reconstruct, record_from_row
from android_forensics.models import Artifact, RecoveredRecord
from android_forensics.sqlite.recover_db import RecoveryReport, recover_database

NOW = datetime(2026, 1, 1, tzinfo=UTC)
MS = 1709280000000  # 2024-03-01T08:00:00Z in Unix milliseconds
WEBKIT = (1709280000 + 11_644_473_600) * 1_000_000  # the same instant as Chromium stores it

SMS_DDL = """CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, person INTEGER, date INTEGER,
    date_sent INTEGER DEFAULT 0, protocol INTEGER, read INTEGER DEFAULT 0, status INTEGER DEFAULT -1,
    type INTEGER, reply_path_present INTEGER, subject TEXT, body TEXT, service_center TEXT,
    locked INTEGER DEFAULT 0, sub_id INTEGER DEFAULT -1, error_code INTEGER DEFAULT 0, creator TEXT, seen INTEGER DEFAULT 0)"""
CALLS_DDL = """CREATE TABLE calls (_id INTEGER PRIMARY KEY AUTOINCREMENT, number TEXT, presentation INTEGER NOT NULL DEFAULT 1,
    date INTEGER, duration INTEGER, type INTEGER, new INTEGER, name TEXT, numbertype INTEGER, numberlabel TEXT,
    countryiso TEXT, voicemail_uri TEXT, is_read INTEGER, geocoded_location TEXT, lookup_uri TEXT,
    matched_number TEXT, normalized_number TEXT, subscription_id TEXT, subscription_component_name TEXT,
    phone_account_address TEXT, phone_account_id TEXT)"""
CHROME_DDL = """
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
    visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
    last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER,
    transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER, visit_duration INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL, current_path LONGVARCHAR NOT NULL,
    target_path LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL, state INTEGER NOT NULL, end_time INTEGER NOT NULL, referrer VARCHAR NOT NULL,
    tab_url VARCHAR NOT NULL, mime_type VARCHAR(255) NOT NULL);
"""
NOTES_DDL = "CREATE TABLE notes(_id INTEGER PRIMARY KEY, title TEXT, content TEXT, created_at INTEGER, modified_at INTEGER)"


def sms_row(i: int) -> dict:
    return dict(_id=i, thread_id=1 + i % 3, address=f"+1202555{i:04d}", person=0, date=MS + i * 60_000, date_sent=0, protocol=0,
                read=1, status=-1, type=1 + i % 2, reply_path_present=0, subject=None, body=f"message number {i} with some body text",
                service_center="+12025550001", locked=0, sub_id=-1, error_code=0, creator="com.google.android.apps.messaging", seen=1)


def call_row(i: int) -> dict:
    return dict(_id=i, number=f"+1202555{i:04d}", presentation=1, date=MS + i * 90_000, duration=10 + i, type=1 + i % 3, new=0,
                name=f"Contact {i}", numbertype=2, numberlabel=None, countryiso="US", voicemail_uri=None, is_read=1,
                geocoded_location="Washington, DC", lookup_uri=f"content://com.android.contacts/contacts/lookup/{i}r{i}",
                matched_number=f"+1202555{i:04d}", normalized_number=f"+1202555{i:04d}", subscription_id="1",
                subscription_component_name="com.android.phone/com.android.services.telephony.TelephonyConnectionService",
                phone_account_address="+12025550001", phone_account_id="89014103211118510720")


def note_row(i: int) -> dict:
    return dict(_id=i, title=f"Note {i}", content=f"the content of note number {i}, written down for later", created_at=MS + i * 1000,
                modified_at=MS + i * 2000)


def _insert(conn: sqlite3.Connection, table: str, rows: Iterable[dict]) -> None:
    for r in rows:
        conn.execute(f"INSERT INTO {table}({','.join(r)}) VALUES({','.join('?' * len(r))})", list(r.values()))


def _fresh(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm", "-journal"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA secure_delete=OFF")
    return conn


def build_table_db(path: Path, ddl: str, table: str, make_row, count: int, delete_where: str) -> dict[int, dict]:
    """A one-table database of ``count`` rows, then ``DELETE ... WHERE delete_where``. Returns every original row by id."""
    conn = _fresh(path)
    conn.execute(ddl)
    rows = [make_row(i) for i in range(1, count + 1)]
    _insert(conn, table, rows)
    conn.commit()
    conn.execute(f"DELETE FROM {table} WHERE {delete_where}")
    conn.commit()
    conn.close()
    return {r["_id"]: r for r in rows}


def build_chrome_db(path: Path) -> dict:
    """40 urls, 80 visits (visit v -> url 1 + v % 40) and 8 downloads; deletes urls 33-36, every 5th visit and downloads 3-4."""
    conn = _fresh(path)
    conn.executescript(CHROME_DDL)
    urls = {i: dict(id=i, url=f"https://site{i}.example.com/page/{i}", title=f"Site {i} title", visit_count=2, typed_count=0,
                    last_visit_time=WEBKIT + i * 1_000_000, hidden=0) for i in range(1, 41)}
    visits = {v: dict(id=v, url=1 + v % 40, visit_time=WEBKIT + v * 500_000, from_visit=0, transition=1, segment_id=None,
                      visit_duration=v * 1_000_000) for v in range(1, 81)}
    downloads = {d: dict(id=d, guid=f"guid-{d:04d}", current_path=f"/sdcard/Download/f{d}.pdf", target_path=f"/sdcard/Download/f{d}.pdf",
                         start_time=WEBKIT + d * 1_000_000, received_bytes=1000 * d, total_bytes=1000 * d, state=1,
                         end_time=WEBKIT + d * 1_000_000 + 5000, referrer="https://docs.example.com/",
                         tab_url="https://docs.example.com/d/x", mime_type="application/pdf") for d in range(1, 9)}
    _insert(conn, "urls", urls.values())
    _insert(conn, "visits", visits.values())
    _insert(conn, "downloads", downloads.values())
    conn.commit()
    conn.execute("DELETE FROM urls WHERE id IN (33,34,35,36)")
    conn.execute("DELETE FROM visits WHERE id % 5 = 0")
    conn.execute("DELETE FROM downloads WHERE id IN (3,4)")
    conn.commit()
    conn.close()
    return {"urls": urls, "visits": visits, "downloads": downloads}


def active_urls(path: Path) -> dict:
    """The urls table as it stands now (read-only), keyed by id: what the reconstruct stage uses to resolve a visit's URL."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {r[0]: (r[1], r[2]) for r in conn.execute("SELECT id, url, title FROM urls")}
    finally:
        conn.close()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(path: Path, application: str | None = None, urls=None, file_id: int = 1) -> tuple[RecoveryReport, DatabaseContext, list[RecoveredRecord]]:
    """Recover ``path`` and stage the rows as records (main file only)."""
    report = recover_database(path)
    sha = sha256_of(path)
    dc = DatabaseContext.from_report(report, database_file_id=file_id, database_sha256=sha, application=application, now=NOW, urls=urls)
    records = [record_from_row(r, database_file_id=file_id, source_file_id=file_id, source_sha256=sha) for r in report.rows]
    return report, dc, records


def artifacts(path: Path, table: str | None = None, application: str | None = None, urls=None) -> list[Artifact]:
    _, dc, records = stage(path, application, urls)
    return [reconstruct(r, dc) for r in records if table is None or r.table == table]
