"""Deterministic synthetic Android evidence generator with ground truth.

Every number the tool is later evaluated against comes from here, not from the tool. Databases
follow the real AOSP / Chromium schemas (subset of columns) so parsers are exercised on realistic
structures. Nothing is random without a seed: the same ``SynthSpec`` yields the same logical data.

Review 2 extends this with controlled deletions and overwrites; the ``ground_truth`` structure
already records the *active* record set per database for that purpose.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import sqlite3
import tarfile
import time
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from android_forensics.lab.journal import build_hot_journal
from android_forensics.sqlite.records import encode_record, encode_table_leaf_cell

WEBKIT_EPOCH_OFFSET_S = 11_644_473_600
BASE = datetime(2024, 3, 1, 8, 0, 0, tzinfo=UTC)
BASE_MS = int(BASE.timestamp() * 1000)

TELEPHONY = "data/data/com.android.providers.telephony/databases"
CONTACTS = "data/data/com.android.providers.contacts/databases"
CHROME = "data/data/com.android.chrome/app_chrome/Default"
NOTES = "data/data/com.example.notes"

FIRST = ["Aarav", "Meera", "Rohan", "Isha", "Kabir", "Nisha", "Vikram", "Anaya", "Dev", "Tara", "Arjun", "Zoya",
         "Karan", "Priya", "Neel", "Sara", "Ravi", "Diya", "Omar", "Leela", "Sameer", "Riya", "Farhan", "Kiara",
         "Yash", "Mira", "Imran", "Anika", "Rahul", "Sneha"]
LAST = ["Sharma", "Iyer", "Khan", "Patel", "Nair", "Reddy", "Gupta", "Menon", "Das", "Bose", "Shah", "Rao", "Jain",
        "Kapoor", "Mehta", "Pillai", "Joshi", "Verma", "Singh", "Kulkarni"]
SMS_TEMPLATES = [
    "Are we still meeting at {h}:00 today?", "Running late, reach by {h}:30", "Please send the report by tonight",
    "Happy birthday! Have a great year ahead", "Your OTP is {otp}. Do not share it with anyone.",
    "Can you call me when you are free?", "Dinner at my place on Saturday?", "Payment of Rs {amt} received. Thank you.",
    "Package out for delivery, arriving between {h}:00 and {h2}:00", "Lecture notes uploaded to the shared drive",
    "Good night :)", "Where did you park?", "Reminder: appointment tomorrow at {h}:15", "Thanks a lot!",
    "Meeting moved to room {room}", "Bring the documents tomorrow", "Ok", "Let's catch up this weekend 🙂",
    "Bank alert: Rs {amt} debited from account XX{otp4}", "Call me back asap",
]
SHORTCODES = ["72000", "56161", "AX-BANKOS", "VM-ALERTS", "JD-DELIVR"]
SITES = [
    ("https://www.wikipedia.org/", "Wikipedia"), ("https://news.example.org/world", "World News"),
    ("https://mail.example.com/inbox", "Inbox"), ("https://maps.example.net/", "Maps"),
    ("https://shop.example.com/cart", "Shopping Cart"), ("https://university.example.edu/portal", "Student Portal"),
    ("https://weather.example.org/city", "Weather"), ("https://video.example.com/watch?v=abc123", "Video"),
    ("https://forum.example.net/thread/4412", "Forum Thread"), ("https://docs.example.com/d/xyz", "Shared Doc"),
]


@dataclass
class SynthSpec:
    seed: int = 1337
    sms_count: int = 120
    call_count: int = 60
    call_wal_rows: int = 20
    contact_count: int = 30
    contacts_marked_deleted: int = 3
    browser_urls: int = 40
    browser_visits: int = 150
    downloads: int = 5
    notes_count: int = 15
    with_deletions: bool = False  # Phase 13: genuinely delete rows from mmssms.db and History, with physical ground truth
    sms_delete_count: int = 12
    browser_delete_urls: int = 3
    browser_delete_visits: int = 15
    downloads_delete: int = 1


def _pn(i: int) -> str:
    return f"+1202555{100 + i:04d}"


def _fmt_pn(n: str) -> str:
    d = n[-10:]
    return f"({d[:3]}) {d[3:6]}-{d[6:]}"


def _webkit_us(unix_ms: int) -> int:
    return (unix_ms // 1000 + WEBKIT_EPOCH_OFFSET_S) * 1_000_000 + (unix_ms % 1000) * 1000


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    for name in ("LOCALIZED", "PHONEBOOK", "UNICODE"):
        conn.create_collation(name, lambda a, b: (a > b) - (a < b))
    return conn


def _build_sms(root: Path, spec: SynthSpec, rng: random.Random, people: list[dict]) -> list[dict]:
    conn = _connect(root / TELEPHONY / "mmssms.db")
    conn.executescript(
        """
        CREATE TABLE android_metadata (locale TEXT);
        INSERT INTO android_metadata VALUES('en_US');
        CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, person INTEGER, date INTEGER,
            date_sent INTEGER DEFAULT 0, protocol INTEGER, read INTEGER DEFAULT 0, status INTEGER DEFAULT -1,
            type INTEGER, reply_path_present INTEGER, subject TEXT, body TEXT, service_center TEXT,
            locked INTEGER DEFAULT 0, sub_id INTEGER DEFAULT -1, error_code INTEGER DEFAULT 0, creator TEXT,
            seen INTEGER DEFAULT 0);
        CREATE TABLE threads (_id INTEGER PRIMARY KEY AUTOINCREMENT, date INTEGER DEFAULT 0,
            message_count INTEGER DEFAULT 0, recipient_ids TEXT, snippet TEXT, read INTEGER DEFAULT 1);
        """
    )
    threads: dict[str, int] = {}
    truth: list[dict] = []
    for i in range(1, spec.sms_count + 1):
        if rng.random() < 0.15:
            address = rng.choice(SHORTCODES)
            mtype = 1
        else:
            person = rng.choice(people)
            address = person["number"]
            mtype = rng.choice([1, 1, 2, 2, 2])
        if i in (17, 58):
            mtype, address = 3, None  # type: ignore[assignment]
        body = rng.choice(SMS_TEMPLATES).format(
            h=rng.randint(1, 12), h2=rng.randint(1, 12), otp=rng.randint(100000, 999999), amt=rng.randint(50, 9000),
            room=rng.randint(100, 499), otp4=rng.randint(1000, 9999),
        )
        if i == 33:
            body = ""
        date = BASE_MS + rng.randint(0, 90 * 24 * 3600) * 1000 + rng.randint(0, 999)
        date_sent = date - rng.randint(1, 4000) if mtype == 1 else 0
        thread = threads.setdefault(address or "draft", len(threads) + 1)
        row = {
            "_id": i, "thread_id": thread, "address": address, "person": 0, "date": date, "date_sent": date_sent,
            "protocol": 0, "read": 1 if (mtype != 1 or rng.random() < 0.8) else 0, "status": -1, "type": mtype,
            "reply_path_present": 0, "subject": None, "body": body,
            "service_center": "+12025550001" if mtype == 1 else None, "locked": 0,
            "sub_id": 1 if rng.random() < 0.5 else -1, "error_code": 0, "creator": "com.google.android.apps.messaging",
            "seen": 1,
        }
        conn.execute(f"INSERT INTO sms({','.join(row)}) VALUES({','.join('?' * len(row))})", list(row.values()))
        truth.append(row)
    for addr, tid in threads.items():
        conn.execute("INSERT INTO threads(_id, message_count, recipient_ids) VALUES(?,?,?)", (tid, 0, addr))
    conn.commit()
    conn.close()
    return truth


def _build_calls(root: Path, spec: SynthSpec, rng: random.Random, people: list[dict]) -> list[dict]:
    dbdir = root / CONTACTS
    dbdir.mkdir(parents=True, exist_ok=True)
    live = _connect(dbdir / "calllog.db")
    live.execute("PRAGMA journal_mode=WAL")
    live.execute("PRAGMA wal_autocheckpoint=0")
    live.executescript(
        """
        CREATE TABLE android_metadata (locale TEXT);
        CREATE TABLE calls (_id INTEGER PRIMARY KEY AUTOINCREMENT, number TEXT, presentation INTEGER NOT NULL DEFAULT 1,
            date INTEGER, duration INTEGER, type INTEGER, new INTEGER, name TEXT, numbertype INTEGER, numberlabel TEXT,
            countryiso TEXT, voicemail_uri TEXT, is_read INTEGER, geocoded_location TEXT, lookup_uri TEXT,
            matched_number TEXT, normalized_number TEXT, subscription_id TEXT, subscription_component_name TEXT,
            phone_account_address TEXT, phone_account_id TEXT);
        """
    )
    truth: list[dict] = []
    total = spec.call_count
    for i in range(1, total + 1):
        person = rng.choice(people)
        ctype = rng.choice([1, 1, 2, 2, 3, 5])
        duration = 0 if ctype in (3, 5) else rng.randint(4, 1800)
        cached = person["name"] if rng.random() < 0.85 else None
        if i == 7:
            person = {"number": "", "name": None}
            cached = None
        row = {
            "number": person["number"], "presentation": 1 if person["number"] else 2,
            "date": BASE_MS + rng.randint(0, 90 * 24 * 3600) * 1000 + rng.randint(0, 999), "duration": duration,
            "type": ctype, "new": 0, "name": cached, "numbertype": 2 if cached else None, "numberlabel": None,
            "countryiso": "US", "voicemail_uri": None, "is_read": 1, "geocoded_location": "Washington, DC",
            "lookup_uri": f"content://com.android.contacts/contacts/lookup/{i}r{i}" if cached else None,
            "matched_number": person["number"], "normalized_number": person["number"], "subscription_id": "1",
            "subscription_component_name": "com.android.phone/com.android.services.telephony.TelephonyConnectionService",
            "phone_account_address": "+12025550001", "phone_account_id": "89014103211118510720",
        }
        cols = list(row)
        live.execute(f"INSERT INTO calls({','.join(cols)}) VALUES({','.join('?' * len(cols))})", list(row.values()))
        truth.append({"_id": i, **row})
        if i == total - spec.call_wal_rows:
            live.commit()
            live.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    live.commit()
    for suffix in ("", "-wal", "-shm"):
        src = dbdir / f"calllog.db{suffix}"
        if src.exists():
            shutil.copyfile(src, dbdir / f"calllog.snap{suffix}")
    live.close()
    for suffix in ("", "-wal", "-shm"):
        p = dbdir / f"calllog.db{suffix}"
        if p.exists():
            p.unlink()
        snap = dbdir / f"calllog.snap{suffix}"
        if snap.exists():
            snap.rename(dbdir / f"calllog.db{suffix}")
    return truth


def _build_contacts(root: Path, spec: SynthSpec, rng: random.Random, people: list[dict]) -> list[dict]:
    conn = _connect(root / CONTACTS / "contacts2.db")
    conn.executescript(
        """
        CREATE TABLE android_metadata (locale TEXT);
        CREATE TABLE accounts (_id INTEGER PRIMARY KEY AUTOINCREMENT, account_name TEXT, account_type TEXT, data_set TEXT);
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY AUTOINCREMENT, mimetype TEXT NOT NULL);
        CREATE TABLE contacts (_id INTEGER PRIMARY KEY AUTOINCREMENT, name_raw_contact_id INTEGER,
            times_contacted INTEGER DEFAULT 0, last_time_contacted INTEGER, starred INTEGER DEFAULT 0,
            has_phone_number INTEGER DEFAULT 0, lookup TEXT, contact_last_updated_timestamp INTEGER);
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER, contact_id INTEGER,
            display_name TEXT COLLATE PHONEBOOK, deleted INTEGER NOT NULL DEFAULT 0, starred INTEGER DEFAULT 0,
            times_contacted INTEGER DEFAULT 0, last_time_contacted INTEGER, version INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE data (_id INTEGER PRIMARY KEY AUTOINCREMENT, mimetype_id INTEGER, raw_contact_id INTEGER,
            is_primary INTEGER DEFAULT 0, data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT, data5 TEXT, data6 TEXT);
        CREATE INDEX raw_contacts_name ON raw_contacts(display_name COLLATE PHONEBOOK);
        INSERT INTO accounts(account_name, account_type) VALUES('owner@example.com','com.google');
        INSERT INTO mimetypes(mimetype) VALUES('vnd.android.cursor.item/email_v2'),('vnd.android.cursor.item/phone_v2'),
            ('vnd.android.cursor.item/name'),('vnd.android.cursor.item/organization');
        """
    )
    truth: list[dict] = []
    deleted_ids = set(range(spec.contact_count - spec.contacts_marked_deleted + 1, spec.contact_count + 1))
    for p in people[: spec.contact_count]:
        cid = p["idx"] + 1
        deleted = 1 if cid in deleted_ids else 0
        updated = BASE_MS + rng.randint(0, 60 * 24 * 3600) * 1000
        last_contacted = BASE_MS + rng.randint(0, 80 * 24 * 3600) * 1000 if rng.random() < 0.7 else None
        conn.execute(
            "INSERT INTO contacts(_id,name_raw_contact_id,times_contacted,last_time_contacted,starred,has_phone_number,lookup,"
            "contact_last_updated_timestamp) VALUES(?,?,?,?,?,1,?,?)",
            (cid, cid, rng.randint(0, 30), last_contacted, int(rng.random() < 0.15), f"{cid}r{cid}", updated),
        )
        conn.execute(
            "INSERT INTO raw_contacts(_id,account_id,contact_id,display_name,deleted,times_contacted,last_time_contacted)"
            " VALUES(?,?,?,?,?,?,?)",
            (cid, 1, cid, p["name"], deleted, 0, last_contacted),
        )
        given, family = p["name"].split(" ", 1)
        conn.execute("INSERT INTO data(mimetype_id,raw_contact_id,is_primary,data1,data2,data3) VALUES(3,?,1,?,?,?)",
                     (cid, p["name"], given, family))
        conn.execute("INSERT INTO data(mimetype_id,raw_contact_id,is_primary,data1,data2) VALUES(2,?,1,?,?)",
                     (cid, _fmt_pn(p["number"]), "2"))
        emails = []
        if rng.random() < 0.6:
            email = f"{given.lower()}.{family.lower()}@example.com"
            conn.execute("INSERT INTO data(mimetype_id,raw_contact_id,is_primary,data1,data2) VALUES(1,?,0,?,?)", (cid, email, "1"))
            emails.append(email)
        truth.append({
            "contact_id": cid, "display_name": p["name"], "phone_display": _fmt_pn(p["number"]), "phone_key_source": p["number"],
            "emails": emails, "deleted_flag": deleted, "contact_last_updated_timestamp": updated,
        })
    conn.commit()
    conn.close()
    return truth


def _build_chrome(root: Path, spec: SynthSpec, rng: random.Random) -> dict[str, list[dict]]:
    conn = _connect(root / CHROME / "History")
    conn.executescript(
        """
        CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
        INSERT INTO meta VALUES('version','52');
        CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
            visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER,
            transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER, visit_duration INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL, current_path LONGVARCHAR NOT NULL,
            target_path LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL, state INTEGER NOT NULL, end_time INTEGER NOT NULL, referrer VARCHAR NOT NULL,
            tab_url VARCHAR NOT NULL, mime_type VARCHAR(255) NOT NULL);
        CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL, term LONGVARCHAR NOT NULL,
            normalized_term LONGVARCHAR NOT NULL);
        """
    )
    urls: list[dict] = []
    for i in range(1, spec.browser_urls + 1):
        base_url, title = SITES[(i - 1) % len(SITES)]
        url = f"{base_url}?p={i}" if i > len(SITES) else base_url
        urls.append({"id": i, "url": url, "title": f"{title} #{i}" if i > len(SITES) else title, "visit_count": 0, "last": 0})
    visits: list[dict] = []
    orphan_ids = {spec.browser_urls - 1, spec.browser_urls}
    for v in range(1, spec.browser_visits + 1):
        u = rng.choice([x for x in urls if x["id"] not in orphan_ids])
        ts_ms = BASE_MS + rng.randint(0, 90 * 24 * 3600) * 1000 + rng.randint(0, 999)
        transition = rng.choice([0, 1, 8, 1 | 0x02000000, 5 | 0x10000000 | 0x20000000])
        visits.append({"id": v, "url": u["id"], "visit_time_ms": ts_ms, "visit_time": _webkit_us(ts_ms),
                       "transition": transition, "visit_duration": rng.randint(0, 900) * 1_000_000})
        u["visit_count"] += 1
        u["last"] = max(u["last"], _webkit_us(ts_ms))
    for u in urls:
        if u["id"] in orphan_ids:
            u["visit_count"], u["last"] = 1, _webkit_us(BASE_MS + rng.randint(0, 90 * 24 * 3600) * 1000)
        conn.execute("INSERT INTO urls(id,url,title,visit_count,typed_count,last_visit_time) VALUES(?,?,?,?,?,?)",
                     (u["id"], u["url"], u["title"], u["visit_count"], 0, u["last"]))
    for v in visits:
        conn.execute("INSERT INTO visits(id,url,visit_time,from_visit,transition,visit_duration) VALUES(?,?,?,?,?,?)",
                     (v["id"], v["url"], v["visit_time"], 0, v["transition"], v["visit_duration"]))
    downloads: list[dict] = []
    for d in range(1, spec.downloads + 1):
        start = BASE_MS + rng.randint(0, 80 * 24 * 3600) * 1000
        row = {"id": d, "guid": f"00000000-0000-4000-8000-{d:012d}", "current_path": f"/storage/emulated/0/Download/file{d}.pdf",
               "target_path": f"/storage/emulated/0/Download/file{d}.pdf", "start_time": _webkit_us(start),
               "received_bytes": 10_000 * d, "total_bytes": 10_000 * d, "state": 1, "end_time": _webkit_us(start + 5000),
               "referrer": "https://docs.example.com/", "tab_url": "https://docs.example.com/d/xyz",
               "mime_type": "application/pdf", "start_ms": start}
        conn.execute("INSERT INTO downloads(id,guid,current_path,target_path,start_time,received_bytes,total_bytes,state,"
                     "end_time,referrer,tab_url,mime_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                     tuple(row[k] for k in ("id", "guid", "current_path", "target_path", "start_time", "received_bytes",
                                            "total_bytes", "state", "end_time", "referrer", "tab_url", "mime_type")))
        downloads.append(row)
    conn.commit()
    conn.close()
    visited = {v["url"] for v in visits}
    url_only = sorted(u["id"] for u in urls if u["id"] not in visited)  # urls rows with no visit rows -> url-level records
    return {"urls": urls, "visits": visits, "downloads": downloads, "orphan_url_ids": url_only}


def _build_notes(root: Path, spec: SynthSpec, rng: random.Random) -> list[dict]:
    dbdir = root / NOTES / "databases"
    conn = _connect(dbdir / "notes.db")
    conn.executescript(
        "CREATE TABLE notes(_id INTEGER PRIMARY KEY, title TEXT, content TEXT, created_at INTEGER, modified_at INTEGER);"
        "CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);"
        "INSERT INTO settings VALUES('sync','off');"
    )
    truth = []
    for i in range(1, spec.notes_count + 1):
        created = BASE_MS + rng.randint(0, 80 * 24 * 3600) * 1000
        row = (i, f"Note {i}", f"Content of note {i}: " + "lorem ipsum " * rng.randint(1, 6), created, created + 60_000)
        conn.execute("INSERT INTO notes VALUES(?,?,?,?,?)", row)
        truth.append(dict(zip(("_id", "title", "content", "created_at", "modified_at"), row)))
    conn.commit()
    conn.close()
    # Simulate a crash mid-transaction: the database as the interrupted UPDATE left it, plus the rollback journal holding
    # the original of every page it changed — exactly what a phone frozen before COMMIT leaves behind. Built from the
    # journal format (lab/journal.py) so it is identical on every run, whatever else the process has open.
    before, after = dbdir / "pending_before.db", dbdir / "pending_after.db"
    pend = _connect(before)
    pend.executescript("CREATE TABLE queue(a TEXT);")
    pend.executemany("INSERT INTO queue VALUES(?)", [("row%05d-" % i + "p" * 120,) for i in range(4000)])
    pend.commit()
    pend.close()
    shutil.copyfile(before, after)
    pend = _connect(after)
    pend.execute("UPDATE queue SET a = 'X' || a")
    pend.commit()
    pend.close()
    build_hot_journal(before, after, dbdir / "pending.db", dbdir / "pending.db-journal")
    for f in (before, after):
        f.unlink()
    prefs = root / NOTES / "shared_prefs"
    prefs.mkdir(parents=True, exist_ok=True)
    (prefs / "com.example.notes_preferences.xml").write_text(
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
        "  <string name=\"theme\">dark</string>\n  <boolean name=\"first_run\" value=\"false\" />\n"
        "  <string name=\"auth_token\">SYNTHETIC-NOT-A-REAL-TOKEN</string>\n  <long name=\"last_sync\" value=\"1709280000000\" />\n</map>\n"
    )
    return truth


def _build_misc(root: Path, spec: SynthSpec, rng: random.Random) -> None:
    secure = root / "data/data/com.example.secure/databases"
    secure.mkdir(parents=True, exist_ok=True)
    (secure / "vault.db").write_bytes(rng.randbytes(16384))

    corrupt_dir = root / "data/data/com.example.corrupt/databases"
    conn = _connect(corrupt_dir / "broken.db")
    conn.execute("CREATE TABLE log(id INTEGER PRIMARY KEY, msg TEXT)")
    conn.executemany("INSERT INTO log(msg) VALUES(?)", [("entry %d " % i + "x" * 80,) for i in range(400)])
    conn.commit()
    conn.close()
    full = (corrupt_dir / "broken.db").read_bytes()
    (corrupt_dir / "broken.db").write_bytes(full[: int(len(full) * 0.6) // 100 * 100 + 37])

    dcim = root / "sdcard/DCIM/Camera"
    dcim.mkdir(parents=True, exist_ok=True)
    (dcim / "IMG_20240301_101500.jpg").write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + rng.randbytes(2048) + b"\xff\xd9")
    pics = root / "storage/emulated/0/Pictures"
    pics.mkdir(parents=True, exist_ok=True)
    (pics / "screenshot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + rng.randbytes(1024))

    sysdir = root / "data/system"
    (sysdir / "users").mkdir(parents=True, exist_ok=True)
    (sysdir / "users/0.xml").write_text("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<user id=\"0\" serialNumber=\"0\" />\n")
    (sysdir / "packages.xml").write_bytes(b"ABX\x00" + rng.randbytes(256))


def _table_model_from_db(conn: sqlite3.Connection, table: str):
    from android_forensics.sqlite.ddl import parse_create_table
    from android_forensics.sqlite.recovery import TableModel

    sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0]
    return TableModel.from_sql(parse_create_table(sql))


def _delete_rows_and_truth(db_path: Path, table: str, ids: list[int]) -> list[dict[str, Any]]:
    """Delete ``ids`` (rowids) from ``table`` in a plain rollback-journal-mode database, and return **physical** ground
    truth for each: the row re-encoded exactly as SQLite wrote it (``records.encode_table_leaf_cell``), searched for in the
    final file bytes. RECOVERED (the whole cell survives), PARTIAL (only the bytes after the first four -- SQLite's
    freeblock header overwrote the payload size and rowid), or UNRECOVERABLE. The expectation never depends on what any
    recovery algorithm finds; see ``lab/deletions.py`` for the same method applied to the single-table recovery matrix."""
    if not ids:
        return []
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA secure_delete=OFF")
    model = _table_model_from_db(conn, table)
    cols = [c.name for c in model.columns]
    placeholders = ",".join("?" * len(ids))
    originals = {
        row[0]: row[1:]
        for row in conn.execute(f"SELECT rowid, {', '.join(cols)} FROM {table} WHERE rowid IN ({placeholders})", ids)
    }
    conn.execute(f"DELETE FROM {table} WHERE rowid IN ({placeholders})", ids)
    conn.commit()
    conn.close()
    data = db_path.read_bytes()
    truth = []
    for rowid, values in sorted(originals.items()):
        stored = list(values)
        if model.alias_index is not None:
            stored[model.alias_index] = None
        cell = encode_table_leaf_cell(rowid, encode_record(tuple(stored)))
        expected = "RECOVERED" if cell in data else ("PARTIAL" if cell[4:] in data else "UNRECOVERABLE")
        truth.append({"table": table, "rowid": rowid, "expected": expected, "values": dict(zip(cols, values))})
    return truth


def _stamp_mtimes(root: Path) -> None:
    files = sorted(p for p in root.rglob("*") if p.is_file())
    for i, p in enumerate(files):
        ts = BASE.timestamp() + 95 * 24 * 3600 + i * 37
        os.utime(p, (ts, ts))


def _package(root: Path, out_dir: Path) -> None:
    files = sorted(p for p in root.rglob("*") if p.is_file())
    zpath, tpath = out_dir / "acquisition.zip", out_dir / "acquisition.tar.gz"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in files:
            st = p.stat()
            zi = zipfile.ZipInfo(p.relative_to(root).as_posix(), date_time=time.gmtime(st.st_mtime)[:6])
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, p.read_bytes())
    with tarfile.open(tpath, "w:gz") as tf:
        for p in files:
            ti = tarfile.TarInfo(p.relative_to(root).as_posix())
            st = p.stat()
            ti.size, ti.mtime, ti.mode = st.st_size, int(st.st_mtime), 0o644
            with open(p, "rb") as fh:
                tf.addfile(ti, fh)


def generate(out_dir: Path, spec: SynthSpec | None = None, overwrite: bool = True) -> dict[str, Any]:
    """Build the synthetic acquisition under ``out_dir`` and return (and write) its ground truth."""
    spec = spec or SynthSpec()
    out_dir = out_dir.resolve()
    root = out_dir / "android_dump"
    if root.exists():
        if not overwrite:
            raise FileExistsError(root)
        shutil.rmtree(root)
    for stale in ("acquisition.zip", "acquisition.tar.gz", "ground_truth.json"):
        (out_dir / stale).unlink(missing_ok=True)
    root.mkdir(parents=True)
    rng = random.Random(spec.seed)
    people = []
    for i in range(max(spec.contact_count, 12)):
        people.append({"idx": i, "name": f"{FIRST[i % len(FIRST)]} {LAST[(i * 7 + 3) % len(LAST)]}", "number": _pn(i)})

    truth: dict[str, Any] = {
        "spec": asdict(spec),
        "environment": {"sqlite": sqlite3.sqlite_version},
        "files": {},
    }
    truth["files"][f"{TELEPHONY}/mmssms.db"] = {"type": "sms", "active": _build_sms(root, spec, rng, people)}
    truth["files"][f"{CONTACTS}/calllog.db"] = {"type": "call", "active": _build_calls(root, spec, rng, people),
                                              "wal_only_rows": spec.call_wal_rows}
    truth["files"][f"{CONTACTS}/contacts2.db"] = {"type": "contact", "active": _build_contacts(root, spec, rng, people)}
    truth["files"][f"{CHROME}/History"] = {"type": "browser", **_build_chrome(root, spec, rng)}
    truth["files"][f"{NOTES}/databases/notes.db"] = {"type": "generic_app", "active": _build_notes(root, spec, rng)}
    _build_misc(root, spec, rng)

    deleted_sms_count = deleted_visits_count = deleted_downloads_count = 0
    if spec.with_deletions:
        sms_path = root / TELEPHONY / "mmssms.db"
        sms_ids = sorted(rng.sample(range(1, spec.sms_count + 1), min(spec.sms_delete_count, spec.sms_count)))
        deleted_sms = _delete_rows_and_truth(sms_path, "sms", sms_ids)
        truth["files"][f"{TELEPHONY}/mmssms.db"]["deleted"] = deleted_sms
        deleted_sms_count = len(deleted_sms)

        history_path = root / CHROME / "History"
        chrome_truth = truth["files"][f"{CHROME}/History"]
        url_ids = [u["id"] for u in chrome_truth["urls"]]
        visit_ids = [v["id"] for v in chrome_truth["visits"]]
        download_ids = [d["id"] for d in chrome_truth["downloads"]]
        delete_urls = sorted(rng.sample(url_ids, min(spec.browser_delete_urls, len(url_ids))))
        delete_visits = sorted(rng.sample(visit_ids, min(spec.browser_delete_visits, len(visit_ids))))
        delete_downloads = sorted(rng.sample(download_ids, min(spec.downloads_delete, len(download_ids))))
        # visits are deleted first: a urls row's own cell does not depend on its visits, but deleting both from the same
        # page keeps the freed space pattern realistic (a user clearing a page's history clears both).
        chrome_truth["deleted_visits"] = _delete_rows_and_truth(history_path, "visits", delete_visits)
        chrome_truth["deleted_urls"] = _delete_rows_and_truth(history_path, "urls", delete_urls)
        chrome_truth["deleted_downloads"] = _delete_rows_and_truth(history_path, "downloads", delete_downloads)
        deleted_visits_count = len(delete_visits)
        deleted_downloads_count = len(delete_downloads)

    _stamp_mtimes(root)
    _package(root, out_dir)

    truth["expected"] = {
        "sms": spec.sms_count - deleted_sms_count,
        "call": spec.call_count,
        "contact": spec.contact_count,
        "browser_visit": spec.browser_visits + len(truth["files"][f"{CHROME}/History"]["orphan_url_ids"]) - deleted_visits_count,
        "browser_download": spec.downloads - deleted_downloads_count,
        "encrypted_suspects": 1,
        "truncated_databases": 1,
        "hot_journal_databases": 1 if (root / NOTES / "databases/pending.db-journal").exists() else 0,
        "hot_journal_rows_after_rollback": 4000,
        "wal_databases": 1,
    }
    if spec.with_deletions:
        deleted_all = (
            truth["files"][f"{TELEPHONY}/mmssms.db"]["deleted"]
            + truth["files"][f"{CHROME}/History"]["deleted_urls"]
            + truth["files"][f"{CHROME}/History"]["deleted_visits"]
            + truth["files"][f"{CHROME}/History"]["deleted_downloads"]
        )
        truth["expected"]["deleted_rows"] = len(deleted_all)
        truth["expected"]["deleted_rows_by_class"] = dict(Counter(d["expected"] for d in deleted_all))
    (out_dir / "ground_truth.json").write_text(json.dumps(truth, indent=2, default=str))
    return truth
