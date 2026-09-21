"""Generic parsers for anything the dedicated parsers do not recognise.

* ``column_hints`` — generic SQLite parser: classifies columns of unrecognised tables (timestamp-like,
  phone-like, URL-like…) from names and sampled values so an examiner can triage app databases.
  It reports *hints*, never conclusions, and does not emit rows as artifacts.
* ``build_app_summaries`` — generic application-data parser: one summary artifact per Android package,
  derived from the hashed inventory. SharedPreferences XML contributes **key names only**; values are
  never extracted, to avoid harvesting credentials or tokens.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from typing import Any

from android_forensics.artifacts.timestamps import plausible_formats
from android_forensics.filesystem.android_paths import KNOWN_APPS
from android_forensics.models import (
    ApplicationSummary,
    ParserInfo,
    Provenance,
    RawKind,
    RawReference,
    TimestampFormat,
    TimestampInfo,
)
from android_forensics.sqlite.discovery import preserved_path
from android_forensics.sqlite.reader import SchemaObject, SQLiteSession
from android_forensics.storage.case_store import CaseStore

_TS_NAME = re.compile(r"(date|time|stamp|_at$|created|modified|updated|expire)", re.I)
_PHONE_NAME = re.compile(r"(phone|number|msisdn|mobile|address|contact)", re.I)
_PHONE_VAL = re.compile(r"^\+?[\d\s().\-]{7,20}$")
_EMAIL_VAL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
SAMPLE_ROWS = 50


def column_hints(session: SQLiteSession, table: SchemaObject, now: datetime | None = None) -> dict[str, Any]:
    cols = [c.name for c in table.columns]
    samples: dict[str, list[Any]] = {c: [] for c in cols}
    n = 0
    for _rid, row in session.iter_rows(table):
        for c in cols:
            if row.get(c) is not None:
                samples[c].append(row[c])
        n += 1
        if n >= SAMPLE_ROWS:
            break
    out: dict[str, Any] = {}
    for c in cols:
        vals = samples[c]
        hints: list[str] = []
        types = sorted({type(v).__name__ for v in vals})
        formats: list[str] = []
        nums = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if nums:
            common = None
            for v in nums:
                pf = set(plausible_formats(v, now))
                common = pf if common is None else common & pf
            if common and len(nums) >= 3:
                formats = sorted(common)
                hints.append("timestamp_like" if _TS_NAME.search(c) else "possible_timestamp")
        texts = [v for v in vals if isinstance(v, str)]
        if texts:
            if sum(bool(_PHONE_VAL.match(v)) for v in texts) >= 0.8 * len(texts) and _PHONE_NAME.search(c):
                hints.append("phone_like")
            if sum(v.lower().startswith(("http://", "https://")) for v in texts) >= 0.5 * len(texts):
                hints.append("url_like")
            if sum(bool(_EMAIL_VAL.match(v)) for v in texts) >= 0.5 * len(texts):
                hints.append("email_like")
            if sum(len(v) for v in texts) / len(texts) > 60:
                hints.append("text_heavy")
        if any(isinstance(v, bytes) for v in vals):
            hints.append("blob")
        out[c] = {"sampled_types": types, "hints": hints, "timestamp_formats": formats, "non_null_samples": len(vals)}
    return {"sampled_rows": n, "columns": out}


def _pref_keys(text: str) -> list[str] | None:
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    return [el.get("name") for el in root if el.get("name")][:200]


def build_app_summaries(store: CaseStore, run_id: int) -> tuple[list[ApplicationSummary], list[tuple[str, str]]]:
    """Return (summary artifacts, [(path, reason)] for XML files that were skipped)."""
    rows = store.q("SELECT * FROM evidence_files WHERE package IS NOT NULL ORDER BY id")
    by_pkg: dict[str, list] = defaultdict(list)
    for r in rows:
        by_pkg[r["package"]].append(r)
    artifacts: list[ApplicationSummary] = []
    skipped: list[tuple[str, str]] = []
    for pkg, files in sorted(by_pkg.items()):
        prefs_files: list[str] = []
        prefs_keys: dict[str, list[str]] = {}
        for f in files:
            if "/shared_prefs/" in "/" + f["path"] and f["path"].endswith(".xml") and f["kind"] == "xml":
                p = preserved_path(store, f)
                if p is not None and p.is_file():
                    keys = _pref_keys(p.read_text(errors="replace"))
                    if keys is None:
                        skipped.append((f["path"], "shared_prefs XML rejected (DOCTYPE/entity or malformed)"))
                    else:
                        prefs_files.append(f["path"])
                        prefs_keys[f["path"]] = keys
        mtimes = sorted(f["mtime"] for f in files if f["mtime"])
        dbs = [f for f in files if f["kind"] == "sqlite_db"]
        first = dbs[0] if dbs else files[0]
        total = sum(f["size"] for f in files)
        summary_fields = dict(
            package=pkg,
            file_count=len(files),
            total_bytes=total,
            database_count=len(dbs),
            sidecar_count=sum(f["kind"] in ("sqlite_wal", "sqlite_shm", "sqlite_journal") for f in files),
            shared_pref_files=prefs_files,
            shared_pref_keys=prefs_keys,
            first_modified_utc=mtimes[0] if mtimes else None,
            last_modified_utc=mtimes[-1] if mtimes else None,
            known_app=KNOWN_APPS.get(pkg),
        )
        ts = (
            TimestampInfo(raw=mtimes[-1], utc=mtimes[-1], format=TimestampFormat.FILE_MTIME, plausible=None,
                          note="latest file modification time among this app's files (filesystem metadata, not app activity)")
            if mtimes
            else None
        )
        derived = [{"path": f["path"], "sha256": f["sha256"], "size": f["size"], "kind": f["kind"]} for f in files[:100]]
        artifacts.append(
            ApplicationSummary(
                parser=ParserInfo(name="app_data", version="1.0"),
                application=pkg,
                timestamp=ts,
                summary=f"Application {KNOWN_APPS.get(pkg, pkg)}: {len(files)} files, {len(dbs)} databases",
                raw=RawReference(kind=RawKind.INVENTORY, row={"derived_from": derived, "member_count": len(files),
                                                             "note": "aggregate of hashed inventory entries"}),
                provenance=Provenance(evidence_file_id=first["id"], source_file=first["path"], source_sha256=first["sha256"]),
                **summary_fields,
            )
        )
    return artifacts, skipped
