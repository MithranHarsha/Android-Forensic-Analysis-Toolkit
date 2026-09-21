"""Compare what the tool extracted against the synthetic generator's ground truth.

The expected values are derived here from the *raw source values* the generator wrote, using
independent arithmetic (not the tool's own converters), so a bug in the tool cannot hide itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from android_forensics.lab.synth import CHROME, CONTACTS, TELEPHONY
from android_forensics.storage.case_store import CaseStore

_UNIX = datetime(1970, 1, 1, tzinfo=timezone.utc)
_WEBKIT = datetime(1601, 1, 1, tzinfo=timezone.utc)
SMS_DIR = {1: "RECEIVED", 2: "SENT", 3: "DRAFT", 4: "OUTBOX", 5: "FAILED", 6: "QUEUED"}
CALL_TYPE = {1: "INCOMING", 2: "OUTGOING", 3: "MISSED", 4: "VOICEMAIL", 5: "REJECTED", 6: "BLOCKED"}


def utc_ms(ms: int) -> str:
    return (_UNIX + timedelta(milliseconds=ms)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utc_webkit(us: int) -> str:
    return (_WEBKIT + timedelta(microseconds=us)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class TypeResult:
    expected: int = 0
    extracted: int = 0
    correct: int = 0
    mismatches: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.correct / self.extracted if self.extracted else 0.0

    @property
    def recall(self) -> float:
        return self.correct / self.expected if self.expected else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


def _load(store: CaseStore, db_suffix: str, atype: str) -> dict[tuple[str, int | None], dict[str, Any]]:
    out: dict[tuple[str, int | None], dict[str, Any]] = {}
    for r in store.q(
        "SELECT * FROM artifacts WHERE artifact_type=? AND source_file LIKE ?", (atype, f"%{db_suffix}")):
        out[(r["source_table"], r["source_rowid"])] = {"row": r, "f": json.loads(r["fields_json"])}
    return out


def _cmp(res: TypeResult, key: Any, expected: dict[str, Any], got: dict[str, Any]) -> None:
    bad = [f"{k}: expected {v!r}, got {got.get(k)!r}" for k, v in expected.items() if got.get(k) != v]
    if bad:
        res.mismatches.append(f"{key}: " + "; ".join(bad))
    else:
        res.correct += 1


def _flat(a: dict[str, Any]) -> dict[str, Any]:
    return {**a["f"], "ts_utc": a["row"]["ts_utc"], "phone_key": a["row"]["phone_key"], "marked_deleted": bool(a["row"]["marked_deleted"])}


def compare_active(store: CaseStore, truth: dict[str, Any]) -> dict[str, TypeResult]:
    files = truth["files"]
    results: dict[str, TypeResult] = {}

    # ---- SMS
    res = results["sms"] = TypeResult()
    got = _load(store, f"{TELEPHONY}/mmssms.db", "sms")
    res.extracted = len(got)
    for t in files[f"{TELEPHONY}/mmssms.db"]["active"]:
        res.expected += 1
        a = got.get(("sms", t["_id"]))
        if a is None:
            res.mismatches.append(f"sms#{t['_id']}: not extracted")
            continue
        _cmp(res, f"sms#{t['_id']}", {
            "address": t["address"], "body": t["body"], "direction": SMS_DIR[t["type"]], "type_code": t["type"],
            "read": bool(t["read"]), "thread_id": t["thread_id"], "ts_utc": utc_ms(t["date"]),
            "date_sent_utc": utc_ms(t["date_sent"]) if t["date_sent"] else None, "service_center": t["service_center"],
            "subscription_id": t["sub_id"],
        }, _flat(a))

    # ---- calls (includes rows that exist only in the WAL)
    res = results["call"] = TypeResult()
    got = _load(store, f"{CONTACTS}/calllog.db", "call")
    res.extracted = len(got)
    for t in files[f"{CONTACTS}/calllog.db"]["active"]:
        res.expected += 1
        a = got.get(("calls", t["_id"]))
        if a is None:
            res.mismatches.append(f"calls#{t['_id']}: not extracted")
            continue
        _cmp(res, f"calls#{t['_id']}", {
            "number": t["number"], "call_type": CALL_TYPE[t["type"]], "duration_seconds": t["duration"],
            "cached_name": t["name"], "ts_utc": utc_ms(t["date"]), "lookup_uri": t["lookup_uri"],
            "phone_account_address": t["phone_account_address"],
        }, _flat(a))

    # ---- contacts
    res = results["contact"] = TypeResult()
    got = _load(store, f"{CONTACTS}/contacts2.db", "contact")
    res.extracted = len(got)
    for t in files[f"{CONTACTS}/contacts2.db"]["active"]:
        res.expected += 1
        a = got.get(("raw_contacts", t["contact_id"]))
        if a is None:
            res.mismatches.append(f"contact#{t['contact_id']}: not extracted")
            continue
        f = _flat(a)
        _cmp(res, f"contact#{t['contact_id']}", {
            "display_name": t["display_name"], "ts_utc": utc_ms(t["contact_last_updated_timestamp"]),
            "phone_key": t["phone_key_source"][-10:], "marked_deleted": bool(t["deleted_flag"]),
            "phone_numbers": [t["phone_display"]], "email_addresses": t["emails"],
        }, {**f, "phone_numbers": [p["number"] for p in f["phones"]], "email_addresses": [e["address"] for e in f["emails"]]})

    # ---- browser (visits, orphan url-level rows, downloads)
    hist = files[f"{CHROME}/History"]
    urls = {u["id"]: u for u in hist["urls"]}
    res = results["browser_visit"] = TypeResult()
    got = _load(store, f"{CHROME}/History", "browser_visit")
    res.extracted = len(got)
    for v in hist["visits"]:
        res.expected += 1
        a = got.get(("visits", v["id"]))
        if a is None:
            res.mismatches.append(f"visits#{v['id']}: not extracted")
            continue
        _cmp(res, f"visits#{v['id']}", {
            "url": urls[v["url"]]["url"], "title": urls[v["url"]]["title"], "ts_utc": utc_webkit(v["visit_time"]),
            "url_level_only": False, "visit_duration_us": v["visit_duration"],
        }, _flat(a))
    for uid in hist["orphan_url_ids"]:
        res.expected += 1
        a = got.get(("urls", uid))
        if a is None:
            res.mismatches.append(f"urls#{uid}: url-level record not extracted")
            continue
        _cmp(res, f"urls#{uid}", {"url": urls[uid]["url"], "url_level_only": True,
                                  "ts_utc": utc_webkit(urls[uid]["last"]) if urls[uid]["last"] else None}, _flat(a))

    res = results["browser_download"] = TypeResult()
    got = _load(store, f"{CHROME}/History", "browser_download")
    res.extracted = len(got)
    for d in hist["downloads"]:
        res.expected += 1
        a = got.get(("downloads", d["id"]))
        if a is None:
            res.mismatches.append(f"downloads#{d['id']}: not extracted")
            continue
        _cmp(res, f"downloads#{d['id']}", {
            "target_path": d["target_path"], "total_bytes": d["total_bytes"], "download_state": "COMPLETE", "tab_url": d["tab_url"],
            "ts_utc": utc_webkit(d["start_time"]),
        }, _flat(a))
    return results


def summarise(results: dict[str, TypeResult]) -> list[dict[str, Any]]:
    return [
        {"artifact_type": k, "expected": r.expected, "extracted": r.extracted, "correct": r.correct,
         "precision": round(r.precision, 4), "recall": round(r.recall, 4), "f1": round(r.f1, 4)}
        for k, r in results.items()
    ]
