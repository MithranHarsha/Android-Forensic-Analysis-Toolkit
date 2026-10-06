"""V1b — compare the SMS this tool finds with the examiner's own list shipped with the Digital Corpora Android images.

``SMS Messages.xlsx`` (Joshua Hickman, Android 9 / Pixel 3) lists every SMS the image author knew about, produced with a commercial
tool and annotated with a *Deleted* column and the source file/offset of each hit. It is the nearest thing to ground truth for
these images, with two caveats the report repeats: it was produced by another tool (so it can be wrong or incomplete), and many
messages live only in Google Messages' own database (``bugle_db``), which this tool has no parser for.

For each of the author's messages we ask: did this tool report the same message (same body, same time within 2 s) as ACTIVE,
as RECOVERED / PARTIAL, or not at all? Messages are listed by source so the gap is explained rather than hidden.

Usage:  python experiments/v1_sms_vs_reference.py CASE_DIR "SMS Messages.xlsx"  [--out experiments/results/v1_sms_vs_reference.json]
Requires openpyxl (experiment-only dependency).
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import openpyxl

from android_forensics.storage.case_store import CaseStore

STAMP = re.compile(r"(\d+)/(\d+)/(\d{4}) (\d+):(\d+):(\d+) (AM|PM)")


def parse_stamp(text: str) -> datetime | None:
    m = STAMP.search(text or "")
    if not m:
        return None
    mo, d, y, h, mi, s, ap = m.groups()
    h = int(h) % 12 + (12 if ap == "PM" else 0)
    return datetime(int(y), int(mo), int(d), h, int(mi), int(s), tzinfo=UTC)


def norm(text: str | None) -> str:
    return " ".join((text or "").split())


def digits(text: str | None) -> str:
    return re.sub(r"\D", "", text or "")[-10:]


def reference_messages(xlsx: Path) -> list[dict]:
    ws = openpyxl.load_workbook(xlsx, read_only=True).worksheets[0]
    rows = list(ws.iter_rows(values_only=True))
    header = rows[1]
    col = {name: i for i, name in enumerate(header)}
    out, current = [], None
    for r in rows[2:]:
        idx = r[col["#"]]
        if idx is None:
            continue
        sources = [s.split(" : ")[0].split("/")[-1] for s in str(r[col["Source file information"]] or "").split("\n") if s.strip()]
        if isinstance(idx, int):          # a primary row; "(n)" rows repeat it from other sources
            current = {"id": idx, "party": str(r[col["Party"]] or ""), "time": parse_stamp(str(r[col["All timestamps"]] or r[col["Time"]] or "")),
                       "direction": r[col["Direction"]], "body": norm(r[col["Message"]]), "deleted": str(r[col["Deleted"]] or "").strip(),
                       "carved": str(r[col["Carved"]] or "").strip(), "sources": set(sources), "number": digits(str(r[col["Party"]] or ""))}
            out.append(current)
        elif current is not None:
            current["sources"] |= set(sources)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("case_dir")
    ap.add_argument("xlsx")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    store = CaseStore.open(Path(args.case_dir))
    ours = [dict(r) for r in store.q("SELECT id, status, ts_utc, summary, fields_json, source_database FROM artifacts WHERE artifact_type='sms'")]
    for o in ours:
        f = json.loads(o["fields_json"] or "{}")
        o["body"], o["time"] = norm(f.get("body") if isinstance(f.get("body"), str) else ""), None
        if o["ts_utc"]:
            o["time"] = datetime.fromisoformat(o["ts_utc"].replace("Z", "+00:00"))
    refs = reference_messages(Path(args.xlsx))
    results = []
    for ref in refs:
        hit = None
        for o in ours:
            if o["body"] and o["body"] == ref["body"] and (ref["time"] is None or o["time"] is None or abs(o["time"] - ref["time"]) <= timedelta(seconds=2)):
                if hit is None or (hit["status"] != "ACTIVE" and o["status"] == "ACTIVE"):
                    hit = o
        results.append({**{k: ref[k] for k in ("id", "deleted", "carved", "body", "direction")}, "sources": sorted(ref["sources"]),
                        "found_as": hit["status"] if hit else None, "found_in": Path(hit["source_database"] or "").name if hit else None})
    by_deleted = Counter()
    for r in results:
        by_deleted[(("deleted" if r["deleted"] else "live"), r["found_as"] or "NOT FOUND")] += 1
    only_bugle = [r for r in results if not r["found_as"] and set(r["sources"]) <= {"bugle_db", "bugle_db-wal", "bugle_db-shm"}]
    in_telephony = [r for r in results if any(s.startswith("mmssms.db") for s in r["sources"])]
    summary = {
        "reference_messages": len(results),
        "reference_flagged_deleted": sum(1 for r in results if r["deleted"]),
        "found": dict(Counter(r["found_as"] or "NOT FOUND" for r in results)),
        "by_deleted_flag": {f"{k[0]}/{k[1]}": v for k, v in sorted(by_deleted.items())},
        "not_found_and_only_in_bugle_db": len(only_bugle),
        "reference_messages_with_a_telephony_mmssms_source": len(in_telephony),
        "of_those_found": dict(Counter(r["found_as"] or "NOT FOUND" for r in in_telephony)),
        "our_sms_artifacts": dict(Counter(o["status"] for o in ours)),
    }
    print(json.dumps(summary, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps({"summary": summary, "messages": results}, indent=2, default=str))


if __name__ == "__main__":
    main()
