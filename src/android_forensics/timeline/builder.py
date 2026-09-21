"""Unified forensic timeline: artifact events + file-system timestamps, in UTC, chronologically sorted.

Recovered events (Review 2) are distinguished from active ones by the event's ``status``; file events carry no
artifact status because a file mtime is filesystem metadata, not evidence of user activity.
"""

from __future__ import annotations

from dataclasses import dataclass

from android_forensics.models import EvidenceFile, TimelineEvent, TimelineEventKind
from android_forensics.storage.case_store import CaseStore


@dataclass
class TimelineStats:
    artifact_events: int = 0
    file_events: int = 0

    @property
    def total(self) -> int:
        return self.artifact_events + self.file_events


def build_timeline(store: CaseStore, run_id: int, files: str = "key") -> TimelineStats:
    """``files``: 'key' (databases, sidecars, shared_prefs), 'all', or 'none'."""
    if files not in ("key", "all", "none"):
        raise ValueError("files must be key|all|none")
    events: list[TimelineEvent] = []
    stats = TimelineStats()

    for a in store.q(
        "SELECT id, artifact_type, status, confidence, summary, ts_utc, ts_raw, ts_format, ts_note, source_file, source_table, "
        "source_rowid, evidence_file_id FROM artifacts WHERE ts_utc IS NOT NULL AND artifact_type!='app_summary'"
    ):
        where = f"{a['source_file']} → {a['source_table']}#{a['source_rowid']}" if a["source_rowid"] is not None else f"{a['source_file']} → {a['source_table']}"
        basis = a["ts_format"] + (f" ({a['ts_note']})" if a["ts_note"] else "")
        events.append(TimelineEvent(
            timestamp=a["ts_utc"], timestamp_raw=a["ts_raw"], time_basis=basis, kind=TimelineEventKind.ARTIFACT,
            artifact_type=a["artifact_type"], event=a["summary"], source=where, status=a["status"],
            confidence=a["confidence"], artifact_id=a["id"], evidence_file_id=a["evidence_file_id"],
        ))
        stats.artifact_events += 1

    if files != "none":
        for f in store.evidence_files():
            if f.times.mtime is None:
                continue
            if files == "key" and not (f.kind.is_sqlite_family or "/shared_prefs/" in "/" + f.path):
                continue
            events.append(_file_event(f))
            stats.file_events += 1

    events.sort(key=lambda e: (e.timestamp, e.kind.value, e.event))
    store.add_timeline_events(run_id, events)
    return stats


def _file_event(f: EvidenceFile) -> TimelineEvent:
    return TimelineEvent(
        timestamp=f.times.mtime, timestamp_raw=f.times.mtime, time_basis=f.times.basis, kind=TimelineEventKind.FILE_MTIME,
        event=f"File modified: {f.logical_path or f.path} ({f.kind.value}, {f.size} bytes)", source=f.path, evidence_file_id=f.id,
    )
