"""Android filesystem discovery.

Two entry points, one analysis core (``analysis.analyze_files``):

* ``scan_directory(root)`` — a standalone, database-free scanner. It walks an evidence directory recursively and
  read-only, classifies every file by content, hashes databases and their sidecars (SHA-256), and returns a typed
  ``FilesystemScan``: layout, categories, application directories, databases with their WAL/SHM/journal files,
  orphaned sidecars and every problem met on the way.
* ``scan_filesystem(store)`` — the case pipeline's ``scan`` stage. It works from the inventory ingestion already hashed and
  classified (so the evidence is not read twice) and persists what it finds.

Nothing here assumes any particular Android directory exists. Problems with individual entries — unreadable, vanished,
dangling, corrupt — become issues and never abort the scan; only a missing or non-directory root does.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from android_forensics.acquisition.hashing import sha256_of
from android_forensics.config import HEAD_BYTES
from android_forensics.errors import DiscoveryError
from android_forensics.filesystem.analysis import FileObservation, analyze_files
from android_forensics.filesystem.classifier import classify, classify_unreadable
from android_forensics.models import FileKind, FilesystemScan, ScanIssue, SourceLayout
from android_forensics.progress import NullProgress, Progress
from android_forensics.readonly import open_readonly
from android_forensics.sqlite.header import HeaderReport, inspect_database_file
from android_forensics.storage.case_store import CaseStore, utcnow
from android_forensics.util import iso_from_epoch, safe_text


# ------------------------------------------------------------------ standalone directory scanner


def scan_directory(
    root: str | Path,
    *,
    hash_databases: bool = True,
    hash_all: bool = False,
    include_files: bool = True,
    progress: Progress | None = None,
) -> FilesystemScan:
    """Recursively inspect an evidence directory (read-only) and describe its Android filesystem.

    ``hash_databases`` (default) computes SHA-256 for every database-like file and every sidecar; ``hash_all`` hashes every
    file. ``include_files=False`` drops the per-file list from the result (aggregates and databases are kept) for very
    large trees. Symlinks are never followed.

    Raises ``DiscoveryError`` only if ``root`` is missing or not a directory.
    """
    progress = progress or NullProgress()
    base = Path(root).expanduser()
    if not base.exists():
        raise DiscoveryError(f"Evidence directory does not exist: {base}")
    if not base.is_dir():
        raise DiscoveryError(f"{base} is not a directory (archives are ingested first; use 'ingest')")
    base = base.resolve()

    observations: list[FileObservation] = []
    directories: list[str] = []
    issues: list[ScanIssue] = []
    stack: list[Path] = [base]
    progress.start(f"Scanning {base.name}", None)
    try:
        while stack:
            current = stack.pop()
            rel_dir = "." if current == base else safe_text(current.relative_to(base).as_posix())
            try:
                with os.scandir(current) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except FileNotFoundError:
                issues.append(ScanIssue(path=rel_dir, issue_type="vanished", detail="directory disappeared while it was being scanned"))
                continue
            except OSError as exc:
                issues.append(ScanIssue(path=rel_dir, issue_type="unreadable_directory", detail=f"{type(exc).__name__}: {exc}"))
                continue

            subdirs: list[Path] = []
            for entry in entries:
                rel = safe_text(Path(entry.path).relative_to(base).as_posix())
                try:
                    if entry.is_symlink():
                        target = safe_text(os.readlink(entry.path))
                        dangling = not os.path.exists(entry.path)
                        issues.append(ScanIssue(
                            path=rel, issue_type="dangling_symlink" if dangling else "symlink_skipped",
                            detail=f"symlink -> {target}" + (" (target does not exist)" if dangling else " (not followed)"),
                        ))
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        directories.append(rel)
                        subdirs.append(Path(entry.path))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        issues.append(ScanIssue(path=rel, issue_type="special_file_skipped", detail="socket, device or fifo: not read"))
                        continue
                    st = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    issues.append(ScanIssue(path=rel, issue_type="vanished", detail="entry disappeared while it was being scanned"))
                    continue
                except OSError as exc:
                    issues.append(ScanIssue(path=rel, issue_type="stat_error", detail=f"{type(exc).__name__}: {exc}"))
                    continue

                observed = _observe(Path(entry.path), rel, st, hash_databases, hash_all)
                if observed is None:
                    issues.append(ScanIssue(path=rel, issue_type="vanished", detail="file disappeared while it was being scanned"))
                    continue
                observations.append(observed)
                progress.advance()
            stack.extend(reversed(subdirs))
    finally:
        progress.stop()
    return analyze_files(observations, directories, root=str(base), extra_issues=issues, include_files=include_files)


def _observe(path: Path, rel: str, st: os.stat_result, hash_databases: bool, hash_all: bool) -> FileObservation | None:
    """Classify one file from its first bytes, hash it if asked, inspect a database header — all read-only, all fault-tolerant.

    Returns ``None`` if the file vanished; a file that exists but cannot be read is kept, flagged ``readable=False``."""
    mtime = iso_from_epoch(st.st_mtime)
    try:
        with open_readonly(path) as fh:
            head = fh.read(HEAD_BYTES)
    except FileNotFoundError:
        return None
    except OSError as exc:
        c = classify_unreadable(rel, f"{type(exc).__name__}: {exc}")
        return FileObservation(rel, st.st_size, c.kind, c.detail, None, mtime, readable=False)
    c = classify(rel, head, st.st_size)

    sha = None
    readable = True
    if hash_all or (hash_databases and (c.kind.is_database_candidate or c.kind.is_sidecar)):
        try:
            sha = sha256_of(path)
        except OSError:
            readable = False
    header: HeaderReport | None = None
    if readable and c.kind is FileKind.SQLITE_DB:
        try:
            header = inspect_database_file(path)
        except OSError:
            readable = False
    return FileObservation(rel, st.st_size, c.kind, c.detail, sha, mtime, readable=readable, header=header)


# ------------------------------------------------------------------ the case pipeline's scan stage


@dataclass
class FilesystemScanStats:
    files: int = 0
    layout: str = "unknown"
    kinds: dict[str, int] = field(default_factory=dict)
    categories: dict[str, int] = field(default_factory=dict)
    packages: int = 0
    app_directories: int = 0
    new_issues: int = 0


def scan_filesystem(store: CaseStore, progress: Progress | None = None) -> FilesystemScanStats:
    """Discovery over the ingested inventory: attribute files to the Android filesystem, find application directories,
    flag oddities, and persist the results. The originals are not read again."""
    progress = progress or NullProgress()
    stats = FilesystemScanStats()
    kinds: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    packages: set[str] = set()
    layouts: dict[int, SourceLayout] = {}
    issue_rows: list[tuple] = []
    app_rows: list[tuple] = []
    now = utcnow()
    progress.start("Analysing filesystem", store.scalar("SELECT COUNT(*) FROM evidence_files"))

    for src in store.sources():
        files = list(store.evidence_files(src.id))
        ids_by_path: dict[str, list[int]] = {}
        observations = []
        for f in files:
            ids_by_path.setdefault(f.path, []).append(f.id)
            header = None
            if f.kind is FileKind.SQLITE_DB and f.is_preserved:
                copy = store.evidence_dir / f"s{f.source_id}" / f.preserved_copy
                try:
                    header = inspect_database_file(copy)
                except OSError:
                    header = None
            observations.append(FileObservation(
                path=f.path, size=f.size, kind=f.kind, kind_detail=f.kind_detail, sha256=f.hashes.sha256,
                mtime=f.times.mtime, evidence_file_id=f.id, header=header,
            ))
        scan = analyze_files(observations, (), root=src.original_path)

        with store.transaction():
            store.conn.executemany(
                "UPDATE evidence_files SET logical_path=?, android_root=?, user_id=?, package=? WHERE id=?",
                [(sf.logical_path, sf.android_root, sf.user_id, sf.package, fid) for sf in scan.files for fid in ids_by_path[sf.path]],
            )
        for sf in scan.files:
            if sf.package:
                packages.add(sf.package)
        kinds.update(scan.kind_counts)
        categories.update(scan.category_counts)
        prefix = scan.layout.roots[0].prefix if len(scan.layout.roots) == 1 else ""
        layouts[src.id] = SourceLayout(layout=scan.layout.layout, prefix=prefix, detail=scan.layout.detail)
        for issue in scan.issues:
            issue_rows.append((src.id, issue.path, issue.issue_type, issue.detail, "scan", now))
        for a in scan.app_directories:
            app_rows.append((
                src.id, a.package, a.path, a.logical_path, a.root, a.area, a.user_id, a.known_app,
                json.dumps(a.subdirectories), a.file_count, a.total_bytes, a.database_count, json.dumps(a.kind_counts),
            ))
        progress.advance(len(files))
    progress.stop()

    with store.transaction():
        store.conn.execute("DELETE FROM scan_issues WHERE stage='scan'")
        store.conn.execute("DELETE FROM app_directories")
        store.conn.executemany(
            "INSERT INTO scan_issues(source_id,path,issue_type,detail,stage,created_at) VALUES(?,?,?,?,?,?)", issue_rows
        )
        store.conn.executemany(
            "INSERT INTO app_directories(source_id,package,path,logical_path,root,area,user_id,known_app,subdirectories_json,"
            "file_count,total_bytes,database_count,kind_counts_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            app_rows,
        )
    names = {v.layout for v in layouts.values()}
    overall = names.pop() if len(names) == 1 else ("multiple" if names else "empty")
    store.set_layouts(overall, layouts)
    stats.files = sum(kinds.values())
    stats.layout = overall
    stats.kinds = dict(kinds)
    stats.categories = dict(categories)
    stats.packages = len(packages)
    stats.app_directories = len(app_rows)
    stats.new_issues = len(issue_rows)
    return stats

