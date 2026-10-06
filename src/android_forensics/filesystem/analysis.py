"""Discovery analysis: from a file inventory to a full picture of the Android filesystem. No I/O happens here.

The same function serves two callers, so their results are consistent by construction:

* the standalone ``scan_directory`` (walks a directory, classifies and hashes what it finds), and
* the case pipeline's ``scan`` stage (works from the inventory ingestion already hashed and classified).

It observes; it does not open databases, parse content or recover anything.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from android_forensics.filesystem.android_paths import KNOWN_APPS, AndroidPath, analyze_layout, is_app_subdir
from android_forensics.filesystem.sidecars import sidecar_paths, split_sidecar
from android_forensics.models import (
    AndroidAppDirectory,
    DiscoveredDatabase,
    DumpRoot,
    FileKind,
    FilesystemScan,
    LayoutInfo,
    ScanIssue,
    ScannedFile,
    Sidecar,
    SidecarKind,
    SqliteStatus,
)
from android_forensics.sqlite.header import HeaderReport
from android_forensics.util import now_iso

_KIND_TO_SIDECAR = {
    FileKind.SQLITE_WAL: SidecarKind.WAL,
    FileKind.SQLITE_SHM: SidecarKind.SHM,
    FileKind.SQLITE_JOURNAL: SidecarKind.JOURNAL,
}

STATUS_ISSUE = {
    SqliteStatus.ENCRYPTED_SUSPECT: "encrypted_suspect",
    SqliteStatus.NOT_SQLITE: "db_unrecognised",
    SqliteStatus.EMPTY: "database_empty",
    SqliteStatus.CORRUPT_HEADER: "database_corrupt_header",
    SqliteStatus.TRUNCATED: "database_truncated",
    SqliteStatus.UNREADABLE: "database_unreadable",
}


@dataclass(frozen=True)
class FileObservation:
    """What is known about one file when the analysis starts. ``header`` is set for SQLite files whose header was inspected."""

    path: str
    size: int
    kind: FileKind
    kind_detail: str | None = None
    sha256: str | None = None
    mtime: str | None = None
    readable: bool = True
    evidence_file_id: int | None = None
    header: HeaderReport | None = None


def detect_sqlite_status(obs: FileObservation) -> tuple[SqliteStatus, str]:
    """Decide a database-like file's status from its bytes alone (no SQLite engine)."""
    if not obs.readable:
        return SqliteStatus.UNREADABLE, "the file could not be read"
    if obs.size == 0:
        return SqliteStatus.EMPTY, "zero-length file with a database name (empty or wiped)"
    if obs.kind is FileKind.ENCRYPTED_SUSPECT:
        return SqliteStatus.ENCRYPTED_SUSPECT, obs.kind_detail or "no SQLite header and high entropy — likely encrypted; never decrypted"
    if obs.kind is FileKind.DB_UNRECOGNISED:
        return SqliteStatus.NOT_SQLITE, obs.kind_detail or "database-like name but no SQLite header"
    if obs.header is None:
        return SqliteStatus.UNVERIFIED, "SQLite magic present; header not inspected (no readable working copy)"
    report = obs.header
    header = report.header
    if not header.valid:
        return SqliteStatus.CORRUPT_HEADER, "; ".join(header.fatal) or "invalid SQLite header"
    if report.expected_size is not None and report.actual_size < report.expected_size:
        return SqliteStatus.TRUNCATED, f"{report.actual_size} bytes on disk but the header implies {report.expected_size}"
    if header.page_size and report.actual_size % header.page_size:
        return SqliteStatus.TRUNCATED, (
            f"file ends mid-page ({report.actual_size} bytes is not a multiple of the {header.page_size}-byte page size)"
        )
    detail = "SQLite magic and header structure valid"
    if report.size_consistent is False:
        detail += "; file is longer than the header declares (trailing data)"
    return SqliteStatus.VALID, detail


def sidecar_header_status(kind: SidecarKind, detail: str | None) -> tuple[bool | None, str | None]:
    """Header validity of a sidecar as established at classification time (None: cannot be determined)."""
    d = detail or ""
    if kind is SidecarKind.WAL:
        if "MISMATCH" in d:
            return False, d
        if "magic" in d and "valid" in d or "non-standard name" in d:
            return True, d
        return None, d or None
    if kind is SidecarKind.JOURNAL:
        return (True, d) if "magic valid" in d or "non-standard name" in d else (None, d or None)
    return None, d or None


@dataclass
class _AppAggregate:
    package: str
    path: str
    root: str | None
    area: str | None
    user_id: int | None
    acquisition_root: str
    logical_path: str | None
    files: int = 0
    total_bytes: int = 0
    databases: int = 0
    kinds: Counter = field(default_factory=Counter)
    subdirs: set[str] = field(default_factory=set)
    content: dict[str, str | None] = field(default_factory=dict)


def _logical_app_path(acquisition_root: str, app_root: str) -> str:
    return "/" + (app_root[len(acquisition_root) + 1 :] if acquisition_root else app_root)


def _aggregate_apps(
    observations: list[FileObservation], directories: list[str], located: dict[str, AndroidPath], layout_locate
) -> dict[str, _AppAggregate]:
    aggs: dict[str, _AppAggregate] = {}

    def agg_for(a: AndroidPath) -> _AppAggregate:
        assert a.app_root is not None and a.package is not None
        if a.app_root not in aggs:
            aggs[a.app_root] = _AppAggregate(
                package=a.package, path=a.app_root, root=a.root, area=a.area, user_id=a.user_id,
                acquisition_root=a.acquisition_root, logical_path=_logical_app_path(a.acquisition_root, a.app_root),
            )
        return aggs[a.app_root]

    for o in observations:
        a = located[o.path]
        if a.app_root is None or a.package is None:
            continue
        agg = agg_for(a)
        agg.files += 1
        agg.total_bytes += o.size
        agg.kinds[o.kind.value] += 1
        agg.databases += o.kind.is_database_candidate
        rel = o.path[len(a.app_root) + 1 :]
        agg.content[rel] = o.sha256
        first, _, rest = rel.partition("/")
        if rest and is_app_subdir(first):
            agg.subdirs.add(first)
    for d in directories:
        a = layout_locate(d)
        if a.app_root is None or a.package is None:
            continue
        agg = agg_for(a)
        if d != a.app_root:
            first, _, _rest = d[len(a.app_root) + 1 :].partition("/")
            if is_app_subdir(first):
                agg.subdirs.add(first)
    return aggs


def _alias_issues(aggs: dict[str, _AppAggregate]) -> list[ScanIssue]:
    """``data/data/<pkg>`` and ``data/user/0/<pkg>`` are the same directory on a device; finding both is unusual."""
    issues: list[ScanIssue] = []
    by_key: dict[tuple[str, str], dict[str, _AppAggregate]] = {}
    for agg in aggs.values():
        if agg.root == "data/data" or (agg.root == "data/user" and agg.user_id == 0):
            by_key.setdefault((agg.acquisition_root, agg.package), {})[agg.root] = agg
    for (_acq, package), pair in sorted(by_key.items()):
        if "data/data" in pair and "data/user" in pair:
            a, b = pair["data/data"], pair["data/user"]
            hashed = all(v is not None for v in (*a.content.values(), *b.content.values())) and (a.content or b.content)
            comparison = ("identical contents" if a.content == b.content else "DIFFERENT contents") if hashed else "contents not compared"
            issues.append(ScanIssue(
                path=b.path, issue_type="app_directory_alias",
                detail=f"{package} appears under both {a.path} and {b.path} (on a device one is normally a symlink to the other); {comparison}",
            ))
    return issues


def analyze_files(
    observations: Iterable[FileObservation],
    directories: Iterable[str] = (),
    *,
    root: str | None = None,
    extra_issues: Iterable[ScanIssue] = (),
    include_files: bool = True,
) -> FilesystemScan:
    """Build the discovery picture for a set of files (and, optionally, directories) of one evidence tree."""
    obs = sorted(observations, key=lambda o: o.path)
    dirs = sorted(set(directories))
    layout = analyze_layout([o.path for o in obs], dirs)
    located = {o.path: layout.locate(o.path) for o in obs}
    by_path = {o.path: o for o in obs}
    issues: list[ScanIssue] = list(extra_issues)

    files = [
        ScannedFile(
            path=o.path, size=o.size, kind=o.kind, kind_detail=o.kind_detail, sha256=o.sha256, mtime=o.mtime,
            readable=o.readable, logical_path=located[o.path].logical_path, android_root=located[o.path].root,
            area=located[o.path].area, user_id=located[o.path].user_id, package=located[o.path].package,
        )
        for o in obs
    ]
    kind_counts = Counter(o.kind.value for o in obs)
    category_counts = Counter(o.kind.category for o in obs)

    # ---- databases and their sidecars
    databases: list[DiscoveredDatabase] = []
    claimed: set[str] = set()
    for o in obs:
        if not o.kind.is_database_candidate:
            continue
        status, detail = detect_sqlite_status(o)
        a = located[o.path]
        header = o.header.header if o.header is not None and o.header.header.valid else None
        sidecars: list[Sidecar] = []
        for kind, sp in sidecar_paths(o.path).items():
            so = by_path.get(sp)
            if so is None:
                continue
            claimed.add(sp)
            valid, note = sidecar_header_status(kind, so.kind_detail)
            sidecars.append(Sidecar(kind=kind, path=sp, size=so.size, sha256=so.sha256, header_valid=valid, note=note,
                                    evidence_file_id=so.evidence_file_id))
        databases.append(DiscoveredDatabase(
            path=o.path, size=o.size, sha256=o.sha256, status=status, detail=detail, logical_path=a.logical_path,
            package=a.package, area=a.area, user_id=a.user_id,
            page_size=header.page_size if header else None, page_count=header.page_count if header else None,
            text_encoding=header.text_encoding if header else None, journal_mode=header.journal_mode if header else None,
            freelist_pages=header.freelist_page_count if header else None, sidecars=sidecars, evidence_file_id=o.evidence_file_id,
        ))
        if status in STATUS_ISSUE:
            issues.append(ScanIssue(path=o.path, issue_type=STATUS_ISSUE[status], detail=detail))

    orphans: list[Sidecar] = []
    for o in obs:
        if not o.kind.is_sidecar:
            continue
        kind = _KIND_TO_SIDECAR[o.kind]
        valid, note = sidecar_header_status(kind, o.kind_detail)
        if valid is False:
            issues.append(ScanIssue(path=o.path, issue_type="sidecar_header_invalid", detail=note or ""))
        if o.path in claimed:
            continue
        split = split_sidecar(o.path)
        if split is None:
            reason = "its name does not follow the <database>-wal / -shm / -journal convention"
        elif split[0] in by_path:
            reason = f"its base file '{split[0]}' exists but is not a database ({by_path[split[0]].kind.value})"
        else:
            reason = f"no database named '{split[0]}' in the evidence"
        orphans.append(Sidecar(kind=kind, path=o.path, size=o.size, sha256=o.sha256, header_valid=valid,
                               note=(note + "; " if note else "") + reason, evidence_file_id=o.evidence_file_id))
        issues.append(ScanIssue(path=o.path, issue_type="orphan_sidecar", detail=reason))

    for o in obs:
        if o.kind is FileKind.XML_BINARY:
            issues.append(ScanIssue(path=o.path, issue_type="binary_xml_not_parsed", detail=o.kind_detail or "Android Binary XML"))
        elif not o.readable and not o.kind.is_database_candidate and not o.kind.is_sidecar:
            issues.append(ScanIssue(path=o.path, issue_type="unreadable_file", detail=o.kind_detail or "could not be read"))

    # ---- application directories
    aggs = _aggregate_apps(obs, dirs, located, layout.locate)
    apps = [
        AndroidAppDirectory(
            package=g.package, path=g.path, logical_path=g.logical_path, root=g.root, area=g.area, user_id=g.user_id,
            known_app=KNOWN_APPS.get(g.package), subdirectories=sorted(g.subdirs), file_count=g.files,
            total_bytes=g.total_bytes, database_count=g.databases, kind_counts=dict(sorted(g.kinds.items())),
        )
        for g in sorted(aggs.values(), key=lambda g: g.path)
    ]
    issues += _alias_issues(aggs)

    # ---- layout
    if layout.layout == "multiple_roots":
        issues.append(ScanIssue(path=".", issue_type="multiple_dumps", detail=layout.detail))
    elif layout.layout == "loose_files" and obs:
        issues.append(ScanIssue(path=".", issue_type="layout_unrecognised", detail=layout.detail))

    info = LayoutInfo(
        layout=layout.layout, detail=layout.detail, matched=layout.matched, total=layout.total,
        roots=[DumpRoot(prefix=r.prefix, files=r.files, markers=list(r.markers)) for r in layout.roots],
        roots_present=layout.roots_present, roots_absent=layout.roots_absent,
    )
    return FilesystemScan(
        root=root, scanned_at=now_iso(), layout=info, files=files if include_files else [], directories=len(dirs),
        total_files=len(obs), total_bytes=sum(o.size for o in obs), kind_counts=dict(sorted(kind_counts.items())),
        category_counts=dict(sorted(category_counts.items())), databases=databases, orphan_sidecars=orphans,
        app_directories=apps, issues=issues,
    )
