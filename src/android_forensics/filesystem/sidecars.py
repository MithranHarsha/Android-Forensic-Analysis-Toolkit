"""Naming rules that associate SQLite sidecar files with their database — one definition for every caller.

A database ``dir/x.db`` owns ``dir/x.db-wal`` (write-ahead log), ``dir/x.db-shm`` (its shared-memory wal-index) and
``dir/x.db-journal`` (rollback journal). Extension-less databases (Chrome's ``History``) follow the same rule.
"""

from __future__ import annotations

from android_forensics.models.enums import SidecarKind

SIDECAR_SUFFIX: dict[SidecarKind, str] = {
    SidecarKind.WAL: "-wal",
    SidecarKind.SHM: "-shm",
    SidecarKind.JOURNAL: "-journal",
}


def sidecar_paths(db_path: str) -> dict[SidecarKind, str]:
    """The paths a database's sidecars would have (whether or not they exist)."""
    return {kind: db_path + suffix for kind, suffix in SIDECAR_SUFFIX.items()}


def split_sidecar(path: str) -> tuple[str, SidecarKind] | None:
    """``dir/x.db-wal`` → (``dir/x.db``, WAL); ``None`` if the name is not a sidecar name (suffix match is case-insensitive)."""
    lower = path.lower()
    for kind, suffix in SIDECAR_SUFFIX.items():
        if lower.endswith(suffix) and len(path) > len(suffix):
            return path[: -len(suffix)], kind
    return None
