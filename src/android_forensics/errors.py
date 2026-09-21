"""Exception hierarchy. The CLI reports any ``ForensicsError`` as a clean message with exit code 2."""

from __future__ import annotations


class ForensicsError(RuntimeError):
    """Base class for expected, user-actionable failures (bad input, unsafe configuration, missing case)."""


class CaseError(ForensicsError):
    """Problem with a case: missing, already exists, inconsistent."""


class IngestionError(ForensicsError):
    """Evidence cannot be ingested as requested (missing path, unsafe working directory, invalid metadata)."""


class DiscoveryError(ForensicsError):
    """The filesystem scanner cannot run on the given input (missing root, not a directory)."""


class InspectionError(ForensicsError):
    """The SQLite inspector cannot run on the given input (missing path, not a regular file, unsafe scratch directory).

    Damaged, encrypted or non-SQLite files are *not* errors: they are inspected and described."""
