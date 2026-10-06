"""Central configuration constants for the analysis engine."""

from __future__ import annotations

from datetime import UTC, datetime

CHUNK_SIZE = 1024 * 1024
HEAD_BYTES = 4096

# Files with these kinds are copied into the case's write-protected evidence store
# so that SQLite / parsers never touch the original acquisition.
PRESERVE_TEXT_MAX_BYTES = 8 * 1024 * 1024

# Archive extraction guards (zip-bomb / runaway acquisitions).
MAX_ARCHIVE_ENTRIES = 2_000_000
MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 ** 3
MAX_MEMBER_BYTES = 64 * 1024 ** 3

# Timestamp plausibility window for Android-era artifacts.
PLAUSIBLE_MIN = datetime(2008, 1, 1, tzinfo=UTC)
PLAUSIBLE_FUTURE_SLACK_DAYS = 2

SCHEMA_MATCH_THRESHOLD = 0.5
HTML_ROW_CAP = 3000
