"""Static report text: methodology, limitations and the recoverability disclaimer."""

DISCLAIMER = (
    "Recoverability of deleted or superseded data depends on the acquisition method and completeness, the "
    "filesystem and storage medium (including flash TRIM / garbage collection), the state of each SQLite database "
    "(auto-vacuum, VACUUM, checkpointing, journal mode, page reuse), device or file-based encryption, subsequent "
    "overwriting, the Android version, and the behaviour of each application. The absence of recovered data in this "
    "report is not evidence that data never existed, and the presence of data is only as reliable as the provenance "
    "shown beside it. This tool supports, and does not replace, the judgement of a qualified examiner. Use only on "
    "evidence you are legally authorised to examine."
)

REVIEW_SCOPE = (
    "Evidence integrity, filesystem analysis, SQLite discovery, extraction of ACTIVE "
    "artifacts, normalisation, validation, timeline and reporting. Deleted-data recovery, carving, correlation and "
    "confidence scoring of recovered records are Review 2 and have NOT been performed."
)

NOT_PERFORMED = {
    "recovered": "Deleted-record recovery (freelist, unallocated space, WAL and rollback-journal analysis, raw page scanning) was NOT performed in Review 1. No claim is made, either way, about whether deleted data exists in this evidence.",
    "partial": "No partial recoveries exist because record recovery was not performed (Review 2).",
    "carved": "Raw binary carving was not performed (Review 2). When it is, hits will be labelled CARVED CANDIDATE and never presented as confirmed evidence until validated and corroborated.",
    "correlation": "Cross-artifact correlation is a Review 2 capability. Review 1 validation only checks consistency between artifacts (for example call-log cached names against contacts).",
    "unrecoverable": "Records that could not be reconstructed are reported by the Review 2 recovery engine; none are classified in Review 1.",
}

METHODOLOGY = [
    ("Evidence integrity", "Every input file is read through a read-only handle exactly once and hashed with SHA-256 (integrity anchor), SHA-1 and MD5 (legacy reference only). Only SQLite databases, their sidecars and small text/XML/JSON files are copied into a write-protected (mode 0444) case evidence store. Originals are never opened for writing and are re-hashed during validation. A hash-chained chain-of-custody log commits each entry to the previous one."),
    ("Filesystem analysis", "Files are classified by content signature first and file name second (SQLite header magic, WAL/journal magic, XML/ABX, media signatures). The Android directory layout (/data/data, /data/user/N, /sdcard, /storage/emulated/N, …) is detected from the evidence rather than assumed; application packages are inferred from paths. Symlinks and special files are never followed."),
    ("SQLite discovery", "The 100-byte SQLite header is parsed in pure Python (page size, encoding, page count, freelist count, schema cookie, journal mode) and checked against the file size. WAL, shared-memory and rollback-journal files are associated with their database and their headers recorded. Each database is opened read-only on a disposable scratch copy so that WAL replay or hot-journal rollback never touches the preserved evidence. PRAGMA integrity_check is recorded."),
    ("Active artifact extraction", "Tables are identified by schema similarity, not file name. Parsers score how many of the columns they understand are present; that score is stored with every artifact. Fields absent from a schema variant are marked UNKNOWN rather than guessed, and are distinct from stored NULLs."),
    ("Normalisation", "Timestamps are converted from their declared storage format (Unix ms, WebKit µs, …) to UTC with the raw value and a plausibility verdict retained. Phone numbers keep their original text and receive a conservative matching key (trailing ten digits of a genuine phone number; short codes and alphanumeric senders receive none)."),
    ("Validation", "Automated checks cover hash consistency, custody chain, SQLite integrity, schema agreement, record structure and datatypes, timestamp plausibility, duplicate detection, cross-artifact consistency and provenance completeness. Failed checks are kept and explained."),
    ("Recovery status (this review)", "Recovery of deleted data is not attempted. Freelist page counts and WAL/journal presence are reported as indicators of recovery potential only."),
]

LIMITATIONS = [
    "No deleted-data recovery, carving, correlation or recovery-confidence scoring was performed (Review 2).",
    "'Active' means present in the database as SQLite itself presents it: main file plus committed WAL frames, with any hot rollback journal rolled back on a scratch copy. Rows flagged deleted by an application (for example Android contacts with deleted=1) are shown as active with a marked-deleted flag.",
    "Databases that SQLite refuses to open (truncated, malformed, encrypted) yield no artifacts in Review 1. Salvage of damaged databases belongs to the Review 2 page-level engine.",
    "Encrypted databases are detected and reported but never decrypted; no credential recovery or lock bypass is attempted.",
    "MMS attachments, messaging apps other than the AOSP SMS provider, and app-specific schemas are catalogued generically (schema, row counts, column hints) but not interpreted.",
    "Android Binary XML (ABX, Android 12+) files are detected but not decoded. SharedPreferences XML contributes key names only; values are deliberately not extracted.",
    "Zip archives store local time without a timezone; those times are labelled as such and shown as UTC. File-system times reflect the acquisition method (extraction may reset them).",
    "Phone-number matching uses a heuristic key, not full E.164 parsing with a numbering-plan database.",
    "Correctness of the parsers was verified against deterministic synthetic evidence with known ground truth; real devices vary by vendor and Android version.",
]

STATUS_GLOSSARY = [
    ("ACTIVE", "Record present in the live database view. Read through the SQLite engine on a scratch copy."),
    ("RECOVERED / PARTIAL / CARVED / CORRUPTED / UNRECOVERABLE / INVALID", "Artifact statuses reserved for the Review 2 recovery engine; none are produced in Review 1. A CARVED artifact is a candidate, never confirmed evidence."),
    ("VALID", "The check passed."),
    ("PARTIAL", "The check passed with reservations that are explained in the result."),
    ("INVALID", "The check failed. Failures are kept and explained, never discarded."),
    ("UNVERIFIED", "The check could not be performed (for example the original evidence is no longer available, or the database is encrypted)."),
]
