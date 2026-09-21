"""Enumerations shared across the toolchain.

``ArtifactStatus`` and ``ExtractionMethod`` carry the full vocabulary the Review 2 recovery engine needs, but
Review 1 only ever produces ``ArtifactStatus.ACTIVE``. The remaining members are reserved so recovered data can be
represented without a schema or model change; the ``Artifact`` invariants stop them being used carelessly.

Code tables for Android value enumerations (SMS type, call type, Chromium transition, …) live here — one source
of truth — as ``from_code`` classmethods. An unmapped code becomes ``UNRECOGNISED``; the raw integer is always kept
beside it on the model.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self


class ArtifactType(StrEnum):
    SMS = "sms"
    CALL = "call"
    CONTACT = "contact"
    BROWSER_VISIT = "browser_visit"  # a browser history entry: a visit, or a URL-level record
    BROWSER_DOWNLOAD = "browser_download"
    APP_SUMMARY = "app_summary"
    GENERIC_RECORD = "generic_record"  # a row of a table no parser recognises (Review 2: recovered rows only)


class ArtifactStatus(StrEnum):
    """How the tool came to hold this record, and how far it can be trusted as a record.

    ACTIVE         present in the live database view (Review 1)
    RECOVERED      deleted, fully reconstructed and structurally valid            (Review 2)
    PARTIAL        deleted, some fields unrecoverable (marked UNKNOWN)            (Review 2)
    CARVED         raw-carved candidate — never confirmed evidence on its own     (Review 2)
    CORRUPTED      fragmentary/damaged remains whose values cannot be trusted     (Review 2)
    UNRECOVERABLE  evidence that a record existed but its content is gone         (Review 2)
    INVALID        a candidate rejected by validation, kept with the reasons      (Review 2)
    """

    ACTIVE = "ACTIVE"
    RECOVERED = "RECOVERED"
    PARTIAL = "PARTIAL"
    CARVED = "CARVED"
    CORRUPTED = "CORRUPTED"
    UNRECOVERABLE = "UNRECOVERABLE"
    INVALID = "INVALID"

    @property
    def is_active(self) -> bool:
        return self is ArtifactStatus.ACTIVE

    @property
    def is_recovery_state(self) -> bool:
        """True for anything that did not come from the live database view."""
        return self is not ArtifactStatus.ACTIVE

    @property
    def requires_confidence(self) -> bool:
        """Statuses that assert 'this is (part of) a record' must say how sure the tool is, and why."""
        return self in _CONFIDENCE_REQUIRED

    @property
    def is_candidate(self) -> bool:
        """A carved hit is a candidate until it is correlated and validated."""
        return self is ArtifactStatus.CARVED


_CONFIDENCE_REQUIRED = frozenset(
    {ArtifactStatus.RECOVERED, ArtifactStatus.PARTIAL, ArtifactStatus.CARVED, ArtifactStatus.CORRUPTED}
)
STATUSES_PRODUCED_IN_REVIEW_1 = frozenset({ArtifactStatus.ACTIVE})


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


class ExtractionMethod(StrEnum):
    """How an artifact's bytes were obtained. Only the first two are produced in Review 1."""

    ACTIVE_QUERY = "ACTIVE_QUERY"  # row read through the SQLite engine on a scratch copy
    FILESYSTEM_METADATA = "FILESYSTEM_METADATA"  # derived from the hashed file inventory
    FREELIST_PAGE = "FREELIST_PAGE"  # reserved: Review 2
    FREEBLOCK = "FREEBLOCK"
    UNALLOCATED_SPACE = "UNALLOCATED_SPACE"
    WAL_FRAME = "WAL_FRAME"
    JOURNAL_PAGE = "JOURNAL_PAGE"
    RAW_PAGE_SCAN = "RAW_PAGE_SCAN"
    CARVING = "CARVING"

    @property
    def is_active(self) -> bool:
        return self in (ExtractionMethod.ACTIVE_QUERY, ExtractionMethod.FILESYSTEM_METADATA)


class RawKind(StrEnum):
    """What a ``RawReference`` points at."""

    SQLITE_ROW = "sqlite_row"  # the row exactly as SQLite returned it (Review 1)
    INVENTORY = "inventory"  # an aggregate of hashed inventory entries (Review 1)
    PAGE_BYTES = "page_bytes"  # reserved: Review 2
    WAL_FRAME = "wal_frame"
    JOURNAL_PAGE = "journal_page"
    FILE_BYTES = "file_bytes"

    @property
    def is_bytes(self) -> bool:
        return self in (RawKind.PAGE_BYTES, RawKind.WAL_FRAME, RawKind.JOURNAL_PAGE, RawKind.FILE_BYTES)


class ValidationStatus(StrEnum):
    VALID = "VALID"
    PARTIAL = "PARTIAL"
    INVALID = "INVALID"
    UNVERIFIED = "UNVERIFIED"


class ValidationTarget(StrEnum):
    CASE = "case"
    SOURCE = "source"
    FILE = "file"
    DATABASE = "database"
    TABLE = "table"
    ARTIFACT = "artifact"


class ValidationCheck(StrEnum):
    HASH_CONSISTENCY = "hash_consistency"
    CUSTODY_CHAIN = "custody_chain"
    MANIFEST_INTEGRITY = "manifest_integrity"
    ACQUISITION_COMPLETENESS = "acquisition_completeness"
    SQLITE_HEADER = "sqlite_header"
    SQLITE_INTEGRITY = "sqlite_integrity"
    TEXT_DECODING = "text_decoding"
    FILENAME_SCHEMA_AGREEMENT = "filename_schema_agreement"
    SCHEMA_CONSISTENCY = "schema_consistency"
    RECORD_STRUCTURE = "record_structure"
    TIMESTAMP_PLAUSIBILITY = "timestamp_plausibility"
    DUPLICATE_DETECTION = "duplicate_detection"
    CROSS_ARTIFACT_CONSISTENCY = "cross_artifact_consistency"
    PROVENANCE_COMPLETENESS = "provenance_completeness"


class RunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class TimelineEventKind(StrEnum):
    ARTIFACT = "artifact"
    FILE_MTIME = "file_mtime"


class FileKind(StrEnum):
    SQLITE_DB = "sqlite_db"
    SQLITE_WAL = "sqlite_wal"
    SQLITE_SHM = "sqlite_shm"
    SQLITE_JOURNAL = "sqlite_journal"
    XML = "xml"
    XML_BINARY = "xml_binary"
    JSON = "json"
    TEXT = "text"
    LOG = "log"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    APK = "apk"
    ARCHIVE = "archive"
    ENCRYPTED_SUSPECT = "encrypted_suspect"
    DB_UNRECOGNISED = "db_unrecognised"
    EMPTY = "empty"
    UNKNOWN = "unknown"

    @property
    def is_sqlite_family(self) -> bool:
        return self in (FileKind.SQLITE_DB, FileKind.SQLITE_WAL, FileKind.SQLITE_SHM, FileKind.SQLITE_JOURNAL)

    @property
    def is_sidecar(self) -> bool:
        return self in (FileKind.SQLITE_WAL, FileKind.SQLITE_SHM, FileKind.SQLITE_JOURNAL)

    @property
    def is_database_candidate(self) -> bool:
        """A file to be reported as a database: real SQLite, or database-named but not (yet) recognisable as one."""
        return self in (FileKind.SQLITE_DB, FileKind.DB_UNRECOGNISED, FileKind.ENCRYPTED_SUSPECT)

    @property
    def is_media(self) -> bool:
        return self in (FileKind.IMAGE, FileKind.VIDEO, FileKind.AUDIO)

    @property
    def category(self) -> str:
        """Coarse discovery category: database · sqlite_wal · sqlite_shm · sqlite_journal · xml · json · log · media · other."""
        if self.is_database_candidate:
            return "database"
        if self is FileKind.XML_BINARY:
            return "xml"
        if self.is_sidecar:
            return self.value
        if self in (FileKind.XML, FileKind.JSON, FileKind.LOG):
            return self.value
        return "media" if self.is_media else "other"


class SqliteStatus(StrEnum):
    """What the scanner could establish about a database-like file from its bytes alone (no SQLite engine involved)."""

    VALID = "VALID"  # SQLite magic and a structurally valid header
    TRUNCATED = "TRUNCATED"  # valid header, but the file is shorter than it declares or ends mid-page
    CORRUPT_HEADER = "CORRUPT_HEADER"  # SQLite magic present, header fields invalid
    NOT_SQLITE = "NOT_SQLITE"  # database-like name, no SQLite magic (overwritten, corrupt or another format)
    ENCRYPTED_SUSPECT = "ENCRYPTED_SUSPECT"  # database-like name, no magic, high entropy — never decrypted
    EMPTY = "EMPTY"  # zero-length file with a database name
    UNREADABLE = "UNREADABLE"  # could not be read
    UNVERIFIED = "UNVERIFIED"  # SQLite magic seen at ingestion but the header was not inspected (no working copy)


class SidecarKind(StrEnum):
    WAL = "wal"
    SHM = "shm"
    JOURNAL = "journal"


class StorageClass(StrEnum):
    """SQLite's five storage classes — what a value *is* on disk, whatever its column declares (``typeof()`` spelling)."""

    NULL = "null"
    INTEGER = "integer"
    REAL = "real"
    TEXT = "text"
    BLOB = "blob"


class TypeAffinity(StrEnum):
    """A column's type affinity, derived from its declared type by SQLite's rules (fileformat/datatype3, section 3.1)."""

    INTEGER = "INTEGER"
    TEXT = "TEXT"
    BLOB = "BLOB"  # also "no declared type"
    REAL = "REAL"
    NUMERIC = "NUMERIC"


class TableKind(StrEnum):
    TABLE = "table"
    VIRTUAL = "virtual"  # CREATE VIRTUAL TABLE (FTS, R-Tree, …): its rows come from a module, not from a b-tree of its own
    SHADOW = "shadow"  # a table a virtual-table module keeps for itself (e.g. FTS5 ``<name>_content``)


class OpenStatus(StrEnum):
    """What happened when SQLite itself was asked to open the database's scratch copy (distinct from ``SqliteStatus``)."""

    OK = "ok"
    UNOPENABLE = "unopenable"  # header looked fine but SQLite refused (truncated / malformed pages …)
    HEADER_INVALID = "header_invalid"  # magic present, header fields invalid: not attempted
    NOT_SQLITE = "not_sqlite"  # no SQLite magic: not attempted
    ENCRYPTED_SUSPECT = "encrypted_suspect"  # no magic and high entropy: never opened
    UNREADABLE = "unreadable"  # the file could not be read
    NOT_PRESERVED = "not_preserved"  # case pipeline only: ingested without a working copy


class SourceType(StrEnum):
    DIRECTORY = "directory"
    ZIP = "zip"
    TAR = "tar"
    SINGLE_FILE = "single_file"


class TimestampFormat(StrEnum):
    UNIX_S = "unix_s"
    UNIX_MS = "unix_ms"
    UNIX_US = "unix_us"
    WEBKIT_US = "webkit_us"  # microseconds since 1601-01-01 UTC (Chromium)
    COCOA_S = "cocoa_s"
    FILE_MTIME = "file_mtime"


# ---------------------------------------------------------------- Android value enumerations


class AddressKind(StrEnum):
    PHONE = "phone"
    SHORTCODE = "shortcode"
    ALPHANUMERIC = "alphanumeric"
    EMPTY = "empty"
    UNKNOWN = "unknown"


class MessageDirection(StrEnum):
    RECEIVED = "RECEIVED"
    SENT = "SENT"
    DRAFT = "DRAFT"
    OUTBOX = "OUTBOX"
    FAILED = "FAILED"
    QUEUED = "QUEUED"
    UNRECOGNISED = "UNRECOGNISED"

    @classmethod
    def from_code(cls, code: int | None) -> Self | None:
        return None if code is None else _MESSAGE_DIRECTION.get(code, cls.UNRECOGNISED)


class CallType(StrEnum):
    INCOMING = "INCOMING"
    OUTGOING = "OUTGOING"
    MISSED = "MISSED"
    VOICEMAIL = "VOICEMAIL"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    ANSWERED_EXTERNALLY = "ANSWERED_EXTERNALLY"
    UNRECOGNISED = "UNRECOGNISED"

    @classmethod
    def from_code(cls, code: int | None) -> Self | None:
        return None if code is None else _CALL_TYPE.get(code, cls.UNRECOGNISED)

    @property
    def is_unanswered(self) -> bool:
        return self in (CallType.MISSED, CallType.REJECTED, CallType.BLOCKED)


class CallPresentation(StrEnum):
    ALLOWED = "ALLOWED"
    RESTRICTED = "RESTRICTED"
    UNKNOWN = "UNKNOWN"  # Android's own "caller id unknown" value (code 3)
    PAYPHONE = "PAYPHONE"
    UNRECOGNISED = "UNRECOGNISED"

    @classmethod
    def from_code(cls, code: int | None) -> Self | None:
        return None if code is None else _CALL_PRESENTATION.get(code, cls.UNRECOGNISED)


class PageTransition(StrEnum):
    """Chromium core transition type (``transition & 0xFF``)."""

    LINK = "LINK"
    TYPED = "TYPED"
    AUTO_BOOKMARK = "AUTO_BOOKMARK"
    AUTO_SUBFRAME = "AUTO_SUBFRAME"
    MANUAL_SUBFRAME = "MANUAL_SUBFRAME"
    GENERATED = "GENERATED"
    AUTO_TOPLEVEL = "AUTO_TOPLEVEL"
    FORM_SUBMIT = "FORM_SUBMIT"
    RELOAD = "RELOAD"
    KEYWORD = "KEYWORD"
    KEYWORD_GENERATED = "KEYWORD_GENERATED"
    UNRECOGNISED = "UNRECOGNISED"

    @classmethod
    def from_code(cls, code: int | None) -> Self | None:
        return None if code is None else _PAGE_TRANSITION.get(code & 0xFF, cls.UNRECOGNISED)


class TransitionQualifier(StrEnum):
    FORWARD_BACK = "FORWARD_BACK"
    FROM_ADDRESS_BAR = "FROM_ADDRESS_BAR"
    HOME_PAGE = "HOME_PAGE"
    FROM_API = "FROM_API"
    CHAIN_START = "CHAIN_START"
    CHAIN_END = "CHAIN_END"
    CLIENT_REDIRECT = "CLIENT_REDIRECT"
    SERVER_REDIRECT = "SERVER_REDIRECT"

    @classmethod
    def from_flags(cls, code: int) -> list[Self]:
        return [q for bit, q in _TRANSITION_QUALIFIER_BITS if code & bit]


class DownloadState(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETE = "COMPLETE"
    CANCELLED = "CANCELLED"
    INTERRUPTED = "INTERRUPTED"
    UNRECOGNISED = "UNRECOGNISED"

    @classmethod
    def from_code(cls, code: int | None) -> Self | None:
        return None if code is None else _DOWNLOAD_STATE.get(code, cls.UNRECOGNISED)


_MESSAGE_DIRECTION = {
    1: MessageDirection.RECEIVED, 2: MessageDirection.SENT, 3: MessageDirection.DRAFT,
    4: MessageDirection.OUTBOX, 5: MessageDirection.FAILED, 6: MessageDirection.QUEUED,
}
_CALL_TYPE = {
    1: CallType.INCOMING, 2: CallType.OUTGOING, 3: CallType.MISSED, 4: CallType.VOICEMAIL,
    5: CallType.REJECTED, 6: CallType.BLOCKED, 7: CallType.ANSWERED_EXTERNALLY,
}
_CALL_PRESENTATION = {
    1: CallPresentation.ALLOWED, 2: CallPresentation.RESTRICTED, 3: CallPresentation.UNKNOWN, 4: CallPresentation.PAYPHONE,
}
_PAGE_TRANSITION = {
    0: PageTransition.LINK, 1: PageTransition.TYPED, 2: PageTransition.AUTO_BOOKMARK, 3: PageTransition.AUTO_SUBFRAME,
    4: PageTransition.MANUAL_SUBFRAME, 5: PageTransition.GENERATED, 6: PageTransition.AUTO_TOPLEVEL,
    7: PageTransition.FORM_SUBMIT, 8: PageTransition.RELOAD, 9: PageTransition.KEYWORD, 10: PageTransition.KEYWORD_GENERATED,
}
_TRANSITION_QUALIFIER_BITS = (
    (0x01000000, TransitionQualifier.FORWARD_BACK), (0x02000000, TransitionQualifier.FROM_ADDRESS_BAR),
    (0x04000000, TransitionQualifier.HOME_PAGE), (0x08000000, TransitionQualifier.FROM_API),
    (0x10000000, TransitionQualifier.CHAIN_START), (0x20000000, TransitionQualifier.CHAIN_END),
    (0x40000000, TransitionQualifier.CLIENT_REDIRECT), (0x80000000, TransitionQualifier.SERVER_REDIRECT),
)
_DOWNLOAD_STATE = {
    0: DownloadState.IN_PROGRESS, 1: DownloadState.COMPLETE, 2: DownloadState.CANCELLED, 3: DownloadState.INTERRUPTED,
}


class CarveKind(StrEnum):
    """What a raw-carving pattern looks for."""

    PHONE_NUMBER = "phone_number"
    URL = "url"
    EMAIL = "email"
    TIMESTAMP_UNIX_SECONDS = "timestamp_unix_seconds"
    TIMESTAMP_UNIX_MILLIS = "timestamp_unix_millis"
    TIMESTAMP_TEXT = "timestamp_text"
    SMS_LIKE_TEXT = "sms_like_text"
    SQLITE_RECORD = "sqlite_record"


class EntityKind(StrEnum):
    """Nodes of the correlation graph."""

    PERSON = "person"
    PHONE_NUMBER = "phone_number"
    MESSAGE = "message"
    CALL = "call"
    CONTACT = "contact"
    APPLICATION = "application"
    DATABASE = "database"
    FILE = "file"
    TIMESTAMP = "timestamp"
    URL = "url"
    ARTIFACT = "artifact"
    CARVED = "carved_candidate"


class Relation(StrEnum):
    """Edges of the correlation graph."""

    SENT = "SENT"
    RECEIVED = "RECEIVED"
    CALLED = "CALLED"
    CONTACT_OF = "CONTACT_OF"
    FOUND_IN = "FOUND_IN"
    RECOVERED_FROM = "RECOVERED_FROM"
    CORRELATES_WITH = "CORRELATES_WITH"
