"""The stable surface for parser plugins. Import from here, not from the internal modules, in third-party code.

A plugin is a Python file (or an installed package advertising the ``android_forensics.parsers`` entry-point group) that,
when imported, registers one or more :class:`ArtifactParser` subclasses with :func:`register`::

    from android_forensics.plugin_api import (ArtifactParser, CallRecord, DbContext, FieldReader, FieldSpec, RoleMatch,
                                              RowSource, SchemaMatch, best_matches, build_envelope, register)

    @register
    class AcmeCalls(ArtifactParser):
        name = "acme_calls"
        ...

Plugins produce the *existing* artifact types (SMS, call, contact, browser visit/download, generic record) so that
validation, correlation, confidence scoring, the timeline and the report all work on their output unchanged. Their output is
tagged with the parser name and version, and the report lists every plugin that was loaded together with its SHA-256.

A plugin is **code that runs with your privileges**: load only plugins you wrote or reviewed, never anything from evidence.
"""

from android_forensics.artifacts.base import ArtifactParser, DbContext, FieldReader, RowSource, build_envelope
from android_forensics.artifacts.registry import register
from android_forensics.artifacts.schema_probe import FieldSpec, RoleMatch, SchemaMatch, best_matches
from android_forensics.artifacts.timestamps import convert
from android_forensics.models import (
    UNKNOWN,
    BrowserDownload,
    BrowserHistoryEntry,
    CallRecord,
    Contact,
    GenericRecord,
    SMSMessage,
    TimestampFormat,
)
from android_forensics.normalization.phone import phone_key
from android_forensics.sqlite.reader import SchemaObject, SQLiteSession

__all__ = [
    "UNKNOWN", "ArtifactParser", "BrowserDownload", "BrowserHistoryEntry", "CallRecord", "Contact", "DbContext", "FieldReader",
    "FieldSpec", "GenericRecord", "RoleMatch", "RowSource", "SMSMessage", "SQLiteSession", "SchemaMatch", "SchemaObject",
    "TimestampFormat", "best_matches", "build_envelope", "convert", "phone_key", "register",
]
