"""Evidence ingestion. Use ``ingest_evidence`` (no database) or ``ingest_source`` (into a case)."""

from android_forensics.acquisition.base import AcquisitionIssue, PreservePolicy
from android_forensics.acquisition.ingest import IngestSummary, ingest_source, manifest_from_store, write_case_manifest
from android_forensics.acquisition.manifest import (
    Discrepancy,
    VerificationReport,
    make_manifest,
    read_manifest,
    verify_manifest,
    write_manifest_file,
)
from android_forensics.acquisition.safety import ExtractionBudget
from android_forensics.acquisition.session import IngestionResult, IngestionSession, IngestionTotals, ingest_evidence

__all__ = [
    "AcquisitionIssue", "Discrepancy", "ExtractionBudget", "IngestSummary", "IngestionResult", "IngestionSession",
    "IngestionTotals", "PreservePolicy", "VerificationReport", "ingest_evidence", "ingest_source",
    "make_manifest", "manifest_from_store", "read_manifest", "verify_manifest", "write_case_manifest",
    "write_manifest_file",
]
