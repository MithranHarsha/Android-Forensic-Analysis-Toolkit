"""The confidence scorer (Phase 8).

Confidence answers *"how sure is the tool that these bytes are a genuine record of what they claim to be?"* — not how
important the record is. It is computed from explicit factors, each with a weight and a sentence, combined by a fixed rule.
The same input always yields the same assessment; there is no model and no randomness.

**Factors** (weight): schema match (2) · valid record structure (2) · valid serial types (1) · field consistency (1.5) ·
page integrity (1) · source provenance (1.5) · timestamp validity (1, only if the record has a timestamp) · raw-byte
completeness (1.5) · cross-artifact corroboration (2) · the same record found in several places (0.5).

**Level.** ``score = Σ weight·satisfied / Σ weight``: HIGH ≥ 0.85, MEDIUM ≥ 0.60, otherwise LOW — then the *caps*, which no
score can exceed:

* no schema match or an inexact record structure → LOW (a byte run that does not fit a table is not a record of it);
* CORRUPTED → LOW; PARTIAL → at most MEDIUM, unless two independent sources corroborate it;
* RECOVERED → HIGH only if its source is verified and its fields are consistent;
* a carved candidate → at most MEDIUM, and LOW without corroboration (it is not confirmed evidence).
"""

from __future__ import annotations

from dataclasses import dataclass

from android_forensics.models import ArtifactStatus, Confidence, ConfidenceAssessment, ConfidenceFactor

HIGH_AT, MEDIUM_AT = 0.85, 0.60
_VERIFIED_FRAME_STATUSES = {"committed", "uncommitted", "stale_generation"}


@dataclass(frozen=True)
class RecoveryEvidence:
    """Everything the scorer knows about one recovered record."""

    status: ArtifactStatus
    source: str  # main | wal | journal
    frame_status: str | None = None  # WAL: committed / uncommitted / stale_generation / stale_unverified / corrupt
    journal_verified: bool = True  # journal: the record's checksum verified
    fit: float = 1.0  # agreement of every column with its declared affinity
    schema_matched: bool = True  # fitted to a table whose schema is known
    parser_score: float | None = None  # how well an artifact parser's schema knowledge matched the table (None: no parser)
    exact_structure: bool = True  # header size + body == payload size, and the cell ends where a cell can end
    unknown_fields: tuple[str, ...] = ()  # columns the bytes do not determine (a lost rowid alias included)
    rowid_known: bool = False
    field_problems: tuple[str, ...] = ()
    timestamp_plausible: bool | None = None  # None: the record carries no timestamp
    page_valid: bool = True
    corroborations: tuple[str, ...] = ()  # independent sources that support it, e.g. "contact Ann Lee", "call log (3 calls)"
    other_locations: int = 0  # other places the same record was found
    untouched_cell: bool = False  # the whole cell survived (payload size and rowid included)


@dataclass(frozen=True)
class CarveEvidence:
    kind: str
    context_valid: bool = True  # the surrounding bytes are consistent with the pattern (e.g. a plausible number of digits)
    value_valid: bool = True  # the value itself validates (a date in range, a number of plausible length, …)
    corroborations: tuple[str, ...] = ()
    inside_known_structure: bool = False  # found inside a parsed page rather than in loose bytes


def _f(name: str, ok: bool, weight: float, explanation: str) -> ConfidenceFactor:
    return ConfidenceFactor(name=name, satisfied=ok, weight=weight, explanation=explanation)


def _level(score: float) -> Confidence:
    return Confidence.HIGH if score >= HIGH_AT else Confidence.MEDIUM if score >= MEDIUM_AT else Confidence.LOW


def _cap(level: Confidence, ceiling: Confidence) -> Confidence:
    return level if level.rank <= ceiling.rank else ceiling


def _ratio(factors: list[ConfidenceFactor]) -> float:
    total = sum(f.weight for f in factors)
    return round(sum(f.weight for f in factors if f.satisfied) / total, 4) if total else 0.0


# ------------------------------------------------------------------ recovered records


def recovery_factors(e: RecoveryEvidence) -> list[ConfidenceFactor]:
    unknown = [u for u in e.unknown_fields]
    if e.source == "wal":
        verified = e.frame_status in _VERIFIED_FRAME_STATUSES
        source_text = {
            "committed": "read from a committed WAL frame whose salts and checksum chain verify",
            "uncommitted": "read from a valid WAL frame of an uncommitted transaction",
            "stale_generation": "read from a stale WAL frame whose checksum chain verifies against its predecessor",
        }.get(e.frame_status or "", f"read from a WAL frame that cannot be verified ({e.frame_status})")
    elif e.source == "journal":
        verified = e.journal_verified
        source_text = "read from a rollback-journal page record whose checksum verifies" if verified else "read from a journal record whose checksum does not verify"
    else:
        verified = True
        source_text = "read from a page of the evidence database file itself"
    factors = [
        _f("schema_match", e.schema_matched and e.fit >= 0.9, 2.0,
           "the bytes fit a table of this database exactly (column count and types agree with its declared schema)" if e.schema_matched and e.fit >= 0.9
           else "the bytes only loosely agree with the declared column types"),
        _f("valid_record_structure", e.exact_structure, 2.0,
           "the record header, body and cell length are mutually consistent" if e.exact_structure else "the record's length could not be confirmed against a cell boundary"),
        _f("valid_serial_types", e.fit >= 0.999, 1.0,
           "every serial type is legal and matches its column's declared type" if e.fit >= 0.999 else "some serial types are legal but atypical for their column"),
        _f("field_consistency", not e.field_problems and e.status is not ArtifactStatus.CORRUPTED, 1.5,
           "every field decodes and validates (text is valid, types match)" if not e.field_problems and e.status is not ArtifactStatus.CORRUPTED
           else "a field fails validation: " + "; ".join(e.field_problems[:2] or ("the record is corrupted",))),
        _f("page_integrity", e.page_valid and e.frame_status != "corrupt", 1.0,
           "the page image has a valid header and free-space structure" if e.page_valid else "the page image has structural problems"),
        _f("source_provenance", verified, 1.5, source_text),
        _f("raw_byte_completeness", not unknown and e.rowid_known, 1.5,
           "every field and the rowid were recovered" if not unknown and e.rowid_known
           else "not everything was recovered: " + (", ".join(unknown) + " unknown" if unknown else "rowid unknown")),
        _f("cross_artifact_corroboration", bool(e.corroborations), 2.0,
           "corroborated by " + " and ".join(e.corroborations) if e.corroborations else "no independent source corroborates it"),
        _f("multiple_locations", e.other_locations > 0, 0.5,
           f"the same record was also found in {e.other_locations} other location(s)" if e.other_locations else "found in one place only"),
    ]
    if e.timestamp_plausible is not None:
        factors.append(_f("timestamp_validity", e.timestamp_plausible, 1.0,
                          "its timestamp is inside the plausible window" if e.timestamp_plausible else "its timestamp is outside the plausible window"))
    return factors


def score_recovered(e: RecoveryEvidence) -> ConfidenceAssessment:
    factors = recovery_factors(e)
    score = _ratio(factors)
    level = _level(score)
    by = {f.name: f for f in factors}
    if not by["schema_match"].satisfied or not by["valid_record_structure"].satisfied:
        level = Confidence.LOW
    if e.status is ArtifactStatus.CORRUPTED:
        level = Confidence.LOW
    elif e.status is ArtifactStatus.PARTIAL and len(e.corroborations) < 2:
        level = _cap(level, Confidence.MEDIUM)
    if level is Confidence.HIGH and not (by["source_provenance"].satisfied and by["field_consistency"].satisfied):
        level = Confidence.MEDIUM
    return ConfidenceAssessment(level=level, score=score, factors=factors, explanation=_explain_recovered(level, e, by))


def _explain_recovered(level: Confidence, e: RecoveryEvidence, by: dict[str, ConfidenceFactor]) -> str:
    reconstruction = ("full page-level reconstruction (the whole cell survived)" if e.untouched_cell
                      else "reconstruction from a freed cell whose header bytes were overwritten (rowid lost)")
    good = [reconstruction]
    if by["schema_match"].satisfied:
        good.append("schema match")
    if e.corroborations:
        good.append("corroborated by " + " and ".join(e.corroborations))
    if e.other_locations:
        good.append(f"also found in {e.other_locations} other location(s)")
    limits = [f.explanation for f in by.values() if not f.satisfied and f.name not in ("cross_artifact_corroboration", "multiple_locations")]
    if not e.corroborations and level is not Confidence.HIGH:
        limits.append("no independent corroboration")
    text = f"{level.value}: " + ", ".join(good)
    if limits and level is not Confidence.HIGH:
        text += "; limited by " + "; ".join(limits)
    return text + "."


# ------------------------------------------------------------------ carved candidates


def score_carved(e: CarveEvidence) -> ConfidenceAssessment:
    factors = [
        _f("value_validity", e.value_valid, 2.0, "the value validates (plausible length, range or format)" if e.value_valid else "the value does not validate"),
        _f("context_consistency", e.context_valid, 1.0,
           "the surrounding bytes are consistent with the pattern" if e.context_valid else "the surrounding bytes do not support the pattern"),
        _f("structured_location", e.inside_known_structure, 1.0,
           "found inside a parsed database page" if e.inside_known_structure else "found in loose bytes outside any parsed structure"),
        _f("cross_artifact_corroboration", bool(e.corroborations), 3.0,
           "the same value appears in " + " and ".join(e.corroborations) if e.corroborations else "no artifact carries this value"),
    ]
    score = _ratio(factors)
    level = _level(score)
    level = _cap(level, Confidence.MEDIUM)  # never confirmed evidence on its own
    if not e.corroborations:
        level = Confidence.LOW
    if not e.value_valid:
        level = Confidence.LOW
    why = "corroborated by " + " and ".join(e.corroborations) if e.corroborations else "no artifact carries this value, so it stays an unconfirmed candidate"
    return ConfidenceAssessment(level=level, score=score, factors=factors, explanation=f"{level.value}: carved {e.kind} pattern match; {why}.")


__all__ = ["CarveEvidence", "RecoveryEvidence", "recovery_factors", "score_carved", "score_recovered"]
