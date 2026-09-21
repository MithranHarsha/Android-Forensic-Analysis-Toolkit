"""Run all validation checks and persist every result."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from android_forensics.models import ValidationResult
from android_forensics.progress import NullProgress, Progress
from android_forensics.storage.case_store import CaseStore
from android_forensics.validation.checks import CHECKS, Options


@dataclass
class ValidationSummary:
    total: int = 0
    by_status: Counter = field(default_factory=Counter)
    by_check: dict[str, Counter] = field(default_factory=dict)


def run_validation(store: CaseStore, run_id: int, progress: Progress | None = None, rehash_originals: bool = True) -> ValidationSummary:
    opts = Options(rehash_originals=rehash_originals, progress=progress or NullProgress())
    summary = ValidationSummary()
    results: list[ValidationResult] = []
    for check in CHECKS:
        for result in check(store, opts):
            results.append(result)
            summary.total += 1
            summary.by_status[result.status.value] += 1
            summary.by_check.setdefault(result.check.value, Counter())[result.status.value] += 1
    store.add_validation_results(run_id, results)
    return summary
