"""Score recovered rows against a deletion case's ground truth.

A recovered row *matches* a deleted row when every value it claims to know equals the truth (an UNKNOWN value claims
nothing). A recovered row that matches no deleted row is a false positive — including one that reports a known value wrongly.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from android_forensics.models.unknown import UNKNOWN


@dataclass
class CaseScore:
    deleted: int
    expected_recoverable: int  # deleted rows whose bytes survive in some file (expected class != UNRECOVERABLE)
    recovered_rows: int  # rows the engine reported
    matched: int  # distinct deleted rows matched by at least one recovered row
    matched_expected: int  # ... of which were expected to be recoverable
    false_positives: int
    class_correct: int  # matched rows whose reported status equals the expected class
    unexpected: int  # matched although expected UNRECOVERABLE (bytes survive somewhere the truth search did not look)
    by_status: dict[str, int] = field(default_factory=dict)
    by_method: dict[str, int] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        return (self.recovered_rows - self.false_positives) / self.recovered_rows if self.recovered_rows else 1.0

    @property
    def recall(self) -> float:
        return self.matched_expected / self.expected_recoverable if self.expected_recoverable else 1.0

    @property
    def recovery_rate(self) -> float:
        return self.matched / self.deleted if self.deleted else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / self.recovered_rows if self.recovered_rows else 0.0


def matches(values: dict[str, Any], truth_values: dict[str, Any]) -> bool:
    known = {k: v for k, v in values.items() if v is not UNKNOWN}
    return bool(known) and all(k in truth_values and truth_values[k] == v for k, v in known.items())


def score_case(truth: dict[str, Any], rows: Iterable[Any]) -> CaseScore:
    """``rows``: objects with ``.values`` (column -> value | UNKNOWN), ``.status`` and ``.method``."""
    deleted = truth["deleted_rows"]
    expected = {r["id"]: r["expected_class"] for r in deleted}
    by_id = {r["id"]: r["values"] for r in deleted}
    rows = list(rows)
    matched_ids: set[int] = set()
    fp = class_ok = 0
    by_status: dict[str, int] = {}
    by_method: dict[str, int] = {}
    for row in rows:
        hits = [i for i, tv in by_id.items() if matches(row.values, tv)]
        by_status[str(row.status)] = by_status.get(str(row.status), 0) + 1
        by_method[str(row.method)] = by_method.get(str(row.method), 0) + 1
        if not hits:
            fp += 1
            continue
        for i in hits:
            if i not in matched_ids:
                matched_ids.add(i)
                class_ok += str(row.status) == expected[i]
    expected_ids = {i for i, c in expected.items() if c != "UNRECOVERABLE"}
    return CaseScore(
        deleted=len(deleted), expected_recoverable=len(expected_ids), recovered_rows=len(rows), matched=len(matched_ids),
        matched_expected=len(matched_ids & expected_ids), false_positives=fp, class_correct=class_ok,
        unexpected=len(matched_ids - expected_ids), by_status=by_status, by_method=by_method,
    )
