"""Charts for the Review 2 experiments (Phase 15). Reads the CSVs ``r2_recovery.py`` wrote; draws nothing it did not
first read from them -- every number on every chart traces back to a measured run.

Usage:  python experiments/r2_charts.py    (after r2_recovery.py; writes experiments/results/*.png)
"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

OUT = Path(__file__).parent / "results"


def _rows(name: str) -> list[dict]:
    with open(OUT / name, newline="") as fh:
        return list(csv.DictReader(fh))


def chart_recall_by_condition() -> None:
    rows = _rows("r2_e6_recovery_matrix.csv")
    rows.sort(key=lambda r: float(r["recall"]))
    names = [r["case"] for r in rows]
    recall = [float(r["recall"]) * 100 for r in rows]
    precision = [float(r["precision"]) * 100 for r in rows]

    fig, ax = plt.subplots(figsize=(11, max(4, 0.28 * len(rows))))
    y = range(len(rows))
    ax.barh([i + 0.2 for i in y], recall, height=0.4, label="Recall", color="#1f77b4")
    ax.barh([i - 0.2 for i in y], precision, height=0.4, label="Precision", color="#2ca02c")
    ax.set_yticks(list(y))
    ax.set_yticklabels(names, fontsize=8)
    ax.set_xlabel("Percent")
    ax.set_xlim(0, 105)
    ax.axvline(100, color="grey", linewidth=0.5, linestyle="--")
    ax.set_title("Recovery matrix: precision and recall by condition")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(OUT / "r2_recall_by_condition.png", dpi=140)
    plt.close(fig)


def chart_status_breakdown() -> None:
    rows = _rows("r2_e6_recovery_matrix.csv")
    recovered = sum(int(r["recovered_count"]) for r in rows)
    partial = sum(int(r["partial_count"]) for r in rows)
    expected = sum(int(r["expected_recoverable"]) for r in rows)
    missed = max(0, expected - recovered - partial)

    fig, ax = plt.subplots(figsize=(6, 4.5))
    labels = ["RECOVERED", "PARTIAL", "missed"]
    values = [recovered, partial, missed]
    colors = ["#2ca02c", "#ff7f0e", "#d62728"]
    ax.bar(labels, values, color=colors)
    for i, v in enumerate(values):
        ax.text(i, v + max(values) * 0.01, str(v), ha="center", fontsize=9)
    ax.set_ylabel("Rows")
    ax.set_title(f"Recovery matrix outcome\n({expected} physically recoverable rows)")
    fig.tight_layout()
    fig.savefig(OUT / "r2_status_breakdown.png", dpi=140)
    plt.close(fig)


def chart_confidence_calibration() -> None:
    rows = _rows("r2_e7_confidence_calibration.csv")
    by_level: dict[str, list[int]] = {}
    for r in rows:
        if r["matches_planted_row"] in ("", "None"):
            continue
        level = r["confidence"] or "NONE"
        by_level.setdefault(level, [0, 0])
        by_level[level][0] += 1
        by_level[level][1] += r["matches_planted_row"] == "True"
    color_by_level = {"LOW": "#d62728", "MEDIUM": "#ff7f0e", "HIGH": "#2ca02c"}
    order = [lvl for lvl in ("LOW", "MEDIUM", "HIGH") if lvl in by_level]
    order += [lvl for lvl in by_level if lvl not in order]
    shares = [by_level[lvl][1] / by_level[lvl][0] * 100 if by_level[lvl][0] else 0 for lvl in order]
    counts = [by_level[lvl][0] for lvl in order]

    fig, ax = plt.subplots(figsize=(6, 4.5))
    bars = ax.bar(order, shares, color=[color_by_level.get(lvl, "#7f7f7f") for lvl in order])
    for bar, n in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, f"n={n}", ha="center", fontsize=9)
    ax.set_ylim(0, 110)
    ax.set_ylabel("Share matching the deleted row's actual values (%)")
    ax.set_title("Confidence calibration:\nis a higher level actually more often correct?")
    fig.tight_layout()
    fig.savefig(OUT / "r2_confidence_calibration.png", dpi=140)
    plt.close(fig)


def main() -> None:
    chart_recall_by_condition()
    chart_status_breakdown()
    chart_confidence_calibration()
    print("wrote", *(p.name for p in OUT.glob("r2_*.png")))


if __name__ == "__main__":
    main()
