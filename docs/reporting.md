# The report (Phase 12)

`android-forensics report CASE --format html,json,csv,pdf` builds the same 16-section report in every format from one
`ReportModel` (`src/android_forensics/reporting/model.py`): HTML (self-contained, sortable/filterable in the browser), JSON
(the complete model, for programmatic use), CSV (one file per table-shaped section) and PDF (condensed, printable).

## The 16 sections

1. Case information (incl. "evidence at a glance") · 2. Examiner and tool information · 3. Evidence sources ·
4. Evidence hashes · 5. Acquisition summary · 6. Artifact summary · **7. Recovered deleted data** (+ recovery-potential
indicators and unrecoverable data) · 8. Active data · **9. Partial recoveries** · **10. Carved candidates** · 11. Timeline ·
**12. Correlation findings** · 13. Validation results · 14. Recovery methodology · 15. Limitations (+ the recoverability
disclaimer) · 16. Appendix (skipped entries, table catalogue, chain of custody, analysis runs, status glossary, how to
verify the evidence independently).

## Before and after recovery

Every report reflects **exactly what ran**, never what the tool is merely capable of. `ReportModel.recovery["performed"]`
and `.recovery["stages_run"]` (one bool per `recover`/`carve`/`correlate`/`reconstruct`) come straight from
`CaseStore.last_run(stage)`:

* **Recovery never ran** (`scan → extract → validate → timeline`, the Review 1 default pipeline): sections 7, 9, 10 and 12
  each show a `NOT PERFORMED (Review 2)` box with a specific explanation of what that means (`reporting/text.py`'s
  `NOT_PERFORMED`), the "at a glance" cards read `not performed` / `not classified`, and the top banner reads
  "Review 1 — forensic foundation."
* **Recovery ran**: those sections show the real `recovered_records`, `carved_candidates` and `correlations` rows — table,
  method, region, unknown columns, and every recovered or carved item's confidence *with its explanation sentence*, never
  a bare label. The banner reads "Review 1 + Review 2 — deleted-data recovery performed," section 14's last item is replaced
  with the recovery/carving/correlation methodology actually used, and section 15's first limitation states plainly that
  recovery ran (the disclaimer above it is unchanged — recoverability limits apply either way).

A carved candidate's status is always rendered as the literal `CARVED CANDIDATE` (never simplified to a badge that could be
mistaken for a confirmed status), and its confidence is never `HIGH` — the same invariant the model and the database enforce.

## The PDF

`reporting/pdf.py` renders the identical 16 sections with fpdf2's core (latin-1) fonts — no external font file to bundle,
at the cost of replacing any character outside latin-1 rather than dropping or mangling it (`_txt`). Tables are one line per
row (long cells are truncated to fit, never wrapped, so row height stays predictable on a printed page) and capped at 40
rows with a note pointing at `report.json` / the CSV export for the rest, the same idea as the HTML report's own row cap.

## CSV exports

`csv/evidence_files.csv`, `artifacts.csv`, `timeline.csv`, `validation.csv`, `databases.csv`, `scan_issues.csv` always;
`recovered_records.csv`, `partial_recoveries.csv`, `unrecoverable_regions.csv` when recovery ran; `carved_candidates.csv`
when carving ran; `correlations.csv` when correlation ran. Every file's SHA-256 is listed in `sha256sums.txt` beside it.

## Tests

`tests/integration/test_report.py` builds two reports: the existing Review 1 `analyzed` fixture (asserts all four Review 2
sections show `NOT PERFORMED (Review 2)`, and that a PDF built from it says the same) and a new case that goes through the
full recovery pipeline (asserts the opposite for every format: HTML has no `NOT PERFORMED` left, JSON's recovered/partial/
carved rows carry a real confidence and an explanation that starts with it, the new CSV files exist and have rows, and the
PDF — read back with `pypdf` — contains every section heading and the real recovery content, never `NOT PERFORMED`).
