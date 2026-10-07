"""PDF rendering of the forensic report (Phase 12): the same 16 sections and the same numbers as the HTML report, in a
condensed, printable form. Built with fpdf2's core (latin-1) fonts, so any character outside that range is replaced --
never dropped silently and never let through as mojibake -- by :func:`_txt`.

Tables are capped at ``PDF_ROW_CAP`` rows (tighter than the HTML cap, since a PDF page is fixed-width): a note says so and
points at ``report.json`` / the CSV files for the rest, exactly as the HTML report already does for its own cap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fpdf import FPDF

from android_forensics.reporting.model import ReportModel

PDF_ROW_CAP = 40
_PAGE_W = 190  # usable width in mm at A4 with default 10mm margins


def _txt(v: Any) -> str:
    s = "" if v is None else str(v)
    return s.encode("latin-1", "replace").decode("latin-1")


class Report(FPDF):
    title_line: str = ""

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, _txt(self.title_line), align="L")
        self.set_text_color(0, 0, 0)
        self.ln(10)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, f"Page {self.page_no()}", align="C")
        self.set_text_color(0, 0, 0)


def _section(pdf: Report, number: int, title: str) -> None:
    pdf.add_page()
    pdf.set_font("helvetica", "B", 15)
    pdf.cell(0, 10, _txt(f"{number}. {title}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(180, 180, 180)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + _PAGE_W, pdf.get_y())
    pdf.ln(4)


def _para(pdf: Report, text: str, *, style: str = "", size: int = 10, align: str = "L") -> None:
    pdf.set_font("helvetica", style, size)
    pdf.multi_cell(0, 5.5, _txt(text), align=align, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _kv(pdf: Report, pairs: list[tuple[str, Any]]) -> None:
    for k, v in pairs:
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(55, 6, _txt(k), new_x="RIGHT", new_y="TOP")
        pdf.set_font("helvetica", "", 10)
        pdf.multi_cell(0, 6, _txt(v if v not in (None, "") else "-"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _fit(pdf: Report, value: Any, width: float) -> str:
    """``value`` truncated (character by character) until it fits ``width`` mm at the current font -- single-line cells only,
    which keeps a table's row height fixed and predictable on a printed page."""
    s = _txt(value)
    limit = width - 2
    if pdf.get_string_width(s) <= limit:
        return s
    while s and pdf.get_string_width(s) > limit:
        s = s[:-1]
    return s


def _table_header(pdf: Report, columns: list[tuple[str, int]]) -> None:
    pdf.set_font("helvetica", "B", 8.5)
    pdf.set_fill_color(235, 237, 240)
    for header, width in columns:
        pdf.cell(width, 6, _txt(header), border=1, fill=True)
    pdf.ln()
    pdf.set_font("helvetica", "", 8)


def _table(pdf: Report, columns: list[tuple[str, int]], rows: list[list[Any]], *, cap: int = PDF_ROW_CAP, total: int | None = None) -> None:
    """``columns`` is ``[(header, width_mm), ...]``; widths should sum to roughly ``_PAGE_W``. One line per row: long cell
    text is truncated to fit rather than wrapped, so every row has the same, predictable height."""
    if not rows:
        _para(pdf, "None.", style="I")
        return
    _table_header(pdf, columns)
    for row in rows[:cap]:
        if pdf.get_y() > 270:
            pdf.add_page()
            _table_header(pdf, columns)
        for (_, width), value in zip(columns, row):
            pdf.cell(width, 5.5, _fit(pdf, value, width), border=1)
        pdf.ln()
    n = len(rows)
    if total is None:
        total = n
    if n > cap or total > cap:
        _para(pdf, f"Showing the first {min(cap, n)} of {total} rows. The complete data is in report.json and the CSV files.", style="I", size=8)


def render_pdf(model: ReportModel, path: Path) -> None:
    """Write the report as a PDF to ``path``. Deterministic given ``model``: no timestamp beyond what the model itself carries."""
    r = model
    pdf = Report(format="A4")
    pdf.title_line = f"{r.meta['case_name']} - {r.meta['tool_name']} {r.meta['tool_version']}"
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.add_page()
    pdf.set_font("helvetica", "B", 22)
    pdf.ln(30)
    pdf.multi_cell(0, 10, _txt("Android Forensic Examination Report"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 13)
    pdf.ln(4)
    pdf.multi_cell(0, 7, _txt(r.meta["case_name"]), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 10)
    pdf.multi_cell(0, 6, _txt(f"Generated {r.meta['generated_at']} - {r.meta['tool_name']} {r.meta['tool_version']}"), align="C",
                  new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    pdf.set_font("helvetica", "I", 9)
    if r.details.get("classification"):
        pdf.set_font("helvetica", "B", 11)
        pdf.multi_cell(0, 6, _txt(r.details["classification"]), align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "I", 9)
    banner = "Review 1 + Review 2 - deleted-data recovery performed." if r.recovery["performed"] else "Review 1 - forensic foundation."
    pdf.multi_cell(0, 6, _txt(f"{banner} {r.meta['review_scope']}"), align="C", new_x="LMARGIN", new_y="NEXT")

    # 1. Case information
    _section(pdf, 1, "Case information")
    _kv(pdf, [("Case name", r.meta["case_name"]), ("Case ID", r.meta["case_id"]), ("Description", r.meta["description"]),
              ("Case created (UTC)", r.meta["created_at"]), ("Report generated (UTC)", r.meta["generated_at"])])
    _para(pdf, "Evidence at a glance:", style="B")
    for g in r.at_a_glance:
        value = g["value"] if isinstance(g["value"], str) else f"{g['value']:,}"
        _para(pdf, f"- {g['label']}: {value}  ({g['note']})")

    # 2. Examiner and tool information
    _section(pdf, 2, "Examiner and tool information")
    _kv(pdf, [("Examiner", r.meta["examiner"]), ("Tool", f"{r.meta['tool_name']} {r.meta['tool_version']}"),
              ("Python", r.meta["python"]), ("SQLite library", r.meta["sqlite_library"]), ("Platform", r.meta["platform"])])
    labels = [("case_number", "Case / reference number"), ("agency", "Requesting agency"), ("requested_by", "Requested by"),
              ("jurisdiction", "Jurisdiction"), ("evidence_description", "Evidence description"), ("evidence_received_on", "Evidence received"),
              ("examination_started", "Examination started"), ("examiner_title", "Examiner title"),
              ("examiner_organisation", "Organisation / laboratory"), ("examiner_accreditation", "Accreditation"),
              ("examiner_email", "Contact e-mail"), ("examiner_phone", "Contact phone")]
    if r.details:
        _para(pdf, "Case details and examiner credentials:", style="B")
        shown = {k for k, _ in labels} | {"classification", "footer", "statement"}
        _kv(pdf, [(lab, r.details[k]) for k, lab in labels if r.details.get(k)]
            + [(k.replace("_", " ").capitalize(), v) for k, v in r.details.items() if k not in shown])
    _para(pdf, "Examiner certification:", style="B")
    _para(pdf, r.details.get("statement") or "I certify that this report accurately describes the examination performed and its results. "
          "Every finding is derived from the evidence hashes listed in section 4 using the tool and build identified above.")
    _para(pdf, f"Examiner signature: ______________________   Name: {r.meta['examiner'] or '-'}   Date: ____________")

    # 3. Evidence sources
    _section(pdf, 3, "Evidence sources")
    _table(pdf, [("Source", 25), ("Path", 75), ("Type", 25), ("Files", 20), ("Complete", 25)],
          [[f"s{s['id']}", s["original_path"], s["source_type"], f"{s['file_count']:,}", "yes" if s["complete"] else "NO"] for s in r.sources])

    # 4. Evidence hashes
    _section(pdf, 4, "Evidence hashes")
    _para(pdf, "SHA-256 is the integrity anchor. The complete list is in evidence_manifest.json, report.json and csv/evidence_files.csv.")
    _table(pdf, [("Path", 70), ("Kind", 25), ("Size", 20), ("SHA-256", 75)],
          [[f["path"], f["kind"], f"{f['size']:,}", f["sha256"]] for f in r.evidence_files], total=len(r.evidence_files))

    # 5. Acquisition summary
    _section(pdf, 5, "Acquisition summary")
    _kv(pdf, [("Files hashed", f"{r.acquisition['files']:,}"), ("Write-protected working copies", r.acquisition["preserved_copies"]),
              ("Acquisition complete", "yes" if r.acquisition["all_complete"] else "NO"), ("Detected layout", r.acquisition["layout"])])
    _para(pdf, "SQLite databases:", style="B")
    _table(pdf, [("Database", 60), ("Status", 25), ("Open", 20), ("Integrity", 25), ("Tables", 20), ("Artifacts", 20)],
          [[d["path"], d["sqlite_status"], d["open_status"], d["integrity"] or "-", d["tables"], d["artifacts"]] for d in r.databases])

    # 6. Artifact summary
    _section(pdf, 6, "Artifact summary")
    _table(pdf, [("Type", 60), ("Count", 30)], [[t, f"{n:,}"] for t, n in r.artifact_summary["by_type"].items()])

    # 7. Recovered deleted data
    _section(pdf, 7, "Recovered deleted data")
    if r.recovery["stages_run"]["recover"]:
        recon = r.recovery["recovered"] + r.recovery["corrupted"]
        _para(pdf, "Records reconstructed from freed cells, released pages, stale page images and WAL/journal history. "
                   "A column the bytes did not determine is never guessed.")
        _table(pdf, [("Status", 22), ("Table", 22), ("Rowid", 16), ("Method", 24), ("Confidence", 20), ("Explanation", 86)],
              [[row["status"], row["table"], row["rowid"] if row["rowid"] is not None else "unknown", row["method"],
                row["confidence"] or "-", row["explanation"]] for row in recon])
    else:
        _para(pdf, f"NOT PERFORMED (Review 2). {r.recovery['messages']['recovered']}", style="I")
    _para(pdf, "Recovery-potential indicators:", style="B")
    _table(pdf, [("Database", 60), ("Freelist pages", 25), ("WAL frame slots", 25), ("Notes", 80)],
          [[i["path"], i["freelist_pages"], i["wal_frame_slots"], "; ".join(i["notes"])[:300]] for i in r.recovery["indicators"]])
    _para(pdf, "Unrecoverable data:", style="B")
    if r.recovery["stages_run"]["recover"]:
        _table(pdf, [("Source", 60), ("Region", 30), ("Reason", 100)],
              [[u["source_path"], u["region"], u["reason"]] for u in r.recovery["unrecoverable"]])
    else:
        _para(pdf, r.recovery["messages"]["unrecoverable"], style="I")

    # 8. Active data
    _section(pdf, 8, "Active data")
    _para(pdf, "Records present in the live database view. Full provenance for each row is in report.json / the CSV export.")
    for key, sec in r.active.items():
        if not sec["total"]:
            continue
        _para(pdf, f"{sec['title']} ({sec['total']:,})", style="B")
        col_w = _PAGE_W // len(sec["columns"])
        _table(pdf, [(c, col_w) for c in sec["columns"]], [row["cells"] for row in sec["rows"]], total=sec["total"])

    # 9. Partial recoveries
    _section(pdf, 9, "Partial recoveries")
    if r.recovery["stages_run"]["recover"]:
        _table(pdf, [("Table", 25), ("Method", 25), ("Unknown columns", 55), ("Confidence", 20), ("Explanation", 65)],
              [[row["table"], row["method"], ", ".join(row["unknown_columns"]), row["confidence"] or "-", row["explanation"]]
               for row in r.recovery["partial"]])
    else:
        _para(pdf, f"NOT PERFORMED (Review 2). {r.recovery['messages']['partial']}", style="I")

    # 10. Carved candidates
    _section(pdf, 10, "Carved candidates")
    if r.recovery["stages_run"]["carve"]:
        _para(pdf, "Every row here is an unconfirmed candidate: status literally CARVED CANDIDATE, never presented as evidence.")
        _table(pdf, [("Kind", 25), ("Matched", 55), ("Container", 25), ("Confidence", 20), ("Explanation", 65)],
              [[c["kind"], (c["matched"] or "")[:80], c["container"], c["confidence"] or "-", c["explanation"]] for c in r.recovery["carved"]])
    else:
        _para(pdf, f"NOT PERFORMED (Review 2). {r.recovery['messages']['carved']}", style="I")

    # 11. Timeline
    _section(pdf, 11, "Timeline")
    _para(pdf, "Chronological (UTC). File events are filesystem metadata, not evidence of user activity.")
    _table(pdf, [("Timestamp", 35), ("State", 22), ("Type", 22), ("Event", 81), ("Source", 30)],
          [[e["ts_utc"], e["status"] or "FILE", e["artifact_type"] or "file", e["event"], e["source"].rsplit("/", 1)[-1]] for e in r.timeline],
          total=len(r.timeline))

    # 12. Correlation findings
    _section(pdf, 12, "Correlation findings")
    if r.recovery["stages_run"]["correlate"]:
        _table(pdf, [("Source", 55), ("Relation", 25), ("Target", 55), ("Explanation", 55)],
              [[e["source"], e["relation"], e["target"], e["explanation"]] for e in r.recovery["correlations"]])
    else:
        _para(pdf, f"NOT PERFORMED (Review 2). {r.recovery['messages']['correlation']}", style="I")

    # 13. Validation results
    _section(pdf, 13, "Validation results")
    _para(pdf, ", ".join(f"{k}: {v}" for k, v in r.validation["by_status"].items()), style="B")
    _table(pdf, [("Status", 20), ("Check", 35), ("Target", 55), ("Detail", 80)],
          [[v["status"], v["check_name"], f"{v['target_type']}: {v['target_label']}", v["detail"]] for v in r.validation["results"]],
          total=r.validation["total"])

    # 14. Methodology
    _section(pdf, 14, "Recovery methodology")
    for title, body in r.methodology:
        _para(pdf, title, style="B")
        _para(pdf, body)

    # 15. Limitations
    _section(pdf, 15, "Limitations")
    _para(pdf, r.disclaimer, style="I")
    for item in r.limitations:
        _para(pdf, f"- {item}")

    # 16. Appendix
    _section(pdf, 16, "Appendix")
    _para(pdf, "A. Skipped / flagged entries", style="B")
    _table(pdf, [("Stage", 25), ("Issue", 35), ("Path", 60), ("Detail", 70)],
          [[i["stage"], i["issue_type"], i["path"] or "-", i["detail"] or "-"] for i in r.scan_issues])
    _para(pdf, "B. Chain of custody", style="B")
    _para(pdf, f"{'VALID' if r.custody['intact'] else 'INVALID'}: {r.custody['message']}")
    _para(pdf, "C. Analysis runs", style="B")
    _table(pdf, [("#", 12), ("Stage", 30), ("Status", 25), ("Started", 60), ("Finished", 60)],
          [[u["id"], u["stage"], u["status"], u["started_at"], u["finished_at"] or "-"] for u in r.runs])
    _para(pdf, "D. Status glossary", style="B")
    for k, v in r.status_glossary:
        _para(pdf, f"{k}: {v}")

    pdf.output(str(path))
