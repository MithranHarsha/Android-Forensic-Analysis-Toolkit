"""Render the report in HTML (self-contained), JSON and CSV, and hash the outputs."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from android_forensics.fmt import fmt_bytes
from android_forensics.reporting.model import ReportModel, build_report_model
from android_forensics.storage.case_store import CaseStore

_SAFE_NUMBER = re.compile(r"^[+-]?[\d\s().\-]+$")


@dataclass
class ReportResult:
    out_dir: Path
    html: Path | None = None
    json: Path | None = None
    csv_dir: Path | None = None
    sums: Path | None = None


def _cell(v: Any) -> str:
    if v is None or v == "":
        return "—"
    if isinstance(v, bool):
        return "yes" if v else "no"
    return str(v)


def _env() -> Environment:
    env = Environment(loader=PackageLoader("android_forensics.reporting", "templates"), autoescape=True, undefined=StrictUndefined)
    env.filters["cell"] = _cell
    env.filters["fmtbytes"] = fmt_bytes
    return env


def _csv_safe(v: Any) -> Any:
    """Neutralise spreadsheet formula injection without mangling phone numbers (original values live in JSON)."""
    if isinstance(v, str) and v and v[0] in "=@+-\t\r":
        if v[0] in "+-" and _SAFE_NUMBER.match(v):
            return v
        return "'" + v
    return v


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str] | None = None) -> None:
    cols = columns or (list(rows[0].keys()) if rows else ["(no rows)"])
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in rows:
            w.writerow([_csv_safe(json.dumps(r.get(c), ensure_ascii=False) if isinstance(r.get(c), (dict, list)) else r.get(c)) for c in cols])


def _artifact_rows(store: CaseStore) -> list[dict[str, Any]]:
    return [dict(r) for r in store.q(
        "SELECT id, artifact_type, status, confidence, extraction_method, application, ts_utc, ts_raw, ts_format, ts_plausible, summary, "
        "source_file, source_sha256, source_database, source_table, source_rowid, view_includes_wal, page_number, byte_offset, raw_kind, raw_sha256, parser, parser_version, "
        "schema_variant, schema_match_score, marked_deleted, flags_json, unknown_fields_json, fields_json FROM artifacts ORDER BY COALESCE(ts_utc,'9999'), id")]


def generate_report(store: CaseStore, formats: list[str], out_dir: Path | None = None, html_row_cap: int | None = None) -> ReportResult:
    formats = [f.lower() for f in formats]
    bad = set(formats) - {"html", "json", "csv"}
    if bad:
        raise ValueError(f"unsupported report format(s): {', '.join(sorted(bad))}")
    model: ReportModel = build_report_model(store, html_row_cap)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = (out_dir or store.reports_dir / f"report-{stamp}").resolve()
    out.mkdir(parents=True, exist_ok=True)
    res = ReportResult(out_dir=out)
    written: list[Path] = []

    if "html" in formats:
        html = _env().get_template("report.html.j2").render(r=model)
        res.html = out / "report.html"
        res.html.write_text(html, encoding="utf-8")
        written.append(res.html)
    if "json" in formats:
        res.json = out / "report.json"
        res.json.write_text(model.model_dump_json(indent=2), encoding="utf-8")
        written.append(res.json)
    if "csv" in formats:
        res.csv_dir = out / "csv"
        res.csv_dir.mkdir(exist_ok=True)
        _write_csv(res.csv_dir / "evidence_files.csv", model.evidence_files)
        _write_csv(res.csv_dir / "artifacts.csv", _artifact_rows(store))
        _write_csv(res.csv_dir / "timeline.csv", model.timeline)
        _write_csv(res.csv_dir / "validation.csv", model.validation["results"])
        _write_csv(res.csv_dir / "databases.csv", model.databases)
        _write_csv(res.csv_dir / "scan_issues.csv", model.scan_issues, ["source_id", "path", "issue_type", "detail", "stage"])
        written += sorted(res.csv_dir.glob("*.csv"))

    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}" for p in written]
    res.sums = out / "sha256sums.txt"
    res.sums.write_text("\n".join(lines) + "\n")
    store.log("report_generated", str(out), {"formats": formats, "files": len(written)})
    return res
