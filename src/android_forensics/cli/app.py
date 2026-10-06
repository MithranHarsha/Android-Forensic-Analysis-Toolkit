"""android-forensics command line interface (Review 1: acquisition → active artifacts → report)."""

from __future__ import annotations

import functools
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel
from rich.text import Text

from android_forensics import TOOL_NAME, __version__
from android_forensics.acquisition import PreservePolicy
from android_forensics.acquisition.hashing import hash_file
from android_forensics.acquisition.ingest import ingest_source
from android_forensics.cli.console import RichProgress, SafeTable, console, err_console, escape, plain_panel, stats_panel, styled
from android_forensics.errors import CaseError, ForensicsError
from android_forensics.fmt import fmt_bytes
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, REVIEW2_STAGE_NAMES, StageOptions, run_pipeline, run_stage
from android_forensics.storage.case_store import CaseStore

app = typer.Typer(
    name=TOOL_NAME,
    help=(
        "Android forensic acquisition, active-artifact extraction, deleted-data recovery, validation, timeline and "
        "reporting.\n\n"
        "[bold]Pipeline:[/] evidence integrity → filesystem analysis → SQLite discovery → active artifact extraction → "
        "deleted/superseded record recovery → raw carving → correlation → validation → timeline → report. "
        "'analyze' runs all of it (recovery can be skipped with --no-recover); 'recover' runs just the recovery stages "
        "on a case that has already been scanned and extracted.\n\n"
        "[yellow]Use only on evidence you are legally authorised to examine.[/]"
    ),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

CasesDir = Annotated[Path, typer.Option("--cases-dir", envvar="ANDROID_FORENSICS_CASES", help="Directory holding cases.")]
CaseArg = Annotated[str, typer.Argument(help="Case name (under --cases-dir) or path to a case directory.")]
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


_audit_ctx: dict[str, CaseStore | None] = {"store": None}
_state: dict[str, Any] = {"config": None}


def _note_case(store: CaseStore) -> CaseStore:
    """Remember which case the running command touched so its execution can be written to that case's audit log."""
    _audit_ctx["store"] = store
    return store


def _audit(fn_name: str, params: dict, outcome: str, started: float) -> None:
    store = _audit_ctx["store"]
    _audit_ctx["store"] = None
    if store is None:
        return
    try:
        from android_forensics.custody import record_command

        head = store.scalar("SELECT entry_hash FROM custody_log ORDER BY id DESC LIMIT 1")
        record_command(store.case_dir, fn_name.replace("_", "-"), [f"{k}={v}" for k, v in sorted(params.items())], outcome,
                       detail={}, db_chain_head=head, seconds=time.monotonic() - started)
    except Exception as exc:  # noqa: BLE001 - an audit failure must be loud but must not destroy the analysis result
        err_console.print(f"[bold yellow]warning:[/] could not write the command audit log: {escape(str(exc))}")


def handle_errors(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        started = time.monotonic()
        _audit_ctx["store"] = None
        try:
            result = fn(*args, **kwargs)
        except ForensicsError as exc:
            _audit(fn.__name__, kwargs, f"error: {exc}", started)
            err_console.print(f"[bold red]error:[/] {escape(str(exc))}")
            raise typer.Exit(2) from exc
        except OSError as exc:
            _audit(fn.__name__, kwargs, f"error: {exc}", started)
            err_console.print(f"[bold red]error:[/] {escape(str(exc))}")
            raise typer.Exit(2) from exc
        except typer.Exit as exc:
            _audit(fn.__name__, kwargs, f"exit {exc.exit_code}", started)
            raise
        except BaseException as exc:
            _audit(fn.__name__, kwargs, f"crashed: {type(exc).__name__}", started)
            raise
        _audit(fn.__name__, kwargs, "ok", started)
        return result

    return wrapper


def open_case(ref: str, cases_dir: Path) -> CaseStore:
    for candidate in (Path(ref), cases_dir / ref):
        if CaseStore.is_case_dir(candidate):
            return _note_case(CaseStore.open(candidate))
    raise CaseError(f"No case '{ref}' found (looked in ./{ref} and {cases_dir}/{ref}). Create one with: {TOOL_NAME} init-case NAME")


def _version(value: bool) -> None:
    if value:
        console.print(f"{TOOL_NAME} {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")] = False,
    config: Annotated[Path | None, typer.Option("--config", envvar="ANDROID_FORENSICS_CONFIG", help="TOML config file (default: ./android-forensics.toml or ~/.config/android-forensics/config.toml).")] = None,
    plugin: Annotated[list[Path] | None, typer.Option("--plugin", help="Load a parser plugin file (repeatable; see docs/plugins.md). Plugins are code: load only ones you trust.")] = None,
    log_level: Annotated[str | None, typer.Option("--log-level", envvar="ANDROID_FORENSICS_LOG_LEVEL", help="DEBUG, INFO, WARNING or ERROR (default: logging off).")] = None,
    log_file: Annotated[Path | None, typer.Option("--log-file", envvar="ANDROID_FORENSICS_LOG_FILE", help="Write logs here (rotating) instead of stderr.")] = None,
    log_format: Annotated[str | None, typer.Option("--log-format", envvar="ANDROID_FORENSICS_LOG_FORMAT", help="text or json (one JSON object per line).")] = None,
) -> None:
    from android_forensics import logs, plugins, userconfig

    try:
        cfg = userconfig.load(config)
        userconfig.apply_to_environment(cfg)
        _state["config"] = cfg
        level = log_level or cfg.logging.get("level")
        if level or log_file or cfg.logging.get("file"):
            logs.configure(level or "INFO", log_file or cfg.logging.get("file"), log_format or cfg.logging.get("format", "text"))
        plugins.load_all([*cfg.plugins, *(plugin or [])])
    except ForensicsError as exc:
        err_console.print(f"[bold red]error:[/] {escape(str(exc))}")
        raise typer.Exit(2) from exc


# ------------------------------------------------------------------ case + evidence


@app.command("init-case")
@handle_errors
def init_case(
    name: Annotated[str, typer.Argument(help="Case identifier, e.g. case001")],
    cases_dir: CasesDir = Path("cases"),
    examiner: Annotated[str | None, typer.Option(envvar="ANDROID_FORENSICS_EXAMINER", help="Examiner name for the report.")] = None,
    description: Annotated[str | None, typer.Option(help="Short case description.")] = None,
    detail: Annotated[list[str] | None, typer.Option("--detail", help="Case detail as key=value, repeatable (case_number, agency, evidence_description, …).")] = None,
) -> None:
    """Create a new case (database, evidence store, report directory)."""
    if not _NAME_RE.match(name):
        raise CaseError("Case name may contain letters, digits, '.', '_' and '-' only")
    store = _note_case(CaseStore.create(cases_dir / name, name, examiner, description))
    cfg = _state.get("config")
    for k, v in {**(cfg.court_defaults() if cfg else {}), **_parse_details(detail)}.items():
        store.set_detail(k, v)
    console.print(stats_panel("Case created", [("Case", name), ("Location", str(store.case_dir)), ("Examiner", examiner or "-"), ("Tool", f"{TOOL_NAME} {__version__}")]))
    console.print(f"Next: [bold]{TOOL_NAME} ingest {name} /path/to/evidence[/]")


def _parse_details(items: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            raise CaseError(f"--detail expects key=value, got {item!r}")
        out[key.strip()] = value.strip()
    return out


@app.command("case-details")
@handle_errors
def case_details(
    case: CaseArg,
    cases_dir: CasesDir = Path("cases"),
    set_: Annotated[list[str] | None, typer.Option("--set", help="key=value, repeatable. Standard keys: case_number, agency, requested_by, jurisdiction, evidence_description, evidence_received_on, examination_started, examiner_title, examiner_organisation, examiner_accreditation, classification, footer, statement.")] = None,
    from_config: Annotated[bool, typer.Option("--from-config", help="Fill examiner/agency defaults from the config file for keys not yet set.")] = False,
) -> None:
    """Show or set the details printed in the report's certification block (case number, agency, examiner credentials …)."""
    store = open_case(case, cases_dir)
    existing = store.details()
    if from_config:
        cfg = _state.get("config")
        for k, v in (cfg.court_defaults() if cfg else {}).items():
            if k not in existing:
                store.set_detail(k, v)
    for k, v in _parse_details(set_).items():
        store.set_detail(k, v)
    t = SafeTable(title=f"Case details: {case}", header_style="bold")
    t.add_column("Key")
    t.add_column("Value", overflow="fold")
    for k, v in store.details().items():
        t.add_row(k, v)
    console.print(t)


@app.command()
@handle_errors
def ingest(
    case: CaseArg,
    path: Annotated[Path, typer.Argument(help="Directory dump, .zip, .tar/.tar.gz, or a single SQLite database.")],
    cases_dir: CasesDir = Path("cases"),
    acquired_at: Annotated[str | None, typer.Option("--acquired-at", help="Acquisition time (ISO 8601 with timezone) if known.")] = None,
    preserve: Annotated[PreservePolicy, typer.Option("--preserve", help="Which files are copied into the working directory: analysis (databases + small text/XML/JSON), all, or none (hash only).")] = PreservePolicy.ANALYSIS,
    mount_point: Annotated[str | None, typer.Option("--mount-point", help="For disk images: the Android path the image is mounted at (e.g. 'data'). Default: detected.")] = None,
) -> None:
    """Hash and ingest evidence. The original is only ever read; write-protected working copies are made where needed."""
    store = open_case(case, cases_dir)
    r = ingest_source(store, path, acquired_at, RichProgress(), preserve=preserve, mount_point=mount_point)
    rows: list[tuple[str, object]] = [
        ("Source type", r.source_type.value), ("Files hashed", r.files), ("Bytes", fmt_bytes(r.total_bytes)),
        ("Preserved copies", r.preserved_copies), ("Skipped/flagged entries", r.issues),
        ("Acquisition complete", "yes" if r.complete else "NO — see issues"),
    ]
    if r.container_sha256:
        rows.append(("Container SHA-256", r.container_sha256))
    rows += [("Manifest", str(r.manifest_path)), ("Manifest SHA-256", r.manifest_sha256), ("Time", f"{r.seconds:.2f}s")]
    console.print(stats_panel("Evidence ingested", rows))
    if r.issues:
        console.print(f"[yellow]{r.issues} entr{'y' if r.issues == 1 else 'ies'} skipped or flagged — review with:[/] {TOOL_NAME} info {escape(case)}")


@app.command("hash")
@handle_errors
def hash_cmd(
    path: Annotated[Path, typer.Argument(help="File or directory to hash (read-only).")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Compute SHA-256 / SHA-1 / MD5 for a file or every file under a directory (MD5/SHA-1 for legacy reference only)."""
    if not path.exists():
        raise CaseError(f"{path} does not exist")
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink())
    out = []
    for p in files:
        d = hash_file(p, follow_symlinks=path.is_file())  # a symlink named explicitly on the command line is followed
        out.append({"path": str(p.relative_to(path)) if path.is_dir() else p.name, "size": d.size, "sha256": d.sha256, "sha1": d.sha1, "md5": d.md5})
    if as_json:
        console.print_json(json.dumps(out))
        return
    t = SafeTable(title=f"Hashes ({len(out)} file(s))", header_style="bold")
    for c in ("Path", "Size", "SHA-256", "SHA-1", "MD5"):
        t.add_column(c, overflow="fold")
    for o in out:
        t.add_row(o["path"], f"{o['size']:,}", o["sha256"], o["sha1"], o["md5"])
    console.print(t)


def _options(no_rehash: bool, files: str) -> StageOptions:
    return StageOptions(progress=RichProgress(), rehash_originals=not no_rehash, timeline_files=files)


@app.command()
@handle_errors
def discover(
    path: Annotated[Path, typer.Argument(help="An evidence directory (an extracted Android filesystem dump). No case is needed.")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit the full scan as JSON.")] = False,
    hash_all: Annotated[bool, typer.Option("--hash-all", help="SHA-256 every file, not only databases and their sidecars.")] = False,
    show_files: Annotated[bool, typer.Option("--files", help="List every file with its classification.")] = False,
) -> None:
    """Recursively discover the Android filesystem in a directory: databases + sidecars, XML/JSON/log/media, application directories."""
    from android_forensics.filesystem.scanner import scan_directory

    scan_result = scan_directory(path, hash_all=hash_all, progress=RichProgress())
    if as_json:
        console.print_json(scan_result.model_dump_json())
        return
    _print_discovery(scan_result, show_files)


def _print_discovery(s, show_files: bool) -> None:
    console.print(stats_panel("Filesystem discovery", [
        ("Root", s.root or "-"), ("Layout", s.layout.layout), ("Files", s.total_files), ("Directories", s.directories),
        ("Bytes", fmt_bytes(s.total_bytes)), ("Application directories", len(s.app_directories)),
        ("Databases", len(s.databases)), ("Orphan sidecars", len(s.orphan_sidecars)), ("Issues", len(s.issues)),
    ]))
    console.print(Text(s.layout.detail, style="dim"))
    console.print(Text(f"Android roots present: {', '.join(s.layout.roots_present) or 'none'}"
                       f" · common roots absent (informational): {', '.join(s.layout.roots_absent) or 'none'}", style="dim"))
    cats = SafeTable(title="File categories", header_style="bold")
    cats.add_column("Category")
    cats.add_column("Files", justify="right")
    for name, n in sorted(s.category_counts.items(), key=lambda kv: -kv[1]):
        cats.add_row(name, f"{n:,}")
    console.print(cats)
    if s.app_directories:
        t = SafeTable(title="Application directories", header_style="bold")
        for c in ("Package", "Android path", "Area", "User", "Files", "DBs", "Subdirectories"):
            t.add_column(c, overflow="fold")
        for a in s.app_directories:
            t.add_row(a.package, a.logical_path or a.path, a.area or "-", "-" if a.user_id is None else str(a.user_id),
                      f"{a.file_count:,}", str(a.database_count), ", ".join(a.subdirectories) or "-")
        console.print(t)
    if s.databases:
        t = SafeTable(title="Databases", header_style="bold")
        for c in ("Path", "Size", "SHA-256", "SQLite status", "Sidecars"):
            t.add_column(c, overflow="fold")
        for d in s.databases:
            side = ", ".join(f"{x.kind.value.upper()} {fmt_bytes(x.size)}" for x in d.sidecars) or "-"
            t.add_row(d.path, fmt_bytes(d.size), (d.sha256 or "-"), styled_sqlite(d.status.value), side)
        console.print(t)
    if s.orphan_sidecars:
        console.print(Text.assemble(("Orphan sidecars: ", "yellow"), ", ".join(o.path for o in s.orphan_sidecars)))
    if s.issues:
        t = SafeTable(title="Issues", header_style="bold")
        for c in ("Issue", "Path", "Detail"):
            t.add_column(c, overflow="fold")
        for i in s.issues:
            t.add_row(i.issue_type, i.path, i.detail[:110])
        console.print(t)
    if show_files:
        t = SafeTable(title="Files", header_style="bold")
        for c in ("Path", "Size", "Kind", "Android path"):
            t.add_column(c, overflow="fold")
        for f in s.files:
            t.add_row(f.path, f"{f.size:,}", f.kind.value, f.logical_path or "-")
        console.print(t)


@app.command("inspect")
@handle_errors
def inspect_cmd(
    path: Annotated[Path, typer.Argument(help="A SQLite database file. Its -wal / -shm / -journal files beside it are detected. No case is needed.")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit the complete inspection (schema, metadata and every active record) as JSON.")] = False,
    rows: Annotated[int | None, typer.Option("--rows", help="Rows kept per table. Default: 3 shown in the text view, all in --json.")] = None,
    tables: Annotated[list[str] | None, typer.Option("--table", help="Read records only from this table (repeatable). The schema is always complete.")] = None,
    no_records: Annotated[bool, typer.Option("--no-records", help="Schema, metadata and row counts only.")] = False,
    no_sidecars: Annotated[bool, typer.Option("--no-sidecars", help="Read the main file alone: do not apply the WAL / hot journal.")] = False,
    blob_limit: Annotated[int, typer.Option("--blob-limit", help="BLOBs up to this many bytes are kept whole (larger: length + SHA-256 + head).")] = 256,
) -> None:
    """Inspect one SQLite database: header, version, sidecars, tables, columns, keys, indexes and the active records.

    Normal inspection only — the rows SQLite itself returns. Deleted rows are absent; recovering them is Review 2. The
    database is only ever read (a private scratch copy is what SQLite opens), so the evidence file is never modified."""
    from android_forensics.sqlite.inspector import InspectionOptions, SQLiteInspector

    result = SQLiteInspector.inspect(path, InspectionOptions(
        include_records=not no_records, max_records_per_table=rows if rows is not None else (None if as_json else 3),
        tables=tuple(tables) if tables else None, apply_sidecars=not no_sidecars, blob_inline_limit=blob_limit,
    ))
    if as_json:
        console.print_json(result.model_dump_json())
        return
    _print_inspection(result, show_rows=not no_records)


def _cell(value) -> Text:
    """One stored value, shown so that its storage class is visible: NULL, blobs and special floats look different from text."""
    from android_forensics.sqlite.inspection import BlobValue, SpecialFloat

    if value is None:
        return Text("NULL", style="dim italic")
    if isinstance(value, BlobValue):
        body = f"{value.hex_head[:24]}" if value.hex is None else value.hex[:24]
        more = "…" if value.length > 12 else ""
        return Text(f"<blob {value.length:,} B {body}{more}>", style="cyan")
    if isinstance(value, SpecialFloat):
        return Text(value.value, style="magenta")
    if isinstance(value, str):
        text = value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return Text(text if len(text) <= 60 else text[:59] + "…")
    return Text(str(value), style="green" if isinstance(value, int) else "yellow")


def _print_inspection(r, show_rows: bool) -> None:
    h, v, e = r.header, r.version, r.engine
    rows: list[tuple[str, object]] = [
        ("Database", r.file.path), ("Size", f"{fmt_bytes(r.file.size)} ({r.file.size:,} bytes)"), ("SHA-256", r.file.sha256 or "-"),
        ("Detection", Text.assemble(styled_sqlite(r.status.value), f"  {r.status_detail}")),
        ("SQLite opened it", Text.assemble(styled_sqlite("VALID" if e.open_status.value == "ok" else "UNVERIFIED" if e.open_status.value == "encrypted_suspect" else "INVALID"), f"  {e.open_status.value}" + (f" — {e.open_error}" if e.open_error and e.open_status.value != "ok" else ""))),
        ("Integrity check", r.integrity.status),
    ]
    if h.valid:
        rows += [
            ("Page size · pages", f"{h.page_size:,} B · {h.page_count:,} declared, {r.size.actual_size // h.page_size:,} on disk"),
            ("Text encoding", h.text_encoding or "not set (no schema yet)"), ("Journal mode", v.write_format or h.journal_mode),
            ("Last written by", (f"SQLite {v.last_writer_version}" + ("" if v.last_writer_version_reliable else " (stale: file changed since it was stamped)")) if v.last_writer_version else "not recorded"),
            ("Schema format", f"{h.schema_format} (needs SQLite ≥ {v.schema_format_min_version})" if v.schema_format else "0 (no schema yet)"),
            ("User version · application id", f"{h.user_version} · {h.application_id}"), ("Auto-vacuum", h.auto_vacuum or "-"),
            ("Freelist pages (header)", h.freelist_page_count),
        ]
    rows += [("Inspected with", f"SQLite library {e.sqlite_library_version}")]
    if e.view_includes_wal is not None:
        rows.append(("Active view", "main file + committed WAL frames" + (f" ({e.wal_frames_valid} valid)" if e.wal_frames_valid else "") if e.view_includes_wal
                     else "main file" + (" + rolled-back journal" if "journal" in e.applied_sidecars else "")))
    console.print(stats_panel("SQLite database", rows))

    if r.sidecars:
        t = SafeTable(title="Sidecar files", header_style="bold")
        for c in ("Kind", "File", "Size", "SHA-256", "Header", "In the view"):
            t.add_column(c, overflow="fold")
        for s in r.sidecars:
            t.add_row(s.kind.value.upper(), s.path.rsplit("/", 1)[-1], fmt_bytes(s.size), s.sha256 or "-",
                      {True: "valid", False: "INVALID", None: "n/a"}[s.header_valid], "yes" if s.applied else "no")
        console.print(t)

    if r.tables:
        t = SafeTable(title=f"Tables ({len(r.tables)}) — {sum(x.row_count or 0 for x in r.tables):,} active rows", header_style="bold")
        for c in ("Table", "Rows", "Columns", "Primary key", "Indexes", "Notes"):
            t.add_column(c, overflow="fold")
        for x in r.tables:
            cols = ", ".join(f"{c.name} {c.declared_type}".strip() + (" NOT NULL" if c.not_null else "") for c in x.columns if c.hidden != 1)
            notes = [n for n, on in (("WITHOUT ROWID", x.without_rowid), ("AUTOINCREMENT", x.autoincrement), ("STRICT", x.strict), (x.kind.value, x.kind.value != "table"),
                                     ("internal", x.internal), (f"rowid = {x.rowid_alias}", x.rowid_alias), ("read error: " + (x.read_error or ""), x.read_error)) if on]
            t.add_row(x.name, "?" if x.row_count is None else f"{x.row_count:,}", cols or "-", ", ".join(x.primary_key) or "none",
                      ", ".join(i.name for i in x.indexes) or "-", "; ".join(notes) or "-")
        console.print(t)
    if r.views or r.triggers:
        console.print(Text(f"Views: {', '.join(v_.name for v_ in r.views) or '-'} · Triggers: {', '.join(t_.name for t_ in r.triggers) or '-'}", style="dim"))

    if show_rows:
        for x in r.tables:
            if not x.records:
                continue
            names = x.data_columns
            title = f"{x.name} — {len(x.records):,} of {x.row_count:,} rows" if x.row_count is not None else x.name
            if len(names) <= 7:
                t = SafeTable(title=title, header_style="bold")
                t.add_column("rowid", justify="right")
                for name in names:
                    t.add_column(name, overflow="fold")
                for rec in x.records:
                    t.add_row("-" if rec.rowid is None else str(rec.rowid), *[_cell(val) for val in rec.values])
                console.print(t)
                continue
            console.print(Text(title, style="bold"))  # too wide for a grid: one block per record, a column per line
            declared = {c.name: c.declared_type for c in x.columns}
            for rec in x.records:
                block = SafeTable.grid(padding=(0, 2))
                block.add_column(style="bold cyan", justify="right")
                block.add_column(overflow="fold")
                for name, val, cls in zip(names, rec.values, rec.storage_classes):
                    block.add_row(Text.assemble(name, (f" {declared.get(name, '')}".rstrip() or "", "dim")), Text.assemble(_cell(val), (f"  {cls.value}", "dim")))
                console.print(Panel(block, title=Text(f"{x.name} · rowid {'-' if rec.rowid is None else rec.rowid}"), border_style="blue", expand=False))
    for issue in r.issues:
        console.print(Text.assemble(("• ", "yellow"), f"{issue.kind}" + (f" [{issue.table}]" if issue.table else "") + f": {issue.detail}"))
    for note in r.notes + e.notes:
        console.print(Text(f"  {note}", style="dim"))
    console.print(Text("Normal inspection only: rows deleted from this database are absent. Deleted-data recovery is Review 2.", style="dim"))


def styled_sqlite(status: str) -> Text:
    color = {"VALID": "green", "UNVERIFIED": "cyan", "TRUNCATED": "yellow", "ENCRYPTED_SUSPECT": "cyan"}.get(status, "bold red")
    return Text(status, style=color)


@app.command()
@handle_errors
def scan(case: CaseArg, cases_dir: CasesDir = Path("cases")) -> None:
    """Filesystem analysis and SQLite discovery over the ingested evidence."""
    store = open_case(case, cases_dir)
    s = run_stage(store, "scan", _options(False, "key"))
    _print_scan(store, s)


def _print_scan(store: CaseStore, s: dict) -> None:
    layouts = store.case().layouts
    console.print(stats_panel("Filesystem & SQLite discovery", [
        ("Files discovered", s["files"]), ("Layout", s["layout"]), ("Android packages", s["packages"]),
        ("Application directories", s["app_directories"]),
        ("SQLite databases", s["databases"]), ("Readable", s["readable"]), ("Encrypted suspects", s["encrypted_suspects"]),
        ("Unreadable/corrupt", s["unreadable"]), ("Tables catalogued", s["tables"]),
        ("With WAL / with journal", f"{s['with_wal']} / {s['with_journal']}"),
    ]))
    k = SafeTable(title="File kinds", header_style="bold")
    k.add_column("Kind")
    k.add_column("Files", justify="right")
    for kind, n in sorted(s["kinds"].items(), key=lambda kv: -kv[1]):
        k.add_row(kind, f"{n:,}")
    console.print(k)
    for sid, info in layouts.items():
        console.print(Text(f"source s{sid}: {info.layout} — {info.detail}", style="dim"))


def _print_recovery(rec: dict, carve: dict, correlate: dict, reconstruct: dict) -> None:
    recovered = sum(v for k, v in rec.items() if k.startswith("recovered_"))
    reconstructed = {k[len("reconstructed_"):]: v for k, v in reconstruct.items() if k.startswith("reconstructed_")}
    console.print(stats_panel("Deleted-data recovery (Review 2)", [
        ("Deleted/superseded records found", recovered),
        ("  reconstructed → RECOVERED", reconstructed.get("recovered", 0)),
        ("  reconstructed → PARTIAL", reconstructed.get("partial", 0)),
        ("  reconstructed → CORRUPTED", reconstructed.get("corrupted", 0)),
        ("Unrecoverable regions (proven, empty)", rec.get("unrecovered_regions", 0)),
        ("Corroborated by another source", correlate.get("recovered_corroborated", 0)),
        ("Databases attempted", rec.get("databases_attempted", 0)),
        ("Skipped (no working copy)", rec.get("skipped_no_working_copy", 0)),
        ("Carved candidates (CARVED CANDIDATE — unconfirmed)", carve.get("candidates", 0)),
        ("  corroborated", correlate.get("carved_corroborated", 0)),
        ("Correlation edges", reconstruct.get("correlation_edges", 0)),
    ]))
    console.print("[dim]A carved candidate is never confirmed evidence; PARTIAL/CORRUPTED records had part of their bytes "
                  "overwritten before recovery — see the report for what each record's confidence explanation says.[/]")


@app.command()
@handle_errors
def analyze(
    target: Annotated[str, typer.Argument(help="An existing case, or a path to evidence (a case is created automatically).")],
    cases_dir: CasesDir = Path("cases"),
    name: Annotated[str | None, typer.Option(help="Case name when TARGET is a path.")] = None,
    timeline_files: Annotated[str, typer.Option("--timeline-files", help="File-time events in the timeline: key | all | none.")] = "key",
    no_rehash: Annotated[bool, typer.Option("--no-rehash", help="Skip re-hashing originals during validation (faster, less assurance).")] = False,
    recover: Annotated[bool, typer.Option("--recover/--no-recover", help="Recover deleted/superseded records and carve raw bytes (Review 2). On by default.")] = True,
    report: Annotated[bool, typer.Option("--report/--no-report", help="Generate the report at the end.")] = True,
    mount_point: Annotated[str | None, typer.Option("--mount-point", help="For disk images: the Android path the image is mounted at (e.g. 'data'). Default: detected.")] = None,
) -> None:
    """Run the full pipeline: scan → extract → recover → carve → correlate → reconstruct → validate → timeline → report."""
    p = Path(target)
    store: CaseStore | None = None
    for candidate in (p, cases_dir / target):
        if CaseStore.is_case_dir(candidate):
            store = _note_case(CaseStore.open(candidate))
            break
    if store is None:
        if not p.exists():
            raise CaseError(f"'{target}' is neither a case nor an existing evidence path")
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        case_name = name or f"{re.sub(r'[^A-Za-z0-9_.-]', '_', p.stem or 'evidence')}-{stamp}"
        store = _note_case(CaseStore.create(cases_dir / case_name, case_name))
        console.print(Text.assemble(("Case created: ", "bold"), str(store.case_dir)), soft_wrap=True)
        r = ingest_source(store, p, progress=RichProgress(), mount_point=mount_point)
        console.print(f"[green]✓[/] ingested {r.files:,} files ({fmt_bytes(r.total_bytes)}), manifest SHA-256 {r.manifest_sha256[:16]}…")

    opts = _options(no_rehash, timeline_files)
    names = list(FULL_PIPELINE_NAMES) if recover else [n for n in FULL_PIPELINE_NAMES if n not in REVIEW2_STAGE_NAMES]
    results = run_pipeline(store, names=names, options=opts, on_stage=lambda n, s: console.print(f"[green]✓[/] {n:<11} {s['seconds']}s"))
    _print_scan(store, results["scan"])
    ex, va, tl = results["extract"], results["validate"], results["timeline"]
    a = ex["artifacts"]
    console.print(stats_panel("Artifacts (ACTIVE)", [
        ("SMS", a.get("sms", 0)), ("Calls", a.get("call", 0)), ("Contacts", a.get("contact", 0)),
        ("Browser visits", a.get("browser_visit", 0)), ("Browser downloads", a.get("browser_download", 0)),
        ("Application summaries", a.get("app_summary", 0)), ("Total", ex["total"]),
        ("Tables recognised by parsers", ex["tables_matched"]), ("Tables catalogued generically", ex["generic_tables"]),
    ]))
    if recover:
        _print_recovery(results["recover"], results["carve"], results["correlate"], results["reconstruct"])
    else:
        console.print("[dim]Deleted-data recovery was not run (--no-recover). Freelist/WAL/journal indicators are reported, not analysed.[/]")
    st = va["by_status"]
    console.print(stats_panel("Validation", [("Checks recorded", va["total"])] + [(k, st.get(k, 0)) for k in ("VALID", "PARTIAL", "INVALID", "UNVERIFIED")]))
    console.print(f"Timeline events: [bold]{tl['total']:,}[/] ({tl['artifact_events']:,} artifact, {tl['file_events']:,} file)")
    if report:
        from android_forensics.reporting.generate import generate_report

        out = generate_report(store, ["html", "json", "csv"])
        console.print(Text.assemble(("Report: ", "bold green"), str(out.html)), soft_wrap=True)


# ------------------------------------------------------------------ inspection


@app.command()
@handle_errors
def artifacts(
    case: CaseArg,
    cases_dir: CasesDir = Path("cases"),
    type_: Annotated[str | None, typer.Option("--type", help="sms|call|contact|browser_visit|browser_download|generic_record|app_summary")] = None,
    status: Annotated[str | None, typer.Option(help="ACTIVE|RECOVERED|PARTIAL|CORRUPTED (the last three only after 'recover'/'analyze' with recovery)")] = None,
    db: Annotated[str | None, typer.Option(help="Substring of the source database path.")] = None,
    app_: Annotated[str | None, typer.Option("--app", help="Android package name.")] = None,
    limit: int = 30,
    offset: int = 0,
    show: Annotated[int | None, typer.Option(help="Show full provenance for one artifact id.")] = None,
) -> None:
    """List extracted artifacts, or show one with complete provenance."""
    store = open_case(case, cases_dir)
    if show is not None:
        return _show_artifact(store, show)
    where, params = ["1=1"], []
    for col, val in (("artifact_type", type_), ("status", status), ("application", app_)):
        if val:
            where.append(f"{col}=?")
            params.append(val)
    if db:
        where.append("source_file LIKE ?")
        params.append(f"%{db}%")
    total = store.scalar(f"SELECT COUNT(*) FROM artifacts WHERE {' AND '.join(where)}", params)
    rows = store.q(f"SELECT * FROM artifacts WHERE {' AND '.join(where)} ORDER BY COALESCE(ts_utc,'9999'), id LIMIT ? OFFSET ?", [*params, limit, offset])
    t = SafeTable(title=f"Artifacts {offset + 1}-{offset + len(rows)} of {total:,}", header_style="bold")
    for c in ("ID", "Type", "Status", "Timestamp (UTC)", "Summary", "Source"):
        t.add_column(c, overflow="fold")
    for r in rows:
        src = f"{r['source_file'].rsplit('/', 1)[-1]}" + (f" › {r['source_table']}#{r['source_rowid']}" if r["source_table"] else "")
        t.add_row(str(r["id"]), r["artifact_type"], styled(r["status"]), r["ts_utc"] or "-", (r["summary"] or "")[:70], src)
    console.print(t)
    console.print(Text(f"Details: {TOOL_NAME} artifacts {case} --show ID", style="dim"))


def _show_artifact(store: CaseStore, aid: int) -> None:
    art = store.get_artifact(aid)
    prov, raw = art.provenance, art.raw
    ev = store.get_file(prov.evidence_file_id)
    ts = art.timestamp
    wal = {True: "yes", False: "no", None: "n/a"}[prov.view_includes_wal]
    where = "not recorded (active row read through SQLite; page-level provenance is Review 2)"
    if prov.physical:
        ph = prov.physical
        where = f"page {ph.page_number}, cell {ph.cell_index}, byte offset {ph.byte_offset} ({ph.region or ph.page_type or 'unspecified'})"
    grid = SafeTable.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column(overflow="fold")
    for k, v in [
        ("Artifact", f"#{aid} {art.artifact_type.value} ({type(art).__name__})"), ("Status", styled(art.status.value)),
        ("Extraction method", art.extraction_method.value),
        ("Confidence", art.confidence.value if art.confidence else "n/a (Review 2 scores recovered data)"),
        ("Source file", prov.source_file), ("Source database", prov.source_database or "-"),
        ("Source table / rowid", f"{prov.source_table or '-'} / {prov.source_rowid if prov.source_rowid is not None else '-'}"),
        ("Android path", ev.logical_path or "-"), ("Application", art.application or "-"),
        ("File SHA-256", prov.source_sha256), ("Includes WAL frames", wal), ("Physical location", where),
        ("Raw reference", f"{raw.kind.value}; SHA-256 of {raw.sha256_of}: {raw.sha256}"),
        ("Parser", f"{art.parser.name} {art.parser.version} — variant {art.parser.schema_variant} (schema match {art.parser.schema_match_score})"),
        ("Timestamp", "-" if ts is None else f"{ts.utc} (raw {ts.raw!r}, {ts.format.value}, plausible={ts.plausible}) {ts.note or ''}"),
        ("Flags", art.flags or "-"), ("Unknown fields", art.unknown_fields or "-"),
    ]:
        grid.add_row(k + ":", v if isinstance(v, Text) else str(v))
    console.print(Panel(grid, title="Provenance", border_style="blue"))
    console.print(plain_panel(json.dumps(art.payload(), indent=2, ensure_ascii=False), "Normalised fields"))
    console.print(plain_panel(json.dumps(raw.row, indent=2, ensure_ascii=False)[:4000] if raw.row is not None else (raw.raw_bytes_hex or ""), "Raw source"))


@app.command()
@handle_errors
def recover(
    case: CaseArg,
    cases_dir: CasesDir = Path("cases"),
) -> None:
    """Recover deleted/superseded SQLite records, carve raw bytes, correlate and score (Review 2).

    Requires 'scan' and 'extract' to have already run (android-forensics analyze --no-recover, or analyze/scan/... in
    sequence). Re-running this recovers the same evidence again: recovery is deterministic."""
    store = open_case(case, cases_dir)
    for stage in ("scan", "extract"):
        if store.last_run(stage) is None:
            raise CaseError(f"Run '{TOOL_NAME} analyze --no-recover {case}' (or 'scan'/'extract') first — no completed '{stage}' stage")
    opts = StageOptions(progress=RichProgress())
    results = {}
    for name in REVIEW2_STAGE_NAMES:
        results[name] = run_stage(store, name, opts)
        console.print(f"[green]✓[/] {name:<11} {results[name]['seconds']}s")
    _print_recovery(results["recover"], results["carve"], results["correlate"], results["reconstruct"])
    console.print(f"Next: [bold]{TOOL_NAME} validate {escape(case)}[/] and [bold]{TOOL_NAME} report {escape(case)}[/] "
                 "to see recovered records reflected there.")


@app.command()
@handle_errors
def validate(
    case: CaseArg,
    cases_dir: CasesDir = Path("cases"),
    no_rehash: Annotated[bool, typer.Option("--no-rehash")] = False,
    show_all: Annotated[bool, typer.Option("--all", help="List every result, not only non-VALID.")] = False,
) -> None:
    """Run automated validation (hashes, SQLite integrity, schema, datatypes, timestamps, duplicates, provenance)."""
    store = open_case(case, cases_dir)
    v = run_stage(store, "validate", _options(no_rehash, "key"))
    st = v["by_status"]
    console.print(stats_panel("Validation", [("Checks recorded", v["total"])] + [(k, st.get(k, 0)) for k in ("VALID", "PARTIAL", "INVALID", "UNVERIFIED")]))
    t = SafeTable(header_style="bold", title="Results")
    for c in ("Status", "Check", "Target", "Explanation"):
        t.add_column(c, overflow="fold")
    q = "SELECT * FROM validation_results WHERE target_type!='artifact'" + ("" if show_all else " AND status!='VALID'") + " ORDER BY status DESC, check_name"
    for r in store.q(q):
        t.add_row(styled(r["status"]), r["check_name"], (r["target_label"] or "")[-60:], r["detail"][:200])
    console.print(t)


@app.command()
@handle_errors
def timeline(
    case: CaseArg,
    cases_dir: CasesDir = Path("cases"),
    limit: int = 40,
    type_: Annotated[str | None, typer.Option("--type", help="Filter by artifact type.")] = None,
    kind: Annotated[str | None, typer.Option(help="artifact | file_mtime")] = None,
    since: Annotated[str | None, typer.Option(help="ISO timestamp lower bound.")] = None,
    until: Annotated[str | None, typer.Option(help="ISO timestamp upper bound.")] = None,
    reverse: bool = False,
) -> None:
    """Show the unified, chronologically sorted timeline."""
    store = open_case(case, cases_dir)
    if not store.scalar("SELECT COUNT(*) FROM timeline_events"):
        run_stage(store, "timeline", StageOptions())
    where, params = ["1=1"], []
    for col, val in (("artifact_type", type_), ("event_kind", kind)):
        if val:
            where.append(f"{col}=?")
            params.append(val)
    if since:
        where.append("ts_utc>=?")
        params.append(since)
    if until:
        where.append("ts_utc<=?")
        params.append(until)
    total = store.scalar(f"SELECT COUNT(*) FROM timeline_events WHERE {' AND '.join(where)}", params)
    rows = store.q(f"SELECT * FROM timeline_events WHERE {' AND '.join(where)} ORDER BY ts_utc {'DESC' if reverse else 'ASC'}, id LIMIT ?", [*params, limit])
    t = SafeTable(title=f"Timeline — {len(rows)} of {total:,} events", header_style="bold")
    for c in ("Timestamp (UTC)", "Marker", "Type", "Event", "Source", "Conf."):
        t.add_column(c, overflow="fold")
    for r in rows:
        marker = (Text("file time", style="dim") if r["status"] is None else Text("ACTIVE", style="green") if r["status"] == "ACTIVE"
                  else Text(f"★ {r['status']}", style="bold magenta"))
        t.add_row(r["ts_utc"], marker, r["artifact_type"] or "file", r["event"][:80], r["source"].rsplit("/", 1)[-1][:40], r["confidence"] or "-")
    console.print(t)


@app.command()
@handle_errors
def report(
    case: CaseArg,
    cases_dir: CasesDir = Path("cases"),
    formats: Annotated[str, typer.Option("--format", help="Comma list: html,json,csv,pdf")] = "html,json,csv",
    out: Annotated[Path | None, typer.Option(help="Output directory (default: <case>/reports/<timestamp>).")] = None,
    sign: Annotated[bool, typer.Option("--sign", help="Sign the report with your Ed25519 key (create one with 'keygen').")] = False,
    key: Annotated[Path | None, typer.Option("--key", help="Signing key (default: ~/.config/android-forensics/signing_key.pem).")] = None,
    signer: Annotated[str | None, typer.Option("--signer", help="Name recorded in the signature (default: the case examiner).")] = None,
    gpg_key: Annotated[str | None, typer.Option("--gpg-key", help="Also create a detached GPG signature with this key id.")] = None,
) -> None:
    """Generate the forensic report (HTML, JSON, CSV, PDF); optionally sign it."""
    from android_forensics.reporting.generate import generate_report

    store = open_case(case, cases_dir)
    for stage in ("extract",):
        if store.last_run(stage) is None:
            raise CaseError(f"Run '{TOOL_NAME} analyze {case}' first — no completed '{stage}' stage")
    fmts = [f.strip() for f in formats.split(",") if f.strip()]
    res = generate_report(store, fmts, out)
    for label, p in (("HTML", res.html), ("JSON", res.json), ("CSV dir", res.csv_dir), ("PDF", res.pdf)):
        if p:
            console.print(Text.assemble((f"{label}: ", "bold green"), str(p)), soft_wrap=True)
    if sign or gpg_key:
        from android_forensics.custody import sign_report

        doc = sign_report(res.out_dir, key, signer=signer or store.case().examiner, gpg_key=gpg_key)
        store.log("report_signed", str(res.out_dir), {"fingerprint": doc["public_key_fingerprint"]})
        console.print(Text.assemble(("Signed: ", "bold green"), f"Ed25519 key {doc['public_key_fingerprint'][:16]}… → {res.out_dir / 'signature.json'}"), soft_wrap=True)


@app.command()
@handle_errors
def dashboard(
    case: CaseArg,
    cases_dir: CasesDir = Path("cases"),
    host: Annotated[str, typer.Option(help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port.")] = 8765,
) -> None:
    """Serve a read-only dashboard (REST API + browser frontend) over this case's results.

    Never runs a stage and never writes to the case: it only reads what 'analyze' / 'recover' / 'report' already produced."""
    import uvicorn

    from android_forensics.dashboard import create_app

    case_dir = None
    for candidate in (Path(case), cases_dir / case):
        if CaseStore.is_case_dir(candidate):
            case_dir = candidate
            break
    if case_dir is None:
        raise CaseError(f"No case '{case}' found (looked in ./{case} and {cases_dir}/{case})")
    app_ = create_app(case_dir)
    console.print(Text.assemble(("Dashboard: ", "bold green"), f"http://{host}:{port}/  (case: {case_dir})"), soft_wrap=True)
    console.print("[dim]Read-only: no analysis stage runs from here. Ctrl+C to stop.[/]")
    uvicorn.run(app_, host=host, port=port, log_level="warning")


@app.command()
@handle_errors
def info(
    target: Annotated[str, typer.Argument(help="A case, or a SQLite database file to inspect.")],
    cases_dir: CasesDir = Path("cases"),
) -> None:
    """Case overview, or a header-level inspection of a database file."""
    p = Path(target)
    if p.is_file():
        from android_forensics.sqlite.header import inspect_database_file
        from android_forensics.sqlite.sidecars import inspect_journal, inspect_shm, inspect_wal

        rep = inspect_database_file(p)
        h = rep.header
        rows: list[tuple[str, object]] = [("File", str(p)), ("Size", fmt_bytes(rep.actual_size)), ("Valid SQLite header", h.valid)]
        if h.magic_ok:
            rows += [("Page size", h.page_size), ("Page count (header)", h.page_count), ("Text encoding", h.text_encoding),
                     ("Journal mode", h.journal_mode), ("Freelist pages (header)", h.freelist_page_count),
                     ("Schema cookie", h.schema_cookie), ("User version", h.user_version), ("Size consistent", rep.size_consistent)]
        console.print(stats_panel("SQLite header", rows))
        for msg in h.fatal + h.warnings + rep.notes:
            console.print(Text.assemble(("• ", "yellow"), msg))
        for suffix, fn in (("-wal", lambda q: inspect_wal(q, h.page_size)), ("-journal", lambda q: inspect_journal(q, h.page_size)), ("-shm", inspect_shm)):
            side = p.with_name(p.name + suffix)
            if side.is_file():
                console.print(plain_panel(json.dumps(fn(side).model_dump(), indent=2), f"{p.name}{suffix}"))
        return
    store = open_case(target, cases_dir)
    c = store.case()
    counts = store.counts()
    console.print(stats_panel(f"Case {c.name}", [
        ("Case ID", c.id), ("Examiner", c.examiner or "-"), ("Created", c.created_at), ("Tool version", c.tool_version),
        ("Layout", c.layout or "not scanned"), ("Evidence sources", counts["sources"]), ("Files", counts["files"]),
        ("Bytes", fmt_bytes(counts["bytes"])), ("SQLite databases", counts["databases"]),
        ("Artifacts (ACTIVE)", counts["active_artifacts"]), ("Validation results", counts["validation_results"]),
        ("Timeline events", counts["timeline_events"]), ("Skipped/flagged entries", counts["scan_issues"]),
        ("Recovered/partial/corrupted records", counts["recovered_records"]),
        ("  reconstructed into artifacts", counts["recovered_artifacts"]),
        ("Carved candidates", counts["carved_candidates"]), ("Correlation edges", counts["correlation_edges"]),
    ]))
    runs = SafeTable(title="Analysis runs", header_style="bold")
    for col in ("#", "Stage", "Status", "Started", "Finished"):
        runs.add_column(col)
    for r in store.runs():
        runs.add_row(str(r.id), r.stage, r.status.value, r.started_at, r.finished_at or "-")
    console.print(runs)
    issues = store.q("SELECT issue_type, path, detail FROM scan_issues ORDER BY id LIMIT 25")
    if issues:
        t = SafeTable(title="Skipped / flagged entries (first 25)", header_style="bold")
        for col in ("Issue", "Path", "Detail"):
            t.add_column(col, overflow="fold")
        for r in issues:
            t.add_row(r["issue_type"], r["path"], (r["detail"] or "")[:100])
        console.print(t)
    ok, msg = store.verify_custody_chain()
    console.print(Text.assemble("Chain of custody: ", (msg, "green" if ok else "bold red")))


@app.command()
@handle_errors
def synth(
    out: Annotated[Path, typer.Argument(help="Output directory for the synthetic acquisition.")] = Path("synthetic_evidence"),
    seed: int = 1337,
    with_deletions: Annotated[bool, typer.Option("--with-deletions/--no-deletions", help="Genuinely delete rows from mmssms.db and History, with physical ground truth (Review 2).")] = True,
) -> None:
    """Generate the deterministic synthetic Android evidence set (with ground truth) used for testing."""
    from android_forensics.lab.synth import SynthSpec, generate

    truth = generate(out, SynthSpec(seed=seed, with_deletions=with_deletions))
    console.print(stats_panel("Synthetic evidence generated", [("Location", str(out.resolve())), ("Seed", seed)] + [(k, v) for k, v in truth["expected"].items()]))


def main() -> None:
    app()


if __name__ == "__main__":
    main()


# ------------------------------------------------------------------ custody: keys, signatures, audit


@app.command()
@handle_errors
def keygen(
    key: Annotated[Path | None, typer.Option("--key", help="Where to write the private key (default: ~/.config/android-forensics/signing_key.pem).")] = None,
    force: Annotated[bool, typer.Option("--force", help="Replace an existing key (the old one is lost).")] = False,
) -> None:
    """Create an Ed25519 key pair for signing reports. Set ANDROID_FORENSICS_KEY_PASSPHRASE to encrypt the private key."""
    from android_forensics.custody import generate_keypair

    priv, pub, fp = generate_keypair(key, overwrite=force)
    console.print(stats_panel("Signing key created", [("Private key (keep secret, mode 0600)", str(priv)), ("Public key (share this)", str(pub)), ("Fingerprint", fp)]))


@app.command("verify-report")
@handle_errors
def verify_report_cmd(
    report_dir: Annotated[Path, typer.Argument(help="A report directory containing signature.json.")],
    trusted_key: Annotated[Path | None, typer.Option("--trusted-key", help="Public key (PEM) the signer must match.")] = None,
    fingerprint: Annotated[str | None, typer.Option("--fingerprint", help="Expected signer key fingerprint (hex).")] = None,
) -> None:
    """Verify a signed report: every file hash, the signature, and (optionally) that the signer is who you expect."""
    from android_forensics.custody import verify_report

    v = verify_report(report_dir, trusted_key, fingerprint)
    rows: list[tuple[str, object]] = [("Result", "VALID" if v.ok else "NOT VALID"), ("Signature", "valid" if v.signature_valid else "invalid"),
                                      ("Files checked", v.files_checked), ("Files that do not match", len(v.files_bad)),
                                      ("Signer", v.signer or "-"), ("Signed at", v.signed_at or "-"), ("Key fingerprint", v.key_fingerprint or "-"),
                                      ("Key pinned", {True: "yes - matches", False: "NO - mismatch", None: "no (self-consistent only)"}[v.key_trusted])]
    console.print(stats_panel("Report signature", rows))
    for m in v.messages:
        console.print(f"[yellow]•[/] {escape(m)}")
    if not v.ok:
        raise typer.Exit(1)


@app.command("audit-verify")
@handle_errors
def audit_verify(
    case: CaseArg,
    cases_dir: CasesDir = Path("cases"),
    harden: Annotated[bool, typer.Option("--harden", help="Also try to set the OS append-only flag on the audit log (may need privileges).")] = False,
    show: Annotated[int, typer.Option("--show", help="Print the last N audit entries.")] = 0,
) -> None:
    """Verify the case's command audit log (who ran what, when) and the database's custody chain."""
    from android_forensics.custody.audit import AUDIT_FILENAME, AuditLog
    from android_forensics.custody.audit import harden as harden_fn

    store = open_case(case, cases_dir)
    log = AuditLog(store.case_dir / AUDIT_FILENAME)
    v = log.verify()
    ok_db, msg_db = store.verify_custody_chain()
    console.print(stats_panel("Audit verification", [
        ("Command audit log", "intact" if v.ok else f"BROKEN at line {v.error_line}: {v.reason}"), ("Entries", v.entries), ("Chain head", v.head),
        ("Database custody chain", "intact" if ok_db else "BROKEN"), ("Database detail", msg_db)]))
    if show:
        for e in log.entries()[-show:]:
            console.print(escape(f"{e['seq']:>4} {e['ts']} {e['user']}@{e['host']} {e['command']} -> {e['outcome']}"), soft_wrap=True)
    if harden:
        console.print(escape(harden_fn(log.path)))
    if not (v.ok and ok_db):
        raise typer.Exit(1)


# ------------------------------------------------------------------ deployable server

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def allowed_hosts(configured: list[str] | None) -> tuple[str, ...]:
    """Host headers the server answers to: the configured public names plus loopback (container health checks and the proxy's
    upstream probe call it as 127.0.0.1; a browser on another machine cannot make *this* name arrive from outside)."""
    return tuple(dict.fromkeys([*(configured or ()), "localhost", "127.0.0.1", "[::1]"]))


@app.command()
@handle_errors
def serve(
    cases_dir: CasesDir = Path("cases"),
    data_dir: Annotated[Path, typer.Option("--data-dir", envvar="ANDROID_FORENSICS_DATA", help="Server state: token DB, uploads, job logs, audit log. Keep it OUTSIDE --cases-dir.")] = Path("server-data"),
    host: Annotated[str, typer.Option(help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Bind port.")] = 8765,
    allowed_host: Annotated[list[str] | None, typer.Option("--allowed-host", help="Host header value(s) this server answers to (repeatable). Required when binding beyond loopback.")] = None,
    allow_origin: Annotated[list[str] | None, typer.Option("--allow-origin", help="CORS origin(s) allowed to call the API (repeatable). Default: none (same-origin only).")] = None,
    tls_certfile: Annotated[Path | None, typer.Option(help="PEM certificate: serve HTTPS directly.")] = None,
    tls_keyfile: Annotated[Path | None, typer.Option(help="PEM private key for --tls-certfile.")] = None,
    behind_proxy: Annotated[bool, typer.Option("--behind-proxy", help="A TLS-terminating reverse proxy (Caddy/nginx) is in front: enables HSTS and trusts one X-Forwarded-For hop.")] = False,
    insecure_http: Annotated[bool, typer.Option("--insecure-http", help="Allow plain HTTP on a non-loopback address (tokens cross the network in clear text!).")] = False,
    max_upload_gb: Annotated[float, typer.Option(help="Largest accepted evidence upload, in GiB.")] = 64.0,
    workers: Annotated[int, typer.Option(help="Concurrent analysis jobs.")] = 2,
    job_memory_gb: Annotated[float, typer.Option(help="Per-job memory limit in GiB (enforced on Linux).")] = 8.0,
    job_hours: Annotated[float, typer.Option(help="Per-job wall-clock limit in hours.")] = 24.0,
    rate_limit: Annotated[int, typer.Option(help="Requests per minute per client IP.")] = 600,
    signing_key: Annotated[Path | None, typer.Option(help="Ed25519 key: sign every report the server's jobs produce.")] = None,
) -> None:
    """Run the authenticated multi-case web server (REST API + browser UI, background analysis jobs, uploads)."""
    import uvicorn

    from android_forensics.server import ServerSettings, create_server_app
    from android_forensics.server.db import ServerDB

    loopback = host in _LOOPBACK
    tls = tls_certfile is not None
    if bool(tls_certfile) != bool(tls_keyfile):
        raise CaseError("--tls-certfile and --tls-keyfile must be given together")
    if not loopback and not (tls or behind_proxy or insecure_http):
        raise CaseError(f"refusing to serve plain HTTP on {host}: bearer tokens would cross the network unencrypted. Use --tls-certfile/--tls-keyfile, "
                        "put a TLS proxy in front and pass --behind-proxy, or (not recommended) --insecure-http")
    if not loopback and not allowed_host:
        raise CaseError("when binding beyond loopback, name the host(s) clients use with --allowed-host (protects against Host-header attacks)")
    data_dir, cases_dir = data_dir.resolve(), cases_dir.resolve()
    if data_dir == cases_dir or cases_dir in data_dir.parents or data_dir in cases_dir.parents:
        raise CaseError("--data-dir and --cases-dir must be separate, non-nested directories")
    hosts = allowed_hosts(allowed_host)
    gib = 1024 ** 3
    settings = ServerSettings(
        cases_dir=cases_dir, data_dir=data_dir, max_upload_bytes=int(max_upload_gb * gib), workers=workers,
        rate_limit_per_minute=rate_limit, allowed_origins=tuple(allow_origin or ()), allowed_hosts=hosts,
        behind_tls=tls or behind_proxy, trust_proxy_hops=1 if behind_proxy else 0, job_memory_bytes=int(job_memory_gb * gib),
        job_wall_seconds=int(job_hours * 3600), signing_key=signing_key,
    )
    server_app = create_server_app(settings)
    if not ServerDB(settings.db_path).tokens():
        err_console.print(f"[bold yellow]No access tokens exist yet.[/] Create the first admin token with:\n  {TOOL_NAME} server-token create --data-dir {data_dir} --name admin --role admin")
    scheme = "https" if tls else "http"
    console.print(Text.assemble(("Server: ", "bold green"), f"{scheme}://{host}:{port}/  (cases: {cases_dir}; state: {data_dir})"), soft_wrap=True)
    uvicorn.run(server_app, host=host, port=port, log_level="warning", ssl_certfile=str(tls_certfile) if tls_certfile else None,
                ssl_keyfile=str(tls_keyfile) if tls_keyfile else None, proxy_headers=False, server_header=False)


token_app = typer.Typer(help="Manage the access tokens of the web server.", no_args_is_help=True, add_completion=False)
app.add_typer(token_app, name="server-token")
DataDir = Annotated[Path, typer.Option("--data-dir", envvar="ANDROID_FORENSICS_DATA", help="The server's --data-dir.")]


@token_app.command("create")
@handle_errors
def token_create(
    name: Annotated[str, typer.Option(help="Who the token is for (shown in audit logs).")],
    role: Annotated[str, typer.Option(help="viewer (read), analyst (+ upload/analyse) or admin (+ tokens, delete).")] = "viewer",
    data_dir: DataDir = Path("server-data"),
) -> None:
    """Create an access token. It is printed ONCE; only its SHA-256 is stored."""
    from android_forensics.server.auth import ROLES, hash_token, new_token
    from android_forensics.server.db import ServerDB

    if role not in ROLES:
        raise CaseError(f"role must be one of: {', '.join(ROLES)}")
    token = new_token()
    token_id = ServerDB(data_dir / "server.db").add_token(name, role, hash_token(token))
    console.print(stats_panel("Token created", [("Id", token_id), ("Name", name), ("Role", role)]))
    console.print(Text.assemble(("Token (shown once): ", "bold yellow"), token), soft_wrap=True)


@token_app.command("list")
@handle_errors
def token_list(data_dir: DataDir = Path("server-data")) -> None:
    """List tokens (never their secrets)."""
    from android_forensics.server.db import ServerDB

    t = SafeTable(title="Tokens", header_style="bold")
    for c in ("Id", "Name", "Role", "Created", "Last used", "Revoked"):
        t.add_column(c)
    for r in ServerDB(data_dir / "server.db").tokens():
        t.add_row(str(r["id"]), r["name"], r["role"], r["created_at"], r["last_used_at"] or "-", r["revoked_at"] or "-")
    console.print(t)


@token_app.command("revoke")
@handle_errors
def token_revoke(token_id: Annotated[int, typer.Argument(help="Token id (see 'server-token list').")], data_dir: DataDir = Path("server-data")) -> None:
    """Revoke a token immediately."""
    from android_forensics.server.db import ServerDB

    if not ServerDB(data_dir / "server.db").revoke_token(token_id):
        raise CaseError(f"no active token with id {token_id}")
    console.print(f"[green]✓[/] token {token_id} revoked")


@app.command("plugins")
@handle_errors
def plugins_cmd() -> None:
    """List the parsers in effect: built-in ones and any plugins loaded for this run."""
    from android_forensics import plugins
    from android_forensics.artifacts.registry import get_parsers

    t = SafeTable(title="Parsers", header_style="bold")
    for c in ("Name", "Version", "Origin"):
        t.add_column(c)
    for p in get_parsers():
        t.add_row(p.name, p.version, "built-in" if plugins.is_builtin(p) else "plugin")
    console.print(t)
    for lp in plugins.LOADED:
        console.print(escape(f"plugin {lp.name}: {lp.origin}  sha256={lp.sha256 or '-'}  parsers={', '.join(lp.parsers) or '-'}"), soft_wrap=True)
