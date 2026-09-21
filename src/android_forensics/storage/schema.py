"""Case database schema, expressed as numbered migrations.

Review 2 adds ``recovered_records``, ``carved_candidates``, ``wal_frames``,
``freelist_pages`` and ``correlations`` as migration 002 — no Review 1 table
needs to change. ``artifacts`` already carries nullable physical-location and
confidence columns for that purpose.
"""

from __future__ import annotations

MIGRATION_001 = """
CREATE TABLE cases(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    examiner TEXT,
    description TEXT,
    created_at TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    layout TEXT,
    layout_detail TEXT
);

CREATE TABLE evidence_sources(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    original_path TEXT NOT NULL,
    original_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    container_size INTEGER,
    container_md5 TEXT,
    container_sha1 TEXT,
    container_sha256 TEXT,
    acquisition_time TEXT,
    ingested_at TEXT NOT NULL,
    file_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    complete INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE evidence_files(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES evidence_sources(id),
    ordinal INTEGER NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    md5 TEXT NOT NULL,
    sha1 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    kind TEXT NOT NULL,
    kind_detail TEXT,
    mtime TEXT, atime TEXT, ctime TEXT, time_basis TEXT,
    preserved_copy TEXT,
    logical_path TEXT,
    android_root TEXT,
    user_id INTEGER,
    package TEXT,
    UNIQUE(source_id, ordinal)
);
CREATE INDEX idx_files_kind ON evidence_files(kind);
CREATE INDEX idx_files_pkg ON evidence_files(package);
CREATE INDEX idx_files_sha ON evidence_files(sha256);

CREATE TABLE scan_issues(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER REFERENCES evidence_sources(id),
    path TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    detail TEXT,
    stage TEXT NOT NULL DEFAULT 'ingest',
    created_at TEXT NOT NULL
);

CREATE TABLE databases(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_file_id INTEGER NOT NULL UNIQUE REFERENCES evidence_files(id),
    header_valid INTEGER NOT NULL,
    header_json TEXT,
    page_size INTEGER,
    page_count_header INTEGER,
    expected_size INTEGER,
    actual_size INTEGER,
    size_consistent INTEGER,
    text_encoding TEXT,
    journal_mode TEXT,
    freelist_page_count INTEGER,
    schema_cookie INTEGER,
    user_version INTEGER,
    application_id INTEGER,
    has_wal INTEGER NOT NULL DEFAULT 0,
    has_shm INTEGER NOT NULL DEFAULT 0,
    has_journal INTEGER NOT NULL DEFAULT 0,
    sidecars_json TEXT,
    view_includes_wal INTEGER,
    sqlite_status TEXT NOT NULL DEFAULT 'UNVERIFIED',
    sqlite_status_detail TEXT,
    open_status TEXT NOT NULL,
    open_error TEXT,
    integrity_status TEXT,
    integrity_detail TEXT,
    table_count INTEGER NOT NULL DEFAULT 0,
    decode_errors INTEGER NOT NULL DEFAULT 0,
    warnings_json TEXT,
    version_json TEXT,
    engine_json TEXT
);

CREATE TABLE app_directories(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES evidence_sources(id),
    package TEXT NOT NULL,
    path TEXT NOT NULL,
    logical_path TEXT,
    root TEXT,
    area TEXT,
    user_id INTEGER,
    known_app TEXT,
    subdirectories_json TEXT,
    file_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    database_count INTEGER NOT NULL DEFAULT 0,
    kind_counts_json TEXT
);
CREATE INDEX idx_app_pkg ON app_directories(package);

CREATE TABLE db_tables(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    database_id INTEGER NOT NULL REFERENCES databases(id),
    name TEXT NOT NULL,
    obj_type TEXT NOT NULL,
    root_page INTEGER,
    sql TEXT,
    rowid_table INTEGER,
    is_virtual INTEGER NOT NULL DEFAULT 0,
    row_count INTEGER,
    columns_json TEXT,
    parsed_by TEXT,
    schema_variant TEXT,
    schema_score REAL,
    hints_json TEXT,
    read_error TEXT,
    details_json TEXT
);
CREATE INDEX idx_tables_db ON db_tables(database_id);

CREATE TABLE analysis_runs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    stage TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    params_json TEXT,
    stats_json TEXT,
    error TEXT
);

CREATE TABLE artifacts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES analysis_runs(id),
    artifact_type TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence TEXT,
    confidence_factors_json TEXT,
    extraction_method TEXT NOT NULL,
    validation_notes_json TEXT,
    application TEXT,
    evidence_file_id INTEGER NOT NULL REFERENCES evidence_files(id),
    database_id INTEGER REFERENCES databases(id),
    source_file TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    source_database TEXT,
    source_table TEXT,
    source_rowid INTEGER,
    view_includes_wal INTEGER,
    page_number INTEGER,
    cell_index INTEGER,
    byte_offset INTEGER,
    page_type TEXT,
    region TEXT,
    raw_kind TEXT NOT NULL,
    raw_row_json TEXT,
    raw_hex TEXT,
    raw_sha256 TEXT NOT NULL,
    parser TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    schema_variant TEXT,
    schema_match_score REAL,
    ts_utc TEXT,
    ts_raw TEXT,
    ts_format TEXT,
    ts_plausible INTEGER,
    ts_note TEXT,
    summary TEXT,
    fields_json TEXT NOT NULL,
    unknown_fields_json TEXT,
    phone_key TEXT,
    marked_deleted INTEGER NOT NULL DEFAULT 0,
    flags_json TEXT,
    metadata_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_art_type ON artifacts(artifact_type);
CREATE INDEX idx_art_status ON artifacts(status);
CREATE INDEX idx_art_ts ON artifacts(ts_utc);
CREATE INDEX idx_art_phone ON artifacts(phone_key);
CREATE INDEX idx_art_db ON artifacts(database_id);

CREATE TABLE messages(
    artifact_id INTEGER PRIMARY KEY REFERENCES artifacts(id),
    address TEXT, address_kind TEXT, body TEXT, direction TEXT, type_code INTEGER,
    read INTEGER, thread_id INTEGER, date_sent_utc TEXT, service_center TEXT,
    subscription_id INTEGER, phone_key TEXT
);
CREATE TABLE calls(
    artifact_id INTEGER PRIMARY KEY REFERENCES artifacts(id),
    number TEXT, call_type TEXT, type_code INTEGER, duration_seconds INTEGER,
    presentation TEXT, cached_name TEXT, lookup_uri TEXT, subscription_id TEXT,
    phone_account_address TEXT, phone_key TEXT
);
CREATE TABLE contacts(
    artifact_id INTEGER PRIMARY KEY REFERENCES artifacts(id),
    contact_id INTEGER, display_name TEXT, phones_json TEXT, emails_json TEXT,
    account_name TEXT, account_type TEXT, last_updated_utc TEXT, marked_deleted INTEGER
);
CREATE TABLE browser_history(
    artifact_id INTEGER PRIMARY KEY REFERENCES artifacts(id),
    entry_kind TEXT NOT NULL, url TEXT, title TEXT, visit_count INTEGER,
    transition TEXT, target_path TEXT, total_bytes INTEGER, download_state TEXT
);

CREATE TABLE validation_results(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES analysis_runs(id),
    target_type TEXT NOT NULL,
    target_id INTEGER,
    target_label TEXT,
    check_name TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT NOT NULL,
    evidence_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_val_status ON validation_results(status);

CREATE TABLE timeline_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES analysis_runs(id),
    ts_utc TEXT NOT NULL,
    ts_raw TEXT,
    time_basis TEXT,
    event_kind TEXT NOT NULL,
    artifact_type TEXT,
    event TEXT NOT NULL,
    source TEXT,
    status TEXT,
    confidence TEXT,
    artifact_id INTEGER REFERENCES artifacts(id),
    evidence_file_id INTEGER REFERENCES evidence_files(id)
);
CREATE INDEX idx_tl_ts ON timeline_events(ts_utc);

CREATE TABLE custody_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail_json TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""

MIGRATION_002 = """
-- Review 2: deleted-data recovery, carving, correlation. Staging tables keep raw findings; artifacts are built from them.
CREATE TABLE recovered_records(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES analysis_runs(id),
    database_id INTEGER REFERENCES databases(id),
    database_file_id INTEGER NOT NULL REFERENCES evidence_files(id),
    source TEXT NOT NULL,                 -- main | wal | journal
    source_file_id INTEGER NOT NULL REFERENCES evidence_files(id),
    source_path TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    table_name TEXT NOT NULL,
    rowid_value INTEGER,
    status TEXT NOT NULL,                 -- RECOVERED | PARTIAL | CORRUPTED
    method TEXT NOT NULL,
    page_number INTEGER NOT NULL,
    page_offset INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    length INTEGER NOT NULL,
    page_type TEXT,
    region TEXT NOT NULL,
    cell_index INTEGER,
    frame INTEGER,
    raw_hex TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    fit REAL NOT NULL,
    values_json TEXT NOT NULL,
    unknown_columns_json TEXT NOT NULL,
    issues_json TEXT NOT NULL,
    also_found_at_json TEXT NOT NULL,
    artifact_id INTEGER REFERENCES artifacts(id)
);
CREATE INDEX idx_rec_db ON recovered_records(database_id);
CREATE INDEX idx_rec_status ON recovered_records(status);

CREATE TABLE unrecovered_regions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES analysis_runs(id),
    database_id INTEGER REFERENCES databases(id),
    source TEXT NOT NULL,
    source_path TEXT NOT NULL,
    page_number INTEGER NOT NULL,
    page_offset INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    length INTEGER NOT NULL,
    region TEXT NOT NULL,
    reason TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    frame INTEGER
);

CREATE TABLE wal_frames(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES analysis_runs(id),
    database_id INTEGER NOT NULL REFERENCES databases(id),
    frame_index INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    page_number INTEGER NOT NULL,
    commit_size INTEGER NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE freelist_pages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES analysis_runs(id),
    database_id INTEGER NOT NULL REFERENCES databases(id),
    page_number INTEGER NOT NULL,
    role TEXT NOT NULL                    -- trunk | leaf
);

CREATE TABLE carved_candidates(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES analysis_runs(id),
    evidence_file_id INTEGER NOT NULL REFERENCES evidence_files(id),
    source_file TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    byte_offset INTEGER NOT NULL,
    length INTEGER NOT NULL,
    kind TEXT NOT NULL,
    pattern TEXT NOT NULL,
    matched TEXT NOT NULL,
    encoding TEXT NOT NULL,
    container TEXT NOT NULL DEFAULT 'file',
    context_valid INTEGER NOT NULL DEFAULT 1,
    context_before_hex TEXT NOT NULL,
    context_after_hex TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'CARVED CANDIDATE' CHECK (status = 'CARVED CANDIDATE'),
    confidence TEXT,
    confidence_factors_json TEXT NOT NULL,
    explanation TEXT NOT NULL,
    corroborated_by_json TEXT NOT NULL,
    notes_json TEXT NOT NULL
);
CREATE INDEX idx_carved_file ON carved_candidates(evidence_file_id);
CREATE INDEX idx_carved_kind ON carved_candidates(kind);

CREATE TABLE correlations(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES analysis_runs(id),
    source_kind TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    relation TEXT NOT NULL,
    strength REAL NOT NULL,
    explanation TEXT NOT NULL,
    evidence_json TEXT NOT NULL
);
CREATE INDEX idx_corr_source ON correlations(source_ref);
CREATE INDEX idx_corr_target ON correlations(target_ref);
"""

MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "Review 1 foundation schema", MIGRATION_001),
    (2, "Review 2: recovered records, carved candidates, correlations", MIGRATION_002),
]
