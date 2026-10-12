"""Desktop front-end: a case library, drag-and-drop analysis with live progress, and result tables — all in one window.

It reads finished cases from their ``case.db`` (opened read-only) and runs the analysis as a separate ``android-forensics analyze``
process, so the GUI adds no new analysis code path: what you see is exactly what the command line produced."""

from __future__ import annotations

import html
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import QProcess, QSortFilterProxyModel, Qt, QUrl
from PySide6.QtGui import QDesktopServices, QIcon, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableView,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from android_forensics.cli.console import sanitize

CASES_DIR = Path.home() / "Documents" / "AndroidForensicsCases"
ROW_CAP = 20_000  # a table view with more rows than this is a report job, not a screen

# tab title -> (query, column headers). Columns are plain text so any value from hostile evidence is shown, never interpreted.
TABS: dict[str, tuple[str, list[str]]] = {
    "Active data": (
        "SELECT artifact_type, status, confidence, COALESCE(ts_utc,''), COALESCE(application,''), summary FROM artifacts "
        "WHERE artifact_type!='app_summary' ORDER BY ts_utc, id",
        ["Type", "Status", "Confidence", "Time (UTC)", "App", "Summary"]),
    "Recovered (deleted)": (
        "SELECT table_name, status, COALESCE(rowid_value,''), source, printf('%.2f', fit), values_json, COALESCE(issues_json,'') "
        "FROM recovered_records ORDER BY table_name, id",
        ["Table", "Status", "Row id", "Source", "Fit", "Values", "Issues"]),
    "Carved": (
        "SELECT kind, COALESCE(confidence,''), matched, byte_offset, source_file, COALESCE(explanation,'') FROM carved_candidates ORDER BY id",
        ["Kind", "Confidence", "Matched text", "Offset", "Source file", "Why"]),
    "Timeline": (
        "SELECT ts_utc, event_kind, COALESCE(artifact_type,''), event, COALESCE(status,''), COALESCE(confidence,'') FROM timeline_events "
        "ORDER BY ts_utc, id",
        ["Time (UTC)", "Kind", "Type", "Event", "Status", "Confidence"]),
    "Validation": (
        "SELECT status, check_name, COALESCE(target_label,''), detail FROM validation_results "
        "ORDER BY CASE status WHEN 'INVALID' THEN 0 WHEN 'PARTIAL' THEN 1 WHEN 'UNVERIFIED' THEN 2 ELSE 3 END, id",
        ["Status", "Check", "Target", "Detail"]),
    "Chain of custody": (
        "SELECT id, ts, actor, action, COALESCE(target,''), substr(entry_hash,1,16) FROM custody_log ORDER BY id",
        ["#", "Time", "Actor", "Action", "Target", "Hash"]),
}


def clean(v: Any) -> str:
    return sanitize(str(v)) if v is not None else ""


def open_ro(case: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{case / 'case.db'}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def list_cases() -> list[Path]:
    if not CASES_DIR.is_dir():
        return []
    found = [p for p in CASES_DIR.iterdir() if (p / "case.db").is_file()]
    return sorted(found, key=lambda p: (p / "case.db").stat().st_mtime, reverse=True)


class SqlTable(QWidget):
    """A sortable, filterable, read-only table filled from one query."""

    def __init__(self, query: str, headers: list[str]):
        super().__init__()
        self.query, self.headers = query, headers
        self.model = QStandardItemModel(0, len(headers))
        self.model.setHorizontalHeaderLabels(headers)
        self.proxy = QSortFilterProxyModel()
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter rows…")
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self.proxy.setFilterFixedString)
        self.note = QLabel()
        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.setAlternatingRowColors(True)
        self.view.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.verticalHeader().setVisible(False)
        top = QHBoxLayout()
        top.addWidget(self.filter, 1)
        top.addWidget(self.note)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.view)

    def load(self, conn: sqlite3.Connection) -> None:
        self.model.removeRows(0, self.model.rowCount())
        self.view.setSortingEnabled(False)
        n = 0
        for n, row in enumerate(conn.execute(self.query + f" LIMIT {ROW_CAP + 1}"), 1):
            if n > ROW_CAP:
                break
            items = []
            for v in row:
                it = QStandardItem(clean(v)[:600])
                it.setEditable(False)
                items.append(it)
            self.model.appendRow(items)
        self.view.setSortingEnabled(True)
        self.view.resizeColumnsToContents()
        for c in range(len(self.headers)):
            self.view.setColumnWidth(c, min(self.view.columnWidth(c), 380))
        self.note.setText(f"{min(n, ROW_CAP):,} rows" + (f" (first {ROW_CAP:,} shown; the exported reports hold everything)" if n > ROW_CAP else ""))


class CaseView(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.case: Path | None = None
        self.title = QLabel()
        self.title.setStyleSheet("font-size: 20px; font-weight: 600;")
        self.report_btn = QPushButton("Open report folder")
        self.report_btn.clicked.connect(self.open_reports)
        self.folder_btn = QPushButton("Show case in Finder")
        self.folder_btn.clicked.connect(lambda: self.case and QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.case))))
        head = QHBoxLayout()
        head.addWidget(self.title, 1)
        head.addWidget(self.report_btn)
        head.addWidget(self.folder_btn)
        self.overview = QTextBrowser()
        self.tabs = QTabWidget()
        self.tabs.addTab(self.overview, "Overview")
        self.tables = {name: SqlTable(q, h) for name, (q, h) in TABS.items()}
        for name, tbl in self.tables.items():
            self.tabs.addTab(tbl, name)
        lay = QVBoxLayout(self)
        lay.addLayout(head)
        lay.addWidget(self.tabs)

    def open_reports(self) -> None:
        if self.case:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.case / "reports")))

    def show_case(self, case: Path) -> None:
        self.case = case
        self.title.setText(clean(case.name))
        conn = open_ro(case)
        try:
            self.overview.setHtml(self._overview(conn))
            for tbl in self.tables.values():
                tbl.load(conn)
            for i, name in enumerate(self.tables, 1):
                n = self.tables[name].model.rowCount()
                self.tabs.setTabText(i, f"{name} ({n:,})")
        finally:
            conn.close()

    @staticmethod
    def _count(conn: sqlite3.Connection, sql: str) -> list[tuple[str, int]]:
        try:
            return [(clean(r[0]), int(r[1])) for r in conn.execute(sql)]
        except sqlite3.Error:
            return []

    def _overview(self, conn: sqlite3.Connection) -> str:
        def block(title: str, rows: list[tuple[str, int]]) -> str:
            if not rows:
                return ""
            body = "".join(f"<tr><td>{html.escape(k)}</td><td align='right'><b>{v:,}</b></td></tr>" for k, v in rows)
            return f"<h3>{html.escape(title)}</h3><table cellpadding='3'>{body}</table>"

        case = conn.execute("SELECT * FROM cases LIMIT 1").fetchone()
        det = f"<p>Examiner: {html.escape(clean(case['examiner']))} · created {html.escape(clean(case['created_at']))} · tool {html.escape(clean(case['tool_version']))}</p>" if case else ""
        parts = [
            det,
            block("Active data by type", self._count(conn, "SELECT artifact_type, COUNT(*) FROM artifacts WHERE artifact_type!='app_summary' GROUP BY 1 ORDER BY 2 DESC")),
            block("Recovered deleted records", self._count(conn, "SELECT status, COUNT(*) FROM recovered_records GROUP BY 1 ORDER BY 2 DESC")),
            block("Carved candidates (unconfirmed)", self._count(conn, "SELECT kind, COUNT(*) FROM carved_candidates GROUP BY 1 ORDER BY 2 DESC")),
            block("Validation checks", self._count(conn, "SELECT status, COUNT(*) FROM validation_results GROUP BY 1 ORDER BY 2 DESC")),
        ]
        if not any(p for p in parts[1:]):
            parts.append("<p>No results in this case yet.</p>")
        parts.append("<p style='color:gray'>Carved candidates are never confirmed evidence. Recovered PARTIAL/CORRUPTED records had bytes overwritten; "
                     "see their confidence explanation in the report.</p>")
        return "".join(parts)


class AnalysePage(QWidget):
    """Drop zone + buttons, then live progress while the analysis process runs."""

    def __init__(self, start) -> None:
        super().__init__()
        self.start = start
        self.drop = QLabel("Drop an Android evidence folder, ZIP/TAR or disk image here\n\nor use the buttons below")
        self.drop.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop.setStyleSheet("border: 2px dashed gray; border-radius: 12px; padding: 60px; font-size: 16px;")
        b1, b2 = QPushButton("Choose folder…"), QPushButton("Choose file…")
        b1.clicked.connect(lambda: self._pick(True))
        b2.clicked.connect(lambda: self._pick(False))
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(b1)
        row.addWidget(b2)
        row.addStretch()
        self.status = QLabel()
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)
        self.bar.hide()
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(2000)
        self.log.hide()
        lay = QVBoxLayout(self)
        lay.addWidget(self.drop, 1)
        lay.addLayout(row)
        lay.addWidget(self.status)
        lay.addWidget(self.bar)
        lay.addWidget(self.log, 1)

    def _pick(self, folder: bool) -> None:
        path = QFileDialog.getExistingDirectory(self, "Evidence folder") if folder else QFileDialog.getOpenFileName(self, "Evidence file")[0]
        if path:
            self.start(path)

    def busy(self, on: bool) -> None:
        self.bar.setVisible(on)
        self.log.setVisible(on)
        self.drop.setVisible(not on)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Android Forensics")
        self.resize(1280, 800)
        self.setAcceptDrops(True)
        self.proc: QProcess | None = None
        self.new_case_name = ""
        self.library = QListWidget()
        self.library.currentItemChanged.connect(self._selected)
        new = QPushButton("＋  New analysis")
        side = QWidget()
        sl = QVBoxLayout(side)
        sl.addWidget(new)
        sl.addWidget(QLabel("Cases"))
        sl.addWidget(self.library, 1)
        self.analyse = AnalysePage(self.start_analysis)
        self.case_view = CaseView()
        self.pages = QStackedWidget()
        self.pages.addWidget(self.analyse)
        self.pages.addWidget(self.case_view)
        new.clicked.connect(lambda: self.pages.setCurrentWidget(self.analyse))
        split = QSplitter()
        split.addWidget(side)
        split.addWidget(self.pages)
        split.setSizes([260, 1000])
        self.setCentralWidget(split)
        self.refresh()
        if self.library.count():
            self.library.setCurrentRow(0)

    # ------------------------------------------------------------------ library
    def refresh(self, select: str | None = None) -> None:
        self.library.blockSignals(True)
        self.library.clear()
        for p in list_cases():
            it = QListWidgetItem(clean(p.name))
            it.setData(Qt.ItemDataRole.UserRole, str(p))
            self.library.addItem(it)
            if select and p.name == select:
                self.library.setCurrentItem(it)
        self.library.blockSignals(False)

    def _selected(self, item: QListWidgetItem | None) -> None:
        if item is None:
            return
        try:
            self.case_view.show_case(Path(item.data(Qt.ItemDataRole.UserRole)))
            self.pages.setCurrentWidget(self.case_view)
        except sqlite3.Error as exc:
            QMessageBox.warning(self, "Cannot open case", f"{exc}")

    # ------------------------------------------------------------------ drag and drop
    def dragEnterEvent(self, e) -> None:  # noqa: N802 (Qt API)
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e) -> None:  # noqa: N802
        urls = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if urls:
            self.start_analysis(urls[0])

    # ------------------------------------------------------------------ analysis
    def start_analysis(self, path: str) -> None:
        if self.proc is not None:
            QMessageBox.information(self, "Busy", "An analysis is already running.")
            return
        CASES_DIR.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in Path(path).name) or "evidence"
        self.new_case_name = f"{safe}-{time.strftime('%Y%m%d-%H%M%S')}"
        self.pages.setCurrentWidget(self.analyse)
        self.analyse.busy(True)
        self.analyse.log.clear()
        self.analyse.status.setText(f"Analysing {clean(Path(path).name)} — the original is opened read-only and never modified")
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self._output)
        self.proc.finished.connect(self._finished)
        self.proc.start(sys.executable, ["-m", "android_forensics", "analyze", path, "--cases-dir", str(CASES_DIR),
                                         "--name", self.new_case_name, "--workers", "auto"])

    def _output(self) -> None:
        if self.proc is None:
            return
        text = bytes(self.proc.readAllStandardOutput().data()).decode("utf-8", "replace")
        text = clean(text)
        self.analyse.log.appendPlainText(text.rstrip())
        lines = [ln.strip() for ln in text.splitlines() if any(ch.isalpha() for ch in ln)]
        if lines:
            self.analyse.status.setText(lines[-1][:140])

    def _finished(self, code: int, _status) -> None:
        self.proc = None
        self.analyse.busy(False)
        self.refresh(select=self.new_case_name)
        if code == 0 and (CASES_DIR / self.new_case_name / "case.db").is_file():
            self.analyse.status.setText("")
            self._selected(self.library.currentItem())
        else:
            self.analyse.status.setText(f"The analysis did not complete (exit code {code}). The log is above.")
            self.analyse.log.show()


def main() -> int:
    app = QApplication(sys.argv[:1])
    app.setApplicationName("Android Forensics")
    icon = os.environ.get("ANDROID_FORENSICS_ICON")
    if icon and Path(icon).is_file():
        app.setWindowIcon(QIcon(icon))
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
