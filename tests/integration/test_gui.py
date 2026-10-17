"""The desktop window reads a finished case read-only and shows exactly what is in its database (skipped without PySide6)."""

import os
import sqlite3

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from android_forensics.gui import app as gui  # noqa: E402


@pytest.fixture(scope="session")  # one QApplication per process, alive for as long as any widget is
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def ui(qapp):
    """Hands out widgets and destroys them here, with the application still alive.

    Leaving them to Python's garbage collector instead means Qt tears them down at an arbitrary later moment — often
    during interpreter shutdown, where it segfaults ("shared QObject was deleted directly") after every test has passed.
    """
    made = []

    def keep(widget):
        made.append(widget)
        return widget

    yield keep
    for widget in made:
        widget.close()
        widget.deleteLater()
    qapp.processEvents()


def test_case_view_shows_the_database_rows(ui, analyzed):
    store, *_ = analyzed
    case_dir = store.case_dir
    view = ui(gui.CaseView())
    view.show_case(case_dir)
    conn = sqlite3.connect(f"file:{case_dir / 'case.db'}?mode=ro", uri=True)
    expected = conn.execute("SELECT COUNT(*) FROM artifacts WHERE artifact_type!='app_summary'").fetchone()[0]
    conn.close()
    assert view.tables["Artifacts"].model.rowCount() == min(expected, gui.ROW_CAP) > 0
    assert "Artifacts by status" in view.overview.toHtml()


def test_hostile_text_is_shown_as_text(qapp):
    assert "\x1b" not in gui.clean("a\x1b[31mred\x1b[0m")


def test_filter_narrows_rows(ui, analyzed):
    store, *_ = analyzed
    case_dir = store.case_dir
    view = ui(gui.CaseView())
    view.show_case(case_dir)
    t = view.tables["Artifacts"]
    total = t.proxy.rowCount()
    t.filter.setText("zzz-no-such-text-zzz")
    assert t.proxy.rowCount() == 0 < total


def test_choosing_a_saved_case_opens_it_instead_of_rerunning(ui, analyzed, monkeypatch):
    store, *_ = analyzed
    win = ui(gui.MainWindow())
    started = []
    monkeypatch.setattr(gui.QProcess, "start", lambda *a, **k: started.append(a))
    win.start_analysis(str(store.case_dir))
    assert not started and win.pages.currentWidget() is win.case_view


def test_choosing_the_case_library_is_refused(ui, tmp_path, monkeypatch):
    monkeypatch.setattr(gui, "CASES_DIR", tmp_path)
    win = ui(gui.MainWindow())
    warned = []
    monkeypatch.setattr(gui.QMessageBox, "warning", lambda *a, **k: warned.append(a))
    started = []
    monkeypatch.setattr(gui.QProcess, "start", lambda *a, **k: started.append(a))
    win.start_analysis(str(tmp_path))
    assert warned and not started
