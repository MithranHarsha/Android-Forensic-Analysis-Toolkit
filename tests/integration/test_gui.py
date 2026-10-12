"""The desktop window reads a finished case read-only and shows exactly what is in its database (skipped without PySide6)."""

import os
import sqlite3

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from android_forensics.gui import app as gui  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def test_case_view_shows_the_database_rows(qapp, analyzed):
    store, *_ = analyzed
    case_dir = store.case_dir
    view = gui.CaseView()
    view.show_case(case_dir)
    conn = sqlite3.connect(f"file:{case_dir / 'case.db'}?mode=ro", uri=True)
    expected = conn.execute("SELECT COUNT(*) FROM artifacts WHERE artifact_type!='app_summary'").fetchone()[0]
    conn.close()
    assert view.tables["Active data"].model.rowCount() == min(expected, gui.ROW_CAP) > 0
    assert "Active data by type" in view.overview.toHtml()


def test_hostile_text_is_shown_as_text(qapp):
    assert "\x1b" not in gui.clean("a\x1b[31mred\x1b[0m")


def test_filter_narrows_rows(qapp, analyzed):
    store, *_ = analyzed
    case_dir = store.case_dir
    view = gui.CaseView()
    view.show_case(case_dir)
    t = view.tables["Active data"]
    total = t.proxy.rowCount()
    t.filter.setText("zzz-no-such-text-zzz")
    assert t.proxy.rowCount() == 0 < total
