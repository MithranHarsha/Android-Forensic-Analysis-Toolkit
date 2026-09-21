import hashlib
import os

import pytest

from android_forensics.acquisition.hashing import hash_file
from android_forensics.acquisition.safety import BudgetExceeded, ExtractionBudget, UnsafePathError, normalize_member_path


def test_hash_matches_hashlib_across_chunks(tmp_path):
    data = os.urandom(2_600_000)
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    d = hash_file(p)
    assert d.sha256 == hashlib.sha256(data).hexdigest()
    assert d.sha1 == hashlib.sha1(data).hexdigest()
    assert d.md5 == hashlib.md5(data).hexdigest()
    assert d.size == len(data)


def test_empty_file_hash(tmp_path):
    p = tmp_path / "e"
    p.write_bytes(b"")
    assert hash_file(p).sha256 == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("bad", ["../evil", "a/../../evil", "C:\\windows\\x", "a\x00b", "", "./", "///"])
def test_unsafe_paths_rejected(bad):
    with pytest.raises(UnsafePathError):
        normalize_member_path(bad)


@pytest.mark.parametrize(
    "raw,expected",
    [("/data/data/x/a.db", "data/data/x/a.db"), ("./a//b/./c", "a/b/c"), ("a\\b\\c.txt", "a/b/c.txt")],
)
def test_path_normalisation(raw, expected):
    assert normalize_member_path(raw) == expected


def test_budget_limits():
    b = ExtractionBudget(max_entries=2, max_total_bytes=100, max_member_bytes=60)
    b.charge_entry()
    b.charge_entry()
    with pytest.raises(BudgetExceeded):
        b.charge_entry()
    b2 = ExtractionBudget(max_total_bytes=100, max_member_bytes=60)
    with pytest.raises(BudgetExceeded):
        b2.charge_bytes(10, member_total=61)
    b3 = ExtractionBudget(max_total_bytes=100)
    b3.charge_bytes(60, 60)
    with pytest.raises(BudgetExceeded):
        b3.charge_bytes(60, 60)
