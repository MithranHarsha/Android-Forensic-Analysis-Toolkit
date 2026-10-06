from __future__ import annotations

import base64
import hashlib

from android_forensics.filesystem.encryption import find_fbe_directories, looks_like_fbe_name


def fbe(i: int) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(f"name{i}".encode()).digest()[:18]).decode().rstrip("=")


def test_ciphertext_like_names_are_recognised():
    names = [fbe(i) for i in range(20)]
    assert sum(looks_like_fbe_name(n) for n in names) >= 18


def test_ordinary_names_are_not():
    for n in ("databases", "com.android.providers.telephony", "mmssms.db", "shared_prefs", "a" * 30, "0123456789abcdef0123456789abcdef",
              "550e8400-e29b-41d4-a716-446655440000", "SomeCamelCaseDirectoryNameHere", "lib-arm64-v8a-release"):
        assert not looks_like_fbe_name(n), n


def test_directory_of_ciphertext_is_reported_once_at_the_outermost_level():
    paths = [f"data/data/{fbe(i)}/{fbe(100 + i)}/file" for i in range(6)] + ["data/data/readme.txt"]
    found = find_fbe_directories(paths)
    assert [d.path for d in found] == ["data/data"]
    assert found[0].encrypted_looking == 6 and "never decrypts" in found[0].detail


def test_a_few_odd_names_in_a_normal_tree_do_not_trigger():
    paths = ["data/data/com.a/databases/x.db", "data/data/com.b/files/y", f"data/data/{fbe(1)}/z", "data/data/com.c/cache/q"]
    assert find_fbe_directories(paths) == []


def test_synthetic_dump_has_no_encryption_findings(analyzed):
    store, *_ = analyzed
    assert store.scalar("SELECT COUNT(*) FROM scan_issues WHERE issue_type='file_based_encryption_suspected'") == 0


def test_scan_reports_fbe_directory_end_to_end(tmp_path):
    from android_forensics.acquisition.ingest import ingest_source
    from android_forensics.pipeline.runner import run_stage
    from android_forensics.storage.case_store import CaseStore

    dump = tmp_path / "dump"
    for i in range(5):
        d = dump / "data" / "data" / fbe(i)
        d.mkdir(parents=True)
        (d / fbe(50 + i)).write_bytes(bytes(range(256)) * 4)
    store = CaseStore.create(tmp_path / "case", "enc", "t")
    ingest_source(store, dump)
    run_stage(store, "scan")
    rows = store.q("SELECT path, detail FROM scan_issues WHERE issue_type='file_based_encryption_suspected'")
    assert len(rows) == 1 and "never decrypts" in rows[0]["detail"]
