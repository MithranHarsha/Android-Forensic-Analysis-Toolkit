from __future__ import annotations

import base64
import hashlib

from android_forensics.filesystem.encryption import find_fbe_directories, looks_like_fbe_name


def fbe(i: int, blocks: int = 1) -> str:
    """A name shaped like an fscrypt-encrypted one: 16*blocks bytes of ciphertext, URL-safe base64 without padding."""
    raw = b"".join(hashlib.sha256(f"name{i}-{b}".encode()).digest() for b in range(2))[: 16 * blocks]
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_ciphertext_like_names_are_recognised():
    names = [fbe(i) for i in range(20)] + [fbe(i, 2) for i in range(20)]
    assert sum(looks_like_fbe_name(n) for n in names) >= 36
    assert {len(fbe(1, k)) for k in (1, 2, 3, 4)} == {22, 43, 64, 86}


def test_hash_named_cache_files_are_not_ciphertext():
    """Real-corpus regression (Pixel 3, Android 9, decrypted): app caches name files after base64 SHA-1/SHA-256 digests."""
    sha1 = [base64.urlsafe_b64encode(hashlib.sha1(f"k{i}".encode()).digest()).decode().rstrip("=") for i in range(20)]
    assert {len(n) for n in sha1} == {27} and not any(looks_like_fbe_name(n) for n in sha1)   # 27 chars: not a block multiple
    paths = [f"data/data/com.facebook.orca/cache/images/{n}" for n in sha1]
    assert find_fbe_directories(paths) == []
    # 43-character SHA-256 names *are* block-sized, but a cache directory deep in an app is not an encryption-policy root
    sha256 = [base64.urlsafe_b64encode(hashlib.sha256(f"k{i}".encode()).digest()).decode().rstrip("=") for i in range(20)]
    assert find_fbe_directories([f"data/data/com.x/cache/glide/{n}" for n in sha256]) == []


def test_ordinary_names_are_not():
    for n in ("databases", "com.android.providers.telephony", "mmssms.db", "shared_prefs", "a" * 30, "0123456789abcdef0123456789abcdef",
              "550e8400-e29b-41d4-a716-446655440000", "SomeCamelCaseDirectoryNameHere", "lib-arm64-v8a-release"):
        assert not looks_like_fbe_name(n), n


def test_an_app_directory_full_of_ciphertext_is_reported_at_the_policy_root():
    paths = [f"data/data/com.example.app/{fbe(i)}/{fbe(100 + i)}/{fbe(200 + i, 2)}" for i in range(6)]
    found = find_fbe_directories(paths)
    assert [d.path for d in found] == ["data/data/com.example.app"]
    assert found[0].encrypted_looking == 6 and "never decrypts" in found[0].detail
    assert [d.path for d in find_fbe_directories([f"data/media/0/{fbe(i)}" for i in range(5)])] == ["data/media/0"]
    assert [d.path for d in find_fbe_directories([f"Image - Data/data/user/0/com.a/{fbe(i)}" for i in range(5)])] == ["Image - Data/data/user/0/com.a"]


def test_a_few_odd_names_in_a_normal_tree_do_not_trigger():
    paths = ["data/data/com.a/databases/x.db", "data/data/com.b/files/y", f"data/data/com.b/{fbe(1)}", "data/data/com.c/cache/q"]
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
        d = dump / "data" / "data" / "com.example.app" / fbe(i)
        d.mkdir(parents=True)
        (d / fbe(50 + i)).write_bytes(bytes(range(256)) * 4)
    store = CaseStore.create(tmp_path / "case", "enc", "t")
    ingest_source(store, dump)
    run_stage(store, "scan")
    rows = store.q("SELECT path, detail FROM scan_issues WHERE issue_type='file_based_encryption_suspected'")
    assert len(rows) == 1 and "never decrypts" in rows[0]["detail"]
