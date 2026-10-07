from __future__ import annotations

import json

import pytest

from android_forensics.custody import AuditLog, generate_keypair, record_command, sign_report, tool_stamp, verify_report
from android_forensics.custody.audit import GENESIS
from android_forensics.custody.signing import SigningError


def _log(tmp_path, n=3):
    log = AuditLog(tmp_path / "audit.log.jsonl")
    for i in range(n):
        log.append({"command": f"cmd{i}", "outcome": "ok"})
    return log


def test_audit_chain_verifies_and_links(tmp_path):
    log = _log(tmp_path)
    v = log.verify()
    assert v.ok and v.entries == 3 and v.head != GENESIS
    e = log.entries()
    assert e[0]["prev"] == GENESIS and e[1]["prev"] == e[0]["hash"] and [x["seq"] for x in e] == [1, 2, 3]


def test_audit_detects_edit_deletion_and_reorder(tmp_path):
    log = _log(tmp_path)
    lines = log.path.read_text().splitlines()
    # edit
    edited = json.loads(lines[1]); edited["outcome"] = "tampered"
    log.path.write_text("\n".join([lines[0], json.dumps(edited), lines[2]]) + "\n")
    assert not log.verify().ok and log.verify().error_line == 2
    # deletion of a middle line
    log.path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not log.verify().ok
    # reorder
    log.path.write_text("\n".join([lines[0], lines[2], lines[1]]) + "\n")
    assert not log.verify().ok
    # truncation of the tail is *not* detectable from the file alone: the head recorded elsewhere is what catches it
    log.path.write_text("\n".join(lines[:2]) + "\n")
    assert log.verify().ok and log.verify().entries == 2


def test_audit_rejects_garbage_and_survives_corrupt_tail(tmp_path):
    log = _log(tmp_path, 1)
    with open(log.path, "ab") as fh:
        fh.write(b"not json\n")
    assert not log.verify().ok
    log.append({"command": "after-garbage"})  # appending must not crash, and the damage must stay visible
    assert not log.verify().ok


def test_record_command_captures_actor_and_evidence_hash(tmp_path):
    (tmp_path / "evidence_manifest.json.sha256").write_text("ab" * 32 + "  evidence_manifest.json\n")
    e = record_command(tmp_path, "analyze", ["x=1"], "ok", db_chain_head="h" * 64)
    assert e["user"] and e["host"] and e["command"] == "analyze"
    assert e["evidence_manifest_sha256"] == "ab" * 32 and e["db_custody_head"] == "h" * 64
    assert AuditLog(tmp_path / "audit.log.jsonl").verify().ok


def test_tool_stamp_has_versions_and_a_stable_fingerprint():
    s = tool_stamp()
    assert s["version"] and s["python"] and s["dependencies"]["pydantic"] != "not installed"
    assert len(s["fingerprint"]) == 64 and tool_stamp()["fingerprint"] == s["fingerprint"]


@pytest.fixture()
def report_dir(tmp_path):
    d = tmp_path / "report"
    (d / "csv").mkdir(parents=True)
    (d / "report.html").write_text("<html>evidence</html>")
    (d / "csv" / "a.csv").write_text("a,b\n1,2\n")
    import hashlib
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(d).as_posix()}" for p in sorted(d.rglob("*")) if p.is_file()]
    (d / "sha256sums.txt").write_text("\n".join(lines) + "\n")
    return d


@pytest.fixture()
def key(tmp_path):
    priv, pub, fp = generate_keypair(tmp_path / "k" / "key.pem")
    return priv, pub, fp


def test_sign_and_verify_roundtrip_with_pinned_key(report_dir, key):
    priv, pub, fp = key
    assert oct(priv.stat().st_mode & 0o777) == "0o600"
    sign_report(report_dir, priv, signer="Examiner A")
    v = verify_report(report_dir, pub)
    assert v.ok and v.key_trusted is True and v.signer == "Examiner A" and v.files_checked == 2
    assert verify_report(report_dir, trusted_fingerprint=fp).ok


def test_unpinned_signature_is_valid_but_flagged(report_dir, key):
    sign_report(report_dir, key[0])
    v = verify_report(report_dir)
    assert v.ok and v.key_trusted is None and any("not pinned" in m for m in v.messages)


def test_modified_extra_or_removed_files_break_verification(report_dir, key):
    sign_report(report_dir, key[0])
    (report_dir / "report.html").write_text("<html>doctored</html>")
    v = verify_report(report_dir)
    assert not v.ok and v.files_bad == ["report.html"]


def test_unlisted_file_is_flagged(report_dir, key):
    sign_report(report_dir, key[0])
    (report_dir / "extra.txt").write_text("sneaked in")
    v = verify_report(report_dir)
    assert not v.ok and any("extra.txt" in f for f in v.files_bad)


def test_forged_signature_payload_and_wrong_key(report_dir, key, tmp_path):
    sign_report(report_dir, key[0], signer="Alice")
    sig = report_dir / "signature.json"
    doc = json.loads(sig.read_text()); doc["payload"]["signer"] = "Mallory"; sig.write_text(json.dumps(doc))
    assert not verify_report(report_dir).ok
    sign_report(report_dir, key[0], signer="Alice")
    _, other_pub, _ = generate_keypair(tmp_path / "other" / "k.pem")
    v = verify_report(report_dir, other_pub)
    assert not v.ok and v.key_trusted is False


def test_unsigned_malformed_and_missing_sums(report_dir, key):
    assert not verify_report(report_dir).ok
    (report_dir / "signature.json").write_text("{not json")
    assert not verify_report(report_dir).ok
    (report_dir / "sha256sums.txt").unlink()
    with pytest.raises(SigningError):
        sign_report(report_dir, key[0])


def test_keygen_refuses_overwrite_and_encrypts_with_passphrase(tmp_path, monkeypatch):
    p = tmp_path / "key.pem"
    generate_keypair(p)
    with pytest.raises(SigningError):
        generate_keypair(p)
    monkeypatch.setenv("ANDROID_FORENSICS_KEY_PASSPHRASE", "s3cret")
    generate_keypair(p, overwrite=True)
    assert b"ENCRYPTED" in p.read_bytes()
    monkeypatch.delenv("ANDROID_FORENSICS_KEY_PASSPHRASE")
    with pytest.raises(SigningError):
        sign_report(tmp_path, p)


def test_passphrase_can_come_from_a_file_so_it_stays_out_of_the_environment(tmp_path, monkeypatch):
    secret = tmp_path / "pw"
    secret.write_text("correct horse\n")
    monkeypatch.setenv("ANDROID_FORENSICS_KEY_PASSPHRASE_FILE", str(secret))
    key = tmp_path / "k" / "key.pem"
    generate_keypair(key)
    assert b"ENCRYPTED" in key.read_bytes()
    d = tmp_path / "rep"
    d.mkdir()
    (d / "sha256sums.txt").write_text("")
    sign_report(d, key)                                   # decrypts with the file's passphrase
    monkeypatch.setenv("ANDROID_FORENSICS_KEY_PASSPHRASE_FILE", str(tmp_path / "missing"))
    with pytest.raises(SigningError, match="passphrase file"):
        sign_report(d, key)
