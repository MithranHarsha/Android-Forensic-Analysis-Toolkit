"""Detached signatures for reports.

A report directory carries ``sha256sums.txt`` (a hash of every file in it). Signing commits to *that file's hash*, so one
signature protects the whole report. Two schemes are supported:

* **Ed25519** (built in, via ``cryptography``): writes ``signature.json`` containing the signed payload, the signature and
  the signer's public key. Verification recomputes every file hash, then checks the signature. A signature verified only
  against the embedded key proves the report is unchanged *since signing*, not *who* signed it — pin the key
  (``--trusted-key`` / fingerprint) to bind it to a person or lab.
* **GPG** (optional, if ``gpg`` is installed and ``gpg_key`` is given): writes ``sha256sums.txt.asc`` (armoured, detached).

Private keys are written ``0600``; set ``ANDROID_FORENSICS_KEY_PASSPHRASE`` to encrypt them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess  # nosec B404 - fixed argv, no shell
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from android_forensics.custody.stamp import tool_stamp
from android_forensics.errors import ForensicsError
from android_forensics.util import now_iso

SIGNATURE_FILE = "signature.json"
SUMS_FILE = "sha256sums.txt"
PASSPHRASE_ENV = "ANDROID_FORENSICS_KEY_PASSPHRASE"


class SigningError(ForensicsError):
    pass


def default_key_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "android-forensics" / "signing_key.pem"


def fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _passphrase() -> bytes | None:
    p = os.environ.get(PASSPHRASE_ENV)
    return p.encode() if p else None


def generate_keypair(private_path: Path | None = None, *, overwrite: bool = False) -> tuple[Path, Path, str]:
    """Create an Ed25519 key pair. Returns (private_path, public_path, fingerprint)."""
    private_path = Path(private_path or default_key_path())
    public_path = private_path.with_suffix(".pub.pem")
    if private_path.exists() and not overwrite:
        raise SigningError(f"{private_path} already exists (use --force to replace it; the old key will be lost)")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pw = _passphrase()
    enc = serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    os.chmod(private_path, 0o600)
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return private_path, public_path, fingerprint(key.public_key())


def _load_private(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=_passphrase())
    except FileNotFoundError as exc:
        raise SigningError(f"signing key not found: {path} (create one with: android-forensics keygen)") from exc
    except (ValueError, TypeError) as exc:
        raise SigningError(f"cannot load signing key {path}: {exc} (encrypted keys need {PASSPHRASE_ENV})") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("signing key must be an Ed25519 key")
    return key


def _load_public(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError("public key must be Ed25519")
    return key


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sums_hash(report_dir: Path) -> str:
    sums = report_dir / SUMS_FILE
    if not sums.exists():
        raise SigningError(f"{sums} not found — generate the report first")
    return hashlib.sha256(sums.read_bytes()).hexdigest()


def sign_report(
    report_dir: Path, key_path: Path | None = None, *, signer: str | None = None, gpg_key: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Sign a report directory. Returns the signature document that was written."""
    report_dir = Path(report_dir)
    key = _load_private(Path(key_path or default_key_path()))
    stamp = tool_stamp()
    payload = {
        "schema": "android-forensics/report-signature/1", "signed_file": SUMS_FILE, "signed_file_sha256": _sums_hash(report_dir),
        "signed_at": now_iso(), "signer": signer or "unspecified", "tool_version": stamp["version"],
        "tool_fingerprint": stamp["fingerprint"], **(extra or {}),
    }
    pub = key.public_key()
    doc = {
        "payload": payload, "algorithm": "ed25519", "signature": base64.b64encode(key.sign(_canonical(payload))).decode(),
        "public_key_pem": pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "public_key_fingerprint": fingerprint(pub),
    }
    if gpg_key:
        gpg = shutil.which("gpg")
        if gpg is None:
            raise SigningError("gpg requested but not installed")
        r = subprocess.run([gpg, "--batch", "--yes", "--armor", "--detach-sign", "-u", gpg_key, str(report_dir / SUMS_FILE)],  # nosec B603
                           capture_output=True, text=True, timeout=60, check=False)
        if r.returncode != 0:
            raise SigningError(f"gpg signing failed: {r.stderr.strip()}")
        doc["gpg"] = {"key": gpg_key, "signature_file": SUMS_FILE + ".asc"}
    (report_dir / SIGNATURE_FILE).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return doc


@dataclass
class SignatureVerification:
    ok: bool                       # every file matches AND the signature is valid
    signature_valid: bool = False
    files_checked: int = 0
    files_bad: list[str] = field(default_factory=list)
    key_fingerprint: str | None = None
    key_trusted: bool | None = None  # None: no trusted key supplied (signature is only self-consistent)
    signer: str | None = None
    signed_at: str | None = None
    messages: list[str] = field(default_factory=list)


def verify_report(report_dir: Path, trusted_public_key: Path | None = None, trusted_fingerprint: str | None = None) -> SignatureVerification:
    report_dir = Path(report_dir)
    res = SignatureVerification(ok=False)
    sig_path = report_dir / SIGNATURE_FILE
    if not sig_path.exists():
        res.messages.append("report is not signed (signature.json missing)")
        return res
    try:
        doc = json.loads(sig_path.read_text(encoding="utf-8"))
        payload, sig = doc["payload"], base64.b64decode(doc["signature"])
        pub = _load_public(doc["public_key_pem"].encode())
    except (ValueError, KeyError, TypeError) as exc:
        res.messages.append(f"signature.json is malformed: {exc}")
        return res
    res.key_fingerprint, res.signer, res.signed_at = fingerprint(pub), payload.get("signer"), payload.get("signed_at")
    if doc.get("public_key_fingerprint") != res.key_fingerprint:
        res.messages.append("embedded fingerprint does not match the embedded public key")
        return res
    try:
        pub.verify(sig, _canonical(payload))
        res.signature_valid = True
    except InvalidSignature:
        res.messages.append("SIGNATURE INVALID: the signed payload was altered or signed by a different key")
        return res
    try:
        sums_ok = _sums_hash(report_dir) == payload.get("signed_file_sha256")
    except SigningError as exc:
        res.messages.append(str(exc))
        return res
    if not sums_ok:
        res.messages.append("sha256sums.txt was modified after signing")
    # every listed file must still match its recorded hash
    for line in (report_dir / SUMS_FILE).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        target = (report_dir / rel).resolve()
        res.files_checked += 1
        try:
            inside = target.is_relative_to(report_dir.resolve())
            good = inside and hashlib.sha256(target.read_bytes()).hexdigest() == digest
        except OSError:
            good = False
        if not good:
            res.files_bad.append(rel)
    listed = {ln.partition("  ")[2] for ln in (report_dir / SUMS_FILE).read_text(encoding="utf-8").splitlines() if ln.strip()}
    extras = sorted(p.relative_to(report_dir).as_posix() for p in report_dir.rglob("*")
                    if p.is_file() and p.relative_to(report_dir).as_posix() not in listed
                    and p.name not in (SIGNATURE_FILE, SUMS_FILE, SUMS_FILE + ".asc"))
    if extras:
        res.files_bad += [f"{e} (not covered by the signature)" for e in extras]
    if res.files_bad:
        res.messages.append(f"{len(res.files_bad)} file(s) do not match their recorded hash: {', '.join(res.files_bad[:5])}")
    if trusted_public_key is not None:
        res.key_trusted = fingerprint(_load_public(Path(trusted_public_key).read_bytes())) == res.key_fingerprint
    elif trusted_fingerprint is not None:
        res.key_trusted = trusted_fingerprint.lower() == res.key_fingerprint
    if res.key_trusted is False:
        res.messages.append("signing key does NOT match the trusted key")
    elif res.key_trusted is None:
        res.messages.append("signature is self-consistent but the key is not pinned: supply --trusted-key to bind it to a signer")
    res.ok = res.signature_valid and sums_ok and not res.files_bad and res.key_trusted is not False
    return res
