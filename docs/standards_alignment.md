# Alignment with forensic standards and guidance — a self-assessment

> **This is not a certification, accreditation or independent review.** No standards body or laboratory has reviewed this tool.
> The tables below are the author's mapping of the tool's behaviour onto well-known guidance, with the gaps stated plainly, so that
> an external reviewer (a laboratory quality manager, a university supervisor, a court-appointed expert) has a concrete starting point
> and does not have to reverse-engineer what is claimed. Anything not listed as "met" should be read as "not met".
>
> Documents referred to (consult the originals; paraphrased here from the author's reading): NIST SP 800-101 Rev. 1 *Guidelines on
> Mobile Device Forensics*; NIST SP 800-86 *Guide to Integrating Forensic Techniques into Incident Response*; SWGDE *Best Practices
> for Mobile Device Forensics* and *Minimum Requirements for Quality Assurance in the Processing of Digital and Multimedia
> Evidence*; ISO/IEC 27037 (identification, collection, acquisition and preservation), 27041 (assurance of methods), 27042
> (analysis and interpretation), 27043 (investigation principles and processes); ISO/IEC 17025 (laboratory competence).

## Scope: what this tool is and is not

It is an **examination and analysis** tool operating on an *already acquired* Android file system (directory dump, archive or disk image).
It does **not** acquire from a device, bypass locks, decrypt, root, or touch live devices. Acquisition-phase requirements (device
isolation, Faraday handling, ADB/chip-off/JTAG choices, legal authority at the scene) are therefore *out of scope* and belong to the
examiner's procedures.

## Principles (ISO/IEC 27037 / SWGDE) → behaviour

| Principle | How the tool supports it | Status |
|---|---|---|
| **Do not alter the original** | Evidence opened `O_RDONLY | O_NOFOLLOW`; SQLite never opens preserved evidence — only a disposable scratch copy, under a read-only authorizer; evidence directories are re-hashed at validation and a changed file is reported; tests assert byte- and mtime-equality of the evidence tree after a full run. | Met for software; **write-blocking is the examiner's job** (OS may update atime — see `readonly.py`) |
| **Integrity verification** | SHA-256 anchor, MD5/SHA-1 for legacy comparison; container hash for archives/images; E01 stored hash re-computed; per-file hashes in a manifest that is itself hashed; `validate` re-hashes originals. | Met |
| **Repeatability / reproducibility** | Deterministic pipeline; report stamps the exact build (version, interpreter, dependency versions, lock-file hash, git commit) and any plugin (SHA-256); lock files pin all dependencies by hash. | Met within a given build; results for *different* builds are not guaranteed identical |
| **Documentation / chain of custody** | In-database hash-chained custody log **and** an external append-only audit log of every command (who, host, when, arguments, outcome, evidence-manifest hash, database-chain head); reports can be Ed25519-signed and verified offline; case details (case number, agency, examiner credentials, certification block) in the report. | Met technically; organisational custody (physical evidence handling, transfer forms) is outside the tool |
| **Auditability of method (27041/27042)** | Methodology, status glossary and limitations are rendered *into every report*; every recovered or carved item carries physical location, raw bytes and an explained confidence level; carved candidates are never presented as confirmed; recovered ≠ active is enforced in the type system. | Met |
| **Competence and validation (17025, SWGDE QA)** | Self-validation harness with ground truth (`docs/evaluation.md`), kernel-written file-system fixtures, fuzzing, adversarial tests, and an independent comparison with a reference recovery tool (`docs/validation.md`). | **Partial** — see the validation limits; the lab must run its own validation on its own cases/tools before relying on results |
| **Error rate and limits (Daubert-style)** | Measured precision/recall on synthetic ground truth with stated limits; confidence is a deterministic, explainable function — not a probability. | **Partial** — error rates on real-world corpora are reported where measured and are not generalisable |

## NIST SP 800-101 Rev. 1 phases

| Phase | Tool role |
|---|---|
| Preservation | n/a (device-side). The tool preserves *copies* of what it must open, write-protected (`0444`), outside the evidence. |
| Acquisition | n/a. Accepts the output of acquisitions: directory, ZIP/TAR, raw/sparse images, E01. |
| Examination and analysis | ext4 and f2fs reading; SQLite discovery/inspection; active extraction; deleted-record recovery (freelist, unallocated space, WAL, rollback journal); carving; correlation; confidence; timeline. |
| Reporting | HTML/PDF/JSON/CSV report, signed on request; limitations and tool/build identity embedded. |

Recognised gaps relative to the guidance's *recommendations for examination*: no physical-level (raw NAND) support, no keychain or
credential decryption, no app-specific parsers beyond SMS/calls/contacts/browser (plugins can add them), no file-system-level
recovery of deleted *files*, no live-device support.

## Items an external reviewer should probe first

1. The recovery algorithm's assumptions about SQLite page reuse across versions (`docs/sqlite_recovery.md`), especially secure-delete and auto-vacuum.
2. The confidence function's factor weights — deterministic and documented, but chosen by the author, not derived from a population study.
3. Behaviour on **encrypted `/data`** (the common case on phones): the tool reports encryption and produces nothing for it; confirm that is acceptable for your casework.
4. The ext4/f2fs readers against corpora the author has not seen (the fixtures were produced by one kernel and one `mkfs`).
5. Operation under your own platform's time zone and locale settings — all stored times are UTC, but verify against your cases.
