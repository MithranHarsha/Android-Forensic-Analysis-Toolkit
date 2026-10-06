"""Chain of custody beyond the case database: an external append-only audit log, a tool/dependency stamp, and
detached signatures for reports.

The case database already holds a hash-chained ``custody_log``. That chain lives in the same file an attacker (or a
mistake) could rewrite, and it records the *tool*, not the *person*. This package adds:

* :mod:`~android_forensics.custody.audit` — who ran what, when, from where, on which evidence, with what result, in a
  separate hash-chained JSON-lines file that also commits to the database chain's head;
* :mod:`~android_forensics.custody.stamp` — exact tool, interpreter and dependency versions (and lock-file hash) so a
  result can be reproduced and a report can be attributed to a precise build;
* :mod:`~android_forensics.custody.signing` — Ed25519 (and optional GPG) detached signatures over a report's checksums.
"""

from android_forensics.custody.audit import AuditLog, AuditVerification, record_command
from android_forensics.custody.signing import (
    SignatureVerification,
    generate_keypair,
    sign_report,
    verify_report,
)
from android_forensics.custody.stamp import tool_stamp

__all__ = [
    "AuditLog",
    "AuditVerification",
    "SignatureVerification",
    "generate_keypair",
    "record_command",
    "sign_report",
    "tool_stamp",
    "verify_report",
]
