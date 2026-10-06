"""f2fs support placeholder: detected and reported, not yet parsed."""

from __future__ import annotations

from android_forensics.acquisition.base import AcquisitionIssue


def acquire_f2fs(acquirer, ctx, src, loc, label, ordinal):  # noqa: ANN001 - generator used with ``yield from``
    yield AcquisitionIssue(label, "filesystem_unsupported",
                           "f2fs file system detected but not supported by this build; extract it first (e.g. with a Linux read-only mount) "
                           "and ingest the resulting directory", incomplete=True)
    return ordinal
