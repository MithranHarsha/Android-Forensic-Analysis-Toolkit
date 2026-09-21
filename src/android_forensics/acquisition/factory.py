"""Source-type detection and acquirer selection."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from android_forensics.acquisition.archive import TarAcquirer, ZipAcquirer
from android_forensics.acquisition.base import Acquirer
from android_forensics.acquisition.directory import DirectoryAcquirer
from android_forensics.acquisition.single_file import SingleFileAcquirer
from android_forensics.filesystem.classifier import SQLITE_MAGIC
from android_forensics.models.enums import SourceType


def detect_source_type(path: Path) -> SourceType:
    if path.is_dir():
        return SourceType.DIRECTORY
    with open(path, "rb") as fh:
        head = fh.read(16)
    if head.startswith(SQLITE_MAGIC):
        return SourceType.SINGLE_FILE
    if zipfile.is_zipfile(path):
        return SourceType.ZIP
    try:
        if tarfile.is_tarfile(path):
            return SourceType.TAR
    except (OSError, tarfile.TarError):
        pass
    return SourceType.SINGLE_FILE


def make_acquirer(path: Path) -> Acquirer:
    stype = detect_source_type(path)
    if stype is SourceType.DIRECTORY:
        return DirectoryAcquirer(path)
    if stype is SourceType.ZIP:
        return ZipAcquirer(path)
    if stype is SourceType.TAR:
        return TarAcquirer(path)
    return SingleFileAcquirer(path)
