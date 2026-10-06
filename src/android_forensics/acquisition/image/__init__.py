"""Raw disk-image evidence: partition images (``.img``/``.dd``), Android sparse images and EWF (E01) containers, with
read-only parsers for the file systems Android uses (ext4 now; f2fs is detected and reported).

Everything here reads through :class:`ImageSource` — a read-only, random-access view of bytes — and treats every
on-disk value as hostile: block numbers, sizes, lengths and counts are bounds-checked, loops are cycle-guarded, and a
damaged structure produces an *issue*, never an exception that aborts the acquisition or an unbounded read.
"""

from android_forensics.acquisition.image.acquirer import ImageAcquirer, is_disk_image
from android_forensics.acquisition.image.source import ImageSource, open_image

__all__ = ["ImageAcquirer", "ImageSource", "is_disk_image", "open_image"]
