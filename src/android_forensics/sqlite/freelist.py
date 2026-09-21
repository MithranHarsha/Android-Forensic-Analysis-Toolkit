"""The freelist: pages SQLite has released but not returned to the file system.

Reference: https://www.sqlite.org/fileformat2.html §1.6 ("The Freelist"). The database header holds the page number of the
first **trunk** page (bytes 32-35) and the total number of freelist pages (bytes 36-39). A trunk page is::

    [0..3]  next trunk page (0 = last)        [4..7]  number L of leaf pointers
    [8..]   L × 4-byte page numbers of freelist **leaf** pages

A freelist *leaf* page is untouched when its page is released (unless ``secure_delete`` zeroes it), so a released b-tree page
usually still holds its old header, cell pointers and cells — whole deleted rows, with their rowids. A trunk page keeps only
what lies beyond its pointer array.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from android_forensics.sqlite.pages import PageError, PageSource


@dataclass(frozen=True)
class FreelistInfo:
    trunks: tuple[int, ...]
    leaves: tuple[int, ...]
    declared_count: int
    problems: tuple[str, ...]

    @property
    def pages(self) -> tuple[int, ...]:
        return self.trunks + self.leaves

    @property
    def consistent(self) -> bool:
        return not self.problems and len(self.pages) == self.declared_count


def walk_freelist(source: PageSource, first_trunk: int, declared_count: int, page_count: int, usable_size: int) -> FreelistInfo:
    """Follow the trunk chain, collecting trunk and leaf page numbers. Loops, out-of-range pointers and count mismatches are
    reported in ``problems`` instead of raising, so a damaged freelist still yields what it safely can."""
    trunks: list[int] = []
    leaves: list[int] = []
    problems: list[str] = []
    seen: set[int] = set()
    trunk = first_trunk
    while trunk:
        if trunk in seen:
            problems.append(f"freelist trunk chain loops at page {trunk}")
            break
        if trunk > page_count:
            problems.append(f"freelist trunk {trunk} is beyond the last page ({page_count})")
            break
        seen.add(trunk)
        try:
            page = source.read_page(trunk)
        except PageError as exc:
            problems.append(f"freelist trunk {trunk} unreadable: {exc}")
            break
        trunks.append(trunk)
        nxt, count = struct.unpack_from(">II", page, 0)
        if count > (usable_size - 8) // 4:
            problems.append(f"trunk {trunk} claims {count} leaf pointers, more than fit on a page")
            count = (usable_size - 8) // 4
        for i in range(count):
            leaf = struct.unpack_from(">I", page, 8 + 4 * i)[0]
            if leaf < 1 or leaf > page_count:
                problems.append(f"trunk {trunk} lists page {leaf}, which does not exist")
            elif leaf in seen or leaf in leaves:
                problems.append(f"page {leaf} is listed twice on the freelist")
            else:
                leaves.append(leaf)
        trunk = nxt
    if declared_count != len(trunks) + len(leaves) and not problems:
        problems.append(f"header declares {declared_count} freelist pages, the chain holds {len(trunks) + len(leaves)}")
    return FreelistInfo(tuple(trunks), tuple(leaves), declared_count, tuple(problems))
