"""Android filesystem layout knowledge.

Layouts differ between Android versions, vendors and acquisition tools, so nothing here assumes a fixed root, that any
particular directory exists, or that the evidence holds a single dump. Every path is *located* independently:

* **strong roots** — ``data/data``, ``data/user/N``, ``data/user_de/N``, ``data/media/N``, ``data/system*``, ``data/misc*``,
  ``data/app``, ``storage/emulated/N``, ``storage/self/primary``, ``storage/<UUID>`` (external SD), ``sdcard``, ``mnt/sdcard``,
  ``mnt/user/N`` …  The *earliest* strong marker in a path defines its ``acquisition_root`` — whatever precedes it
  (``userdata/``, ``phoneA/``, an examiner's folder names) is the dump's prefix, so one evidence directory can hold several dumps;
* **weak roots** — ``system``, ``vendor``, ``cache`` — honoured only at the top of a dump, never deep in a path
  (``com.foo/cache/x`` is an app's cache directory, not a cache partition);
* **bare application directories** — ``<package>/databases/…`` — when there is no Android root at all;
* anything else is reported as unrecognised, never guessed.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_UUID_STORAGE_RE = re.compile(r"^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$")
_APK_DIR_RE = re.compile(r"^(?P<pkg>[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)-[A-Za-z0-9_=+~/\-]+$")

APP_SUBDIRS = frozenset({"databases", "shared_prefs", "files", "cache", "code_cache", "no_backup", "app_webview", "app_chrome", "lib"})

KNOWN_APPS = {
    "com.android.providers.telephony": "Android Telephony Provider (SMS/MMS)",
    "com.android.providers.contacts": "Android Contacts Provider (contacts, call log)",
    "com.android.chrome": "Google Chrome",
    "com.android.browser": "Android Stock Browser",
    "com.google.android.apps.messaging": "Google Messages",
    "com.google.android.dialer": "Google Phone",
    "com.android.dialer": "AOSP Dialer",
    "com.sec.android.provider.logsprovider": "Samsung Call/Message Logs",
    "com.whatsapp": "WhatsApp",
    "org.telegram.messenger": "Telegram",
    "org.mozilla.firefox": "Firefox",
}

# (marker components, canonical root name, area, followed by a numeric user id, package directory follows)
_STRONG: list[tuple[tuple[str, ...], str, str, bool, bool]] = [
    (("data", "data"), "data/data", "app_internal", False, True),
    (("data", "user"), "data/user", "app_internal", True, True),
    (("data", "user_de"), "data/user_de", "app_internal_de", True, True),
    (("data", "system_ce"), "data/system_ce", "system", True, False),
    (("data", "system_de"), "data/system_de", "system", True, False),
    (("data", "system"), "data/system", "system", False, False),
    (("data", "misc_ce"), "data/misc_ce", "system", True, False),
    (("data", "misc_de"), "data/misc_de", "system", True, False),
    (("data", "misc"), "data/misc", "system", False, False),
    (("data", "media"), "data/media", "shared_storage", True, False),
    (("data", "app"), "data/app", "app_binary", False, False),
    (("storage", "emulated"), "storage/emulated", "shared_storage", True, False),
    (("storage", "self", "primary"), "storage/self/primary", "shared_storage", False, False),
    (("storage", "sdcard0"), "storage/sdcard0", "shared_storage", False, False),
    (("storage", "sdcard1"), "storage/sdcard1", "shared_storage", False, False),
    (("mnt", "sdcard"), "mnt/sdcard", "shared_storage", False, False),
    (("mnt", "extsdcard"), "mnt/extsdcard", "shared_storage", False, False),
    (("mnt", "user"), "mnt/user", "shared_storage", True, False),
    (("sdcard",), "sdcard", "shared_storage", False, False),
    (("sdcard0",), "sdcard0", "shared_storage", False, False),
    (("sdcard1",), "sdcard1", "shared_storage", False, False),
]
_WEAK: list[tuple[tuple[str, ...], str, str]] = [
    (("system",), "system", "system_partition"),
    (("vendor",), "vendor", "system_partition"),
    (("cache",), "cache", "cache_partition"),
]
# The user-data roots an examiner would expect; reporting which are absent is informational, never an error.
COMMON_USER_ROOTS = ("data/data", "data/user", "storage/emulated", "sdcard")


def is_app_subdir(name: str) -> bool:
    return name in APP_SUBDIRS or (name.startswith("app_") and len(name) > 4)


@dataclass(frozen=True)
class AndroidPath:
    """A path attributed to the Android filesystem. ``logical_path`` is what the device would show."""

    logical_path: str
    root: str | None
    area: str | None
    user_id: int | None
    package: str | None
    app_root: str | None  # the application's directory, as a path inside the evidence
    acquisition_root: str  # what precedes the Android root in the evidence ('' when the dump starts at the root)


@dataclass(frozen=True)
class _Hit:
    index: int
    root: str
    area: str
    user_id: int | None
    next_index: int
    pkg_follows: bool


def _match_strong(comps: list[str], i: int) -> _Hit | None:
    lowered = [c.lower() for c in comps[i : i + 3]]
    for marker, root, area, has_user, pkg_follows in _STRONG:
        n = len(marker)
        if tuple(lowered[:n]) != marker or len(comps) < i + n:
            continue
        idx, user_id = i + n, None
        if has_user:
            if idx < len(comps) and comps[idx].isdigit():
                user_id = int(comps[idx])
                idx += 1
            else:
                continue
        return _Hit(i, root, area, user_id, idx, pkg_follows)
    if len(comps) > i + 1 and comps[i].lower() == "storage" and _UUID_STORAGE_RE.match(comps[i + 1]):
        return _Hit(i, "storage/external", "shared_storage", None, i + 2, False)
    return None


def _find_strong(comps: list[str]) -> _Hit | None:
    for i in range(len(comps)):
        hit = _match_strong(comps, i)
        if hit is not None:
            return hit
    return None


def _apk_package(comp: str) -> str | None:
    m = _APK_DIR_RE.match(comp)
    return m.group("pkg") if m else None


def _attribute(comps: list[str], hit: _Hit) -> AndroidPath:
    acquisition_root = "/".join(comps[: hit.index])
    logical = "/" + "/".join(comps[hit.index :])
    package = app_root = None
    area = hit.area
    if hit.pkg_follows and hit.next_index < len(comps) and PACKAGE_RE.match(comps[hit.next_index]):
        package = comps[hit.next_index]
        app_root = "/".join(comps[: hit.next_index + 1])
    elif hit.root == "data/app":
        for j in range(hit.next_index, min(len(comps), hit.next_index + 3)):
            pkg = _apk_package(comps[j])
            if pkg:
                package, app_root = pkg, "/".join(comps[: j + 1])
                break
    elif hit.area == "shared_storage":
        for j in range(hit.next_index, len(comps) - 2):
            if comps[j].lower() == "android" and comps[j + 1].lower() in ("data", "media", "obb") and PACKAGE_RE.match(comps[j + 2]):
                package, app_root, area = comps[j + 2], "/".join(comps[: j + 3]), "app_external"
                break
    return AndroidPath(logical, hit.root, area, hit.user_id, package, app_root, acquisition_root)


def _app_dump_package(comps: list[str]) -> tuple[str, str] | None:
    """(package, app_root) for a bare ``<package>/<app subdir>/…`` tree, or a top-level directory that is named like a package."""
    for i in range(len(comps) - 1):
        if PACKAGE_RE.match(comps[i]) and is_app_subdir(comps[i + 1]):
            return comps[i], "/".join(comps[: i + 1])
    if len(comps) > 1 and PACKAGE_RE.match(comps[0]):
        return comps[0], comps[0]
    return None


@dataclass(frozen=True)
class AcquisitionRoot:
    """One dump inside the evidence: the folder path preceding its Android root ('' if the dump starts at the root)."""

    prefix: str
    files: int
    markers: tuple[str, ...]


@dataclass
class LayoutAnalysis:
    layout: str
    detail: str
    matched: int
    total: int
    roots: list[AcquisitionRoot]
    roots_present: list[str]
    roots_absent: list[str]
    _strong: dict[str, _Hit] = field(default_factory=dict, repr=False)
    _prefixes: list[str] = field(default_factory=list, repr=False)

    def locate(self, path: str) -> AndroidPath:
        """Attribute one evidence path (file or directory) to the Android filesystem; never invents a location."""
        comps = path.split("/")
        hit = self._strong.get(path) or _find_strong(comps)
        if hit is not None:
            return _attribute(comps, hit)
        for prefix in self._prefixes:  # weak roots are honoured at the top of a dump we already recognised
            if prefix == "" or path.startswith(prefix + "/"):
                rest = comps[len(prefix.split("/")) :] if prefix else comps
                for marker, root, area in _WEAK:
                    if tuple(c.lower() for c in rest[: len(marker)]) == marker:
                        return AndroidPath("/" + "/".join(rest), root, area, None, None, None, prefix)
        for marker, root, area in _WEAK:
            if tuple(c.lower() for c in comps[: len(marker)]) == marker:
                return AndroidPath("/" + "/".join(comps), root, area, None, None, None, "")
        dump = _app_dump_package(comps)
        if dump is not None:
            return AndroidPath("/" + "/".join(comps), None, "app_directory_dump", None, dump[0], dump[1], "")
        return AndroidPath("/" + "/".join(comps), None, "unrecognised_layout", None, None, None, "")


def analyze_layout(files: Iterable[str], directories: Iterable[str] = ()) -> LayoutAnalysis:
    """Work out how the evidence is laid out. ``directories`` lets empty directories (an app with no files) count too."""
    files, directories = list(files), list(directories)
    file_set = set(files)
    strong: dict[str, _Hit] = {}
    prefix_files: Counter[str] = Counter()
    prefix_markers: dict[str, set[str]] = defaultdict(set)
    for p in files + directories:
        hit = _find_strong(p.split("/"))
        if hit is None:
            continue
        strong[p] = hit
        prefix = "/".join(p.split("/")[: hit.index])
        if p in file_set:
            prefix_files[prefix] += 1
        prefix_markers[prefix].add(hit.root)
    prefixes = sorted(prefix_markers, key=lambda k: (-len(k), k))

    analysis = LayoutAnalysis("loose_files", "", 0, len(files), [], [], list(COMMON_USER_ROOTS), _strong=strong, _prefixes=prefixes)
    located = [analysis.locate(p) for p in files]
    analysis.matched = sum(1 for a in located if a.root is not None or a.area == "app_directory_dump")
    present = {a.root for a in located if a.root} | {strong[d].root for d in directories if d in strong}
    analysis.roots_present = sorted(present)
    analysis.roots_absent = [r for r in COMMON_USER_ROOTS if r not in present]
    analysis.roots = [AcquisitionRoot(p, prefix_files.get(p, 0), tuple(sorted(prefix_markers[p]))) for p in prefixes]

    android_matched = sum(1 for a in located if a.root is not None)
    if prefix_markers:
        if len(prefixes) > 1:
            analysis.layout = "multiple_roots"
            analysis.detail = f"{len(prefixes)} dumps in one evidence tree: " + ", ".join(f"'{p or '.'}'" for p in sorted(prefixes))
        elif prefixes[0] == "":
            analysis.layout = "android_root"
        else:
            analysis.layout = "android_root_with_prefix"
            analysis.detail = f"beneath prefix '{prefixes[0]}/'"
        analysis.detail = f"{android_matched}/{len(files)} files sit under recognised Android roots" + (f" — {analysis.detail}" if analysis.detail else "")
    elif android_matched:
        analysis.layout = "android_root"
        analysis.detail = f"{android_matched}/{len(files)} files sit under recognised top-level system roots"
    elif any(a.area == "app_directory_dump" for a in located):
        n = sum(1 for a in located if a.area == "app_directory_dump")
        analysis.layout = "app_directories"
        analysis.detail = f"{n}/{len(files)} files look like <package>/<app subdirectory>/… (no Android root present)"
    elif len(files) == 1:
        analysis.layout, analysis.detail = "single_file", "single file input"
    else:
        analysis.layout, analysis.detail = "loose_files", "no recognised Android directory structure"
    return analysis
