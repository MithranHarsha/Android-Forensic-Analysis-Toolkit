"""Loading of parser plugins (see :mod:`android_forensics.plugin_api`).

Plugins come from two places, both explicit: ``--plugin FILE`` / ``ANDROID_FORENSICS_PLUGINS`` / the config file, and installed
packages that declare the ``android_forensics.parsers`` entry-point group. Nothing is ever discovered inside evidence or inside
a case directory. A plugin file must belong to the current user and must not be writable by anyone else.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from importlib import metadata
from pathlib import Path

from android_forensics.artifacts import registry
from android_forensics.errors import ForensicsError

ENTRY_POINT_GROUP = "android_forensics.parsers"
ENV_VAR = "ANDROID_FORENSICS_PLUGINS"


class PluginError(ForensicsError):
    pass


@dataclass
class LoadedPlugin:
    name: str
    origin: str                  # file path or "entry-point:<dist>"
    sha256: str | None
    parsers: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


LOADED: list[LoadedPlugin] = []


def _check_file(path: Path) -> None:
    if not path.is_file():
        raise PluginError(f"plugin not found: {path}")
    st = path.stat()
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise PluginError(f"refusing to load {path}: it is owned by another user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PluginError(f"refusing to load {path}: it is writable by group/others (chmod go-w)")


def _registered() -> list[str]:
    return [f"{type(p).__module__}.{type(p).__name__}" for p in registry._PARSERS]


def load_plugin_file(path: str | Path) -> LoadedPlugin:
    p = Path(path).expanduser().resolve()
    _check_file(p)
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    for already in LOADED:
        if already.sha256 == digest and already.origin == str(p):
            return already
    registry.get_parsers()  # make sure the built-in parsers are registered first, so the diff below is only the plugin's
    before = set(_registered())
    mod_name = f"android_forensics_plugin_{p.stem}_{digest[:8]}"
    spec = importlib.util.spec_from_file_location(mod_name, p)
    if spec is None or spec.loader is None:
        raise PluginError(f"cannot import plugin {p}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - a broken plugin must be reported, not crash the tool with a bare traceback
        sys.modules.pop(mod_name, None)
        raise PluginError(f"plugin {p.name} failed to load: {type(exc).__name__}: {exc}") from exc
    hook = getattr(module, "register_plugin", None)
    if callable(hook):
        hook(registry)
    loaded = LoadedPlugin(p.stem, str(p), digest, sorted(set(_registered()) - before))
    LOADED.append(loaded)
    return loaded


def load_entry_points() -> list[LoadedPlugin]:
    out = []
    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        if any(l.origin == f"entry-point:{ep.name}" for l in LOADED):  # noqa: E741
            continue
        registry.get_parsers()
        before = set(_registered())
        try:
            ep.load()
        except Exception as exc:  # noqa: BLE001
            raise PluginError(f"entry-point plugin {ep.name} failed to load: {type(exc).__name__}: {exc}") from exc
        loaded = LoadedPlugin(ep.name, f"entry-point:{ep.name}", None, sorted(set(_registered()) - before))
        LOADED.append(loaded)
        out.append(loaded)
    return out


def paths_from_env() -> list[str]:
    return [p for p in os.environ.get(ENV_VAR, "").split(os.pathsep) if p]


def load_all(paths: Iterable[str | Path] = (), *, entry_points: bool = True) -> list[LoadedPlugin]:
    loaded = [load_plugin_file(p) for p in [*paths_from_env(), *paths]]
    if entry_points:
        loaded += load_entry_points()
    return loaded


def is_builtin(parser: object) -> bool:
    return type(parser).__module__.startswith("android_forensics.artifacts.")
