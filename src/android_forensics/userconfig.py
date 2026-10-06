"""``android-forensics.toml``: defaults so the command line stays short and examiners do not retype their details.

Looked up in order (first found wins; ``--config`` / ``ANDROID_FORENSICS_CONFIG`` override the search)::

    ./android-forensics.toml
    $XDG_CONFIG_HOME/android-forensics/config.toml   (default ~/.config/android-forensics/config.toml)

Example::

    cases_dir = "/srv/cases"
    plugins = ["/opt/af-plugins/acme_calls.py"]

    [examiner]
    name = "Dr. Jane Doe"
    title = "Senior Digital Forensic Examiner"
    organisation = "State Forensic Laboratory"
    accreditation = "ISO/IEC 17025:2017, cert. 1234"

    [report]
    agency = "City Police Department"
    jurisdiction = "State of Example"
    footer = "Confidential - law-enforcement sensitive"

    [logging]
    level = "INFO"
    file = "/var/log/android-forensics.jsonl"
    format = "json"

Values here only set *defaults*: a command-line option or an environment variable always wins.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from android_forensics.errors import ForensicsError

ENV_VAR = "ANDROID_FORENSICS_CONFIG"
EXAMINER_KEYS = ("name", "title", "organisation", "accreditation", "email", "phone")
REPORT_KEYS = ("agency", "jurisdiction", "footer", "classification")


class ConfigError(ForensicsError):
    pass


@dataclass
class UserConfig:
    path: Path | None = None
    cases_dir: str | None = None
    data_dir: str | None = None
    plugins: list[str] = field(default_factory=list)
    examiner: dict[str, str] = field(default_factory=dict)
    report: dict[str, str] = field(default_factory=dict)
    logging: dict[str, str] = field(default_factory=dict)

    def court_defaults(self) -> dict[str, str]:
        """Case-detail defaults derived from the config (see ``case_details``)."""
        out = {f"examiner_{k}": v for k, v in self.examiner.items() if k != "name"}
        out.update({k: v for k, v in self.report.items()})
        return out


def search_paths(explicit: str | Path | None = None) -> list[Path]:
    if explicit or os.environ.get(ENV_VAR):
        return [Path(explicit or os.environ[ENV_VAR]).expanduser()]
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return [Path("android-forensics.toml"), Path(xdg) / "android-forensics" / "config.toml"]


def load(explicit: str | Path | None = None) -> UserConfig:
    candidates = search_paths(explicit)
    for p in candidates:
        if not p.is_file():
            if explicit or os.environ.get(ENV_VAR):
                raise ConfigError(f"config file not found: {p}")
            continue
        try:
            raw = tomllib.loads(p.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as exc:
            raise ConfigError(f"cannot read {p}: {exc}") from exc
        return _parse(raw, p)
    return UserConfig()


def _strs(table: Any, allowed: tuple[str, ...], where: str) -> dict[str, str]:
    if not isinstance(table, dict):
        raise ConfigError(f"[{where}] must be a table")
    unknown = set(table) - set(allowed)
    if unknown:
        raise ConfigError(f"[{where}] has unknown key(s): {', '.join(sorted(unknown))} (allowed: {', '.join(allowed)})")
    return {k: str(v) for k, v in table.items()}


def _parse(raw: dict[str, Any], path: Path) -> UserConfig:
    known = {"cases_dir", "data_dir", "plugins", "examiner", "report", "logging"}
    if set(raw) - known:
        raise ConfigError(f"{path}: unknown top-level key(s): {', '.join(sorted(set(raw) - known))}")
    plugins = raw.get("plugins", [])
    if not isinstance(plugins, list) or not all(isinstance(x, str) for x in plugins):
        raise ConfigError("plugins must be a list of file paths")
    return UserConfig(
        path=path, cases_dir=raw.get("cases_dir"), data_dir=raw.get("data_dir"), plugins=plugins,
        examiner=_strs(raw.get("examiner", {}), EXAMINER_KEYS, "examiner"), report=_strs(raw.get("report", {}), REPORT_KEYS, "report"),
        logging=_strs(raw.get("logging", {}), ("level", "file", "format"), "logging"),
    )


def apply_to_environment(cfg: UserConfig) -> None:
    """Expose config values as the environment variables the CLI options already read — never overriding an existing one."""
    for var, value in (("ANDROID_FORENSICS_CASES", cfg.cases_dir), ("ANDROID_FORENSICS_DATA", cfg.data_dir),
                       ("ANDROID_FORENSICS_EXAMINER", cfg.examiner.get("name"))):
        if value and var not in os.environ:
            os.environ[var] = str(Path(value).expanduser()) if var != "ANDROID_FORENSICS_EXAMINER" else value
