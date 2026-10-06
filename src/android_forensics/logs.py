"""Structured logging. Off by default (the CLI's own output is the interface); enable with ``--log-level`` / ``--log-file`` /
``--log-format json`` or the ``[logging]`` table of the config file. JSON lines are one event per line, ready for a log shipper."""

from __future__ import annotations

import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOGGER = "android_forensics"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z", "level": record.levelname,
               "logger": record.name, "msg": record.getMessage()}
        for k, v in getattr(record, "fields", {}).items():
            doc[k] = v
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str, ensure_ascii=False)


def configure(level: str = "WARNING", file: Path | str | None = None, fmt: str = "text") -> logging.Logger:
    log = logging.getLogger(LOGGER)
    for h in list(log.handlers):
        log.removeHandler(h)
        h.close()
    log.setLevel(getattr(logging, level.upper(), logging.WARNING))
    log.propagate = False
    handler: logging.Handler
    if file:
        Path(file).parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(file, maxBytes=20 * 1024 * 1024, backupCount=5, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    log.addHandler(handler)
    return log


def get(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER}.{name}" if name else LOGGER)


def event(logger: logging.Logger, level: int, msg: str, **fields: object) -> None:
    logger.log(level, msg, extra={"fields": fields})
