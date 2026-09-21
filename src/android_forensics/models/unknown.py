"""``UNKNOWN`` sentinel.

A SQL ``NULL`` (Python ``None``) means "the database stored NULL".
``UNKNOWN`` means "this value could not be determined / does not exist in this
schema variant". The two must never be conflated in forensic output.
"""

from __future__ import annotations


class _Unknown:
    _instance: "_Unknown | None" = None

    def __new__(cls) -> "_Unknown":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self) -> bool:
        return False

    def __copy__(self) -> "_Unknown":
        return self

    def __deepcopy__(self, memo: dict) -> "_Unknown":
        return self


UNKNOWN = _Unknown()


def is_unknown(value: object) -> bool:
    return value is UNKNOWN
