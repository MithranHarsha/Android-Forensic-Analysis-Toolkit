"""A small in-memory sliding-window rate limiter (single process; put a shared limiter at the proxy for multi-node)."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0, max_keys: int = 50_000):
        self.limit, self.window, self.max_keys = limit, window_seconds, max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def hit(self, key: str, *, count: bool = True) -> tuple[bool, float]:
        """Record one event for ``key``. Returns (allowed, seconds_until_allowed)."""
        now = time.monotonic()
        with self._lock:
            q = self._hits.get(key)
            if q is None:
                if len(self._hits) >= self.max_keys:
                    self._hits.popitem(last=False)   # bounded memory: forget the least-recently-seen key
                q = self._hits[key] = deque()
            else:
                self._hits.move_to_end(key)
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False, max(0.0, self.window - (now - q[0]))
            if count:
                q.append(now)
            return True, 0.0

    def blocked(self, key: str) -> tuple[bool, float]:
        """Is ``key`` already over its limit? (does not record an event)"""
        allowed, retry = self.hit(key, count=False)
        return (not allowed), retry
