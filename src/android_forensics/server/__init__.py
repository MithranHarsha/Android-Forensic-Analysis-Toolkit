"""Authenticated, multi-case web server for android-forensics.

``android-forensics dashboard CASE`` is a *local, single-case, read-only* viewer. This package is the deployable counterpart:

* **authentication and roles** — bearer tokens (only their SHA-256 is stored) with ``viewer`` / ``analyst`` / ``admin`` roles;
* **multi-case management** — case metadata in a server database, one directory per case, soft deletion;
* **safe uploads** — streamed to disk with a hard size cap and hashing, never held in memory, stored read-only outside any case;
* **background jobs** — ingestion + analysis run as *separate, resource-limited processes* (CPU/memory/file-size/wall-clock
  limits, own process group, scrubbed environment) so a hostile evidence file can hurt only its own job;
* **defence in depth** — strict CSP and security headers, rate limiting with brute-force lockout, restricted CORS and Host
  headers, an append-only hash-chained server audit log of every mutating request.

The read-only case endpoints are the very same router the local dashboard uses (``dashboard.api.build_router``).
"""

from android_forensics.server.app import create_server_app
from android_forensics.server.settings import ServerSettings

__all__ = ["ServerSettings", "create_server_app"]
