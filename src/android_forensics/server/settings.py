from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

GiB = 1024 ** 3


@dataclass(frozen=True)
class ServerSettings:
    cases_dir: Path
    data_dir: Path                      # server.db, uploads, job logs, audit log — keep it OUTSIDE cases_dir
    max_upload_bytes: int = 64 * GiB
    workers: int = 2                    # concurrent analysis jobs
    rate_limit_per_minute: int = 600    # per client IP, all endpoints
    principal_rate_limit_per_minute: int = 240
    auth_failures_per_minute: int = 10  # per client IP; beyond this, even valid tokens are refused until the window clears
    allowed_origins: tuple[str, ...] = ()      # CORS: none by default (same-origin only)
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "[::1]", "testserver")
    behind_tls: bool = False            # sends HSTS; set when a TLS terminator or --tls-* is in front
    trust_proxy_hops: int = 0           # how many X-Forwarded-For hops to trust (0 = use the socket peer)
    job_cpu_seconds: int = 12 * 3600
    job_wall_seconds: int = 24 * 3600
    job_memory_bytes: int = 8 * GiB
    job_file_bytes: int = 512 * GiB
    # Single sign-on through a trusted reverse proxy (oauth2-proxy, Authelia, an OIDC-aware ingress …). The proxy authenticates the user and
    # passes their name and groups in headers; the server believes those headers ONLY for connections that come from these networks.
    sso_trusted_proxies: tuple[str, ...] = ()           # CIDRs, e.g. ("10.0.0.0/8", "172.18.0.0/16")
    sso_user_header: str = "X-Auth-Request-User"
    sso_groups_header: str = "X-Auth-Request-Groups"     # comma-separated
    sso_role_map: tuple[tuple[str, str], ...] = ()       # (group, role) pairs; the highest role among a user's groups wins
    sso_default_role: str | None = None                  # role for an authenticated user in no mapped group (None = refuse)
    signing_key: Path | None = None     # when set, reports produced by jobs are signed with this Ed25519 key
    signer_name: str = "android-forensics server"
    extra_env: dict[str, str] = field(default_factory=dict)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "server.db"

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def jobs_dir(self) -> Path:
        return self.data_dir / "jobs"

    @property
    def audit_path(self) -> Path:
        return self.data_dir / "server_audit.log.jsonl"
