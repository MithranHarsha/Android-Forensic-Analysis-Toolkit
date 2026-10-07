"""Bearer-token authentication with roles. Tokens are 256-bit random secrets; only their SHA-256 is stored, so a leaked
server database does not reveal usable credentials (high-entropy tokens need no slow hash)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from fastapi import HTTPException, Request

from android_forensics.server.db import ServerDB

ROLES = ("viewer", "analyst", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}
TOKEN_PREFIX = "afk_"  # nosec B105 - a public prefix that makes tokens recognisable, not a secret


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class Principal:
    token_id: int
    name: str
    role: str

    def at_least(self, role: str) -> bool:
        return _RANK[self.role] >= _RANK[role]


def parse_bearer(header: str | None) -> str | None:
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value or len(value) > 256:
        return None
    return value.strip()


def authenticate(db: ServerDB, token: str | None) -> Principal | None:
    if not token or not token.startswith(TOKEN_PREFIX):
        return None
    digest = hash_token(token)
    row = db.token_by_hash(digest)
    if row is None or not hmac.compare_digest(row["token_sha256"], digest):
        return None
    db.touch_token(row["id"])
    return Principal(row["id"], row["name"], row["role"])


def _highest(roles: list[str]) -> str | None:
    return max(roles, key=lambda r: _RANK[r]) if roles else None


def sso_principal(request: Request, trusted: list, user_header: str, groups_header: str, role_map: dict[str, str],
                  default_role: str | None) -> Principal | None:
    """The user a trusted proxy vouches for, or None when SSO does not apply to this request.

    SSO applies only when the TCP peer is inside a configured proxy network *and* the user header is present; headers sent by any
    other peer are ignored (they are just untrusted request headers, so a client cannot talk its way into a role)."""
    import ipaddress

    peer = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return None
    if not any(addr in net for net in trusted):
        return None
    user = request.headers.get(user_header, "").strip()
    if not user or len(user) > 200 or any(ord(c) < 32 for c in user):
        return None
    groups = [g.strip() for g in request.headers.get(groups_header, "").split(",") if g.strip()]
    role = _highest([role_map[g] for g in groups if g in role_map]) or default_role
    if role is None:
        raise HTTPException(403, "your account is not in any group that grants access")
    return Principal(-1, user, role)


def forbidden(role: str) -> HTTPException:
    return HTTPException(403, f"this action needs the '{role}' role")


def client_ip(request: Request, trusted_hops: int) -> str:
    if trusted_hops > 0:
        xff = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(xff) >= trusted_hops:
            return xff[-trusted_hops]
    return request.client.host if request.client else "unknown"
