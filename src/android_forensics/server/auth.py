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
TOKEN_PREFIX = "afk_"


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


def forbidden(role: str) -> HTTPException:
    return HTTPException(403, f"this action needs the '{role}' role")


def client_ip(request: Request, trusted_hops: int) -> str:
    if trusted_hops > 0:
        xff = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(xff) >= trusted_hops:
            return xff[-trusted_hops]
    return request.client.host if request.client else "unknown"
