from __future__ import annotations

from fastapi.testclient import TestClient

from android_forensics.server import ServerSettings, create_server_app
from android_forensics.server.auth import hash_token, new_token
from android_forensics.server.db import ServerDB

PROXY = ("10.1.2.3", 40000)
OUTSIDER = ("203.0.113.9", 40000)
ROLE_MAP = (("forensics-admins", "admin"), ("forensics-analysts", "analyst"), ("forensics-readers", "viewer"))


def settings(tmp_path, **kw) -> ServerSettings:
    return ServerSettings(cases_dir=tmp_path / "cases", data_dir=tmp_path / "data", workers=1, sso_trusted_proxies=("10.0.0.0/8",),
                          sso_role_map=ROLE_MAP, **kw)


def sso(user: str, groups: str = "") -> dict[str, str]:
    return {"X-Auth-Request-User": user, "X-Auth-Request-Groups": groups}


def client(tmp_path, peer=PROXY, **kw) -> TestClient:
    return TestClient(create_server_app(settings(tmp_path, **kw)), client=peer)


def test_trusted_proxy_vouches_for_a_user_and_groups_become_a_role(tmp_path):
    with client(tmp_path) as c:
        me = c.get("/api/me", headers=sso("alice@example.org", "staff, forensics-analysts")).json()
        assert me == {"name": "alice@example.org", "role": "analyst", "via": "sso"}
        assert c.post("/api/cases", json={"id": "sso1"}, headers=sso("alice@example.org", "forensics-analysts")).status_code == 201
        assert c.post("/api/cases", json={"id": "sso2"}, headers=sso("rita", "forensics-readers")).status_code == 403   # viewer cannot create
        assert c.get("/api/me", headers=sso("both", "forensics-readers,forensics-admins")).json()["role"] == "admin"      # highest wins
        assert c.get("/api/cases/sso1/meta", headers=sso("rita", "forensics-readers")).json()["created_by"] == "alice@example.org"


def test_headers_from_anyone_else_are_just_untrusted_headers(tmp_path):
    with client(tmp_path, peer=OUTSIDER) as c:
        r = c.get("/api/me", headers=sso("mallory", "forensics-admins"))
        assert r.status_code == 401
        assert c.get("/api/admin/tokens", headers=sso("mallory", "forensics-admins")).status_code == 401


def test_trusted_proxy_without_a_user_header_falls_back_to_tokens(tmp_path):
    s = settings(tmp_path)
    token = new_token()
    ServerDB(s.db_path).add_token("api-bot", "viewer", hash_token(token))
    with TestClient(create_server_app(s), client=PROXY) as c:
        assert c.get("/api/me").status_code == 401
        assert c.get("/api/me", headers={"Authorization": f"Bearer {token}"}).json() == {"name": "api-bot", "role": "viewer", "via": "token"}


def test_unmapped_users_are_refused_unless_a_default_role_is_set(tmp_path):
    with client(tmp_path) as c:
        r = c.get("/api/me", headers=sso("nobody", "marketing"))
        assert r.status_code == 403 and "not in any group" in r.json()["detail"]
    with client(tmp_path / "d", sso_default_role="viewer") as c:
        assert c.get("/api/me", headers=sso("nobody", "marketing")).json()["role"] == "viewer"


def test_malformed_user_headers_are_ignored_not_trusted(tmp_path):
    with client(tmp_path) as c:
        for bad in ("x" * 500, "bell\x07char", ""):
            r = c.get("/api/me", headers={"X-Auth-Request-User": bad, "X-Auth-Request-Groups": "forensics-admins"}) if "\x07" not in bad else None
            if r is not None:
                assert r.status_code == 401


def test_sso_users_are_rate_limited_per_user(tmp_path):
    with client(tmp_path, principal_rate_limit_per_minute=3) as c:
        codes = [c.get("/api/me", headers=sso("loud", "forensics-readers")).status_code for _ in range(5)]
        assert codes == [200, 200, 200, 429, 429]
        assert c.get("/api/me", headers=sso("quiet", "forensics-readers")).status_code == 200


def test_cli_validates_sso_options(tmp_path):
    from typer.testing import CliRunner

    from android_forensics.cli.app import app

    base = ["serve", "--cases-dir", str(tmp_path / "c"), "--data-dir", str(tmp_path / "d")]
    for extra in (["--sso-trusted-proxy", "not-a-cidr", "--sso-default-role", "viewer"], ["--sso-trusted-proxy", "10.0.0.0/8"],
                  ["--sso-trusted-proxy", "10.0.0.0/8", "--sso-role-map", "g=root"], ["--sso-default-role", "god"]):
        r = CliRunner().invoke(app, [*base, *extra])
        assert r.exit_code == 2, extra
