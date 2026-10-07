"""Fuzz the HTTP surface: random methods, paths, headers and bodies must never yield a 5xx, never leak a traceback, and — the
property that matters most — never reach protected data without a valid token."""

from __future__ import annotations

import string

import pytest
from fastapi.testclient import TestClient
from hypothesis import given
from hypothesis import strategies as st

from android_forensics.server import ServerSettings, create_server_app
from android_forensics.server.auth import hash_token, new_token
from android_forensics.server.db import ServerDB

PUBLIC = {"/", "/api/health", "/api/mode"}
SEGMENT = st.text(alphabet=string.ascii_letters + string.digits + "._-%~:;@!$&'()*+,=", min_size=0, max_size=24) | st.sampled_from(
    ["..", ".", "%2e%2e", "%2f", "%00", "", "admin", "cases", "jobs", "reports", "tokens", "uploads", "audit", "summary", "artifacts", "static"])
PATHS = st.lists(SEGMENT, min_size=0, max_size=6).map(lambda parts: "/" + "/".join(parts))
METHODS = st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
HEADER_VALUES = st.text(alphabet=string.printable.replace("\r", "").replace("\n", ""), max_size=80)


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    base = tmp_path_factory.mktemp("fzs")
    settings = ServerSettings(cases_dir=base / "cases", data_dir=base / "data", workers=1, rate_limit_per_minute=10**9,
                              principal_rate_limit_per_minute=10**9, auth_failures_per_minute=10**9)
    token = new_token()
    ServerDB(settings.db_path).add_token("fz-viewer", "viewer", hash_token(token))
    with TestClient(create_server_app(settings), raise_server_exceptions=False) as client:
        yield client, token


@given(METHODS, PATHS, st.binary(max_size=200), st.dictionaries(st.sampled_from(["content-type", "x-forwarded-for", "origin", "range", "x-test"]), HEADER_VALUES, max_size=3))
def test_unauthenticated_requests_never_succeed_on_protected_routes_nor_error(srv, method, path, body, headers):
    client, _token = srv
    r = client.request(method, path, content=body, headers=headers)
    assert r.status_code < 500, (method, path, r.status_code, r.text[:200])
    assert "Traceback" not in r.text and "File \"" not in r.text
    base = path.split("?")[0].rstrip("/") or "/"
    if base not in PUBLIC and not base.startswith("/static") and method not in ("OPTIONS", "HEAD") and r.status_code == 200:
        pytest.fail(f"{method} {path} answered 200 without a token")


@given(METHODS, PATHS, st.binary(max_size=200))
def test_authenticated_viewer_never_triggers_a_server_error_or_a_write(srv, method, path, body):
    client, token = srv
    r = client.request(method, path, content=body, headers={"Authorization": f"Bearer {token}", "content-type": "application/json"})
    assert r.status_code < 500, (method, path, r.status_code, r.text[:200])
    if method in ("POST", "PUT", "DELETE", "PATCH") and not path.startswith("/static"):
        assert r.status_code != 201 and r.status_code != 202, f"a viewer created something via {method} {path}"


@given(st.text(max_size=300))
def test_garbage_tokens_are_401_never_500(srv, junk):
    client, _ = srv
    for value in (junk, "Bearer " + junk, "bearer afk_" + junk):
        try:
            r = client.get("/api/me", headers={"Authorization": value})
        except Exception:  # header values the HTTP client itself refuses to send
            continue
        assert r.status_code in (400, 401, 429), (value[:40], r.status_code)
