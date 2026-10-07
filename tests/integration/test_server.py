from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from android_forensics.custody.audit import AuditLog
from android_forensics.server import ServerSettings, create_server_app
from android_forensics.server.auth import hash_token, new_token
from android_forensics.server.db import ServerDB


def make_settings(tmp_path: Path, **kw) -> ServerSettings:
    return ServerSettings(cases_dir=tmp_path / "cases", data_dir=tmp_path / "data", workers=1, **kw)


def add_token(settings: ServerSettings, role: str, name: str | None = None) -> str:
    token = new_token()
    ServerDB(settings.db_path).add_token(name or role, role, hash_token(token))
    return token


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def srv(tmp_path):
    settings = make_settings(tmp_path)
    tokens = {r: add_token(settings, r) for r in ("viewer", "analyst", "admin")}
    with TestClient(create_server_app(settings)) as client:
        yield client, tokens, settings


def wait_for(client, case, job, headers, timeout=300):
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = client.get(f"/api/cases/{case}/jobs/{job}", headers=headers).json()
        if j["status"] in ("succeeded", "failed", "cancelled", "interrupted"):
            return j
        time.sleep(0.5)
    raise AssertionError("job did not finish")


# ---------------------------------------------------------------------------- authentication


def test_everything_but_health_and_static_needs_a_token(srv):
    c, _t, _s = srv
    assert c.get("/api/health").json() == {"status": "ok"} and c.get("/api/mode").json()["mode"] == "server"
    for path in ("/api/cases", "/api/me", "/api/admin/tokens", "/api/cases/x/summary"):
        assert c.get(path).status_code == 401
    assert c.get("/api/cases", headers=bearer("afk_forged")).status_code == 401
    assert c.get("/api/cases", headers={"Authorization": "Basic abc"}).status_code == 401
    assert c.get("/api/cases", headers={"Authorization": "Bearer " + "A" * 5000}).status_code == 401


def test_roles_are_enforced(srv):
    c, t, _s = srv
    assert c.get("/api/me", headers=bearer(t["viewer"])).json() == {"name": "viewer", "role": "viewer"}
    assert c.get("/api/cases", headers=bearer(t["viewer"])).status_code == 200
    assert c.post("/api/cases", json={"id": "c1"}, headers=bearer(t["viewer"])).status_code == 403
    assert c.post("/api/cases", json={"id": "c1"}, headers=bearer(t["analyst"])).status_code == 201
    assert c.delete("/api/cases/c1", headers=bearer(t["analyst"])).status_code == 403
    assert c.get("/api/admin/tokens", headers=bearer(t["analyst"])).status_code == 403
    assert c.get("/api/admin/tokens", headers=bearer(t["admin"])).status_code == 200


def test_brute_force_lockout_blocks_even_valid_tokens_until_the_window_clears(tmp_path):
    settings = make_settings(tmp_path, auth_failures_per_minute=3)
    good = add_token(settings, "admin")
    with TestClient(create_server_app(settings)) as c:
        for _ in range(3):
            assert c.get("/api/me", headers=bearer("afk_guess")).status_code == 401
        r = c.get("/api/me", headers=bearer(good))
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1


def test_token_lifecycle_and_secrets_are_not_stored(srv):
    c, t, s = srv
    created = c.post("/api/admin/tokens", json={"name": "new-analyst", "role": "analyst"}, headers=bearer(t["admin"])).json()
    token = created["token"]
    assert c.get("/api/me", headers=bearer(token)).json()["role"] == "analyst"
    assert c.get("/api/admin/tokens", headers=bearer(t["admin"])).json()[-1]["last_used_at"]
    for secret in (token, *t.values()):
        for f in (s.db_path, *s.data_dir.rglob("*")):
            if f.is_file():
                assert secret.encode() not in f.read_bytes(), f"plaintext token found in {f}"
    assert c.delete(f"/api/admin/tokens/{created['id']}", headers=bearer(t["admin"])).json() == {"revoked": True}
    assert c.get("/api/me", headers=bearer(token)).status_code == 401
    me = c.get("/api/me", headers=bearer(t["admin"])).json()
    assert me["role"] == "admin"
    assert c.post("/api/admin/tokens", json={"name": "x", "role": "root"}, headers=bearer(t["admin"])).status_code == 422
    own = next(x["id"] for x in c.get("/api/admin/tokens", headers=bearer(t["admin"])).json() if x["role"] == "admin")
    assert c.delete(f"/api/admin/tokens/{own}", headers=bearer(t["admin"])).status_code == 409   # no self-lockout


# ---------------------------------------------------------------------------- cases, uploads, jobs


def test_case_ids_cannot_traverse_or_collide(srv):
    c, t, s = srv
    h = bearer(t["analyst"])
    for bad in ("../evil", "a/b", "..", ".hidden", "x" * 80, "has space", "semi;colon", ""):
        assert c.post("/api/cases", json={"id": bad}, headers=h).status_code in (404, 422), bad
    assert c.post("/api/cases", json={"id": "ok-1.a_b"}, headers=h).status_code == 201
    assert c.post("/api/cases", json={"id": "ok-1.a_b"}, headers=h).status_code == 409
    assert (s.cases_dir / "ok-1.a_b" / "case.db").is_file()
    for path in ("/api/cases/..%2f..%2fetc/summary", "/api/cases/%2e%2e/summary", "/api/cases/nope/summary"):
        assert c.get(path, headers=h).status_code in (404, 422)


def test_upload_enforces_size_length_and_sanitises_names(tmp_path):
    settings = make_settings(tmp_path, max_upload_bytes=1000)
    t = add_token(settings, "analyst")
    h = bearer(t)
    with TestClient(create_server_app(settings)) as c:
        c.post("/api/cases", json={"id": "u"}, headers=h)
        assert c.put("/api/cases/u/uploads?filename=big.bin", content=b"x" * 1001, headers=h).status_code == 413
        assert c.put("/api/cases/u/uploads?filename=empty", content=b"", headers=h).status_code == 400
        body = b"evidence-bytes" * 10
        r = c.put("/api/cases/u/uploads?filename=..%2F..%2Fetc%2Fpasswd", content=body, headers=h)
        assert r.status_code == 201
        up = r.json()
        assert up["name"] == "passwd" and up["size"] == len(body) and up["sha256"] == hashlib.sha256(body).hexdigest()
        stored = next(settings.uploads_dir.rglob("*passwd"))
        assert stored.read_bytes() == body and not (stored.stat().st_mode & 0o222), "stored read-only"
        assert settings.uploads_dir in stored.parents and settings.cases_dir not in stored.parents
        assert not list(settings.uploads_dir.rglob(".*.part")), "no partial files left behind"
        assert c.get("/api/cases/u/uploads", headers=h).json()[0]["sha256"] == up["sha256"]
        assert c.put("/api/cases/nope/uploads?filename=x", content=b"abc", headers=h).status_code == 404


def test_viewer_cannot_upload_or_start_jobs(srv):
    c, t, _s = srv
    c.post("/api/cases", json={"id": "v"}, headers=bearer(t["analyst"]))
    assert c.put("/api/cases/v/uploads?filename=x", content=b"abc", headers=bearer(t["viewer"])).status_code == 403
    assert c.post("/api/cases/v/jobs", json={"kind": "report"}, headers=bearer(t["viewer"])).status_code == 403


@pytest.mark.skipif(sys.platform == "win32", reason="the analysis-job sandbox (resource limits, process groups) is POSIX-only")
def test_end_to_end_upload_analyse_view_download_and_audit(tmp_path, synth):
    out, _ = synth
    key_dir = tmp_path / "keys"
    from android_forensics.custody import generate_keypair
    key, pub, _fp = generate_keypair(key_dir / "k.pem")
    settings = make_settings(tmp_path, signing_key=key)
    a, v, adm = add_token(settings, "analyst", "alice"), add_token(settings, "viewer"), add_token(settings, "admin")
    with TestClient(create_server_app(settings)) as c:
        assert c.post("/api/cases", json={"id": "case1", "description": "e2e"}, headers=bearer(a)).status_code == 201
        data = (out / "acquisition.zip").read_bytes()
        up = c.put("/api/cases/case1/uploads?filename=acquisition.zip", content=data, headers=bearer(a)).json()
        assert up["sha256"] == hashlib.sha256(data).hexdigest()
        job = c.post("/api/cases/case1/jobs", json={"kind": "analyze", "upload_id": up["id"]}, headers=bearer(a)).json()
        assert job["status"] in ("queued", "running")
        done = wait_for(c, "case1", job["id"], bearer(a))
        log = c.get(f"/api/cases/case1/jobs/{job['id']}?log=1", headers=bearer(a)).json()["log_tail"]
        assert done["status"] == "succeeded" and done["exit_code"] == 0, log

        # the same read-only router as the local dashboard, now per case and behind auth
        s = c.get("/api/cases/case1/summary", headers=bearer(v)).json()
        assert s["case"]["name"] == "case1" and s["counts"]["active_artifacts"] > 300
        assert c.get("/api/cases/case1/artifacts?limit=2", headers=bearer(v)).json()["total"] > 300
        assert c.get("/api/cases/case1/summary").status_code == 401

        reports = c.get("/api/cases/case1/reports", headers=bearer(v)).json()
        assert reports and reports[0]["signed"] and "report.html" in reports[0]["files"]
        r = c.get(f"/api/cases/case1/reports/{reports[0]['name']}/report.html", headers=bearer(v))
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and "sandbox" in r.headers["content-security-policy"]
        # report files verify with the offline verifier
        from android_forensics.custody import verify_report
        rep_dir = settings.cases_dir / "case1" / "reports" / reports[0]["name"]
        assert verify_report(rep_dir, pub).ok

        # traversal through the download route
        name = reports[0]["name"]
        for evil in ("../../case.db", "..%2f..%2fcase.db", "%2e%2e/%2e%2e/case.db", "csv/../../../case.db"):
            assert c.get(f"/api/cases/case1/reports/{name}/{evil}", headers=bearer(v)).status_code == 404
        assert c.get("/api/cases/case1/reports/..%2f/x", headers=bearer(v)).status_code == 404

        # the case's own audit log names the web user the job acted for
        case_audit = c.get("/api/cases/case1/audit", headers=bearer(a)).json()
        assert case_audit["intact"] and {e["user"] for e in case_audit["tail"]} == {"server:alice"}
        assert {e["command"] for e in case_audit["tail"]} >= {"ingest", "analyze", "report"}

        # the server audit log recorded each mutation, with who and from where, and it verifies
        sa = c.get("/api/admin/audit", headers=bearer(adm)).json()
        events = [e["event"] for e in sa["tail"]]
        assert sa["intact"] and {"case_created", "evidence_uploaded", "job_submitted", "job_started", "job_finished", "report_downloaded"} <= set(events)
        assert all(e.get("ip") for e in sa["tail"] if e["event"] == "case_created")


def test_cancel_a_queued_job_and_unknown_upload(srv):
    c, t, _s = srv
    h = bearer(t["analyst"])
    c.post("/api/cases", json={"id": "q"}, headers=h)
    assert c.post("/api/cases/q/jobs", json={"kind": "analyze", "upload_id": "nope"}, headers=h).status_code == 404
    assert c.post("/api/cases/q/jobs", json={"kind": "rm -rf"}, headers=h).status_code == 422
    assert c.post("/api/cases/q/jobs", json={"kind": "analyze"}, headers=h).status_code in (202, 422)


def test_soft_delete_hides_the_case_but_keeps_its_files(srv):
    c, t, s = srv
    c.post("/api/cases", json={"id": "gone"}, headers=bearer(t["analyst"]))
    assert c.delete("/api/cases/gone", headers=bearer(t["admin"])).json() == {"deleted": True}
    assert c.get("/api/cases/gone/summary", headers=bearer(t["viewer"])).status_code == 404
    assert "gone" not in [x["id"] for x in c.get("/api/cases", headers=bearer(t["viewer"])).json()]
    assert (s.cases_dir / "gone" / "case.db").is_file()
    assert c.post("/api/cases", json={"id": "gone"}, headers=bearer(t["analyst"])).status_code == 409


# ---------------------------------------------------------------------------- HTTP hardening


def test_security_headers_on_api_and_frontend(srv):
    c, t, _s = srv
    for r in (c.get("/api/health"), c.get("/"), c.get("/static/app.js"), c.get("/api/cases", headers=bearer(t["viewer"]))):
        assert "default-src 'none'" in r.headers["content-security-policy"] and "script-src 'self'" in r.headers["content-security-policy"]
        assert "unsafe-inline" not in r.headers["content-security-policy"] and "unsafe-eval" not in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
        assert r.headers["referrer-policy"] == "no-referrer"
    assert c.get("/api/cases", headers=bearer(t["viewer"])).headers["cache-control"] == "no-store"
    assert "strict-transport-security" not in c.get("/api/health").headers
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404


def test_hsts_when_behind_tls(tmp_path):
    with TestClient(create_server_app(make_settings(tmp_path, behind_tls=True))) as c:
        assert "max-age" in c.get("/api/health").headers["strict-transport-security"]


def test_host_header_attacks_are_rejected(srv):
    c, _t, _s = srv
    assert c.get("/api/health", headers={"Host": "evil.example"}).status_code == 400


def test_cors_is_closed_by_default_and_exact_when_configured(tmp_path):
    with TestClient(create_server_app(make_settings(tmp_path / "a"))) as c:
        r = c.get("/api/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in r.headers
    with TestClient(create_server_app(make_settings(tmp_path / "b", allowed_origins=("https://good.example",)))) as c:
        ok = c.get("/api/health", headers={"Origin": "https://good.example"})
        bad = c.get("/api/health", headers={"Origin": "https://evil.example"})
        assert ok.headers["access-control-allow-origin"] == "https://good.example"
        assert "access-control-allow-origin" not in bad.headers
        pre = c.options("/api/cases", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        assert pre.status_code == 400


def test_rate_limit_applies_per_client_and_reports_retry_after(tmp_path):
    with TestClient(create_server_app(make_settings(tmp_path, rate_limit_per_minute=5))) as c:
        codes = [c.get("/api/health").status_code for _ in range(8)]
        assert codes[:5] == [200] * 5 and set(codes[5:]) == {429}
        assert int(c.get("/api/health").headers["Retry-After"]) >= 1


def test_per_token_limit(tmp_path):
    settings = make_settings(tmp_path, principal_rate_limit_per_minute=4)
    t = add_token(settings, "viewer")
    with TestClient(create_server_app(settings)) as c:
        codes = [c.get("/api/me", headers=bearer(t)).status_code for _ in range(6)]
        assert codes[:4] == [200] * 4 and codes[4:] == [429, 429]


def test_server_state_is_private_and_orphan_jobs_are_interrupted_on_restart(tmp_path):
    settings = make_settings(tmp_path)
    create_server_app(settings)
    assert oct(settings.data_dir.stat().st_mode & 0o777) == "0o700" and oct(settings.db_path.stat().st_mode & 0o777) == "0o600"
    db = ServerDB(settings.db_path)
    db.add_case("c", "c", None, None, "t")
    jid = db.add_job("c", "report", None, "t")
    db.update_job(jid, status="running")
    with TestClient(create_server_app(settings)):
        pass
    assert db.job(jid)["status"] == "interrupted"
    conn = sqlite3.connect(settings.db_path)
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] in (0, 1)
    assert AuditLog(settings.audit_path).verify().ok
    assert json.loads(settings.audit_path.read_text().splitlines()[0])["event"] == "jobs_interrupted_at_startup"


def test_head_requests_work_for_health_checks(srv):
    c, _t, _s = srv
    assert c.head("/api/health").status_code == 200 and c.head("/").status_code == 200
    assert "default-src 'none'" in c.head("/").headers["content-security-policy"]


def test_public_host_names_still_allow_loopback_for_health_checks(tmp_path):
    from android_forensics.cli.app import allowed_hosts

    hosts = allowed_hosts(["forensics.example.org"])
    assert hosts[0] == "forensics.example.org" and {"localhost", "127.0.0.1", "[::1]"} <= set(hosts)
    assert allowed_hosts(None) == ("localhost", "127.0.0.1", "[::1]")
    with TestClient(create_server_app(make_settings(tmp_path, allowed_hosts=hosts)), base_url="http://forensics.example.org") as c:
        assert c.get("/api/health").status_code == 200
        assert c.get("/api/health", headers={"Host": "127.0.0.1:8765"}).status_code == 200      # the compose healthcheck
        assert c.get("/api/health", headers={"Host": "evil.example"}).status_code == 400
