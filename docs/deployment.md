# Deploying the server

`android-forensics dashboard CASE` is a local, read-only viewer. `android-forensics serve` is the deployable service: several
cases, several users, evidence uploads and background analysis, all behind authentication.

```
browser ──HTTPS──► Caddy / nginx ──HTTP (private network)──► android-forensics serve
                    (TLS, size limits)                          ├─ token auth + roles, rate limits, CSP
                                                                ├─ SQLite: tokens, cases, uploads, jobs
                                                                └─ job workers ─► resource-limited child processes
                                                                                   (ingest → analyse → report → sign)
```

## 1. Quick start with Docker Compose (recommended)

```bash
cp deploy/.env.example deploy/.env      # set AF_DOMAIN to a name that resolves to this host
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.yml exec app android-forensics server-token create --name admin --role admin
```

Open `https://<AF_DOMAIN>/` and paste the token. What the stack does for you:

* Caddy gets and renews a certificate, enforces the upload size, and is the only published port.
* The app container: non-root, read-only root filesystem, **no capabilities, no route to the internet** (internal network),
  pid and memory limits, `no-new-privileges`. Evidence is parsed in a place that cannot phone home.
* `cases` and `data` are named volumes. Back them up together; `data` holds the token hashes, uploads and the server audit log.

## 2. Roles and tokens

| Role | Can |
|---|---|
| `viewer` | list cases, browse results, download reports, read audit logs of cases |
| `analyst` | + create cases, upload evidence, start/cancel jobs |
| `admin` | + manage tokens, delete (hide) cases, read the server audit log |

```bash
android-forensics server-token create --name alice --role analyst --data-dir /var/lib/android-forensics/data
android-forensics server-token list   --data-dir …
android-forensics server-token revoke 7 --data-dir …
```

A token is shown **once**; only its SHA-256 is stored. Revocation is immediate. Too many failed attempts from one address locks
that address out (even for valid tokens) until the window clears.

## 3. Without Docker

```bash
python -m venv /opt/android-forensics
/opt/android-forensics/bin/pip install --require-hashes --no-deps -r requirements.lock
/opt/android-forensics/bin/pip install --no-deps .
```

then install `deploy/android-forensics.service` (heavily sandboxed systemd unit) and `deploy/nginx.conf` (or the Caddyfile).
`serve` refuses to listen on a non-loopback address over plain HTTP unless you pass `--behind-proxy`, `--tls-certfile/--tls-keyfile`
or the explicitly named `--insecure-http`, and it insists on `--allowed-host` (Host-header protection) beyond loopback.

## 4. Limits and what they protect

| Setting | Default | Protects against |
|---|---|---|
| `--max-upload-gb` | 64 | a client filling the disk (checked against free space before accepting) |
| `--workers` | 2 | too many concurrent analyses |
| `--job-memory-gb` | 8 | a hostile database exhausting RAM (enforced via `RLIMIT_AS` on Linux; use container memory limits elsewhere) |
| `--job-hours` | 24 | runaway jobs (wall clock) — CPU seconds and maximum file size are also capped |
| `--rate-limit` | 600/min/IP | request floods; per-token and failed-auth limits are separate |

Each job is a fresh process in its own process group with a scrubbed environment (no server secrets), no core dumps and the
limits above; cancelling a job kills the whole group. See `server/sandbox.py`.

## 5. Signing reports

```bash
android-forensics keygen --key /secure/path/report-signing.pem        # once; set ANDROID_FORENSICS_KEY_PASSPHRASE to encrypt it
android-forensics serve … --signing-key /secure/path/report-signing.pem
```

Every report the server's jobs produce is signed (Ed25519, over `sha256sums.txt`). Anyone with the public key verifies offline:

```bash
android-forensics verify-report REPORT_DIR --trusted-key report-signing.pub.pem
```

Keep the private key off the server's data volume if you can (mount it read-only from a secrets store).

## 6. Operating it

* **Logs** — `--log-format json` produces one event per line (stage start/finish, durations, counts). The server's own audit
  log (`data/server_audit.log.jsonl`) is hash-chained; `GET /api/admin/audit` verifies it.
* **Health** — `GET /api/health` (no authentication, no data) for load balancers.
* **Restarts** — jobs that were running or queued when the process stopped are marked `interrupted`; re-submit them.
* **Retention** — deleting a case only hides it; evidence, results and audit trail stay on disk. Removal is a records-management
  decision made outside the tool.
* **Upgrades** — the case database migrates itself on open; back up volumes first.

## 7. What is *not* provided

Multi-node scaling (the job queue and rate limiter are per process; put a shared limiter at the proxy and run one server per
volume), single sign-on (tokens only; put an OIDC-aware proxy such as oauth2-proxy in front if you need SSO), and malware
sandboxing of apps found in evidence (the tool only parses data; it never executes anything from evidence).
