# Security policy

## Threat model

This tool parses **hostile input by design**: acquisitions, archives and SQLite files from compromised or
adversarial devices. It is built so that evidence content can never (a) escape the case directory, (b) modify the
original evidence, (c) exhaust the host, or (d) inject script into a report or the dashboard.

| Concern | Control |
|---|---|
| Path traversal / zip-slip / absolute paths | `acquisition/safety.py` normalises every member path; `..`, NUL, drive prefixes rejected |
| Symlink / hardlink / device / FIFO entries | skipped and recorded as an acquisition issue, never followed |
| Decompression bombs / runaway archives | entry-count, per-member and total byte budgets (`config.py`) |
| Modification of evidence | opened `O_RDONLY | O_NOFOLLOW`; originals re-hashed at validation |
| XML entity expansion | `defusedxml` |
| Report / dashboard XSS | Jinja2 autoescaping; dashboard escapes evidence text and sends a strict CSP |
| Resource exhaustion | per-stage time / memory limits when run through the job worker (`android-forensics serve`) |
| Dashboard access | token authentication with roles, rate limiting, security headers (`serve`) |

## Operating guidance
- Run analysis in a container or VM with **no network** and the evidence mounted **read-only** (see `Dockerfile`).
- Use a hardware write blocker when acquiring from original media; this tool never writes to evidence, but your OS may
  update access times on read.
- Do not expose the dashboard to untrusted networks without TLS (reverse proxy; see `docs/deployment.md`).

## Reporting a vulnerability
Please open a **private** GitHub security advisory on this repository (Security → Report a vulnerability), or email the
maintainer. Do not file public issues for exploitable bugs. Expect an acknowledgement within 7 days.

## Supported versions
Only the latest minor release receives security fixes.
