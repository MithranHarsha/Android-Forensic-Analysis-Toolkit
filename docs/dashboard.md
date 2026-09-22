# The dashboard (Phase 11)

`android-forensics dashboard CASE` serves a small FastAPI application over one case's results: a REST API
(`src/android_forensics/dashboard/api.py`) and a static single-page frontend (`web/index.html`, vanilla HTML/CSS/JS, no
build step, no external network dependency). It is **read-only**: no endpoint runs a pipeline stage or writes to the case
database, so opening the dashboard can never change what a report or the CLI would show. Every number it displays comes
straight from the same case database `analyze` / `recover` / `report` already populated.

```
android-forensics analyze case001          # or: recover case001, after analyze --no-recover
android-forensics dashboard case001        # http://127.0.0.1:8765/
```

## Endpoints

| Path | Returns |
|---|---|
| `GET /api/summary` | case metadata, `CaseStore.counts()`, every analysis run |
| `GET /api/artifacts` | artifacts, filterable by `type`, `status`, `app`, `db` (substring), `q` (summary substring); paginated |
| `GET /api/artifacts/{id}` | one artifact's full row, its `recovered_records` entry (with `corroboration`) if it has one, and every correlation edge touching it |
| `GET /api/recovery` | recovered-record counts by status and method, how many are corroborated, unrecoverable regions, the last run of each Review 2 stage |
| `GET /api/recovered` | recovered records themselves (`values`, `unknown_columns`, `issues`, `also_found_at`, `corroboration`), filterable by `status` |
| `GET /api/carved` | carved candidates, filterable by `kind` — always `status: "CARVED CANDIDATE"`, `confidence` never `"HIGH"` |
| `GET /api/correlations` | the evidence graph's edges (filterable by `entity_kind`, `entity_ref`, `relation`) plus the node list they touch |
| `GET /api/validation` | validation results and the status breakdown, filterable by `status` |
| `GET /api/timeline` | timeline events, filterable by `kind`, `artifact_type`, `since`/`until` |

Every list endpoint is paginated (`limit`, `offset`) and reports its own `total`, so the frontend (or any other client) never
has to guess whether it has seen everything.

## The frontend

`web/index.html` has one tab per major result: Summary, Artifacts, Recovery, Carved, Correlation, Validation, Timeline.
Every carved row renders its status as the literal pill `CARVED CANDIDATE`; there is no code path in the page that turns a
carved or recovered entry into anything resembling `ACTIVE`. The page never talks to anything but this case's own API.

## A real export

`docs/dashboard_export.json` is genuine output, not a mock-up: a synthetic case (a telephony database with isolated deleted
rows, a contacts database naming the same number) was ingested, the full pipeline (`scan → extract → recover → carve →
correlate → reconstruct → validate → timeline`) was run against it, and these are the literal JSON bodies `/api/summary`,
`/api/recovery`, `/api/recovered` (first 2), `/api/carved` (first 2), `/api/correlations` (first 5) and `/api/validation`
(first 3) returned. From that run's `summary.counts`:

```json
{
  "files": 2, "databases": 2, "active_artifacts": 59,
  "recovered_records": 8, "recovered_artifacts": 8,
  "carved_candidates": 120, "correlation_edges": 250
}
```

Regenerate it with:

```python
from fastapi.testclient import TestClient
from android_forensics.dashboard import create_app
client = TestClient(create_app(Path("cases/your-case")))
client.get("/api/summary").json()
```

## Tests

`tests/integration/test_dashboard.py` runs the app in-process with `fastapi.testclient.TestClient` against a real
recovered case: every endpoint's numbers are checked against the case database directly (not against a second copy of the
same logic), a carved candidate is asserted to always read `CARVED CANDIDATE` with confidence never `HIGH`, `/api/artifacts/
{id}` is checked to include a recovered record's corroboration list, and a test confirms `CaseStore.counts()` is unchanged
before and after a full round of API calls.
