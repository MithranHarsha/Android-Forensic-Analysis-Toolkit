# Dashboard UI walkthrough

A plain-language guide to every screen in `src/android_forensics/dashboard/web/index.html` — what it shows, what each control does, and why it matters
forensically. Written to be read from while presenting the live dashboard (`android-forensics dashboard CASE`,
`http://127.0.0.1:8765/`). For the underlying REST API each screen calls, see [dashboard.md](dashboard.md).

The dashboard is **read-only**: nothing you click here runs a pipeline stage or changes the case database. Every number
on screen comes straight from the same `case.db` that `analyze` already populated, so it can never show something the
CLI or the report wouldn't also show.

## The header and the seven tabs

The header bar names the case (`name — first 8 characters of the case ID — detected layout`). Below it is a row of
seven tabs; clicking one loads that screen's summary cards and its table. The tabs, in the order they appear, are:
**Summary, Artifacts, Recovery, Carved, Correlation, Validation, Timeline.**

Every status you'll see anywhere in the UI is rendered as a small coloured **pill**, and the colour always means the
same thing across every tab:

| Colour | Statuses | Meaning |
|---|---|---|
| Green | `ACTIVE`, `VALID` | Untouched, currently-live data, or a check that passed cleanly |
| Blue | `RECOVERED` | A deleted record whose bytes came back completely intact |
| Amber | `PARTIAL`, `UNVERIFIED` | Recovered but missing something specific (usually the rowid), or a check that couldn't be run |
| Red | `CORRUPTED`, `INVALID` | Structurally readable but fails validation — kept and flagged, never silently dropped |
| Purple | `CARVED CANDIDATE` | A raw byte-pattern match with no structural guarantee at all — the weakest category, explained below |

That consistency is deliberate: once you've explained the pill colours once on the Summary tab, every other tab is
self-explanatory.

## Summary tab

The first thing anyone sees. Eight cards across the top give the case at a glance:

- **Files / Databases** — what filesystem discovery found and how many were SQLite.
- **Active artifacts** — live SMS, calls, contacts, browser history, etc. — Review 1's output, unchanged by anything
  Review 2 does.
- **Recovered records** and **Reconstructed** — how many deleted/superseded SQLite cells the recovery engine found, and
  how many of those were turned into typed artifacts (normally equal — every recovered record becomes an artifact).
- **Carved candidates** — raw pattern hits (phone numbers, URLs, e-mails, timestamps, SMS-shaped text) found outside any
  parsed table structure.
- **Correlation edges** — links the evidence graph drew between artifacts (e.g. a phone number that appears in both
  calls and contacts).
- **Validation results** — how many automated integrity/consistency checks ran.

Below the cards, an **Analysis runs** table lists every pipeline stage that has ever executed on this case (`scan`,
`extract`, `recover`, `carve`, `correlate`, `reconstruct`, `validate`, `timeline`), each with its status pill and
start/finish time. This is the audit trail: it proves what was actually run, not just claimed.

*Talking point:* this tab alone answers "what did the tool actually do to this evidence" in one screen.

## Artifacts tab

Every artifact the case has — active and recovered side by side, because a recovered SMS and a live one are the same
kind of thing at different confidence, not two different systems.

- **Type filter** — narrows to one artifact kind: `sms`, `call`, `contact`, `browser_visit`, `browser_download`, or
  `generic_record` (anything without a dedicated parser).
- **Status filter** — `ACTIVE`, `RECOVERED`, `PARTIAL`, or `CORRUPTED`.
- **Table columns** — ID, type, status pill, confidence level, UTC timestamp, and a one-line summary (truncated to 90
  characters; the full record is available via `artifacts --show <id>` on the CLI).

*Talking point:* set the status filter to `RECOVERED` live — this is the moment to show a row that used to be a
`DELETE`d SQLite cell and is now sitting here as a normal-looking artifact, just with a blue pill instead of a green
one.

## Recovery tab

Zooms into Review 2's core result: what came back from freeblocks, the freelist, WAL frames and rollback-journal pages.

- **Status cards** — one card per outcome (`RECOVERED`, `PARTIAL`, `CORRUPTED`), a **Corroborated** card (how many were
  confirmed by an independent source elsewhere in the evidence), and an **Unrecoverable (proven)** card — regions the
  engine can *prove* are gone (overwritten), not just regions it failed to find something in. That distinction — proven
  gone vs. simply not found — is one of the project's core honesty guarantees.
- **Table columns** — ID, which SQLite table the cell belongs to, status, recovery **method** (which structure it was
  found in), **rowid** (or literally `unknown` when the freeblock header overwrote it — never guessed), the page/frame
  **region** it lives in, and a **fit** score.

*Talking point:* point at a `PARTIAL` row and explain the rowid column reads `unknown`, not a placeholder number — the
tool refuses to invent what SQLite's own freeblock header physically erased.

## Carved tab

The deliberately weakest evidence category, and the UI says so up front: a banner reads *"A carved candidate is never
confirmed evidence: it stays **CARVED CANDIDATE** whatever its confidence."* There is no code path anywhere in the
frontend that lets a carved hit's status render as anything else.

- **Table columns** — ID, pattern **kind** (phone number, URL, e-mail, timestamp, SMS-like text, loose SQLite-record
  shape), status (always the purple `CARVED CANDIDATE` pill), confidence (never `HIGH` — enforced by the scorer, not
  just the UI), the matched text (truncated to 60 characters), and how many independent sources **corroborate** it.

*Talking point:* this tab is the answer to "how do you stop the tool from overclaiming" — show that even a
high-confidence-looking carved match is capped below `HIGH` and permanently labelled a candidate, never evidence.

## Correlation tab

The evidence graph. Two cards give the scale (**Entities** — distinct people/numbers/databases involved, **Edges** —
links drawn between them), then a table of every edge: **Source**, **Relation** (e.g. `CONTACT_OF`, `SENT`, `CALLED`,
`CORRELATES_WITH`), **Target**, and a plain-English **Explanation** of why the link was drawn.

*Talking point:* find an edge whose explanation cites two different databases — corroboration in this project only ever
counts if it comes from an independent source, never the same file's data matched against itself.

## Validation tab

The integrity layer. Cards break down all validation results by outcome (`VALID`, `PARTIAL`, `INVALID`, `UNVERIFIED`),
then a table lists every individual check: its status pill, the **check name**, the **target** it ran against, and a
**detail** string explaining the result (truncated to 140 characters).

*Talking point:* an `INVALID` or `UNVERIFIED` row here is not hidden or excluded from counts elsewhere — it's kept and
explained, which is the point: failures are data too.

## Timeline tab

Every dateable event — active-artifact timestamps and recovered-record timestamps — merged into one chronological feed:
**Timestamp** (UTC), **Kind** (the event category), **Type** (artifact type, or `file` for filesystem events), **Status**
pill, and a one-line **Event** description.

*Talking point:* this is the "reconstruct what happened, in order" view — the same recovered rows shown individually on
the Recovery tab now sit in chronological context next to the active data around them.

## Suggested walkthrough order for a live demo

1. **Summary** — orient the panel: what the case is, what ran, the headline numbers.
2. **Artifacts**, filtered to `RECOVERED` — show a deleted record that came back.
3. **Recovery** — show the same result from the engine's side: method, region, and a `PARTIAL` row's `unknown` rowid.
4. **Carved** — show the weakest-evidence guardrail (the banner, the capped confidence).
5. **Correlation** — show one link corroborated across two independent databases.
6. **Validation** — show that failures are kept and explained, not swept away.
7. **Timeline** — close by showing it all merged into one reconstructed sequence of events.

That order mirrors the pipeline itself (`scan → extract → recover → carve → correlate → validate → timeline`), so the
UI walkthrough doubles as an architecture walkthrough.
