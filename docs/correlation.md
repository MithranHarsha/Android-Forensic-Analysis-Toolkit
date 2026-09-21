# Correlation (Phase 7)

Correlation links evidence across independent sources, and answers one question for every recovered record and carved
candidate: **what else, in a different database, says the same thing?** The answer feeds the confidence scorer.

Code: `src/android_forensics/correlation/` — `graph.py` (in-memory graph), `facts.py` (what an artifact says), `builder.py`
(entities, edges, corroboration). Edges persist to the `correlations` table through the `CorrelationEdge` model, so what is
queried in memory is what is stored.

## Entities

Person · PhoneNumber · Message · Call · Contact · Application · Database · File · Timestamp · URL, plus the generic `artifact`
and `carved_candidate`. A node is `(kind, ref)`: `phone:2025550101`, `artifact:12`, `recovered:7` (a draft not yet stored),
`carved:3`, `database:1`, `file:5`, `person:ann lee`, `app:com.android.chrome`, `timestamp:2024-03-01T08:00:00Z`, `url:https://…`.

One phone number is **one node** whichever artifact carried it: `+12025550101` (SMS), `202-555-0101` (call log) and
`(202) 555-0101` (contacts) all key to `2025550101` (`normalization.phone_key`, the trailing ten digits). Short codes and sender
names have no key and are never matched.

## Relationships (`source --relation--> target`)

| Edge | Meaning |
|---|---|
| `phone SENT message` | the number sent this received message |
| `phone RECEIVED message` | the device sent the message to this number |
| `phone CALLED call` | the number called the device (incoming, missed, rejected, blocked, voicemail) |
| `phone RECEIVED call` | the device called this number |
| `contact CONTACT_OF phone` / `person` | the contact lists this number / is this person |
| `artifact FOUND_IN database` | a live record of that database; `database FOUND_IN application` |
| `recovered RECOVERED_FROM database` / `file` | where a recovered record's bytes were found (a `-wal` or `-journal` is a file) |
| `CORRELATES_WITH` | a recovered record or carved candidate and an independent artifact (or shared phone / URL / timestamp entity) |

A message or call whose direction is not known gets `phone CORRELATES_WITH artifact`, saying so, rather than a guessed direction.

## Corroboration

`build_correlation(subjects, carved, files)` returns the graph and, for each recovered record and carved candidate, a
`Corroboration`: one sentence per **kind** of independent source, ready for the scorer
(`"contact Ann Lee"`, `"call log (2 calls with this number; nearest 42 s from this record)"`, `"SMS thread (3 messages with this
number)"`, `"browser history (1 entry for this address)"`, `"the timestamp of 1 message"`, `"the body of 1 message"`).

* **Independent** means a different database. A hit in the free space of `x.db-wal` is *not* corroborated by a live row of
  `x.db`: that is the same file's own data (a sidecar resolves to its main file).
* A recovered record is corroborated by artifacts of a **different kind** than itself (a message by contacts and the call log; a
  call by contacts and the SMS thread), matched on the phone key.
* A recovered record's timestamp must be **structurally valid** (plausible) for its matches to count. If it is not, the artifacts
  are still linked, the edge says `corroborated: false`, and the record's `Corroboration.notes` explain why. A record with no
  timestamp has nothing to judge and is not penalised.
* A source that is itself only a recovered record says so (`"recovered SMS thread (1 message …)"`): weaker than a live row.
* Carved candidates are matched by value: phone key, normalised URL, e-mail address, the second a timestamp reads as, message
  body text, or any text value inside a record shape.
* At most five links per kind are drawn per record (the five nearest in time); the sentence always counts them all.

## Two-pass use

Correlation is pure, so the pipeline runs it twice: once over active artifacts plus *drafts* of the recovered records (refs
`recovered:<id>`) to learn what supports each; the recovered records are then reconstructed with those sentences and stored; and
once more over the stored artifacts (refs `artifact:<id>`) to persist the final edges.

## Limits

* Matching is by identity of a value, not by meaning: two people who share a landline share a `PhoneNumber`.
* Names are not matched across artifacts except through a contact's display name in a carved record.
* A candidate with no value to match (`SQLITE_RECORD` with no phone, body or name in it) cannot be corroborated and stays LOW.
