# Raw carving (Phase 6)

Carving looks for artifact-shaped data in bytes that no parser reads: the free space of a database, a WAL frame's stale page,
a journal page, a file that is not a database at all. **Everything it reports is a candidate, not evidence.** Its status is the
literal string `CARVED CANDIDATE`; the model refuses any other status and a `CHECK` constraint in the case database refuses it
too. A candidate is never `ACTIVE`, never `RECOVERED`, and can never be `HIGH` confidence.

Code: `src/android_forensics/carving/` — `rules.py` (patterns and validators), `sms.py` (SMS-like text), `records.py`
(SQLite record shapes), `carver.py` (scanning, windows, exclusions), `database.py` (what to skip inside SQLite files).

## What a candidate carries

| Field | Meaning |
|---|---|
| `evidence_file_id`, `source_file`, `source_sha256` | the file the bytes are in |
| `offset`, `length` | byte-accurate position of the hit in that file |
| `kind`, `pattern` | the class (phone, URL, …) and the rule that matched |
| `matched` | the matched text, or a JSON rendering of the record for record shapes |
| `encoding` | `ascii` (also UTF-8), `utf-16le`, or `binary` |
| `container` | `file` (loose bytes) or `sqlite_free_space` (non-record space of a parsed database) |
| `context_valid` | neither neighbouring byte is an ASCII letter or digit — the hit is a whole token, not the middle of one |
| `context_before_hex`, `context_after_hex` | 24 bytes on either side |
| `extraction_method` | always `CARVING` |

## Rules

A rule is a regular expression (the shape) plus a validator (is the value possible). A shape that fails its validator is not
reported. Every rule also runs over UTF-16LE text.

| Kind | Pattern | Validation |
|---|---|---|
| phone | `phone_e164`: `+` and 8–15 digits | country code 1 must be a legal ten-digit North-American number |
| phone | `phone_nanp_formatted`: `(202) 555-0101`, `202-555-0101`, `1-202.555.0101` | area code and exchange start 2–9 and are not N11 |
| URL | `url_http`: `http(s)://…` | host is a domain with a real TLD, an IPv4 (octets ≤ 255), an IPv6 literal or `localhost`; port ≤ 65535; wrapping punctuation trimmed |
| URL | `url_android`: `content://`, `file:///`, `market://`, `intent://` | authority / path shape |
| e-mail | `email` | no `..`, local ≤ 64, labels legal, alphabetic TLD 2–24 |
| timestamp | `timestamp_unix_seconds` (10 digits), `timestamp_unix_millis` (13), `timestamp_webkit_micros` (17, Chromium) | reads as a date between 2008-01-01 and now + 2 days |
| timestamp | `timestamp_iso8601` (`2024-03-01 08:00:00`, `…T…Z`, offsets), `timestamp_medium_date` (`Mar 1, 2024 8:00:00 AM`) | real calendar date, in the same window |
| SMS-like text | `sms_backup_xml`, `sms_body_near_address`, `sms_otp_text`, `sms_body_near_timestamp` | see below |
| SQLite record | `sqlite_record_shape` | see below |

**SMS-like text.** Nothing about text says it is an SMS, so a run is reported only when something around it supports the
reading: an `<sms address=… body=…>` element (SMS Backup & Restore); a phone number within 96 bytes of a run of four or more
words; a one-time / verification code; or a 13-digit millisecond timestamp within 96 bytes. The strongest support names the
pattern; the others are listed in `notes`.

**SQLite record shapes.** A header size byte whose serial-type varints end *exactly* at it, no reserved types, at least three
columns, a body that fits (≤ 16 KiB), every text value valid UTF-8, at least one four-character text that is mostly printable
and mostly letters or digits, and not all-but-one column NULL. Random bytes essentially never satisfy this (tested on 200 kB of
noise). It is a shape, not a schema match: it does not say which table the record came from.

## Where carving looks inside a database

Carving a database blind would re-find everything the parsers already turned into artifacts. So it skips:

* the 100-byte header, every b-tree page header and pointer array, a freelist trunk's bookkeeping;
* the cells of every page image that is **the current version of its page** — main-file pages the WAL has not replaced, and the
  newest committed WAL frame of each page;
* overflow, pointer-map and lock-byte pages;
* the raw bytes of records the recovery engine reported.

Kept for carving: a page's unallocated gap, freeblocks nobody could turn into a row, released (freelist / orphan) pages, and
*history* — a main-file page the WAL replaced, older or uncommitted or stale WAL frames, every journal page. Their cells are
values the database no longer shows, and a table the recovery engine cannot model (fewer than three columns, `WITHOUT ROWID`,
virtual) is only reachable this way.

## Limits

* A bare digit run is never a phone number (timestamps, ids and sizes look the same); international numbers written with spaces
  or dashes are not recognised.
* A timestamp stored as a binary integer is not carved on its own (a random 6-byte value is in the plausible range about 0.3 % of
  the time); it is decoded when it sits in a record shape.
* Dates without a year (logcat) cannot be checked for plausibility and are not carved.
* Languages that do not separate words with spaces are not recognised as SMS-like text.
* A URL is taken up to the first character a URL cannot contain, so a URL stored directly against the next text column is
  reported too long — which is why `context_valid` exists.
* Only the reported *instance* of a recovered row is excluded; other copies of the same record (a split's residue, a freeblock
  copy) are separate bytes and are carved, then corroborated by the recovered artifact during correlation.
* Windowed scanning (1 MiB + 4 KiB overlap) assumes no single hit is longer than the overlap; the longest rule (a URL) is 2 KiB.
