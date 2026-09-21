# Artifact formats and parsing rules

Parsers never trust a file name. Each one lists the fields it understands as `FieldSpec(field, aliases, required, weight)`.
A table is a candidate if every *required* field is present and `matched weight / total weight ≥ 0.5`
(`+0.05` if the table name also matches, capped at 1.0). The score and the matched *variant* are stored on every
artifact (`schema_match_score`, `schema_variant`). Fields absent from a table are `UNKNOWN`. Virtual and `sqlite_*` tables
are ignored.

## SMS — `artifacts/sms.py` (variant `aosp_sms`)

Required: `address`, `body`, `date`. Optional: `type`, `date_sent`, `read`, `seen`, `thread_id`, `service_center`,
`sub_id`/`subscription_id`, `_id`, `status`, `protocol`, `locked`, `subject`.

| `type` | direction | | `type` | direction |
|---|---|---|---|---|
| 1 | RECEIVED | | 4 | OUTBOX |
| 2 | SENT | | 5 | FAILED |
| 3 | DRAFT | | 6 | QUEUED |

Any other value → `UNRECOGNISED` (the raw integer stays in `type_code`) and a flag. `date`, `date_sent` are Unix **milliseconds**; `date_sent = 0` means unset.
`address` is classified `phone` / `shortcode` / `alphanumeric` / `empty`; only genuine phone numbers get a `phone_key`.

## Call log — `artifacts/calls.py` (variant `aosp_calls`)

Required: `number`, `date`, `duration`, `type`. Optional: `presentation`, `name` (cached), `lookup_uri`,
`subscription_id`, `phone_account_address`, `phone_account_id`, `geocoded_location`, `countryiso`, `is_read`, `_id`.

`type`: 1 INCOMING · 2 OUTGOING · 3 MISSED · 4 VOICEMAIL · 5 REJECTED · 6 BLOCKED · 7 ANSWERED_EXTERNALLY.
`presentation`: 1 ALLOWED · 2 RESTRICTED · 3 UNKNOWN · 4 PAYPHONE. `date` Unix ms; `duration` seconds (negative → flag).
An empty number is a private/unknown caller and gets no `phone_key`.

## Contacts — `artifacts/contacts.py`

**`aosp_contacts2`** (Android `contacts2.db`): joins `raw_contacts` (`_id`, `display_name`, `contact_id`, `account_id`,
`deleted`, `starred`, `times_contacted`, `last_time_contacted`) ⨝ `data` (`raw_contact_id`, `mimetype_id`, `data1…`) ⨝
`mimetypes` ⨝ optional `accounts` and `contacts` (`contact_last_updated_timestamp`).

| mimetype | data columns |
|---|---|
| `vnd.android.cursor.item/name` | data1 display · data2 given · data3 family |
| `vnd.android.cursor.item/phone_v2` | data1 number · data2 type (1 HOME, 2 MOBILE, 3 WORK, …) |
| `vnd.android.cursor.item/email_v2` | data1 address · data2 type (1 HOME, 2 WORK, 3 OTHER, 4 MOBILE) |
| `vnd.android.cursor.item/organization` | data1 company |

Timestamp = `contact_last_updated_timestamp` if present else `last_time_contacted` (Unix ms). `deleted = 1` rows are
reported as ACTIVE with `marked_deleted = true` — Android keeps them until the next sync; they are *not* recovered data.

**`flat_contacts`**: a single table whose *name* suggests contacts (`contacts`, `contact`, `phonebook`, `people`) with a name
and a number column. (The name requirement prevents the call log's `name`/`number` columns from being misread as contacts.)

## Browser — `artifacts/browser.py`

**`chromium_history`** (Chrome and Chromium-based Android browsers, file `History`, no extension):
`urls (id, url, title, visit_count, typed_count, last_visit_time, hidden)`, `visits (id, url, visit_time, from_visit,
transition, visit_duration)`, `downloads (target_path|full_path, current_path, start_time, end_time, received_bytes,
total_bytes, state, tab_url, referrer, mime_type)` (the `state` column becomes the model field `download_state`).

* Times are **WebKit microseconds since 1601-01-01 UTC**.
* One `browser_visit` per `visits` row joined to its URL; a `urls` row with no visit rows becomes a *URL-level* record
  (`url_level_only = true`); a visit pointing at a missing URL row is flagged `dangling_url_reference`.
* `transition & 0xFF`: 0 LINK · 1 TYPED · 2 AUTO_BOOKMARK · 3 AUTO_SUBFRAME · 4 MANUAL_SUBFRAME · 5 GENERATED ·
  6 AUTO_TOPLEVEL · 7 FORM_SUBMIT · 8 RELOAD · 9 KEYWORD · 10 KEYWORD_GENERATED; qualifier bits: `0x01000000`
  FORWARD_BACK, `0x02000000` FROM_ADDRESS_BAR, `0x04000000` HOME_PAGE, `0x08000000` FROM_API, `0x10000000` CHAIN_START,
  `0x20000000` CHAIN_END, `0x40000000` CLIENT_REDIRECT, `0x80000000` SERVER_REDIRECT.
* Download `state` (`DownloadState`): 0 IN_PROGRESS · 1 COMPLETE · 2 CANCELLED · 3 INTERRUPTED; other values are `UNRECOGNISED` with the raw code kept in `download_state_code`.

**`legacy_flat_history`**: a table named `history`/`browser_history` with `url` and a date column (Unix ms).

## Generic parsers — `artifacts/generic.py`

* **Column hints** for tables no parser recognised: from names and up to 50 sampled rows — `timestamp_like` /
  `possible_timestamp` (with the plausible formats), `phone_like`, `url_like`, `email_like`, `text_heavy`, `blob`. They are
  triage aids stored in `db_tables.hints_json`; they do not create artifacts.
* **Application summary** (one artifact per package): file / database / sidecar counts, bytes, first/last file times,
  known-app label, SharedPreferences **file and key names only**. Provenance is the app's first database (or file) and
  `raw.row.derived_from` lists member files with their SHA-256; its extraction method is `FILESYSTEM_METADATA`.

## Not supported in Review 1

MMS parts and attachments, messaging apps (WhatsApp, Telegram, Signal — encrypted or app-specific schemas), Samsung/OEM
call-log variants beyond the generic schema match, Firefox/Gecko `places.sqlite`, Android Binary XML, media EXIF, key
stores, and any encrypted content. Add a parser by subclassing `ArtifactParser` (see [architecture.md](architecture.md)).
