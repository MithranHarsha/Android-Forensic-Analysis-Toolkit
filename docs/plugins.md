# Writing a parser plugin

The built-in parsers recognise AOSP SMS, call-log, contact and Chromium-history schemas, scored by column names rather than file
names. A plugin teaches the tool a schema it does not know — typically an OEM variant or a messaging app — **without touching the
core**. A complete, working example is [`examples/plugins/acme_calls.py`](https://github.com/MithranHarsha/Android-Forensic-Analysis-Toolkit/blob/main/examples/plugins/acme_calls.py).

## What a plugin is

A Python file that, when imported, registers one or more `ArtifactParser` subclasses:

```python
from android_forensics.plugin_api import (ArtifactParser, CallRecord, FieldSpec, RoleMatch, SchemaMatch,
                                          best_matches, build_envelope, register)

@register
class AcmeCalls(ArtifactParser):
    name = "acme_calls"
    version = "0.1"

    def identify(self, tables, ctx):      # which tables look like mine? returns SchemaMatch objects
        ...
    def extract(self, session, match, ctx):   # read rows, yield artifacts
        ...
    def from_row(self, row, match, ctx):      # PURE row -> artifact conversion (also used for recovered rows)
        ...
```

Rules that keep your output trustworthy:

1. **`from_row` must be a pure function of the row.** The recovery engine feeds *deleted* records through the same code, with
   fields it could not reconstruct set to `UNKNOWN`. Do not invent values; use `FieldReader` (it flags type mismatches instead of
   coercing silently) and `UNKNOWN` for what is absent.
2. **Produce the existing artifact types** (`SMSMessage`, `CallRecord`, `Contact`, `BrowserHistoryEntry`, `BrowserDownload`,
   `GenericRecord`). Validation, correlation, confidence scoring, the timeline and the report then work on your output unchanged.
3. **Declare timestamp formats** (`convert(value, TimestampFormat.UNIX_S, ctx.now)`); the raw value and a plausibility verdict are kept.
4. Wrap raw rows with `build_envelope(...)` so provenance (file, SHA-256, table, rowid, parser name/version) is attached.

## Loading it

```bash
android-forensics --plugin ./acme_calls.py analyze EVIDENCE
export ANDROID_FORENSICS_PLUGINS=/opt/plugins/a.py:/opt/plugins/b.py      # or
# android-forensics.toml:   plugins = ["/opt/plugins/a.py"]
android-forensics --plugin ./acme_calls.py plugins                         # list parsers in effect
```

Packages can instead advertise an entry point in `pyproject.toml`:

```toml
[project.entry-points."android_forensics.parsers"]
acme = "acme_forensics.parsers"
```

## Safety model

* A plugin **is code that runs with your privileges.** The tool refuses plugin files owned by another user or writable by group/others,
  never searches evidence or case directories for plugins, and the web server never loads plugins from requests.
* A plugin that raises, in `identify` or `extract`, is recorded as a `parser_plugin_error` scan issue and the analysis continues.
  Built-in parsers do not get this leniency: their exceptions are bugs and surface.
* **Attribution:** every artifact carries `parser` and `version`; the report's *Build and audit provenance* section lists each loaded
  plugin with its SHA-256, so a result can always be traced to the exact code that produced it.
* The same hardened SQLite session is used for plugins: read-only authorizer, deadlines, no extension loading.
