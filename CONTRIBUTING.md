# Contributing

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request
```bash
ruff check src tests          # lint
mypy                          # types (new modules must be clean; see [[tool.mypy.overrides]] for known debt)
bandit -q -c pyproject.toml -r src
coverage run -m pytest && coverage report --fail-under=93
```

## Ground rules
- **Forensic integrity first.** Nothing may write to evidence. A recovered record is never presented as confirmed
  without provenance (location, raw bytes) and an explained confidence level; a carved candidate is never `HIGH`.
- **No fabricated results.** Numbers in docs come from `experiments/` and are regenerated, not typed in.
- **Tests with every change.** Parsers need adversarial inputs (truncated, corrupt, hostile) not just happy paths.
- Add an entry to `CHANGELOG.md` under *Unreleased*.

## Adding a parser (plugin)
See `docs/plugins.md`. A plugin is a Python module exposing `register(registry)`; it can be loaded without editing the
core via the `android_forensics.parsers` entry-point group or `--plugin path/to/module.py`.
