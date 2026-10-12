#!/bin/bash
# Runs the full analysis on one piece of evidence with no terminal. Called by the macOS app; progress goes to a log file.
# usage: analyze_evidence.sh <evidence path> <repo root> <case name> <log file> <result file>
# Writes the report path to <result file> on success, or "FAILED" if the analysis did not complete.
set -u
EVIDENCE="$1"; REPO="$2"; NAME="$3"; LOG="$4"; RESULT="$5"
CASES="$HOME/Documents/AndroidForensicsCases"
TOOL="$REPO/.venv/bin/android-forensics"
[ -x "$TOOL" ] || TOOL="$(command -v android-forensics || true)"
mkdir -p "$CASES"
if [ -z "$TOOL" ]; then
  echo "android-forensics is not installed in $REPO/.venv (run: python3 -m venv .venv && .venv/bin/pip install -e .)" > "$LOG"
  echo FAILED > "$RESULT"; exit 1
fi
rm -f "$RESULT"
if NO_COLOR=1 TERM=dumb caffeinate -i "$TOOL" analyze "$EVIDENCE" --cases-dir "$CASES" --name "$NAME" --workers auto > "$LOG" 2>&1; then
  REPORT="$(ls -td "$CASES/$NAME"/reports/*/report.html 2>/dev/null | head -1)"
  [ -n "$REPORT" ] && echo "$REPORT" > "$RESULT" || echo FAILED > "$RESULT"
else
  echo FAILED > "$RESULT"
fi
