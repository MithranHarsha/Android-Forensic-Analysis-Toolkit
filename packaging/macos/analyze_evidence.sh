#!/bin/bash
# Runs the full analysis on one piece of evidence and opens the HTML report. Called by the macOS app (Terminal window, so progress is visible).
# usage: analyze_evidence.sh <evidence path> <repo root>
set -u
EVIDENCE="$1"
REPO="$2"
CASES="$HOME/Documents/AndroidForensicsCases"
TOOL="$REPO/.venv/bin/android-forensics"
[ -x "$TOOL" ] || TOOL="$(command -v android-forensics || true)"
if [ -z "$TOOL" ]; then
  echo "android-forensics is not installed. In $REPO run:  python3 -m venv .venv && .venv/bin/pip install -e ."
  read -r -p "Press Return to close"; exit 1
fi
mkdir -p "$CASES"
NAME="$(basename "$EVIDENCE" | sed 's/[^A-Za-z0-9._-]/_/g')-$(date +%Y%m%d-%H%M%S)"
echo "Evidence : $EVIDENCE   (opened read-only; the original is never modified)"
echo "Case     : $CASES/$NAME"
echo
caffeinate -i "$TOOL" analyze "$EVIDENCE" --cases-dir "$CASES" --name "$NAME" --workers auto
STATUS=$?
REPORT="$(ls -td "$CASES/$NAME"/reports/*/report.html 2>/dev/null | head -1)"
echo
if [ $STATUS -eq 0 ] && [ -n "$REPORT" ]; then
  echo "Report: $REPORT"
  open "$REPORT"
else
  echo "Analysis did not complete (exit $STATUS) — see the messages above."
fi
read -r -p "Press Return to close"
