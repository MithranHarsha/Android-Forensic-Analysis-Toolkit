#!/usr/bin/env bash
# Run the full test-suite in Linux containers on several Python versions — a local stand-in for the CI matrix.
#
#   scripts/test_linux_matrix.sh                 # 3.11 3.12 3.13
#   scripts/test_linux_matrix.sh 3.12            # one version
#
# The working tree is streamed into the container with tar (no bind mount), the project is installed with its dev extras and
# pytest runs everything except the browser e2e tests (those need Playwright browsers; CI runs them in their own job).
# Requires Docker. Each version's tail output is printed; the script exits non-zero if any version fails.
set -u
versions=("$@")
[ ${#versions[@]} -eq 0 ] && versions=(3.11 3.12 3.13)
cd "$(dirname "$0")/.."
status=0
for v in "${versions[@]}"; do
  echo "=== Python $v"
  if ! tar --exclude=./.venv --exclude=./.git --exclude=./cases --exclude=./reports --exclude=./dist --exclude=./build --exclude=./site \
          --exclude='*.pdf' --exclude=./server-data --exclude=./.hypothesis --exclude=./.pytest_cache --exclude=./.mypy_cache \
          --exclude=./.ruff_cache -cf - . | docker run --rm -i "python:$v-slim" bash -c '
    set -e
    apt-get update -qq >/dev/null && apt-get install -y -qq git procps >/dev/null 2>&1
    mkdir /work && tar -xf - -C /work && cd /work && git init -q .
    pip install -q -e ".[dev]" 2>&1 | tail -2
    python -m pytest -q -p no:cacheprovider -p no:warnings --ignore=tests/e2e 2>&1 | tail -30
  '; then status=1; fi
done
exit $status
