#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m compileall -q .
python3 -m unittest discover -s tools/tests -p 'test_*.py'
python3 tools/workflow.py sync-index --check
python3 tools/workflow.py render-issues --check
python3 tools/workflow.py doctor
