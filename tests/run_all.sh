#!/usr/bin/env bash
# Runs every test script from the repo root. Needs: pip install -r tests/requirements.txt
set -u; cd "$(dirname "$0")/.."; rc=0
for t in test_engine test_parsers test_tables test_app; do
  echo "== $t"; PYTHONPATH=. python3 "tests/$t.py" 2>&1 | grep -E "^(FAIL|ALL PASS|ALL MATCH|SOME FAILED)|MISMATCH|Traceback|ALL MATCH" ; [ "${PIPESTATUS[0]}" -eq 0 ] || rc=1
done
exit $rc
