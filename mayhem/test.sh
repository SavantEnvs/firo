#!/usr/bin/env bash
#
# mayhem/test.sh — RUN firo's own libspark Boost.Test suites (built by mayhem/build.sh with normal flags).
# These are the real upstream src/libspark/test/*_test.cpp suites: proof completeness/soundness for
# schnorr, chaum, grootle, bpplus, owner/spend/mint transactions, AEAD, f4grumble, address and coin
# encodings. Every BOOST_CHECK is an asserted value, so a no-op/neutered program cannot pass.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/mayhem/build-test/libspark_tests"
[ -x "$RUNNER" ] || { echo "missing $RUNNER (mayhem/build.sh builds it)" >&2; exit 2; }

REPORT="$(mktemp)"
rm -f "$REPORT"
"$RUNNER" --log_format=JUNIT --log_sink="$REPORT" --log_level=all >/dev/null 2>&1
rc=$?

# The JUnit report is the only source of counts: a runner that exits early without producing it
# (e.g. a neutered binary) reports nothing and fails.
if [ ! -s "$REPORT" ]; then
  echo "no test report produced (runner exited rc=$rc)" >&2
  emit_ctrf "boost-test" 0 1 0
  exit 1
fi

read -r tests failures errors skipped < <(python3 - "$REPORT" <<'PY'
import sys, xml.etree.ElementTree as ET
r = ET.parse(sys.argv[1]).getroot()
print(r.get("tests", 0), r.get("failures", 0), r.get("errors", 0), r.get("skipped", 0))
PY
)
rm -f "$REPORT"

failed=$(( failures + errors ))
passed=$(( tests - failed - skipped ))
# upstream ships 54 libspark cases; far fewer means a suite silently dropped out.
if [ "$tests" -lt 50 ]; then failed=$(( failed + 1 )); echo "only $tests test cases ran (expected >= 50)" >&2; fi
[ "$rc" -eq 0 ] || failed=$(( failed + 1 ))
emit_ctrf "boost-test" "$passed" "$failed" "$skipped"
