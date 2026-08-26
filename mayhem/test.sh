#!/usr/bin/env bash
#
# mayhem/test.sh — RUN Kuroko's own functional test suite (built by mayhem/build.sh
# step 1, the plain `make` oracle build). This is exactly upstream's own CI recipe
# (`make test` in .github/workflows/build.yml), reimplemented here so the counts can
# be mapped to CTRF: for each test/*.krk, run the freshly-built, DYNAMICALLY LINKED
# ./kuroko binary and diff its real stdout against the checked-in test/*.krk.expect
# golden file. This is a genuine behavioral oracle -- a neutered/no-op kuroko binary
# produces empty (or wrong) stdout, which mismatches nearly every non-trivial
# .expect file, so the LD_PRELOAD sabotage check (verify-repo.sh) fails this loudly.
#
# Do NOT build here -- mayhem/build.sh already compiled ./kuroko + modules/*.so with
# the project's normal (unsanitized) flags. This script only RUNS the pre-built
# binary and reports counts.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

[ -x ./kuroko ] || { echo "test.sh: ./kuroko missing -- build.sh should have produced it" >&2; emit_ctrf "kuroko-selftest" 0 1; exit 1; }

passed=0
failed=0
fail_list=()

shopt -s nullglob
tests=(test/*.krk)
shopt -u nullglob

if [ "${#tests[@]}" -eq 0 ]; then
  echo "test.sh: no test/*.krk found -- expected upstream's own suite to be present" >&2
  emit_ctrf "kuroko-selftest" 0 1
  exit 1
fi

for t in "${tests[@]}"; do
  expect="$t.expect"
  if [ ! -f "$expect" ]; then
    echo "test.sh: FAIL $t (no .expect golden file committed upstream)" >&2
    failed=$((failed+1))
    fail_list+=("$t: missing .expect")
    continue
  fi
  actual="$(mktemp)"
  KUROKO_TEST_ENV=1 ./kuroko "$t" > "$actual" 2>&1
  if diff -q "$expect" "$actual" > /dev/null 2>&1; then
    passed=$((passed+1))
  else
    failed=$((failed+1))
    fail_list+=("$t")
    echo "test.sh: FAIL $t (stdout differs from $expect)" >&2
  fi
  rm -f "$actual"
done

echo "test.sh: upstream test/*.krk suite: $passed passed, $failed failed (of ${#tests[@]})"
if [ "$failed" -gt 0 ]; then
  printf 'test.sh: failing scripts: %s\n' "${fail_list[*]}" >&2
fi

# ---------------------------------------------------------------------------
# A few direct known-answer probes on top of the diff suite, run straight
# through the same dynamically-linked ./kuroko via `-c` (bash/coreutils are
# whitelisted by the sabotage shim, so the comparison happens where sabotage
# cannot hide). Unconditional -- a missing/wrong value is a failure, not a skip.
# ---------------------------------------------------------------------------
kat_pass=0
kat_fail=0

check_kat() {
  local desc="$1" expr="$2" want="$3"
  local got
  got="$(./kuroko -c "$expr" 2>&1)"
  if [ "$got" = "$want" ]; then
    kat_pass=$((kat_pass+1))
  else
    kat_fail=$((kat_fail+1))
    echo "test.sh: KAT FAIL [$desc]: expr=<$expr> want=<$want> got=<$got>" >&2
  fi
}

check_kat "arithmetic"         'print(6 * 7)'                             '42'
check_kat "string-reverse"     'print("kuroko"[::-1])'                    'okoruk'
check_kat "list-comprehension" 'print([x*x for x in range(5)])'           '[0, 1, 4, 9, 16]'
check_kat "dict-sum"           'print(sum({"a":1,"b":2,"c":3}.values()))' '6'

echo "test.sh: KAT probes: $kat_pass passed, $kat_fail failed (of $((kat_pass+kat_fail)))"

total_passed=$((passed + kat_pass))
total_failed=$((failed + kat_fail))

emit_ctrf "kuroko-selftest" "$total_passed" "$total_failed"
