#!/bin/sh
# Test harness for ak_search. Runs each subcommand against fixtures/mini.trace
# and verifies JSONL output line counts + key fields. Exit 0 on success.
# (No set -e — grep -c returns 1 on zero matches and would abort the harness.)

cd "$(dirname "$0")/.."
BIN=./ak_search
FIXTURE=tests/fixtures/mini.trace

if [ ! -x "$BIN" ]; then
    echo "[setup] building ak_search..."
    make >/dev/null
fi

# pretty-print helpers
PASS=0
FAIL=0

assert_eq() {
    label="$1"; expected="$2"; actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  PASS  $label"
        PASS=$((PASS+1))
    else
        echo "  FAIL  $label"
        echo "        expected: $expected"
        echo "        actual:   $actual"
        FAIL=$((FAIL+1))
    fi
}

assert_contains() {
    label="$1"; needle="$2"; haystack="$3"
    if printf '%s' "$haystack" | grep -q -F -- "$needle"; then
        echo "  PASS  $label"
        PASS=$((PASS+1))
    else
        echo "  FAIL  $label  (missing: $needle)"
        echo "        haystack: $haystack"
        FAIL=$((FAIL+1))
    fi
}

# -----------------------------------------------------------------------------
echo "[test] existing: match (sanity — must not regress)"
out=$($BIN match --file "$FIXTURE" --query "eor" --from-line 1 --limit 10)
count=$(printf '%s\n' "$out" | grep -c '^{"type":"match"')
assert_eq "match finds 3 eor lines" "3" "$count"

# -----------------------------------------------------------------------------
echo "[test] existing: context (sanity)"
out=$($BIN context --file "$FIXTURE" --line 3 --before 1 --after 1)
count=$(printf '%s\n' "$out" | grep -c '^{"type":"context"')
assert_eq "context returns 3 lines" "3" "$count"

# -----------------------------------------------------------------------------
echo "[test] new: regflow"

# Track x0: should appear on lines 1 (=0x10) and 3 (=0x30)
out=$($BIN regflow --file "$FIXTURE" --reg x0 --from-line 1 --to-line 15 --limit 10)
count=$(printf '%s\n' "$out" | grep -c '^{"type":"regflow"')
assert_eq "regflow x0 emits 2 records" "2" "$count"
assert_contains "regflow x0 line 1 value=0x10" '"line":1' "$out"
assert_contains "regflow x0 line 3 value=0x30" '"line":3' "$out"
assert_contains "regflow x0 captures 0x10" '"value":"0x10"' "$out"
assert_contains "regflow x0 captures 0x30" '"value":"0x30"' "$out"

# Track x2 (line 4 sets to 0)
out=$($BIN regflow --file "$FIXTURE" --reg x2 --from-line 1 --to-line 15 --limit 10)
count=$(printf '%s\n' "$out" | grep -c '^{"type":"regflow"')
assert_eq "regflow x2 emits 1 record (line 4 zero)" "1" "$count"
assert_contains "regflow x2 line 4" '"line":4' "$out"
assert_contains "regflow x2 value 0x0" '"value":"0x0"' "$out"

# Track a register that's never an output → 0 records
out=$($BIN regflow --file "$FIXTURE" --reg x99 --from-line 1 --to-line 15 --limit 10)
count=$(printf '%s\n' "$out" | grep -c '^{"type"')
assert_eq "regflow on unused reg → 0" "0" "$count"

# -----------------------------------------------------------------------------
echo "[test] new: producer"

# Value 0xa1b2c3d4 is written on line 7 (ldr x7, ...)
out=$($BIN producer --file "$FIXTURE" --value 0xa1b2c3d4 --sink-line 10 --max-back 100)
count=$(printf '%s\n' "$out" | grep -c '^{"type":"producer"')
assert_eq "producer finds 1 hit" "1" "$count"
assert_contains "producer line=7" '"line":7' "$out"
assert_contains "producer reg=x7" '"reg":"x7"' "$out"

# Value 0x30 is written on line 3 (eor x0, x0, x1) → first hit reverse from line 8 is line 3
out=$($BIN producer --file "$FIXTURE" --value 0x30 --sink-line 8 --max-back 100)
assert_contains "producer 0x30 finds line 3" '"line":3' "$out"
assert_contains "producer 0x30 reg=x0" '"reg":"x0"' "$out"

# A value nobody writes → 0 records
out=$($BIN producer --file "$FIXTURE" --value 0xdeadc0de --sink-line 15 --max-back 100)
count=$(printf '%s\n' "$out" | grep -c '^{"type"')
assert_eq "producer nonexistent value → 0" "0" "$count"

# -----------------------------------------------------------------------------
echo "[test] new: semop classifications"

# Line 1: mov → data_move
out=$($BIN semop --file "$FIXTURE" --line 1)
assert_contains "L1 mov classified" '"class":"data_move"' "$out"

# Line 3: eor x0, x0, x1 (different regs) → crypto_candidate
out=$($BIN semop --file "$FIXTURE" --line 3)
assert_contains "L3 eor x0,x0,x1 → crypto_candidate" '"class":"crypto_candidate"' "$out"

# Line 4: eor x2, x2, x2 (all same) → zero
out=$($BIN semop --file "$FIXTURE" --line 4)
assert_contains "L4 eor x2,x2,x2 → zero" '"class":"zero"' "$out"

# Line 5: madd → hash_loop_candidate
out=$($BIN semop --file "$FIXTURE" --line 5)
assert_contains "L5 madd → hash_loop_candidate" '"class":"hash_loop_candidate"' "$out"

# Line 6: stp x29, x30 → stack_save
out=$($BIN semop --file "$FIXTURE" --line 6)
assert_contains "L6 stp x29,x30 → stack_save" '"class":"stack_save"' "$out"

# Line 7: ldr → memory_load
out=$($BIN semop --file "$FIXTURE" --line 7)
assert_contains "L7 ldr → memory_load" '"class":"memory_load"' "$out"

# Line 11: ldp x29, x30 → stack_restore
out=$($BIN semop --file "$FIXTURE" --line 11)
assert_contains "L11 ldp x29,x30 → stack_restore" '"class":"stack_restore"' "$out"

# Line 12: ret → branch
out=$($BIN semop --file "$FIXTURE" --line 12)
assert_contains "L12 ret → branch" '"class":"branch"' "$out"

# Line 13: bl → branch
out=$($BIN semop --file "$FIXTURE" --line 13)
assert_contains "L13 bl → branch" '"class":"branch"' "$out"

# Line 14: str → memory_store
out=$($BIN semop --file "$FIXTURE" --line 14)
assert_contains "L14 str → memory_store" '"class":"memory_store"' "$out"

# Line 15: adrp → addr_calc
out=$($BIN semop --file "$FIXTURE" --line 15)
assert_contains "L15 adrp → addr_calc" '"class":"addr_calc"' "$out"

# Range mode: limit 5 over the whole fixture
out=$($BIN semop --file "$FIXTURE" --from-line 1 --to-line 15 --limit 5)
count=$(printf '%s\n' "$out" | grep -c '^{"type":"semop"')
assert_eq "semop range respects limit=5" "5" "$count"

# -----------------------------------------------------------------------------
echo ""
echo "==================================================="
echo "  PASS=$PASS  FAIL=$FAIL"
echo "==================================================="
[ "$FAIL" -eq 0 ] || exit 1
