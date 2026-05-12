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
echo "[test] new: lint"

out=$($BIN lint --file "$FIXTURE" --top 5)
count=$(printf '%s\n' "$out" | grep -c '^{"type":"lint"' || true)
assert_eq "lint emits 1 JSON object" "1" "$count"
assert_contains "lint reports 15 lines" '"line_count":15' "$out"
assert_contains "lint sees app_main module" '"name":"app_main"' "$out"
assert_contains "lint detects register obs" '"has_register_observations":true' "$out"
assert_contains "lint detects memory reads" '"has_memory_reads":true' "$out"
assert_contains "lint detects memory writes" '"has_memory_writes":true' "$out"
assert_contains "lint sees 1 call_func block" '"call_func_blocks":1' "$out"
assert_contains "lint format_ok=true" '"format_ok":true' "$out"
assert_contains "lint sees mov mnemonic" '"mnem":"mov"' "$out"
assert_contains "lint sees eor mnemonic" '"mnem":"eor"' "$out"

# lint on a non-GumTrace file (use the test script itself as a fake trace) → format_ok=false
out=$($BIN lint --file "tests/run_tests.sh")
assert_contains "lint flags non-GumTrace format" '"format_ok":false' "$out"
assert_contains "lint warns on non-GumTrace" "not GumTrace format" "$out"

# -----------------------------------------------------------------------------
echo "[test] new: fold"

FOLD_IN=tests/fixtures/fold-input.trace
FOLD_OUT=tests/fixtures/fold-output.trace

# fold-input: 1 unique mov, 11 identical madd lines, 1 unique ldr, then call/ret
# threshold=5 → the 11-line madd run collapses to first + sentinel + last (3 lines)
summary=$($BIN fold --in "$FOLD_IN" --out "$FOLD_OUT" --threshold 5)
assert_contains "fold reports 1 fold applied" '"folds_applied":1' "$summary"
assert_contains "fold reports 9 lines skipped" '"lines_skipped":9' "$summary"
assert_contains "fold reports threshold" '"threshold":5' "$summary"
assert_contains "fold reports original 15 lines" '"original_line_count":15' "$summary"

# Resulting file: 15 original - 11 madd + 3 (first+sentinel+last) = 7 lines
out_lines=$(wc -l < "$FOLD_OUT" | tr -d ' ')
assert_eq "fold-output has 7 lines" "7" "$out_lines"

# Sentinel comment must be present and reference the madd op
assert_contains "fold sentinel present" "ak_fold: skipped 9 identical lines" "$(cat $FOLD_OUT)"
assert_contains "fold sentinel mentions madd" 'op="madd x9, x9, x10, x11"' "$(cat $FOLD_OUT)"

# First line of the run is preserved (initial accumulator value)
assert_contains "fold preserves first run line" "x9=0x1 x10=0x83 x11=0x10 -> x9=0x93" "$(cat $FOLD_OUT)"
# Last line of the run is preserved (final accumulator value)
assert_contains "fold preserves last run line" "-> x9=0x2eb87b094c0a8c91" "$(cat $FOLD_OUT)"
# Non-instruction lines (call func / ret) are passed through verbatim
assert_contains "fold passes call func through" "call func: objc_retain" "$(cat $FOLD_OUT)"

# fold with high threshold should not collapse (run of 11 < 50)
summary=$($BIN fold --in "$FOLD_IN" --out "$FOLD_OUT" --threshold 50)
assert_contains "fold below threshold: 0 folds" '"folds_applied":0' "$summary"
out_lines=$(wc -l < "$FOLD_OUT" | tr -d ' ')
assert_eq "fold below threshold: no shrink (15 lines)" "15" "$out_lines"

rm -f "$FOLD_OUT"

# -----------------------------------------------------------------------------
echo "[test] new: fold --block 4 (DJB-style 4-instr loop)"

FOLD_BLOCK_IN=tests/fixtures/fold-block-input.trace
FOLD_BLOCK_OUT=tests/fixtures/fold-block-output.trace

# fold-block-input: 1 mov, then 5 iterations of a 4-instr loop (ldrsb / madd /
# subs / b.ne), then 1 ldr, then call/ret. Total 24 lines.
# With --block 4 --threshold 3, the 5 iterations should be detected (>=3) and
# folded into first-block + sentinel + last-block (= 4 + 1 + 4 = 9 lines).
# Output: 1 (mov) + 9 (fold) + 1 (ldr) + 2 (call/ret) = 13 lines.
summary=$($BIN fold --in "$FOLD_BLOCK_IN" --out "$FOLD_BLOCK_OUT" --threshold 3 --block 4)
assert_contains "block-fold reports 1 fold applied" '"folds_applied":1' "$summary"
assert_contains "block-fold reports window=4" '"window":4' "$summary"
assert_contains "block-fold skips 12 lines (3 middle reps * 4)" '"lines_skipped":12' "$summary"

out_lines=$(wc -l < "$FOLD_BLOCK_OUT" | tr -d ' ')
assert_eq "block-fold output has 13 lines" "13" "$out_lines"

assert_contains "block-fold sentinel mentions block_reps=5" "block_reps=5" "$(cat $FOLD_BLOCK_OUT)"
assert_contains "block-fold preserves first iteration ldrsb" "x9=0x182" "$(cat $FOLD_BLOCK_OUT)"
assert_contains "block-fold preserves last iteration final x9" "x9=0x1aa2f37d36" "$(cat $FOLD_BLOCK_OUT)"
assert_contains "block-fold passes ldr through" "0xa1b2c3d4" "$(cat $FOLD_BLOCK_OUT)"

# Threshold above repetitions → no fold
summary=$($BIN fold --in "$FOLD_BLOCK_IN" --out "$FOLD_BLOCK_OUT" --threshold 10 --block 4)
assert_contains "block-fold above threshold: 0 folds" '"folds_applied":0' "$summary"
out_lines=$(wc -l < "$FOLD_BLOCK_OUT" | tr -d ' ')
assert_eq "block-fold above threshold: 24 lines" "24" "$out_lines"

rm -f "$FOLD_BLOCK_OUT"

# -----------------------------------------------------------------------------
echo "[test] new: callgraph"

S34=tests/fixtures/sprint34.trace

# 4 call func lines in fixture: __memcpy / objc_retain / objc_msgSend / objc_msgSend... wait, we have 3.
# Lines: __memcpy_aarch64_simd, objc_retain, objc_msgSend
out=$($BIN callgraph --file "$S34" --top 10)
assert_contains "callgraph reports 3 total_calls" '"total_calls":3' "$out"
assert_contains "callgraph names __memcpy" '"name":"__memcpy_aarch64_simd"' "$out"
assert_contains "callgraph names objc_retain" '"name":"objc_retain"' "$out"
assert_contains "callgraph names objc_msgSend" '"name":"objc_msgSend"' "$out"

# xref --to filter
out=$($BIN callgraph --file "$S34" --to "objc_retain" --limit 10)
assert_contains "callgraph xref total_hits=1" '"total_hits":1' "$out"
count=$(printf '%s\n' "$out" | grep -c '"type":"callgraph_xref"' || true)
assert_eq "callgraph xref emits 1 row" "1" "$count"

# xref miss
out=$($BIN callgraph --file "$S34" --to "nonexistent_fn" --limit 10)
assert_contains "callgraph xref miss → 0 hits" '"total_hits":0' "$out"

# -----------------------------------------------------------------------------
echo "[test] new: modgraph"

out=$($BIN modgraph --file "$S34" --top 10)
assert_contains "modgraph sees app_main module" '"name":"app_main"' "$out"
assert_contains "modgraph sees lib_net module" '"name":"lib_net"' "$out"
# fixture: app_main → lib_net 1, lib_net → app_main 1 = 2 transitions
assert_contains "modgraph app_main→lib_net edge" '"from":"app_main","to":"lib_net"' "$out"
assert_contains "modgraph lib_net→app_main edge" '"from":"lib_net","to":"app_main"' "$out"
assert_contains "modgraph total_transitions=2" '"total_transitions":2' "$out"

# -----------------------------------------------------------------------------
echo "[test] new: hexblock"

# Find the __memcpy line in sprint34.trace
MEMCPY_LINE=$(grep -n "^call func: __memcpy" "$S34" | head -1 | cut -d: -f1)
out=$($BIN hexblock --file "$S34" --line "$MEMCPY_LINE")
assert_contains "hexblock parses __memcpy" '"call":"__memcpy_aarch64_simd"' "$out"
assert_contains "hexblock captures args" '"args_raw":"0x300001000, 0x400001000, 0x10"' "$out"
assert_contains "hexblock parses hexdump addr" '"address":"0x400001000"' "$out"
assert_contains "hexblock parses hexdump length" '"length":"0x10"' "$out"
assert_contains "hexblock captures hex bytes" '4142434445464748494a4b4c4d4e4f50' "$out"
assert_contains "hexblock captures ret" '"ret":"0x300001000"' "$out"

# Find an objc_retain line (has class : but no hexdump)
RETAIN_LINE=$(grep -n "^call func: objc_retain" "$S34" | head -1 | cut -d: -f1)
out=$($BIN hexblock --file "$S34" --line "$RETAIN_LINE")
assert_contains "hexblock objc_retain call" '"call":"objc_retain"' "$out"
assert_contains "hexblock objc_retain class" '"class":"NSDictionary"' "$out"
assert_contains "hexblock objc_retain ret" '"ret":"0x500000000"' "$out"

# Calling hexblock on a non-call line should error
err=$($BIN hexblock --file "$S34" --line 1 2>&1 >/dev/null || true)
assert_contains "hexblock rejects non-call line" "is not a 'call func:' line" "$err"

# -----------------------------------------------------------------------------
echo "[test] new: constscan"

out=$($BIN constscan --file "$S34" --samples 3)
assert_contains "constscan finds MD5.A" '"fingerprint":"MD5.A"' "$out"
assert_contains "constscan finds MD5.B" '"fingerprint":"MD5.B"' "$out"
assert_contains "constscan finds MD5.C" '"fingerprint":"MD5.C"' "$out"
assert_contains "constscan finds MD5.D" '"fingerprint":"MD5.D"' "$out"
assert_contains "constscan finds SHA256.h0" '"fingerprint":"SHA256.h0"' "$out"
assert_contains "constscan categories include hash" '"category":"hash"' "$out"

# A trace with no fingerprints should yield empty hits
out=$($BIN constscan --file "$FIXTURE" --samples 3)
assert_contains "constscan on mini.trace returns valid JSON" '"type":"constscan"' "$out"

# Sprint 5+ verdict tests
S5=tests/fixtures/sprint5-constscan.trace
out=$($BIN constscan --file "$S5" --samples 1)
assert_contains "constscan emits confidence field" '"confidence":' "$out"
assert_contains "constscan emits evidence breakdown" '"evidence":{"load_imm":' "$out"
assert_contains "constscan emits verdict field" '"verdict":' "$out"
assert_contains "fixture mov w16 #0x61707865 → load_imm" '"verdict":"real"' "$out"
assert_contains "ChaCha20 sigma category cipher_sym" '"category":"cipher_sym"' "$out"
assert_contains "Poly1305 category mac" '"category":"mac"' "$out"
assert_contains "P256.b_lo category ecc" '"category":"ecc"' "$out"
assert_contains "secp256k1.p_lo present" '"fingerprint":"secp256k1.p_lo"' "$out"
assert_contains "Ed25519.d_lo present" '"fingerprint":"Ed25519.d_lo"' "$out"
assert_contains "SipHash.k0 present" '"fingerprint":"SipHash.k0"' "$out"
# Verify the deleted BKDR.mul131 fingerprint really gone from output
count=$(printf '%s\n' "$out" | grep -c '"fingerprint":"BKDR.mul131"' || true)
assert_eq "BKDR.mul131 fingerprint removed (0 occurrences)" "0" "$count"

# v0.9.2 additions — 24 new round-constant / HMAC / DES fingerprints.
# Fixture exercises every new entry exactly once via load_imm (mov w?, #imm).
S92=tests/fixtures/v092-constscan.trace
out=$($BIN constscan --file "$S92" --samples 1)
# MD5 T table — loop-body constants (closes the IV-only blind spot for MD5)
assert_contains "v0.9.2 MD5.T[1] hit"         '"fingerprint":"MD5.T[1]"' "$out"
assert_contains "v0.9.2 MD5.T[2] hit"         '"fingerprint":"MD5.T[2]"' "$out"
assert_contains "v0.9.2 MD5.T[3] hit"         '"fingerprint":"MD5.T[3]"' "$out"
assert_contains "v0.9.2 MD5.T[4] hit"         '"fingerprint":"MD5.T[4]"' "$out"
# SHA-256 K table — loop-body constants (closes the IV-only blind spot for SHA-256)
assert_contains "v0.9.2 SHA256.K[0] hit"      '"fingerprint":"SHA256.K[0]"' "$out"
assert_contains "v0.9.2 SHA256.K[1] hit"      '"fingerprint":"SHA256.K[1]"' "$out"
assert_contains "v0.9.2 SHA256.K[7] hit"      '"fingerprint":"SHA256.K[7]"' "$out"
# SM3 round constants — T_j[0..15] vs T_j[16..63]
assert_contains "v0.9.2 SM3.T_j[0..15] hit"   '"fingerprint":"SM3.T_j[0..15]"' "$out"
assert_contains "v0.9.2 SM3.T_j[16..63] hit"  '"fingerprint":"SM3.T_j[16..63]"' "$out"
# HMAC ipad/opad — token-signing detection
assert_contains "v0.9.2 HMAC.ipad hit"        '"fingerprint":"HMAC.ipad"' "$out"
assert_contains "v0.9.2 HMAC.opad hit"        '"fingerprint":"HMAC.opad"' "$out"
# DES constants (imported trace-ui table, FP_WEAK pending real-trace verification)
assert_contains "v0.9.2 DES.const0 hit"       '"fingerprint":"DES.const0"' "$out"
assert_contains "v0.9.2 DES.sbox_word[0] hit" '"fingerprint":"DES.sbox_word[0]"' "$out"
# Verdict on the new round constants: load_imm → real
assert_contains "v0.9.2 new fingerprints classified real" '"verdict":"real"' "$out"

# -----------------------------------------------------------------------------
echo "[test] new: bytes"

out=$($BIN bytes --file "$S34" --query 0x67452301 --limit 5)
assert_contains "bytes finds MD5.A literal" '"variant":"0x67452301"' "$out"
assert_contains "bytes also tries byte-reversed" '"0x01234567"' "$out"

# Boundary check: 0x67452301 in mov w0 (full match)
count=$(printf '%s\n' "$out" | grep -c '"line":1' || true)
[ "$count" -ge 1 ] && { echo "  PASS  bytes hits line 1"; PASS=$((PASS+1)); } || { echo "  FAIL  bytes does not hit line 1"; FAIL=$((FAIL+1)); }

# bytes on a value that doesn't exist
out=$($BIN bytes --file "$S34" --query 0xfeedfacedeadbeef --limit 5)
count=$(printf '%s\n' "$out" | grep -c '"line":' || true)
assert_eq "bytes nonexistent → 0 hits" "0" "$count"

# bytes --with-text emits instr field
out=$($BIN bytes --file "$S34" --query 0xa1b2c3d4 --with-text --limit 3)
assert_contains "bytes --with-text emits instr" '"instr":' "$out"

# -----------------------------------------------------------------------------
echo "[test] new: cryptoinstr (ARM Crypto Extensions detection)"

S6=tests/fixtures/sprint6-cryptoinstr.trace
out=$($BIN cryptoinstr --file "$S6" --samples 2)
assert_contains "cryptoinstr emits type=cryptoinstr" '"type":"cryptoinstr"' "$out"

# fixture covers 8 primitives
for prim in AES SHA-1 SHA-256 SHA-512 SHA-3 GHASH SM3 SM4; do
    assert_contains "cryptoinstr detects $prim" "\"$prim\"" "$out"
done

# specific strong-confidence mnemonics
for mnem in aese aesmc sha256h sha512h sm3ss1 sm4e bcax xar; do
    assert_contains "cryptoinstr matches $mnem" "\"mnem\":\"$mnem\"" "$out"
done

assert_contains "cryptoinstr has confidence field" '"confidence":' "$out"
assert_contains "cryptoinstr has note field" '"note":' "$out"
assert_contains "cryptoinstr has primitives_present array" '"primitives_present":' "$out"

# pmull is medium (also generic GF mul)
assert_contains "pmull marked medium" '"mnem":"pmull","primitive":"GHASH","confidence":"medium"' "$out"

# eor3 is medium (also general 3-way XOR)
assert_contains "eor3 marked medium" '"mnem":"eor3","primitive":"SHA-3","confidence":"medium"' "$out"

# AES variants all strong
assert_contains "aese marked strong" '"mnem":"aese","primitive":"AES","confidence":"strong"' "$out"

# Non-crypto noise line should not trigger anything
out_noise=$($BIN cryptoinstr --file "$FIXTURE" --samples 2)
count=$(printf '%s\n' "$out_noise" | python3 -c "import json,sys; print(len(json.loads(sys.stdin.read())['hits']))")
assert_eq "cryptoinstr on mini.trace returns 0 hits" "0" "$count"

# -----------------------------------------------------------------------------
echo "[test] FIX F-16: hexblock call_kind + arc_warning (v0.9.6)"
ARC_FIXTURE=tests/fixtures/v096-arc-and-simd.trace

# ARC bookkeeping line (objc_retainAutoreleasedReturnValue at line ~21 in fixture)
arc_line=$(grep -n 'call func: objc_retainAutoreleasedReturnValue' "$ARC_FIXTURE" | head -1 | cut -d: -f1)
out_arc=$($BIN hexblock --file "$ARC_FIXTURE" --line "$arc_line")
assert_contains "ARC call tagged call_kind=arc_bookkeeping" '"call_kind":"arc_bookkeeping"' "$out_arc"
assert_contains "ARC block carries arc_warning" '"arc_warning":"call_kind=' "$out_arc"
assert_contains "arc_warning explains Frida-stalker side-effect" 'Frida-stalker side-effect' "$out_arc"

# Normal call (memcpy at the end of the fixture)
mc_line=$(grep -n 'call func: __memcpy_aarch64_simd' "$ARC_FIXTURE" | head -1 | cut -d: -f1)
out_mc=$($BIN hexblock --file "$ARC_FIXTURE" --line "$mc_line")
assert_contains "memcpy stays call_kind=normal" '"call_kind":"normal"' "$out_mc"
# Make sure arc_warning is NOT emitted on normal calls
warning_count=$(printf '%s' "$out_mc" | grep -c 'arc_warning')
assert_eq "memcpy has no arc_warning" "0" "$warning_count"

# -----------------------------------------------------------------------------
echo "[test] FIX F-17: constscan SIMD broadcast + per-block hint (v0.9.6)"
out_sc=$($BIN constscan --file "$ARC_FIXTURE")

# SIMD movi patterns appended as synthetic fingerprints
assert_contains "HMAC.ipad.simd_movi appended" '"fingerprint":"HMAC.ipad.simd_movi"' "$out_sc"
assert_contains "HMAC.opad.simd_movi appended" '"fingerprint":"HMAC.opad.simd_movi"' "$out_sc"
assert_contains "SIMD verdict labelled real_simd" '"verdict":"real_simd"' "$out_sc"
assert_contains "ipad match_pattern emitted" '"match_pattern":".16b, #0x36"' "$out_sc"
assert_contains "opad match_pattern emitted" '"match_pattern":".16b, #0x5c"' "$out_sc"

# Per-block hint attached to MD5.T[1] and SHA256.K[0]
md5t1=$(printf '%s' "$out_sc" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for h in d['hits']:
    if h['fingerprint']=='MD5.T[1]':
        print(json.dumps(h, separators=(',',':')));break
")
assert_contains "MD5.T[1] has block_count_estimate" '"block_count_estimate":1' "$md5t1"
assert_contains "MD5.T[1] primitive_for_blocks=MD5" '"primitive_for_blocks":"MD5"' "$md5t1"
assert_contains "MD5.T[1] block_count_note present" 'Do NOT divide by 4/16/64' "$md5t1"

sha256k0=$(printf '%s' "$out_sc" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for h in d['hits']:
    if h['fingerprint']=='SHA256.K[0]':
        print(json.dumps(h, separators=(',',':')));break
")
assert_contains "SHA256.K[0] has block_count_estimate" '"block_count_estimate":1' "$sha256k0"
assert_contains "SHA256.K[0] primitive=SHA-256" '"primitive_for_blocks":"SHA-256"' "$sha256k0"

# MD5.A (IV, not per-block) should NOT have block_count_estimate
md5a=$(printf '%s' "$out_sc" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for h in d['hits']:
    if h['fingerprint']=='MD5.A':
        print(json.dumps(h, separators=(',',':')));break
")
assert_eq "MD5.A (IV) has no block_count_estimate" "0" "$(printf '%s' "$md5a" | grep -c 'block_count_estimate')"

# Boundary check: .16b, #0x361 should NOT match HMAC.ipad.simd_movi
# (the fixture doesn't have such a line; confirm count is exactly 2 ipad hits)
ipad_total=$(printf '%s' "$out_sc" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for h in d['hits']:
    if h['fingerprint']=='HMAC.ipad.simd_movi':
        print(h['total_hits']);break
")
assert_eq "ipad total_hits exact (2 in fixture)" "2" "$ipad_total"

# -----------------------------------------------------------------------------
echo "[test] FIX F-18: parallel scan determinism (constscan / cryptoinstr)"
# --threads 1 vs --threads 4 must produce byte-identical JSON. Locks in the
# determinism invariant of the data-parallel constscan / cryptoinstr workers.
# If this ever fails, the merge step lost ordering (likely sample_lines).
PAR_FIXTURES="tests/fixtures/sprint34.trace tests/fixtures/v092-constscan.trace tests/fixtures/sprint5-constscan.trace tests/fixtures/v096-arc-and-simd.trace"
for F in $PAR_FIXTURES; do
    for SUB in constscan cryptoinstr; do
        s1=$($BIN $SUB --file "$F" --threads 1 2>/dev/null)
        s4=$($BIN $SUB --file "$F" --threads 4 2>/dev/null)
        if [ "$s1" = "$s4" ]; then
            echo "  PASS  $SUB $(basename $F): --threads 1 == --threads 4"
            PASS=$((PASS+1))
        else
            echo "  FAIL  $SUB $(basename $F): --threads 1 != --threads 4"
            echo "        single: $s1" | head -c 400
            echo "        eight : $s4" | head -c 400
            FAIL=$((FAIL+1))
        fi
    done
done

# Bad --threads values must be rejected.
out_bad=$($BIN constscan --file tests/fixtures/sprint34.trace --threads 0 2>&1)
rc=$?
if [ $rc -ne 0 ] && echo "$out_bad" | grep -q "invalid --threads"; then
    echo "  PASS  --threads 0 rejected"; PASS=$((PASS+1))
else
    echo "  FAIL  --threads 0 should be rejected (rc=$rc)"; FAIL=$((FAIL+1))
fi
out_bad=$($BIN cryptoinstr --file tests/fixtures/sprint34.trace --threads 100 2>&1)
rc=$?
if [ $rc -ne 0 ] && echo "$out_bad" | grep -q "invalid --threads"; then
    echo "  PASS  --threads 100 rejected (cap=64)"; PASS=$((PASS+1))
else
    echo "  FAIL  --threads 100 should be rejected (rc=$rc)"; FAIL=$((FAIL+1))
fi

echo ""
echo "==================================================="
echo "  PASS=$PASS  FAIL=$FAIL"
echo "==================================================="
[ "$FAIL" -eq 0 ] || exit 1
