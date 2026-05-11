# ak_search tests

Minimal regression harness for the C engine.

## Run

```bash
cd tools/search
./tests/run_tests.sh
```

Exits 0 on success, non-zero with PASS/FAIL counts on failure. No external test framework — pure POSIX sh + `grep`.

## What's covered

| Subcommand | Cases |
|---|---|
| `match`     | sanity (3 hits for "eor") — must not regress |
| `context`   | sanity (3 lines around target) |
| `regflow`   | output-value extraction, missing reg → 0 records, range walk |
| `producer`  | backward scan for value, matched reg name, nonexistent value → 0 |
| `semop`     | per-class spot-checks (zero / crypto_candidate / hash_loop_candidate / stack_save / stack_restore / memory_load / memory_store / branch / addr_calc / data_move / alu), range mode with limit |

29 assertions total. See `fixtures/mini.trace` (15 lines, hand-crafted to hit every classifier branch) for the gold-standard inputs.

## Adding new fixtures

Drop additional trace samples into `tests/fixtures/`. Keep them small (≤ 100 lines) — heavy regression against real captures lives outside this harness; this is for catching parser-level breakage.
