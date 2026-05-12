# ak_search

High-throughput trace-evidence engine for very large ARM64 trace files.

> **Forked + extended from**: [AlgoKiller/tools/search](https://github.com/lidongyooo/AlgoKiller/tree/main/tools/search) by [@lidongyooo](https://github.com/lidongyooo).
>
> **Upstream contributes**: the original `match` / `context` / `daemon` engine —— mmap + 1-based line index + ASCII case-insensitive BMH + tab-protocol daemon. Copyright on those code paths and the original `search.c` skeleton belongs to the upstream author.
>
> **This plugin extends with 11 new subcommands** for register-flow tracing, semantic classification, call-graph aggregation, hex-dump block parsing, cryptographic-constant fingerprinting (`constscan`), ARM Crypto Extensions hardware-instruction detection (`cryptoinstr`), byte-sequence search, lint, and trace folding. The plugin's contributions are MIT-licensed alongside the rest of `algokiller-plugin`.

---

## Why this directory exists

Source of the native engine, vendored into the plugin repo so non-arm64-macOS users can build their own `ak_search` binary without cloning the upstream repo separately.

- `./search.c`   — full source (single C11 translation unit, ~3.8 K lines)
- `./Makefile`   — minimal builder
- `./build.sh`   — thin wrapper around `make`
- `./tests/`     — POSIX-sh harness, 173 assertions across all subcommands, hand-crafted fixtures

The prebuilt runtime binary lives at [`../../server/bin/ak_search`](../../server/bin/ak_search) (arm64-macOS). The `tools/search/ak_search` produced by `make` here is a local build artifact and is git-ignored.

### Build for your platform

```bash
cd tools/search
make                              # produces ./ak_search
cp ak_search ../../server/bin/    # replace the prebuilt arm64 binary
chmod +x ../../server/bin/ak_search
./tests/run_tests.sh              # 173 PASS expected
```

The plugin auto-runs `chmod +x` + Gatekeeper xattr cleanup on `daemon.start()`. If you cross-compile or grab from CI, drop the binary at `server/bin/ak_search` and the plugin picks it up.

## Build flags

```makefile
CC      ?= cc
CFLAGS  ?= -O3 -std=c11 -Wall -Wextra -Wpedantic -pthread
LDFLAGS ?= -pthread
```

`-pthread` is required for the data-parallel `constscan` / `cryptoinstr` workers (no-op on macOS where pthread is in libSystem; links libpthread on Linux).

Override at command line:

```bash
make CC=clang CFLAGS='-O3 -march=native -std=c11 -pthread'
make CC=aarch64-linux-gnu-gcc          # cross-compile for Linux arm64
```

## CLI surface (14 subcommands)

### Upstream engine

```bash
ak_search match    --file PATH --query TEXT [--from-line N | --before-line N] [--limit N]
ak_search context  --file PATH --line N [--context N | --before N --after N]
ak_search daemon   --file PATH
```

`match` is ASCII case-insensitive BMH. `--before-line` searches backward, nearest first. `daemon` holds the mmap + line-index open and accepts tab-delimited `match` / `context` commands on stdin.

### Plugin extensions

```bash
ak_search regflow   --file PATH --reg xN [--from-line N] [--to-line N] [--limit N]
ak_search producer  --file PATH --value 0xVAL --sink-line N [--max-back N]
ak_search semop     --file PATH (--line N | --from-line N --to-line N) [--limit N]
ak_search lint      --file PATH [--top N]
ak_search fold      --in PATH --out PATH [--threshold N] [--block N]
ak_search callgraph --file PATH (--to NAME | --top N) [--limit N]
ak_search modgraph  --file PATH [--top N]
ak_search hexblock  --file PATH --line N [--max-lines N]
ak_search constscan   --file PATH [--samples N] [--threads N]
ak_search cryptoinstr --file PATH [--samples N] [--threads N]
ak_search bytes       --file PATH --query 0xVAL [--limit N] [--with-text]
```

| Subcommand | What it does | Sample real-trace cost (684 MB / 7.14 M lines) |
|---|---|---|
| `regflow`   | Emit value-write sequence of one register over a line range, parsing the `-> regN=0xVAL` portion. | ~28 ms per 100-line slice |
| `producer`  | Backward scan from `--sink-line` for the most recent `-> regN=0xVAL` matching the requested value. | ~28 ms per 50-line back-scan |
| `semop`     | Classify each instruction (`zero` / `crypto_candidate` / `hash_loop_candidate` / `stack_save|restore` / `memory_load|store` / `branch` / `addr_calc` / `data_move` / `alu` / `compare` / `unknown`). | linear, < 5 ms per row |
| `lint`      | Single-pass JSON health-check: line count, module distribution, top mnemonics, `call func:` / `hexdump` / `ret` counts, register/memory observation presence, format warnings. | 0.22 s |
| `fold`      | Write a derivative trace with repeated W-line blocks collapsed to first-block + sentinel + last-block. `--block 4 --threshold 100` collapses ARM64 4-instruction hash loops. | 0.09 s — 115 MB → 1.1 MB (99 %) on a production startup trace |
| `callgraph` | `--top N` Top-K most-called `call func:` symbols; `--to NAME` lists every call site of NAME. | 0.4 s |
| `modgraph`  | Cross-module transition matrix + per-module line counts + Top-K edges. | 0.45 s |
| `hexblock`  | Parse a `call func: NAME(args)` block at `--line` into structured JSON: call, args, optional ObjC class, optional hexdumps with concatenated `bytes_hex`, terminating `ret`. | 0.15 s |
| `constscan` | Scan for **97 curated cryptographic fingerprints** (95 scalar literals + 2 NEON SIMD broadcasts) across hash / cipher_sym / ecc / crc / mac: MD5 init+T-table, SHA-1, SHA-256 init+K-table, SHA-512, SM3 init+T_j round constants, SHA-3, CRC32, FNV-1a, AES sbox+Te0, SM4 sbox+FK+CK, ChaCha20, TEA, DES SP-box, Whirlpool, Poly1305, SipHash, **HMAC ipad/opad (scalar + `.16b, #0x36/0x5c` SIMD)**, P-256, secp256k1, Ed25519, Curve25519. Each scalar fingerprint (e.g. `MD5.T[1]`) fires **once per compression block** — `total_hits ≈ block count`; per-block fingerprints expose this directly via `block_count_estimate`. Each hit carries a `verdict` ∈ `real` / `real_simd` / `weak` / `alu_only` so ALU collisions are not mistaken for real signals. **Data-parallel**: line range is partitioned across worker threads (default = host CPU, max 16; override via `--threads N`); byte-identical output across thread counts. | ~11 s single-threaded → ~1.8 s with 8 threads on 684 MB / 7 M lines; scales to ~80 GB inputs within the 300 s MCP timeout |
| `cryptoinstr` | Scan for ARM Crypto Extensions hardware instructions: AES (aese/aesmc/aesd/aesimc), SHA-1 (sha1c/m/p/h/su0/su1), SHA-256 (sha256h/h2/su0/su1), SHA-512 (sha512h/h2/su0/su1), SHA-3 (eor3/rax1/xar/bcax), GHASH (pmull/pmull2), SM3 (sm3*), SM4 (sm4e/sm4ekey). Companion to `constscan` for hardware-accelerated crypto. Same data-parallel `--threads N` support. | 0.3 s (8 threads) |
| `bytes`     | Hex-literal search with automatic byte-reversed and leading-zero-stripped variants; default output is line + variant only (token-frugal). | 0.2 s |

## Output format

Every subcommand emits one JSON object per line:

```json
{"type":"match","line":42,"byte_offset":8192,"text":"..."}
{"type":"regflow","line":600000,"value":"0x2bab...","instr":"[Module] 0x... madd x9, ..."}
{"type":"producer","line":17,"reg":"x0","value":"0x11fbcded8","instr":"..."}
{"type":"semop","line":1,"mnem":"stp","class":"stack_save","operands":"x29, x30, [sp,#0x60]","instr":"..."}
{"type":"lint","size_bytes":...,"line_count":...,"top_modules":[...],"top_mnemonics":[...],"format_ok":true,"warnings":[]}
{"type":"hexblock","line":8871,"call":"__memcpy_aarch64_simd","args_raw":"...","hexdumps":[{"address":"0x...","length":"0x...","bytes_hex":"..."}],"ret":"0x..."}
{"type":"constscan","hits":[{"fingerprint":"MD5.A","category":"hash","magic":"0x67452301","total_hits":37,"sample_lines":[244787,244793]}]}
```

## Daemon protocol (upstream-compatible)

The MCP server drives the daemon for `match` / `context`. Extension subcommands (`regflow` / `producer` / `semop` / `lint` / `fold` / `callgraph` / `modgraph` / `hexblock` / `constscan` / `bytes`) currently spawn a fresh one-shot process — daemon integration is a planned follow-up.
