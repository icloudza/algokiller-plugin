# Changelog

All notable changes to **algokiller-plugin** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.5.1] — Audit-driven patch: ARC tagging, SIMD detection, multithreaded scan, skill hygiene

Versioning note: this release uses the 4-segment `0.9.5.x` patch scheme.
The work is substantial (3 FIX numbers, new C-engine features, new MCP
fields, fully parallel scan workers) but is conceptually a **patch** of
the 0.9.5 release — every change traces back to gaps surfaced by a real
external audit of the v0.9.5 toolchain on a 4.5 GB XHS register-di
trace. The MINOR position (0.9.6) is reserved for net-new feature
batches that are not audit remediation.

### Added

- Cursor/Codex MCP client setup docs in `docs/mcp-clients.md`.
- Project-scoped Cursor MCP config at `.cursor/mcp.json`.
- Codex MCP config example at `examples/mcp/codex.config.toml`.
- **FIX F-16 (hexblock ARC-bookkeeping detection) — full-stack.**
  Fix lives at every layer that touches `trace_hexblock` output, so a
  CLI user calling `ak_search hexblock` raw gets the same protection
  as an MCP agent.
  - **C engine (`tools/search/search.c`):** `run_hexblock` now emits a
    `"call_kind"` field (`"arc_bookkeeping"` or `"normal"`) computed
    against an explicit prefix table (`ARC_BOOKKEEPING_PREFIXES`:
    `objc_retain*`, `objc_autorelease*`, `objc_release`,
    `swift_retain`, `swift_release`, `swift_bridgeObject*`,
    `_Block_copy/release`). When `call_kind="arc_bookkeeping"` AND
    the block carries one or more hexdumps, the JSON also includes an
    `"arc_warning"` field stating the buffer is a Frida-stalker
    side-effect dump of the receiver, not an algorithmic input.
  - **MCP wrapper (`server/tools/handlers.py`):** detects whether the
    C engine already set `call_kind` / `arc_warning`; if so, passes
    them through verbatim. Falls back to the Python classifier when
    running against an older binary. Always lifts `arc_warning` into
    `result.instruction` so the discipline-reminder path surfaces it.
  - **Skill docs:** new "证据陷阱清单 (v0.9.6)" subsection in
    `skills/trace-analysis/SKILL.md` documents the pitfall, and
    `skills/ciphertext-recovery/SKILL.md`'s `trace_hexblock` bullet
    references `call_kind`. The "工具使用规则" subsection adds a
    must-read rule on `call_kind` interpretation.
  - **Background:** real-world trace audit (XHS iOS register-di,
    4.5 GB / 48 M lines) showed an agent reading three consecutive
    same-address-same-length hexdumps from an ARC triplet and
    concluding the payload was fed into three independent HMAC
    contexts — when in fact only one `dataWithJSONObject:` call ever
    ran on that buffer. F-16 closes the gap at C, MCP, and methodology
    levels simultaneously so the misread is impossible regardless of
    entry point.
- **FIX F-18 (data-parallel scan in ak_search).** `constscan` and
  `cryptoinstr` partition the trace line range across worker threads
  (default = host CPU count, capped at 16; overridable via
  `--threads N` / MCP `threads` param). The mmap'd buffer and line
  index are shared read-only; each worker writes into a thread-local
  result struct; the main thread merges counters (commutative) and
  sample_lines (sorted multiset → take first K in line order) so the
  output is byte-identical between any thread count.
  - **Why "speed and accuracy":** on a 4.5 GB / 48 M-line trace
    `constscan` went from 121 s single-threaded → 19 s with 8 threads
    (≈ 6.3× wall-clock). The Python wrapper's 300 s timeout was the
    real accuracy hit before — single-threaded constscan on a 10 GB+
    trace would hit it, producing a truncated result that read as
    "no crypto detected" to the agent. With F-18 the same scan
    handles ~80 GB inputs inside the timeout.
  - **Determinism is locked in** by 10 new native tests
    (`sprint34.trace`, `v092-constscan.trace`, `sprint5-constscan.trace`,
    `v096-arc-and-simd.trace` × `constscan` + `cryptoinstr`, plus
    `--threads 0` / `--threads 100` rejection cases). The same
    invariant holds against the real 4.5 GB XHS trace.
  - C source touched: `tools/search/search.c` only (added pthread
    include, `detect_default_threads`, `partition_line_range`,
    `u64_cmp_asc`, worker types `ConstscanWork` / `CryptoinstrWork`,
    rewrote `run_constscan` / `run_cryptoinstr` to spawn + merge).
    `tools/search/Makefile` gains `-pthread` (no-op on macOS, links
    libpthread on Linux). Single-source compile preserved.

- **FIX F-17 (constscan SIMD broadcast detection + per-block hint) —
  full-stack.** Same layering as F-16.
  - **C engine:** new `InstructionPattern` table (substring matches on
    disassembly text, not on `-> reg=MAGIC` output values) with
    `HMAC.ipad.simd_movi` / `HMAC.opad.simd_movi` patterns. Each hit
    emits `verdict="real_simd"`, `match_pattern=".16b, #0x36/0x5c"`,
    `primitive="HMAC.ipad/opad"`, and an `interpretation` field.
    Per-block fingerprints (`MD5.T[i]`, `SHA256.K[i]`,
    `SM3.T_j[*]`) now also emit `block_count_estimate`,
    `primitive_for_blocks`, and a `block_count_note` directly from
    `run_constscan`.
  - **MCP wrapper:** treats C-engine output as primary, builds
    `hmac_estimate` (cross-references SIMD count against scalar
    `evidence.mem_r` / `load_imm`) and `block_count_hints` summaries
    on top. When the binary is older and emits no SIMD rows, the
    wrapper still does the daemon-side match scan as a fallback so
    MCP behaviour is consistent across binary versions.
  - **Skill docs:** the new "证据陷阱清单" subsection has dedicated
    bullets for SIMD-vs-scalar HMAC counting and for per-block table
    constants ("`MD5.T[1]=114` → 114 blocks, NOT 28 blocks"); the
    ciphertext-recovery skill's HMAC row in the "已识别 → 直接深挖
    的算法" table is rewritten to point at `simd_movi` as the
    primary signal.
  - **Background:** XHS audit predicted 44 HMAC ops from a 710-hit
    scalar `HMAC.ipad` count; the actual SIMD count is 11 (matches
    independent rmcp engine cross-check). The same audit divided
    `MD5.T[1]=114` by 4 to get "28 blocks ≈ 1.8 KB" — the correct
    answer is 114 blocks ≈ 7 KB.

### Changed

- Aligned marketplace metadata with v0.9.5: 25 MCP tools, 95 crypto
  fingerprints, and 14 native `ak_search` subcommands.
- Updated stale native test-count references from 132 to 163.
- E2E test suite: 14 → 20 cases (`TestF16ArcBookkeepingHexblock` ×2 +
  `TestF17ConstscanSimdAugmentation` ×4) backed by new fixture
  `tools/search/tests/fixtures/v096-arc-and-simd.trace`.
- Native shell test suite: 146 → 163 cases (added F-16 `call_kind` /
  `arc_warning` assertions and F-17 SIMD-pattern / block-count-hint
  assertions, both running directly against the C engine without the
  Python wrapper to verify end-to-end coverage).

## [0.9.5] — Full VM reversal methodology in ciphertext-recovery SKILL

`skills/ciphertext-recovery/SKILL.md` previously had a one-paragraph
treatment of VMP / 自研 VM with a "bypass via IO-buffer semantic ops"
strategy. The bypass strategy is correct as the **default** path for
most VMP tasks. But the SKILL had no guidance for the cases where:

- The user explicitly asks for a complete byte-code → executable
  Python decoder, OR
- The bypass path deadlocks because the IO buffer's intermediate state
  lives entirely inside the VM context (invisible to trace).

Without a structured methodology for these escalation cases, the agent
would either give up or, worse, ship a half-reversed "decoder" with
fabricated handler semantics. VMP reversal is a brittle workflow —
one wrong bit in the opcode bit-field decode produces 100+ lines of
plausible-looking but semantically false listing.

### Added — `完整 VM 还原 4 阶段流程` section (+140 lines)

Four explicit stages with **strict brittleness gates** at every transition:

| Stage | Purpose | Gate |
|---|---|---|
| **A. VMP 识别** | confirm it's actually a VM(P), not OLLVM-fla / heavy obfuscation | 3 necessary conditions (high-frequency dispatcher + computed-goto + persistent VM context register), all must ✓ |
| **B. opcode schema 推导** | determine word size / endianness / bit field / encoding state / PC stride | 100-opcode frequency distribution check + multi-handler hit check + no "ghost opcode" — **99% pass does NOT pass; needs 100%** |
| **C. 单 handler 迭代反编译** | reverse each VM handler with round-trip emulation | per-handler hypothesis_add → conclude with `falsification_evidence` proving Python emulator output = trace mem_w output |
| **D. 业务级闭环验证** | bit-for-bit business-level output match | 3 levels (instruction / block / business) all must pass with 100% / 100% / bit-for-bit |

### Anti-hallucination scaffold wiring

Every stage explicitly invokes the v0.9.0–v0.9.3 scaffold:

- Stage B schema hypothesis MUST conclude with `falsification_evidence`
  (FIX #5) — schema verified against 100-opcode round-trip.
- Stage C every handler hypothesis MUST round-trip vs trace mem_w output.
  Handler count > 30 → **mandatory `hypothesis-reviewer` audit** every
  10 handlers (FIX #6 hard gate).
- Stages chain via `depends_on` — Stage A abandon cascades to B/C/D
  (FIX #4 abandon-cascade); Stage B abandon cascades to C/D; etc.
- Stage D business-level pass → `write_artifact` `[H<n>]` citations link
  the whole chain (FIX #7 — non-load-bearing handlers can be
  `hypothesis_archive`d).
- v0.9.3 high-confidence tier marker gate enforces "complete decoder"
  language can ONLY appear when Stage D bit-for-bit passes.

### Explicit "不可自动化" boundary

Four scenarios are now documented as out-of-scope for pure-trace +
algokiller workflow:

- Encrypted opcode with runtime-decrypted key
- Self-modifying opcode stream
- VM-internal state-integrity checks
- JIT-style runtime native code emission (this is JIT, NOT VMP)

In these cases the SKILL mandates that the agent either record the
blocker as `contradicting` evidence (FIX #2 contradiction pressure
auto-caps confidence at low) or call `hypothesis_abandon` on the full
VM-reversal track. "Half-decoder is 10× more misleading than 'I can't
see it' is" — written into the SKILL verbatim.

### Why this is its own release, not a v0.9.4 amendment

- Adds a new behavioural path the agent didn't have before (full
  reversal vs bypass) — large enough to deserve a version of its own.
- Server / handlers / schemas / gates unchanged. Plugin will function
  identically v0.9.4 vs v0.9.5 at the API level; the difference is
  agent-visible methodology only.

### Tests

- No engine changes → native 146/146 PASS unchanged.
- No handler changes → Python 83/83 PASS unchanged.

## [0.9.4] — Brand hygiene: strip app-specific names from skill / code / fixtures

algokiller's mission is **algorithm-domain-agnostic** trace analysis ——
"秒杀一切算法", not "reverse a specific app". Prior releases accidentally
embedded specific app/product names (TikTok / WeChat / libmetasec / X-Sign
header families / `抖音/微信/支付宝/淘宝/京东` SDK list / `mmcronet` /
`trace_1009_main.log`) into SKILL docs, code comments, MCP schema
descriptions, test fixtures, and discipline reminders.

This is a real anti-hallucination concern: when the AI agent loads an
algokiller skill and sees brand-specific exemplars, it biases prior
toward that brand's tech stack — exactly the hallucination vector
FIX#1-#7 are built to suppress. Brand contamination in skill text =
priming the agent for false positives on any unrelated trace.

### Changed — generic identifiers across the board

| Surface | Before | After |
|---|---|---|
| SKILL.md modgraph examples | `WeChat ↔ mmcronet / libmetasec ↔ libc++` | `app_main ↔ lib_net / target_sign ↔ libc++` |
| SKILL.md fold example | `WeChat 启动 trace 实测 115MB → 1.1MB` | `大型移动应用启动 trace 实测 115MB → 1.1MB` |
| SKILL.md constscan example | `wechat TEA delta 28 命中` | `ARM64 trace TEA delta 28 命中` |
| SKILL.md VM detection list | `抖音/微信/支付宝/淘宝/京东` | `大型应用厂商自研 VM (各家社交/支付/电商客户端)` |
| SKILL.md table row | `看 WeChat 调没调 mmcronet` | `看主模块调没调子模块` |
| Server comments | `real TikTok trace audit on trace_1009_main.log` | `real-world large-trace audit (684 MB / 7.1M-line production ARM64 trace)` |
| schemas.py modgraph desc | `WeChat <-> mmcronet` | `app_main <-> lib_net` |
| schemas.py fold desc | `Real WeChat startup trace` | `Real production startup trace` |
| search.c GumTrace example | `[WeChat]` | `[Module]` |
| tools/search/README.md | `WeChat startup trace` | `a production startup trace` |
| Test fixtures (5 .trace files) | `[WeChat]` / `[mmcronet]` | `[app_main]` / `[lib_net]` |
| Test assertions (4 lines) | mentions of `WeChat` / `mmcronet` | `app_main` / `lib_net` |

### Changed — CHANGELOG narrative softened

v0.9.3 entry's "TikTok / libmetasec / trace_1009_main.log" references
generalised to "real-world large-trace audit (684 MB / 7.1M-line
production ARM64 trace)". The specific brand provided the empirical
ground truth for the gap-1 fix; the gap-1 fix itself is brand-agnostic
and should be documented that way going forward.

v0.9.2 entry's `WeChat-style X-Sign / X-Token` softened to generic
"API-auth signing header reverse-engineering target".

### Notes

- Git commit messages preceding this release contain the original
  brand references and are NOT rewritten — rewriting public history
  would force-push downstream consumers and is not worth the
  blast-radius.
- Going forward, **no new commit / SKILL / comment / schema description
  / test fixture may introduce specific app or product names**. Use
  generic identifiers (`app_main`, `lib_net`, `target_sign`, "production
  trace", "large internet app SDK") in their place.
- Native tests: 146 PASS (unchanged after fixture rename).
- Python tests: 83 PASS (unchanged).

## [0.9.3] — Close general-mode ledger bypass (real-world large-trace audit gap 1)

The first real-world production run of algokiller (a 684 MB / 7.1M-line
production ARM64 trace) shipped two analysis reports and surfaced a
hole the v0.9.0/v0.9.1 anti-hallucination scaffold could not close on
its own:

> The general-mode artifact contained 7+ "高置信推断" / "high-confidence
> inference" tier claims (signature pipeline order, AES mode, hash
> object semantics, MD5 sentinel interpretation) with **zero `[H<n>]`
> ledger backing**. The agent never called `hypothesis_add`, so the
> existing "concluded but unreferenced" gate didn't trigger. The skill
> doc said "general 模式不强制走 Hypothesis Ledger" — agent obeyed
> literally and bypassed the entire FIX#1-#7 layer.

### Added — High-confidence tier marker gate

- **`HypothesisLedger.HIGH_CONFIDENCE_TIER_MARKERS`** — explicit list of
  tier label phrases (`高置信推断`, `高置信`, `high-confidence
  inference`, `high-confidence`, `high confidence`) that signal a
  cross-evidence-synthesis claim, not a raw observation.
- **`HypothesisLedger._detect_high_confidence_tier(content)`** —
  case-insensitive substring scan. Returned in
  `validate_artifact_references()` as `high_confidence_markers_found`.
- **`tool_write_artifact` new hard gate** — if `len(content) > 200` and
  any marker is found and no `[H<n>]` is cited, rejected with explicit
  instruction listing the markers and the two remediation paths
  (run the ledger loop OR downgrade the tier label).
- **General-mode discipline reminder** — added to
  `GENERAL_SHORT_REMINDERS` so the agent learns the protocol before
  hitting the gate.

### Why marker-based, not catch-all

Deliberately narrow: the gate fires only on **explicit tier labels**,
not incidental occurrences of `confirmed` / `确认` / `结论`. Reports
that only contain observation-tier (`已确认`) and tentative-tier
(`推断`) language are unaffected. The point is to enforce discipline
on the *claim tier the agent itself chose to label* — agents who never
type the high-confidence label can still ship narratives, they just
forfeit the tier-signal in their deliverable.

### Skill doc rewrite

`skills/trace-analysis/SKILL.md` now carries a v0.9.3 "Hypothesis
Ledger 使用纪律" section spelling out the three-tier model:

| 档位 | 是否要 [H<n>] | 例 |
|---|---|---|
| 已确认 (wire boundary confirmed) | 否 | line 8872 hexdump 4192 字节 = HTTP header |
| 高置信推断 (high-confidence inference) | **是** | binary 在做 SM3 主压缩循环 |
| 推断 / 猜测 (inference / hypothesis) | 推荐 | AES 模式可能是 CBC (open thread) |

The old "general 模式不强制" wording is deleted.

### Tests

- `tests/python/test_hypothesis.py` — 8 new assertions across two new
  test classes (`TestHighConfidenceTierGate`,
  `TestWriteArtifactHighConfGate`):
  - Empty content / observation-only content: no marker, no rejection.
  - Chinese marker detected (`高置信推断`).
  - English marker detected case-insensitively
    (`High-Confidence Inference`).
  - Mixed zh+en markers both flagged.
  - Marker + `[H<n>]` citation → passes.
  - Marker + empty ledger + no citation → rejected (the real-trace
    audit case).
  - No marker + empty ledger → ships (observation-only artifacts work).
  - Marker + valid `[H<n>]` from full hypothesis_add → conclude loop →
    ships (the happy path).
- Python test count: 75 → 83.
- Native tests unchanged at 146 PASS (no C engine work).

### Notes — what this does NOT address

The 0.9.3 batch is **deliberately scoped to gap 1** (general-mode
bypass). The C-engine deferred items (F-4 adrp+ldr / F-6 hexblock
nested depth / F-9 fold samples_per_fold / F-15 hexblock direction /
A-3 daemon extcall) are now **rebadged 0.9.4** — they require deeper
work and warrant their own focused release. Real-iOS-trace sample
collection (to validate F-4) is still the prerequisite gate for that
release.

## [0.9.2] — Loop-body crypto constants + trace-ui borrowed algorithms

Comparative analysis against [imj01y/trace-ui](https://github.com/imj01y/trace-ui)
surfaced a fundamental scan-strategy gap in algokiller's v0.5-v0.9.1
`constscan`:

> Pre-v0.9.2 the fingerprint table biased toward INIT-time constants
> (IVs, state vectors, sigma, FK). The init constants appear ONCE per
> algorithm run; the loop-body constants (MD5 T-table, SHA-256 K-table,
> SM3 T_j) are referenced 64× per block compression. Active-hash traces
> were therefore matched on the lowest-density signal possible — and on
> short traces or hardened binaries the IV would miss entirely while
> the loop-body constants were sitting right there unscanned.

This release closes that strategy gap.

### Added — 24 new fingerprints (71 → 95)

- **MD5.T[1..4]** (RFC 1321 §3.4): `0xd76aa478` `0xe8c7b756`
  `0x242070db` `0xc1bdceee`. T-table = floor(|sin(i)| * 2^32) — hit
  64× per block compression vs A/B/C/D IVs which hit once.
- **SHA-256.K[0..7]** (FIPS 180-4 §4.2.2): `0x428a2f98` `0x71374491`
  `0xb5c0fbcf` `0xe9b5dba5` `0x3956c25b` `0x59f111f1` `0x923f82a4`
  `0xab1c5ed5`. K[0..63] are first 32 bits of cube roots of first 64
  primes; loaded 64× per block compression.
- **SM3.T_j[0..15]** = `0x79cc4519`, **SM3.T_j[16..63]** = `0x7a879d8a`
  (GM/T 0004-2012 §5.4). Two round constants covering all 64 rounds.
- **HMAC.ipad** = `0x36363636`, **HMAC.opad** = `0x5c5c5c5c`
  (RFC 2104 §2). Token-signing / API-auth signal — high-value for the
  API-auth signing header reverse-engineering target.
- **DES** (FIPS 46-3) — `DES.const0` / `const1` / `shifted0` /
  `shifted1` + `DES.sbox_word[0..3]`. Imported from trace-ui's 28-magic
  table; marked **FP_WEAK** (const0/const1/shifted0/shifted1) and
  **FP_MEDIUM** (sbox_word) pending independent verification on a real
  DES trace. Comment in the C table explicitly says: corroborate with
  `bl/blr` to `des_*` / `3des` / `triple_des` call symbols before
  naming DES as the algorithm.

### Added — Native test coverage

- `tools/search/tests/fixtures/v092-constscan.trace` — 24-line
  synthetic trace exercising every new fingerprint via `mov w?, #imm`
  (load_imm verdict path). Locks each new entry against schema drift.
- `tools/search/tests/run_tests.sh` — 14 new `assert_contains`
  assertions for the v0.9.2 batch. Native test count 132 → **146 PASS**
  (0 FAIL).

### Notes — What was NOT borrowed from trace-ui

trace-ui ships 28 algorithm-name buckets vs algokiller's 95-entry
classified fingerprint table. The other 5 algorithms trace-ui covers
(Twofish / Blowfish / RC6 / Camellia / Serpent / Threefish) are
**deferred to 0.9.3+** pending real-sample demand — the China-internet
SDK landscape this plugin targets rarely uses these.

trace-ui's parallel chunked scan + disk cache is a real performance
win on multi-GB traces but is **deferred to 0.9.4+**: it's a
performance optimisation, not a correctness one, and the Tool
Reliability First pivot from v0.9.1 still applies.

trace-ui does NOT have:

- Per-hit `verdict` classification (real / weak / alu_only — the
  algokiller v0.5 contribution that catches ALU collisions like
  `0x9e3779b9 = TEA delta + TEA delta`).
- `category` taxonomy or `confidence` levels.
- ARM Crypto Extensions HW instruction scan (`trace_cryptoinstr`).
- Endian variant exploration (`trace_bytes`).
- Co-occurrence corroboration verdict (FIX F-5 in v0.9.1).
- Hypothesis Ledger anti-hallucination scaffold.

algokiller is keeping all of those.

### Changed

- Plugin version: `0.9.1` → `0.9.2`.
- README.md / README.en.md / tools/search/README.md /
  skills/ciphertext-recovery/SKILL.md — fingerprint count 71 → 95;
  native test count 132 → 146.

### Deferred — unchanged from v0.9.1

The original v0.9.1 deferred items (F-4 constscan adrp+ldr,
F-6 hexblock nested depth, F-9 fold samples_per_fold, F-15 hexblock
direction, A-3 daemon extcall) are now **rebadged 0.9.3** — they
require deeper C-engine work than v0.9.2's table additions and
warrant their own focused release.

## [0.9.1] — Anti-hallucination layer 4 + tool-semantics correction batch

External 29-point code-review surfaced two damaging gaps that the
v0.8.x / v0.9.0 anti-hallucination scaffold could not close on its own:

1. The `falsification_attempted=true` boolean self-report could be set
   without ever running the experiment, vacating FIX #1's verbatim
   grounding on the high-confidence path.
2. The `hypothesis-reviewer` sub-agent (v0.9.0) was a documentation-only
   constraint — main agents could skip spawning it and still reach
   `conclude(high)`.

And 12+ tool-semantics issues where the engine returned data the agent
systematically misread (silent fallback / observation emits / first+last
fold / substring vs exact callgraph match / etc).

### Added — Hypothesis Ledger v3 (server-side hard gates)

- **FIX #5 — `falsification_evidence`**. `hypothesis_update` accepts a
  new `falsification_evidence={tool_call_id, excerpt}` object. The
  excerpt is verbatim-checked through the same FIX #1 anchor, and the
  `tool_call_id` must be *greater than* the hypothesis's
  `created_at_tool_call` (experiment must run *after* the hypothesis was
  formed). `conclude(high)` now requires this evidence; boolean
  `falsification_attempted=true` alone is rejected.
- **FIX #6 — `mark_hypothesis_reviewed` hard gate**. New MCP tool the
  `hypothesis-reviewer` sub-agent calls after auditing a hypothesis.
  `conclude(high)` rejects hypotheses without a recent (within 30 tool
  calls) `verdict="confirm"` record. Closes the documentation-soft hole
  from v0.9.0.
- **FIX #7 — `hypothesis_archive`**. New state `archived` for concluded
  hypotheses that turn out not to be load-bearing for the deliverable.
  Removes the reverse-prompt-injection failure where agents were forced
  to either cite irrelevant `[H<id>]`s or have `conclude(high)` rejected.

### Added — Per-tool semantic correctness (Python-side wrappers)

- **F-1 `trace_search`**: removed silent byte-reversed / leading-zero-
  stripped fallback that was attributing reversed-endian hits to the
  original query. Zero-hit 0x-queries now return a `hint` pointing at
  `trace_bytes` (which exposes per-variant counts explicitly).
- **F-2 `trace_producer`**: added `target_reg` parameter (surfaces
  register mismatches instead of silently returning a misleading row)
  and `min_hex_length` (default 4 — protects against `0x0`/`0x1`/`0xff`
  collisions with thousands of unrelated writes).
- **F-3 `trace_regflow`**: rows now classified as `write` / `observation`
  / `unclassified` via mnemonic taxonomy. `cmp`/`tst`/`cbz`/`bl`/`ret`
  emits (where GumTrace records the register's current value but the
  instruction does NOT write it) are filtered by default. `regflow_summary`
  carries the filter counts. Pass `include_observations=true` for the
  raw view.
- **F-5 `trace_cryptoinstr`**: per-primitive `verdict`
  (confirmed / suspected / ambiguous) in `primitive_corroboration`.
  SHA-3 needs `eor3 + (rax1|xar|bcax)` co-occurrence (eor3 alone is
  generic 3-way XOR); GHASH needs `pmull + aese` (pmull alone is more
  often CRC / Reed-Solomon erasure code).
- **F-6 partial `trace_hexblock`**: Python-side defensive check —
  status flips to `ok_truncated` with a `warning` when the engine
  reaches `max_lines` without finding a matching `ret`. Hexdumps from
  such blocks may belong to a nested inner call (張冠李戴 corruption);
  the warning explicitly tells the agent not to cite them. Full
  C-engine nested-depth counter ships in 0.9.2.
- **F-7 `trace_callgraph`**: explicit `match` parameter
  (`exact` | `prefix` | `substring`, default `exact`). The engine's
  default substring match was over-counting (`memcpy` silently matched
  `_memcpy`, `__memcpy_aarch64_simd`, `safe_memcpy_helper`, etc).
- **F-11 `trace_search`**: clarified `before_line` direction semantics
  in the schema description — engine returns hits nearest-to-cutoff
  first, but the schema wording was easy to misread.
- **F-13 `trace_bytes`**: limit now allocated evenly per variant.
  Previously a canonical-heavy result could exhaust the limit before
  reversed/stripped variants were reported, making agents conclude
  "no reversed hit" when there were plenty. Response carries
  `per_variant_emitted`.
- **F-14 `trace_semop`**: `crypto_candidate` hits sub-classified by ±3
  ARX-neighbour co-occurrence. `subclass="crypto_arx"` for hits near
  rotate/add/multiply (genuinely cipher-round territory);
  `subclass="xor_three_reg"` for bare 3-way XOR with no ARX neighbour
  (common in constant-time conditionals, byteswap, base64 lookup,
  software CRC — lead, not evidence).
- **F-15 schema-only `trace_hexblock`**: each hexdump tagged
  `direction="unknown"` to make the missing in/out distinction
  explicit. Full C-engine mem_r vs mem_w discrimination ships in 0.9.2.
- **F-16 discipline reminder**: first `EARLY_PHASE_HINT_CALLS=3` tool
  calls now get a fixed Detection-phase reminder instead of the
  modular wrap. Previously the call_count % 11 rotation could land
  "Classify hit: origin / generation / copy ..." on the first call
  (bind_trace), with zero hits to classify.

### Added — Server-side security + correctness

- **F-12 r2 prefix blacklist**: `R2_FORBIDDEN_TOKEN_PREFIXES` rejects r2
  command tokens starting with `!` (shell escape), `.` (script eval),
  `@@` (iterate), `=` (network/RAP), `#!` (macro), `$` (alias),
  `|` (pipe). Previously `r2 -q -2 -n -c "!rm -rf ~"` passed the v0.8.x
  blacklist because only the first whitespace token (`!rm`) was checked
  against `aaa/aac/...`.
- **A-4 `trace_fold` path containment**: `out_filename` is the new
  preferred parameter (single filename, no directory components). Legacy
  `out_path` accepted but forced under `STATE.artifacts_dir` via
  `Path.relative_to`. Removes the path-traversal hole where any
  absolute output path was accepted.
- **A-2 `bind_trace`** now resets `tool_call_count = 0` on (re-)bind.
  CHANGELOG v0.8.x promised "fresh per-session"; the code was not
  resetting, so the new session's first tool call inherited the prior
  session's counter (file numbering started at e.g. `000047.json`).
- **A-6 `_skip_discipline`**: handlers can opt out of the discipline
  counter for pure argument-validation failures (`_skip_discipline=true`
  on the payload). Used across handlers so a session with typos doesn't
  trigger full-rule reinjection at call 14 instead of 20.
- **A-8 `[H<n>]` bracket-only citation**: the `validate_artifact_
  references` regex tightened to `\[H(\d+)\]|<H(\d+)>` — bare `H1`/`H2`
  no longer matched, avoiding false matches on Python variable names,
  SHA-3 state vector identifiers, etc. SKILL docs teach the bracket
  form.

### Changed — Daemon / MCP

- **F-10 ToolCallLog stores full pre-truncation result**. Previously
  `daemon.request` / `daemon.run_cli` truncated stdout *during* read
  and the `ToolCallLog.record` step stored the already-truncated
  payload. FIX #1 verbatim verification could then spuriously fail
  when real evidence fell past the truncation boundary — pushing
  agents toward picking only excerpts visible in the truncated window.
  Now the daemon returns `_stdout_full` for ledger-side recording;
  `_attach_discipline` swaps it into the persisted payload then strips
  it from the agent-facing one.

### Deferred to 0.9.2 — Requires C-engine work (`tools/search/search.c`)

Documented as KNOWN GAPS in the affected tools' schema descriptions so
agents see them at the call site, not just in CHANGELOG.

- **F-4 `trace_constscan` adrp+ldr literal-pool blind spot**. iOS
  Apple-clang -O default emits `adrp x9, page; ldr w0, [x9, #off]` for
  any 32-bit constant; the magic lives in `.rodata` not on the
  instruction line, so the current `classify_evidence` reports zero
  hits when the binary IS doing MD5/SHA-256. New `EV_POOL_LOAD` type
  + `mem_r=<addr>` dump scanner ships next.
- **F-6 full `trace_hexblock` nested depth**. Python defensive check
  (above) catches the truncated case; the C engine still doesn't
  count `bl`/`ret` nesting so a long-span call block with internal
  `bl objc_retain; ret` returns the inner ret as the outer boundary.
- **F-9 `trace_fold` samples_per_fold**. The current first+last
  collapse drops middle-round state, breaking hash algorithm
  identification (you can't see SHA-1's a/b/c/d/e rotation across 80
  rounds when only round 1 + round 80 are kept). New
  `samples_per_fold` (3-5 evenly spaced) + block-signature in
  sentinel comment.
- **F-15 full `trace_hexblock` direction**. Per-hexdump
  `direction="in"|"out"` based on `mem_r=` vs `mem_w=` source line.
- **A-3 daemon `extcall` protocol**. Extend the persistent daemon
  protocol from `match`/`context` to cover the 11 extension
  subcommands (regflow / producer / semop / lint / fold / callgraph /
  modgraph / hexblock / constscan / cryptoinstr / bytes). Saves
  20-150s of cumulative mmap+line-index rebuild on a typical 30-50
  tool-call session over a GB-scale trace.

### Deferred to 0.9.5+ — Original "Evidence Weighting" roadmap

The pre-review v0.9.1 plan was Evidence Weighting / Confidence Decay /
Independence anchor model. Postponed: building those on top of tools
with structural biases amplifies error rather than reducing it. Tool
correctness (this release) ships first.

### Notes — Hygiene items still pending

- **A-1** docs lint CI for tool count drift, **A-5** SessionState.cleanup
  unification, **A-9** ToolCallLog chunked truncation, **A-10** startup
  binary-existence logging, **A-11** daemon retry / SIGTERM / path
  escape edge tests. Tracked separately.

## [0.9.0] — Sub-Agents: Hypothesis Reviewer (anti-hallucination defence layer 3)

### Added
- **`agents/hypothesis-reviewer.md`** — Plugin-level sub-agent invoked
  via the `Agent` tool. Independent blue-team reviewer for any
  `hypothesis_conclude(final_confidence="high")` call on a load-bearing
  hypothesis. Tools restricted to read-only trace queries + `hypothesis_list`
  (no `conclude`/`add`/`update`/`abandon` power) — it can only recommend,
  not execute. Closes the one anti-hallucination gap the server-side
  FIX#1–#4 gates cannot: an agent that has invested 20+ tool calls in a
  hypothesis becomes biased toward concluding it; an independent reviewer
  with no sunk cost stays objective.
- **`docs/agents.md`** — sub-agent inventory, invocation patterns,
  design boundaries, future-agent rationale (why
  `trace-evidence-scout` / `crypto-recovery-specialist` were considered
  and withdrawn).
- **`skills/ciphertext-recovery/SKILL.md`** — new `conclude(high) 必经
  蓝军审查` section spelling out when and how to spawn the reviewer.
- **`skills/trace-analysis/SKILL.md`** — pointer to the reviewer for
  the optional ledger usage in general mode.

### Changed
- Plugin version: `0.8.1` → `0.9.0`.

## [0.8.x] — pre-sub-agent baseline (preserved for changelog continuity)

### Added
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md` (project hygiene baseline).
- GitHub Actions CI: macOS + Linux matrix, runs `tools/search/tests/run_tests.sh`
  (132 assertions) and the new Python `pytest` suite on every push / PR.
- Python unit tests under `tests/python/` (standard-library `unittest`,
  no third-party deps) covering the Hypothesis Ledger FIX #1–#4 gates,
  `ArtifactStore` path-escape guards, and `static_tools._validate_r2_args`
  boundary policy.
- `tests/python/test_e2e_mcp.py` — spawns `algokiller_mcp.py` as a real
  subprocess and drives the full JSON-RPC 2.0 path (L1 plumbing:
  bind → lint → constscan → callgraph → hexblock; L3 ledger end-to-end:
  hypothesis_add → conclude(high) reject → falsification_attempted →
  conclude(high) ok → write_artifact reference vs bypass). Uses the
  existing synthetic fixtures `sprint34.trace` and
  `sprint5-constscan.trace`; no real-world trace required.

### Changed
- Docs: synced fingerprint count (`constscan` advertises **71** entries,
  not the historical 26) and tool surface (`tools/list` returns **22**
  tools — 17 trace/artifact + 5 hypothesis-ledger). README, English README,
  and `tools/search/README.md` updated together to prevent drift.
- Docs: bumped `ak_search` CLI surface to **14 subcommands** (added
  `cryptoinstr` to the inventory).

### Fixed
- README test-harness expectation: `97 PASS expected` → `132 PASS expected`.
- `HypothesisLedger.excerpt_in_result` no longer rejects evidence whose
  verbatim excerpt contains `"` (or any JSON-escaped character). The
  tool-call log stores the JSON-serialised payload, where `"` becomes
  `\"`, but agents see the un-escaped stdout — a literal-quote excerpt
  was failing the substring check spuriously. Now falls back to comparing
  against `json.dumps(excerpt)[1:-1]`. Surfaced by the new e2e test
  driving the JSON-RPC path against `sprint5-constscan.trace`.

## [0.8.1] — Hypothesis Ledger Hardening

### Fixed (Hypothesis Ledger v2)
External review surfaced four anti-hallucination gaps; all closed in this
release (commit `b59125b`):

- **FIX #1 — Evidence excerpt verification.** Every `Evidence` item must
  cite an `excerpt` string (≥8 chars) that the server can locate verbatim
  inside the stored tool result. Paraphrased summaries no longer satisfy
  the gate.
- **FIX #2 — Contradiction pressure.** `conclude(high)` requires
  `supporting ≥ 2 × contradicting`; `conclude(medium)` requires
  `supporting > contradicting`; any time contradicting outweighs
  supporting, confidence is hard-capped at `low`.
- **FIX #3 — Source diversity.** `conclude(high)` requires supporting
  evidence from ≥2 distinct `tool_name` buckets (3 hits from one tool is
  correlated, not independent). `tool_name` is derived server-side from
  `ToolCallLog`, not user-supplied.
- **FIX #4 — Conflict graph.** Hypotheses can declare `conflicts_with`;
  `conclude(≥medium)` is rejected if a conflicting hypothesis is already
  concluded at ≥medium confidence.

## [0.8.0] — Hypothesis Ledger scaffold

### Added
- `server/hypothesis.py` — `HypothesisLedger` + `ToolCallLog`.
- 5 new MCP tools: `hypothesis_add`, `hypothesis_update`,
  `hypothesis_conclude`, `hypothesis_abandon`, `hypothesis_list`.
- Falsification gate on `conclude(high)`, depends_on cascade on
  `abandon`, automatic per-bind\_trace artifact directory housing
  `hypothesis_ledger.jsonl` + `tool_call_log/*.json`.
- `write_artifact` now validates that every `H<id>` referenced in the
  deliverable resolves to a concluded ≥medium hypothesis (rejects "bypass
  ledger" deliverables).

## [0.7.0] — Skill methodology rewrite

### Changed
- Rewrote `skills/ciphertext-recovery/SKILL.md` Stage 1 to multi-signal
  correlation per RE-pipeline review feedback (constscan + cryptoinstr
  joint reading, no single-point attribution for "hardened binary").

## [0.6.0] — Sprint 6: ARM Crypto Extensions + anti-RE SOP

### Added
- `trace_cryptoinstr` MCP tool + `cryptoinstr` `ak_search` subcommand.
  Detects AES (aese/aesmc/aesd/aesimc), SHA-1, SHA-256, SHA-512, SHA-3,
  GHASH, SM3, SM4 hardware instructions — closes the constscan blind
  spot for hardware-accelerated crypto (iOS CryptoKit / BoringSSL ARM /
  libsodium-arm / Android Keystore HW path).
- Big-tech anti-RE SOP section in the ciphertext skill.

## [0.5.0] — Sprint 5: constscan evidence-classified verdicts

### Added
- `constscan` expanded to 71 fingerprints across hash / cipher_sym / ecc
  / crc / mac (was 26 in earlier releases).
- Per-hit `verdict` classification: `real` (load_imm or mem_r), `weak`
  (mem_w / mem_r_addr only), `alu_only` (ALU collision false positive).
- `confidence` field: `strong` / `medium` / `weak`.

## [0.4.0] — Sprint 3+4: callgraph / modgraph / hexblock / constscan / bytes

### Added
- `trace_callgraph` (Top-K + xref), `trace_modgraph` (cross-module
  matrix), `trace_hexblock` (structured `call func:` block parser),
  `trace_constscan` (initial 26-entry fingerprint table), `trace_bytes`
  (hex literal search with auto byte-reverse + leading-zero-strip).

## [0.3.0] — Sprint 2: lint + fold

### Added
- `trace_lint` — single-pass JSON health-check for bound traces.
- `trace_fold` — block-aware repeated-region folding; 115 MB → 1.1 MB
  on a production startup trace at `--block 4 --threshold 100`.

## [0.2.0] — Sprint 1: regflow / producer / semop

### Added
- `trace_regflow`, `trace_producer`, `trace_semop` MCP tools and matching
  `ak_search` subcommands (one-shot CLI mode via `AkSearchDaemon.run_cli`).

## [0.1.0] — Initial release

### Added
- Claude Desktop plugin manifest (`.claude-plugin/plugin.json`, `.mcp.json`).
- Python MCP server (JSON-RPC 2.0 over stdio, zero external deps).
- Native `ak_search` engine (mmap + line-index + ASCII case-insensitive
  BMH, daemon tab protocol) vendored from upstream AlgoKiller.
- Skills: `algokiller:ciphertext-recovery`,
  `algokiller:trace-analysis`, `/algokiller:ciphertext`,
  `/algokiller:general`.
- Discipline reinjection: per-call `discipline_reminder`, every 20 calls
  `discipline_full_reinjection`.
- Allow-listed `run_static_tool` (radare2 / binutils / LLVM /
  Mach-O-iOS / ripgrep / jq) with hard r2 boundary
  (`-q -2 -n` required, `aaa` family forbidden).
