# Changelog

All notable changes to **algokiller-plugin** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  on WeChat startup trace at `--block 4 --threshold 100`.

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
