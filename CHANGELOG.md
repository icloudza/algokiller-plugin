# Changelog

All notable changes to **algokiller-plugin** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
