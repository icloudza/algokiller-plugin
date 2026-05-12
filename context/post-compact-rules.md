## Post-compact context restoration

The previous session was just compacted. Re-read these rules before continuing — they are NOT covered by the conversation summary the compactor produced.

### Critical rules still apply (do not relax post-compact)

The full anti-hallucination ruleset lives in `context/critical-rules.md` and was injected at session start. After compact, these rules in particular are the ones models historically forget first — re-anchor on them before resuming:

- **R2** SIMD broadcast (`movi v*.16b, #imm`) ≠ AES Tbox. Don't promote it back to AES on second pass.
- **R3** `call_kind = "arc_bookkeeping"` hexdumps are receiver side-effects, not algo inputs.
- **R4** `block_count_estimate` IS the block count. Do not divide.
- **R6** Every "高置信推断 / high-confidence inference" tier claim requires `[H<n>]` ledger citation.
- **C1** **First tool call after compact MUST be `hypothesis_list`** — verify ledger state matches the conversation summary before doing anything else.

### Compact-specific rules

### Hypothesis ledger references survive compact

If the pre-compact conversation history mentions `[H1]`, `[H2]` … markers, those refer to entries in the algokiller hypothesis ledger that still exists on disk. Do NOT treat them as dangling references. The structured ledger state is reattached below as a JSON snapshot.

Before claiming "high-confidence inference" status on any new claim, re-check the ledger via `hypothesis_list` — it carries the authoritative state, not the conversation summary.

### Output directory survives compact

The session's resolved artifacts directory is recorded in the snapshot below as `session_dir`. **Continue writing all artifacts under that directory** — do not invoke `bind_trace` again unless the user explicitly changes traces or wants a fresh `<timestamp>/` subdirectory.

### Already-written artifacts

The snapshot lists `artifacts_written`. Do not re-emit those files; if a follow-up is needed, write a new file with a clear delta name (e.g. `report-v2.md`).

### What compact dropped

The compactor preserves narrative and concluded hypotheses but discards raw tool outputs (hexdumps, large `trace_search` / `trace_constscan` results, decompilation excerpts). If you need a specific raw observation that was previously surfaced, RE-RUN the tool — do not reconstruct it from memory.
