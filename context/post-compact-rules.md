## Post-compact context restoration

The previous session was just compacted. Re-read these rules before continuing — they are NOT covered by the conversation summary the compactor produced:

### Hypothesis ledger references survive compact

If the pre-compact conversation history mentions `[H1]`, `[H2]` … markers, those refer to entries in the algokiller hypothesis ledger that still exists on disk. Do NOT treat them as dangling references. The structured ledger state is reattached below as a JSON snapshot.

Before claiming "high-confidence inference" status on any new claim, re-check the ledger via `hypothesis_list` — it carries the authoritative state, not the conversation summary.

### Output directory survives compact

The session's resolved artifacts directory is recorded in the snapshot below as `session_dir`. **Continue writing all artifacts under that directory** — do not invoke `bind_trace` again unless the user explicitly changes traces or wants a fresh `<timestamp>/` subdirectory.

### Already-written artifacts

The snapshot lists `artifacts_written`. Do not re-emit those files; if a follow-up is needed, write a new file with a clear delta name (e.g. `report-v2.md`).

### What compact dropped

The compactor preserves narrative and concluded hypotheses but discards raw tool outputs (hexdumps, large `trace_search` / `trace_constscan` results, decompilation excerpts). If you need a specific raw observation that was previously surfaced, RE-RUN the tool — do not reconstruct it from memory.
