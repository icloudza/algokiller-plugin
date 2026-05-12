---
description: Rebind the currently-bound trace into a fresh `<timestamp>/` session directory while keeping the trace path + mode + output_dir unchanged. Useful when starting a new analysis pass without re-typing the trace path.
---

The user wants a clean session on the same trace they were just analysing.

Steps:

1. **Recover the current binding**. The previous `bind_trace` response should still be in your context — extract `trace_file`, `mode`, and `output_dir_resolved`. If you don't have them, ask the user for the trace path; do NOT guess.
2. **Re-invoke `bind_trace`** with those exact values plus `output_dir` set to the parent of the previous `output_dir_resolved` so the new resolution lands in the SAME project's `.algokiller/<trace>/<NEW_TIMESTAMP>/` rather than rolling Documents fallback.

   Example: previous `output_dir_resolved` was
   `/Users/foo/proj/.algokiller/login.trace/20990101_120000` —
   pass `output_dir = /Users/foo/proj/.algokiller/login.trace` (the parent
   of the old timestamp dir) so the resolver creates a fresh
   `<NEW_TIMESTAMP>/` under it.
3. **Report the new session directory** to the user verbatim, in one short sentence.

DO NOT carry hypotheses across — the new session has a fresh ledger by design (each bind == fresh ledger; see CHANGELOG 0.9.6). If the user wants continuity, they should explicitly say so and you'd re-add hypotheses manually.
