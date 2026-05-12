---
description: Show the current algokiller session state — bound trace, mode, output_dir, ledger summary, artifacts written.
---

Report the current algokiller session state in this exact structure:

1. **Trace binding** — call `bind_trace` is required first. If no trace is bound yet, say so and stop.
2. **Output directory** — show the `output_dir_resolved` and `output_dir_source` from the latest `bind_trace` response (you should have it in context; if not, call `bind_trace` again to refresh).
3. **Hypothesis ledger** — call `hypothesis_list` and present:
   - count of `concluded` / `active` / `abandoned` / `archived` hypotheses
   - one-line summary of each concluded hypothesis (id, final_confidence, statement)
   - any `active` hypothesis with `confidence: high` that hasn't been concluded (these are dangerous open threads)
4. **Artifacts written this session** — call `list_artifacts` and list each file by name + size; group by extension (`.py` vs `.md`).
5. **Recommendations** — single short paragraph: are there active hypotheses that should be concluded? unreferenced concluded ones that need archive? falsification gaps? Suggest the next concrete action.

Keep the whole report under 500 words. Don't dump raw JSON; format as a compact human-readable digest.
