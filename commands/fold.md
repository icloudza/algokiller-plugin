---
description: Run `trace_fold` on the currently-bound trace to produce a block-collapsed derivative trace (typically 99 % compression on hash-loop-heavy traces) and bind to that instead.
---

Use this when the bound trace is so large that subsequent `trace_constscan` / `trace_search` calls feel slow, especially when the trace contains long repeating instruction blocks (hash main loops, AES rounds in a loop, VM dispatch loops).

Steps:

1. **Sanity-check** the binding. If no trace is bound, stop and tell the user.
2. **Run `trace_fold`** with sensible defaults for the bound trace's shape. For hash-loop-heavy traces use `block=4, threshold=100`; for VM-dispatch heavy use `block=2`; for unknown use `block=4, threshold=200`. Direct the output to `out_filename` (relative, lands inside the current artifacts_dir).
3. **Report the size delta** to the user: "trace_fold collapsed X MB → Y MB (Z %)". Pull the byte counts from the `trace_fold` response.
4. **Ask the user** if they want to `bind_trace` to the folded version. If yes, call `bind_trace(path=<folded path>, mode=<same mode>)`. The folded trace's line numbers do NOT correspond to the original, so any line-number anchors from prior analysis become invalid — warn the user before rebinding.

DO NOT silently rebind. The folded trace is a derivative artifact, and using it requires user acknowledgement that line numbers don't carry over.
