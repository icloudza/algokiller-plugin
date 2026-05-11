---
name: ciphertext
description: Strong activation entry for AlgoKiller ciphertext-recovery mode. Bind an ARM64 trace, force-load the ciphertext-recovery methodology, and start cipher / algorithm recovery from a target ciphertext.
argument-hint: <absolute_trace_path> <task description with target ciphertext>
disable-model-invocation: true
---

You are now entering **AlgoKiller ciphertext-recovery mode**. High-discipline analysis; drift = hallucination.

**MANDATORY FIRST STEPS — execute in order:**

1. Load the full methodology from the `algokiller:ciphertext-recovery` skill. Read it completely before any tool call. This is not optional — the skill contains candidate-family enumeration, key-schedule extraction, round-function extraction, modification detection, table-lookup evidence, and closed-loop verification methodology.

2. Parse the user input below. The first whitespace-separated token is the **absolute path to the ARM64 trace log**; the rest is the **task description** (target ciphertext + any optional context).

3. Call MCP tool `algokiller.bind_trace` with that path and `mode="ciphertext"`. Do not proceed if bind fails.

4. Proceed with the methodology from the skill. Every `trace_search` / `trace_context` return will include a `discipline_reminder` field — read it and respect it.

**NON-NEGOTIABLE RULES (skill expands each):**

- Earliest hit = candidate, not conclusion. Verify it sits on the upstream data-flow of the target ciphertext.
- Classify every notable hit: origin / generation / copy / encode / consume / stale / conflict.
- Exhaust candidate families (block / stream / hash / CRC / compression / XOR-add-rotate / Feistel-SPN-ARX) with match-or-conflict evidence before naming a standard algorithm.
- Backward chain-chasing: hard limit 3 hops.
- Input contract: only target ciphertext is guaranteed. Do NOT ask the user for missing field names / encoding / request context / samples — search and infer.
- Sufficient evidence → `write_artifact` recovered Python (`.py`) + analysis report (`.md`).
- Partial evidence → deliver confirmed + high-confidence + open gaps. Don't stall.

**User input:**

$ARGUMENTS
