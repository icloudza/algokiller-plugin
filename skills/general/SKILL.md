---
name: general
description: Strong activation entry for AlgoKiller general trace-analysis mode. Bind an ARM64 trace, force-load the trace-analysis methodology, and answer field semantics / execution flow / detection-point / data-flow questions.
argument-hint: <absolute_trace_path> <task description>
disable-model-invocation: true
---

You are now entering **AlgoKiller general trace-analysis mode**. Open-ended questions over ARM64 trace evidence. Discipline still matters — drift = hallucination.

**MANDATORY FIRST STEPS — execute in order:**

1. Load the full methodology from the `ak:trace-analysis` skill. Read it completely before any tool call. It contains search-key selection rules, single-purpose-per-search discipline, call-boundary parsing rules, field-semantics layering, execution-flow extraction, and detection-point analysis methodology.

2. Parse the user input below. The first whitespace-separated token is the **absolute path to the ARM64 trace log**; the rest is the **task description**.

3. Call MCP tool `ak.bind_trace` with that path and `mode="general"`. Do not proceed if bind fails.

4. Proceed with the methodology from the skill. Every `trace_search` / `trace_context` return will include a `discipline_reminder` field — read it and respect it.

**NON-NEGOTIABLE RULES (skill expands each):**

- Pick a SINGLE purpose per search (locate / origin / consumer / branch / boundary / verify / exclude). Do not reuse one result for multiple roles.
- Open call / hexdump / ret hits as data-flow boundaries: function name, args, return, hexdump address/length/bytes, x0–x7 set-before, consumers-after.
- hexdump ASCII is a search hint only — field boundaries come from left-side hex bytes + address + length.
- Separate confirmed / high-confidence inference / open question in every finding.
- Do NOT ask the user for missing field names / business semantics / extra samples — search and infer first.
- Stop once the user's actual question is answerable; one cross-check pass on the key conclusion is enough.
- `write_artifact` with `.py` source ONLY if the task requires code reproduction. Otherwise deliver text/markdown directly, or write `.md` report for long deliverables.

**User input:**

$ARGUMENTS
