"""Discipline reminders attached to every tool result.

Each tool return carries a short mode-specific reminder; every REINJECTION_INTERVAL
calls upgrades to a full rules block. Mirrors the original harness's
system_reinjection_interval mechanism to prevent drift on long trace tasks.
"""

from __future__ import annotations


CIPHERTEXT_SHORT_REMINDERS = [
    "Classify hit: origin / generation / copy / encode / consume / stale / conflict before concluding.",
    "Call/hexdump/ret hit → open trace_context for args, ret, hexdump address/length/bytes.",
    "ON-TASK CHECK: name current phase (Detection / Identification / Analysis / Extraction) + how next call serves the root task.",
    "Single-purpose-per-search: don't reuse one result as evidence for multiple roles.",
    ">4-byte data: slide 2-4 distinctive 4-byte windows × (original + reversed) before widening.",
    "STRATEGY: 3 same-direction calls with no new evidence → switch (top-down / bottom-up / pattern / constraint).",
    "No algorithm naming from function names or constants alone; require data-flow / call-boundary / hexdump / instruction evidence.",
    "THREAD BOOKMARK: off-mainline finding → record `open thread: ...` inline, stay on main task.",
    "Backward chain-chasing: hard limit 3 hops; verify chain integrity first.",
    "TIME-BOX: >30 calls without algorithm candidate → start degraded delivery (confirmed + high-confidence + gaps + open threads).",
    "STATIC-AID: if BN MCP offline, use algokiller.run_static_tool (rabin2 -Iz / objdump -d --start/--stop / r2 -q -2 -n -c / rax2 / class-dump). r2 single-command only; no -A / aaa.",
]

GENERAL_SHORT_REMINDERS = [
    "Single-purpose-per-search: locate / origin / consumer / branch / boundary — pick one.",
    "ON-TASK CHECK: restate root question + confirm next call is shortest path.",
    "Earliest hit ≠ origin; verify it's on the data-flow path of the target.",
    "Hex queries: original order then byte-reversed; >4 byte → 2-4 4-byte windows.",
    "THREAD BOOKMARK: adjacent-but-off-question finding → record `open thread: ...` inline.",
    "Don't ask user for missing field names / semantics / extra samples — search and infer.",
    "hexdump ASCII = search hint; field boundaries = left-side hex + address + length.",
    "TIME-BOX: >20 calls on single-question task → start degraded delivery.",
    "STATIC-AID: algokiller.run_static_tool available — file / rabin2 -Iz / strings / rg / jq / class-dump / r2 (bounded). Priority: BN MCP > run_static_tool > trace-only.",
]

CIPHERTEXT_FULL_BLOCK = """[Full-rule reinjection — ciphertext mode]
1. Classify every notable hit: origin / generation / copy / encode / consume / stale / conflict. Earliest hit = candidate, not conclusion.
2. Verify candidate sits on upstream data-flow of target ciphertext: mem_w into ciphertext buffer, call output hexdump, ret pointer/length, or instruction writing a participating register.
3. Call boundary capture: function name, arg registers, return value, hexdump (address/length/bytes), instructions setting x0-x7 before, consumers after.
4. >4-byte data: 2-4 distinctive 4-byte windows × (original + reversed).
5. Exhaust candidate families (block / stream / hash/MAC / CRC / compression / XOR-add-rotate / Feistel-SPN-ARX) with match-or-conflict evidence before naming a standard algorithm.
6. Backward chain-chasing: hard limit 3 hops.
7. ON-TASK CHECK every 3-5 calls: name current phase (Detection / Identification / Analysis / Extraction) + how next call serves the root task.
8. THREAD BOOKMARK: off-mainline findings recorded inline as `open thread: ...`; batch-evaluate after main delivery.
9. STUCK SWITCH: 3 same-direction calls with no new evidence → top-down / bottom-up / pattern (magic constants) / constraint (loop / compare).
10. TIME-BOX: locate+evidence 10-20 calls; algorithm ID + closed-loop verification cumulative 30-50; hard ceiling 60 → force degraded delivery."""

GENERAL_FULL_BLOCK = """[Full-rule reinjection — general mode]
1. Single-purpose-per-search: locate / origin / consumer / branch / boundary / verify / exclude.
2. Open call/hexdump/ret as data-flow boundaries (function name, args, return, hexdump, x0-x7 before, consumers after).
3. hexdump ASCII = search hint; field boundaries = left-side hex + address + length.
4. Separate confirmed / high-confidence inference / open question.
5. ON-TASK CHECK every 3-5 calls: restate root question + shortest-path justification for next call.
6. THREAD BOOKMARK: adjacent-off-question findings recorded inline; not chased.
7. TIME-BOX: single-question <20 calls; execution flow / detection clusters <30; hard ceiling 50 → force degraded delivery.
8. Stop once root question is answerable; one cross-check pass on key conclusion.
9. Field semantics: 'wire boundary confirmed' vs 'business name inferred' reported separately."""

REINJECTION_INTERVAL = 20

# FIX F-16 (v0.9.1): the first 3 tool calls of a session are usually
# bind_trace + lint/constscan/cryptoinstr triage — these are NOT yet
# producing hits, so the modular-wrap reminders ("Classify hit: origin /
# generation / copy ...") arrived before the agent had any hits to
# classify, becoming pure noise. Fix: phase-pin the early calls to a
# fixed Detection-phase reminder, then resume the modular wrap from
# call 4 onward when the agent is actually in evidence-gathering territory.
DETECTION_PHASE_HINT = (
    "Phase: Detection — run trace_lint → trace_constscan → trace_cryptoinstr → "
    "trace_callgraph(top=N) to triage the trace before drilling. If trace_lint "
    "warns about format/missing-call-blocks/missing-register-observations, fix "
    "the input before sinking analysis tokens."
)
EARLY_PHASE_HINT_CALLS = 3


def build_reminder(*, mode: str, call_count: int) -> dict:
    """Return a discipline payload to merge into a tool result dict.

    mode: "ciphertext" | "general" | "unknown".
    call_count: monotonic tool-call counter after bumping for this call.
    Returns dict with `discipline_reminder`; every REINJECTION_INTERVAL calls
    also includes `discipline_full_reinjection`.
    """
    if mode == "ciphertext":
        short_pool = CIPHERTEXT_SHORT_REMINDERS
        full_block = CIPHERTEXT_FULL_BLOCK
    elif mode == "general":
        short_pool = GENERAL_SHORT_REMINDERS
        full_block = GENERAL_FULL_BLOCK
    else:
        return {}

    # FIX F-16: the first EARLY_PHASE_HINT_CALLS get a fixed Detection-phase
    # reminder; modular wrap resumes after.
    if 1 <= call_count <= EARLY_PHASE_HINT_CALLS:
        payload = {"discipline_reminder": DETECTION_PHASE_HINT}
    else:
        payload = {"discipline_reminder": short_pool[call_count % len(short_pool)]}
    if call_count > 0 and call_count % REINJECTION_INTERVAL == 0:
        payload["discipline_full_reinjection"] = full_block
    return payload
