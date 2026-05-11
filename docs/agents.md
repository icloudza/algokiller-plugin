# algokiller Sub-Agents

algokiller v0.9.0+ ships **plugin-level sub-agents** that the main
Claude Code / Claude Desktop session can spawn via the `Agent` tool.

Sub-agents extend algokiller's anti-hallucination scaffold beyond what
a single agent context can enforce: they have independent context, no
visibility into the main agent's reasoning, and tool permissions that
are deliberately narrowed.

## Inventory (v0.9.0)

| Agent | Purpose | tools |
|---|---|---|
| `hypothesis-reviewer` | Independent blue-team review of any Hypothesis Ledger entry before `conclude(final_confidence="high")`. Returns `confirm` / `refute` / `abandon` with reasons. Read-only over the ledger and trace; **no power to mutate the ledger itself.** | trace_* (read-only), `hypothesis_list`, artifact read |

(more agents will land in 0.9.x patches as real usage surfaces specific
multi-agent value — see CHANGELOG.)

## Why sub-agents matter for trace analysis

The single-agent Hypothesis Ledger (added in v0.8.0) closes the obvious
hallucination paths: fabricated evidence, insufficient supporting count,
missed falsification attempts, conflicting concluded hypotheses. But it
**cannot** close one specific gap:

> The main agent has been working on hypothesis H<N> for 20 tool calls.
> Sunk cost makes it want to conclude. It picks the *minimally sufficient*
> evidence to clear the server-side gates. The server cannot detect this
> bias because it only sees the final ledger state, not the agent's
> internal pressure to ship.

`hypothesis-reviewer` closes that gap. It is spawned with **no context
about the main agent's reasoning** — only the hypothesis id. It
independently re-fetches the evidence excerpts from the bound trace and
asks "does this evidence actually support the statement, or does it just
*look* like it does?"

If you've ever caught yourself thinking "the evidence is good enough,
just conclude already" — that's exactly the moment a blue-team reviewer
catches.

## How to invoke

The main agent calls the `Agent` tool whenever it's about to
`hypothesis_conclude(final_confidence="high")` on a load-bearing
hypothesis (one that will be cited by the final `write_artifact`):

```text
Agent(
  subagent_type="hypothesis-reviewer",
  prompt=(
    "Review H3. Main agent is preparing "
    "hypothesis_conclude(id='H3', final_confidence='high'). "
    "H3 statement: 'WeChat metasec_ov.so computes SM4-CBC for X-Sign'. "
    "Bound trace: /captures/wechat_login.trace.log (mode=ciphertext)"
  ),
)
```

The reviewer returns a JSON object:

```json
{
  "hypothesis_id": "H3",
  "recommendation": "confirm" | "refute" | "abandon",
  "gate_check": {
    "supporting_count": 4,
    "contradicting_count": 0,
    "falsification_attempted": true,
    "distinct_tool_sources": 3,
    "all_gates_passed": true
  },
  "excerpt_audit": [
    {"tool_call_id": 12, "verdict": "supports", "note": "..."},
    {"tool_call_id": 27, "verdict": "weak",     "note": "..."}
  ],
  "counter_evidence_found": "none" | "<≤120 chars>",
  "reason": "<≤200 chars>",
  "next_steps_for_main_agent": "<empty if confirm>"
}
```

On `confirm` → main agent proceeds with `hypothesis_conclude(...)`.
On `refute` → main agent follows `next_steps_for_main_agent` to gather
more / different evidence, then re-reviews.
On `abandon` → main agent calls `hypothesis_abandon(id, reason)` and
restarts that branch of analysis.

## When NOT to invoke

- For `confidence="low"` or `unknown`: no review needed; these are
  exploratory anyway.
- For `confidence="medium"`: optional — recommended for hypotheses that
  drive a major branch, otherwise skip.
- For abandoning a hypothesis: no review; main agent's call.
- After a hypothesis is already `concluded`: cannot re-review; if it
  was wrong, `hypothesis_abandon` it and start a new one.

## Design boundaries

`hypothesis-reviewer`:

- **Cannot** call `hypothesis_add` / `update` / `conclude` / `abandon`
  — it only reads and recommends. Tool-permission isolation enforces this
  at the SDK layer.
- **Cannot** see the main agent's chat history or reasoning. It receives
  only the prompt the main agent gives it.
- **Cannot** write artifacts. It is a read-only auditor.
- **Can** call any read-only trace tool (`trace_search`, `trace_context`,
  `trace_regflow`, etc.) and `hypothesis_list` to independently verify
  evidence excerpts.

## Future agents (under evaluation, NOT shipped in 0.9.0)

- `trace-evidence-scout` — A specialist for context-heavy evidence
  gathering (15+ tool calls on a single question). Considered for
  v0.9.0 but withdrawn because the evidence-chain referencing (tool_call_id
  + verbatim excerpt) doesn't carry cleanly across sub-agent boundaries
  given the current server design. Will revisit if real usage shows the
  main agent's context getting blown out repeatedly.
- `crypto-recovery-specialist` — Considered, withdrawn: the ciphertext
  methodology already lives in `skills/ciphertext-recovery/SKILL.md`, and
  spawning a specialist would split the main agent's situational
  awareness. Cleaner to keep it in-process.

The principle: **every new sub-agent must answer "what does this enforce
that the main agent + server-side gates cannot?"** `hypothesis-reviewer`
answers cleanly (independent context, no sunk-cost bias). Nothing else
currently does.

## References

- `agents/hypothesis-reviewer.md` — full agent prompt.
- `skills/ciphertext-recovery/SKILL.md` § "conclude(high) 必经蓝军审查"
  — main-agent-side protocol.
- `server/hypothesis.py` — server-side FIX#1–#4 gates (defence in depth
  layer 1).
