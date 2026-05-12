---
name: AlgoKiller ciphertext report
description: Fixed-structure analysis report for ciphertext-recovery deliverables. Locks the section order so reports across different traces are directly comparable.
---

When writing the final analysis report for a ciphertext-recovery session, use this exact section structure. Every section is required; omit only the optional "Open gaps" if there are none. Cite `[H<n>]` for every high-confidence claim.

# `<trace_basename>` — Algorithm Recovery Report

> **Source trace**: `<trace_path>` (`<size>`, `<line_count>` lines)
> **Bound**: `<bind timestamp>` | **Mode**: ciphertext
> **Output directory**: `<output_dir_resolved>` (source: `<output_dir_source>`)

## 1. Executive summary

One paragraph (≤ 5 sentences) answering: what algorithm was identified, what input it consumed, what key/IV/nonce material was extracted, what's the confidence of the overall recovery. Cite the **single most load-bearing** `[H<n>]`.

## 2. Algorithm identification

- **Primary algorithm**: `<name>` [H<n>]
- **Mode / variant**: `<CBC / GCM / CTR / raw block / modified>` [H<n>]
- **Block / digest size**: `<bytes>`
- **Round count**: `<observed>` vs `<spec>` — match / **mismatch (modification suspected)**
- **Verdict source** (constscan / cryptoinstr / regflow / manual round-trip): `<...>`

Subsection only if modifications detected — describe each deviation from the standard with evidence.

## 3. Key schedule extraction

| Step | Source line(s) | Bytes | Interpretation |
|------|---------------|-------|----------------|
| Master key entry | `<line>` | `<hex>` | from `<source>` |
| Round key derivation | `<line range>` | `<...>` | `<algorithm>` |
| Final usage | `<line>` | — | consumed by `<round function>` |

## 4. Round function (single representative round)

Show the recovered Python or pseudo-code for one representative round, annotated with line-number anchors from the trace. If round 0 differs from round N (key whitening, etc.), document both.

## 5. Hypothesis ledger trace-back

For every `[H<n>]` cited in this report, one row:

| ID | Final confidence | Supporting evidence (tool_call_id) | Falsification evidence | Reviewer verdict |
|----|------------------|-----------------------------------|------------------------|------------------|
| H1 | high | #12, #34, #56 | #78 (refuted "AES-128 GCM hypothesis") | confirm @ #90 |

## 6. Artifacts produced

- `recovered.py` — `<path>`
- `report.md` — this file
- Any auxiliary files (test vectors, key dumps): list each

## 7. Open gaps (optional)

Things the recovery did NOT cover. Each gap should be specific enough to be actionable, not "unknown stuff remains".

---

**Formatting rules**:
- Code in fenced blocks with language hint
- Line-number citations use `line:<N>` form
- `[H<n>]` citations are bracketed; bare `H1` / `H2` are not recognised
- No "高置信推断" / "high-confidence inference" tier marker without a `[H<n>]` citation — the server gate will reject the artifact
