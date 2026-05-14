#!/usr/bin/env python3
"""PreCompact / Stop hook: persist a structured per-session snapshot so
the post-compact ``SessionStart`` event can rehydrate the *work
semantics*, not just the ledger's interpretation layer.

Why
---
Auto-compact silently discards the full ledger when it summarises the
conversation. Hypothesis IDs (``[H1]``, ``[H2]`` …) survive in the
narrative but the structured state they reference does not — and worse,
even the structured ledger is not enough on its own: post-compact the
model also needs to know **which tools it already ran** (to avoid
redoing work), **which paths it already ruled out** (to avoid walking
back into rejected hypotheses), and **what its current trace +
scanned ranges are** (to avoid spurious rebinds). That is what the
harness-engineering book calls *preserving work semantics* — compact's
job is not to summarise, it is to rebuild the runtime environment.

What goes to disk
-----------------

Two files, written atomically (tmp + rename) to the active session
directory:

* ``_compact_state.json`` — machine-readable, for the
  ``verify_hypothesis`` / future ``ak:status`` tooling.
* ``_compact_state.md``   — human/model-readable structured markdown.
  This is what ``session-start-compact.sh`` cat-injects into the
  post-compact context.

Contents (only what compact would otherwise drop):

* ``trace_file`` path, basename, bound mode
* ``output_dir_resolved`` + ``output_dir_source``
* **Active** hypotheses — not just concluded — with latest evidence
  offset (so the model knows what it was mid-verifying)
* Rejected paths (abandoned + archived) — to prevent walking back into
  ruled-out hypotheses
* Tool-call ledger summary — most recent N tool invocations with
  arg shape + hit count, so the model can see what's already been run
* Concluded hypotheses (the original use case)
* Artifacts already written (so the model doesn't re-emit them)

We deliberately do NOT dump raw tool outputs (hexdumps, constscan JSON,
trace_search hits) — those are the things compact SHOULD drop. The
goal is to preserve the *interpretation + execution* layers, not the
evidence layer.

Failure mode
------------
If we cannot locate the active session or read the ledger, exit 0
silently. Hooks must never make compact fail; the worst case is a
slightly more useful "I lost context" experience post-compact.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Cap the per-section size so the rehydrated context doesn't blow the
# budget post-compact. Numbers come from the harness-engineering
# book's SessionMemory thresholds (MAX_SECTION_LENGTH = 2000 chars).
MAX_RECENT_TOOL_CALLS = 8
MAX_ACTIVE_HYPOTHESES = 12
MAX_REJECTED_HYPOTHESES = 12
MAX_ARTIFACTS = 10
MAX_STATEMENT_CHARS = 240
MAX_EXCERPT_CHARS = 160
MAX_ARGS_CHARS = 160


def _find_latest_session() -> Path | None:
    """The MCP server doesn't expose its STATE to the hook process —
    they're separate Python interpreters. Find the most recently
    written session directory by scanning the user's likely artifact
    roots in order.

    The hook runs in the parent shell of the Claude client (Claude Code
    or Claude Desktop), which spawned the MCP server; we don't have a
    reliable IPC channel back to it,
    so the disk is our only source of truth. The 5-priority routing
    means sessions can land in several places.
    """
    candidates: list[Path] = []
    home = Path.home()

    # ⑤ Documents fallback
    documents = home / "Documents" / "AlgoKiller-Reports"
    if documents.is_dir():
        candidates.append(documents)

    # Also Linux XDG_DOCUMENTS_DIR
    xdg = os.environ.get("XDG_DOCUMENTS_DIR")
    if xdg:
        x = Path(os.path.expandvars(xdg)).expanduser() / "AlgoKiller-Reports"
        if x.is_dir():
            candidates.append(x)

    # ② env var
    env_root = os.environ.get("ALGOKILLER_OUTPUT_DIR")
    if env_root:
        e = Path(os.path.expandvars(env_root)).expanduser()
        if e.is_dir():
            candidates.append(e)

    # ④ project_marker layout — we don't know which project, but we can
    # search common workspaces. Cheap: walk a depth-limited glob.
    for workspace in (home / "Development", home / "Projects", home / "Code"):
        if workspace.is_dir():
            for ak_dir in workspace.glob("*/.algokiller"):
                candidates.append(ak_dir)

    # Find the most recent <trace>/<timestamp>/ leaf across all candidates.
    leaves: list[Path] = []
    for base in candidates:
        # Two-level glob: <trace>/<timestamp>/
        try:
            for trace_dir in base.iterdir():
                if not trace_dir.is_dir():
                    continue
                for ts_dir in trace_dir.iterdir():
                    if ts_dir.is_dir():
                        leaves.append(ts_dir)
        except OSError:
            continue
    if not leaves:
        return None
    leaves.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return leaves[0]


def _read_ledger(session_dir: Path) -> dict:
    """Best-effort load of the ledger JSON. Schema mirrors what
    ``server/hypothesis.py`` writes; we only consume what compact needs."""
    ledger_path = session_dir / "ledger.json"
    if not ledger_path.is_file():
        return {}
    try:
        return json.loads(ledger_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _read_tool_call_log(session_dir: Path, limit: int) -> list[dict]:
    """Walk the tool_call_log/ directory in reverse-id order and return
    up to ``limit`` of the most recent calls in a compact shape.

    Each ToolCallLog record is ``{id, tool_name, args, result_text,
    result_sha256}`` (see ``server/hypothesis.py:ToolCallLog``). We
    drop the bulky ``result_text`` here — only the call shape matters
    for the "did I already run this?" check. We also extract one
    coarse hit signal (``hits`` / ``total_hits`` / ``len(results)``)
    from result_text where it's cheap to do so.
    """
    log_dir = session_dir / "tool_call_log"
    if not log_dir.is_dir():
        return []
    files = sorted(log_dir.glob("*.json"),
                   key=lambda p: p.name, reverse=True)[:limit]
    out: list[dict] = []
    for f in files:
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        args = rec.get("args") or {}
        # Drop verbose args and stringify a one-liner. Real args here
        # are usually {query: "...", limit: N, from_line: K} — < 100 chars.
        args_short = json.dumps(args, ensure_ascii=False,
                                separators=(",", ":"))[:MAX_ARGS_CHARS]
        # Cheap hit-count signal from the cached result_text JSON
        # without re-parsing it fully (it can be huge for trace_search).
        result_text = rec.get("result_text") or ""
        hits = None
        # These keys appear at the JSON top level for the major scan
        # tools — a substring probe is good enough for a snapshot.
        for key in ('"total_hits":', '"hits":', '"matches":'):
            idx = result_text.find(key)
            if idx >= 0:
                # parse the integer that follows, best-effort
                tail = result_text[idx + len(key): idx + len(key) + 16]
                digits = ""
                for ch in tail.lstrip():
                    if ch.isdigit():
                        digits += ch
                    else:
                        break
                if digits:
                    try:
                        hits = int(digits)
                    except ValueError:
                        pass
                    break
        out.append({
            "id": rec.get("id"),
            "tool": rec.get("tool_name"),
            "args": args_short,
            "hits": hits,
        })
    # log_dir glob() returns most-recent-first by filename (zero-padded
    # ids), so out[] is also most-recent-first. Reverse so the snapshot
    # reads chronologically — easier for the model to follow.
    out.reverse()
    return out


def _evidence_anchor(ev: dict) -> str:
    """Best-effort extract a short anchor (line / offset / call id) from
    a hypothesis evidence item. Used in the markdown rendering so the
    model can re-locate the evidence quickly without re-running tools."""
    if not isinstance(ev, dict):
        return ""
    pieces: list[str] = []
    tcid = ev.get("tool_call_id")
    if tcid:
        pieces.append(f"tc#{tcid}")
    excerpt = (ev.get("excerpt") or "")[:MAX_EXCERPT_CHARS]
    if excerpt:
        # collapse whitespace so the snapshot stays one-line per evidence
        excerpt = " ".join(excerpt.split())
        pieces.append(f'"{excerpt}"')
    return " ".join(pieces)


def _summarise(session_dir: Path, ledger: dict) -> dict:
    """Build the post-compact context payload. Target < 8 KB so it
    slips into the rehydrated context without pushing the model back
    over the budget. Section caps enforced by MAX_* constants above."""
    hypos = ledger.get("hypotheses") or []

    concluded: list[dict] = []
    active: list[dict] = []
    rejected: list[dict] = []
    for h in hypos:
        state = h.get("state")
        if state == "concluded":
            concluded.append({
                "id": h.get("id"),
                "confidence": h.get("final_confidence") or h.get("confidence"),
                "statement": (h.get("final_statement") or h.get("statement")
                              or "")[:MAX_STATEMENT_CHARS],
            })
        elif state == "active":
            # For active hypotheses the most useful thing post-compact is
            # the latest evidence anchor — that's what tells the model
            # what it was mid-verifying. Pick the last supporting evidence.
            supporting = h.get("supporting") or []
            latest = supporting[-1] if supporting else None
            active.append({
                "id": h.get("id"),
                "confidence": h.get("confidence"),
                "statement": (h.get("statement") or "")[:MAX_STATEMENT_CHARS],
                "latest_evidence": _evidence_anchor(latest) if latest else "",
                "supporting_count": len(supporting),
            })
        elif state in ("abandoned", "archived"):
            rejected.append({
                "id": h.get("id"),
                "state": state,
                "statement": (h.get("statement") or "")[:MAX_STATEMENT_CHARS],
                "reason": (h.get("abandon_reason") or h.get("archive_reason")
                           or "")[:MAX_STATEMENT_CHARS],
            })

    # Apply caps. Keep MOST RECENTLY UPDATED items by walking the input
    # list in reverse — ledger appends, so end ≈ newest.
    concluded = concluded[-MAX_ACTIVE_HYPOTHESES:]
    active = active[-MAX_ACTIVE_HYPOTHESES:]
    rejected = rejected[-MAX_REJECTED_HYPOTHESES:]

    artifacts: list[str] = []
    for p in sorted(session_dir.glob("*"), key=lambda x: x.stat().st_mtime):
        if p.is_file() and p.suffix in {".py", ".md"} and p.name not in {
                "ledger.json", "_compact_state.json", "_compact_state.md",
                "session-summary.md"}:
            artifacts.append(p.name)

    recent_tools = _read_tool_call_log(session_dir, MAX_RECENT_TOOL_CALLS)

    # Try to recover trace_file + mode from the ledger (it stamps them
    # at bind time) or from the session directory name (the parent is
    # the trace basename).
    trace_basename = session_dir.parent.name

    return {
        "schema": 2,                                            # bumped from 1
        "stamped_at": datetime.now().isoformat(timespec="seconds"),
        "session_dir": str(session_dir),
        "trace_basename": trace_basename,
        "active_hypotheses": active,
        "concluded_hypotheses": concluded,
        "rejected_hypotheses": rejected,
        "recent_tool_calls": recent_tools,
        "artifacts_written": artifacts[-MAX_ARTIFACTS:],
    }


def _render_markdown(payload: dict) -> str:
    """Render the snapshot as structured markdown for SessionStart
    injection. Markdown beats JSON-in-codefence because the model
    actually reads the section headers; JSON-in-codefence tends to get
    scanned past as "raw data."
    """
    lines: list[str] = []
    lines.append("## Pre-compact session snapshot")
    lines.append("")
    lines.append("Re-attached after compact so ledger / tool-call references "
                 "in the conversation summary still resolve. Treat each "
                 "section as authoritative structured evidence from disk, "
                 "**not** as part of the compactor's narrative.")
    lines.append("")
    lines.append(f"- **Session directory**: `{payload['session_dir']}`")
    lines.append(f"- **Trace basename**: `{payload['trace_basename']}`")
    lines.append(f"- **Snapshot taken**: {payload['stamped_at']}")
    lines.append("")

    active = payload.get("active_hypotheses") or []
    lines.append("### Active Hypotheses (mid-verification)")
    if not active:
        lines.append("_None — every hypothesis is either concluded or rejected._")
    else:
        lines.append("")
        lines.append("| ID | Confidence | Statement | Latest evidence anchor |")
        lines.append("|---|---|---|---|")
        for h in active:
            lines.append(f"| {h['id']} | {h.get('confidence', '?')} | "
                         f"{h.get('statement', '').replace('|', '\\|')} | "
                         f"{h.get('latest_evidence', '').replace('|', '\\|')} |")
    lines.append("")

    concluded = payload.get("concluded_hypotheses") or []
    lines.append("### Concluded Hypotheses")
    if not concluded:
        lines.append("_None concluded yet._")
    else:
        lines.append("")
        lines.append("| ID | Confidence | Statement |")
        lines.append("|---|---|---|")
        for h in concluded:
            lines.append(f"| {h['id']} | {h.get('confidence', '?')} | "
                         f"{h.get('statement', '').replace('|', '\\|')} |")
    lines.append("")

    rejected = payload.get("rejected_hypotheses") or []
    lines.append("### Rejected Paths (do not walk back into)")
    if not rejected:
        lines.append("_None abandoned or archived._")
    else:
        lines.append("")
        lines.append("| ID | State | Statement | Reason |")
        lines.append("|---|---|---|---|")
        for h in rejected:
            lines.append(f"| {h['id']} | {h['state']} | "
                         f"{h.get('statement', '').replace('|', '\\|')} | "
                         f"{h.get('reason', '').replace('|', '\\|')} |")
    lines.append("")

    recent = payload.get("recent_tool_calls") or []
    lines.append("### Tool Call Ledger (recent — do not redo)")
    if not recent:
        lines.append("_No tool calls recorded yet._")
    else:
        lines.append("")
        lines.append("| Call # | Tool | Args | Hits |")
        lines.append("|---|---|---|---|")
        for c in recent:
            hits_repr = "—" if c.get("hits") is None else str(c["hits"])
            lines.append(f"| {c.get('id', '?')} | "
                         f"`{c.get('tool', '?')}` | "
                         f"`{c.get('args', '').replace('|', '\\|')}` | "
                         f"{hits_repr} |")
    lines.append("")

    artifacts = payload.get("artifacts_written") or []
    lines.append("### Artifacts Already Written")
    if not artifacts:
        lines.append("_None._")
    else:
        for a in artifacts:
            lines.append(f"- `{a}`")
    lines.append("")
    lines.append("### Next-step discipline")
    lines.append("")
    lines.append("**C1**: First tool call after compact MUST be "
                 "`hypothesis_list` — verify the ledger matches this snapshot "
                 "before resuming. See `context/critical-rules.md` §5.")
    lines.append("")
    return "\n".join(lines)


def _atomic_write(path: Path, content: str) -> None:
    """Write atomically so a SIGINT mid-write doesn't leave a half-file
    on disk that the next post-compact rehydrate will trip on."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def main() -> int:
    try:
        session_dir = _find_latest_session()
    except Exception as exc:
        print(f"# algokiller dump-session-state: locate failed ({exc})",
              file=sys.stderr)
        return 0
    if session_dir is None:
        # No session bound — nothing to preserve. Normal early exit.
        return 0

    try:
        ledger = _read_ledger(session_dir)
        payload = _summarise(session_dir, ledger)
        # Both files in the session dir — JSON for verify_hypothesis /
        # ak:status to read programmatically, MD for the post-compact
        # SessionStart hook to cat-inject into context.
        _atomic_write(
            session_dir / "_compact_state.json",
            json.dumps(payload, indent=2, ensure_ascii=False))
        _atomic_write(
            session_dir / "_compact_state.md",
            _render_markdown(payload))
    except Exception as exc:
        print(f"# algokiller dump-session-state: write failed ({exc})",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
