#!/usr/bin/env python3
"""PreCompact / Stop hook: persist the per-session ledger summary so it
can be re-injected on the post-compact ``SessionStart`` event.

Why
---
Auto-compact silently discards the full ledger when it summarises the
conversation. Hypothesis IDs (``[H1]``, ``[H2]`` …) survive in the
narrative but the structured ledger they reference does not, so the
v0.9.3 write_artifact gate can spuriously reject a deliverable that
was perfectly valid pre-compact. Dumping the ledger state to disk
before compact, then ``cat``-ing the relevant slice back on
``SessionStart(matcher=compact)``, closes that loop.

What goes to disk
-----------------
A compact-friendly JSON summary stored at:

    <artifacts_dir>/_compact_state.json

Contents (only what compact would otherwise drop):

* trace_file path, basename, mode
* output_dir_resolved + output_dir_source
* concluded hypotheses with ``id`` + ``confidence`` + ``final_statement``
* the most recent ledger ``state`` snapshot timestamp

We deliberately do NOT dump raw tool outputs (hexdumps, constscan JSON,
trace_search hits) — those are the things compact SHOULD drop. The
goal is to preserve the *interpretation layer*, not the evidence layer.

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


def _find_latest_session() -> Path | None:
    """The MCP server doesn't expose its STATE to the hook process —
    they're separate Python interpreters. Find the most recently
    written session directory by scanning the user's likely artifact
    roots in order.

    The hook runs in the parent shell of Claude Desktop, which spawned
    the MCP server; we don't have a reliable IPC channel back to it,
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


def _summarise(session_dir: Path, ledger: dict) -> dict:
    """Build the post-compact context payload. Keep it compact —
    target < 4 KB so it slips into the rehydrated context without
    pushing the model back over the budget."""
    hypotheses = []
    for h in (ledger.get("hypotheses") or []):
        if h.get("state") != "concluded":
            continue
        hypotheses.append({
            "id": h.get("id"),
            "confidence": h.get("final_confidence") or h.get("confidence"),
            "statement": (h.get("final_statement") or h.get("statement") or "")[:240],
        })

    # Find any artifacts already written so the agent doesn't re-write them.
    artifacts = []
    for p in sorted(session_dir.glob("*"), key=lambda x: x.stat().st_mtime):
        if p.is_file() and p.suffix in {".py", ".md"} and p.name not in {
                "ledger.json", "_compact_state.json", "session-summary.md"}:
            artifacts.append(p.name)

    return {
        "schema": 1,
        "stamped_at": datetime.now().isoformat(timespec="seconds"),
        "session_dir": str(session_dir),
        "trace_basename": session_dir.parent.name,
        "concluded_hypotheses": hypotheses,
        "artifacts_written": artifacts[-10:],  # keep the slice tight
    }


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
        out_path = session_dir / "_compact_state.json"
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                            encoding="utf-8")
    except Exception as exc:
        print(f"# algokiller dump-session-state: write failed ({exc})",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
