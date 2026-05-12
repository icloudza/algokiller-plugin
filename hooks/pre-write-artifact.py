#!/usr/bin/env python3
"""PreToolUse hook for ``write_artifact``: warn (don't block) when the
draft content has fewer `[H<n>]` citations than the ledger has
concluded hypotheses.

The server-side gate (``v0.9.3`` bypass-detection) rejects deliverables
that omit concluded hypotheses. Catching this client-side gives the
agent a chance to fix the gap before the rejected call burns a round
trip; we emit a stderr warning the agent can read.

We don't BLOCK because:
* sometimes the agent intentionally archived hypotheses just before
  ``write_artifact`` and the disk ledger doesn't yet reflect that —
  blocking would fight the agent
* false-positive grep on `[H<n>]` is possible (e.g. inside a code
  block that happens to mention Python's `H1` variable)

The hook reads the tool's JSON payload from stdin, extracts the
``content`` field, greps for ``[H<n>]`` markers, and compares the set
of cited IDs to the ledger's concluded set. Mismatch → warn.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


HOOK_DIR = Path(__file__).resolve().parent
CITATION_RE = re.compile(r"\[H(\d+)\]", re.IGNORECASE)


def _load_helper():
    helper = HOOK_DIR / "dump-session-state.py"
    if not helper.is_file():
        return None
    ns: dict = {}
    try:
        exec(helper.read_text(encoding="utf-8"), ns)  # noqa: S102
    except Exception:
        return None
    return ns


def _read_tool_payload() -> dict:
    """Claude Code's PreToolUse hook passes a JSON object on stdin
    containing ``tool_name`` and ``tool_input``. We only act when
    ``tool_name`` matches a write_artifact path (it carries the
    server's MCP prefix). Tolerate any shape."""
    try:
        raw = sys.stdin.read()
    except OSError:
        return {}
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {}


def main() -> int:
    payload = _read_tool_payload()
    name = (payload.get("tool_name") or "").lower()
    if "write_artifact" not in name:
        # Different tool; PreToolUse runs for every Bash + MCP call.
        return 0
    content = (payload.get("tool_input") or {}).get("content")
    if not isinstance(content, str) or not content:
        return 0

    helper = _load_helper()
    if helper is None:
        return 0
    finder = helper.get("_find_latest_session")
    reader = helper.get("_read_ledger")
    if not (callable(finder) and callable(reader)):
        return 0
    try:
        session_dir = finder()
        ledger = reader(session_dir) if session_dir else {}
    except Exception:
        return 0

    concluded_ids = {h.get("id") for h in (ledger.get("hypotheses") or [])
                     if h.get("state") == "concluded" and h.get("id")}
    if not concluded_ids:
        # No concluded hypotheses yet → no citation requirement.
        return 0

    cited_ids = set()
    for m in CITATION_RE.finditer(content):
        cited_ids.add(f"H{int(m.group(1))}")

    missing = concluded_ids - cited_ids
    if not missing:
        return 0

    # Warning to stderr — visible in Claude Code logs / debug pane,
    # gives the agent a chance to either archive or cite before the
    # server gate rejects the call.
    warn = {
        "stage": "pre-write-artifact",
        "warning": (f"draft cites {sorted(cited_ids)} but ledger has "
                    f"concluded hypotheses {sorted(concluded_ids)}; "
                    f"missing citations for {sorted(missing)}. The "
                    "server's v0.9.3 bypass-detection gate will reject "
                    "this write_artifact unless those hypotheses are "
                    "either cited or archived. Re-check the draft or "
                    "run hypothesis_archive on truly-unrelated ones."),
    }
    print(json.dumps(warn), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
