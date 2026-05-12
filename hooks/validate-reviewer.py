#!/usr/bin/env python3
"""SubagentStop hook validator.

The hypothesis-reviewer subagent is the *only* path that can satisfy
the server-side conclude(high) gate by calling ``mark_hypothesis_reviewed``
inside its own context. If the reviewer returns without recording a
verdict, the main agent's subsequent ``hypothesis_conclude(high)`` will
fail with a confusing error message that the user has to debug.

This hook reads the ledger after every subagent stop and emits a
stderr warning when the most recent reviewer invocation did NOT
produce a fresh ``reviewer_verdict``. The warning surfaces in Claude
Code's logs and gives the main agent a chance to retry before
attempting the conclude.

We never block — this is a soft signal, not enforcement. The server
gate is the real enforcement layer.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


HOOK_DIR = Path(__file__).resolve().parent


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


def _read_stdin_json() -> dict:
    """Claude Code passes the SubagentStop hook a JSON payload on stdin
    containing at least ``subagent`` (the agent name). Tolerate
    invalid / empty input."""
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
    payload = _read_stdin_json()
    subagent = payload.get("subagent") or payload.get("subagent_type") or ""
    # Only validate reviewer stops. The other 3 algokiller subagents
    # are read-only and have no enforcement contract.
    if "hypothesis-reviewer" not in subagent:
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

    # Find the most recently reviewed hypothesis. If reviewed_at_tool_call
    # is not set on ANY hypothesis, the reviewer didn't record anything.
    reviewed = [h for h in (ledger.get("hypotheses") or [])
                if h.get("reviewed_at_tool_call")]
    if not reviewed:
        msg = ("# algokiller SubagentStop: hypothesis-reviewer returned "
               "without calling mark_hypothesis_reviewed. The next "
               "conclude(high) call WILL be rejected by the server gate. "
               "Re-spawn the reviewer and ensure it records its verdict "
               "before returning.")
        print(msg, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
