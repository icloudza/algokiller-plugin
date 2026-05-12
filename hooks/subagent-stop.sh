#!/usr/bin/env bash
# SubagentStop hook — runs whenever a subagent returns.
#
# Algokiller spawns 4 subagents: hypothesis-reviewer (the one that MUST
# call mark_hypothesis_reviewed before returning) plus 3 read-only
# helpers added in 1.0.0. We only want to validate the reviewer here.
#
# Failure mode: a hypothesis-reviewer that returns without calling
# mark_hypothesis_reviewed silently breaks the conclude(high) gate.
# We can't observe tool calls from a shell hook directly, but the
# hook payload carries the subagent's identifier (when available)
# and the ledger's reviewed_at_tool_call field is the canonical
# source of truth. We delegate validation to a small Python script
# rather than parse JSON in shell.
set -u
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 "${PLUGIN_ROOT}/hooks/validate-reviewer.py" || true
exit 0
