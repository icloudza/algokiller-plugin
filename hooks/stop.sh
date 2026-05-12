#!/usr/bin/env bash
# Stop hook — runs when the conversation/session ends.
#
# Writes a session-summary.md into the active session directory so the
# user (and any future agent reading the artifact tree) has a stable
# disk record of:
#   * all concluded hypotheses with their final confidences
#   * all artifacts written during the session
#   * any still-active (un-concluded) hypotheses as open threads
#
# This is the disk-resident counterpart to the ledger-curator subagent
# (which the main agent may or may not have spawned). Belt-and-braces:
# even if the curator wasn't invoked, the user still gets a summary.
set -u
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 "${PLUGIN_ROOT}/hooks/write-session-summary.py" || true
exit 0
