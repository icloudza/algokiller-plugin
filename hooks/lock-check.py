#!/usr/bin/env python3
"""PreCompact gate: refuse compact while a long algokiller scan holds the
cross-process advisory lock.

The kernel does the heavy lifting (``server/locks.py`` documents why);
this script just exit-codes:

    0  no scan in progress, compact may proceed
    2  scan in progress, block compact

Any other failure (lock file unreadable, ImportError, etc.) is treated
as "fail open" — we'd rather lose ledger state on rare bugs than
permanently brick the user's compact flow.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _server_dir() -> Path:
    """Locate the plugin's server/ directory regardless of how the hook
    was invoked. Two possibilities:

    1. ``CLAUDE_PLUGIN_ROOT`` is set by Claude Code → server is
       ``$CLAUDE_PLUGIN_ROOT/server``.
    2. Fallback: walk up from this script's parent (hooks/) → ../server.
    """
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if plugin_root:
        candidate = Path(plugin_root) / "server"
        if candidate.is_dir():
            return candidate
    return (Path(__file__).resolve().parent.parent / "server").resolve()


def main() -> int:
    try:
        sys.path.insert(0, str(_server_dir()))
        from locks import is_scan_in_progress  # type: ignore
    except Exception as exc:
        # Don't block compact if the import fails — would brick the user.
        print(f"# algokiller lock-check: import failed ({exc}); fail-open",
              file=sys.stderr)
        return 0

    try:
        state = is_scan_in_progress()
    except Exception as exc:
        print(f"# algokiller lock-check: probe failed ({exc}); fail-open",
              file=sys.stderr)
        return 0

    if not state.get("in_progress"):
        # Fast path. Optionally surface the failsafe warning so power
        # users notice if the in-kernel signal disagreed with PID liveness.
        warn = state.get("warning")
        if warn:
            print(f"# algokiller lock-check: {warn}", file=sys.stderr)
        return 0

    # Lock held → block compact.
    response = {
        "decision": "block",
        "reason": ("algokiller: a long-running scan (constscan / "
                   "cryptoinstr) is in progress. Auto-compact would "
                   "discard ledger references mid-scan. Wait for the "
                   "scan to finish, then run /compact manually."),
        "holder_pid": state.get("holder_pid"),
    }
    print(json.dumps(response), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
