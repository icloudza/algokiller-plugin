"""Session-level state for the algokiller MCP server.

Holds the bound trace file, ak_search daemon handle, the analysis mode,
the per-session artifacts directory, and a monotonic tool-call counter
used by the discipline reinjection mechanism.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Optional


_HERE = Path(__file__).resolve()
PLUGIN_ROOT = Path(os.environ.get("ALGOKILLER_PLUGIN_ROOT") or _HERE.parent.parent).resolve()
# ak_search lives under server/bin/ (NOT plugin-root bin/) so the executable
# is NOT auto-injected into Claude's Bash tool PATH. All access must go
# through the MCP server's tools, which preserves daemon reuse and discipline
# reinjection. See README "Design rationale".
AK_SEARCH_BIN = PLUGIN_ROOT / "server" / "bin" / "ak_search"
ARTIFACTS_ROOT = Path.home() / "AlgoKiller" / "artifacts"


class SessionState:
    def __init__(self) -> None:
        self.trace_file: Optional[Path] = None
        self.trace_basename: Optional[str] = None
        self.mode: str = "unknown"
        self.daemon = None
        self.tool_call_count: int = 0
        self.artifacts_dir: Optional[Path] = None

    def bind(self, trace_path: Path, mode: str) -> None:
        self.trace_file = trace_path
        self.trace_basename = trace_path.stem
        self.mode = mode
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.artifacts_dir = ARTIFACTS_ROOT / self.trace_basename / timestamp
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def bump_tool_call(self) -> int:
        self.tool_call_count += 1
        return self.tool_call_count


STATE = SessionState()
