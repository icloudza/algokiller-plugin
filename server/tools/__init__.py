"""algokiller MCP tool layer.

Split from the original single-file `algokiller_mcp.py` into:

  - `schemas`  — JSON-Schema declarations advertised via `tools/list`.
  - `handlers` — Tool-call implementations + the `HANDLERS` dispatch
                 dictionary consumed by the JSON-RPC layer.

`algokiller_mcp.py` itself keeps only the JSON-RPC plumbing, discipline
injection, and process lifecycle.
"""

from .schemas import TOOLS
from .handlers import HANDLERS

__all__ = ["TOOLS", "HANDLERS"]
