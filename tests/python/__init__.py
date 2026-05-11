"""Python unit tests for the algokiller MCP server.

Tests use the standard-library `unittest` framework — no `pytest` or
other third-party dependency required. Run from the repo root:

    python3 -m unittest discover -s tests/python -v
"""

import sys
from pathlib import Path

# Make `server/` importable without installing the package, so tests can
# do `from hypothesis import HypothesisLedger` etc.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SERVER = _REPO_ROOT / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))
