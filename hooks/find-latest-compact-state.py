#!/usr/bin/env python3
"""Print the absolute path of the most recently written
``_compact_state.json`` across all algokiller session directories.

Used by ``session-start-compact.sh`` to locate the dump produced by
``dump-session-state.py`` just before compact happened. Reuses the
session-lookup logic from ``dump-session-state.py`` to keep the
candidate-roots policy in one place.
"""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    hook_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(hook_dir))
    try:
        from importlib import import_module
        mod = import_module("dump-session-state".replace("-", "_"))
        # ``dump-session-state.py`` isn't a normal module name — the
        # hyphenated form can't be imported. Instead, exec it.
    except Exception:
        pass

    # Direct exec of the sibling script: simpler than aliasing the file.
    helper = hook_dir / "dump-session-state.py"
    if not helper.is_file():
        return 0
    namespace: dict = {}
    try:
        exec(helper.read_text(encoding="utf-8"), namespace)  # noqa: S102
    except Exception:
        return 0
    finder = namespace.get("_find_latest_session")
    if not callable(finder):
        return 0
    try:
        session_dir = finder()
    except Exception:
        return 0
    if session_dir is None:
        return 0
    dump = Path(session_dir) / "_compact_state.json"
    if dump.is_file():
        print(str(dump))
    return 0


if __name__ == "__main__":
    sys.exit(main())
