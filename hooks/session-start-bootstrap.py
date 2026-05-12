#!/usr/bin/env python3
"""SessionStart bootstrap (matchers: startup | resume).

Two responsibilities:

1. **Auto-install ``pyright``** so the ``.lsp.json`` config the plugin
   ships works out of the box. The user opted into this behavior
   (see CHANGELOG 1.0.0 — "auto-install Python LSP"); we do it idempotently
   per session start and emit a one-line stderr notice the FIRST time
   we install so the user knows what happened. Subsequent sessions
   see ``pyright`` already on PATH and exit quietly.

2. **Diagnose obvious environment gaps** (Python <3.11, missing
   ``ak_search`` binary, missing ``fcntl`` on Windows = lock disabled)
   and surface them once per session via stderr so users don't get
   bitten mid-analysis.

Failures here MUST NOT block session start — we always exit 0.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


MARKER_DIR = Path.home() / ".algokiller"
PYRIGHT_NOTICE_MARKER = MARKER_DIR / ".pyright-install-notified"


def _ensure_marker_dir() -> None:
    try:
        MARKER_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


def _check_pyright() -> None:
    """Install pyright if missing. Uses ``pip install --user`` so we
    don't pollute the system site-packages. If pip itself is missing
    or both ``pyright`` and ``pyright-langserver`` are already on PATH,
    do nothing.
    """
    if shutil.which("pyright-langserver") or shutil.which("pyright"):
        return
    if not shutil.which("pip3") and not shutil.which("pip"):
        # Can't install — emit guidance once and stop.
        if not PYRIGHT_NOTICE_MARKER.exists():
            print("# algokiller: pyright not found and `pip` is also "
                  "missing. The bundled .lsp.json relies on pyright for "
                  "type feedback on recovered.py decoders. Install "
                  "manually: `npm install -g pyright` or "
                  "`pip install pyright`.", file=sys.stderr)
            _ensure_marker_dir()
            try:
                PYRIGHT_NOTICE_MARKER.touch()
            except OSError:
                pass
        return

    # Auto-install via pip --user. Quiet by default; we capture output
    # so a session start doesn't dump 50 lines of pip noise into the
    # Claude Code log.
    pip_cmd = ["pip3", "install", "--user", "--quiet", "pyright"]
    try:
        result = subprocess.run(pip_cmd, capture_output=True, text=True,
                                timeout=120)
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"# algokiller: pyright auto-install failed ({exc}). "
              "Run `pip3 install --user pyright` manually if you want "
              "type-checking on recovered Python decoders.",
              file=sys.stderr)
        return
    if result.returncode != 0:
        print("# algokiller: pyright auto-install failed:",
              file=sys.stderr)
        print((result.stderr or "").strip().splitlines()[-1:][0] if (result.stderr or "").strip() else "(no stderr)",
              file=sys.stderr)
        return

    # Success — notify once per host.
    _ensure_marker_dir()
    if not PYRIGHT_NOTICE_MARKER.exists():
        print("# algokiller: auto-installed pyright (Python LSP) via "
              "`pip3 install --user pyright`. This powers type "
              "feedback on recovered.py decoders edited in this "
              "session. To uninstall later: `pip3 uninstall pyright`.",
              file=sys.stderr)
        try:
            PYRIGHT_NOTICE_MARKER.touch()
        except OSError:
            pass


def _diagnose_environment() -> None:
    """Best-effort sanity checks. All warnings, no blocking."""
    py = sys.version_info
    if (py.major, py.minor) < (3, 11):
        print(f"# algokiller: Python {py.major}.{py.minor} detected; "
              "plugin requires 3.11+ (tomllib + Optional[X] syntax). "
              "Some features will silently misbehave.", file=sys.stderr)

    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.environ.get(
        "ALGOKILLER_PLUGIN_ROOT")
    if plugin_root:
        ak_bin = Path(plugin_root) / "server" / "bin" / "ak_search"
        if not ak_bin.exists():
            print(f"# algokiller: ak_search binary missing at {ak_bin}. "
                  "Rebuild via `cd tools/search && make && cp ak_search "
                  "../../server/bin/`.", file=sys.stderr)

    if sys.platform.startswith("win"):
        try:
            import msvcrt  # noqa: F401
        except ImportError:
            print("# algokiller: msvcrt not importable on this Windows "
                  "Python; PreCompact scan-lock will be disabled.",
                  file=sys.stderr)


def main() -> int:
    try:
        _check_pyright()
        _diagnose_environment()
    except Exception as exc:
        print(f"# algokiller bootstrap: unexpected error ({exc}); "
              "session continues regardless.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
