"""Cross-platform native directory picker for the `pick_output_dir` MCP tool.

The plugin's primary battleground is GUI clients (Claude Desktop, Cursor,
Codex). When the user wants to choose a report destination interactively,
they say so; the agent calls `pick_output_dir(initial_dir=...)`, which
shells out to the host's native folder picker:

    macOS    osascript `choose folder` (Finder dialog)
    Windows  PowerShell System.Windows.Forms.FolderBrowserDialog
    Linux    zenity --file-selection --directory  (GNOME / generic)
             kdialog --getexistingdirectory      (KDE fallback)

Web / headless / unrecognised platforms return `{"status":"unsupported"}`
with a hint pointing at `bind_trace(output_dir=...)` for explicit path
injection.

Cancellation is a normal outcome (user clicks Cancel) — returns
`{"status":"cancelled"}`, not an error. Errors are reserved for actual
failures (missing tool, dialog crash).

Timeout 120s — if the user walks away the call returns
`{"status":"timeout"}` and the agent can retry.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


PICKER_TIMEOUT_SECONDS = 120


def _macos_pick(initial_dir: Optional[Path]) -> dict:
    """osascript folder picker. `initial_dir` becomes the default location
    when the dialog opens. We `activate` first to bring the dialog in
    front of Claude Desktop / the calling app."""
    if initial_dir is not None and initial_dir.is_dir():
        default_loc = f' default location (POSIX file "{initial_dir}")'
    else:
        default_loc = ""
    script = (
        'activate\n'
        f'set chosenFolder to (choose folder with prompt '
        f'"Choose a directory for AlgoKiller analysis reports"'
        f'{default_loc})\n'
        'return POSIX path of chosenFolder'
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True,
            timeout=PICKER_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return {"status": "unsupported",
                "reason": "osascript not found (unusual macOS install)"}
    except subprocess.TimeoutExpired:
        return {"status": "timeout",
                "reason": f"no selection within {PICKER_TIMEOUT_SECONDS}s"}
    if result.returncode == 0:
        path = result.stdout.strip()
        if path:
            # Use abspath, NOT .resolve() — osascript may return /tmp/foo
            # and the user expects /tmp/foo back, not /private/tmp/foo
            # (macOS symlinks /tmp -> /private/tmp). abspath only
            # canonicalises (.., empty segments) without chasing symlinks.
            import os as _os
            return {"status": "ok", "path": _os.path.abspath(path)}
        return {"status": "cancelled",
                "reason": "osascript returned empty path"}
    stderr = (result.stderr or "").strip()
    if "User canceled" in stderr or "User cancelled" in stderr:
        return {"status": "cancelled", "reason": "user cancelled dialog"}
    return {"status": "error",
            "reason": stderr or f"osascript exit {result.returncode}"}


def _windows_pick(initial_dir: Optional[Path]) -> dict:
    initial = ""
    if initial_dir is not None and initial_dir.is_dir():
        # PowerShell wants escaped backslashes.
        initial = str(initial_dir).replace("\\", "\\\\")
        initial = f'$dlg.SelectedPath = "{initial}"\n'
    script = (
        'Add-Type -AssemblyName System.Windows.Forms\n'
        '$dlg = New-Object System.Windows.Forms.FolderBrowserDialog\n'
        '$dlg.Description = "Choose a directory for AlgoKiller analysis reports"\n'
        '$dlg.ShowNewFolderButton = $true\n'
        f'{initial}'
        'if ($dlg.ShowDialog() -eq "OK") { Write-Output $dlg.SelectedPath } '
        'else { exit 1 }'
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True,
            timeout=PICKER_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return {"status": "unsupported",
                "reason": "powershell not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"status": "timeout",
                "reason": f"no selection within {PICKER_TIMEOUT_SECONDS}s"}
    if result.returncode == 0:
        path = result.stdout.strip()
        if path:
            import os as _os
            return {"status": "ok", "path": _os.path.abspath(path)}
        return {"status": "cancelled", "reason": "empty selection"}
    # rc=1 is our cancel signal from the script above.
    if result.returncode == 1 and not (result.stderr or "").strip():
        return {"status": "cancelled", "reason": "user cancelled dialog"}
    return {"status": "error",
            "reason": (result.stderr or "").strip()
                      or f"powershell exit {result.returncode}"}


def _linux_pick(initial_dir: Optional[Path]) -> dict:
    """Try zenity (GNOME, default on most distros), fall back to kdialog.

    On headless / no-DISPLAY systems both tools either are absent or fail
    immediately; we report `unsupported` so the agent can ask the user
    for the path conversationally instead.
    """
    initial = str(initial_dir) if (initial_dir and initial_dir.is_dir()) else None

    if shutil.which("zenity"):
        cmd = [
            "zenity", "--file-selection", "--directory",
            "--title=Choose AlgoKiller output directory",
        ]
        if initial is not None:
            cmd.append(f"--filename={initial}/")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=PICKER_TIMEOUT_SECONDS, check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout",
                    "reason": f"no selection within {PICKER_TIMEOUT_SECONDS}s"}
        if result.returncode == 0:
            path = result.stdout.strip()
            if path:
                import os as _os
            return {"status": "ok", "path": _os.path.abspath(path)}
            return {"status": "cancelled", "reason": "empty selection"}
        # zenity returns 1 on cancel, >1 on error. Both with possibly empty stderr.
        if result.returncode == 1:
            return {"status": "cancelled", "reason": "user cancelled dialog"}
        # fall through to try kdialog if zenity bailed unexpectedly

    if shutil.which("kdialog"):
        cmd = ["kdialog", "--getexistingdirectory"]
        cmd.append(initial or str(Path.home()))
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=PICKER_TIMEOUT_SECONDS, check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout",
                    "reason": f"no selection within {PICKER_TIMEOUT_SECONDS}s"}
        if result.returncode == 0:
            path = result.stdout.strip()
            if path:
                import os as _os
            return {"status": "ok", "path": _os.path.abspath(path)}
            return {"status": "cancelled", "reason": "empty selection"}
        if result.returncode == 1:
            return {"status": "cancelled", "reason": "user cancelled dialog"}

    return {"status": "unsupported",
            "reason": ("no GUI picker available on this Linux system "
                       "(zenity / kdialog not installed). Pass output_dir "
                       "to bind_trace explicitly.")}


def pick_directory(initial_dir: Optional[Path] = None) -> dict:
    """Pop the host's native folder picker. Returns one of:

        {"status": "ok", "path": "/abs/path"}
        {"status": "cancelled", "reason": "..."}
        {"status": "timeout", "reason": "..."}
        {"status": "unsupported", "reason": "..."}
        {"status": "error", "reason": "..."}

    Agents should:
      - cancelled / timeout → not an error, just no path returned; ask user
      - unsupported         → tell the user to pass output_dir to bind_trace
      - error               → report verbatim, then ask user for the path
    """
    if sys.platform == "darwin":
        return _macos_pick(initial_dir)
    if sys.platform.startswith("win"):
        return _windows_pick(initial_dir)
    if sys.platform.startswith("linux"):
        return _linux_pick(initial_dir)
    return {"status": "unsupported",
            "reason": f"unrecognised platform {sys.platform!r}; "
                      "pass output_dir to bind_trace explicitly."}
