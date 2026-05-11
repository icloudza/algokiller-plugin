"""Allow-listed read-only static-analysis CLI runner.

Why this module exists:
    Claude Desktop has a Bash tool, but exposing arbitrary shell to a plugin
    is risky and prompt-hard. This wrapper exposes a CURATED set of read-only
    binary-analysis CLIs (radare2 family, GNU binutils, LLVM tools, Mach-O /
    iOS specific, ripgrep, jq) through ONE MCP tool — `algokiller.run_static_tool`.

Safety design (defense in depth):
    1. argv-list execution (subprocess.run([tool, *args], ...)) — never goes
       through /bin/sh, so command injection via metacharacters is impossible.
    2. Hard tool allow-list (enum at the MCP schema layer AND re-checked here).
    3. Per-tool guard policies:
         - r2 must include -q -2 -n + -c "<cmd>", forbid -A/-AA/-AAA, and the
           -c command string is scanned for the full-analysis verbs (aaa/aac/...).
         - Other tools have per-tool forbidden_args / required_args policies.
    4. Per-tool timeouts (r2 / objdump / class-dump get longer budgets).
    5. Output truncation (stdout 30000 chars; stderr last 4000 chars).
    6. UTF-8 surrogate scrub on output (same policy as ak_search daemon).
    7. NUL byte rejected in args.

Boundary policy with r2 (CRITICAL):
    r2 defaults to running `aaa` on load which is unusable on multi-MB binaries
    (minutes to hours on GB-scale). This wrapper FORCES `-n` (skip RBin) and
    rejects `-A`/`aaa` family. r2 is only allowed in single-command mode via
    `-c "<bounded command>"`. The fast path is: BN MCP for full decompile,
    r2 only for spot disassembly (`pd N @ addr`) or info commands (`iI`/`iS`).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Tool registry — every entry must include timeout (seconds) and category.
# `guard` triggers per-tool argument validation (currently used by r2).
# `forbid_args` blocks individual flags (substring match against any arg).
# ---------------------------------------------------------------------------

ALLOWED_TOOLS: dict[str, dict[str, Any]] = {
    # Tier A — instant (milliseconds)
    "file":          {"timeout": 10, "category": "metadata"},
    "rax2":          {"timeout": 5,  "category": "convert"},
    "rg":            {"timeout": 30, "category": "search"},
    "jq":            {"timeout": 30, "category": "json"},
    "strings":       {"timeout": 30, "category": "strings"},
    "c++filt":       {"timeout": 10, "category": "demangle"},
    "llvm-cxxfilt":  {"timeout": 10, "category": "demangle"},
    "swift-demangle": {"timeout": 10, "category": "demangle"},
    "addr2line":     {"timeout": 10, "category": "addr"},
    "lipo":          {"timeout": 10, "category": "fat", "forbid_args": ["-create", "-replace", "-remove"]},

    # Tier B — fast metadata (seconds)
    "rabin2":        {"timeout": 30, "category": "metadata"},
    "readelf":       {"timeout": 30, "category": "metadata"},
    "objdump":       {"timeout": 60, "category": "metadata_or_disasm"},
    "nm":            {"timeout": 30, "category": "symbols"},
    "otool":         {"timeout": 30, "category": "metadata"},
    "jtool2":        {"timeout": 60, "category": "metadata_or_disasm"},
    "llvm-objdump":  {"timeout": 60, "category": "metadata_or_disasm"},
    "llvm-nm":       {"timeout": 30, "category": "symbols"},
    "llvm-readelf":  {"timeout": 30, "category": "metadata"},
    "llvm-strings":  {"timeout": 30, "category": "strings"},
    "rasm2":         {"timeout": 10, "category": "assemble"},

    # Tier D — Mach-O / iOS specific
    "class-dump":    {"timeout": 60, "category": "objc"},
    # iOS code-signing / entitlements (read-only sub-commands enforced via forbid_args)
    "codesign":      {"timeout": 30, "category": "codesign",
                      "forbid_args": ["--sign", "-s", "--remove-signature", "--force",
                                      "--deep-sign", "--detached-database", "-r"]},
    "ldid":          {"timeout": 30, "category": "codesign",
                      "forbid_args": ["-S", "-s"]},  # -S<file> writes entitlements; -s replaces signature

    # Tier C — r2 STRICTLY bounded (see validate_r2_args)
    "r2":            {"timeout": 60, "category": "r2_bounded", "guard": "r2"},
}


# ---------------------------------------------------------------------------
# r2 boundary policy
# ---------------------------------------------------------------------------

R2_FORBIDDEN_FLAGS: set[str] = {"-A", "-AA", "-AAA"}

# r2 commands that trigger full-binary analysis (slow on real binaries).
# We block these as -c command tokens.
R2_FORBIDDEN_R2_COMMANDS: set[str] = {
    "aaa", "aaaa", "aac", "aacu", "aae", "aab", "aav", "aar", "aap",
    "aas", "aaef", "aaft", "aanr", "aaw",
}

R2_REQUIRED_FLAGS: set[str] = {"-q", "-2", "-n"}


def _validate_r2_args(args: list[str]) -> Optional[str]:
    """Return error string if r2 args violate the boundary, else None."""
    arg_set = set(args)

    # 1. enforce required flags
    missing = R2_REQUIRED_FLAGS - arg_set
    if missing:
        return (
            f"r2 must include flags {sorted(R2_REQUIRED_FLAGS)} "
            f"(missing: {sorted(missing)}). -q=quit after command, -2=silent stderr, "
            "-n=SKIP RBin auto-load to avoid full analysis. "
            "Without -n, r2 will run aaa on GB-scale binaries and time out."
        )

    # 2. block forbidden flags (-A etc)
    forbidden = arg_set & R2_FORBIDDEN_FLAGS
    if forbidden:
        return (
            f"r2 flags {sorted(forbidden)} are forbidden (they trigger full analysis "
            "which is too slow on real binaries). Use specific bounded commands via "
            "-c (e.g. -c \"pd 50 @ 0xADDR\" or -c \"iI\")."
        )

    # 3. require -c "<cmd>" and scan the command string for analysis verbs
    has_c = False
    for i, arg in enumerate(args):
        if arg == "-c" and i + 1 < len(args):
            has_c = True
            cmd_str = args[i + 1]
            # split on r2 separators: ; && || newline
            tokens: list[str] = []
            for piece in cmd_str.replace(";", "\n").replace("&&", "\n").replace("||", "\n").splitlines():
                piece = piece.strip()
                if piece:
                    head = piece.split()[0] if piece.split() else piece
                    tokens.append(head)
            for tok in tokens:
                if tok in R2_FORBIDDEN_R2_COMMANDS:
                    return (
                        f"r2 command '{tok}' is forbidden (full-analysis verb). "
                        "Use spot commands like pd/pi/px/iI/iS/iE/iz/is."
                    )
    if not has_c:
        return "r2 must be invoked with -c \"<single command>\" in this wrapper."

    return None


# ---------------------------------------------------------------------------
# Generic per-tool forbid_args check
# ---------------------------------------------------------------------------

def _validate_generic(tool: str, args: list[str], cfg: dict[str, Any]) -> Optional[str]:
    forbid = cfg.get("forbid_args") or []
    if not forbid:
        return None
    for arg in args:
        if arg in forbid:
            return (
                f"tool '{tool}' argument '{arg}' is forbidden by the algokiller wrapper "
                "(write/mutating operations are blocked)."
            )
    return None


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _scrub(text: str) -> str:
    """Strip lone UTF-8 surrogates / invalid sequences before returning."""
    return text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")


def _install_hint(tool: str) -> str:
    hints = {
        "rabin2": "brew install radare2",
        "rasm2":  "brew install radare2",
        "rax2":   "brew install radare2",
        "r2":     "brew install radare2",
        "jtool2": "brew install jtool2",
        "class-dump": "brew install --cask class-dump",
        "rg":     "brew install ripgrep",
        "jq":     "brew install jq",
        "llvm-objdump":  "brew install llvm",
        "llvm-nm":       "brew install llvm",
        "llvm-readelf":  "brew install llvm",
        "llvm-strings":  "brew install llvm",
        "llvm-cxxfilt":  "brew install llvm",
    }
    return hints.get(tool, f"install '{tool}' via your distro's package manager")


def run_static_tool(
    *,
    tool: str,
    args: list[str],
    input_stdin: Optional[str] = None,
    cwd: Optional[Path] = None,
) -> dict[str, Any]:
    """Execute an allow-listed read-only static-analysis CLI tool.

    Returns a dict suitable for direct json.dumps and MCP tool result emission.
    Status is "ok" if returncode == 0, otherwise "error" with stderr tail.
    """
    if tool not in ALLOWED_TOOLS:
        return {
            "status": "error",
            "error": f"tool '{tool}' is not in the allow-list",
            "allowed_tools": sorted(ALLOWED_TOOLS.keys()),
        }

    cfg = ALLOWED_TOOLS[tool]

    # Resolve binary on PATH
    binary = shutil.which(tool)
    if not binary:
        return {
            "status": "error",
            "error": f"tool '{tool}' is not installed (not found in PATH)",
            "hint": _install_hint(tool),
        }

    # NUL byte rejection (subprocess would error anyway, but explicit is better)
    for a in args:
        if "\x00" in a:
            return {"status": "error", "error": "NUL byte not allowed in arguments"}

    # Per-tool boundary validation
    if cfg.get("guard") == "r2":
        err = _validate_r2_args(args)
        if err:
            return {"status": "error", "error": err}
    else:
        err = _validate_generic(tool, args, cfg)
        if err:
            return {"status": "error", "error": err}

    # Execute (NOTE: argv list — no shell, no metachar expansion)
    try:
        proc = subprocess.run(
            [binary, *args],
            input=input_stdin,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=cfg["timeout"],
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": f"tool '{tool}' timed out after {cfg['timeout']}s",
            "hint": (
                "narrow the scope: for objdump add --start-address/--stop-address; "
                "for strings raise -n; for r2 keep the -c command to a single function "
                "(pd N @ addr); for class-dump target a single .arm64 slice via lipo first."
            ),
        }
    except FileNotFoundError as exc:
        return {"status": "error", "error": f"failed to launch '{tool}': {exc}"}
    except Exception as exc:
        return {"status": "error", "error": f"unexpected error: {exc}"}

    stdout = _scrub(proc.stdout or "")
    stderr = _scrub(proc.stderr or "")
    truncated = len(stdout) > 30000
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "tool": tool,
        "returncode": proc.returncode,
        "stdout": stdout[:30000],
        "stderr": stderr[-4000:],
        "truncated_stdout": truncated,
    }
