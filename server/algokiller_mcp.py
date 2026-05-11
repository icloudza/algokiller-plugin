#!/usr/bin/env python3
"""algokiller MCP server — JSON-RPC 2.0 over stdio, zero external deps.

Speaks MCP 2024-11-05 directly (initialize / tools/list / tools/call / ping).
Designed to be launched by Claude Desktop's plugin runtime via .mcp.json.
"""

from __future__ import annotations

import atexit
import json
import re
import signal
import sys
import traceback
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from state import STATE, AK_SEARCH_BIN, PLUGIN_ROOT  # noqa: E402
from daemon import AkSearchDaemon  # noqa: E402
from discipline import build_reminder  # noqa: E402
from artifacts import ArtifactStore  # noqa: E402
from static_tools import ALLOWED_TOOLS as STATIC_TOOLS_ALLOW, run_static_tool  # noqa: E402


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "algokiller"
SERVER_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Tool schemas (advertised via tools/list)
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "bind_trace",
        "description": (
            "Bind the current session to an ARM64 trace log file and analysis mode. "
            "Must be called once before any trace_search or trace_context. "
            "Subsequent calls re-bind (the previous ak_search daemon is closed and a new one is started)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to the trace log file."},
                "mode": {
                    "type": "string",
                    "enum": ["ciphertext", "general"],
                    "description": "Analysis mode: 'ciphertext' for cipher / algorithm recovery, 'general' for open trace analysis.",
                },
            },
            "required": ["path", "mode"],
        },
    },
    {
        "name": "trace_search",
        "description": (
            "Case-insensitive exact substring search over the bound trace. "
            "Provide exactly one of from_line / before_line plus limit (<=100). "
            "from_line searches forward; before_line searches backward and returns nearest earlier matches first. "
            "For 0x-hex queries with no matches, the server automatically retries with byte-reversed and "
            "leading-zero-trimmed variants."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Exact substring to find. ASCII case-insensitive."},
                "from_line": {"type": "integer", "minimum": 1, "description": "1-based file line to start searching from (forward)."},
                "before_line": {"type": "integer", "minimum": 1, "description": "1-based file line; search only lines strictly before this (backward)."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Maximum number of matching lines to return."},
            },
            "required": ["query", "limit"],
        },
    },
    {
        "name": "trace_context",
        "description": (
            "Return neighboring trace lines around a 1-based file line in the bound trace. "
            "Both before and after must be provided, each <= 100."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "line": {"type": "integer", "minimum": 1},
                "before": {"type": "integer", "minimum": 0, "maximum": 100},
                "after": {"type": "integer", "minimum": 0, "maximum": 100},
            },
            "required": ["line", "before", "after"],
        },
    },
    {
        "name": "write_artifact",
        "description": (
            "Write a final deliverable (recovered Python source, or markdown analysis report) "
            "into the session artifacts directory. Path is relative; the server appends mode + timestamp."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative filename, e.g. 'recovered.py' or 'report.md'."},
                "content": {"type": "string", "description": "Full file content."},
                "notes": {"type": "string", "description": "Optional short evidence / confidence note saved alongside."},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "list_artifacts",
        "description": "List all artifacts written in the current session directory.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_artifact",
        "description": "Read back an artifact previously written by write_artifact (path must be inside the current session directory).",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "run_static_tool",
        "description": (
            "Execute an allow-listed READ-ONLY static-analysis CLI on the user's machine. "
            "Use this to complement trace analysis with binary metadata, local disassembly, string extraction, "
            "byte-order conversion, and JSON / cross-file search — especially when Binary Ninja MCP is NOT connected. "
            "Tools are launched via argv (no shell), have per-tool timeouts, and r2 is bounded to single-command "
            "mode with mandatory -q -2 -n flags (no full-binary analysis allowed — r2 -A / aaa are rejected). "
            "If a tool is not installed, the response includes a 'hint' with the install command. "
            "Priority: prefer Binary Ninja MCP if connected; use this only when BN is offline or for capabilities "
            "BN does not have (rax2 byte-order conversion, ripgrep cross-file search, jq JSON, etc)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "enum": sorted(STATIC_TOOLS_ALLOW.keys()),
                    "description": "Tool name from the allow-list. Use 'file' to detect binary type / arch first.",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Command-line arguments as a list of strings (NOT a shell string). "
                        "Example: ['-I', '/path/to/binary'] for rabin2 info. "
                        "For r2: MUST include ['-q', '-2', '-n', '-c', '<single bounded command>', '<binary path>']. "
                        "Forbidden for r2: -A / -AA / -AAA flags, and -c commands containing aaa/aac/aae/aab/aav/aar/aap."
                    ),
                },
                "input_stdin": {
                    "type": "string",
                    "description": "Optional stdin content. Use for jq (pipe JSON in) or c++filt (pipe symbols in).",
                },
            },
            "required": ["tool", "args"],
        },
    },
    {
        "name": "trace_regflow",
        "description": (
            "Emit the value-write sequence for a target register over a line range. "
            "Each row corresponds to a trace line where the register receives an output value "
            "(the '-> regN=0xVAL' portion of GumTrace format). Use this to follow how a key, "
            "hash accumulator, or buffer pointer evolves across instructions — far cheaper than "
            "repeated trace_search calls + manual reconstruction."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "reg": {"type": "string", "description": "Register name, e.g. 'x0', 'x9', 'w12', 'sp', 'fp'."},
                "from_line": {"type": "integer", "minimum": 1, "description": "1-based start line (default 1)."},
                "to_line": {"type": "integer", "minimum": 1, "description": "1-based end line (default last)."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Max records (default 100)."},
            },
            "required": ["reg"],
        },
    },
    {
        "name": "trace_producer",
        "description": (
            "Scan backward from sink_line to find the most recent instruction whose '-> regN=0xVAL' "
            "matches the requested value. Returns a single producer row with the writing register "
            "and instruction text. Replaces the 'before_line + manual bisect' loop the agent does "
            "when chasing where a value came from."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "Target value as 0x-prefixed hex, e.g. '0xa1b2c3d4'."},
                "sink_line": {"type": "integer", "minimum": 2, "description": "1-based sink line; search scans lines strictly before this."},
                "max_back": {"type": "integer", "minimum": 1, "description": "Maximum lines to scan backward (default 100000)."},
            },
            "required": ["value", "sink_line"],
        },
    },
    {
        "name": "trace_callgraph",
        "description": (
            "Caller/callee analysis over 'call func: NAME(args)' lines. Two modes: "
            "--to NAME returns every line that calls a function matching NAME (substring "
            "match on the call symbol). --top N returns the Top-K most-called symbols with "
            "counts. Use --to to find every call site of a specific helper (e.g. 'objc_retain', "
            "'__memcpy_aarch64_simd'); use --top to discover hot dependencies before deep dive."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Function name substring to filter by."},
                "top": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Top-K most-called names; mutually exclusive with --to."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Max xref rows when --to is set (default 100)."},
            },
        },
    },
    {
        "name": "trace_modgraph",
        "description": (
            "Cross-module transition graph. Scans adjacent module-tagged lines and emits "
            "directed edges (from_module -> to_module) with transition counts. Top-K edges "
            "highlight the cross-module hot path. Each module also reports total line count. "
            "Use this to identify which modules bridge to which (e.g. WeChat <-> mmcronet) "
            "before drilling into a specific call boundary."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "top": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Top-K edges by count (default 30)."},
            },
        },
    },
    {
        "name": "trace_hexblock",
        "description": (
            "Parse a 'call func: NAME(args)' block at the given line and return structured JSON: "
            "call name, args, optional ObjC class label, optional hexdumps (address + length + "
            "concatenated bytes_hex), and ret value. Replaces multi-step trace_context + manual "
            "row stitching when the agent needs the bytes flowing through a memcpy / sprintf / "
            "encryption helper. ASCII preview is not emitted — use the bytes_hex directly."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "line": {"type": "integer", "minimum": 1, "description": "1-based file line of the 'call func:' header."},
                "max_lines": {"type": "integer", "minimum": 1, "maximum": 10000, "description": "Max lines to scan forward looking for ret (default 1024)."},
            },
            "required": ["line"],
        },
    },
    {
        "name": "trace_constscan",
        "description": (
            "Scan the trace for known cryptographic constants (MD5 / SHA1 / SHA256 init values, "
            "CRC32 polynomials, FNV-1a constants, AES sbox leading words, SM4 sbox + FK, "
            "Bernstein multiplier). Returns a list of fingerprints with hit counts and sample "
            "line numbers. Use right after bind_trace to identify which crypto primitives the "
            "binary is exercising before sinking analysis tokens into the wrong region. "
            "Categories: hash / cipher / cipher_hint / crc."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "samples": {"type": "integer", "minimum": 1, "maximum": 16, "description": "Sample line numbers per fingerprint (default 5)."},
            },
        },
    },
    {
        "name": "trace_bytes",
        "description": (
            "Hex-literal search with automatic byte-reverse and leading-zero-strip variants. "
            "Like trace_search but specialised for 0xVAL queries: emits ALL hit line numbers "
            "(no 100-row cap), reports which variant matched. Use this when chasing a specific "
            "value across the whole trace and trace_search's limit is too tight. Pass "
            "--with-text to also include the instruction line, otherwise output is "
            "token-frugal (just line + variant)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Hex literal, e.g. '0x67452301' or '0xa1b2c3d4'."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "description": "Max total hits across all variants (default 100)."},
                "with_text": {"type": "boolean", "description": "Include the matched instruction line text (default false)."},
            },
            "required": ["query"],
        },
    },
    {
        "name": "trace_cryptoinstr",
        "description": (
            "Scan the trace for ARM Crypto Extensions instructions — the only signal when a "
            "binary uses hardware-accelerated crypto (AES-NI equivalent on ARM). Detects: "
            "AES (aese/aesmc/aesd/aesimc), SHA-1 (sha1c/m/p/h/su0/su1), SHA-256 (sha256h/h2/su0/su1), "
            "SHA-512 (sha512h/h2/su0/su1, ARMv8.2), SHA-3 (eor3/rax1/xar/bcax, ARMv8.2), "
            "GHASH (pmull/pmull2), SM3 (sm3*, ARMv8.2), SM4 (sm4e/sm4ekey, ARMv8.2). "
            "Critical companion to trace_constscan: if constscan reports 0 AES constants but "
            "cryptoinstr finds aese hits, you're looking at hardware AES — NOT a missing crypto "
            "implementation. Most modern OEM SDKs (iOS CryptoKit, BoringSSL ARM, libsodium-arm, "
            "Android Keystore HW path) use these instructions on iPhone 5s+ / Pixel / etc."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "samples": {"type": "integer", "minimum": 1, "maximum": 8, "description": "Sample line numbers per mnemonic (default 5)."},
            },
        },
    },
    {
        "name": "trace_lint",
        "description": (
            "Single-pass health-check of the bound trace. Returns JSON: line count, average line "
            "length, module distribution, top mnemonics, call_func / hexdump / ret block counts, "
            "and whether register / memory observations are present. Use this RIGHT AFTER bind_trace "
            "to confirm the file is a valid GumTrace-format capture before sinking analysis tokens "
            "into it. Warnings highlight likely problems (wrong format / missing call blocks / "
            "missing register observations)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "top": {"type": "integer", "minimum": 1, "maximum": 50, "description": "Top-K rows for modules and mnemonics (default 10)."},
            },
        },
    },
    {
        "name": "trace_fold",
        "description": (
            "Write a derivative trace file with repeated W-line blocks collapsed to "
            "first-block + sentinel + last-block. Default block=1 collapses runs of a single "
            "identical-signature instruction; block=4 catches ARM64 4-instruction hot loops "
            "(typical DJB/Bernstein hash loops with ldrsb / madd / subs / b.ne). Threshold is "
            "the minimum number of block repetitions required before collapsing. Real WeChat "
            "startup trace (115 MB / 1.12 M lines) folds to ~1 MB / 12 K lines with "
            "block=4 / threshold=100, retaining all data-flow boundary evidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "out_path": {"type": "string", "description": "Absolute output path for the folded trace."},
                "threshold": {"type": "integer", "minimum": 3, "description": "Min repetitions to trigger a fold (default 100)."},
                "block": {"type": "integer", "minimum": 1, "maximum": 32, "description": "Block window size in lines (default 1)."},
            },
            "required": ["out_path"],
        },
    },
    {
        "name": "trace_semop",
        "description": (
            "Classify each instruction's semantic role. Classes: zero (xor x,x,x), "
            "crypto_candidate (eor with distinct regs), hash_loop_candidate (madd/msub), "
            "stack_save/restore, memory_load/store, branch, data_move, addr_calc, alu, "
            "compare, unknown. Use to prune non-crypto candidates before deep dive, or to "
            "stage-classify a hot region. Either --line for a single instruction, or "
            "--from-line + --to-line + --limit for a range."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "line": {"type": "integer", "minimum": 1, "description": "Single line to classify."},
                "from_line": {"type": "integer", "minimum": 1, "description": "Range start (use with to_line)."},
                "to_line": {"type": "integer", "minimum": 1, "description": "Range end (use with from_line)."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Max records (default 100)."},
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _require_bound() -> dict | None:
    if STATE.trace_file is None or STATE.daemon is None:
        return {
            "status": "error",
            "error": "no trace bound",
            "instruction": "Call bind_trace(path, mode) first.",
        }
    return None


def _byte_reverse_hex(hex_digits: str) -> str:
    padded = hex_digits if len(hex_digits) % 2 == 0 else "0" + hex_digits
    return "0x" + "".join(reversed([padded[i:i + 2] for i in range(0, len(padded), 2)]))


def _hex_fallback_queries(query: str) -> list[str]:
    if not query.lower().startswith("0x"):
        return []
    hex_digits = query[2:]
    if not re.fullmatch(r"[0-9a-fA-F]+", hex_digits):
        return []
    fallbacks = [_byte_reverse_hex(hex_digits)]
    trimmed = hex_digits.lstrip("0")
    if trimmed and trimmed != hex_digits:
        fallbacks.append("0x" + trimmed)
        fallbacks.append(_byte_reverse_hex(trimmed))
    seen = {query.lower()}
    out: list[str] = []
    for fq in fallbacks:
        if fq.lower() not in seen:
            seen.add(fq.lower())
            out.append(fq)
    return out


def _search_once(query: str, *, from_line: int = 0, before_line: int = 0, limit: int) -> dict:
    hex_query = query.encode("utf-8").hex()
    return STATE.daemon.request(f"match\t{from_line}\t{before_line}\t{limit}\t{hex_query}")


def _empty_ok(result: dict) -> bool:
    return result.get("status") == "ok" and not str(result.get("stdout") or "").strip()


def _has_matches(result: dict) -> bool:
    return result.get("status") == "ok" and bool(str(result.get("stdout") or "").strip())


def tool_bind_trace(args: dict[str, Any]) -> dict:
    path_arg = args.get("path")
    mode_arg = args.get("mode")
    if not path_arg or not isinstance(path_arg, str):
        return {"status": "error", "error": "path is required"}
    if mode_arg not in ("ciphertext", "general"):
        return {"status": "error", "error": "mode must be 'ciphertext' or 'general'"}

    trace_path = Path(path_arg).expanduser()
    if not trace_path.is_absolute():
        trace_path = trace_path.resolve()
    else:
        trace_path = trace_path.resolve()
    if not trace_path.exists():
        return {"status": "error", "error": f"trace file not found: {trace_path}"}
    if not trace_path.is_file():
        return {"status": "error", "error": f"trace path is not a file: {trace_path}"}

    if STATE.daemon is not None:
        STATE.daemon.close()
        STATE.daemon = None

    daemon = AkSearchDaemon(binary=AK_SEARCH_BIN, trace_file=trace_path)
    try:
        daemon.start()
    except Exception as exc:
        return {"status": "error", "error": f"failed to start ak_search daemon: {exc}"}

    STATE.daemon = daemon
    STATE.bind(trace_path, mode_arg)

    return {
        "status": "ok",
        "trace_file": str(trace_path),
        "mode": mode_arg,
        "artifacts_dir": str(STATE.artifacts_dir),
        "instruction": (
            "Trace bound. Use trace_search / trace_context to gather evidence; "
            "use write_artifact to deliver final source or analysis. "
            "Tool returns include a 'discipline_reminder' field — read it before deciding the next call."
        ),
    }


def tool_trace_search(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err

    query = str(args.get("query", ""))
    if not query:
        return {"status": "error", "error": "query must not be empty"}
    has_from = "from_line" in args
    has_before = "before_line" in args
    if has_from == has_before:
        return {"status": "error", "error": "exactly one of from_line / before_line is required"}
    try:
        limit = int(args.get("limit", 0))
    except (TypeError, ValueError):
        return {"status": "error", "error": "limit must be an integer"}
    if not (1 <= limit <= 100):
        return {"status": "error", "error": "limit must be in [1, 100]"}

    if has_before:
        try:
            before_line = int(args["before_line"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "before_line must be an integer"}
        if before_line < 1:
            return {"status": "error", "error": "before_line must be >= 1"}
        result = _search_once(query, before_line=before_line, limit=limit)
        if _empty_ok(result):
            for fq in _hex_fallback_queries(query):
                fallback = _search_once(fq, before_line=before_line, limit=limit)
                if _has_matches(fallback):
                    fallback["fallback_query"] = fq
                    return fallback
        return result

    try:
        from_line = int(args["from_line"])
    except (TypeError, ValueError):
        return {"status": "error", "error": "from_line must be an integer"}
    if from_line < 1:
        return {"status": "error", "error": "from_line must be >= 1"}
    result = _search_once(query, from_line=from_line, limit=limit)
    if _empty_ok(result):
        for fq in _hex_fallback_queries(query):
            fallback = _search_once(fq, from_line=from_line, limit=limit)
            if _has_matches(fallback):
                fallback["fallback_query"] = fq
                return fallback
    return result


def tool_trace_context(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    try:
        line = int(args.get("line", 0))
    except (TypeError, ValueError):
        return {"status": "error", "error": "line must be an integer"}
    if line < 1:
        return {"status": "error", "error": "line must be >= 1"}
    if "before" not in args or "after" not in args:
        return {"status": "error", "error": "before and after are both required"}
    try:
        before = int(args["before"])
        after = int(args["after"])
    except (TypeError, ValueError):
        return {"status": "error", "error": "before / after must be integers"}
    if not (0 <= before <= 100 and 0 <= after <= 100):
        return {"status": "error", "error": "before and after must be in [0, 100]"}
    return STATE.daemon.request(f"context\t{line}\t{before}\t{after}")


def tool_write_artifact(args: dict[str, Any]) -> dict:
    if STATE.artifacts_dir is None:
        return {"status": "error", "error": "artifacts dir not initialized; call bind_trace first"}
    store = ArtifactStore(STATE.artifacts_dir, mode=STATE.mode)
    return store.write(
        rel_path=str(args.get("path", "")),
        content=str(args.get("content", "")),
        notes=args.get("notes"),
    )


def tool_list_artifacts(_args: dict[str, Any]) -> dict:
    if STATE.artifacts_dir is None:
        return {"status": "error", "error": "artifacts dir not initialized; call bind_trace first"}
    store = ArtifactStore(STATE.artifacts_dir, mode=STATE.mode)
    return {
        "status": "ok",
        "artifacts_dir": str(STATE.artifacts_dir),
        "items": store.list_all(),
    }


def tool_read_artifact(args: dict[str, Any]) -> dict:
    if STATE.artifacts_dir is None:
        return {"status": "error", "error": "artifacts dir not initialized; call bind_trace first"}
    store = ArtifactStore(STATE.artifacts_dir, mode=STATE.mode)
    try:
        text = store.read(str(args.get("path", "")))
    except (FileNotFoundError, ValueError) as exc:
        return {"status": "error", "error": str(exc)}
    return {"status": "ok", "content": text}


def tool_run_static_tool(args: dict[str, Any]) -> dict:
    tool_name = args.get("tool")
    tool_args = args.get("args")
    stdin = args.get("input_stdin")
    if not isinstance(tool_name, str) or not tool_name:
        return {"status": "error", "error": "tool must be a non-empty string"}
    if not isinstance(tool_args, list) or any(not isinstance(a, str) for a in tool_args):
        return {"status": "error", "error": "args must be a list of strings"}
    if stdin is not None and not isinstance(stdin, str):
        return {"status": "error", "error": "input_stdin, if provided, must be a string"}
    return run_static_tool(tool=tool_name, args=tool_args, input_stdin=stdin)


def tool_trace_regflow(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    reg = str(args.get("reg", "")).strip()
    if not reg:
        return {"status": "error", "error": "reg must not be empty"}
    cli_args: list[str] = ["--reg", reg]
    if "from_line" in args:
        try:
            cli_args += ["--from-line", str(int(args["from_line"]))]
        except (TypeError, ValueError):
            return {"status": "error", "error": "from_line must be an integer"}
    if "to_line" in args:
        try:
            cli_args += ["--to-line", str(int(args["to_line"]))]
        except (TypeError, ValueError):
            return {"status": "error", "error": "to_line must be an integer"}
    if "limit" in args:
        try:
            limit = int(args["limit"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "limit must be an integer"}
        if not (1 <= limit <= 1000):
            return {"status": "error", "error": "limit must be in [1, 1000]"}
        cli_args += ["--limit", str(limit)]
    return STATE.daemon.run_cli("regflow", cli_args)


def tool_trace_producer(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    value = str(args.get("value", "")).strip()
    if not value or not value.lower().startswith("0x"):
        return {"status": "error", "error": "value must be a 0x-prefixed hex literal, e.g. '0xa1b2c3d4'"}
    try:
        sink_line = int(args.get("sink_line", 0))
    except (TypeError, ValueError):
        return {"status": "error", "error": "sink_line must be an integer"}
    if sink_line < 2:
        return {"status": "error", "error": "sink_line must be >= 2"}
    cli_args: list[str] = ["--value", value, "--sink-line", str(sink_line)]
    if "max_back" in args:
        try:
            mb = int(args["max_back"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "max_back must be an integer"}
        if mb < 1:
            return {"status": "error", "error": "max_back must be >= 1"}
        cli_args += ["--max-back", str(mb)]
    return STATE.daemon.run_cli("producer", cli_args)


def tool_trace_semop(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    has_line = "line" in args
    has_range = "from_line" in args and "to_line" in args
    if not has_line and not has_range:
        return {"status": "error", "error": "provide either 'line' or both 'from_line' and 'to_line'"}
    cli_args: list[str] = []
    if has_line:
        try:
            cli_args += ["--line", str(int(args["line"]))]
        except (TypeError, ValueError):
            return {"status": "error", "error": "line must be an integer"}
    else:
        try:
            cli_args += ["--from-line", str(int(args["from_line"])), "--to-line", str(int(args["to_line"]))]
        except (TypeError, ValueError):
            return {"status": "error", "error": "from_line / to_line must be integers"}
    if "limit" in args:
        try:
            limit = int(args["limit"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "limit must be an integer"}
        if not (1 <= limit <= 1000):
            return {"status": "error", "error": "limit must be in [1, 1000]"}
        cli_args += ["--limit", str(limit)]
    return STATE.daemon.run_cli("semop", cli_args)


def tool_trace_callgraph(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    has_to = "to" in args and str(args.get("to", "")).strip()
    has_top = "top" in args
    if has_to and has_top:
        return {"status": "error", "error": "provide exactly one of 'to' or 'top'"}
    if not has_to and not has_top:
        return {"status": "error", "error": "provide 'to' (substring) or 'top' (Top-K)"}
    cli: list[str] = []
    if has_to:
        cli += ["--to", str(args["to"]).strip()]
        if "limit" in args:
            try:
                limit = int(args["limit"])
            except (TypeError, ValueError):
                return {"status": "error", "error": "limit must be an integer"}
            if not (1 <= limit <= 1000):
                return {"status": "error", "error": "limit must be in [1, 1000]"}
            cli += ["--limit", str(limit)]
    else:
        try:
            top = int(args["top"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "top must be an integer"}
        if not (1 <= top <= 200):
            return {"status": "error", "error": "top must be in [1, 200]"}
        cli += ["--top", str(top)]
    return STATE.daemon.run_cli("callgraph", cli, timeout=120)


def tool_trace_modgraph(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    cli: list[str] = []
    if "top" in args:
        try:
            top = int(args["top"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "top must be an integer"}
        if not (1 <= top <= 200):
            return {"status": "error", "error": "top must be in [1, 200]"}
        cli += ["--top", str(top)]
    return STATE.daemon.run_cli("modgraph", cli, timeout=120)


def tool_trace_hexblock(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    try:
        line = int(args.get("line", 0))
    except (TypeError, ValueError):
        return {"status": "error", "error": "line must be an integer"}
    if line < 1:
        return {"status": "error", "error": "line must be >= 1"}
    cli: list[str] = ["--line", str(line)]
    if "max_lines" in args:
        try:
            ml = int(args["max_lines"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "max_lines must be an integer"}
        if not (1 <= ml <= 10000):
            return {"status": "error", "error": "max_lines must be in [1, 10000]"}
        cli += ["--max-lines", str(ml)]
    return STATE.daemon.run_cli("hexblock", cli, timeout=60)


def tool_trace_constscan(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    cli: list[str] = []
    if "samples" in args:
        try:
            s = int(args["samples"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "samples must be an integer"}
        if not (1 <= s <= 16):
            return {"status": "error", "error": "samples must be in [1, 16]"}
        cli += ["--samples", str(s)]
    return STATE.daemon.run_cli("constscan", cli, timeout=300, max_output_chars=200_000)


def tool_trace_bytes(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    query = str(args.get("query", "")).strip()
    if not query or not query.lower().startswith("0x"):
        return {"status": "error", "error": "query must be a 0x-prefixed hex literal"}
    cli: list[str] = ["--query", query]
    if "limit" in args:
        try:
            lim = int(args["limit"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "limit must be an integer"}
        if not (1 <= lim <= 10000):
            return {"status": "error", "error": "limit must be in [1, 10000]"}
        cli += ["--limit", str(lim)]
    if args.get("with_text"):
        cli.append("--with-text")
    return STATE.daemon.run_cli("bytes", cli, timeout=120)


def tool_trace_cryptoinstr(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    cli: list[str] = []
    if "samples" in args:
        try:
            s = int(args["samples"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "samples must be an integer"}
        if not (1 <= s <= 8):
            return {"status": "error", "error": "samples must be in [1, 8]"}
        cli += ["--samples", str(s)]
    return STATE.daemon.run_cli("cryptoinstr", cli, timeout=120)


def tool_trace_lint(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    cli_args: list[str] = []
    if "top" in args:
        try:
            top = int(args["top"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "top must be an integer"}
        if not (1 <= top <= 50):
            return {"status": "error", "error": "top must be in [1, 50]"}
        cli_args += ["--top", str(top)]
    return STATE.daemon.run_cli("lint", cli_args, timeout=120, max_output_chars=400_000)


def tool_trace_fold(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    out_path = str(args.get("out_path", "")).strip()
    if not out_path:
        return {"status": "error", "error": "out_path is required"}
    if not out_path.startswith("/"):
        return {"status": "error", "error": "out_path must be an absolute path"}
    if STATE.daemon is None or STATE.trace_file is None:
        return {"status": "error", "error": "no trace bound"}
    cli_args: list[str] = ["--in", str(STATE.trace_file), "--out", out_path]
    if "threshold" in args:
        try:
            thr = int(args["threshold"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "threshold must be an integer"}
        if thr < 3:
            return {"status": "error", "error": "threshold must be >= 3"}
        cli_args += ["--threshold", str(thr)]
    if "block" in args:
        try:
            blk = int(args["block"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "block must be an integer"}
        if not (1 <= blk <= 32):
            return {"status": "error", "error": "block must be in [1, 32]"}
        cli_args += ["--block", str(blk)]
    # fold's CLI takes --in/--out itself; run_cli always inserts --file, so we
    # call subprocess directly bypassing run_cli's --file injection.
    import subprocess as _sp
    try:
        result = _sp.run(
            [str(STATE.daemon.binary), "fold", *cli_args],
            capture_output=True, text=True, timeout=600, check=False,
        )
    except _sp.TimeoutExpired:
        return {"status": "error", "error": "fold timed out after 600s"}
    except OSError as exc:
        return {"status": "error", "error": f"fold exec failed: {exc}"}
    return {
        "status": "ok" if result.returncode == 0 else "error",
        "stdout": result.stdout or "",
        "stderr": result.stderr or "",
        "returncode": result.returncode,
        "out_path": out_path,
    }


HANDLERS = {
    "bind_trace": tool_bind_trace,
    "trace_search": tool_trace_search,
    "trace_context": tool_trace_context,
    "trace_regflow": tool_trace_regflow,
    "trace_producer": tool_trace_producer,
    "trace_semop": tool_trace_semop,
    "trace_lint": tool_trace_lint,
    "trace_fold": tool_trace_fold,
    "trace_callgraph": tool_trace_callgraph,
    "trace_modgraph": tool_trace_modgraph,
    "trace_hexblock": tool_trace_hexblock,
    "trace_constscan": tool_trace_constscan,
    "trace_bytes": tool_trace_bytes,
    "trace_cryptoinstr": tool_trace_cryptoinstr,
    "write_artifact": tool_write_artifact,
    "list_artifacts": tool_list_artifacts,
    "read_artifact": tool_read_artifact,
    "run_static_tool": tool_run_static_tool,
}


# ---------------------------------------------------------------------------
# JSON-RPC plumbing
# ---------------------------------------------------------------------------

def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _log(msg: str) -> None:
    sys.stderr.write(f"[algokiller-mcp] {msg}\n")
    sys.stderr.flush()


def _attach_discipline(name: str, payload: dict) -> dict:
    # Skip discipline injection on protocol-level errors (no bound trace).
    if payload.get("status") == "error" and STATE.daemon is None and name != "bind_trace":
        return payload
    call_count = STATE.bump_tool_call()
    payload.update(build_reminder(mode=STATE.mode, call_count=call_count))
    return payload


def handle_request(req: dict) -> dict | None:
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "notifications/initialized":
        return None  # notification, no response expected
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if handler is None:
            # M3: don't return a JSON-RPC protocol error — return a normal tool
            # result with a strong self-correction instruction so the agent
            # doesn't stall on an unknown-tool reply.
            known = ", ".join(HANDLERS.keys())
            payload = {
                "status": "error",
                "error": f"Unknown tool: {name}",
                "instruction": (
                    "This tool does not exist and has been skipped. Do NOT stop, do NOT ask the user; "
                    f"retry using one of the available tools: {known}. "
                    "If you intended to search trace evidence, use trace_search / trace_context. "
                    "If you intended to deliver a final artifact, use write_artifact."
                ),
                "available_tools": list(HANDLERS.keys()),
            }
            payload = _attach_discipline(name, payload)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]},
            }
        try:
            payload = handler(arguments)
        except Exception as exc:
            _log(f"tool '{name}' raised: {exc}\n{traceback.format_exc()}")
            payload = {
                "status": "error",
                "error": str(exc),
                "instruction": (
                    "Tool call failed and has been skipped. Do NOT stop, do NOT ask the user; "
                    "fix the arguments or switch to another tool and continue the previous task."
                ),
            }

        payload = _attach_discipline(name, payload)
        text = json.dumps(payload, ensure_ascii=False)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": text}]},
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method and method.startswith("notifications/"):
        return None  # ignore other notifications silently

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    }


def _shutdown(_signum: int | None = None, _frame: Any = None) -> None:
    # P11: ensure the ak_search daemon is reaped on normal exit, SIGTERM, or
    # SIGINT. Without this the daemon can survive plugin reload and pile up.
    if STATE.daemon is not None:
        try:
            STATE.daemon.close()
        except Exception:
            pass
        STATE.daemon = None
    if _signum is not None:
        raise SystemExit(0)


def main() -> int:
    # P9: force line buffering so every JSON-RPC response leaves the process
    # immediately. Belt + suspenders with the `-u` flag and PYTHONUNBUFFERED=1
    # set in .mcp.json — if any of the three is honored we are safe.
    try:
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
        sys.stderr.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except Exception:
        pass

    # P11: register cleanup hooks before serving any request.
    atexit.register(_shutdown)
    try:
        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)
    except (ValueError, OSError):
        # Not in main thread, or running on a platform that disallows the
        # handler. Plugin still works, just without graceful signal cleanup.
        pass

    _log(f"starting (plugin_root={PLUGIN_ROOT}, binary={AK_SEARCH_BIN})")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            _log(f"invalid JSON-RPC line: {exc}")
            continue
        try:
            resp = handle_request(req)
        except Exception as exc:
            _log(f"handle_request crashed: {exc}\n{traceback.format_exc()}")
            resp = {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "error": {"code": -32000, "message": str(exc)},
            }
        if resp is not None:
            _send(resp)

    if STATE.daemon is not None:
        STATE.daemon.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
