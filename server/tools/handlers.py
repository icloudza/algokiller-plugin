"""Tool-call implementations and the `HANDLERS` dispatch dictionary.

Every tool advertised in `schemas.TOOLS` has a matching `tool_*` callable
here. The JSON-RPC layer in `algokiller_mcp.py` looks the function up via
`HANDLERS[name]`, passes the raw `arguments` dict, and wraps the return
value with discipline injection.

Tools group conceptually:

  * Binding + low-level search       — bind_trace, trace_search, trace_context
  * Data flow                        — trace_regflow, trace_producer, trace_semop
  * Call / module graphs             — trace_callgraph, trace_modgraph, trace_hexblock
  * Crypto detection                 — trace_constscan, trace_cryptoinstr, trace_bytes
  * Trace health / volume            — trace_lint, trace_fold
  * Artifacts + static-analysis      — write_artifact, list_artifacts,
                                       read_artifact, run_static_tool
  * Hypothesis Ledger (anti-halluc.) — hypothesis_add / update / conclude /
                                       abandon / list

All extension subcommands go through `STATE.daemon.run_cli()` (one-shot
CLI mode of ak_search). Only `match` / `context` ride the persistent
daemon protocol today.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from state import STATE, AK_SEARCH_BIN
from daemon import AkSearchDaemon
from artifacts import ArtifactStore
from static_tools import run_static_tool


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _require_bound() -> dict | None:
    if STATE.trace_file is None or STATE.daemon is None:
        return {
            "status": "error",
            "error": "no trace bound",
            "instruction": "Call bind_trace(path, mode) first.",
        }
    return None


def _require_ledger() -> dict | None:
    if STATE.ledger is None:
        return {"status": "error", "error":
                "hypothesis ledger not initialised; call bind_trace first"}
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


# ---------------------------------------------------------------------------
# Binding + low-level search
# ---------------------------------------------------------------------------

def tool_bind_trace(args: dict[str, Any]) -> dict:
    path_arg = args.get("path")
    mode_arg = args.get("mode")
    if not path_arg or not isinstance(path_arg, str):
        return {"status": "error", "error": "path is required"}
    if mode_arg not in ("ciphertext", "general"):
        return {"status": "error", "error": "mode must be 'ciphertext' or 'general'"}

    trace_path = Path(path_arg).expanduser().resolve()
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


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

def tool_write_artifact(args: dict[str, Any]) -> dict:
    if STATE.artifacts_dir is None:
        return {"status": "error", "error": "artifacts dir not initialized; call bind_trace first"}
    content = str(args.get("content", ""))
    # Hypothesis-ledger reference guard (anti-hallucination final line of
    # defence). If the deliverable contains H<N> citations, every one of them
    # must resolve to a concluded hypothesis with confidence >= medium and
    # actual supporting evidence. If the deliverable contains zero H<N>
    # citations AND the ledger has at least one concluded hypothesis, the
    # agent is silently bypassing the scaffold — also blocked, with guidance.
    if STATE.ledger is not None:
        check = STATE.ledger.validate_artifact_references(content)
        ledger_has_concluded = any(
            h["state"] == "concluded"
            for h in STATE.ledger.list(state="concluded")["hypotheses"]
        )
        if check["errors"]:
            return {"status": "error",
                    "error": "artifact references invalid hypotheses",
                    "validation_errors": check["errors"],
                    "referenced_ids": check["referenced_ids"],
                    "instruction": (
                        "Each H<id> mentioned in the deliverable must be a CONCLUDED "
                        "hypothesis with confidence >= medium and at least one supporting "
                        "evidence. Either conclude the cited hypothesis first via "
                        "hypothesis_conclude, or remove the citation if the claim cannot "
                        "be backed."),
                    }
        if not check["referenced_ids"] and ledger_has_concluded and len(content) > 200:
            return {"status": "error",
                    "error": "deliverable bypasses hypothesis ledger",
                    "instruction": (
                        "You have concluded hypotheses in the ledger but the artifact "
                        "cites none of them. Either cite the relevant H<id> in your "
                        "claims, or abandon those hypotheses if they no longer apply."),
                    }
    store = ArtifactStore(STATE.artifacts_dir, mode=STATE.mode)
    return store.write(
        rel_path=str(args.get("path", "")),
        content=content,
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


# ---------------------------------------------------------------------------
# Hypothesis Ledger
# ---------------------------------------------------------------------------

def tool_hypothesis_add(args: dict[str, Any]) -> dict:
    err = _require_ledger()
    if err is not None:
        return err
    return STATE.ledger.add(
        statement=str(args.get("statement", "")),
        confidence=str(args.get("confidence", "low")),
        falsification_plan=str(args.get("falsification_plan", "")),
        supporting=args.get("supporting"),
        contradicting=args.get("contradicting"),
        depends_on=args.get("depends_on"),
        conflicts_with=args.get("conflicts_with"),
        next_experiment=args.get("next_experiment"),
        reason_for_experiment=args.get("reason_for_experiment"),
    )


def tool_hypothesis_update(args: dict[str, Any]) -> dict:
    err = _require_ledger()
    if err is not None:
        return err
    return STATE.ledger.update(
        hid=str(args.get("id", "")),
        confidence=args.get("confidence"),
        add_supporting=args.get("add_supporting"),
        add_contradicting=args.get("add_contradicting"),
        next_experiment=args.get("next_experiment"),
        reason_for_experiment=args.get("reason_for_experiment"),
        falsification_attempted=args.get("falsification_attempted"),
    )


def tool_hypothesis_conclude(args: dict[str, Any]) -> dict:
    err = _require_ledger()
    if err is not None:
        return err
    return STATE.ledger.conclude(
        hid=str(args.get("id", "")),
        final_statement=str(args.get("final_statement", "")),
        final_confidence=str(args.get("final_confidence", "")),
    )


def tool_hypothesis_abandon(args: dict[str, Any]) -> dict:
    err = _require_ledger()
    if err is not None:
        return err
    return STATE.ledger.abandon(
        hid=str(args.get("id", "")),
        reason=str(args.get("reason", "")),
    )


def tool_hypothesis_list(args: dict[str, Any]) -> dict:
    err = _require_ledger()
    if err is not None:
        return err
    return STATE.ledger.list(
        state=args.get("state"),
        with_evidence=bool(args.get("with_evidence", False)),
    )


# ---------------------------------------------------------------------------
# Data flow
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Call / module graphs + hexblock
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Crypto detection
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Trace health / volume
# ---------------------------------------------------------------------------

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
    try:
        result = subprocess.run(
            [str(STATE.daemon.binary), "fold", *cli_args],
            capture_output=True, text=True, timeout=600, check=False,
        )
    except subprocess.TimeoutExpired:
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


# ---------------------------------------------------------------------------
# Dispatch table — single source of truth for the JSON-RPC layer.
# ---------------------------------------------------------------------------

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
    "hypothesis_add": tool_hypothesis_add,
    "hypothesis_update": tool_hypothesis_update,
    "hypothesis_conclude": tool_hypothesis_conclude,
    "hypothesis_abandon": tool_hypothesis_abandon,
    "hypothesis_list": tool_hypothesis_list,
    "write_artifact": tool_write_artifact,
    "list_artifacts": tool_list_artifacts,
    "read_artifact": tool_read_artifact,
    "run_static_tool": tool_run_static_tool,
}


# Set of tool names whose payloads MUST NOT be recorded into the
# ToolCallLog (those are ledger-internal ops, not evidence sources).
LEDGER_INTERNAL_TOOLS = frozenset({
    "hypothesis_add", "hypothesis_update", "hypothesis_conclude",
    "hypothesis_abandon", "hypothesis_list",
})
