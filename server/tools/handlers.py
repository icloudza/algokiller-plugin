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

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from state import STATE, AK_SEARCH_BIN
from daemon import AkSearchDaemon
from artifacts import ArtifactStore
from static_tools import run_static_tool


# ---------------------------------------------------------------------------
# Mnemonic taxonomies — used by F-3 regflow and F-14 semop post-processing.
# These mirror the classify_semop tables in ak_search but live in Python so
# the post-processing wrappers can filter/promote without C engine round-trips.
# Adding a mnemonic here without updating ak_search is fine: the wrapper is
# advisory, the engine remains the authoritative classifier.
# ---------------------------------------------------------------------------

# Instructions that genuinely write the destination register. Includes the
# common scalar + SIMD families; conservative on purpose (we'd rather mark a
# real write as "observation" than the inverse).
_REAL_WRITE_MNEMS: frozenset[str] = frozenset({
    # data movement
    "mov", "movz", "movk", "movn", "fmov", "smov", "umov",
    # loads (any ldr* family that writes to a destination register)
    "ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "ldrsh", "ldp", "ldur", "ldurb",
    "ldurh", "ldursw", "ldursb", "ldursh", "ldnp", "ldxr", "ldaxr", "ldar",
    # ALU
    "add", "adds", "sub", "subs", "neg", "negs", "mul", "smull", "umull",
    "smulh", "umulh", "madd", "msub", "mneg", "smaddl", "smsubl",
    "umaddl", "umsubl", "udiv", "sdiv",
    # bitwise
    "and", "ands", "orr", "orn", "eor", "eon", "bic", "bics", "tst",
    # shifts / rotates
    "lsl", "lsr", "asr", "ror", "lslv", "lsrv", "asrv", "rorv",
    # extends
    "sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw", "extr",
    # address calc
    "adr", "adrp",
    # NEON / SIMD writes (sampled — not exhaustive)
    "dup", "ins", "ext", "rev", "rev16", "rev32", "rev64",
    "bit", "bif", "bsl", "trn1", "trn2", "uzp1", "uzp2", "zip1", "zip2",
    # crypto extensions
    "aese", "aesmc", "aesd", "aesimc",
    "sha1c", "sha1m", "sha1p", "sha1h", "sha1su0", "sha1su1",
    "sha256h", "sha256h2", "sha256su0", "sha256su1",
    "sha512h", "sha512h2", "sha512su0", "sha512su1",
    "eor3", "rax1", "xar", "bcax",
    "pmull", "pmull2",
    "sm3partw1", "sm3partw2", "sm3ss1", "sm3tt1a", "sm3tt1b", "sm3tt2a", "sm3tt2b",
    "sm4e", "sm4ekey",
})

# Instructions that DON'T write the named destination — they merely take it as
# an input. When GumTrace emits `-> regN=X` after these, it's an *observation*
# of the register's current state, not a fresh write. Filtering these out is
# the core of F-3.
_OBSERVATION_MNEMS: frozenset[str] = frozenset({
    "cmp", "cmn", "ccmp", "ccmn", "tst",  # tst overlap is fine — compare-only path takes precedence
    "b", "bl", "br", "blr", "ret", "eret",
    "cbz", "cbnz", "tbz", "tbnz",
    "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge", "b.lo", "b.ls", "b.hi", "b.hs",
    "b.mi", "b.pl", "b.vs", "b.vc", "b.cc", "b.cs", "b.al",
    "nop", "yield", "wfe", "wfi", "sev", "sevl",
    "stp", "str", "strb", "strh", "stur", "sturb", "sturh", "stnp",
    "stxr", "stlxr", "stlr",  # stores: they observe regs as input, don't write dst-of-emit
})

# ARX-family neighbours that promote `xor_three_reg` semop hits to a stronger
# crypto_candidate verdict (F-14 — eor in isolation has 80%+ non-crypto uses;
# eor co-located with rotate+add+mul is genuinely ARX cipher round territory).
_ARX_PROMOTER_MNEMS: frozenset[str] = frozenset({
    "lsl", "lsr", "asr", "ror", "lslv", "lsrv", "asrv", "rorv",
    "add", "adds", "sub", "subs", "mul", "madd", "msub",
    "extr",  # ROR via EXTR is a common compiler choice
})


def _extract_mnem(instr: str) -> str:
    """Best-effort mnemonic extraction from an ak_search instr field.

    Format observed: '[module] 0xADDR!0xOFF MNEM operands; -> reg=val'
    or just 'MNEM operands' for synthetic fixtures. Returns lowercased
    mnemonic or '' if the field is unparseable.
    """
    if not instr:
        return ""
    # Strip optional [module] prefix
    s = instr.strip()
    if s.startswith("["):
        rb = s.find("]")
        if rb != -1:
            s = s[rb + 1:].lstrip()
    # Strip optional 0xADDR!0xOFF prefix (matches '0x...!0x...' or '0x...')
    tokens = s.split(None, 2)
    if not tokens:
        return ""
    if tokens[0].startswith("0x") and "!" in tokens[0]:
        # consume the addr token, mnem is next
        if len(tokens) >= 2:
            return tokens[1].lower()
        return ""
    return tokens[0].lower()


def _byte_reverse_hex(hex_digits: str) -> str:
    padded = hex_digits if len(hex_digits) % 2 == 0 else "0" + hex_digits
    return "0x" + "".join(reversed([padded[i:i + 2] for i in range(0, len(padded), 2)]))


def _hex_variant_set(query: str) -> list[str]:
    """All distinct variants for a 0x-hex query (canonical, byte-reversed,
    leading-zero-stripped, both). Used by F-13 to allocate per-variant limits."""
    if not query.lower().startswith("0x"):
        return [query]
    hex_digits = query[2:]
    if not re.fullmatch(r"[0-9a-fA-F]+", hex_digits):
        return [query]
    out: list[str] = []
    seen: set[str] = set()
    for cand in (query, _byte_reverse_hex(hex_digits),
                 "0x" + hex_digits.lstrip("0") if hex_digits.lstrip("0") else None,
                 _byte_reverse_hex(hex_digits.lstrip("0")) if hex_digits.lstrip("0") else None):
        if cand is None:
            continue
        key = cand.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(cand)
    return out


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


def _search_once(query: str, *, from_line: int = 0, before_line: int = 0, limit: int) -> dict:
    hex_query = query.encode("utf-8").hex()
    return STATE.daemon.request(f"match\t{from_line}\t{before_line}\t{limit}\t{hex_query}")


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

    # FIX F-1: removed silent hex byte-reversal / leading-zero-strip fallback.
    # Previously when a 0x-hex query had zero hits, the server quietly retried
    # with variants and returned those line numbers as if they were the
    # original query's hits — only differentiated by an extra `fallback_query`
    # field. Agents routinely missed that field and treated the byte-reversed
    # match as the origin of the original value, which is the textbook
    # endianness-attribution failure in trace analysis.
    # Use trace_bytes for hex literal search with explicit variant handling
    # (it returns per-variant counts and is designed for the job).
    if has_before:
        try:
            before_line = int(args["before_line"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "before_line must be an integer"}
        if before_line < 1:
            return {"status": "error", "error": "before_line must be >= 1"}
        result = _search_once(query, before_line=before_line, limit=limit)
        if (result.get("status") == "ok"
                and not str(result.get("stdout") or "").strip()
                and query.lower().startswith("0x")):
            result["hint"] = (
                "no matches for this exact 0x-hex query. For byte-reversed "
                "and leading-zero-stripped variants, use trace_bytes (it "
                "returns per-variant hit counts explicitly so you don't "
                "mistake a reversed-endian hit for the original value's source)."
            )
        return result

    try:
        from_line = int(args["from_line"])
    except (TypeError, ValueError):
        return {"status": "error", "error": "from_line must be an integer"}
    if from_line < 1:
        return {"status": "error", "error": "from_line must be >= 1"}
    result = _search_once(query, from_line=from_line, limit=limit)
    if (result.get("status") == "ok"
            and not str(result.get("stdout") or "").strip()
            and query.lower().startswith("0x")):
        result["hint"] = (
            "no matches for this exact 0x-hex query. For byte-reversed "
            "and leading-zero-stripped variants, use trace_bytes (it "
            "returns per-variant hit counts explicitly so you don't "
            "mistake a reversed-endian hit for the original value's source)."
        )
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
        # FIX gap 1 (v0.9.3, real-world large-trace audit closure):
        # If the deliverable labels any claim as "高置信推断" / "high-confidence
        # inference" tier, [H<n>] backing is mandatory regardless of whether
        # the ledger currently has any concluded hypothesis. Pre-v0.9.3 this
        # check was a soft skill rule; in production audit (684 MB / 7.1M-line
        # ARM64 trace) the agent emitted 7+ such claims with zero ledger
        # citations, bypassing the entire v0.9.0/v0.9.1 anti-hallucination
        # scaffold. The hard gate forces the agent to either (a) actually run
        # the hypothesis_add → conclude → [H<n>] loop, or (b) downgrade the
        # claim's tier label.
        high_conf_markers = check.get("high_confidence_markers_found", [])
        if high_conf_markers and not check["referenced_ids"] and len(content) > 200:
            return {"status": "error",
                    "error": ("artifact contains 'high-confidence inference' tier "
                              "claims but cites no [H<n>] backing"),
                    "high_confidence_markers_found": high_conf_markers,
                    "instruction": (
                        f"The deliverable uses tier marker(s) {high_conf_markers!r} "
                        "but no [H<n>] hypothesis is cited. v0.9.3 anti-hallucination "
                        "rule (general mode): any 'high-confidence inference' tier "
                        "claim must trace back to a concluded hypothesis in the "
                        "ledger. Either:\n"
                        "  1) Run hypothesis_add → gather evidence → "
                        "hypothesis_conclude(>=medium) → cite as [H<n>] in the "
                        "narrative, OR\n"
                        "  2) Downgrade the marker to '推断' / 'inference' / "
                        "'tentative' if you don't have the evidence to back high "
                        "confidence. Don't ship a high-confidence label without a "
                        "ledger entry — that's exactly what the FIX#1-#7 scaffold "
                        "is built to prevent."),
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
        falsification_evidence=args.get("falsification_evidence"),
    )


def tool_mark_hypothesis_reviewed(args: dict[str, Any]) -> dict:
    err = _require_ledger()
    if err is not None:
        return err
    return STATE.ledger.mark_reviewed(
        hid=str(args.get("id", "")),
        verdict=str(args.get("verdict", "")),
        reason=str(args.get("reason", "")),
    )


def tool_hypothesis_archive(args: dict[str, Any]) -> dict:
    err = _require_ledger()
    if err is not None:
        return err
    return STATE.ledger.archive(
        hid=str(args.get("id", "")),
        reason=str(args.get("reason", "")),
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

def _parse_jsonl(stdout: str) -> list[dict]:
    """Parse newline-delimited JSON objects from ak_search stdout. Tolerant
    of trailing whitespace and empty lines. Lines that fail to decode are
    skipped (engine occasionally interleaves info messages)."""
    out: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def tool_trace_regflow(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    reg = str(args.get("reg", "")).strip()
    if not reg:
        return {"status": "error", "error": "reg must not be empty",
                "_skip_discipline": True}
    cli_args: list[str] = ["--reg", reg]
    if "from_line" in args:
        try:
            cli_args += ["--from-line", str(int(args["from_line"]))]
        except (TypeError, ValueError):
            return {"status": "error", "error": "from_line must be an integer",
                    "_skip_discipline": True}
    if "to_line" in args:
        try:
            cli_args += ["--to-line", str(int(args["to_line"]))]
        except (TypeError, ValueError):
            return {"status": "error", "error": "to_line must be an integer",
                    "_skip_discipline": True}
    if "limit" in args:
        try:
            limit = int(args["limit"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "limit must be an integer",
                    "_skip_discipline": True}
        if not (1 <= limit <= 1000):
            return {"status": "error", "error": "limit must be in [1, 1000]",
                    "_skip_discipline": True}
        cli_args += ["--limit", str(limit)]
    include_observations = bool(args.get("include_observations", False))
    result = STATE.daemon.run_cli("regflow", cli_args)
    if result.get("status") != "ok":
        return result
    # FIX F-3: classify each row's mnemonic to distinguish real register
    # writes from "observation emits" (cmp/tst/cbz/bl/ret etc that GumTrace
    # records as `-> regN=X` but where regN was an INPUT not a freshly-
    # written destination). Counting these as writes was the textbook
    # ARM64-trace mistake that made hash main loops look noisy.
    rows = _parse_jsonl(result.get("stdout") or "")
    kept_lines: list[str] = []
    write_count = 0
    observation_count = 0
    unclassified_count = 0
    for row in rows:
        mnem = _extract_mnem(row.get("instr", ""))
        if mnem in _OBSERVATION_MNEMS:
            row["kind"] = "observation"
            observation_count += 1
            if include_observations:
                kept_lines.append(json.dumps(row, ensure_ascii=False))
        elif mnem in _REAL_WRITE_MNEMS:
            row["kind"] = "write"
            write_count += 1
            kept_lines.append(json.dumps(row, ensure_ascii=False))
        else:
            row["kind"] = "unclassified"
            unclassified_count += 1
            # Default-include: unknown mnemonics are usually genuine writes
            # that our taxonomy hasn't catalogued yet. Better to over-report
            # than to silently drop a real cipher instruction.
            kept_lines.append(json.dumps(row, ensure_ascii=False))
    result["stdout"] = "\n".join(kept_lines)
    result["regflow_summary"] = {
        "writes": write_count,
        "observations_filtered": 0 if include_observations else observation_count,
        "observations_present": observation_count,
        "unclassified": unclassified_count,
        "include_observations": include_observations,
    }
    if observation_count > 0 and not include_observations:
        result["instruction"] = (
            f"Filtered {observation_count} observation-emit row(s) (cmp/tst/cbz/bl/ret etc — "
            "they record the register's current state without writing it). Pass "
            "include_observations=true if you need the raw GumTrace view."
        )
    return result


def tool_trace_producer(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    value = str(args.get("value", "")).strip()
    if not value or not value.lower().startswith("0x"):
        return {"status": "error", "error":
                "value must be a 0x-prefixed hex literal, e.g. '0xa1b2c3d4'",
                "_skip_discipline": True}
    # FIX F-2: short-value collision protection. 0x0 / 0x1 / 0xff appear
    # everywhere in a long ARM64 trace; "most recent write" of those is
    # almost never what the agent meant. Reject by default; agent can
    # override via min_hex_length=1 if they really want.
    hex_digits = value[2:]
    if not re.fullmatch(r"[0-9a-fA-F]+", hex_digits):
        return {"status": "error",
                "error": "value must be a valid hex literal",
                "_skip_discipline": True}
    try:
        min_hex_length = int(args.get("min_hex_length", 4))
    except (TypeError, ValueError):
        return {"status": "error",
                "error": "min_hex_length must be an integer",
                "_skip_discipline": True}
    if len(hex_digits.lstrip("0")) < min_hex_length:
        return {"status": "error", "error":
                (f"value {value!r} has {len(hex_digits.lstrip('0'))} significant hex "
                 f"digits, below min_hex_length={min_hex_length}. Short values "
                 "(0x0 / 0x1 / 0xff) collide with thousands of unrelated writes in "
                 "an ARM64 trace — producer's 'most recent' result is almost never "
                 "the cipher source. Either pick a more distinctive value or set "
                 "min_hex_length=1 to override."),
                "_skip_discipline": True}
    try:
        sink_line = int(args.get("sink_line", 0))
    except (TypeError, ValueError):
        return {"status": "error", "error": "sink_line must be an integer",
                "_skip_discipline": True}
    if sink_line < 2:
        return {"status": "error", "error": "sink_line must be >= 2",
                "_skip_discipline": True}
    target_reg = str(args.get("target_reg", "")).strip().lower() or None
    cli_args: list[str] = ["--value", value, "--sink-line", str(sink_line)]
    if "max_back" in args:
        try:
            mb = int(args["max_back"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "max_back must be an integer",
                    "_skip_discipline": True}
        if mb < 1:
            return {"status": "error", "error": "max_back must be >= 1",
                    "_skip_discipline": True}
        cli_args += ["--max-back", str(mb)]
    result = STATE.daemon.run_cli("producer", cli_args)
    if result.get("status") != "ok":
        return result
    # FIX F-2: post-filter on target_reg if the agent specified one. The
    # engine returns the "most recent ANY-reg write of this value", but in
    # crypto analysis the agent usually wants "most recent write of value
    # INTO x0 specifically before the bl encrypt". If the most recent
    # writer is a different register (SIMD spill, register-allocator reuse),
    # surface that mismatch as a warning rather than silently returning a
    # misleading answer.
    rows = _parse_jsonl(result.get("stdout") or "")
    if target_reg and rows:
        producer_row = rows[0]
        actual_reg = str(producer_row.get("reg", "")).lower()
        if actual_reg and actual_reg != target_reg:
            result["target_reg_mismatch"] = {
                "requested": target_reg,
                "actual": actual_reg,
                "line": producer_row.get("line"),
            }
            result["instruction"] = (
                f"The most recent writer of {value} in the {sink_line}-line backward "
                f"window is register {actual_reg!r}, not the requested {target_reg!r}. "
                f"This is common: ARM64 register allocator reuses temporaries, and "
                f"SIMD spills can briefly hold the value. If you specifically need "
                f"the most recent write into {target_reg!r}, narrow max_back or "
                f"consider using trace_regflow(reg={target_reg!r}) to see the full "
                f"write history of that register and then locate the one with this value."
            )
    return result


def tool_trace_semop(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    has_line = "line" in args
    has_range = "from_line" in args and "to_line" in args
    if not has_line and not has_range:
        return {"status": "error",
                "error": "provide either 'line' or both 'from_line' and 'to_line'",
                "_skip_discipline": True}
    cli_args: list[str] = []
    if has_line:
        try:
            cli_args += ["--line", str(int(args["line"]))]
        except (TypeError, ValueError):
            return {"status": "error", "error": "line must be an integer",
                    "_skip_discipline": True}
    else:
        try:
            cli_args += ["--from-line", str(int(args["from_line"])), "--to-line", str(int(args["to_line"]))]
        except (TypeError, ValueError):
            return {"status": "error", "error": "from_line / to_line must be integers",
                    "_skip_discipline": True}
    if "limit" in args:
        try:
            limit = int(args["limit"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "limit must be an integer",
                    "_skip_discipline": True}
        if not (1 <= limit <= 1000):
            return {"status": "error", "error": "limit must be in [1, 1000]",
                    "_skip_discipline": True}
        cli_args += ["--limit", str(limit)]
    result = STATE.daemon.run_cli("semop", cli_args)
    if result.get("status") != "ok":
        return result
    # FIX F-14: discriminate `eor x,y,z` ARX-context (genuinely cipher-round)
    # from bare bitwise-XOR (constant-time conditional, byteswap optimisation,
    # base64 lookup, network CRC software path — all 80%+ of crypto_candidate
    # false-positives). Look at a ±3-line window for rotate/add/mul co-located
    # neighbours; if any present, keep `crypto_candidate`. Otherwise downgrade
    # to a new `xor_three_reg` label so the agent treats it as a lead, not as
    # a positive identification.
    rows = _parse_jsonl(result.get("stdout") or "")
    if rows:
        # Build line→mnem lookup for the returned range
        by_line: dict[int, str] = {}
        for r in rows:
            ln = r.get("line")
            if isinstance(ln, int):
                by_line[ln] = _extract_mnem(r.get("instr", ""))
        promotions = 0
        downgrades = 0
        for row in rows:
            cls = row.get("class")
            if cls != "crypto_candidate":
                continue
            ln = row.get("line")
            if not isinstance(ln, int):
                continue
            has_arx = False
            for delta in range(-3, 4):
                if delta == 0:
                    continue
                neighbour = by_line.get(ln + delta)
                if neighbour and neighbour in _ARX_PROMOTER_MNEMS:
                    has_arx = True
                    break
            if has_arx:
                row["subclass"] = "crypto_arx"
                promotions += 1
            else:
                row["subclass"] = "xor_three_reg"
                row["class_hint"] = ("bare eor without ARX neighbours within ±3 "
                                     "lines — common in constant-time conditionals, "
                                     "byteswap, base64 lookup, software CRC. Lead, "
                                     "not confirmation.")
                downgrades += 1
        result["stdout"] = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
        result["semop_arx_summary"] = {
            "crypto_arx_promoted": promotions,
            "xor_three_reg_downgraded": downgrades,
            "note": ("FIX F-14: crypto_candidate hits are now sub-classified by "
                     "ARX-neighbour co-occurrence. Treat xor_three_reg as a lead "
                     "requiring corroboration, not as evidence of cipher round."),
        }
    return result


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
        return {"status": "error", "error": "provide exactly one of 'to' or 'top'",
                "_skip_discipline": True}
    if not has_to and not has_top:
        return {"status": "error", "error": "provide 'to' (substring) or 'top' (Top-K)",
                "_skip_discipline": True}
    # FIX F-7: explicit match mode. The engine does substring match by
    # default which over-counts: query='memcpy' matches '_memcpy',
    # '__memcpy_aarch64_simd', 'safe_memcpy_helper', and any ObjC
    # '-[NSData memcpyImpl:]' simultaneously. Default to exact match for
    # crypto / hash analysis where you usually want one specific symbol.
    match_mode = str(args.get("match", "exact")).strip().lower()
    if match_mode not in ("exact", "prefix", "substring"):
        return {"status": "error",
                "error": "match must be one of 'exact' | 'prefix' | 'substring' (default exact)",
                "_skip_discipline": True}
    cli: list[str] = []
    if has_to:
        target = str(args["to"]).strip()
        cli += ["--to", target]
        if "limit" in args:
            try:
                limit = int(args["limit"])
            except (TypeError, ValueError):
                return {"status": "error", "error": "limit must be an integer",
                        "_skip_discipline": True}
            if not (1 <= limit <= 1000):
                return {"status": "error", "error": "limit must be in [1, 1000]",
                        "_skip_discipline": True}
            cli += ["--limit", str(limit)]
    else:
        try:
            top = int(args["top"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "top must be an integer",
                    "_skip_discipline": True}
        if not (1 <= top <= 200):
            return {"status": "error", "error": "top must be in [1, 200]",
                    "_skip_discipline": True}
        cli += ["--top", str(top)]
    result = STATE.daemon.run_cli("callgraph", cli, timeout=120)
    if result.get("status") != "ok" or not has_to or match_mode == "substring":
        return result
    # Post-filter xref rows for exact / prefix match modes.
    rows = _parse_jsonl(result.get("stdout") or "")
    target_lower = target.lower()
    kept_lines: list[str] = []
    kept_count = 0
    by_name: dict[str, int] = {}
    dropped = 0
    for row in rows:
        rtype = row.get("type")
        if rtype == "callgraph_xref":
            name = str(row.get("name", ""))
            name_lower = name.lower()
            by_name[name] = by_name.get(name, 0) + 1
            if match_mode == "exact" and name_lower != target_lower:
                dropped += 1
                continue
            if match_mode == "prefix" and not name_lower.startswith(target_lower):
                dropped += 1
                continue
            kept_lines.append(json.dumps(row, ensure_ascii=False))
            kept_count += 1
        elif rtype == "callgraph_summary":
            # Re-issue summary reflecting the filter
            row["emitted"] = kept_count
            row["match_mode"] = match_mode
            row["dropped_by_match_filter"] = dropped
            if dropped > 0 and by_name:
                row["distinct_symbols_seen"] = sorted(by_name.keys())[:20]
            kept_lines.append(json.dumps(row, ensure_ascii=False))
        else:
            kept_lines.append(json.dumps(row, ensure_ascii=False))
    result["stdout"] = "\n".join(kept_lines)
    if match_mode == "exact" and dropped > 0:
        result["instruction"] = (
            f"Filtered {dropped} non-exact substring match(es). The engine matches "
            f"on substring; with match='exact' (default), only call_name == "
            f"{target!r} survives. Distinct symbols seen "
            f"(grouped by C/Obj-C/Swift name): {sorted(by_name.keys())[:8]}. "
            f"Pass match='substring' for the legacy behaviour, or "
            f"match='prefix' for namespace-style filtering."
        )
    return result


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
        return {"status": "error", "error": "line must be an integer",
                "_skip_discipline": True}
    if line < 1:
        return {"status": "error", "error": "line must be >= 1",
                "_skip_discipline": True}
    try:
        max_lines = int(args.get("max_lines", 1024))
    except (TypeError, ValueError):
        return {"status": "error", "error": "max_lines must be an integer",
                "_skip_discipline": True}
    if not (1 <= max_lines <= 10000):
        return {"status": "error", "error": "max_lines must be in [1, 10000]",
                "_skip_discipline": True}
    cli: list[str] = ["--line", str(line), "--max-lines", str(max_lines)]
    result = STATE.daemon.run_cli("hexblock", cli, timeout=60)
    if result.get("status") != "ok":
        return result
    # FIX F-6 partial (Python-side defensive check): if the engine returns a
    # block but no `ret` field, OR `lines_scanned` reached max_lines without
    # closing, the block boundary is unconfirmed. In that case the hexdumps
    # may belong to a nested inner call (張冠李戴 — the canonical GumTrace
    # data-corruption mode). Surface this explicitly so the agent does NOT
    # treat the hexdumps as evidence of the outer call's inputs/outputs.
    # The full C-engine nested-depth counter ships in 0.9.2.
    rows = _parse_jsonl(result.get("stdout") or "")
    if rows:
        block = rows[0]
        lines_scanned = block.get("lines_scanned", 0)
        has_ret = "ret" in block and block.get("ret") not in (None, "")
        # F-15 schema note: direction info (mem_r vs mem_w → input vs output)
        # is not currently emitted per hexdump. Tag each hexdump with
        # direction="unknown" so the agent sees the gap explicitly.
        for hd in block.get("hexdumps", []) or []:
            if "direction" not in hd:
                hd["direction"] = "unknown"
        if not has_ret or (max_lines > 1 and lines_scanned >= max_lines):
            block["status"] = "truncated"
            block["warning"] = (
                f"hexblock boundary NOT confirmed: max_lines={max_lines} scanned without "
                f"finding the matching 'ret'. The hexdumps in this block MAY belong to a "
                f"nested inner call (classic GumTrace 張冠李戴 pattern). Do NOT cite these "
                f"hexdumps as evidence of {block.get('call', 'this')!r}'s inputs/outputs "
                f"until you re-run with a larger max_lines and confirm a true outer ret. "
                f"(F-6 nested-depth counter ships in 0.9.2; current behavior is "
                f"max_lines-bounded scan without nesting awareness.)"
            )
            result["status"] = "ok_truncated"
            result["instruction"] = block["warning"]
        result["stdout"] = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
    return result


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
        return {"status": "error", "error": "query must be a 0x-prefixed hex literal",
                "_skip_discipline": True}
    if "limit" in args:
        try:
            lim = int(args["limit"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "limit must be an integer",
                    "_skip_discipline": True}
        if not (1 <= lim <= 10000):
            return {"status": "error", "error": "limit must be in [1, 10000]",
                    "_skip_discipline": True}
    else:
        lim = 100
    with_text = bool(args.get("with_text"))
    # FIX F-13: the engine truncates total hits across all variants at `limit`,
    # so a canonical-heavy result can completely hide the byte-reversed
    # variant (causing agents to conclude "no reversed-endian match" when
    # there are actually plenty). Allocate the limit evenly per variant and
    # also report per-variant total counts (a high count under the
    # allocation tells the agent to ask for more).
    variants = _hex_variant_set(query)
    per_variant_limit = max(1, lim // max(1, len(variants)))
    hits_total: list[dict] = []
    per_variant_emitted: dict[str, int] = {}
    queries_seen: list[str] = []
    for variant in variants:
        cli: list[str] = ["--query", variant, "--limit", str(per_variant_limit)]
        if with_text:
            cli.append("--with-text")
        sub_result = STATE.daemon.run_cli("bytes", cli, timeout=120)
        if sub_result.get("status") != "ok":
            return sub_result
        rows = _parse_jsonl(sub_result.get("stdout") or "")
        for row in rows:
            if row.get("type") == "bytes_summary":
                for q in row.get("queries", []) or []:
                    if q not in queries_seen:
                        queries_seen.append(q)
                for hit in row.get("hits", []) or []:
                    # Engine reports `variant` per hit — preserve it
                    v = hit.get("variant") or variant
                    hits_total.append(hit)
                    per_variant_emitted[v] = per_variant_emitted.get(v, 0) + 1
    summary = {
        "type": "bytes_summary",
        "queries": queries_seen or variants,
        "hits": hits_total,
        "per_variant_emitted": per_variant_emitted,
        "per_variant_limit": per_variant_limit,
        "note": ("FIX F-13: limit allocated evenly across variants so a "
                 "canonical-heavy result cannot hide reversed-endian matches."),
    }
    return {
        "status": "ok",
        "stdout": json.dumps(summary, ensure_ascii=False),
        "stderr": "",
        "returncode": 0,
        "truncated": False,
    }


def tool_trace_cryptoinstr(args: dict[str, Any]) -> dict:
    err = _require_bound()
    if err is not None:
        return err
    cli: list[str] = []
    if "samples" in args:
        try:
            s = int(args["samples"])
        except (TypeError, ValueError):
            return {"status": "error", "error": "samples must be an integer",
                    "_skip_discipline": True}
        if not (1 <= s <= 8):
            return {"status": "error", "error": "samples must be in [1, 8]",
                    "_skip_discipline": True}
        cli += ["--samples", str(s)]
    result = STATE.daemon.run_cli("cryptoinstr", cli, timeout=120)
    if result.get("status") != "ok":
        return result
    # FIX F-5: primitive-level corroboration. The engine reports raw mnemonic
    # counts per primitive but treats e.g. eor3=SHA-3 as if a single hit
    # confirmed Keccak — false. Real SHA-3 uses Keccak's χ/ρ/π/θ rounds so
    # eor3 must co-occur with rax1 / xar / bcax. Real GHASH uses GCM mode so
    # pmull must co-occur with aese. Without co-occurrence the hit is
    # ambiguous — pmull alone is more often CRC / FEC / erasure code.
    parsed = _parse_jsonl(result.get("stdout") or "")
    if not parsed:
        return result
    summary_row = parsed[0]
    if summary_row.get("type") != "cryptoinstr":
        return result
    mnem_seen: set[str] = set()
    for hit in summary_row.get("hits", []) or []:
        m = str(hit.get("mnem", "")).lower()
        if m:
            mnem_seen.add(m)

    def has(group: set[str]) -> bool:
        return any(m in mnem_seen for m in group)

    def overlap(group: set[str]) -> list[str]:
        return sorted([m for m in group if m in mnem_seen])

    aes_set = {"aese", "aesmc", "aesd", "aesimc"}
    sha1_set = {"sha1c", "sha1m", "sha1p", "sha1h", "sha1su0", "sha1su1"}
    sha256_set = {"sha256h", "sha256h2", "sha256su0", "sha256su1"}
    sha512_set = {"sha512h", "sha512h2", "sha512su0", "sha512su1"}
    sha3_set = {"eor3", "rax1", "xar", "bcax"}
    pmull_set = {"pmull", "pmull2"}
    sm3_set = {"sm3partw1", "sm3partw2", "sm3ss1",
               "sm3tt1a", "sm3tt1b", "sm3tt2a", "sm3tt2b"}
    sm4_set = {"sm4e", "sm4ekey"}

    corroboration: dict[str, dict] = {}

    # AES: any aese/aesd is essentially a smoking gun (hardware AES has no
    # general-purpose use outside AES rounds).
    aes_overlap = overlap(aes_set)
    if aes_overlap:
        corroboration["AES"] = {
            "verdict": "confirmed",
            "found": aes_overlap,
            "note": "ARM Crypto Extensions AES mnemonics have no non-AES use.",
        }

    # SHA-1: any sha1c / sha1p / sha1m / sha1h confirms.
    sha1_overlap = overlap(sha1_set)
    if sha1_overlap:
        corroboration["SHA-1"] = {
            "verdict": "confirmed",
            "found": sha1_overlap,
            "note": "ARM Crypto Extensions SHA-1 mnemonics are SHA-1 specific.",
        }

    sha256_overlap = overlap(sha256_set)
    if sha256_overlap:
        corroboration["SHA-256"] = {
            "verdict": "confirmed",
            "found": sha256_overlap,
            "note": "ARM Crypto Extensions SHA-256 mnemonics are SHA-256 specific.",
        }

    sha512_overlap = overlap(sha512_set)
    if sha512_overlap:
        corroboration["SHA-512"] = {
            "verdict": "confirmed",
            "found": sha512_overlap,
            "note": "ARM Crypto Extensions SHA-512 mnemonics are SHA-512 specific.",
        }

    # SHA-3 (Keccak): NOT confirmed by eor3 alone — it's also generic 3-way
    # XOR. Requires at least one of {rax1, xar, bcax} (Keccak's other χ/ρ/π
    # building blocks).
    sha3_overlap = overlap(sha3_set)
    if "eor3" in mnem_seen and {"rax1", "xar", "bcax"} & mnem_seen:
        corroboration["SHA-3"] = {
            "verdict": "confirmed",
            "found": sha3_overlap,
            "note": "Keccak χ/ρ/π corroboration — eor3 + (rax1|xar|bcax) present.",
        }
    elif "eor3" in mnem_seen:
        corroboration["SHA-3"] = {
            "verdict": "ambiguous",
            "found": ["eor3"],
            "missing_required_at_least_one": ["rax1", "xar", "bcax"],
            "note": ("eor3 in isolation is also a generic 3-way XOR used by "
                     "Keccak/SHAKE, ZK / FEC libraries, SIMD bit tricks. "
                     "Treat as lead, not as evidence of SHA-3 specifically."),
        }
    elif {"rax1", "xar", "bcax"} & mnem_seen:
        corroboration["SHA-3"] = {
            "verdict": "suspected",
            "found": sha3_overlap,
            "note": ("rax1/xar/bcax present without eor3 — partial Keccak "
                     "but main χ-step mnemonic missing."),
        }

    # GHASH: pmull alone is ambiguous (CRC, erasure code, GF(2^n) generic).
    # Confirmed only if aese also present (GCM mode = AES + GHASH).
    pmull_overlap = overlap(pmull_set)
    if pmull_overlap and ("aese" in mnem_seen):
        corroboration["GHASH"] = {
            "verdict": "confirmed",
            "found": pmull_overlap + ["aese (corroborates GCM context)"],
            "note": "pmull + aese is the canonical AES-GCM pattern.",
        }
    elif pmull_overlap:
        corroboration["GHASH"] = {
            "verdict": "ambiguous",
            "found": pmull_overlap,
            "missing_required_at_least_one": ["aese"],
            "note": ("pmull/pmull2 without AES context is more often CRC32 "
                     "(network stack), Reed-Solomon erasure code (storage), "
                     "or generic GF(2^n). Look for aese co-occurrence before "
                     "concluding GHASH/GCM."),
        }

    sm3_overlap = overlap(sm3_set)
    if sm3_overlap:
        corroboration["SM3"] = {
            "verdict": "confirmed",
            "found": sm3_overlap,
            "note": "ARM Crypto Extensions SM3 mnemonics are SM3 specific.",
        }

    sm4_overlap = overlap(sm4_set)
    if sm4_overlap:
        corroboration["SM4"] = {
            "verdict": "confirmed",
            "found": sm4_overlap,
            "note": "ARM Crypto Extensions SM4 mnemonics are SM4 specific.",
        }

    summary_row["primitive_corroboration"] = corroboration
    summary_row["corroboration_note"] = (
        "FIX F-5: per-primitive verdict accounts for co-occurrence requirements. "
        "'confirmed' = mnemonic itself is primitive-exclusive; 'suspected' = "
        "partial pattern; 'ambiguous' = mnemonic has significant non-crypto use "
        "and needs additional corroboration before naming the primitive."
    )
    result["stdout"] = json.dumps(summary_row, ensure_ascii=False)
    return result


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
    # FIX A-4: out_filename replaces the old absolute-out_path contract.
    # Previously the agent could pass any /absolute/path and trace_fold would
    # write there — bypassing the artifacts_dir containment every other write
    # path enforces. Now we accept a relative filename and resolve it under
    # the current session's artifacts directory.
    # Backward-compat: keep accepting out_path, but force it under artifacts_dir.
    out_filename = str(args.get("out_filename", "")).strip()
    out_path_arg = str(args.get("out_path", "")).strip()
    if not out_filename and not out_path_arg:
        return {"status": "error",
                "error": "out_filename (preferred) or out_path is required"}
    if STATE.artifacts_dir is None:
        return {"status": "error", "error": "artifacts dir not initialised"}
    art_dir = Path(STATE.artifacts_dir).resolve()
    if out_filename:
        # Reject any path component / parent traversal
        if "/" in out_filename or "\\" in out_filename or out_filename in ("", ".", ".."):
            return {"status": "error",
                    "error": "out_filename must be a single filename "
                             "(no directory components, no '..')"}
        out_path = str((art_dir / out_filename).resolve())
    else:
        out_path = str(Path(out_path_arg).expanduser().resolve())
        try:
            Path(out_path).relative_to(art_dir)
        except ValueError:
            return {"status": "error",
                    "error": (f"out_path must be under the session artifacts "
                              f"directory {art_dir}. Use out_filename "
                              "(single filename) instead — fold output is "
                              "written into the session dir automatically.")}
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
    "mark_hypothesis_reviewed": tool_mark_hypothesis_reviewed,
    "hypothesis_archive": tool_hypothesis_archive,
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
    "mark_hypothesis_reviewed", "hypothesis_archive",
})
