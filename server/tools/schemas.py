"""JSON-Schema declarations for every MCP tool exposed by algokiller.

This module is the single source of truth for what `tools/list` returns.
Tool implementations live in `server/tools/handlers.py` and are dispatched
by name — adding a new tool means appending an entry here AND wiring the
handler in `handlers.HANDLERS`.

Kept deliberately free of runtime imports beyond the allow-list lookup so
the schema list can be inspected statically (e.g. by tests, doc generators).
"""

from __future__ import annotations

from typing import Any

from static_tools import ALLOWED_TOOLS as STATIC_TOOLS_ALLOW


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
            "from_line searches forward in line order (matches returned earliest-first). "
            "before_line searches strictly before the given line and returns hits nearest "
            "to the cutoff FIRST, i.e. ordered from latest-earlier-match to earliest-earlier-"
            "match (FIX F-11 v0.9.1: language clarified — agents previously misread this).\n\n"
            "FIX F-1 (v0.9.1): silent byte-reversed / leading-zero-stripped fallback was "
            "removed. Use trace_bytes for hex literal search — it explicitly enumerates "
            "variants and returns per-variant hit counts. When trace_search returns zero "
            "hits for a 0x-prefixed query, the response now includes a `hint` field "
            "pointing at trace_bytes."
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
            "repeated trace_search calls + manual reconstruction.\n\n"
            "FIX F-3 (v0.9.1): each row is now tagged with `kind`:\n"
            "  - 'write':         mov/ldr/add/sub/orr/and/eor/mul/lsl/lsr/madd/msub etc — "
            "actually writes the destination register.\n"
            "  - 'observation':   cmp/tst/cbz/bl/ret etc — GumTrace records the register's "
            "current value as a side effect but the instruction does NOT write it.\n"
            "  - 'unclassified':  taxonomy not yet covering this mnemonic; included by default.\n"
            "By default observation rows are FILTERED OUT. The response includes "
            "`regflow_summary.observations_filtered`. Pass include_observations=true for the "
            "raw GumTrace view (e.g. when auditing what was compared, not just written)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "reg": {"type": "string", "description": "Register name, e.g. 'x0', 'x9', 'w12', 'sp', 'fp'."},
                "from_line": {"type": "integer", "minimum": 1, "description": "1-based start line (default 1)."},
                "to_line": {"type": "integer", "minimum": 1, "description": "1-based end line (default last)."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Max records (default 100)."},
                "include_observations": {"type": "boolean",
                                          "description": "Include observation-emit rows (cmp/tst/cbz/bl/ret etc). Default false."},
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
            "when chasing where a value came from.\n\n"
            "FIX F-2 (v0.9.1):\n"
            "  - min_hex_length (default 4): short values (0x0/0x1/0xff) collide with thousands "
            "    of unrelated writes; rejected unless overridden.\n"
            "  - target_reg: optional — if provided and the most recent writer is a DIFFERENT "
            "    register (common: ARM64 register-allocator reuse, SIMD spill), the response "
            "    surfaces `target_reg_mismatch` instead of silently returning a misleading row."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "Target value as 0x-prefixed hex, e.g. '0xa1b2c3d4'."},
                "sink_line": {"type": "integer", "minimum": 2, "description": "1-based sink line; search scans lines strictly before this."},
                "max_back": {"type": "integer", "minimum": 1, "description": "Maximum lines to scan backward (default 100000)."},
                "target_reg": {"type": "string",
                                "description": "Optional register filter (x0/w0/x9 etc). If the most recent writer is a different register, a mismatch warning is surfaced."},
                "min_hex_length": {"type": "integer", "minimum": 1, "maximum": 16,
                                    "description": "Reject values with fewer significant hex digits (default 4 — protects against 0x0/0x1/0xff collisions)."},
            },
            "required": ["value", "sink_line"],
        },
    },
    {
        "name": "trace_callgraph",
        "description": (
            "Caller/callee analysis over 'call func: NAME(args)' lines. Two modes: "
            "--to NAME returns every line that calls a function matching NAME. "
            "--top N returns the Top-K most-called symbols with counts.\n\n"
            "FIX F-7 (v0.9.1): explicit match mode. The engine matches on substring "
            "by default, which over-counts when one common name is a prefix of others "
            "(query 'memcpy' silently matches '_memcpy', '__memcpy_aarch64_simd', "
            "'safe_memcpy_helper', '-[NSData memcpyImpl:]'). The `match` parameter "
            "now controls this:\n"
            "  - 'exact'      (default): only call_name == target.\n"
            "  - 'prefix'     : call_name.startswith(target).\n"
            "  - 'substring'  : legacy engine behaviour.\n"
            "Filtered hits surface in `dropped_by_match_filter`, with the distinct "
            "symbols seen listed in the summary so the agent can disambiguate."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Function name (default exact match; see `match`)."},
                "top": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Top-K most-called names; mutually exclusive with --to."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Max xref rows when --to is set (default 100)."},
                "match": {"type": "string", "enum": ["exact", "prefix", "substring"],
                          "description": "Symbol match mode (default exact)."},
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
            "before drilling into a specific call boundary.\n\n"
            "KNOWN GAP F-8 (deferred to 0.9.2): edge counts include EVERY adjacent-line "
            "module transition, not just bl/blr/ret call boundaries. A function call "
            "A→B→ret→A inside a loop registers as TWO transitions per iteration even "
            "though it's one caller-callee relationship. Treat counts as relative weight "
            "indicators, not as literal call counts. To find specific call sites use "
            "trace_callgraph --to <symbol> --match exact instead."
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
            "encryption helper. ASCII preview is not emitted — use the bytes_hex directly.\n\n"
            "FIX F-6 partial (v0.9.1 Python defensive check): when max_lines scan reaches the "
            "limit without finding a matching `ret`, the response status flips to "
            "`ok_truncated` and the block carries a `warning` field. The hexdumps in a "
            "truncated block MAY belong to a nested inner call (classic GumTrace 張冠李戴 "
            "data-corruption pattern) — do NOT cite them as evidence until re-run with "
            "larger max_lines confirms a true outer ret. C-engine nested-depth counter "
            "ships in 0.9.2 to make this watertight.\n\n"
            "KNOWN GAP F-15 (deferred to 0.9.2): hexdumps currently report "
            "`direction='unknown'`. In 0.9.2 each dump will be tagged 'in' (mem_r) or "
            "'out' (mem_w) so the agent can distinguish memcpy(src=in, dst=out) at a "
            "glance."
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
            "Categories: hash / cipher / cipher_hint / crc.\n\n"
            "KNOWN GAP F-4 (deferred to 0.9.2): the scanner currently inspects instruction "
            "output values (`-> reg=MAGIC`) and direct memory reads (`mem_r=MAGIC`). It does "
            "NOT yet scan `adrp + ldr literal_pool` sequences emitted by clang -O on iOS / "
            "Apple platforms — 32-bit crypto constants compile to `adrp x9, page` + `ldr w0, "
            "[x9, #off]` where the magic lives in the .rodata pool, not the instruction line. "
            "On iOS apps `constscan` may report 0 hits when the binary actually IS doing MD5. "
            "If you suspect this case, corroborate with `trace_cryptoinstr` and "
            "`trace_callgraph --to <crypto_symbol>` before concluding 'no crypto'. The C-side "
            "EV_POOL_LOAD detector ships in 0.9.2."
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
            "token-frugal (just line + variant).\n\n"
            "FIX F-13 (v0.9.1): limit is now allocated evenly PER VARIANT (canonical, "
            "byte-reversed, leading-zero-stripped). Previously the engine returned the first "
            "`limit` hits in canonical-first order, so a canonical-heavy result could entirely "
            "hide reversed-endian matches and make agents conclude 'no reversed hit' when "
            "there were plenty. Response now includes `per_variant_emitted` so the agent "
            "can immediately tell which variant carries the signal."
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
            "Android Keystore HW path) use these instructions on iPhone 5s+ / Pixel / etc.\n\n"
            "FIX F-5 (v0.9.1): per-primitive `verdict` (confirmed | suspected | ambiguous) is "
            "now computed via co-occurrence corroboration in `primitive_corroboration`:\n"
            "  - AES / SHA-1 / SHA-256 / SHA-512 / SM3 / SM4: confirmed by single hit "
            "    (mnemonics are primitive-exclusive).\n"
            "  - SHA-3: eor3 alone is ambiguous (also generic 3-way XOR / SHAKE / ZK code). "
            "    Confirmed only if eor3 + (rax1|xar|bcax) co-occur.\n"
            "  - GHASH: pmull alone is ambiguous (also CRC32 network stack, Reed-Solomon "
            "    erasure code, GF(2^n) generic). Confirmed only if pmull + aese co-occur."
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
            "block=4 / threshold=100, retaining all data-flow boundary evidence.\n\n"
            "FIX A-4 (v0.9.1): output is FORCED into the current session artifacts directory "
            "(previously any absolute path was accepted — a path-traversal hole if the agent "
            "context was prompt-injected). Pass `out_filename` (preferred — a single filename "
            "with no directory components) and the file is written to "
            "$ARTIFACTS_DIR/<filename>. Legacy `out_path` is still accepted but must resolve "
            "under the artifacts directory.\n\n"
            "KNOWN GAP F-9 (deferred to 0.9.2): the first+last collapse strategy preserves "
            "data-flow boundary evidence but DROPS middle-round state — bad for hash "
            "algorithm identification (you can't see SHA-1's a/b/c/d/e rotation across 80 "
            "rounds when only round 1 + round 80 are kept). 0.9.2 adds samples_per_fold (3-5 "
            "evenly spaced samples between first and last) + block signature in the sentinel "
            "comment line. For now: if you need round identification, fold AFTER you've "
            "located the hash region, not before."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "out_filename": {"type": "string", "description": "Preferred: single filename (no '/' or '..') written under the session artifacts directory."},
                "out_path": {"type": "string", "description": "Legacy: absolute path. Must resolve under the session artifacts directory or it is rejected (FIX A-4)."},
                "threshold": {"type": "integer", "minimum": 3, "description": "Min repetitions to trigger a fold (default 100)."},
                "block": {"type": "integer", "minimum": 1, "maximum": 32, "description": "Block window size in lines (default 1)."},
            },
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
            "--from-line + --to-line + --limit for a range.\n\n"
            "FIX F-14 (v0.9.1): every `crypto_candidate` hit is now sub-classified by "
            "checking the ±3-line window for ARX neighbours (rotate / add / multiply):\n"
            "  - subclass='crypto_arx'     → genuinely ARX cipher-round territory.\n"
            "  - subclass='xor_three_reg'  → bare 3-way XOR with no ARX neighbour. Common in "
            "constant-time conditionals, byteswap optimisations, base64 lookups, software "
            "CRC. TREAT AS LEAD, NOT EVIDENCE — corroborate before naming a cipher.\n"
            "Summary counts arrive in `semop_arx_summary`."
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
    # ---- Hypothesis Ledger (anti-hallucination reasoning scaffold) ---------
    {
        "name": "hypothesis_add",
        "description": (
            "Create a new active hypothesis. Every claim in your final deliverable MUST be "
            "backed by a concluded hypothesis. Anti-hallucination scaffold v2 enforces:\n"
            "  FIX#1 Each evidence item MUST contain `excerpt` — a >=12-char verbatim substring "
            "        of the cited tool_call_id's output. Server checks the substring exists.\n"
            "  FIX#2 Contradiction pressure: contradicting > supporting → confidence hard-capped "
            "        at 'low'; conclude(high) needs supporting >= 2× contradicting.\n"
            "  FIX#3 Source diversity: conclude(high) requires supporting from >=2 distinct "
            "        tool names (3 hits from one tool = correlated, not independent).\n"
            "  FIX#4 Conflict graph: declare conflicts_with for mutually exclusive hypotheses. "
            "        Cannot conclude(>=medium) while a conflicting hypothesis is concluded."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "statement": {"type": "string", "description": "One-sentence hypothesis. >=6 chars."},
                "confidence": {"type": "string", "enum": ["unknown", "low", "medium", "high"],
                               "description": "Initial confidence; start at unknown/low."},
                "falsification_plan": {"type": "string",
                                       "description": "Required >=10 chars. Which tool + result would refute this?"},
                "supporting": {"type": "array", "items": {"type": "object",
                               "properties": {"tool_call_id": {"type": "integer"},
                                              "excerpt": {"type": "string",
                                                          "description": "REQUIRED. >=12-char verbatim substring of the tool's output. Not your paraphrase."},
                                              "summary": {"type": "string",
                                                          "description": "Optional human commentary on what the excerpt means."},
                                              "line_range": {"type": "array"},
                                              "note": {"type": "string"}},
                               "required": ["tool_call_id", "excerpt"]}},
                "contradicting": {"type": "array", "items": {"type": "object",
                                  "properties": {"tool_call_id": {"type": "integer"},
                                                 "excerpt": {"type": "string"},
                                                 "summary": {"type": "string"},
                                                 "line_range": {"type": "array"},
                                                 "note": {"type": "string"}},
                                  "required": ["tool_call_id", "excerpt"]}},
                "depends_on": {"type": "array", "items": {"type": "string"},
                               "description": "Hypothesis ids this depends on. abandon-cascade ready."},
                "conflicts_with": {"type": "array", "items": {"type": "string"},
                                   "description": "Hypothesis ids this is mutually exclusive with. Both cannot be concluded >=medium."},
                "next_experiment": {"type": "string"},
                "reason_for_experiment": {"type": "string",
                                          "description": "Why this experiment next, given current ledger state."},
            },
            "required": ["statement", "confidence", "falsification_plan"],
        },
    },
    {
        "name": "hypothesis_update",
        "description": (
            "Append evidence or revise confidence on an active hypothesis.\n"
            "FIX #5 (v0.9.1): conclude(high) now requires `falsification_evidence` — "
            "a single {tool_call_id, excerpt} object recording the *result* of running "
            "your falsification_plan. The tool_call_id must be GREATER than the "
            "hypothesis's created_at_tool_call (experiment must run AFTER the "
            "hypothesis is formed). The boolean `falsification_attempted` is now "
            "deprecated — setting it alone no longer satisfies the gate; the server "
            "needs verifiable evidence the experiment actually ran.\n"
            "All evidence tool_call_ids must be real."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Hypothesis id, e.g. 'H1'."},
                "confidence": {"type": "string", "enum": ["unknown", "low", "medium", "high"]},
                "add_supporting": {"type": "array", "items": {"type": "object"}},
                "add_contradicting": {"type": "array", "items": {"type": "object"}},
                "next_experiment": {"type": "string"},
                "falsification_attempted": {"type": "boolean",
                                            "description": "DEPRECATED in v0.9.1: use falsification_evidence instead. The boolean alone no longer satisfies conclude(high)."},
                "falsification_evidence": {
                    "type": "object",
                    "description": (
                        "REQUIRED for conclude(high). Single Evidence object recording "
                        "the experiment result. tool_call_id MUST be > the hypothesis's "
                        "created_at_tool_call. excerpt is verbatim-checked the same way "
                        "supporting evidence is (FIX #1 anchor)."
                    ),
                    "properties": {
                        "tool_call_id": {"type": "integer"},
                        "excerpt": {"type": "string",
                                    "description": ">=8-char verbatim substring of the cited tool's output"},
                        "summary": {"type": "string",
                                    "description": "Optional commentary on what the experiment showed"},
                        "note": {"type": "string"},
                    },
                    "required": ["tool_call_id", "excerpt"],
                },
            },
            "required": ["id"],
        },
    },
    {
        "name": "hypothesis_conclude",
        "description": (
            "Promote a hypothesis to concluded state. Gates: conclude(medium) needs >=2 "
            "supporting; conclude(high) needs >=3 supporting AND falsification_attempted=true. "
            "Concluded hypotheses with confidence >= medium are the only thing write_artifact "
            "accepts as backing for claims."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "final_statement": {"type": "string", "description": "Refined conclusion text (>=6 chars)."},
                "final_confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            },
            "required": ["id", "final_statement", "final_confidence"],
        },
    },
    {
        "name": "hypothesis_abandon",
        "description": (
            "Mark a hypothesis as abandoned (refuted, replaced by a better one, or no longer "
            "relevant). Server surfaces any active hypotheses that depended on this one."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "reason": {"type": "string", "description": ">=6 chars."},
            },
            "required": ["id", "reason"],
        },
    },
    {
        "name": "hypothesis_list",
        "description": (
            "List hypotheses with optional filter (state=active|concluded|abandoned|archived). "
            "Pass with_evidence=true to include the full evidence arrays (heavier)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {"type": "string", "enum": ["active", "concluded", "abandoned", "archived"]},
                "with_evidence": {"type": "boolean"},
            },
        },
    },
    {
        "name": "mark_hypothesis_reviewed",
        "description": (
            "FIX #6 (v0.9.1) — independent-reviewer gate.\n"
            "The `hypothesis-reviewer` sub-agent calls this AFTER auditing a "
            "hypothesis. Records its verdict (confirm | refute | abandon) so the "
            "server-side gate on conclude(final_confidence='high') can require a "
            "recent (within last 30 tool calls) 'confirm' verdict.\n\n"
            "Workflow:\n"
            "  1. Main agent prepares to hypothesis_conclude(high) on H<N>\n"
            "  2. Main agent spawns Agent(subagent_type='hypothesis-reviewer', "
            "prompt='Review H<N>')\n"
            "  3. Reviewer audits independently, calls mark_hypothesis_reviewed(\n"
            "       id='H<N>', verdict='confirm'|'refute'|'abandon', reason='...')\n"
            "  4. Main agent now hypothesis_conclude(high) — gate checks verdict\n\n"
            "Main agents calling this on their own hypotheses is technically allowed "
            "but visible on the on-disk hypothesis_ledger.jsonl audit log (mark_reviewed "
            "and conclude both happen on the same context = not an independent review). "
            "The reviewer sub-agent has narrowed tool permissions and no main-agent "
            "chat history — that's where independence comes from."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Hypothesis id being reviewed."},
                "verdict": {"type": "string", "enum": ["confirm", "refute", "abandon"]},
                "reason": {"type": "string",
                           "description": ">=6 chars. Short explanation of the verdict (gate audits, excerpt audit summary, counter-evidence note)."},
            },
            "required": ["id", "verdict", "reason"],
        },
    },
    {
        "name": "hypothesis_archive",
        "description": (
            "FIX #7 (v0.9.1) — archive a concluded (or active) hypothesis that turned "
            "out NOT to be load-bearing for the final deliverable.\n\n"
            "Use case: agent concluded H1..H5 during analysis, but the final write_artifact "
            "only needs to cite H1 and H3. Previously the 'concluded but unreferenced' bypass "
            "gate would force citation of all five or none at all. Archive lets the agent "
            "explicitly mark H2/H4/H5 as 'not load-bearing for delivery' without losing the "
            "audit trail (the archived hypothesis stays in the ledger with state='archived' "
            "and the reason recorded).\n\n"
            "Cannot archive abandoned hypotheses (already terminal-negative). Archived "
            "hypotheses cannot be cited via [H<n>] in the artifact narrative."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "reason": {"type": "string", "description": ">=6 chars explaining why this is not load-bearing for the final deliverable."},
            },
            "required": ["id", "reason"],
        },
    },
]
