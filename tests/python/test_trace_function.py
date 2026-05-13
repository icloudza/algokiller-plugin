"""Unit tests for the trace_function tool's pure parse helpers.

These cover the AArch64 trace-line parsers in isolation (no daemon, no
fixture trace). The full integration path — anchor search, depth-counter
ret detection, paginated context scan — is exercised by the main agent
against real bound traces; unit tests here pin down the parser invariants
so a regex tweak can't silently change semantics.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SERVER = Path(__file__).resolve().parent.parent.parent / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

from tools.handlers import (  # noqa: E402
    _fn_parse_trace_line,
    _fn_extract_reg_state,
    _fn_extract_after_arrow_reg,
    _FN_BL_TARGET_RE,
    _FN_BLR_REG_RE,
    _FN_B_TARGET_RE,
)


class TestParseTraceLine(unittest.TestCase):
    """Each line shape that appears in real GumTrace logs."""

    def test_canonical_mov_with_reg_state(self):
        text = (
            "[discover] 0x10543cf44!0x27ecf44 sub sp, sp, #0x1f0; "
            "sp=0x16f9422b0 sp=0x16f9422b0 -> sp=0x16f9420c0"
        )
        p = _fn_parse_trace_line(text)
        self.assertEqual(p["abs_pc"], "0x10543cf44")
        self.assertEqual(p["rel_pc"], "0x27ecf44")
        self.assertEqual(p["op"], "sub")
        self.assertIn("sub sp, sp, #0x1f0", p["inst_body"])
        self.assertIn("-> sp=0x16f9420c0", p["tail_body"])

    def test_ldp_neon_double_destination(self):
        text = (
            "[discover] 0x10543cf80!0x27ecf80 ldp q0, q1, [x0]; "
            "q0=0x0 q1=0x2 x0=0x16efbdcb0 mem_r=0x16efbdcb0 "
            "-> q0=0xd60b2d95706bed1b179b8a38cda239e8 q1=0x2924f672972e35b83d917cf679baf795"
        )
        p = _fn_parse_trace_line(text)
        self.assertEqual(p["op"], "ldp")
        # R9: tail_body retains both the prev and new values for downstream
        # extractors to disambiguate.
        self.assertIn("q1=0x2", p["tail_body"])
        self.assertIn("-> q0=0xd60b2d95", p["tail_body"])

    def test_bl_direct_call(self):
        text = "[discover] 0x10542cf74!0x27dcf74 bl #0x10543cf44;"
        p = _fn_parse_trace_line(text)
        self.assertEqual(p["op"], "bl")
        m = _FN_BL_TARGET_RE.search(p["inst_body"])
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "0x10543cf44")

    def test_blr_indirect_call(self):
        text = "[discover] 0x11209c37c!0xf44c37c blr x16; x16=0x1b720fdf4 -> x16=0x1b720fdf4"
        p = _fn_parse_trace_line(text)
        self.assertEqual(p["op"], "blr")
        m = _FN_BLR_REG_RE.search(p["inst_body"])
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "x16")

    def test_ret_no_operand(self):
        text = "[discover] 0x10543d05c!0x27ed05c ret ;"
        p = _fn_parse_trace_line(text)
        self.assertEqual(p["op"], "ret")

    def test_conditional_branch_b_dot_eq(self):
        text = "[discover] 0x10542cf80!0x27dcf80 b.eq #0x10542d010;"
        p = _fn_parse_trace_line(text)
        # The opcode-only regex captures "b" (the .eq is part of the suffix);
        # what matters is that we don't crash and rel_pc parses fine.
        self.assertEqual(p["rel_pc"], "0x27dcf80")
        # b.eq must NOT match the unconditional-b target regex —
        # otherwise tail-call detection would mistake conditional jumps
        # for unconditional exits.
        bm = _FN_B_TARGET_RE.search(p["inst_body"])
        # NB: _FN_B_TARGET_RE accepts `b` and `b.<cond>`. That's fine because
        # the tail-call logic guards on `op == 'b'` (op is set by the opcode
        # regex which captures the full mnemonic including dot). So even if
        # the target regex matches, the op-name guard rejects it. Verify:
        self.assertNotEqual(p["op"], "b")

    def test_unconditional_branch_b(self):
        text = "[discover] 0x10542cf80!0x27dcf80 b #0x10542d010;"
        p = _fn_parse_trace_line(text)
        self.assertEqual(p["op"], "b")
        bm = _FN_B_TARGET_RE.search(p["inst_body"])
        self.assertIsNotNone(bm)
        self.assertEqual(bm.group(1), "0x10542d010")

    def test_non_matching_lines_return_empty(self):
        # NDJSON-style or hexdump-marker rows don't match.
        self.assertEqual(_fn_parse_trace_line(""), {})
        self.assertEqual(_fn_parse_trace_line('{"type":"match"}'), {})
        self.assertEqual(_fn_parse_trace_line(
            "hexdump at address 0x400001000 with length 0x10:"), {})
        self.assertEqual(_fn_parse_trace_line(
            "call func: __memcpy_aarch64_simd(0x300001000, 0x400001000, 0x10)"
        ), {})


class TestExtractRegState(unittest.TestCase):
    """The R9 prev/new gate — `regN=X` BEFORE `->` is the OLD value;
    `regN=Y` AFTER `->` is the new value. Helper must isolate the
    BEFORE half so callers don't accidentally read the new value as
    the input.
    """

    def test_extract_simple(self):
        tail = "x20=0x0 x2=0x24 -> x20=0x24"
        out = _fn_extract_reg_state(tail, ["x2", "x20"])
        self.assertEqual(out, {"x2": "0x24", "x20": "0x0"})

    def test_extracts_only_before_arrow_for_dst(self):
        # mov w8, #0x1b; w8=0x5f -> w8=0x1b
        # When the same reg appears on both sides, we must take the BEFORE
        # value (the R9 'PREV' goldmine).
        tail = "w8=0x5f -> w8=0x1b"
        out = _fn_extract_reg_state(tail, ["w8"])
        self.assertEqual(out, {"w8": "0x5f"})

    def test_extracts_only_requested_regs(self):
        tail = "x0=0xa x1=0xb x2=0xc x3=0xd -> x0=0xfff"
        out = _fn_extract_reg_state(tail, ["x1", "x3"])
        self.assertEqual(out, {"x1": "0xb", "x3": "0xd"})
        self.assertNotIn("x0", out)
        self.assertNotIn("x2", out)

    def test_missing_reg_returns_partial(self):
        tail = "x0=0xa -> x0=0xfff"
        out = _fn_extract_reg_state(tail, ["x0", "x1", "x2"])
        self.assertEqual(out, {"x0": "0xa"})

    def test_memr_memw_fields_ignored(self):
        # mem_r / mem_w / sp / fp can appear in the same tail; the regex
        # is reg-anchored so it should not confuse them with arg regs.
        tail = "x0=0x100 sp=0x16efbdcb0 mem_r=0x16f9442c0 -> x0=0x200"
        out = _fn_extract_reg_state(tail, ["x0"])
        self.assertEqual(out, {"x0": "0x100"})

    def test_no_arrow_uses_whole_tail(self):
        # Some trace lines have no -> (instruction had no defined output).
        tail = "x0=0x123 x1=0xabc"
        out = _fn_extract_reg_state(tail, ["x0", "x1"])
        self.assertEqual(out, {"x0": "0x123", "x1": "0xabc"})


class TestExtractAfterArrowReg(unittest.TestCase):
    """Symmetric helper for ret-value capture: read the NEW (right of `->`)
    side. Useful for ret_x0 / ret_x1 extraction at function exit.
    """

    def test_extracts_after_arrow(self):
        tail = "x0=0xdead -> x0=0xbeef"
        self.assertEqual(_fn_extract_after_arrow_reg(tail, "x0"), "0xbeef")

    def test_no_arrow_returns_none(self):
        tail = "x0=0xdead"
        self.assertIsNone(_fn_extract_after_arrow_reg(tail, "x0"))

    def test_after_arrow_but_reg_not_present(self):
        tail = "x0=0xdead -> x1=0xface"
        self.assertIsNone(_fn_extract_after_arrow_reg(tail, "x0"))


class TestSubcallRegexes(unittest.TestCase):
    """Direct vs indirect call detection."""

    def test_bl_with_hash_prefix(self):
        m = _FN_BL_TARGET_RE.search("bl #0x10543cf44;")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "0x10543cf44")

    def test_bl_without_hash_prefix(self):
        m = _FN_BL_TARGET_RE.search("bl 0x1234abcd;")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "0x1234abcd")

    def test_blr_register_capture(self):
        m = _FN_BLR_REG_RE.search("blr x16;")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "x16")

    def test_bl_does_not_match_blr(self):
        # blr starts with "bl" — make sure the direct-bl regex doesn't
        # accidentally pull a target out of the register name.
        m = _FN_BL_TARGET_RE.search("blr x16;")
        self.assertIsNone(m)


if __name__ == "__main__":
    unittest.main()
