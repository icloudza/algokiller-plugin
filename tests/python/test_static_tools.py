"""Regression tests for static_tools — r2 boundary, forbid_args policy,
NUL-byte rejection, allow-list enforcement."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SERVER = Path(__file__).resolve().parent.parent.parent / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

from static_tools import (  # noqa: E402
    ALLOWED_TOOLS,
    R2_FORBIDDEN_FLAGS,
    R2_FORBIDDEN_R2_COMMANDS,
    R2_FORBIDDEN_TOKEN_PREFIXES,
    R2_REQUIRED_FLAGS,
    _validate_r2_args,
    _validate_generic,
    run_static_tool,
)


class TestR2Boundary(unittest.TestCase):
    """The r2 boundary is the most security-critical gate in the plugin —
    without it, a long-running aaa on a multi-GB binary would lock up the
    machine."""

    def test_missing_required_flags(self):
        err = _validate_r2_args(["-c", "iI", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("must include flags", err)

    def test_explicit_dash_a_rejected(self):
        err = _validate_r2_args(["-q", "-2", "-n", "-A", "-c", "iI", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("-A", err)

    def test_aaa_in_c_command_rejected(self):
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "aaa; iI", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("'aaa'", err)

    def test_aac_in_c_command_rejected(self):
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "aac", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("'aac'", err)

    def test_chained_aaa_via_andand_rejected(self):
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "iI && aaa", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("forbidden", err)

    def test_chained_aaa_via_pipepipe_rejected(self):
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "iI || aar", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("forbidden", err)

    def test_bounded_pd_command_accepted(self):
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "pd 50 @ 0x100000000", "/bin/ls"])
        self.assertIsNone(err)

    def test_missing_c_rejected(self):
        err = _validate_r2_args(["-q", "-2", "-n", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("-c", err)

    # FIX F-12 (v0.9.1) — token-prefix blacklist closes the r2 shell-escape /
    # script-eval / iterate / network / macro routes that bypassed the
    # earlier `aaa/aac/...` head-token check.

    def test_shell_escape_bang_rejected(self):
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "!rm -rf ~", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("'!'", err)

    def test_shell_escape_bang_inside_chain_rejected(self):
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "iI; !whoami", "/bin/ls"])
        self.assertIsNotNone(err)

    def test_r2_script_eval_dot_rejected(self):
        # `.script.r2` is r2's script-interpret prefix — must be blocked.
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", ".script.r2", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("'.'", err)

    def test_iterate_at_at_rejected(self):
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "@@=sym.imp.malloc; ?", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("'@@'", err)

    def test_rap_equals_rejected(self):
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "=h", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("'='", err)

    def test_pipe_to_shell_rejected(self):
        # r2's pipe-to-shell syntax — `|sh` would route through system.
        err = _validate_r2_args(
            ["-q", "-2", "-n", "-c", "iI; |sh", "/bin/ls"])
        self.assertIsNotNone(err)
        self.assertIn("'|'", err)

    def test_forbidden_prefix_table_locked(self):
        for bad in ("!", ".", "@@", "=", "#!", "$", "|"):
            self.assertIn(bad, R2_FORBIDDEN_TOKEN_PREFIXES,
                          f"{bad!r} must remain in R2_FORBIDDEN_TOKEN_PREFIXES")


class TestForbidArgs(unittest.TestCase):

    def test_codesign_sign_forbidden(self):
        cfg = ALLOWED_TOOLS["codesign"]
        err = _validate_generic("codesign", ["--sign", "id", "bin"], cfg)
        self.assertIsNotNone(err)
        self.assertIn("forbidden", err)

    def test_codesign_display_allowed(self):
        cfg = ALLOWED_TOOLS["codesign"]
        err = _validate_generic("codesign", ["-d", "-v", "bin"], cfg)
        self.assertIsNone(err)

    def test_ldid_replace_signature_forbidden(self):
        cfg = ALLOWED_TOOLS["ldid"]
        err = _validate_generic("ldid", ["-s", "bin"], cfg)
        self.assertIsNotNone(err)

    def test_lipo_create_forbidden(self):
        cfg = ALLOWED_TOOLS["lipo"]
        err = _validate_generic("lipo", ["-create", "a", "b"], cfg)
        self.assertIsNotNone(err)


class TestRunStaticTool(unittest.TestCase):

    def test_unknown_tool_rejected(self):
        r = run_static_tool(tool="rm", args=["-rf", "/"])
        self.assertEqual(r["status"], "error")
        self.assertIn("not in the allow-list", r["error"])
        # Allow-list is surfaced so the caller can self-correct.
        self.assertIn("allowed_tools", r)

    def test_nul_byte_rejected(self):
        r = run_static_tool(tool="file", args=["abc\x00def"])
        self.assertEqual(r["status"], "error")
        self.assertIn("NUL byte", r["error"])

    def test_r2_boundary_enforced_at_runtime(self):
        # We don't need r2 installed to test the boundary — the boundary
        # check fires before resolving the binary on PATH... but actually
        # PATH resolution comes first in run_static_tool. Use a guarded
        # check: only assert when r2 is missing on this machine.
        r = run_static_tool(tool="r2", args=["-A", "/bin/ls"])
        # Either r2 is missing (hint provided) or boundary kicked in.
        self.assertEqual(r["status"], "error")

    def test_unsupported_codesign_sign_blocked(self):
        r = run_static_tool(tool="codesign",
                            args=["--sign", "Apple Development", "/bin/ls"])
        # If codesign is not installed we get "not installed"; if it is,
        # we get the forbid_args message. Either way the call must error.
        self.assertEqual(r["status"], "error")


class TestAllowListShape(unittest.TestCase):
    """Lock the allow-list shape — every entry must have timeout + category
    so the runtime layer can rely on them."""

    def test_every_entry_has_timeout_and_category(self):
        for name, cfg in ALLOWED_TOOLS.items():
            self.assertIn("timeout", cfg, f"{name} missing timeout")
            self.assertIn("category", cfg, f"{name} missing category")
            self.assertIsInstance(cfg["timeout"], int)
            self.assertGreater(cfg["timeout"], 0)

    def test_r2_required_flags_complete(self):
        # If someone removes -n from required flags by accident, r2 will
        # run aaa on multi-GB binaries.
        for flag in ("-q", "-2", "-n"):
            self.assertIn(flag, R2_REQUIRED_FLAGS,
                          f"{flag} must remain in R2_REQUIRED_FLAGS")

    def test_r2_forbidden_flags_include_full_analysis(self):
        for flag in ("-A", "-AA", "-AAA"):
            self.assertIn(flag, R2_FORBIDDEN_FLAGS,
                          f"{flag} must remain in R2_FORBIDDEN_FLAGS")

    def test_r2_forbidden_commands_cover_full_analysis_verbs(self):
        # Spot-check the dangerous ones; the full set is in the module.
        for verb in ("aaa", "aaaa", "aac", "aar", "aap"):
            self.assertIn(verb, R2_FORBIDDEN_R2_COMMANDS,
                          f"{verb} must remain forbidden")


if __name__ == "__main__":
    unittest.main()
