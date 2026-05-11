"""ak_search daemon wrapper.

One MCP server lifetime owns at most one daemon, bound to a single trace
file. Re-binding closes the previous daemon. Communicates over stdin /
stdout using the daemon's tab-separated text protocol; responses are
JSON lines, terminated by a daemon_end marker.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional


def _scrub_text(value: str) -> str:
    """Strip lone UTF-8 surrogates / invalid byte sequences so the MCP layer
    can safely json.dumps the tool result. Mirrors trace_agent.clean_text in
    the standalone harness — without this, raw trace bytes inside ak_search
    `text` fields can crash downstream JSON serialization."""
    return value.encode("utf-8", errors="replace").decode("utf-8", errors="replace")


class AkSearchDaemon:
    def __init__(self, binary: Path, trace_file: Path) -> None:
        self.binary = binary
        self.trace_file = trace_file
        self.process: Optional[subprocess.Popen[str]] = None

    def start(self) -> None:
        if self.process is not None and self.process.poll() is None:
            return
        if not self.binary.exists():
            raise FileNotFoundError(f"ak_search binary not found: {self.binary}")
        if not self.trace_file.exists():
            raise FileNotFoundError(f"trace file not found: {self.trace_file}")

        # P4: ensure exec bit is set. zip extraction or copy through some
        # tools strips +x; this is idempotent and silent on failure.
        try:
            mode = self.binary.stat().st_mode
            if not (mode & 0o111):
                os.chmod(self.binary, mode | 0o755)
        except OSError:
            pass

        # P5: on macOS, unsigned binaries downloaded via the browser / unzip /
        # AirDrop carry the com.apple.quarantine xattr which makes Gatekeeper
        # refuse exec with "developer cannot be verified". Try to clear it.
        # No-op on Linux or when xattr is absent.
        if sys.platform == "darwin":
            try:
                subprocess.run(
                    ["xattr", "-d", "com.apple.quarantine", str(self.binary)],
                    capture_output=True, check=False, timeout=2,
                )
            except Exception:
                pass

        self.process = subprocess.Popen(
            [str(self.binary), "daemon", "--file", str(self.trace_file)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
        )
        if self.process.stdout is None:
            self.process.kill()
            raise RuntimeError("ak_search daemon did not expose stdout")

        ready_line = self.process.stdout.readline()
        if not ready_line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            self.process.wait(timeout=1)
            raise RuntimeError(f"ak_search daemon failed to start: {stderr.strip()}")
        try:
            ready = json.loads(ready_line)
        except json.JSONDecodeError as exc:
            self.process.kill()
            raise RuntimeError(f"ak_search daemon invalid ready: {ready_line!r}") from exc
        if ready.get("type") != "daemon_ready" or ready.get("status") != "ok":
            self.process.kill()
            raise RuntimeError(f"ak_search daemon refused to start: {ready}")

    def request(self, command: str, *, max_output_chars: int = 30000, _retry: bool = True) -> dict:
        # M1: daemon self-heal. If the daemon died between calls, restart it
        # transparently so a single brokn pipe doesn't bubble up to Claude.
        if self.process is None or self.process.poll() is not None:
            self.start()
        assert self.process is not None and self.process.stdin is not None and self.process.stdout is not None

        try:
            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            self.close()
            if _retry:
                return self.request(command, max_output_chars=max_output_chars, _retry=False)
            raise RuntimeError("ak_search daemon stdin closed unexpectedly (after retry)")

        parts: list[str] = []
        char_count = 0
        truncated = False
        while True:
            line = self.process.stdout.readline()
            if not line:
                stderr_tail = self._drain_stderr_tail()
                self.close()
                if _retry:
                    return self.request(command, max_output_chars=max_output_chars, _retry=False)
                raise RuntimeError(f"ak_search daemon exited unexpectedly: {stderr_tail}")
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict) and data.get("type") == "daemon_end":
                # M2: scrub UTF-8 surrogates / invalid byte sequences before
                # returning to the MCP layer. ak_search JSON-escapes its lines
                # but raw trace bytes inside `text` fields can still be lone
                # surrogates that crash json serialization upstream.
                clean_stdout = _scrub_text("".join(parts))
                return {
                    "status": "ok" if data.get("status") == "ok" else "error",
                    "stdout": clean_stdout,
                    "stderr": _scrub_text(str(data.get("error") or "")),
                    "truncated": truncated,
                }
            if char_count + len(line) <= max_output_chars:
                parts.append(line)
                char_count += len(line)
            else:
                truncated = True

    def _drain_stderr_tail(self, tail_chars: int = 4000) -> str:
        if self.process is None or self.process.stderr is None:
            return ""
        try:
            data = self.process.stderr.read() or ""
        except Exception:
            return ""
        return data[-tail_chars:].strip()

    def run_cli(self, subcommand: str, args: list[str],
                timeout: int = 30, max_output_chars: int = 200_000) -> dict:
        """Run ak_search in one-shot CLI mode (no daemon protocol).

        All extension subcommands (regflow / producer / semop / lint / fold /
        callgraph / modgraph / hexblock / constscan / cryptoinstr / bytes)
        go through this path: they re-mmap the trace each call and exit. The
        upstream daemon protocol is currently `match` / `context` only.

        Expanding the daemon protocol to cover extension subcommands would
        save the mmap+line-index rebuild per call. On a 684 MB / 7.14 M-line
        trace that rebuild is sub-300 ms thanks to mmap + the line-index in
        an anonymous shared mapping — the overhead is real but not currently
        a blocker. Tracked for a future release; not on the critical path.
        """
        if not self.binary.exists():
            return {"status": "error", "error": f"ak_search binary not found: {self.binary}"}
        if not self.trace_file.exists():
            return {"status": "error", "error": f"trace file not found: {self.trace_file}"}
        try:
            result = subprocess.run(
                [str(self.binary), subcommand, "--file", str(self.trace_file), *args],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": f"{subcommand} timed out after {timeout}s"}
        except OSError as exc:
            return {"status": "error", "error": f"{subcommand} exec failed: {exc}"}

        stdout = _scrub_text(result.stdout or "")
        truncated = False
        if len(stdout) > max_output_chars:
            stdout = stdout[:max_output_chars]
            truncated = True
        return {
            "status": "ok" if result.returncode == 0 else "error",
            "stdout": stdout,
            "stderr": _scrub_text(result.stderr or ""),
            "returncode": result.returncode,
            "truncated": truncated,
        }

    def close(self) -> None:
        process = self.process
        self.process = None
        if process is None or process.poll() is not None:
            return
        try:
            if process.stdin is not None:
                process.stdin.write("quit\n")
                process.stdin.flush()
        except Exception:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
