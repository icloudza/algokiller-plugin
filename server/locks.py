"""Advisory file locks for long-running scans.

Why a lock at all
-----------------
The plugin's ``PreCompact`` hook needs to know whether a long scan
(``trace_constscan`` / ``trace_cryptoinstr`` on a multi-GB trace) is in
flight. If one is, auto-compact is blocked so the agent's accumulated
ledger references stay intact; if not, compact proceeds normally.

Why kernel-level (``fcntl.flock`` / ``msvcrt.locking``) and not a pidfile
------------------------------------------------------------------------
A naive pidfile is stale-prone: process crashes, SIGKILL, system reboots,
or PID recycling all leave a lock file that "looks held" but isn't. The
chosen design pushes the lifecycle to the OS:

* POSIX (Linux + macOS): ``fcntl.flock`` on an open file descriptor.
  When the process exits — for ANY reason — the kernel closes the fd
  and releases the lock. There is no codepath that produces a stale
  lock; this is a true correctness guarantee, not a heuristic.

* Windows: ``msvcrt.locking`` byte-range lock on the same file. The
  Windows kernel applies the same fd-lifecycle rule. We lock byte
  range [0, 1) so the lock representation matches across platforms.

The shell hook (``hooks/lock-check.py``) just attempts a non-blocking
acquire; success = no holder = proceed with compact; failure = held =
block compact.

Residual risk
-------------
If a Python interpreter wedges so badly that its file descriptors stay
open but ``fcntl.flock`` returns inconsistent state, we'd block compact
indefinitely. To bound that worst case we also stamp the lock file with
the holder's PID + monotonic acquisition time, and the lock-check
script may treat a lock older than ``MAX_STALE_SECONDS`` AND whose PID
is no longer alive as forcibly released. In normal operation that
fallback never fires — it's a belt-and-braces layer below the kernel
guarantee.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional


# Absolute upper bound for how long a scan is allowed to hold the lock
# before the failsafe path is willing to treat it as abandoned. 60 min
# covers a 30 GB constscan with overhead headroom; anything longer is
# almost certainly a wedged process.
MAX_STALE_SECONDS = 3600

# Lock file lives in the user's home, not the plugin root, because the
# plugin root is read-only when installed via marketplace. The home
# location also lets multiple Python processes (MCP server + any future
# CLI use) share the same lock semantics.
LOCK_DIR = Path.home() / ".algokiller"
LOCK_FILE = LOCK_DIR / "active-scans.lock"


def _ensure_lock_path() -> Path:
    """Create the lock file's parent + the file itself if missing.
    Idempotent and safe to call from multiple processes."""
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    if not LOCK_FILE.exists():
        # touch with mode 0600 so the file can carry the holder's PID
        # without exposing it to other users on multi-user hosts.
        fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
    return LOCK_FILE


def _flock_acquire(fd: int, blocking: bool) -> bool:
    """POSIX flock acquire. Returns True on success, False on contention."""
    import fcntl
    try:
        flags = fcntl.LOCK_EX
        if not blocking:
            flags |= fcntl.LOCK_NB
        fcntl.flock(fd, flags)
        return True
    except BlockingIOError:
        return False


def _flock_release(fd: int) -> None:
    import fcntl
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass


def _msvcrt_acquire(fd: int, blocking: bool) -> bool:
    """Windows byte-range lock on bytes [0, 1). Equivalent semantics:
    held until process exits or the fd closes."""
    import msvcrt
    mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, mode, 1)
        return True
    except OSError:
        return False


def _msvcrt_release(fd: int) -> None:
    import msvcrt
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    except OSError:
        pass


def _is_posix() -> bool:
    return sys.platform != "win32"


# ---------------------------------------------------------------------------
# Holder API (used by the MCP server when a long scan begins / ends)
# ---------------------------------------------------------------------------

class ScanLock:
    """Hold for the duration of a long scan. Re-entrant via reference count
    so nested handler calls don't double-release. Idempotent close() so
    atexit + explicit release are both safe."""

    def __init__(self) -> None:
        self._fd: Optional[int] = None
        self._count: int = 0

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self, *, blocking: bool = True) -> bool:
        if self._count > 0:
            self._count += 1
            return True
        path = _ensure_lock_path()
        fd = os.open(str(path), os.O_RDWR)
        ok = (_flock_acquire(fd, blocking) if _is_posix()
              else _msvcrt_acquire(fd, blocking))
        if not ok:
            os.close(fd)
            return False
        # Stamp the file with holder metadata so the lock-check failsafe
        # can identify abandoned holders. The kernel lock is the
        # authoritative signal; this is purely diagnostic.
        meta = {
            "pid": os.getpid(),
            "acquired_at": time.time(),
            "platform": sys.platform,
        }
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, json.dumps(meta).encode("utf-8"))
        except OSError:
            pass  # metadata write is best-effort, lock state is the truth
        self._fd = fd
        self._count = 1
        return True

    def release(self) -> None:
        if self._count > 1:
            self._count -= 1
            return
        if self._fd is None:
            self._count = 0
            return
        if _is_posix():
            _flock_release(self._fd)
        else:
            _msvcrt_release(self._fd)
        try:
            os.close(self._fd)
        except OSError:
            pass
        self._fd = None
        self._count = 0


# Module-level singleton — there is exactly one MCP server process, so a
# single ScanLock instance covers all concurrent tool calls within it.
SCAN_LOCK = ScanLock()


# ---------------------------------------------------------------------------
# Checker API (used by hooks/lock-check.py and any external script)
# ---------------------------------------------------------------------------

def is_scan_in_progress() -> dict:
    """Probe the lock without acquiring it. Returns a structured result
    suitable for JSON-encoding to a hook stderr line.

    The kernel lock is authoritative: if we can acquire non-blocking,
    no scan is in progress. The metadata file is only used to enrich
    the negative-result reason field (and as failsafe input).
    """
    path = _ensure_lock_path()
    fd = os.open(str(path), os.O_RDWR)
    try:
        # Try non-blocking acquire. If we get it, release immediately —
        # this was just a probe.
        ok = (_flock_acquire(fd, blocking=False) if _is_posix()
              else _msvcrt_acquire(fd, blocking=False))
        if ok:
            if _is_posix():
                _flock_release(fd)
            else:
                _msvcrt_release(fd)
            return {"in_progress": False}
        # Lock held. Try to read the holder metadata for diagnostics.
        meta = {}
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 1024)
            if raw:
                meta = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            pass
        # Failsafe: if metadata claims the holder PID is dead AND the
        # acquisition timestamp is older than MAX_STALE_SECONDS, refuse
        # to report "in progress". This bypasses the kernel signal only
        # in the theoretical wedge case described in the module docstring.
        if meta:
            holder_pid = meta.get("pid")
            age = time.time() - float(meta.get("acquired_at", 0))
            if (isinstance(holder_pid, int)
                    and age > MAX_STALE_SECONDS
                    and not _pid_alive(holder_pid)):
                return {
                    "in_progress": False,
                    "warning": "kernel lock held but holder pid is dead "
                               f"and age={int(age)}s exceeds "
                               f"MAX_STALE_SECONDS={MAX_STALE_SECONDS}; "
                               "treating as released (failsafe path).",
                }
        return {
            "in_progress": True,
            "holder_pid": meta.get("pid"),
            "acquired_at": meta.get("acquired_at"),
            "platform": meta.get("platform"),
        }
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _pid_alive(pid: int) -> bool:
    """Cross-platform 'is this PID still alive'. Used only in the
    failsafe path."""
    if pid <= 0:
        return False
    if _is_posix():
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # Process exists, owned by someone else.
            return True
    else:
        # Windows: open the process handle; if OpenProcess works,
        # the PID is live (or recently exited but handle still open).
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        except (OSError, AttributeError):
            return False
