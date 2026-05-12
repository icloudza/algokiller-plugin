"""Resolve where analysis artifacts get written for a bound trace.

Five-priority resolution chain, highest wins:

    1. `bind_trace(output_dir=...)` explicit argument
    2. `ALGOKILLER_OUTPUT_DIR` environment variable (CI / global override)
    3. `.algokiller.toml` in the trace's project root, `[output] dir = "..."`
    4. Project-marker walk-up from the trace's parent directory; resolved
       to `<project_root>/.algokiller/<trace_basename>/<timestamp>/`
    5. Fallback: `<documents>/AlgoKiller-Reports/<trace_basename>/<timestamp>/`
       — `<documents>` follows XDG_DOCUMENTS_DIR on Linux when set, else
       `~/Documents`; final fallback is `~/AlgoKiller-Reports/`.

The legacy `~/AlgoKiller/artifacts/` path from earlier versions is NOT
read or written by this resolver — old artifacts stay untouched.

The function returns both the resolved path and a `source` tag so the
MCP wrapper can echo it to the agent (who in turn echoes it to the
user — the conversational equivalent of "this is where reports go").
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


# Project markers, ordered by reliability. First match in the walk-up
# wins. Keep this list generous — most trace files will live somewhere
# downstream of one of these.
PROJECT_MARKERS: tuple[str, ...] = (
    # VCS — most authoritative
    ".git", ".hg", ".svn",
    # Plugin-local override (drop in a project root to lock our behaviour)
    ".algokiller.toml",
    # Language / build ecosystems
    "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "poetry.lock",
    "package.json", "pnpm-workspace.yaml", "lerna.json",
    "Cargo.toml", "go.mod",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "composer.json", "Gemfile",
    "CMakeLists.txt", "Makefile",
)

# How many directory levels to walk up from the trace's parent before
# giving up. 4 covers typical layouts like
# `<project>/captures/<vendor>/<trace>.log` without false-positives.
PROJECT_WALK_LIMIT = 4

# Subdirectory under the project root where we write reports — hidden so
# it doesn't pollute the project tree.
PROJECT_REPORTS_SUBDIR = ".algokiller"

# Subdirectory under <documents> for the no-project fallback.
DOCUMENTS_REPORTS_SUBDIR = "AlgoKiller-Reports"


@dataclass
class ResolvedOutputDir:
    """Result of resolve_output_dir.

    `path` is the per-session directory the caller should write into
    (already includes the trace basename + timestamp segments where
    applicable). `source` tells the agent which rule fired; surface this
    to the user so they're never surprised about where reports landed.
    """
    path: Path
    source: str            # explicit | env | project_config | project_marker | documents
    project_root: Optional[Path] = None
    reason: Optional[str] = None


def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _xdg_documents_dir() -> Optional[Path]:
    """Return XDG_DOCUMENTS_DIR if it resolves to an existing directory.

    Looks at the env var first, then ~/.config/user-dirs.dirs (the file
    xdg-user-dirs-update writes). Returns None on macOS / Windows where
    the spec doesn't apply.
    """
    if sys.platform.startswith(("darwin", "win")):
        return None
    env = os.environ.get("XDG_DOCUMENTS_DIR")
    if env:
        candidate = Path(os.path.expandvars(env)).expanduser()
        if candidate.is_dir():
            return candidate
    # user-dirs.dirs is shell-ish; do a tolerant parse for XDG_DOCUMENTS_DIR.
    user_dirs = Path.home() / ".config" / "user-dirs.dirs"
    if user_dirs.is_file():
        try:
            for line in user_dirs.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("XDG_DOCUMENTS_DIR="):
                    raw = line.split("=", 1)[1].strip().strip('"')
                    expanded = Path(os.path.expandvars(raw)).expanduser()
                    if expanded.is_dir():
                        return expanded
        except OSError:
            pass
    return None


def _documents_root() -> Path:
    """Cross-platform Documents folder. Falls back to ~/AlgoKiller-Reports
    if Documents itself doesn't exist (e.g. fresh server install)."""
    xdg = _xdg_documents_dir()
    if xdg is not None:
        return xdg
    candidate = Path.home() / "Documents"
    if candidate.is_dir():
        return candidate
    # No Documents folder — last-resort: write directly into the home dir
    # under a clearly-named root. Don't create Documents ourselves; the
    # absence often means "this user's filesystem layout differs" and
    # we'd rather be visible at $HOME than guess.
    return Path.home()


def _find_project_root(start: Path) -> Optional[Path]:
    """Walk up at most PROJECT_WALK_LIMIT levels from `start` looking for
    a known project marker. Returns the directory containing the first
    matching marker, or None."""
    current = start.resolve()
    for _ in range(PROJECT_WALK_LIMIT + 1):
        for marker in PROJECT_MARKERS:
            if (current / marker).exists():
                return current
        parent = current.parent
        if parent == current:
            break  # hit filesystem root
        current = parent
    return None


def _read_algokiller_toml(project_root: Path) -> Optional[Path]:
    """Read `[output] dir` out of project_root/.algokiller.toml. Returns
    the configured directory (expanded), or None when missing/invalid.

    Uses tomllib (Python 3.11+) — no external dep.
    """
    config = project_root / ".algokiller.toml"
    if not config.is_file():
        return None
    try:
        import tomllib  # Python 3.11+
        data = tomllib.loads(config.read_text(encoding="utf-8"))
    except Exception:
        return None
    out = data.get("output", {}).get("dir")
    if not isinstance(out, str) or not out.strip():
        return None
    candidate = Path(os.path.expandvars(out)).expanduser()
    if not candidate.is_absolute():
        # Interpret relative to project root.
        candidate = (project_root / candidate).resolve()
    return candidate


def _ensure_writable(path: Path) -> bool:
    """Best-effort writability check without actually creating files.

    We require either the path itself to be a writable directory, or
    the nearest existing ancestor to be writable (so the resolver can
    later mkdir(parents=True)). Returns False if neither holds.
    """
    probe = path
    while True:
        if probe.exists():
            return probe.is_dir() and os.access(probe, os.W_OK)
        parent = probe.parent
        if parent == probe:
            return False
        probe = parent


def resolve_output_dir(
    trace_path: Path,
    explicit: Optional[str] = None,
    *,
    env: Optional[dict[str, str]] = None,
    now_stamp_fn=_now_stamp,
) -> ResolvedOutputDir:
    """Resolve the per-session output directory for a bound trace.

    `trace_path` must already be an absolute, existing file (the caller
    handles validation). `explicit` is whatever the agent passed to
    `bind_trace(output_dir=...)`.

    The returned `path` is NOT created — that's the caller's job once
    the resolution is accepted. We only validate writability up front
    so the agent gets a fast error instead of a half-built session.

    `env` is injected for tests; defaults to os.environ.
    """
    if env is None:
        env = os.environ
    trace_basename = trace_path.stem
    stamp = now_stamp_fn()

    # ① Explicit argument wins, no walk-up.
    if explicit:
        target = Path(os.path.expandvars(explicit)).expanduser()
        if not target.is_absolute():
            raise ValueError(
                f"output_dir must be an absolute path; got: {explicit!r}")
        session = target / trace_basename / stamp
        if not _ensure_writable(session):
            raise ValueError(
                f"output_dir is not writable: {target} "
                "(check permissions or pick a different path)")
        return ResolvedOutputDir(
            path=session,
            source="explicit",
            reason=f"caller passed output_dir={explicit!r}",
        )

    # ② $ALGOKILLER_OUTPUT_DIR — CI / power-user global override.
    env_dir = env.get("ALGOKILLER_OUTPUT_DIR")
    if env_dir:
        target = Path(os.path.expandvars(env_dir)).expanduser()
        if not target.is_absolute():
            raise ValueError(
                "ALGOKILLER_OUTPUT_DIR must be an absolute path; got: "
                f"{env_dir!r}")
        session = target / trace_basename / stamp
        if not _ensure_writable(session):
            raise ValueError(
                f"ALGOKILLER_OUTPUT_DIR is not writable: {target}")
        return ResolvedOutputDir(
            path=session,
            source="env",
            reason="ALGOKILLER_OUTPUT_DIR environment variable",
        )

    # ③ / ④ Walk up from the trace's parent looking for a project root.
    project_root = _find_project_root(trace_path.parent)
    if project_root is not None:
        # ③ .algokiller.toml inside the project root takes precedence
        # over the default project_marker target.
        configured = _read_algokiller_toml(project_root)
        if configured is not None:
            session = configured / trace_basename / stamp
            if _ensure_writable(session):
                return ResolvedOutputDir(
                    path=session,
                    source="project_config",
                    project_root=project_root,
                    reason=(f"{project_root}/.algokiller.toml [output] "
                            f"dir = {configured}"),
                )
            # Misconfigured .algokiller.toml — fall through to project_marker
            # with a note. We do NOT silently swallow; the response surfaces
            # the override that didn't apply.

        # ④ Default project-marker target: <project>/.algokiller/<trace>/<ts>/
        session = project_root / PROJECT_REPORTS_SUBDIR / trace_basename / stamp
        if _ensure_writable(session):
            return ResolvedOutputDir(
                path=session,
                source="project_marker",
                project_root=project_root,
                reason=f"found project marker at {project_root}",
            )

    # ⑤ Fallback: Documents.
    documents = _documents_root()
    session = documents / DOCUMENTS_REPORTS_SUBDIR / trace_basename / stamp
    if not _ensure_writable(session):
        raise ValueError(
            f"could not find a writable output location; tried Documents "
            f"({documents}) and home directory. Pass an explicit "
            "output_dir or set ALGOKILLER_OUTPUT_DIR.")
    return ResolvedOutputDir(
        path=session,
        source="documents",
        reason=("no project root detected in trace path's ancestors; "
                f"using Documents fallback ({documents})"),
    )
