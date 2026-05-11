"""Artifact store: write deliverables (recovered Python source, markdown
analysis reports) into the session artifacts directory and read them back.

Directory layout:
    ~/AlgoKiller/artifacts/<trace_basename>/<session_timestamp>/...

Filenames are auto-stamped with mode + timestamp + de-dup index so the
agent never overwrites a previous deliverable inside the same session.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path


class ArtifactStore:
    def __init__(self, base_dir: Path, mode: str = "unknown") -> None:
        self.base_dir = base_dir.resolve()
        self.mode = self._safe_mode(mode)

    @staticmethod
    def _safe_mode(mode: str) -> str:
        text = "".join(c if c.isalnum() else "_" for c in str(mode).strip().upper())
        return text or "UNKNOWN"

    def _stamp(self) -> str:
        return f"{self.mode}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def write(self, rel_path: str, content: str, notes: str | None = None) -> dict:
        if not rel_path:
            return {"status": "error", "error": "path must not be empty"}
        path = Path(rel_path)
        if path.is_absolute():
            return {"status": "error", "error": "path must be relative to the artifacts directory"}

        stamp = self._stamp()
        target: Path | None = None
        for index in range(1000):
            suffix = f"_{index}" if index else ""
            timestamped = path.with_name(f"{path.stem}_{stamp}{suffix}{path.suffix}")
            candidate = (self.base_dir / timestamped).resolve()
            if not candidate.is_relative_to(self.base_dir):
                return {"status": "error", "error": f"path escapes artifacts directory: {rel_path}"}
            if not candidate.exists():
                target = candidate
                break
        if target is None:
            return {"status": "error", "error": f"could not allocate a timestamped artifact path for: {rel_path}"}

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

        notes_path: Path | None = None
        if notes:
            notes_path = target.with_suffix(".notes.md")
            notes_path.write_text(str(notes), encoding="utf-8")

        return {
            "status": "ok",
            "path": str(target),
            "notes_path": str(notes_path) if notes_path else None,
        }

    def list_all(self) -> list[dict]:
        if not self.base_dir.exists():
            return []
        items: list[dict] = []
        for path in sorted(self.base_dir.rglob("*")):
            if path.is_file():
                stat = path.stat()
                items.append({
                    "path": str(path),
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                })
        return items

    def read(self, abs_path: str) -> str:
        path = Path(abs_path).expanduser().resolve()
        if not path.is_relative_to(self.base_dir):
            raise ValueError(f"path is outside session artifacts directory: {abs_path}")
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"artifact not found: {abs_path}")
        return path.read_text(encoding="utf-8")
