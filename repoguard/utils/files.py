"""Shared file-walk helpers: skip-lists and candidate python files."""
from __future__ import annotations

from pathlib import Path

SKIP_DIRS = {"venv", ".venv", "repoguard-report", "evidence", ".git", "__pycache__",
             "node_modules", ".tox", ".pytest_cache"}


def iter_files(target: Path, suffix: str | None = None):
    """Yield files under target, pruning SKIP_DIRS. Optional suffix filter."""
    target = Path(target)
    stack = [target]
    while stack:
        cur = stack.pop()
        if cur.is_dir():
            if cur.name in SKIP_DIRS and cur != target:
                continue
            try:
                children = sorted(cur.iterdir())
            except OSError:
                continue
            stack.extend(children)
        elif cur.is_file():
            if suffix and cur.suffix != suffix:
                continue
            yield cur


def is_env_value(node) -> bool:
    """True if an AST node reads from env (os.environ / getenv / config())."""
    import ast
    src = ast.dump(node)
    return "environ" in src or "getenv" in src or "config(" in src
