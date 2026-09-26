"""Subprocess helper: run a scanner binary with timeout, never raise."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from repoguard.utils.debug import dprint

DEFAULT_TIMEOUT = 300


@dataclass
class ProcResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    missing: bool


def run(cmd: list[str], cwd: Path | None = None, timeout: int = DEFAULT_TIMEOUT) -> ProcResult:
    """Run cmd, capturing output. Missing binary and timeouts are data, not exceptions."""
    dprint("subprocess.run", " ".join(cmd))  # [DEBUG] REMOVE in T6
    if shutil.which(cmd[0]) is None:
        dprint("subprocess.missing", cmd[0])  # [DEBUG] REMOVE in T6
        return ProcResult(returncode=127, stdout="", stderr=f"binary not found: {cmd[0]}",
                          timed_out=False, missing=True)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        dprint("subprocess.done rc=", p.returncode)  # [DEBUG] REMOVE in T6
        return ProcResult(returncode=p.returncode, stdout=p.stdout, stderr=p.stderr,
                          timed_out=False, missing=False)
    except subprocess.TimeoutExpired as e:
        dprint("subprocess.timeout", " ".join(cmd))  # [DEBUG] REMOVE in T6
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        return ProcResult(returncode=124, stdout=out, stderr="timeout", timed_out=True, missing=False)
    except OSError as e:
        return ProcResult(returncode=127, stdout="", stderr=str(e), timed_out=False, missing=True)
