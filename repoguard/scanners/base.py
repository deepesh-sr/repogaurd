"""ScannerAdapter ABC. Contract: run() never raises.

Returns (findings, status) where status is a short human string for the
report's scanner_status table: "ok (...)", "missing ...", "error ...",
"skipped ...". Scanner failure -> status + at most one Info finding.
"""
from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from pathlib import Path

from repoguard.models import Finding


class ScannerAdapter(ABC):
    name: str = "unknown"

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    @property
    @abstractmethod
    def binary(self) -> str:
        ...

    @abstractmethod
    def run(self, target: Path) -> tuple[list[Finding], str]:
        ...

    def _unavailable(self, reason: str) -> tuple[list[Finding], str]:
        # Missing binary is environment data -> scanner_status only, NOT a
        # finding (keeps clean-repo scans at zero findings; the HTML header
        # renders scanner_status so the gap is never silent).
        return ([], f"missing ({reason})")
