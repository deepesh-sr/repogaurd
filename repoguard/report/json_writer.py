"""findings.json emitter. Single source: Report.to_dict()."""
from __future__ import annotations

import json
from pathlib import Path

from repoguard.models import Report


def write_json(report: Report, dest: Path) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    return dest
