"""findings.json emitter. Single source: Report.to_dict()."""
from __future__ import annotations

import json
from pathlib import Path

from repoguard.models import Report
from repoguard.utils.debug import dprint


def write_json(report: Report, dest: Path) -> Path:
    dprint("json_writer.write", str(dest))  # [DEBUG] REMOVE in T6
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    return dest
