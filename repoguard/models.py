"""Unified Finding / Endpoint / Report data models.

Contract: findings.json is the serialized Report. HTML renders the same
object. schema_version bumps on any field change.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

Severity = Literal["Critical", "High", "Medium", "Low", "Info"]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

SCHEMA_VERSION = 1


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    tool: str
    where: str
    evidence: str
    owasp: str
    fix: str
    file: str | None = None
    line: int | None = None
    endpoint: str | None = None
    method: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Endpoint:
    path: str
    methods: list[str]
    view: str
    file: str
    line: int
    auth: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    protection: Literal["protected", "open", "allowany-default", "unknown"] = "unknown"
    source: str = "unknown"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    target: str
    base_url: str | None
    generated_at: str
    summary: dict
    findings: list[Finding]
    endpoints: list[Endpoint]
    scanner_status: dict
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "base_url": self.base_url,
            "generated_at": self.generated_at,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "scanner_status": self.scanner_status,
            "schema_version": self.schema_version,
        }


def build_summary(findings: list[Finding]) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return {"counts": counts, "total": len(findings)}
