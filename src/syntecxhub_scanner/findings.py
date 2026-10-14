"""The Finding data model and the severity scale used throughout the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # nicer printing: "HIGH" instead of "Severity.HIGH"
        return self.name


@dataclass
class Finding:
    """One vulnerability or misconfiguration indicator found on a page."""

    check_id: str
    title: str
    severity: Severity
    url: str
    evidence: str
    remediation: str
    category: str = ""  # e.g. "OWASP A05:2021 - Security Misconfiguration"

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": str(self.severity),
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "category": self.category,
        }


@dataclass
class ScanResult:
    """Everything produced by one scan run."""

    target: str
    pages_scanned: int = 0
    findings: list = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def by_severity(self) -> dict:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: (-f.severity, f.url, f.check_id))
