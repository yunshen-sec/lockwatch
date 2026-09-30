"""Small, serialisable data models used by lockwatch."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    """Severity ordering used for filtering findings."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        normalised = (value or "unknown").strip().lower().replace("-", "_")
        aliases = {"moderate": "medium", "informational": "unknown", "none": "unknown"}
        normalised = aliases.get(normalised, normalised)
        try:
            return cls[normalised.upper()]
        except KeyError as exc:
            raise ValueError("severity must be one of unknown, low, medium, high, critical") from exc


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str
    source: str
    dependency_type: str = "runtime"

    def key(self) -> str:
        return "%s:%s@%s" % (self.ecosystem, self.name, self.version)


@dataclass
class Finding:
    package: Package
    vulnerability_id: str
    severity: Severity = Severity.UNKNOWN
    summary: str = ""
    details: str = ""
    aliases: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    source: str = "osv"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["package"] = asdict(self.package)
        data["severity"] = self.severity.name.lower()
        return data


@dataclass
class ScanResult:
    packages: List[Package] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packages": [asdict(item) for item in self.packages],
            "findings": [item.to_dict() for item in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
        }


def severity_from_osv(vulnerability: Dict[str, Any]) -> Severity:
    """Extract a useful severity from OSV's several severity representations."""

    database = vulnerability.get("database_specific") or {}
    for candidate in (database.get("severity"), vulnerability.get("severity")):
        if isinstance(candidate, str):
            try:
                return Severity.parse(candidate)
            except ValueError:
                pass
        if isinstance(candidate, list):
            for item in candidate:
                if not isinstance(item, dict):
                    continue
                score = item.get("score") or item.get("baseScore")
                try:
                    score_float = float(score)
                except (TypeError, ValueError):
                    continue
                if score_float >= 9.0:
                    return Severity.CRITICAL
                if score_float >= 7.0:
                    return Severity.HIGH
                if score_float >= 4.0:
                    return Severity.MEDIUM
                return Severity.LOW
    return Severity.UNKNOWN
