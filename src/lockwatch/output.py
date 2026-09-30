"""JSON, SARIF, and human-readable renderers."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Iterable, List

from .models import Finding, ScanResult, Severity


def filter_findings(findings: Iterable[Finding], threshold: Severity) -> List[Finding]:
    """Keep findings at or above ``threshold`` (unknown is severity zero)."""

    return [finding for finding in findings if finding.severity >= threshold]


def render_json(result: ScanResult, pretty: bool = False) -> str:
    return json.dumps(result.to_dict(), indent=2 if pretty else None, sort_keys=True) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity >= Severity.MEDIUM:
        return "warning"
    return "note"


def render_sarif(result: ScanResult) -> str:
    rules = {}
    sarif_results = []
    for finding in result.findings:
        rule_id = finding.vulnerability_id
        rules.setdefault(rule_id, {"id": rule_id, "name": rule_id, "shortDescription": {"text": finding.summary or rule_id}})
        result_item = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": "%s %s is affected: %s" % (finding.package.name, finding.package.version, finding.summary or rule_id)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.package.source}}}],
            "properties": {"package": finding.package.name, "version": finding.package.version, "ecosystem": finding.package.ecosystem, "severity": finding.severity.name.lower(), "aliases": finding.aliases},
        }
        if finding.references:
            result_item["message"]["text"] += " References: " + ", ".join(finding.references)
        sarif_results.append(result_item)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "lockwatch", "version": "0.1.0", "informationUri": "https://github.com/lockwatch/lockwatch", "rules": list(rules.values())}}, "results": sarif_results}],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_text(result: ScanResult) -> str:
    lines = ["lockwatch: %d packages, %d findings" % (len(result.packages), len(result.findings))]
    for finding in result.findings:
        lines.append("[%s] %s %s (%s): %s" % (finding.severity.name.lower(), finding.vulnerability_id, finding.package.name, finding.package.version, finding.summary or "no summary"))
    for error in result.errors:
        lines.append("warning: " + error)
    return "\n".join(lines) + "\n"
