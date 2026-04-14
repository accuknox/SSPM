"""
SARIF 2.1.0 reporter.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Key mapping
-----------
FindingStatus.PASS    → kind="pass",   level="none"
FindingStatus.FAIL    → kind="fail",   level=<severity>
FindingStatus.MANUAL  → kind="open",   level="none"  (human review required)
FindingStatus.ERROR   → kind="review", level="note"
FindingStatus.SKIPPED → kind="none",   level="none"
"""

from __future__ import annotations

import json
from typing import Any

from sspm.core.models import FindingStatus, ScanResult, Severity

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_LEVEL: dict[str, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

_STATUS_TO_KIND: dict[FindingStatus, str] = {
    FindingStatus.PASS: "pass",
    FindingStatus.FAIL: "fail",
    FindingStatus.MANUAL: "open",
    FindingStatus.ERROR: "review",
    FindingStatus.SKIPPED: "none",
}


def _rule_descriptor(rule_meta) -> dict[str, Any]:
    """Convert RuleMetadata → SARIF reportingDescriptor."""
    profiles = [p.value for p in rule_meta.profiles]
    cis_controls = [
        {
            "version": c.version,
            "controlId": c.control_id,
            "title": c.title,
            "ig1": c.ig1,
            "ig2": c.ig2,
            "ig3": c.ig3,
        }
        for c in rule_meta.cis_controls
    ]

    return {
        "id": rule_meta.id,
        "name": rule_meta.title,
        "shortDescription": {"text": rule_meta.title},
        "fullDescription": {"text": rule_meta.description},
        "defaultConfiguration": {
            "level": _SEVERITY_TO_LEVEL.get(rule_meta.severity, "warning"),
        },
        "help": {
            "text": (
                f"Rationale: {rule_meta.rationale}\n\n"
                f"Impact: {rule_meta.impact}\n\n"
                f"Audit: {rule_meta.audit_procedure}\n\n"
                f"Remediation: {rule_meta.remediation}"
            ),
            "markdown": (
                f"**Rationale:** {rule_meta.rationale}\n\n"
                f"**Impact:** {rule_meta.impact}\n\n"
                f"**Audit Procedure:**\n{rule_meta.audit_procedure}\n\n"
                f"**Remediation:**\n{rule_meta.remediation}"
            ),
        },
        "properties": {
            "benchmark": rule_meta.benchmark,
            "section": rule_meta.section,
            "assessmentStatus": rule_meta.assessment_status.value,
            "profiles": profiles,
            "severity": rule_meta.severity.value,
            "defaultValue": rule_meta.default_value,
            "cisControls": cis_controls,
            "tags": rule_meta.tags,
        },
        "helpUri": rule_meta.references[0] if rule_meta.references else "",
    }


def _target_fqn(provider: str, target: str) -> str:
    """Return a provider-appropriate fully-qualified name for an account-level target."""
    if provider == "aws":
        return f"arn:aws:iam::{target}:root"
    if provider == "ms365":
        return f"ms365://{target}"
    if provider == "gws":
        return f"gws://{target}"
    return target


def _finding_result(finding, rule_index: int, target: str = "", provider: str = "") -> dict[str, Any]:
    """Convert Finding → SARIF result object."""
    kind = _STATUS_TO_KIND.get(finding.status, "none")
    level: str
    if finding.status == FindingStatus.FAIL:
        level = _SEVERITY_TO_LEVEL.get(finding.rule.severity, "warning")
    elif finding.status == FindingStatus.ERROR:
        level = "note"
    else:
        level = "none"

    # Build the message text
    message_parts = [finding.message or finding.rule.title]
    if finding.status == FindingStatus.MANUAL:
        message_parts.append(
            "This control requires manual verification. "
            "See auditProcedure in rule properties."
        )
    remediation = finding.remediation_guidance or finding.rule.remediation
    if finding.status == FindingStatus.FAIL and remediation:
        message_parts.append(f"Remediation: {remediation}")

    # Location – use logical location (tenant / resource) rather than file URI
    # Prefer a specific resource ARN; fall back to the account root ARN.
    locations = []
    if finding.resource_id or finding.resource_type or target:
        resource_type = finding.resource_type or "tenant"
        resource_id = finding.resource_id  # specific resource ARN when available

        if resource_id:
            # Resource-specific finding: use the ARN directly as fullyQualifiedName
            name = resource_id.split(":")[-1].split("/")[-1] if resource_id.startswith("arn:") else resource_id
            fqn = resource_id
        elif target:
            # Account-level finding: use a provider-appropriate FQN as fallback
            name = target
            fqn = _target_fqn(provider, target)
        else:
            name = resource_type
            fqn = resource_type

        locations.append(
            {
                "logicalLocations": [
                    {
                        "name": name,
                        "kind": resource_type,
                        "fullyQualifiedName": fqn,
                    }
                ]
            }
        )

    # Evidence as related locations / attachments
    related: list[dict] = []
    for ev in finding.evidence:
        related.append(
            {
                "message": {"text": f"{ev.source}: {ev.description}"},
                "properties": {"data": ev.data},
            }
        )

    result: dict[str, Any] = {
        "ruleId": finding.rule.id,
        "ruleIndex": rule_index,
        "kind": kind,
        "level": level,
        "message": {"text": " ".join(message_parts)},
        "properties": {
            "status": finding.status.value,
            "resourceId": finding.resource_id,
            "resourceType": finding.resource_type,
        },
    }
    if locations:
        result["locations"] = locations
    if related:
        result["relatedLocations"] = related

    return result


def to_sarif(scan_result: ScanResult) -> dict[str, Any]:
    """
    Convert a ``ScanResult`` to a SARIF 2.1.0 document (as a Python dict).
    Serialise with ``json.dumps(sarif_doc, indent=2)``.
    """
    # De-duplicate rules (a rule can appear in multiple findings)
    seen_ids: dict[str, int] = {}
    rule_descriptors: list[dict] = []
    for finding in scan_result.findings:
        rid = finding.rule.id
        if rid not in seen_ids:
            seen_ids[rid] = len(rule_descriptors)
            rule_descriptors.append(_rule_descriptor(finding.rule))

    results = [
        _finding_result(f, seen_ids[f.rule.id], target=scan_result.target, provider=scan_result.provider)
        for f in scan_result.findings
    ]

    summary = scan_result.summary()

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AccuKnox SSPM",
                        "version": "0.1.0",
                        "organization": "AccuKnox",
                        "informationUri": "https://accuknox.com",
                        "rules": rule_descriptors,
                        "properties": {
                            "provider": scan_result.provider,
                            "benchmark": scan_result.benchmark,
                        },
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan_result.started_at,
                        "endTimeUtc": scan_result.completed_at,
                        "properties": {
                            "target": scan_result.target,
                            "scanId": scan_result.scan_id,
                        },
                        "workingDirectory": {
                            "uri": scan_result.target,
                        }
                    }
                ],
                "results": results,
                "properties": {
                    "summary": summary,
                },
            }
        ],
    }


def write_sarif(scan_result: ScanResult, path: str) -> None:
    """Serialize a ScanResult to a SARIF JSON file."""
    doc = to_sarif(scan_result)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
