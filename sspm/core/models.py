"""
Core data models for SSPM.

Every SaaS provider maps its controls onto these shared abstractions so the
scan engine, reporter, and CLI remain provider-agnostic.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AssessmentStatus(str, Enum):
    """Whether a CIS recommendation can be evaluated automatically or requires
    human inspection."""

    AUTOMATED = "automated"
    MANUAL = "manual"


class FindingStatus(str, Enum):
    """Outcome of evaluating a single rule against a target."""

    PASS = "pass"
    FAIL = "fail"
    # Control cannot be evaluated programmatically; human review required.
    MANUAL = "manual"
    # Rule execution raised an unexpected error (misconfiguration, permissions…)
    ERROR = "error"
    # Prerequisites for this rule were not met (e.g. feature not licensed).
    SKIPPED = "skipped"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CISProfile(str, Enum):
    """License + level profiles from the CIS MS365 benchmark."""

    E3_L1 = "E3 Level 1"
    E3_L2 = "E3 Level 2"
    E5_L1 = "E5 Level 1"
    E5_L2 = "E5 Level 2"


# ---------------------------------------------------------------------------
# Metadata structures
# ---------------------------------------------------------------------------


@dataclass
class CISControl:
    """Mapping to a CIS Critical Security Controls safeguard."""

    version: str       # "v7" or "v8"
    control_id: str    # e.g. "5.4"
    title: str
    ig1: bool = False  # Implementation Group applicability
    ig2: bool = False
    ig3: bool = False


@dataclass
class RuleMetadata:
    """
    Complete metadata for a security rule, modelled after a CIS benchmark
    recommendation definition.  New providers can attach extra metadata via
    the ``extra`` dict without changing the schema.
    """

    # --- Identification ---
    id: str             # Globally unique, e.g. "ms365-cis-1.1.1"
    title: str          # Short human-readable title
    section: str        # Benchmark section, e.g. "1.1 Users"
    benchmark: str      # Source document name + version

    # --- Classification ---
    assessment_status: AssessmentStatus
    profiles: list[CISProfile]
    severity: Severity

    # --- Narrative ---
    description: str
    rationale: str
    impact: str

    # --- Procedures ---
    audit_procedure: str     # How to audit (UI / API / PowerShell)
    remediation: str         # How to fix a failing control
    default_value: str = ""  # System default before hardening

    # --- References ---
    references: list[str] = field(default_factory=list)
    cis_controls: list[CISControl] = field(default_factory=list)

    # --- Tagging (free-form, for filtering) ---
    tags: list[str] = field(default_factory=list)

    # --- Provider-specific extras ---
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    """Observed data that led to a finding status."""

    source: str        # API endpoint, PowerShell cmdlet, or UI path
    data: Any          # Raw API response or extracted value
    description: str = ""


@dataclass
class Finding:
    """
    The result of evaluating one rule against one (or more) resources.

    A single rule may produce multiple findings when it iterates over
    resources (e.g. per-user checks).  Each finding carries enough context
    for a human to understand what was checked, what was found, and what
    to do about it.
    """

    rule: RuleMetadata
    status: FindingStatus
    resource_id: str = ""       # e.g. tenant ID, user UPN, domain name
    resource_type: str = ""     # e.g. "tenant", "user", "domain"
    message: str = ""           # Human-readable summary of the finding
    evidence: list[Evidence] = field(default_factory=list)
    # Override rule-level remediation guidance for this specific instance
    remediation_guidance: str = ""


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Aggregated output of a complete scan run."""

    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""          # Tenant domain / organisation identifier
    provider: str = ""        # e.g. "ms365"
    benchmark: str = ""       # e.g. "CIS Microsoft 365 Foundations Benchmark v6.0.1"
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: str = ""
    findings: list[Finding] = field(default_factory=list)

    # --- Convenience accessors ---

    @property
    def passed(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.PASS]

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.FAIL]

    @property
    def manual(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.MANUAL]

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.ERROR]

    @property
    def skipped(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FindingStatus.SKIPPED]

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.findings),
            "passed": len(self.passed),
            "failed": len(self.failed),
            "manual": len(self.manual),
            "errors": len(self.errors),
            "skipped": len(self.skipped),
        }
