"""
CIS GWS 3.1.3.4.3.1 (L1) – Ensure protection against domain spoofing
based on similar domain names is enabled (Manual)

Profile Applicability: Enterprise Level 1
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_3_1_3_4_3_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.4.3.1",
        title="Ensure protection against domain spoofing based on similar domain names is enabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Moves domain spoofing emails to spam folder.  This setting detects "
            "emails from domains with similar names to your organisation's domains "
            "(typosquatting / homograph attacks)."
        ),
        rationale="You should protect your users from domain spoofing emails.",
        impact="Domain spoofed emails will be moved to a user's spam folder.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Spoofing and authentication, ensure 'Protect "
            "against domain spoofing based on similar domain names' is checked\n"
            "  4. Ensure Action is 'Move email to spam'"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Spoofing and authentication, set 'Protect against "
            "domain spoofing based on similar domain names' to checked\n"
            "  4. Set Action to 'Move email to spam'\n"
            "  5. Click Save"
        ),
        default_value=(
            "Protect against domain spoofing based on similar domain names is checked; "
            "Action is 'Keep email in inbox and show warning' (default)."
        ),
        references=[
            "https://support.google.com/a/answer/9157861",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.3",
                title="Maintain and Enforce Network-Based URL Filters",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["gmail", "spoofing", "phishing", "domain-spoofing", "safety"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
