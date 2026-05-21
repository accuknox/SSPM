"""
CIS GWS 3.1.3.4.2.1 (L1) – Ensure link identification behind shortened
URLs is enabled (Manual)

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
class CIS_3_1_3_4_2_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.4.2.1",
        title="Ensure link identification behind shortened URLs is enabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "Identify links behind short URLs, and display a warning when you "
            "click links to untrusted domains.  This protects users from "
            "malicious links hidden behind URL shorteners."
        ),
        rationale="You should protect your users from potentially malicious links.",
        impact="Users will be warned when they click links to untrusted domains.",
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Links and external images, ensure 'Identify links "
            "behind shortened URLs' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Links and external images, set 'Identify links "
            "behind shortened URLs' to checked\n"
            "  4. Click Save"
        ),
        default_value="Identify links behind shortened URLs is checked.",
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
        tags=["gmail", "links", "phishing", "url-scanning", "safety"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
