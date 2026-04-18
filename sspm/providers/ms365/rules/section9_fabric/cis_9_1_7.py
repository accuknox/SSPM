"""
CIS MS365 9.1.7 (L1) – Ensure shareable links in Microsoft Fabric are
restricted (Manual)

Profile Applicability: E3 Level 1, E5 Level 1
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
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_9_1_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.7",
        title="Ensure shareable links in Microsoft Fabric are restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Shareable links in Microsoft Fabric should be restricted to prevent "
            "users from creating publicly accessible links to reports and dashboards "
            "containing potentially sensitive data."
        ),
        rationale=(
            "Shareable links allow any person with the link to access reports "
            "without authentication. Restricting this feature prevents accidental "
            "public disclosure of business intelligence data."
        ),
        impact="Users will not be able to create shareable links for Fabric content.",
        audit_procedure=(
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > Export and sharing settings:\n"
            "  Check shareable links settings"
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings > Export and sharing:\n"
            "  Disable or restrict shareable links feature"
        ),
        default_value="Shareable links may be available to all users by default.",
        references=[
            "https://learn.microsoft.com/en-us/power-bi/collaborate-share/service-share-dashboards",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.3",
                title="Configure Data Access Control Lists",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["fabric", "power-bi", "shareable-links", "data-protection"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
