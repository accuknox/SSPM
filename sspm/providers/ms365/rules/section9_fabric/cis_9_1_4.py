"""
CIS MS365 9.1.4 (L1) – Ensure 'Publish to web' in Microsoft Fabric is
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
class CIS_9_1_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.4",
        title="Ensure 'Publish to web' in Microsoft Fabric is restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The 'Publish to web' feature in Microsoft Fabric (Power BI) allows "
            "reports to be published publicly on the internet. This should be "
            "disabled or restricted to prevent accidental public exposure of "
            "sensitive data."
        ),
        rationale=(
            "'Publish to web' creates anonymous, publicly accessible links to "
            "reports. If a user accidentally publishes a sensitive report, the "
            "data is exposed to anyone on the internet."
        ),
        impact="Users will not be able to publish reports to the public web.",
        audit_procedure=(
            "Microsoft Fabric admin portal:\n"
            "  Tenant settings > Export and sharing settings:\n"
            "  Check 'Publish to web' setting\n\n"
            "Compliant: Disabled or restricted to specific groups"
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Disable 'Publish to web' or restrict to specific security groups"
        ),
        default_value="Publish to web may be enabled for all users by default.",
        references=[
            "https://learn.microsoft.com/en-us/power-bi/collaborate-share/service-publish-to-web",
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
        tags=["fabric", "power-bi", "publish-to-web", "public-access"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify 'Publish to web' restrictions in Microsoft Fabric:\n"
            "  1. Go to https://app.powerbi.com/admin\n"
            "  2. Navigate to Tenant settings > Export and sharing settings\n"
            "  3. Check 'Publish to web' setting\n"
            "  Compliant: Disabled or restricted to specific security groups"
        )
