"""
CIS MS365 9.1.2 (L1) – Ensure external user invitations to Microsoft Fabric
are restricted (Manual)

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
class CIS_9_1_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-9.1.2",
        title="Ensure external user invitations to Microsoft Fabric are restricted",
        section="9.1 Microsoft Fabric",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "The ability to invite external users to Microsoft Fabric content should "
            "be restricted to prevent unauthorized sharing of analytical content "
            "with external parties."
        ),
        rationale=(
            "Unrestricted external user invitations can result in sensitive business "
            "intelligence content being shared with external parties without proper "
            "authorization."
        ),
        impact="Users will not be able to invite external users to Fabric content directly.",
        audit_procedure=(
            "Microsoft Fabric admin portal (app.powerbi.com/admin):\n"
            "  Tenant settings > Export and sharing settings:\n"
            "  Check 'Invite external users to your organization through Microsoft Fabric'\n\n"
            "Compliant: Setting is disabled"
        ),
        remediation=(
            "Microsoft Fabric admin portal → Tenant settings:\n"
            "  Disable 'Invite external users to your organization through Microsoft Fabric'"
        ),
        default_value="External user invitations may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-export-sharing",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.1",
                title="Establish an Access Granting Process",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["fabric", "power-bi", "external-invitations", "data-analytics"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify external user invitations to Microsoft Fabric:\n"
            "  1. Go to https://app.powerbi.com/admin\n"
            "  2. Navigate to Tenant settings > Export and sharing settings\n"
            "  3. Check 'Invite external users to your organization through Microsoft Fabric'\n"
            "  Compliant: Setting is disabled"
        )
