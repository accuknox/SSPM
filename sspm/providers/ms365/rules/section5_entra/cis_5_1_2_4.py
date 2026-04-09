"""
CIS MS365 5.1.2.4 (L1) – Ensure access to the Entra administration portal is
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
class CIS_5_1_2_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.2.4",
        title="Ensure access to the Entra administration portal is restricted",
        section="5.1.2 Account Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Access to the Microsoft Entra administration portal should be "
            "restricted to administrators only. Non-admin users should not "
            "be able to access the Entra admin portal."
        ),
        rationale=(
            "Restricting portal access reduces the information available to "
            "potential attackers who may compromise a regular user account. "
            "Non-admin users do not need access to the administrative portal."
        ),
        impact=(
            "Non-admin users will not be able to access the Microsoft Entra "
            "admin center portal."
        ),
        audit_procedure=(
            "Microsoft Entra admin center → Identity > Users > User settings.\n"
            "Check 'Restrict access to Microsoft Entra admin center' setting.\n\n"
            "The setting 'Restrict non-admins from accessing the Entra admin portal' "
            "should be set to Yes."
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Users > User settings.\n"
            "Set 'Restrict access to Microsoft Entra admin center' to Yes."
        ),
        default_value="Non-admin users can access the Entra admin portal by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.6",
                title="Securely Manage Enterprise Assets and Software",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "admin-portal", "access-control"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Entra admin portal access restriction:\n"
            "  1. Go to https://entra.microsoft.com\n"
            "  2. Navigate to Identity > Users > User settings\n"
            "  3. Verify 'Restrict access to Microsoft Entra admin center' is enabled\n\n"
            "This setting cannot be verified via Microsoft Graph API."
        )
