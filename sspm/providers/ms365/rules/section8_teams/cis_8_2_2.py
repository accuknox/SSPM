"""
CIS MS365 8.2.2 (L1) – Ensure communication with unmanaged Teams users is
disabled (Manual)

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
class CIS_8_2_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.2.2",
        title="Ensure communication with unmanaged Teams users is disabled",
        section="8.2 Teams External Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Communication with unmanaged Teams users (those who use Teams without "
            "a work or school account) should be disabled to prevent data leakage "
            "to consumer accounts."
        ),
        rationale=(
            "Unmanaged Teams accounts (personal/consumer) don't have the same "
            "governance as organizational accounts. Disabling communication with "
            "them prevents sensitive business data from being shared with consumer accounts."
        ),
        impact="Users will not be able to communicate with personal/consumer Teams accounts.",
        audit_procedure=(
            "Microsoft Teams admin center → External access > Teams accounts not managed by an organization.\n"
            "Teams PowerShell:\n"
            "  Get-CsExternalAccessPolicy | Select-Object AllowTeamsConsumer"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsExternalAccessPolicy -AllowTeamsConsumer $false"
        ),
        default_value="Communication with unmanaged Teams users may be enabled.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/manage-external-access",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="12.2",
                title="Establish and Maintain a Secure Network Architecture",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["teams", "external-access", "unmanaged-users", "consumer-accounts"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify communication with unmanaged Teams users:\n"
            "  Connect-MicrosoftTeams\n"
            "  Get-CsExternalAccessPolicy | Select-Object AllowTeamsConsumer\n\n"
            "Compliant: AllowTeamsConsumer = False"
        )
