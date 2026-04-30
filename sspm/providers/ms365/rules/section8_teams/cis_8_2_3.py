"""
CIS MS365 8.2.3 (L1) – Ensure external Teams users cannot initiate
conversations (Manual)

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
class CIS_8_2_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.2.3",
        title="Ensure external Teams users cannot initiate conversations with internal users",
        section="8.2 Teams External Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "External Teams users should not be able to initiate conversations with "
            "internal users. Internal users should be the ones initiating external "
            "communications."
        ),
        rationale=(
            "Allowing external users to initiate conversations opens the door to "
            "social engineering and phishing via Teams chat. Restricting initiation "
            "to internal users reduces unsolicited external contact."
        ),
        impact="External Teams users will not be able to initiate chats with internal users.",
        audit_procedure=(
            "Microsoft Teams PowerShell:\n"
            "  Get-CsExternalAccessPolicy | Select-Object AllowTeamsConsumerInbound\n\n"
            "Also check federation configuration:\n"
            "  Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsExternalAccessPolicy -AllowTeamsConsumerInbound $false"
        ),
        default_value="External users may be able to initiate conversations.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/manage-external-access",
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
        tags=["teams", "external-access", "inbound-communication"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
