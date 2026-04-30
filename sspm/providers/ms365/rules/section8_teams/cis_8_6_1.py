"""
CIS MS365 8.6.1 (L1) – Ensure users can report a security concern in Teams
(Manual)

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
class CIS_8_6_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.6.1",
        title="Ensure users can report a security concern in Teams",
        section="8.6 Teams Messaging",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Users should be able to report security concerns (phishing, malware, "
            "inappropriate content) in Microsoft Teams. This feature should be "
            "enabled to facilitate incident reporting."
        ),
        rationale=(
            "Enabling users to report suspicious content in Teams creates a simple "
            "mechanism for early detection of phishing or social engineering attempts "
            "targeting the organization through Teams."
        ),
        impact="Minimal; this is an additive capability that enables security reporting.",
        audit_procedure=(
            "Microsoft Teams admin center → Messaging policies.\n"
            "Teams PowerShell:\n"
            "  Get-CsTeamsMessagingPolicy | Select-Object AllowUserReportSecurityConcerns\n\n"
            "Compliant: AllowUserReportSecurityConcerns = True"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMessagingPolicy -AllowUserReportSecurityConcerns $true"
        ),
        default_value="Security concern reporting may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/messaging-policies-in-teams",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="17.4",
                title="Establish and Maintain an Incident Response Process",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["teams", "messaging", "security-reporting", "incident-response"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
