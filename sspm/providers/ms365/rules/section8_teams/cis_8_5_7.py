"""
CIS MS365 8.5.7 (L1) – Ensure external participants cannot give or request
control (Manual)

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
class CIS_8_5_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.7",
        title="Ensure external participants cannot give or request control",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "External participants in Teams meetings should not be able to give "
            "or request control of a presenter's desktop or application. This "
            "prevents external parties from controlling internal computers."
        ),
        rationale=(
            "Allowing external users to control screen shares gives them direct "
            "control of internal computers, which can be exploited to install "
            "malware or access sensitive data."
        ),
        impact="External meeting participants will not be able to use remote control features.",
        audit_procedure=(
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object AllowExternalParticipantGiveRequestControl\n\n"
            "Compliant: AllowExternalParticipantGiveRequestControl = False"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -AllowExternalParticipantGiveRequestControl $false"
        ),
        default_value="External control may be allowed by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/meeting-policies-content-sharing",
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
        tags=["teams", "meetings", "remote-control", "external-participants"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify external participant control settings via Teams PowerShell:\n"
            "  Connect-MicrosoftTeams\n"
            "  Get-CsTeamsMeetingPolicy | "
            "Select-Object AllowExternalParticipantGiveRequestControl\n\n"
            "Compliant: AllowExternalParticipantGiveRequestControl = False"
        )
