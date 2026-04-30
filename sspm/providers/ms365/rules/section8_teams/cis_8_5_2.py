"""
CIS MS365 8.5.2 (L1) – Ensure anonymous users and dial-in callers can't start
a meeting (Manual)

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
class CIS_8_5_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.2",
        title="Ensure anonymous users and dial-in callers can't start a meeting",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Anonymous users and dial-in callers should not be able to start "
            "Teams meetings. Only authenticated users should be able to initiate meetings."
        ),
        rationale=(
            "Allowing anonymous or unauthenticated users to start meetings creates "
            "opportunities for unauthorized meeting sessions that could be used for "
            "eavesdropping or social engineering."
        ),
        impact="Meetings must be started by authenticated meeting participants.",
        audit_procedure=(
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object AllowAnonymousUsersToStartMeeting\n\n"
            "Compliant: AllowAnonymousUsersToStartMeeting = False"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -AllowAnonymousUsersToStartMeeting $false"
        ),
        default_value="Anonymous users cannot start meetings by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/meeting-policies-participants-and-guests",
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
        tags=["teams", "meetings", "anonymous-users", "meeting-policy"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
