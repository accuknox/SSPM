"""
CIS MS365 8.5.4 (L1) – Ensure dial-in users can't bypass the lobby (Manual)

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
class CIS_8_5_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.4",
        title="Ensure dial-in users can't bypass the lobby",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Dial-in callers should not be able to bypass the meeting lobby. "
            "They should wait in the lobby until an organizer admits them."
        ),
        rationale=(
            "Dial-in callers cannot be authenticated the same way as Teams users. "
            "Requiring them to wait in the lobby for admission ensures an "
            "authenticated meeting participant approves their access."
        ),
        impact="Dial-in callers must be admitted by a meeting organizer or presenter.",
        audit_procedure=(
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object AllowPSTNUsersToBypassLobby\n\n"
            "Compliant: AllowPSTNUsersToBypassLobby = False"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -AllowPSTNUsersToBypassLobby $false"
        ),
        default_value="Dial-in callers bypass lobby by default when organizer is in meeting.",
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
        tags=["teams", "meetings", "lobby", "dial-in", "pstn"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify dial-in lobby bypass setting via Teams PowerShell:\n"
            "  Connect-MicrosoftTeams\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object AllowPSTNUsersToBypassLobby\n\n"
            "Compliant: AllowPSTNUsersToBypassLobby = False"
        )
