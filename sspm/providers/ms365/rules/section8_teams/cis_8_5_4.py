"""
CIS MS365 8.5.4 (L1) – Ensure users dialing in can't bypass the lobby
(Automated)

Profile Applicability: E3 Level 1, E5 Level 1
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    Evidence,
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
        title="Ensure users dialing in can't bypass the lobby",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Get-CsTeamsMeetingPolicy -Identity Global | fl "
            "AllowPSTNUsersToBypassLobby\n\n"
            "Ensure AllowPSTNUsersToBypassLobby is False."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -Identity Global -AllowPSTNUsersToBypassLobby $false"
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
        # Get-CsTeamsMeetingPolicy is a MicrosoftTeams Remote PowerShell
        # cmdlet with no Microsoft Graph equivalent, so this collector (which
        # only performs Graph client-credentials auth) cannot read it.
        if "teams_meeting_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Teams meeting policy: "
                f"{data.errors.get('teams_meeting_policy')}"
            )

        policy = data.get("teams_meeting_policy")
        if policy is None:
            return self._manual(
                message=(
                    "Whether dial-in (PSTN) users can bypass the lobby requires "
                    "the Microsoft Teams PowerShell bridge (Connect-MicrosoftTeams "
                    "with certificate app-only auth), which is not configured for "
                    "this scan. Verify manually: Get-CsTeamsMeetingPolicy "
                    "-Identity Global | fl AllowPSTNUsersToBypassLobby — ensure "
                    "it is False."
                )
            )

        value = policy.get("AllowPSTNUsersToBypassLobby")
        evidence = [
            Evidence(
                source="teams/Get-CsTeamsMeetingPolicy",
                data={"AllowPSTNUsersToBypassLobby": value},
                description="Whether dial-in (PSTN) callers can bypass the meeting lobby.",
            )
        ]

        if value is False:
            return self._pass(
                "AllowPSTNUsersToBypassLobby is False.", evidence=evidence
            )
        if value is True:
            return self._fail(
                "AllowPSTNUsersToBypassLobby is True; dial-in callers can bypass "
                "the lobby.",
                evidence=evidence,
            )
        return self._manual(
            message=(
                f"AllowPSTNUsersToBypassLobby has an unexpected value ({value!r}); "
                "verify manually via Get-CsTeamsMeetingPolicy -Identity Global | "
                "fl AllowPSTNUsersToBypassLobby."
            )
        )
