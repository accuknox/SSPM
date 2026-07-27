"""
CIS MS365 8.5.8 (L1) – Ensure external meeting chat is off (Automated)

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
class CIS_8_5_8(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.8",
        title="Ensure external meeting chat is off",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Meeting chat should be restricted so that external participants "
            "(guests and federated users) cannot use the meeting chat to communicate "
            "with internal participants."
        ),
        rationale=(
            "External participants in meeting chat can send malicious links or "
            "attempt social engineering through meeting chat. Restricting external "
            "chat reduces this attack vector."
        ),
        impact="External participants will not be able to use meeting chat.",
        audit_procedure=(
            "Get-CsTeamsMeetingPolicy -Identity Global | fl "
            "AllowExternalNonTrustedMeetingChat\n\n"
            "Ensure AllowExternalNonTrustedMeetingChat is False."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -Identity Global "
            "-AllowExternalNonTrustedMeetingChat $false"
        ),
        default_value="External participants can use meeting chat by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/meeting-policies-in-teams-general",
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
        tags=["teams", "meetings", "chat", "external-participants"],
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
                    "Whether external (non-trusted) meeting chat is enabled "
                    "requires the Microsoft Teams PowerShell bridge "
                    "(Connect-MicrosoftTeams with certificate app-only auth), "
                    "which is not configured for this scan. Verify manually: "
                    "Get-CsTeamsMeetingPolicy -Identity Global | fl "
                    "AllowExternalNonTrustedMeetingChat — ensure it is False."
                )
            )

        value = policy.get("AllowExternalNonTrustedMeetingChat")
        evidence = [
            Evidence(
                source="teams/Get-CsTeamsMeetingPolicy",
                data={"AllowExternalNonTrustedMeetingChat": value},
                description="Whether external (non-trusted) participants can use meeting chat.",
            )
        ]

        if value is False:
            return self._pass(
                "AllowExternalNonTrustedMeetingChat is False.", evidence=evidence
            )
        if value is True:
            return self._fail(
                "AllowExternalNonTrustedMeetingChat is True; external "
                "participants can use meeting chat.",
                evidence=evidence,
            )
        return self._manual(
            message=(
                "AllowExternalNonTrustedMeetingChat has an unexpected value "
                f"({value!r}); verify manually via Get-CsTeamsMeetingPolicy "
                "-Identity Global | fl AllowExternalNonTrustedMeetingChat."
            )
        )
