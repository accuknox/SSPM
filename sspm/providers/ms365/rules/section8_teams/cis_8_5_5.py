"""
CIS MS365 8.5.5 (L1) – Ensure meeting chat does not allow anonymous users
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
class CIS_8_5_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.5",
        title="Ensure meeting chat does not allow anonymous users",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Meeting chat should be configured to prevent anonymous users from "
            "posting in chat, limiting chat participation to authenticated users."
        ),
        rationale=(
            "Anonymous users in meeting chat cannot be held accountable for their "
            "communications. Restricting anonymous chat participation prevents "
            "abuse and potential social engineering through chat."
        ),
        impact="Anonymous users will not be able to post in meeting chat.",
        audit_procedure=(
            "Get-CsTeamsMeetingPolicy -Identity Global | fl MeetingChatEnabledType\n\n"
            "Ensure MeetingChatEnabledType is EnabledExceptAnonymous or a more "
            "restrictive value (EnabledInMeetingOnlyForAllExceptAnonymous, "
            "Disabled)."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -Identity Global -MeetingChatEnabledType "
            "EnabledExceptAnonymous"
        ),
        default_value="Meeting chat settings vary by policy.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/meeting-policies-in-teams-general",
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
        tags=["teams", "meetings", "chat", "anonymous-users"],
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
                    "Whether anonymous users can use meeting chat requires the "
                    "Microsoft Teams PowerShell bridge (Connect-MicrosoftTeams "
                    "with certificate app-only auth), which is not configured "
                    "for this scan. Verify manually: Get-CsTeamsMeetingPolicy "
                    "-Identity Global | fl MeetingChatEnabledType — ensure it is "
                    "EnabledExceptAnonymous or a more restrictive value "
                    "(EnabledInMeetingOnlyForAllExceptAnonymous, Disabled)."
                )
            )

        value = policy.get("MeetingChatEnabledType")
        evidence = [
            Evidence(
                source="teams/Get-CsTeamsMeetingPolicy",
                data={"MeetingChatEnabledType": value},
                description="Meeting chat availability for anonymous users.",
            )
        ]

        compliant_values = {
            "EnabledExceptAnonymous",
            "EnabledInMeetingOnlyForAllExceptAnonymous",
            "Disabled",
        }
        if value in compliant_values:
            return self._pass(
                f"MeetingChatEnabledType is {value!r}, which prevents anonymous "
                "users from using meeting chat.",
                evidence=evidence,
            )
        if value is not None:
            return self._fail(
                f"MeetingChatEnabledType is {value!r}, which allows anonymous "
                "users to use meeting chat.",
                evidence=evidence,
            )
        return self._manual(
            message=(
                "MeetingChatEnabledType is missing/unexpected; verify manually "
                "via Get-CsTeamsMeetingPolicy -Identity Global | fl "
                "MeetingChatEnabledType."
            )
        )
