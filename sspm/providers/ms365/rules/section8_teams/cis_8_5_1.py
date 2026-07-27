"""
CIS MS365 8.5.1 (L2) – Ensure anonymous users can't join a meeting (Automated)

Profile Applicability: E3 Level 2, E5 Level 2

The Teams global meeting policy should prevent anonymous (unauthenticated)
users from joining meetings.
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
class CIS_8_5_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.1",
        title="Ensure anonymous users can't join a meeting",
        section="8.5 Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Anonymous meeting join allows anyone who has a meeting link to join "
            "without authenticating.  This should be disabled to prevent uninvited "
            "participants from joining sensitive meetings."
        ),
        rationale=(
            "Allowing anonymous users to join meetings increases the risk of "
            "eavesdropping on sensitive discussions, meeting bombing, and social "
            "engineering attacks."
        ),
        impact=(
            "External guests must be authenticated before joining meetings. "
            "B2B guest users can still join; only truly anonymous users are blocked."
        ),
        audit_procedure=(
            "Teams PowerShell:\n"
            "  Get-CsTeamsMeetingPolicy -Identity Global | "
            "Select-Object AllowAnonymousUsersToJoinMeeting\n"
            "  Expected: AllowAnonymousUsersToJoinMeeting = False\n\n"
            "Or Teams admin center → Meetings > Meeting policies > Global > "
            "Participants & guests > Allow anonymous users to join a meeting."
        ),
        remediation=(
            "Teams admin center:\n"
            "  Meetings > Meeting policies > Global > Participants & guests.\n"
            "  Set 'Allow anonymous users to join a meeting' to Off.\n\n"
            "PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -Identity Global "
            "-AllowAnonymousUsersToJoinMeeting $false"
        ),
        default_value="Enabled (anonymous join is on by default).",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/meeting-settings-in-teams",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.2",
                title="Establish an Access Granting Process",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["teams", "meetings", "anonymous-access", "collaboration"],
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
                    "Whether anonymous users can join meetings requires the "
                    "Microsoft Teams PowerShell bridge (Connect-MicrosoftTeams "
                    "with certificate or access-token app-only auth), which is "
                    "not configured for this scan. Verify manually: "
                    "Get-CsTeamsMeetingPolicy -Identity Global | fl "
                    "AllowAnonymousUsersToJoinMeeting — ensure it is False."
                )
            )

        value = policy.get("AllowAnonymousUsersToJoinMeeting")
        evidence = [
            Evidence(
                source="teams/Get-CsTeamsMeetingPolicy",
                data={"AllowAnonymousUsersToJoinMeeting": value},
                description="Whether anonymous users can join a meeting.",
            )
        ]

        if value is False:
            return self._pass(
                "AllowAnonymousUsersToJoinMeeting is False; anonymous users "
                "are blocked from joining Teams meetings.",
                evidence=evidence,
            )
        if value is True:
            return self._fail(
                "AllowAnonymousUsersToJoinMeeting is True; anonymous users "
                "are allowed to join Teams meetings.",
                evidence=evidence,
            )
        return self._manual(
            message=(
                f"AllowAnonymousUsersToJoinMeeting has an unexpected value "
                f"({value!r}); verify manually via Get-CsTeamsMeetingPolicy "
                "-Identity Global | fl AllowAnonymousUsersToJoinMeeting."
            )
        )
