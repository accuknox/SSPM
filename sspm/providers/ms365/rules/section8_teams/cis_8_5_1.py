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
        # Teams meeting policy data requires Teams PowerShell or Graph beta.
        # Flag as manual if not available.
        meeting_policies = data.get("teams_meeting_policies")
        if not meeting_policies:
            return self._manual()

        global_policy = next(
            (p for p in meeting_policies if p.get("identity") == "Global"), None
        )
        if not global_policy:
            return self._skip("Global Teams meeting policy not found in collected data.")

        allows_anon = global_policy.get("allowAnonymousUsersToJoinMeeting", True)
        if not allows_anon:
            return self._pass(
                "Anonymous users are blocked from joining Teams meetings.",
                evidence=[
                    Evidence(
                        source="graph/teams/meetingPolicies",
                        data={"allowAnonymousUsersToJoinMeeting": False},
                        description="Global Teams meeting policy.",
                    )
                ],
            )

        return self._fail(
            "Anonymous users are allowed to join Teams meetings.",
            evidence=[
                Evidence(
                    source="graph/teams/meetingPolicies",
                    data=global_policy,
                    description="Global Teams meeting policy allows anonymous join.",
                )
            ],
        )
