"""
CIS MS365 8.5.3 (L1) – Ensure only people in my org can bypass the lobby
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
class CIS_8_5_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.3",
        title="Ensure only people in my org can bypass the lobby",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Only users from the organization should be able to bypass the meeting "
            "lobby. External users and guests should wait in the lobby for an "
            "organizer or presenter to admit them."
        ),
        rationale=(
            "The meeting lobby acts as a security gate, ensuring unauthorized users "
            "don't join meetings without explicit admission. External users should "
            "not automatically bypass this control."
        ),
        impact="External users must wait in the lobby before being admitted to meetings.",
        audit_procedure=(
            "Get-CsTeamsMeetingPolicy -Identity Global | fl AutoAdmittedUsers\n\n"
            "Ensure AutoAdmittedUsers is InvitedUsers or a more restrictive value "
            "(EveryoneInCompanyExcludingGuests, OrganizerOnly)."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -Identity Global -AutoAdmittedUsers InvitedUsers"
        ),
        default_value="AutoAdmittedUsers may allow everyone to bypass lobby.",
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
        tags=["teams", "meetings", "lobby", "meeting-policy"],
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
                    "Lobby bypass settings require the Microsoft Teams PowerShell "
                    "bridge (Connect-MicrosoftTeams with certificate app-only "
                    "auth), which is not configured for this scan. Verify "
                    "manually: Get-CsTeamsMeetingPolicy -Identity Global | fl "
                    "AutoAdmittedUsers — ensure it is InvitedUsers or a more "
                    "restrictive value (EveryoneInCompanyExcludingGuests, "
                    "OrganizerOnly)."
                )
            )

        value = policy.get("AutoAdmittedUsers")
        evidence = [
            Evidence(
                source="teams/Get-CsTeamsMeetingPolicy",
                data={"AutoAdmittedUsers": value},
                description="Who can bypass the meeting lobby.",
            )
        ]

        # Per CIS's audit procedure, compliant values are InvitedUsers or a
        # more restrictive value.
        compliant_values = {
            "InvitedUsers",
            "EveryoneInCompanyExcludingGuests",
            "OrganizerOnly",
        }
        if value in compliant_values:
            return self._pass(
                f"AutoAdmittedUsers is {value!r}, which restricts lobby bypass "
                "to organization members or more restrictive.",
                evidence=evidence,
            )
        if value is not None:
            return self._fail(
                f"AutoAdmittedUsers is {value!r}, which allows more than "
                "InvitedUsers/organization members to bypass the lobby.",
                evidence=evidence,
            )
        return self._manual(
            message=(
                "AutoAdmittedUsers is missing/unexpected; verify manually via "
                "Get-CsTeamsMeetingPolicy -Identity Global | fl AutoAdmittedUsers."
            )
        )
