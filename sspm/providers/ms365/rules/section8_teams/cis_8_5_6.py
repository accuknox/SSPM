"""
CIS MS365 8.5.6 (L2) – Ensure only organizers and co-organizers can present
(Automated)

Profile Applicability: E3 Level 2, E5 Level 2
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
class CIS_8_5_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.6",
        title="Ensure only organizers and co-organizers can present",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Meeting presentation rights should be configured so only the organizer "
            "and co-organizers can present by default. This prevents external "
            "attendees or others from unexpectedly presenting screen shares."
        ),
        rationale=(
            "Limiting presenter rights to organizers and co-organizers prevents "
            "external attendees from sharing potentially malicious content during "
            "meetings."
        ),
        impact="Meeting participants who need to present must be explicitly promoted by the organizer.",
        audit_procedure=(
            "Get-CsTeamsMeetingPolicy -Identity Global | fl "
            "DesignatedPresenterRoleMode\n\n"
            "Ensure DesignatedPresenterRoleMode is OrganizerOnlyUserOverride."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -Identity Global -DesignatedPresenterRoleMode "
            "OrganizerOnlyUserOverride"
        ),
        default_value="Everyone can present by default.",
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
        tags=["teams", "meetings", "presenter", "meeting-policy"],
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
            return self._skip(
                reason=(
                    "Presenter role restrictions require the Microsoft Teams "
                    "PowerShell bridge (Connect-MicrosoftTeams with certificate "
                    "app-only auth), which is not configured for this scan. "
                    "Verify manually: Get-CsTeamsMeetingPolicy -Identity Global | "
                    "fl DesignatedPresenterRoleMode — ensure it is "
                    "OrganizerOnlyUserOverride."
                )
            )

        value = policy.get("DesignatedPresenterRoleMode")
        evidence = [
            Evidence(
                source="teams/Get-CsTeamsMeetingPolicy",
                data={"DesignatedPresenterRoleMode": value},
                description="Who can be designated as a presenter by default.",
            )
        ]

        if value == "OrganizerOnlyUserOverride":
            return self._pass(
                "DesignatedPresenterRoleMode is OrganizerOnlyUserOverride.",
                evidence=evidence,
            )
        return self._fail(
            f"DesignatedPresenterRoleMode is {value!r}, not "
            "OrganizerOnlyUserOverride; participants other than organizers/"
            "co-organizers may be able to present by default.",
            evidence=evidence,
        )
