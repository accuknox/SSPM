"""
CIS MS365 8.5.6 (L2) – Ensure only organizers can present in meetings
(Manual)

Profile Applicability: E3 Level 2, E5 Level 2
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
class CIS_8_5_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.6",
        title="Ensure only organizers can present in meetings",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Meeting presentation rights should be configured so only the organizer "
            "can present by default. This prevents external attendees or others "
            "from unexpectedly presenting screen shares."
        ),
        rationale=(
            "Limiting presenter rights to organizers prevents external attendees "
            "from sharing potentially malicious content during meetings."
        ),
        impact="Meeting participants who need to present must be explicitly promoted by the organizer.",
        audit_procedure=(
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object DesignatedPresenterRoleMode\n\n"
            "Compliant: DesignatedPresenterRoleMode = 'OrganizerOnlyUserOverride' "
            "or 'OrganizerOnly'"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -DesignatedPresenterRoleMode OrganizerOnlyUserOverride"
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
        return self._manual(
            "Verify meeting presenter settings via Teams PowerShell:\n"
            "  Connect-MicrosoftTeams\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object DesignatedPresenterRoleMode\n\n"
            "Compliant: DesignatedPresenterRoleMode = OrganizerOnlyUserOverride"
        )
