"""
CIS MS365 8.5.3 (L1) – Ensure only org users bypass the lobby (Manual)

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
class CIS_8_5_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.3",
        title="Ensure only org users bypass the lobby",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object AutoAdmittedUsers\n\n"
            "Compliant: AutoAdmittedUsers = 'OrganizerOnly' or 'InvitedUsers' (not 'Everyone')"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -AutoAdmittedUsers OrganizerOnly"
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
        return self._manual()
