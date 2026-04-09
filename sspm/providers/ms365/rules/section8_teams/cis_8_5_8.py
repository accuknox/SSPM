"""
CIS MS365 8.5.8 (L1) – Ensure external meeting chat is turned off (Manual)

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
class CIS_8_5_8(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.8",
        title="Ensure external meeting chat is turned off",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object MeetingChatEnabledType\n\n"
            "Compliant: Chat is restricted to authenticated internal users only."
        ),
        remediation=(
            "Microsoft Teams admin center → Meetings > Meeting policies.\n"
            "Configure meeting chat settings to restrict external participants."
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
        return self._manual(
            "Verify external meeting chat settings via Teams PowerShell:\n"
            "  Connect-MicrosoftTeams\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object MeetingChatEnabledType\n\n"
            "Compliant: External participants are restricted from meeting chat."
        )
