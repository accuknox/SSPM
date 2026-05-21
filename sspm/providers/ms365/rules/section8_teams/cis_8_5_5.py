"""
CIS MS365 8.5.5 (L1) – Ensure meeting chat does not allow anonymous users
(Manual)

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
class CIS_8_5_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.5",
        title="Ensure meeting chat does not allow anonymous users",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object MeetingChatEnabledType\n\n"
            "Compliant: MeetingChatEnabledType = 'Enabled' (not 'EnabledExceptAnonymous')"
        ),
        remediation=(
            "Microsoft Teams admin center → Meetings > Meeting policies.\n"
            "Set meeting chat to not allow anonymous participants."
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
        return self._manual()
