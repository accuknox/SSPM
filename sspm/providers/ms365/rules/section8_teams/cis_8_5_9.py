"""
CIS MS365 8.5.9 (L2) – Ensure meeting recordings are not available by default
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
class CIS_8_5_9(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.9",
        title="Ensure meeting recordings are not available by default",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Meeting recording should be disabled by default to prevent sensitive "
            "meeting content from being recorded and stored without explicit consent "
            "from all participants."
        ),
        rationale=(
            "Meeting recordings can contain sensitive business discussions. "
            "Disabling recording by default ensures recordings are made intentionally "
            "and not without participants' knowledge."
        ),
        impact="Users must explicitly enable recording for each meeting.",
        audit_procedure=(
            "Microsoft Teams PowerShell:\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object AllowCloudRecording\n\n"
            "Compliant: AllowCloudRecording = False (or recording disabled by default)"
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -AllowCloudRecording $false"
        ),
        default_value="Meeting recording may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/meeting-policies-recording-and-transcription",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.3",
                title="Configure Data Access Control Lists",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["teams", "meetings", "recording", "privacy"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify meeting recording settings via Teams PowerShell:\n"
            "  Connect-MicrosoftTeams\n"
            "  Get-CsTeamsMeetingPolicy | Select-Object AllowCloudRecording\n\n"
            "Compliant: AllowCloudRecording = False (recording disabled by default)."
        )
