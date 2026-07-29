"""
CIS MS365 8.5.9 (L2) – Ensure meeting recording is off by default (Automated)

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
class CIS_8_5_9(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.9",
        title="Ensure meeting recording is off by default",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Get-CsTeamsMeetingPolicy -Identity Global | fl AllowCloudRecording\n\n"
            "Ensure AllowCloudRecording is False."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -Identity Global -AllowCloudRecording $false"
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
                    "Whether cloud recording is off by default requires the "
                    "Microsoft Teams PowerShell bridge (Connect-MicrosoftTeams "
                    "with certificate app-only auth), which is not configured "
                    "for this scan. Verify manually: Get-CsTeamsMeetingPolicy "
                    "-Identity Global | fl AllowCloudRecording — ensure it is "
                    "False."
                )
            )

        value = policy.get("AllowCloudRecording")
        evidence = [
            Evidence(
                source="teams/Get-CsTeamsMeetingPolicy",
                data={"AllowCloudRecording": value},
                description="Whether meeting cloud recording is allowed.",
            )
        ]

        if value is False:
            return self._pass(
                "AllowCloudRecording is False.", evidence=evidence
            )
        if value is True:
            return self._fail(
                "AllowCloudRecording is True; meeting recording is enabled by "
                "default.",
                evidence=evidence,
            )
        return self._skip(
            reason=(
                f"AllowCloudRecording has an unexpected value ({value!r}); "
                "verify manually via Get-CsTeamsMeetingPolicy -Identity Global "
                "| fl AllowCloudRecording."
            )
        )
