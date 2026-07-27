"""
CIS MS365 8.5.7 (L1) – Ensure external participants can't give or request
control (Automated)

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
class CIS_8_5_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.5.7",
        title="Ensure external participants can't give or request control",
        section="8.5 Teams Meetings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "External participants in Teams meetings should not be able to give "
            "or request control of a presenter's desktop or application. This "
            "prevents external parties from controlling internal computers."
        ),
        rationale=(
            "Allowing external users to control screen shares gives them direct "
            "control of internal computers, which can be exploited to install "
            "malware or access sensitive data."
        ),
        impact="External meeting participants will not be able to use remote control features.",
        audit_procedure=(
            "Get-CsTeamsMeetingPolicy -Identity Global | fl "
            "AllowExternalParticipantGiveRequestControl\n\n"
            "Ensure AllowExternalParticipantGiveRequestControl is False."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMeetingPolicy -Identity Global "
            "-AllowExternalParticipantGiveRequestControl $false"
        ),
        default_value="External control may be allowed by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/meeting-policies-content-sharing",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="12.2",
                title="Establish and Maintain a Secure Network Architecture",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["teams", "meetings", "remote-control", "external-participants"],
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
                    "Whether external participants can give or request control "
                    "requires the Microsoft Teams PowerShell bridge "
                    "(Connect-MicrosoftTeams with certificate app-only auth), "
                    "which is not configured for this scan. Verify manually: "
                    "Get-CsTeamsMeetingPolicy -Identity Global | fl "
                    "AllowExternalParticipantGiveRequestControl — ensure it is "
                    "False."
                )
            )

        value = policy.get("AllowExternalParticipantGiveRequestControl")
        evidence = [
            Evidence(
                source="teams/Get-CsTeamsMeetingPolicy",
                data={"AllowExternalParticipantGiveRequestControl": value},
                description="Whether external participants can give/request remote control.",
            )
        ]

        if value is False:
            return self._pass(
                "AllowExternalParticipantGiveRequestControl is False.",
                evidence=evidence,
            )
        if value is True:
            return self._fail(
                "AllowExternalParticipantGiveRequestControl is True; external "
                "participants can give or request control.",
                evidence=evidence,
            )
        return self._manual(
            message=(
                "AllowExternalParticipantGiveRequestControl has an unexpected "
                f"value ({value!r}); verify manually via "
                "Get-CsTeamsMeetingPolicy -Identity Global | fl "
                "AllowExternalParticipantGiveRequestControl."
            )
        )
