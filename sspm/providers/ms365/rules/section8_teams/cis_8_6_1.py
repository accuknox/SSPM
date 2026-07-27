"""
CIS MS365 8.6.1 (L1) – Ensure users can report security concerns in Teams
(Automated)

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
class CIS_8_6_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-8.6.1",
        title="Ensure users can report security concerns in Teams",
        section="8.6 Teams Messaging",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Users should be able to report security concerns (phishing, malware, "
            "inappropriate content) in Microsoft Teams. This feature should be "
            "enabled to facilitate incident reporting."
        ),
        rationale=(
            "Enabling users to report suspicious content in Teams creates a simple "
            "mechanism for early detection of phishing or social engineering attempts "
            "targeting the organization through Teams."
        ),
        impact="Minimal; this is an additive capability that enables security reporting.",
        audit_procedure=(
            "Connect-MicrosoftTeams.\n"
            "  Get-CsTeamsMessagingPolicy -Identity Global | fl "
            "AllowSecurityEndUserReporting\n"
            "  Ensure AllowSecurityEndUserReporting is True.\n\n"
            "ALSO Connect-ExchangeOnline.\n"
            "  Get-ReportSubmissionPolicy | fl Report*\n"
            "  Ensure ReportJunkToCustomizedAddress = True, "
            "ReportNotJunkToCustomizedAddress = True, "
            "ReportPhishToCustomizedAddress = True, ReportJunkAddresses / "
            "ReportNotJunkAddresses / ReportPhishAddresses are set to the "
            "organization's SOC address, ReportChatMessageEnabled = False, and "
            "ReportChatMessageToCustomizedAddressEnabled = True."
        ),
        remediation=(
            "Microsoft Teams PowerShell:\n"
            "  Set-CsTeamsMessagingPolicy -Identity Global "
            "-AllowSecurityEndUserReporting $true\n\n"
            "Exchange Online PowerShell:\n"
            "  Set-ReportSubmissionPolicy -ReportJunkToCustomizedAddress $true "
            "-ReportNotJunkToCustomizedAddress $true -ReportPhishToCustomizedAddress "
            "$true -ReportJunkAddresses <SOC address> -ReportNotJunkAddresses "
            "<SOC address> -ReportPhishAddresses <SOC address> "
            "-ReportChatMessageEnabled $false "
            "-ReportChatMessageToCustomizedAddressEnabled $true"
        ),
        default_value="Security concern reporting may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoftteams/messaging-policies-in-teams",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="17.4",
                title="Establish and Maintain an Incident Response Process",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["teams", "messaging", "security-reporting", "incident-response"],
    )

    async def check(self, data: CollectedData):
        # Get-CsTeamsMessagingPolicy (MicrosoftTeams Remote PowerShell) and
        # Get-ReportSubmissionPolicy (Exchange Online PowerShell) have no
        # Microsoft Graph equivalent, so this collector (which only performs
        # Graph client-credentials auth) cannot read them.
        errors = data.errors or {}
        if "teams_messaging_policy" in errors or "report_submission_policy" in errors:
            return self._skip(
                "Could not retrieve Teams messaging policy or report submission "
                "policy: "
                f"{errors.get('teams_messaging_policy') or errors.get('report_submission_policy')}"
            )

        return self._manual(
            message=(
                "Security concern reporting configuration cannot be read via "
                "Microsoft Graph. Verify manually via Microsoft Teams PowerShell: "
                "Connect-MicrosoftTeams; Get-CsTeamsMessagingPolicy -Identity "
                "Global | fl AllowSecurityEndUserReporting — ensure it is True. "
                "ALSO via Exchange Online PowerShell: Connect-ExchangeOnline; "
                "Get-ReportSubmissionPolicy | fl Report* — ensure "
                "ReportJunkToCustomizedAddress, ReportNotJunkToCustomizedAddress, "
                "and ReportPhishToCustomizedAddress are True, "
                "ReportJunkAddresses/ReportNotJunkAddresses/ReportPhishAddresses "
                "are set to the organization's SOC address, "
                "ReportChatMessageEnabled is False, and "
                "ReportChatMessageToCustomizedAddressEnabled is True."
            )
        )
