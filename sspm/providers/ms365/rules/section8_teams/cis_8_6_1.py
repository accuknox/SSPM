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
    Evidence,
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

        messaging_policy = data.get("teams_messaging_policy")
        report_policies = data.get("report_submission_policy")

        if messaging_policy is None and report_policies is None:
            return self._manual(
                message=(
                    "Security concern reporting requires BOTH the Microsoft "
                    "Teams PowerShell bridge (Connect-MicrosoftTeams) and the "
                    "Exchange Online PowerShell bridge (Connect-ExchangeOnline), "
                    "neither of which is configured for this scan. Verify "
                    "manually: Get-CsTeamsMessagingPolicy -Identity Global | fl "
                    "AllowSecurityEndUserReporting — ensure it is True. ALSO: "
                    "Get-ReportSubmissionPolicy | fl Report* — ensure "
                    "ReportJunkToCustomizedAddress, "
                    "ReportNotJunkToCustomizedAddress, and "
                    "ReportPhishToCustomizedAddress are True, "
                    "ReportJunkAddresses/ReportNotJunkAddresses/"
                    "ReportPhishAddresses are set to the organization's SOC "
                    "address, ReportChatMessageEnabled is False, and "
                    "ReportChatMessageToCustomizedAddressEnabled is True."
                )
            )

        if messaging_policy is None or report_policies is None:
            missing_bridge = (
                "Microsoft Teams (Connect-MicrosoftTeams)"
                if messaging_policy is None
                else "Exchange Online (Connect-ExchangeOnline)"
            )
            return self._manual(
                message=(
                    f"Only partial data is available — the {missing_bridge} "
                    "PowerShell bridge is not configured for this scan — so this "
                    "control cannot be fully evaluated. Verify manually: "
                    "Get-CsTeamsMessagingPolicy -Identity Global | fl "
                    "AllowSecurityEndUserReporting (must be True), and "
                    "Get-ReportSubmissionPolicy | fl Report* (see this rule's "
                    "audit_procedure for the required values)."
                )
            )

        reasons: list[str] = []

        if messaging_policy.get("AllowSecurityEndUserReporting") is not True:
            reasons.append(
                "AllowSecurityEndUserReporting is not True on the Teams "
                "messaging policy"
            )

        # Get-ReportSubmissionPolicy is a tenant-wide singleton (the built-in
        # "DefaultReportSubmissionPolicy") — exchange.ps1 wraps it in @(...)
        # only to stop ConvertTo-Json from unwrapping a single-element array,
        # not because there can be multiple independent policies to choose
        # from. It's therefore correct to evaluate the one (first) entry
        # directly rather than applying "at least one of many" semantics.
        if not report_policies:
            reasons.append(
                "no report submission policy was returned by "
                "Get-ReportSubmissionPolicy"
            )
        else:
            policy = report_policies[0]
            required_bools = {
                "ReportJunkToCustomizedAddress": True,
                "ReportNotJunkToCustomizedAddress": True,
                "ReportPhishToCustomizedAddress": True,
                "ReportChatMessageEnabled": False,
                "ReportChatMessageToCustomizedAddressEnabled": True,
            }
            for prop, expected in required_bools.items():
                if policy.get(prop) is not expected:
                    reasons.append(f"{prop} is not {expected}")
            for prop in (
                "ReportJunkAddresses",
                "ReportNotJunkAddresses",
                "ReportPhishAddresses",
            ):
                if not policy.get(prop):
                    reasons.append(
                        f"{prop} is not set to the organization's SOC address"
                    )

        evidence = [
            Evidence(
                source=(
                    "teams/Get-CsTeamsMessagingPolicy + "
                    "exchange/Get-ReportSubmissionPolicy"
                ),
                data={
                    "teams_messaging_policy": messaging_policy,
                    "report_submission_policy": report_policies,
                },
                description=(
                    "Teams security end-user reporting and report submission "
                    "policy settings."
                ),
            )
        ]

        if reasons:
            return self._fail(
                "Users cannot fully report security concerns in Teams: "
                + "; ".join(reasons)
                + ".",
                evidence=evidence,
            )

        return self._pass(
            "Security concern reporting is enabled in Teams "
            "(AllowSecurityEndUserReporting=True) and the report submission "
            "policy is correctly configured to route reports to the "
            "organization's SOC address.",
            evidence=evidence,
        )
