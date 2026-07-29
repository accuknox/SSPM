"""
CIS MS365 2.1.12 (L1) – Ensure the connection filter IP allow list is not used
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
class CIS_2_1_12(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.12",
        title="Ensure the connection filter IP allow list is not used",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "The connection filter IP allow list allows emails from specified IP "
            "addresses to bypass spam filtering. This should not be used as it "
            "can allow spam and malware from those IP addresses."
        ),
        rationale=(
            "IP addresses in the connection filter allow list bypass spam and "
            "malware filtering. This creates a potential attack vector if any of "
            "those IP addresses become compromised or are used by attackers."
        ),
        impact=(
            "Removing IP addresses from the allow list means their emails will "
            "be subject to normal spam and malware filtering."
        ),
        audit_procedure=(
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-HostedConnectionFilterPolicy -Identity Default | "
            "fl IPAllowList\n\n"
            "Ensure IPAllowList is empty."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-HostedConnectionFilterPolicy -Identity Default -IPAllowList @()\n\n"
            "If specific IPs need to be trusted, use the Enhanced Filtering for "
            "Connectors feature instead."
        ),
        default_value="IP allow list is empty by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/connection-filter-policies-configure",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-hostedconnectionfilterpolicy",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.5",
                title="Implement DMARC",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "connection-filter", "email-security", "anti-spam"],
    )

    async def check(self, data: CollectedData):
        if "hosted_connection_filter_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the hosted connection filter policy: "
                f"{data.errors.get('hosted_connection_filter_policy')}"
            )

        policy = data.get("hosted_connection_filter_policy")
        if policy is None:
            return self._skip(
                "The connection filter IP allow list requires the Exchange "
                "Online PowerShell bridge (Connect-ExchangeOnline with "
                "certificate app-only auth), which is not configured for "
                "this scan. Verify manually: "
                "Get-HostedConnectionFilterPolicy -Identity Default | fl "
                "IPAllowList (should be empty)."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-HostedConnectionFilterPolicy",
                data={"IPAllowList": policy.get("IPAllowList")},
                description="Hosted connection filter policy (Default).",
            )
        ]

        ip_allow_list = policy.get("IPAllowList") or []
        if not ip_allow_list:
            return self._pass(
                "The connection filter IP allow list is empty.",
                evidence=evidence,
            )

        return self._fail(
            f"The connection filter IP allow list is not empty: {ip_allow_list}.",
            evidence=evidence,
        )
