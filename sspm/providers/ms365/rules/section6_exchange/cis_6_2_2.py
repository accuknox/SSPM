"""
CIS MS365 6.2.2 (L1) – Ensure mail transport rules do not whitelist specific
domains (Automated)

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
class CIS_6_2_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.2.2",
        title="Ensure mail transport rules do not whitelist specific domains",
        section="6.2 Mail flow",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Mail transport rules should not be configured to whitelist entire "
            "domains from spam and malware filtering. Domain whitelisting bypasses "
            "security controls and can allow malicious emails to reach users."
        ),
        rationale=(
            "Domain whitelist transport rules bypass all spam and malware filters "
            "for that domain. If a whitelisted domain is compromised, or the rule "
            "uses an attacker-controlled domain, malicious emails can reach users."
        ),
        impact="Removing domain whitelist rules means email from those domains will be filtered.",
        audit_procedure=(
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-TransportRule | Where-Object { $_.setscl -eq -1 -and "
            "$_.SenderDomainIs -ne $null } | ft Name,SenderDomainIs,SetSCL\n\n"
            "Compliant: no rule sets SCL to -1 (bypass spam filtering) for a "
            "specific sender domain; no output is returned."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Get-TransportRule | Where-Object {$_.SetSCL -eq -1} | Remove-TransportRule\n\n"
            "Review and remove transport rules that bypass spam/malware filtering."
        ),
        default_value="No domain whitelist transport rules exist by default.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules",
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
        tags=["exchange", "transport-rules", "whitelist", "email-security"],
    )

    async def check(self, data: CollectedData):
        # Transport rules have no Graph API equivalent.  If collection
        # errored, surface the error; otherwise always return MANUAL.
        if "transport_rules" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange transport rules: "
                f"{data.errors.get('transport_rules')}"
            )

        # data.get("transport_rules") returns None because the collector
        # deliberately returns None for this key (no Graph endpoint exists).
        return self._manual(
            message=(
                "Exchange transport rules cannot be read via Microsoft Graph. "
                "Verify manually via Exchange Online PowerShell: "
                "Get-TransportRule | Where-Object { $_.setscl -eq -1 -and "
                "$_.SenderDomainIs -ne $null } - any rule returned indicates a "
                "domain-whitelisting rule that bypasses spam filtering."
            )
        )
