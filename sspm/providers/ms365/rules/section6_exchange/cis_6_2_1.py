"""
CIS MS365 6.2.1 (L1) – Ensure all forms of mail forwarding are blocked and/or
disabled (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Automatic email forwarding to external domains is a common data exfiltration
technique.  A transport rule should block all external forwarding.
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
class CIS_6_2_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.2.1",
        title="Ensure all forms of mail forwarding are blocked and/or disabled",
        section="6.2 Mail flow",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Automatic email forwarding to external addresses is a well-known data "
            "exfiltration technique, frequently used by attackers who have compromised "
            "a mailbox.  Blocking auto-forwarding via transport rules prevents sensitive "
            "data from leaving the organisation silently."
        ),
        rationale=(
            "Compromised accounts configured to silently forward mail to an attacker-"
            "controlled address can exfiltrate sensitive data for extended periods "
            "without detection.  Blocking external forwarding reduces this risk."
        ),
        impact=(
            "Legitimate use-cases such as personal forwarding rules will be blocked. "
            "Users who require external forwarding for business purposes will need an "
            "approved exception documented in the transport rule."
        ),
        audit_procedure=(
            "Exchange Online PowerShell:\n"
            "  Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null -or "
            "$_.BlindCopyTo -ne $null}\n"
            "  Or check outbound spam policy:\n"
            "  Get-HostedOutboundSpamFilterPolicy | "
            "Select-Object AutoForwardingMode\n"
            "  AutoForwardingMode should be 'Off'.\n\n"
            "Via admin portal:\n"
            "  Exchange admin center → Mail flow > Rules.\n"
            "  Verify a rule exists that blocks forwarding to external recipients.\n"
            "  Also check: Exchange admin center → Policies > Anti-spam > "
            "Outbound policy > Automatic forwarding rules = Off."
        ),
        remediation=(
            "Option 1 – Outbound anti-spam policy (recommended):\n"
            "  Exchange admin center → Policies > Anti-spam > Outbound policy.\n"
            "  Set 'Automatic forwarding rules' to 'Off - Forwarding is disabled'.\n\n"
            "Option 2 – Transport rule:\n"
            "  Create a transport rule that rejects messages where:\n"
            "  • The message was auto-forwarded (message type is auto-forward).\n"
            "  • The recipient is outside the organisation."
        ),
        default_value="AutoForwardingMode is 'Automatic' (allows forwarding) by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-configure",
            "https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="0.0",
                title="Data Protection",
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["email", "mail-forwarding", "data-exfiltration", "exchange"],
    )

    async def check(self, data: CollectedData):
        # Transport rules have no Graph API equivalent.  If collection errored,
        # surface the error; otherwise always return MANUAL.
        if "transport_rules" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange transport rules: "
                f"{data.errors.get('transport_rules')}"
            )

        # data.get("transport_rules") returns None because the collector
        # deliberately returns None for this key (no Graph endpoint exists).
        return self._manual(
            message="Exchange transport rules cannot be read via Microsoft Graph."
        )
