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
        # Neither Get-HostedOutboundSpamFilterPolicy nor Get-TransportRule
        # have a Microsoft Graph equivalent; both are only reachable via
        # Exchange Online Remote PowerShell.
        if "hosted_outbound_spam_filter_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the hosted outbound spam filter policy: "
                f"{data.errors.get('hosted_outbound_spam_filter_policy')}"
            )

        spam_policy = data.get("hosted_outbound_spam_filter_policy")
        if spam_policy is None:
            return self._skip(
                "Mail-forwarding controls require the Exchange Online "
                "PowerShell bridge (Connect-ExchangeOnline with certificate "
                "app-only auth), which is not configured for this scan. Verify "
                "manually: Get-HostedOutboundSpamFilterPolicy | "
                "Select-Object AutoForwardingMode (must be 'Off'), and "
                "Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne "
                "$null -or $_.BlindCopyTo -ne $null} (should return nothing)."
            )

        auto_forwarding_mode = spam_policy.get("AutoForwardingMode")
        evidence = [
            Evidence(
                source="Get-HostedOutboundSpamFilterPolicy",
                data={"AutoForwardingMode": auto_forwarding_mode},
                description="Outbound spam filter policy automatic forwarding mode.",
            )
        ]

        # Transport rules are collected separately; fold them into the same
        # verdict when available, but don't block the primary check on them.
        forwarding_rules = []
        if "transport_rules" not in (data.errors or {}):
            rules = data.get("transport_rules")
            if rules is not None:
                forwarding_rules = [
                    r for r in rules
                    if r.get("RedirectMessageTo") or r.get("BlindCopyTo")
                ]
                evidence.append(
                    Evidence(
                        source="Get-TransportRule",
                        data=forwarding_rules,
                        description="Transport rules that redirect or BCC mail.",
                    )
                )

        problems = []
        if auto_forwarding_mode != "Off":
            problems.append(
                f"AutoForwardingMode is '{auto_forwarding_mode}' (must be 'Off')"
            )
        if forwarding_rules:
            names = ", ".join(r.get("Name", "") for r in forwarding_rules)
            problems.append(
                f"transport rule(s) redirect or BCC mail: {names}"
            )

        if problems:
            return self._fail(
                "Mail forwarding is not fully blocked: " + "; ".join(problems),
                evidence=evidence,
            )

        return self._pass(
            "AutoForwardingMode is 'Off' and no transport rule redirects or "
            "BCCs mail.",
            evidence=evidence,
        )
