"""
CIS MS365 2.4.4 (L2) – Ensure Zero-hour auto purge for Microsoft Teams is on
(Automated)

Profile Applicability: E5 Level 2
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
class CIS_2_4_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.4.4",
        title="Ensure Zero-hour auto purge for Microsoft Teams is on",
        section="2.4 Microsoft Defender",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Zero-hour auto purge (ZAP) for Teams automatically removes malicious "
            "messages from Teams conversations after delivery, similar to how "
            "email ZAP works for Exchange Online."
        ),
        rationale=(
            "Malicious URLs and files can be shared in Teams messages. ZAP for Teams "
            "ensures that messages identified as malicious after delivery are "
            "automatically removed, reducing the window of exposure."
        ),
        impact=(
            "Messages identified as malicious will be automatically removed from "
            "Teams conversations, which may cause confusion if users saw the "
            "message before it was removed."
        ),
        audit_procedure=(
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-TeamsProtectionPolicy | fl ZapEnabled\n"
            "Run: Get-TeamsProtectionPolicyRule | fl ExceptIf*\n\n"
            "Ensure ZapEnabled is True and review any exclusions configured on "
            "the rule (ExceptIf* conditions)."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Zero-hour auto purge, enable ZAP for Microsoft Teams.\n\n"
            "Or via Exchange Online PowerShell:\n"
            "  Set-TeamsProtectionPolicy -Identity Default -ZapEnabled $true"
        ),
        default_value="ZAP for Teams is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/zero-hour-auto-purge",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-teamsprotectionpolicy",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.3",
                title="Maintain and Enforce Network-Based URL Filters",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "zap", "teams", "e5"],
    )

    async def check(self, data: CollectedData):
        if "teams_protection_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the Teams protection policy: "
                f"{data.errors.get('teams_protection_policy')}"
            )

        policies = data.get("teams_protection_policy")
        if policies is None:
            return self._manual(
                "Zero-hour auto purge for Microsoft Teams requires the "
                "Exchange Online PowerShell bridge (Connect-ExchangeOnline "
                "with certificate app-only auth), which is not configured "
                "for this scan. Verify manually: Get-TeamsProtectionPolicy "
                "| fl ZapEnabled (should be True) and "
                "Get-TeamsProtectionPolicyRule | fl ExceptIf* (review any "
                "exclusions)."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-TeamsProtectionPolicy",
                data=policies,
                description="Teams protection policies.",
            )
        ]

        compliant = [p for p in policies if p.get("ZapEnabled") is True]
        if compliant:
            names = ", ".join(p.get("Identity", "<unknown>") for p in compliant)
            return self._pass(
                f"Zero-hour auto purge for Teams is enabled on: {names}. "
                "Rule-level exclusions (Get-TeamsProtectionPolicyRule "
                "ExceptIf*) were not verified — this data is not collected.",
                evidence=evidence,
            )

        return self._fail(
            "Zero-hour auto purge for Teams (ZapEnabled) is not enabled on "
            f"any of the {len(policies)} Teams protection policy(ies).",
            evidence=evidence,
        )
