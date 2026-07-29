"""
CIS MS365 2.1.4 (L1) – Ensure Safe Attachments policy is enabled (Automated)

Profile Applicability: E5 Level 1
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
class CIS_2_1_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.4",
        title="Ensure Safe Attachments policy is enabled",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Safe Attachments in Microsoft Defender for Office 365 provides "
            "advanced malware protection for email attachments by opening them "
            "in a virtual sandbox environment before delivery."
        ),
        rationale=(
            "Safe Attachments provides protection against zero-day threats and "
            "unknown malware in email attachments by detonating attachments in a "
            "sandbox before delivering them to recipients."
        ),
        impact=(
            "Email delivery may be delayed slightly while attachments are scanned. "
            "The delay is typically a few minutes but can vary based on file type "
            "and size."
        ),
        audit_procedure=(
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-SafeAttachmentPolicy | ft Identity, Enable, Action, "
            "QuarantineTag\n\n"
            "The highest-priority policy that applies to all users should have "
            "Enable = True, Action = Block, and QuarantineTag = "
            "AdminOnlyAccessPolicy."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Safe Attachments.\n"
            "Create or edit a Safe Attachments policy:\n"
            "  • Enable the policy\n"
            "  • Set action to 'Block'\n"
            "  • Apply to all recipients\n\n"
            "PowerShell:\n"
            "  Set-SafeAttachmentPolicy -Identity Default -Enable $true -Action Block "
            "-QuarantineTag AdminOnlyAccessPolicy"
        ),
        default_value="Safe Attachments is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-about",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-safeattachmentpolicy",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.6",
                title="Block Unnecessary File Types",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "safe-attachments", "email-security", "e5"],
    )

    async def check(self, data: CollectedData):
        if "safe_attachments_policies" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Safe Attachments policies: "
                f"{data.errors.get('safe_attachments_policies')}"
            )

        policies = data.get("safe_attachments_policies")
        if policies is None:
            return self._skip(
                "Safe Attachments policy configuration requires the "
                "Exchange Online PowerShell bridge (Connect-ExchangeOnline "
                "with certificate app-only auth), which is not configured "
                "for this scan. Verify manually: Get-SafeAttachmentPolicy | "
                "ft Identity, Enable, Action, QuarantineTag (the "
                "highest-priority policy should have Enable=True, "
                "Action=Block, QuarantineTag=AdminOnlyAccessPolicy)."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-SafeAttachmentPolicy",
                data=policies,
                description="Safe Attachments policies.",
            )
        ]

        # NOTE: Get-SafeAttachmentPolicy itself doesn't expose rule priority
        # (that lives on Get-SafeAttachmentRule, which is not collected), so
        # we cannot determine which policy is "highest priority" here. We
        # instead check whether ANY policy meets the compliant configuration.
        compliant = [
            p
            for p in policies
            if p.get("Enable") is True
            and p.get("Action") == "Block"
            and p.get("QuarantineTag") == "AdminOnlyAccessPolicy"
        ]
        if compliant:
            names = ", ".join(p.get("Identity", "<unknown>") for p in compliant)
            return self._pass(
                f"Found compliant Safe Attachments policy(ies): {names} "
                "(Enable=True, Action=Block, "
                "QuarantineTag=AdminOnlyAccessPolicy). Rule priority/scope "
                "was not verified (Get-SafeAttachmentRule data is not "
                "collected) — confirm it applies to all recipients.",
                evidence=evidence,
            )

        return self._fail(
            "No Safe Attachments policy has Enable=True, Action=Block, and "
            f"QuarantineTag=AdminOnlyAccessPolicy (checked {len(policies)} "
            "policy(ies)).",
            evidence=evidence,
        )
