"""
CIS MS365 2.1.4 (L1) – Ensure Safe Attachments policy is enabled (Manual)

Profile Applicability: E5 Level 1
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
class CIS_2_1_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.4",
        title="Ensure Safe Attachments policy is enabled",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Using Exchange Online PowerShell:\n"
            "  Get-SafeAttachmentPolicy | Select Name, Enable, Action, "
            "ActionOnError, Redirect, RedirectAddress\n\n"
            "Compliant: Enable = True, Action = Block or DynamicDelivery."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Safe Attachments.\n"
            "Create or edit a Safe Attachments policy:\n"
            "  • Enable the policy\n"
            "  • Set action to 'Block' or 'Dynamic Delivery'\n"
            "  • Apply to all recipients\n\n"
            "PowerShell:\n"
            "  Set-SafeAttachmentPolicy -Identity Default -Enable $true -Action Block"
        ),
        default_value="Safe Attachments is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-about",
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
        return self._manual()
