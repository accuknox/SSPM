"""
CIS MS365 2.4.2 (L2) – Ensure Priority accounts have 'Strict protection'
presets applied (Automated)

Profile Applicability: E5 Level 2
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
class CIS_2_4_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.4.2",
        title="Ensure Priority accounts have 'Strict protection' presets applied",
        section="2.4 Microsoft Defender",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Priority accounts should be assigned the 'Strict protection' preset "
            "security policy in Microsoft Defender for Office 365, which applies "
            "the most aggressive email security settings."
        ),
        rationale=(
            "The Strict protection preset applies the most aggressive anti-spam, "
            "anti-malware, anti-phishing, Safe Links, and Safe Attachments settings, "
            "providing the highest level of email security for high-value accounts."
        ),
        impact=(
            "Strict protection settings may cause more false positives and quarantine "
            "more legitimate emails. Priority account users should be prepared for "
            "occasional false positives."
        ),
        audit_procedure=(
            "Microsoft 365 Defender portal (https://security.microsoft.com):\n"
            "  Email & Collaboration > Policies & Rules > Threat policies.\n"
            "  For each of: Anti-phishing, Anti-spam, Anti-malware, Safe "
            "Attachments, and Safe Links, open the policy and confirm a "
            "'Strict Preset Security Policy' exists whose recipient conditions "
            "include the priority accounts/groups.\n\n"
            "Note: CIS publishes no PowerShell or Microsoft Graph audit method "
            "for this control; it is Defender portal (UI) only."
        ),
        remediation=(
            "Microsoft 365 Defender portal → Email & Collaboration > Policies & "
            "Rules > Threat policies > Preset security policies:\n"
            "  1. Edit the Strict protection preset.\n"
            "  2. Add the priority accounts/groups to the policy recipients for "
            "each of Anti-phishing, Anti-spam, Anti-malware, Safe Attachments, "
            "and Safe Links.\n"
            "  3. Save the configuration."
        ),
        default_value="Priority accounts do not have Strict protection by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies",
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
        tags=["defender", "priority-accounts", "strict-protection", "e5"],
    )

    async def check(self, data: CollectedData):
        if "preset_security_policies" in (data.errors or {}):
            return self._skip(
                "Could not retrieve preset security policies: "
                f"{data.errors.get('preset_security_policies')}"
            )

        # CIS labels this control Automated but publishes a UI-only audit
        # procedure for it — there is no Microsoft Graph API or PowerShell
        # cmdlet to read preset security policy assignment, so there is
        # nothing to evaluate rather than a control CIS expects a human to
        # judge.
        return self._skip(
            "Strict Preset Security Policy assignment for priority accounts "
            "has no Microsoft Graph API or PowerShell cmdlet published by CIS, "
            "so it cannot be collected. Verify in the Microsoft 365 Defender "
            "portal: Email & Collaboration > Policies & Rules > Threat "
            "policies > Preset security policies, confirming each of "
            "Anti-phishing, Anti-spam, Anti-malware, Safe Attachments, and "
            "Safe Links includes the priority accounts/groups under the Strict "
            "preset."
        )
