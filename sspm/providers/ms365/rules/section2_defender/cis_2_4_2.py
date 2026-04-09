"""
CIS MS365 2.4.2 (L2) – Ensure Priority accounts have 'Strict protection'
preset security policy (Manual)

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
        title="Ensure Priority accounts have 'Strict protection' preset security policy",
        section="2.4 Microsoft Defender",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Microsoft Defender portal (https://security.microsoft.com):\n"
            "  Email & Collaboration > Policies & Rules > Threat policies > "
            "Preset security policies\n"
            "  Verify Strict protection is applied to priority accounts."
        ),
        remediation=(
            "Microsoft Defender portal:\n"
            "  Email & Collaboration > Policies & Rules > Threat policies > "
            "Preset security policies\n"
            "  1. Click on Strict protection\n"
            "  2. Add priority accounts to the policy recipients\n"
            "  3. Save the configuration"
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
        return self._manual(
            "Verify Strict protection for priority accounts in Microsoft Defender portal:\n"
            "  1. Go to https://security.microsoft.com\n"
            "  2. Navigate to Email & Collaboration > Policies & Rules > "
            "Threat policies > Preset security policies\n"
            "  3. Verify priority accounts are included in the Strict protection policy"
        )
