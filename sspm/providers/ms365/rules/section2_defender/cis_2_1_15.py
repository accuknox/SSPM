"""
CIS MS365 2.1.15 (L1) – Ensure that an outbound anti-spam policy restricts
forwarding (Manual)

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
class CIS_2_1_15(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.15",
        title="Ensure that an outbound anti-spam policy restricts automatic forwarding",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The outbound spam filter policy should restrict or block automatic "
            "email forwarding to external domains. Automatic forwarding can be "
            "used by attackers to exfiltrate data from compromised accounts."
        ),
        rationale=(
            "Attackers who compromise email accounts often set up auto-forwarding "
            "rules to exfiltrate email to external addresses. Blocking automatic "
            "forwarding prevents data exfiltration through this vector."
        ),
        impact=(
            "Legitimate auto-forwarding rules configured by users will be blocked. "
            "Organizations must evaluate and approve any necessary forwarding rules."
        ),
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-HostedOutboundSpamFilterPolicy | Select Name, AutoForwardingMode\n\n"
            "Compliant: AutoForwardingMode = Off or Automatic (which disables "
            "auto-forwarding when Microsoft detects abuse).\n"
            "Non-compliant: AutoForwardingMode = On."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-HostedOutboundSpamFilterPolicy -Identity Default "
            "-AutoForwardingMode Off\n\n"
            "Or in Microsoft Defender portal:\n"
            "  Email & Collaboration > Policies & Rules > Threat policies > "
            "Anti-spam > Outbound spam filter > Edit > Automatic forwarding rules"
        ),
        default_value="AutoForwardingMode = Automatic by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-configure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.2",
                title="Establish and Maintain a Data Inventory",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "anti-spam", "outbound", "forwarding", "data-exfiltration"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
