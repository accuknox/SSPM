"""
CIS MS365 2.4.4 (L2) – Ensure Zero-hour auto purge for Microsoft Teams is
enabled (Manual)

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
class CIS_2_4_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.4.4",
        title="Ensure Zero-hour auto purge for Microsoft Teams is enabled",
        section="2.4 Microsoft Defender",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
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
            "Microsoft Defender portal (https://security.microsoft.com):\n"
            "  Email & Collaboration > Policies & Rules > Threat policies > "
            "Zero-hour auto purge\n"
            "  Verify ZAP for Teams is enabled."
        ),
        remediation=(
            "Microsoft Defender portal:\n"
            "  Email & Collaboration > Policies & Rules > Threat policies > "
            "Zero-hour auto purge\n"
            "  Enable ZAP for Microsoft Teams."
        ),
        default_value="ZAP for Teams is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/zero-hour-auto-purge",
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
        return self._manual()
