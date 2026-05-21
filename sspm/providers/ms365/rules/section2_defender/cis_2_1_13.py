"""
CIS MS365 2.1.13 (L1) – Ensure the connection filter safe list is off (Manual)

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
class CIS_2_1_13(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.13",
        title="Ensure the connection filter safe list is off",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "The connection filter safe list allows Microsoft to periodically "
            "update a list of IP addresses considered safe. This should be disabled "
            "as it can bypass spam filtering for IPs that may be compromised."
        ),
        rationale=(
            "The safe list is a shared Microsoft list that can allow IPs used by "
            "spammers to bypass filtering. Disabling it ensures all email goes "
            "through your configured filtering policies."
        ),
        impact=(
            "Disabling the safe list means emails from those IP addresses will "
            "be subject to normal spam filtering."
        ),
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-HostedConnectionFilterPolicy -Identity Default | Select EnableSafeList\n\n"
            "Compliant: EnableSafeList = False."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-HostedConnectionFilterPolicy -Identity Default -EnableSafeList $false"
        ),
        default_value="EnableSafeList is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/connection-filter-policies-configure",
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
        tags=["defender", "connection-filter", "email-security", "anti-spam"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
