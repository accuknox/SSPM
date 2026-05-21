"""
CIS MS365 5.1.8.1 (L1) – Ensure password hash synchronization is enabled for
hybrid environments (Manual)

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
class CIS_5_1_8_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.8.1",
        title="Ensure password hash synchronization is enabled for hybrid environments",
        section="5.1.8 Identity Security",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "For hybrid environments using Microsoft Entra Connect, password hash "
            "synchronization should be enabled. This allows leaked credential "
            "detection and provides a fallback authentication mechanism."
        ),
        rationale=(
            "Password hash synchronization enables Entra ID Protection to detect "
            "leaked credentials by comparing synchronized password hashes against "
            "known compromised password lists. It also provides authentication "
            "resilience if federation services are unavailable."
        ),
        impact=(
            "Enabling password hash sync may require changes to the Entra Connect "
            "configuration and on-premises infrastructure."
        ),
        audit_procedure=(
            "On the Microsoft Entra Connect server:\n"
            "  1. Open Microsoft Entra Connect configuration wizard\n"
            "  2. Check if 'Password hash synchronization' is enabled\n\n"
            "Or via Microsoft Entra Connect Health:\n"
            "  Azure portal → Microsoft Entra Connect Health\n"
            "  Verify Password Hash Sync is shown as active"
        ),
        remediation=(
            "On the Microsoft Entra Connect server:\n"
            "  1. Run the Microsoft Entra Connect configuration wizard\n"
            "  2. Under Optional features, enable 'Password hash synchronization'\n"
            "  3. Complete the wizard and verify sync is working"
        ),
        default_value="Depends on hybrid configuration choices during Entra Connect setup.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.12",
                title="Segment Data Processing and Storage Based on Sensitivity",
                ig1=False,
                ig2=False,
                ig3=True,
            ),
        ],
        tags=["identity", "hybrid", "password-hash-sync", "entra-connect"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
