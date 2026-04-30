"""
CIS GWS 4.1.3.1 (L2) – Ensure Advanced Protection Program is configured
(Manual)

Profile Applicability: Enterprise Level 2
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
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_4_1_3_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.1.3.1",
        title="Ensure Advanced Protection Program is configured",
        section="4.1.3 Advanced Protection Program",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.HIGH,
        description=(
            "Enables and configures Google's Advanced Protection Program "
            "for high-value accounts (executives, IT administrators, finance "
            "staff) that are at elevated risk of targeted attacks.  The "
            "program enforces hardware security keys, blocks unverified app "
            "access, and adds enhanced Gmail scanning."
        ),
        rationale=(
            "High-value accounts are prime targets for sophisticated, "
            "targeted attacks such as spear-phishing.  The Advanced "
            "Protection Program provides the strongest available account "
            "security controls, including mandatory hardware security keys "
            "that are phishing-resistant.  Standard 2SV methods (SMS, "
            "authenticator apps) can be defeated by real-time phishing "
            "proxies."
        ),
        impact=(
            "Users enrolled in Advanced Protection must use hardware security "
            "keys for authentication.  Some less-secure legacy app access "
            "will be blocked.  This may require hardware token procurement "
            "and user training."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Advanced Protection "
            "Program\n"
            "  3. Verify that the Advanced Protection Program is enabled and "
            "that high-value accounts (Super Admins, privileged users) are "
            "enrolled or required to enrol"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Advanced Protection "
            "Program\n"
            "  3. Enable the Advanced Protection Program\n"
            "  4. Identify and enrol high-value account holders\n"
            "  5. Distribute hardware security keys to enrolled users\n"
            "  6. Click Save"
        ),
        default_value=(
            "The Advanced Protection Program is not enabled by default "
            "(non-compliant for EL2)."
        ),
        references=[
            "https://support.google.com/a/answer/9378686",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.5",
                title="Require MFA for Administrative Access",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["advanced-protection", "high-value-accounts"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
