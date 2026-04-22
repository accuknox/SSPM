"""
CIS GWS 4.1.5.1 (L1) – Ensure password policy is configured for enhanced
security (Manual)

Profile Applicability: Enterprise Level 1
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
class CIS_4_1_5_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.1.5.1",
        title="Ensure password policy is configured for enhanced security",
        section="4.1.5 Password Management",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures the Google Workspace password policy to enforce a "
            "minimum length of at least 12 characters, enable password "
            "strength enforcement, and optionally enforce periodic password "
            "reuse restrictions.  Strong password policies reduce the "
            "effectiveness of brute-force and credential-stuffing attacks."
        ),
        rationale=(
            "Weak or reused passwords are a leading cause of account "
            "compromise.  A strong password policy that enforces minimum "
            "length and complexity requirements, combined with 2SV, "
            "significantly reduces the risk of successful credential attacks.  "
            "NIST SP 800-63B recommends a minimum of 8 characters; CIS "
            "recommends at least 12."
        ),
        impact=(
            "Users with passwords shorter than the minimum length will be "
            "required to change their password at the next sign-in.  "
            "Administrators should communicate the change and provide guidance "
            "on creating strong passwords."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Password management\n"
            "  3. Verify that 'Minimum length' is set to at least 12 "
            "characters\n"
            "  4. Verify that 'Enforce strong password' is enabled\n"
            "  5. Verify that password reuse is restricted"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Password management\n"
            "  3. Set 'Minimum length' to at least 12 characters\n"
            "  4. Enable 'Enforce strong password'\n"
            "  5. Enable password reuse restriction\n"
            "  6. Click Save"
        ),
        default_value=(
            "Default minimum password length is 8 characters with strength "
            "enforcement disabled (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/139399",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.2",
                title="Use Unique Passwords",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["password", "policy", "complexity"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
