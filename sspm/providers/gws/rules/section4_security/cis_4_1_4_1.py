"""
CIS GWS 4.1.4.1 (L2) – Ensure login challenges are enforced (Manual)

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
class CIS_4_1_4_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.1.4.1",
        title="Ensure login challenges are enforced",
        section="4.1.4 Login Challenges",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.HIGH,
        description=(
            "Ensures that Google Workspace enforces additional login "
            "challenges when suspicious sign-in activity is detected, such "
            "as sign-ins from unknown devices or unusual locations.  Login "
            "challenges require users to verify their identity via a "
            "secondary method before access is granted."
        ),
        rationale=(
            "Suspicious login detection and additional challenges provide a "
            "safety net when users' passwords may have been compromised.  "
            "Even if an attacker has valid credentials, login challenges add "
            "friction that can block unauthorised access and alert the "
            "legitimate user to the intrusion attempt."
        ),
        impact=(
            "Users may be occasionally prompted for additional verification "
            "when Google detects unusual sign-in patterns.  This is expected "
            "behaviour and provides an important security safety net."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Login challenges\n"
            "  3. Verify that 'Login challenges' is enabled and that "
            "'Disable login challenges' is NOT selected for any "
            "organisational unit"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Login challenges\n"
            "  3. Ensure 'Login challenges' is enabled\n"
            "  4. Do not disable login challenges for any OU\n"
            "  5. Click Save"
        ),
        default_value=(
            "Login challenges are enabled by default but may be disabled at "
            "the OU level (verify current configuration)."
        ),
        references=[
            "https://support.google.com/a/answer/6002699",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.3",
                title="Require MFA for Externally-Exposed Applications",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["login-challenges", "suspicious-login"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
