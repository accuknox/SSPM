"""
CIS GWS 4.1.1.3 (L1) – Ensure 2-Step Verification (MFA) is enforced for all
users (Manual)

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
class CIS_4_1_1_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.1.1.3",
        title="Ensure 2-Step Verification (MFA) is enforced for all users",
        section="4.1.1 2-Step Verification",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.CRITICAL,
        description=(
            "Enforces 2-Step Verification (2SV) for all users in the "
            "organisation, requiring a second authentication factor in "
            "addition to a password when signing in to Google accounts.  "
            "This is the most impactful control to prevent account takeover."
        ),
        rationale=(
            "Passwords alone are insufficient to protect accounts from "
            "credential stuffing, phishing, and brute-force attacks.  "
            "Enforcing 2SV for all users significantly reduces the likelihood "
            "of account compromise even when a user's password is exposed, "
            "as the attacker would also need access to the second factor."
        ),
        impact=(
            "All users must enrol in 2SV.  Users who have not enrolled will "
            "be blocked from signing in after the enforcement grace period. "
            "Administrators should communicate the change and provide "
            "enrollment instructions ahead of enforcement."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → 2-step verification\n"
            "  3. Verify that 'Allow users to turn on 2-step verification' "
            "is enabled\n"
            "  4. Verify that 'Enforcement' is set to 'On' for all "
            "organisational units"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → 2-step verification\n"
            "  3. Enable 'Allow users to turn on 2-step verification'\n"
            "  4. Set 'Enforcement' to 'On'\n"
            "  5. Set an appropriate grace period for enrollment\n"
            "  6. Click Save"
        ),
        default_value=(
            "2-Step Verification is not enforced by default (non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/9176657",
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
        tags=["mfa", "2sv", "authentication", "all-users"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
