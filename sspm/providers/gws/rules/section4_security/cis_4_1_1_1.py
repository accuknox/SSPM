"""
CIS GWS 4.1.1.1 (L1) – Ensure that 2-Step Verification is enabled for all
users (Automated)

Profile Applicability: Enterprise Level 1
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    Evidence,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_4_1_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.1.1.1",
        title="Ensure that 2-Step Verification is enabled for all users",
        section="4.1.1 Two-Step Verification",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Two-step verification (2SV) should be enabled and enforced for all "
            "users to protect against account compromise through stolen or guessed "
            "passwords."
        ),
        rationale=(
            "Passwords alone provide insufficient protection against credential "
            "attacks such as phishing, credential stuffing, and brute force. "
            "Two-step verification requires a second factor (e.g. Google Authenticator "
            "or a security key), significantly reducing the risk of account takeover "
            "even when a password is compromised."
        ),
        impact=(
            "Users will be required to enrol in and use 2SV.  Organisations should "
            "allow a grace period for users to enrol before enforcing the policy."
        ),
        audit_procedure=(
            "Google Workspace Admin Console → Security → 2-step verification.\n"
            "Verify 'Allow users to turn on 2-Step Verification' is checked and\n"
            "'Enforcement' is set to 'On'.\n\n"
            "Via Admin SDK Directory API:\n"
            "  GET /admin/directory/v1/users?customer=my_customer\n"
            "  Check 'isEnrolledIn2Sv' and 'isEnforcedIn2Sv' for each user."
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Navigate to Security → 2-step verification\n"
            "  2. Under 'Authentication', check 'Allow users to turn on 2-Step "
            "Verification'\n"
            "  3. Set 'Enforcement' to 'On'\n"
            "  4. Set a grace period to allow users to enrol\n"
            "  5. Click Save"
        ),
        default_value="2-Step Verification is off (not enforced) by default.",
        references=[
            "https://support.google.com/a/answer/175197",
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
            CISControl(
                version="v8",
                control_id="6.5",
                title="Require MFA for Administrative Access",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "2sv", "mfa", "authentication"],
    )

    async def check(self, data: CollectedData):
        users = data.get("users")
        if users is None:
            return self._skip(
                "Could not retrieve user list. "
                "Requires admin.directory.user.readonly scope."
            )

        if not users:
            return self._skip("No users found in the directory.")

        active_users = [
            u for u in users
            if not u.get("suspended") and not u.get("archived")
        ]

        if not active_users:
            return self._pass("No active users found — 2SV check not applicable.")

        not_enrolled = [
            u.get("primaryEmail", u.get("id", ""))
            for u in active_users
            if not u.get("isEnrolledIn2Sv")
        ]
        not_enforced = [
            u.get("primaryEmail", u.get("id", ""))
            for u in active_users
            if not u.get("isEnforcedIn2Sv")
        ]

        total = len(active_users)
        enrolled_count = total - len(not_enrolled)
        enforced_count = total - len(not_enforced)

        evidence = [
            Evidence(
                source="admin/directory/v1/users",
                data={
                    "total_active": total,
                    "enrolled_in_2sv": enrolled_count,
                    "enforced_2sv": enforced_count,
                    "not_enrolled": not_enrolled[:20],  # cap at 20 for evidence
                },
                description="2SV enrollment and enforcement status for active users.",
            )
        ]

        if not_enforced:
            sample = not_enforced[:5]
            return self._fail(
                f"{len(not_enforced)} of {total} active user(s) do not have 2SV enforced "
                f"(e.g. {', '.join(sample)}{' ...' if len(not_enforced) > 5 else ''}).",
                evidence=evidence,
            )

        if not_enrolled:
            sample = not_enrolled[:5]
            return self._fail(
                f"{len(not_enrolled)} of {total} active user(s) are not enrolled in 2SV "
                f"(e.g. {', '.join(sample)}{' ...' if len(not_enrolled) > 5 else ''}).",
                evidence=evidence,
            )

        return self._pass(
            f"All {total} active users are enrolled in and have 2SV enforced.",
            evidence=evidence,
        )
