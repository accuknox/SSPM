"""
CIS MS365 5.2.3.4 (L1) – Ensure all member users are MFA capable (Automated)

Profile Applicability: E3 Level 1, E5 Level 1
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
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_5_2_3_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.3.4",
        title="Ensure all member users are MFA capable",
        section="5.2.3 Authentication Methods",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "All member (non-guest) users should have at least one MFA method "
            "registered to be MFA capable. Users without MFA registered cannot "
            "comply with MFA enforcement policies."
        ),
        rationale=(
            "MFA enforcement policies only protect users who have registered MFA "
            "methods. Users without registered MFA methods are at risk if their "
            "passwords are compromised."
        ),
        impact=(
            "Users without MFA registered may be blocked from accessing resources "
            "when MFA enforcement policies take effect."
        ),
        audit_procedure=(
            "GET /reports/authenticationMethods/userRegistrationDetails\n"
            "  Filter by userType = 'member'\n"
            "  Check isMfaCapable = true for all member users"
        ),
        remediation=(
            "1. Identify users who are not MFA capable using the report\n"
            "2. Contact those users and require MFA registration\n"
            "3. Run an MFA registration campaign\n"
            "4. Use the Entra ID MFA Registration Campaign feature:\n"
            "   Microsoft Entra admin center → Protection > Authentication methods > "
            "Registration campaign"
        ),
        default_value="No MFA registered for new users by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.3",
                title="Require MFA for Externally-Exposed Applications",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "mfa", "registration", "user-capability"],
    )

    async def check(self, data: CollectedData):
        mfa_registrations = data.get("user_mfa_registration")
        if mfa_registrations is None:
            return self._skip(
                "Could not retrieve MFA registration data. "
                "Requires Reports.Read.All permission."
            )

        if not mfa_registrations:
            return self._skip("No MFA registration data found.")

        # Filter to member users only
        member_users = [
            u for u in mfa_registrations
            if u.get("userType", "").lower() == "member"
        ]

        if not member_users:
            return self._skip("No member users found in registration report.")

        mfa_incapable = [
            u for u in member_users
            if not u.get("isMfaCapable", False)
        ]

        total_members = len(member_users)
        incapable_count = len(mfa_incapable)

        evidence = [
            Evidence(
                source="graph/reports/authenticationMethods/userRegistrationDetails",
                data={
                    "totalMemberUsers": total_members,
                    "mfaCapableCount": total_members - incapable_count,
                    "notMfaCapableCount": incapable_count,
                },
                description="MFA capability report for member users.",
            )
        ]

        if incapable_count == 0:
            return self._pass(
                f"All {total_members} member users are MFA capable.",
                evidence=evidence,
            )

        sample_users = [
            u.get("userPrincipalName", u.get("id"))
            for u in mfa_incapable[:10]
        ]
        return self._fail(
            f"{incapable_count} of {total_members} member users are not MFA capable. "
            f"Examples: {', '.join(sample_users)}{'...' if incapable_count > 10 else ''}",
            evidence=evidence,
        )
