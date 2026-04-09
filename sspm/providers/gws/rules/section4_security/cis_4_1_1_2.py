"""
CIS GWS 4.1.1.2 (L1) – Ensure that 2-Step Verification is enforced for
admin accounts (Automated)

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
class CIS_4_1_1_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.1.1.2",
        title="Ensure that 2-Step Verification is enforced for admin accounts",
        section="4.1.1 Two-Step Verification",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.CRITICAL,
        description=(
            "Two-step verification should be enforced for all administrator accounts "
            "as a priority, as these accounts have elevated privileges and are high-value "
            "targets for attackers."
        ),
        rationale=(
            "Administrator accounts have full access to all Google Workspace data "
            "and settings.  A compromised admin account can result in complete "
            "domain takeover.  Enforcing 2SV for admins is a critical baseline "
            "security control."
        ),
        impact=(
            "Administrators will be required to use 2SV for every login.  "
            "Security keys (hardware tokens) are recommended for admin accounts."
        ),
        audit_procedure=(
            "Via Admin SDK Directory API:\n"
            "  GET /admin/directory/v1/users?customer=my_customer&query=isAdmin=True\n"
            "  Verify 'isEnrolledIn2Sv' = true and 'isEnforcedIn2Sv' = true for "
            "all admin accounts."
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Navigate to Security → 2-step verification\n"
            "  2. Ensure 2SV enforcement is enabled for the Super Admin OU\n"
            "  3. Individually verify each admin account is enrolled\n\n"
            "For any admin not enrolled:\n"
            "  Admin Console → Directory → Users → [user] → Security → 2-step verification"
        ),
        default_value="2-Step Verification is not enforced for admins by default.",
        references=[
            "https://support.google.com/a/answer/175197",
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
        tags=["identity", "2sv", "mfa", "admin", "privileged-access"],
    )

    async def check(self, data: CollectedData):
        super_admins = data.get("super_admins")
        # Fall back to filtering from all users if super_admins key absent
        if super_admins is None:
            users = data.get("users")
            if users is None:
                return self._skip(
                    "Could not retrieve admin user list. "
                    "Requires admin.directory.user.readonly scope."
                )
            super_admins = [u for u in users if u.get("isAdmin")]

        if not super_admins:
            return self._skip("No super admin accounts found.")

        not_enrolled = [
            u.get("primaryEmail", u.get("id", ""))
            for u in super_admins
            if not u.get("isEnrolledIn2Sv")
        ]
        not_enforced = [
            u.get("primaryEmail", u.get("id", ""))
            for u in super_admins
            if not u.get("isEnforcedIn2Sv")
        ]

        total = len(super_admins)
        evidence = [
            Evidence(
                source="admin/directory/v1/users?query=isAdmin=True",
                data={
                    "total_admins": total,
                    "not_enrolled_in_2sv": not_enrolled,
                    "not_enforced_2sv": not_enforced,
                },
                description="2SV status for super administrator accounts.",
            )
        ]

        if not_enrolled or not_enforced:
            failing = list(set(not_enrolled) | set(not_enforced))
            return self._fail(
                f"{len(failing)} of {total} super admin account(s) do not have "
                f"2SV enrolled/enforced: {', '.join(failing)}.",
                evidence=evidence,
            )

        return self._pass(
            f"All {total} super admin account(s) have 2SV enrolled and enforced.",
            evidence=evidence,
        )
