"""
CIS GWS 1.1.1 (L1) – Ensure that there are at least two admin accounts
(Automated)

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
class CIS_1_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-1.1.1",
        title="Ensure that there are at least two admin accounts",
        section="1.1 Admin Accounts",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "There should be at least two super administrator accounts configured "
            "in the Google Workspace domain to ensure administrative access is "
            "not lost if one account becomes unavailable."
        ),
        rationale=(
            "Relying on a single super admin account creates a single point of "
            "failure.  If that account is locked, compromised, or the owner leaves "
            "the organisation, administrative access to the domain may be lost."
        ),
        impact=(
            "No impact on existing users.  Additional admin accounts must be "
            "managed and secured appropriately, including enforcing 2SV."
        ),
        audit_procedure=(
            "Google Workspace Admin Console → Account → Admin roles.\n"
            "  Count users with the Super Admin role.\n\n"
            "Via Admin SDK Directory API:\n"
            "  GET /admin/directory/v1/users?customer=my_customer&query=isAdmin=True\n"
            "  Count users in the response."
        ),
        remediation=(
            "Google Workspace Admin Console → Account → Admin roles → Super Admin.\n"
            "Assign the Super Admin role to at least one additional user."
        ),
        default_value="One super admin account is configured during domain setup.",
        references=[
            "https://support.google.com/a/answer/33325",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.4",
                title="Restrict Administrator Privileges to Dedicated Administrator Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "admin", "super-admin"],
    )

    async def check(self, data: CollectedData):
        super_admins = data.get("super_admins")
        if super_admins is None:
            return self._skip(
                "Could not retrieve super admin list. "
                "Requires admin.directory.user.readonly scope."
            )

        count = len(super_admins)
        evidence = [
            Evidence(
                source="admin/directory/v1/users?query=isAdmin=True",
                data={"super_admin_count": count,
                      "super_admins": [u.get("primaryEmail") for u in super_admins]},
                description="Super administrator accounts in the domain.",
            )
        ]

        if count >= 2:
            return self._pass(
                f"Found {count} super admin account(s) — at least 2 are required.",
                evidence=evidence,
            )
        return self._fail(
            f"Only {count} super admin account(s) found. At least 2 are required.",
            evidence=evidence,
        )
