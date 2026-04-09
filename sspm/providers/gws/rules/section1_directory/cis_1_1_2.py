"""
CIS GWS 1.1.2 (L1) – Ensure that there are no more than four admin accounts
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
class CIS_1_1_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-1.1.2",
        title="Ensure that there are no more than four admin accounts",
        section="1.1 Admin Accounts",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.MEDIUM,
        description=(
            "The number of super administrator accounts should be kept to a minimum "
            "(no more than four) to reduce the attack surface associated with "
            "highly privileged accounts."
        ),
        rationale=(
            "Super administrators have unrestricted access to all Google Workspace "
            "data and settings.  Each additional super admin account is an additional "
            "vector for privilege abuse or account compromise.  Four is a reasonable "
            "upper bound: enough for redundancy without excessive exposure."
        ),
        impact=(
            "Excess super admin accounts must be demoted to less-privileged roles "
            "or removed.  Affected users will lose administrative capabilities."
        ),
        audit_procedure=(
            "Google Workspace Admin Console → Account → Admin roles → Super Admin.\n"
            "Verify the number of users with the Super Admin role does not exceed 4.\n\n"
            "Via Admin SDK Directory API:\n"
            "  GET /admin/directory/v1/users?customer=my_customer&query=isAdmin=True\n"
            "  Count users in the response."
        ),
        remediation=(
            "Google Workspace Admin Console → Account → Admin roles → Super Admin.\n"
            "Remove the Super Admin role from accounts that don't need it.\n"
            "Assign more granular delegated admin roles where full super admin access "
            "is not required."
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
        tags=["identity", "admin", "super-admin", "least-privilege"],
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

        if count <= 4:
            return self._pass(
                f"Found {count} super admin account(s) — within the maximum of 4.",
                evidence=evidence,
            )
        return self._fail(
            f"Found {count} super admin account(s) — exceeds the maximum of 4.",
            evidence=evidence,
        )
