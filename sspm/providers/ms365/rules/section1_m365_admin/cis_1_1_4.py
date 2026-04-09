"""
CIS MS365 1.1.4 (L1) – Ensure administrative accounts use reduced-footprint
licenses (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Privileged administrative accounts should not have productivity suite licenses
(E3/E5 etc.) that expose unnecessary attack surface via email clients, Office
apps, and collaboration services.
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

# Microsoft 365 / Office 365 SKU part-numbers that include full productivity suites
# (non-exhaustive; covers the most common E3/E5 and A-series SKUs)
_HIGH_FOOTPRINT_SKUS = {
    "SPE_E3",          # Microsoft 365 E3
    "SPE_E5",          # Microsoft 365 E5
    "ENTERPRISEPACK",  # Office 365 E3
    "ENTERPRISEPREMIUM",  # Office 365 E5
    "M365EDU_A3_FACULTY",
    "M365EDU_A5_FACULTY",
    "M365EDU_A3_STUDENT",
    "M365EDU_A5_STUDENT",
    "STANDARDPACK",    # Office 365 E1
    "ENTERPRISEWITHSCAL",  # Office 365 E4
    "BUSINESS_PREMIUM",  # Microsoft 365 Business Premium
    "SPB",             # Microsoft 365 Business Premium (alt SKU)
}


@registry.rule
class CIS_1_1_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.1.4",
        title="Ensure administrative accounts use reduced-footprint licenses",
        section="1.1 Users",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Administrative accounts should use reduced-footprint licenses such as "
            "Microsoft Entra ID P1 or P2 only. Full productivity suite licenses "
            "(E3/E5) include email, Office apps, and Teams which increase the "
            "attack surface of high-privileged accounts."
        ),
        rationale=(
            "Dedicated admin accounts that only have identity/governance licenses "
            "cannot receive phishing emails (no mailbox), cannot be used to open "
            "malicious attachments (no Office apps), and generally have a smaller "
            "attack surface than accounts with full E3/E5 licenses."
        ),
        impact=(
            "Administrative accounts will not have Exchange mailboxes, Office apps, "
            "or Teams. Admins will need a separate day-to-day account for "
            "productivity tasks."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "1. Get all privileged role members.\n"
            "2. For each privileged user, check assignedLicenses.\n"
            "3. The account is non-compliant if any assigned SKU part number "
            "is in the high-footprint set (E3, E5, Business Premium, etc.).\n"
            "Compliant accounts should have no licenses OR only Entra ID P1/P2."
        ),
        remediation=(
            "1. Create dedicated cloud-only admin accounts without productivity licenses.\n"
            "2. Assign only Microsoft Entra ID P1 or P2 licenses to admin accounts.\n"
            "3. Remove full E3/E5 licenses from dedicated admin accounts."
        ),
        default_value="N/A",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#4-use-dedicated-admin-accounts",
            "https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles",
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
        tags=["identity", "admin", "licensing", "privileged-access"],
    )

    async def check(self, data: CollectedData):
        users = data.get("users")
        if users is None:
            return self._skip("Could not retrieve users data.")

        role_members = self._get_members_of_privileged_roles(data)
        if not role_members:
            return self._skip("No directory role data available.")

        user_map = {u["id"]: u for u in users}
        violating: list[dict] = []

        for uid in role_members:
            user = user_map.get(uid)
            if not user:
                continue
            assigned = user.get("assignedLicenses") or []
            sku_ids = {lic.get("skuId", "") for lic in assigned}
            # We don't have skuPartNumber in the users query; check by skuId count
            # If user has any licenses, we flag for manual review unless we can match
            # For now flag users who have >0 licenses with a note
            if assigned:
                violating.append(
                    {
                        "userPrincipalName": user.get("userPrincipalName"),
                        "id": uid,
                        "assignedLicenseCount": len(assigned),
                        "skuIds": list(sku_ids),
                    }
                )

        if not violating:
            return self._pass(
                f"All {len(role_members)} privileged accounts have no assigned "
                "productivity licenses.",
                evidence=[
                    Evidence(
                        source="graph/users",
                        data={"privilegedMembersChecked": len(role_members)},
                        description="No privileged accounts with licenses found.",
                    )
                ],
            )

        return self._fail(
            f"{len(violating)} privileged account(s) have assigned licenses. "
            "Verify that none are full E3/E5 productivity suites.",
            evidence=[
                Evidence(
                    source="graph/users",
                    data=violating,
                    description="Privileged accounts with assigned licenses.",
                )
            ],
        )
