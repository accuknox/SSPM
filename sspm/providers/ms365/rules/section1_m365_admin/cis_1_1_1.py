"""
CIS MS365 1.1.1 (L1) – Ensure Administrative accounts are cloud-only (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Checks that no user assigned a privileged directory role has
OnPremisesSyncEnabled = True.
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
class CIS_1_1_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.1.1",
        title="Ensure Administrative accounts are cloud-only",
        section="1.1 Users",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Administrative accounts are special privileged accounts that could have "
            "varying levels of access to data, users, and settings. In a hybrid "
            "environment, administrative accounts should not have On-premises sync "
            "enabled, keeping them separate from on-premises accounts to prevent "
            "lateral movement between cloud and on-prem."
        ),
        rationale=(
            "In a hybrid environment, having separate accounts will help ensure that "
            "in the event of a breach in the cloud, the breach does not affect the "
            "on-prem environment and vice versa."
        ),
        impact=(
            "Administrative users will need to utilize login/logout functionality to "
            "switch accounts when performing administrative tasks, losing SSO benefit. "
            "A migration process from the 'daily driver' account to a dedicated admin "
            "account is required."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "1. Get all directory roles and identify privileged roles "
            "(roles with 'Administrator' in the name or 'Global Reader').\n"
            "2. Get members of those roles.\n"
            "3. For each member, check if OnPremisesSyncEnabled is True.\n"
            "4. Any user with OnPremisesSyncEnabled = True in a privileged role "
            "is non-compliant."
        ),
        remediation=(
            "1. Identify privileged accounts that are synced from on-premises.\n"
            "2. Create a new cloud-only admin account for each.\n"
            "3. Migrate M365 and Azure RBAC roles to the new cloud-only account.\n"
            "4. Reduce the hybrid account to a non-privileged user or remove it."
        ),
        default_value="N/A",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/add-users",
            "https://learn.microsoft.com/en-us/microsoft-365/enterprise/protect-your-global-administrator-accounts",
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#9-use-cloud-native-accounts-for-microsoft-entra-roles",
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
            CISControl(
                version="v7",
                control_id="4.1",
                title="Maintain Inventory of Administrative Accounts",
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "admin", "hybrid", "privileged-access"],
    )

    async def check(self, data: CollectedData):
        users = data.get("users")
        if users is None:
            return self._skip("Could not retrieve users data.")

        role_members = self._get_members_of_privileged_roles(data)
        if not role_members:
            return self._skip("No directory role data available.")

        # Build a lookup of user_id → user object
        user_map = {u["id"]: u for u in users}

        violating: list[dict] = []
        for uid in role_members:
            user = user_map.get(uid)
            if user and user.get("onPremisesSyncEnabled"):
                violating.append(user)

        if not violating:
            return self._pass(
                "All administrative accounts are cloud-only "
                f"(checked {len(role_members)} privileged role members).",
                evidence=[
                    Evidence(
                        source="graph/users + graph/directoryRoles",
                        data={"privileged_member_count": len(role_members)},
                        description="No on-premises synced accounts found in privileged roles.",
                    )
                ],
            )

        upns = [u.get("userPrincipalName", u["id"]) for u in violating]
        return self._fail(
            f"{len(violating)} administrative account(s) have OnPremisesSyncEnabled=True: "
            + ", ".join(upns),
            evidence=[
                Evidence(
                    source="graph/users",
                    data=[
                        {
                            "id": u["id"],
                            "userPrincipalName": u.get("userPrincipalName"),
                            "onPremisesSyncEnabled": True,
                        }
                        for u in violating
                    ],
                    description="On-premises synced accounts with privileged roles.",
                )
            ],
        )
