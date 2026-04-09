"""
CIS MS365 1.1.3 (L1) – Ensure there are between 2 and 4 Global Administrators
(Automated)

Profile Applicability: E3 Level 1, E5 Level 1

The number of Global Administrator role members should be between 2 and 4.
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
class CIS_1_1_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.1.3",
        title="Ensure there are between 2 and 4 Global Administrators",
        section="1.1 Users",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The number of Global Administrators should be between 2 and 4. "
            "Having fewer than 2 creates a single point of failure; having more "
            "than 4 unnecessarily expands the attack surface for the most "
            "privileged role in the tenant."
        ),
        rationale=(
            "Designating at least 2 Global Administrators ensures that "
            "administrative tasks can still be performed if one account is "
            "unavailable. Limiting to no more than 4 reduces the blast radius "
            "should a Global Administrator account be compromised."
        ),
        impact=(
            "If the current number of Global Administrators is outside the 2–4 "
            "range, accounts must be added or removed. Removing Global Admin from "
            "existing users may impact their ability to perform tasks."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "1. GET /directoryRoles and find the role with displayName = "
            "'Global Administrator'.\n"
            "2. GET /directoryRoles/{id}/members\n"
            "3. Count the members. Compliant if count is between 2 and 4 (inclusive)."
        ),
        remediation=(
            "Microsoft 365 admin center → Users > Active Users.\n"
            "Assign or remove the Global Administrator role until there are between "
            "2 and 4 Global Administrators."
        ),
        default_value="N/A",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles",
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices",
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
        tags=["identity", "admin", "global-administrator", "privileged-access"],
    )

    async def check(self, data: CollectedData):
        roles = data.get("directory_roles")
        if roles is None:
            return self._skip("Could not retrieve directory roles data.")

        ga_role = next(
            (r for r in roles if r.get("displayName") == "Global Administrator"), None
        )
        if ga_role is None:
            return self._skip("Global Administrator role not found in directory roles.")

        role_members_map = data.get("directory_role_members") or {}
        ga_members = role_members_map.get(ga_role["id"], [])
        count = len(ga_members)

        evidence = [
            Evidence(
                source="graph/directoryRoles/{id}/members",
                data={"globalAdminCount": count, "memberIds": ga_members},
                description="Global Administrator role member count.",
            )
        ]

        if 2 <= count <= 4:
            return self._pass(
                f"Global Administrator count is {count}, which is within the "
                "compliant range of 2–4.",
                evidence=evidence,
            )

        if count < 2:
            msg = (
                f"Only {count} Global Administrator(s) found. "
                "At least 2 are required to avoid a single point of failure."
            )
        else:
            msg = (
                f"{count} Global Administrators found, which exceeds the maximum "
                "of 4. Reduce the number to limit privileged access exposure."
            )

        return self._fail(msg, evidence=evidence)
