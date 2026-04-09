"""
CIS MS365 5.1.3.2 (L2) – Ensure users can not create security groups
(Automated)

Profile Applicability: E3 Level 2, E5 Level 2
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
class CIS_5_1_3_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.3.2",
        title="Ensure users can not create security groups",
        section="5.1.3 Groups",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Non-administrator users should not be able to create security groups. "
            "Group creation should be restricted to administrators to maintain "
            "control over group-based access assignments."
        ),
        rationale=(
            "Unrestricted security group creation can lead to group sprawl and "
            "make it difficult to manage access control. Restricting creation to "
            "administrators ensures groups are created with proper governance."
        ),
        impact=(
            "Users will not be able to create security groups. They must request "
            "group creation from IT administrators."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /policies/authorizationPolicy\n"
            "  Check: defaultUserRolePermissions.allowedToCreateSecurityGroups should be false"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Groups > General.\n"
            "Set 'Users can create security groups in Microsoft Entra admin centers, "
            "API or PowerShell' to No.\n\n"
            "Or via Microsoft Graph:\n"
            "  PATCH /policies/authorizationPolicy\n"
            "  { 'defaultUserRolePermissions': { 'allowedToCreateSecurityGroups': false } }"
        ),
        default_value="Users can create security groups by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.1",
                title="Establish an Access Granting Process",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "groups", "authorization-policy", "access-control"],
    )

    async def check(self, data: CollectedData):
        auth_policy = data.get("authorization_policy")
        if auth_policy is None:
            return self._skip(
                "Could not retrieve authorization policy. "
                "Requires Policy.Read.All permission."
            )

        if isinstance(auth_policy, list):
            auth_policy = auth_policy[0] if auth_policy else {}

        default_role_perms = auth_policy.get("defaultUserRolePermissions") or {}
        allowed_create_sg = default_role_perms.get("allowedToCreateSecurityGroups")

        evidence = [
            Evidence(
                source="graph/policies/authorizationPolicy",
                data={"allowedToCreateSecurityGroups": allowed_create_sg},
                description="Authorization policy security group creation setting.",
            )
        ]

        if allowed_create_sg is False:
            return self._pass(
                "Users cannot create security groups "
                "(allowedToCreateSecurityGroups = false).",
                evidence=evidence,
            )

        return self._fail(
            "Users are allowed to create security groups "
            f"(allowedToCreateSecurityGroups = {allowed_create_sg}).",
            evidence=evidence,
        )
