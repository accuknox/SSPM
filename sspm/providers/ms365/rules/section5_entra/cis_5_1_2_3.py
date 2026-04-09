"""
CIS MS365 5.1.2.3 (L1) – Ensure non-admin users cannot create tenants
(Automated)

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
class CIS_5_1_2_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.2.3",
        title="Ensure non-admin users cannot create tenants",
        section="5.1.2 Account Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Non-administrator users should not be allowed to create new Microsoft "
            "Entra ID tenants. Tenant creation should be restricted to administrators "
            "to prevent unauthorized tenant sprawl."
        ),
        rationale=(
            "Allowing non-admin users to create tenants can result in shadow IT "
            "environments where organizational data is stored outside of governed "
            "and managed tenants."
        ),
        impact=(
            "Non-admin users will not be able to create new Entra ID tenants. "
            "All new tenants must be created by IT administrators."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /policies/authorizationPolicy\n"
            "  Check: allowedToCreateTenants should be false"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Users > User settings.\n"
            "Set 'Restrict non-admin users from creating tenants' to Yes.\n\n"
            "Or via Microsoft Graph:\n"
            "  PATCH /policies/authorizationPolicy\n"
            "  { 'allowedToCreateTenants': false }"
        ),
        default_value="Non-admin users can create tenants by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions",
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
        tags=["identity", "tenant", "authorization-policy", "admin"],
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

        allowed_create_tenants = auth_policy.get("allowedToCreateTenants")

        evidence = [
            Evidence(
                source="graph/policies/authorizationPolicy",
                data={"allowedToCreateTenants": allowed_create_tenants},
                description="Authorization policy tenant creation setting.",
            )
        ]

        if allowed_create_tenants is False:
            return self._pass(
                "Non-admin users cannot create tenants (allowedToCreateTenants = false).",
                evidence=evidence,
            )

        return self._fail(
            "Non-admin users are allowed to create tenants "
            f"(allowedToCreateTenants = {allowed_create_tenants}).",
            evidence=evidence,
        )
