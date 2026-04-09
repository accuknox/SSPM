"""
CIS MS365 5.1.5.1 (L1) – Ensure user consent to apps is not allowed
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
class CIS_5_1_5_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.5.1",
        title="Ensure user consent to apps accessing company data on their behalf is not allowed",
        section="5.1.5 Applications",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Users should not be allowed to consent to applications accessing "
            "company data on their behalf. Only administrators should be able to "
            "grant application permissions to prevent unauthorized data access."
        ),
        rationale=(
            "User consent to apps can result in third-party applications gaining "
            "access to organizational data. Restricting consent to admins ensures "
            "all app permissions are reviewed and approved by IT."
        ),
        impact=(
            "Users will not be able to consent to new application permissions. "
            "They must request admin consent for applications they need."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /policies/authorizationPolicy\n"
            "  Check: defaultUserRolePermissions.permissionGrantPoliciesAssigned\n"
            "  Compliant: empty array or no permissive grant policies"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Enterprise applications > "
            "Consent and permissions > User consent settings.\n"
            "Set 'User consent for applications' to 'Do not allow user consent'.\n\n"
            "Enable admin consent workflow so users can request consent:\n"
            "  Identity > Enterprise applications > Consent and permissions > "
            "Admin consent settings > Enable admin consent requests"
        ),
        default_value="Users can consent to apps from verified publishers by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="2.5",
                title="Allowlist Authorized Software",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "apps", "consent", "oauth", "data-protection"],
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
        grant_policies = default_role_perms.get("permissionGrantPoliciesAssigned") or []

        evidence = [
            Evidence(
                source="graph/policies/authorizationPolicy",
                data={"permissionGrantPoliciesAssigned": grant_policies},
                description="Authorization policy permission grant policies.",
            )
        ]

        # Empty = no user consent allowed (compliant)
        # "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" = permissive (non-compliant)
        permissive_policies = [
            p for p in grant_policies
            if "user-default" in p.lower() or "managePermissionGrantsForSelf" in p
        ]

        if not permissive_policies:
            return self._pass(
                "User consent to applications is restricted. "
                f"permissionGrantPoliciesAssigned = {grant_policies}",
                evidence=evidence,
            )

        return self._fail(
            "Users are allowed to consent to application permissions. "
            f"Permissive grant policies found: {permissive_policies}",
            evidence=evidence,
        )
