"""
CIS MS365 5.1.2.2 (L2) – Ensure third party integrated applications are not
allowed (Automated)

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
class CIS_5_1_2_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.2.2",
        title="Ensure third party integrated applications are not allowed",
        section="5.1.2 Account Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Users should not be allowed to register or consent to third-party "
            "applications. This prevents unvetted applications from gaining access "
            "to organizational data through OAuth consent grants."
        ),
        rationale=(
            "Third-party applications registered by users can access organizational "
            "data with the permissions the user grants. Restricting app registration "
            "ensures only IT-approved applications can access organizational data."
        ),
        impact=(
            "Users will not be able to register new applications or consent to "
            "third-party applications. Applications needed by users must be "
            "pre-approved and deployed by IT administrators."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /policies/authorizationPolicy\n"
            "  Check: defaultUserRolePermissions.allowedToCreateApps should be false"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Users > User settings.\n"
            "Set 'Users can register applications' to No.\n\n"
            "Or via Microsoft Graph:\n"
            "  PATCH /policies/authorizationPolicy\n"
            "  { 'defaultUserRolePermissions': { 'allowedToCreateApps': false } }"
        ),
        default_value="Users can register applications by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/prevent-domain-hints-with-home-realm-discovery",
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
        tags=["identity", "apps", "authorization-policy", "oauth"],
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
        allowed_create_apps = default_role_perms.get("allowedToCreateApps")

        evidence = [
            Evidence(
                source="graph/policies/authorizationPolicy",
                data={"allowedToCreateApps": allowed_create_apps},
                description="Authorization policy app registration setting.",
            )
        ]

        if allowed_create_apps is False:
            return self._pass(
                "Users are not allowed to register applications "
                "(allowedToCreateApps = false).",
                evidence=evidence,
            )

        return self._fail(
            "Users are allowed to register applications "
            f"(allowedToCreateApps = {allowed_create_apps}). "
            "Third-party apps can be registered without IT approval.",
            evidence=evidence,
        )
