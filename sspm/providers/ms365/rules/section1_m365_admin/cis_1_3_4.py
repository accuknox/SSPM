"""
CIS MS365 1.3.4 (L2) – Ensure user owned apps and services are restricted
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
class CIS_1_3_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.4",
        title="Ensure user owned apps and services are restricted",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Users should not be able to sign up for email-based subscriptions or "
            "consent to third-party applications on behalf of the organization. "
            "These capabilities should be restricted to administrators."
        ),
        rationale=(
            "Allowing users to sign up for email-based subscriptions or create "
            "apps introduces unmanaged SaaS services and potential data exposure. "
            "Centralized control ensures only approved applications are used."
        ),
        impact=(
            "Users will not be able to sign up for free trials of Microsoft services "
            "or other email-based subscriptions without admin approval."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /policies/authorizationPolicy\n"
            "  Check:\n"
            "  • allowedToSignUpEmailBasedSubscriptions should be false\n"
            "  • defaultUserRolePermissions.allowedToCreateApps should be false"
        ),
        remediation=(
            "Microsoft 365 admin center → Settings > Org settings > Services > "
            "User owned apps and services.\n"
            "Disable 'Let users access the Office Store' and "
            "'Let users start trials on behalf of your organization'.\n\n"
            "Or via Microsoft Graph:\n"
            "  PATCH /policies/authorizationPolicy\n"
            "  { 'allowedToSignUpEmailBasedSubscriptions': false,\n"
            "    'defaultUserRolePermissions': { 'allowedToCreateApps': false } }"
        ),
        default_value="Users can sign up for email-based subscriptions and create apps by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/admin/misc/self-service-sign-up",
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
        tags=["identity", "apps", "self-service", "authorization-policy"],
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

        email_signup = auth_policy.get("allowedToSignUpEmailBasedSubscriptions")
        default_role_perms = auth_policy.get("defaultUserRolePermissions") or {}
        allowed_create_apps = default_role_perms.get("allowedToCreateApps")

        issues = []
        if email_signup is True:
            issues.append("allowedToSignUpEmailBasedSubscriptions = true")
        if allowed_create_apps is True:
            issues.append("defaultUserRolePermissions.allowedToCreateApps = true")

        evidence = [
            Evidence(
                source="graph/policies/authorizationPolicy",
                data={
                    "allowedToSignUpEmailBasedSubscriptions": email_signup,
                    "allowedToCreateApps": allowed_create_apps,
                },
                description="Authorization policy user app permissions.",
            )
        ]

        if not issues:
            return self._pass(
                "User app and email subscription restrictions are properly configured.",
                evidence=evidence,
            )

        return self._fail(
            f"User app restrictions not fully configured: {'; '.join(issues)}",
            evidence=evidence,
        )
