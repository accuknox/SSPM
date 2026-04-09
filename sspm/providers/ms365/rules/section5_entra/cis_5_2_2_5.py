"""
CIS MS365 5.2.2.5 (L2) – Ensure phishing-resistant MFA is required for admins
(Automated)

Profile Applicability: E5 Level 2
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
class CIS_5_2_2_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.5",
        title="Ensure phishing-resistant MFA is required for admins",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Administrative accounts should be required to use phishing-resistant "
            "MFA methods (FIDO2 security keys or Windows Hello for Business) via "
            "a Conditional Access policy with authentication strength."
        ),
        rationale=(
            "Standard MFA methods like SMS OTP are susceptible to real-time "
            "phishing attacks (AiTM). Phishing-resistant MFA methods eliminate "
            "this risk by binding authentication to the legitimate site."
        ),
        impact=(
            "Administrative users must register phishing-resistant MFA methods "
            "(FIDO2 keys or Windows Hello). This may require device and hardware "
            "investments."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy targeting admin roles with:\n"
            "  • grantControls.authenticationStrength.displayName containing "
            "'Phishing-resistant' or a custom strength requiring FIDO2/WHfB"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Target: All administrator roles\n"
            "  2. Grant: Require authentication strength\n"
            "  3. Select: Phishing-resistant MFA\n"
            "  4. Enable the policy"
        ),
        default_value="No phishing-resistant MFA requirement by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.5",
                title="Require MFA for Administrative Access",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "conditional-access", "mfa", "phishing-resistant", "admin", "fido2"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        phishing_resistant_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            grant = policy.get("grantControls") or {}
            auth_strength = grant.get("authenticationStrength") or {}
            strength_name = auth_strength.get("displayName", "").lower()

            if "phishing" in strength_name or "fido" in strength_name:
                conditions = policy.get("conditions") or {}
                users_cond = conditions.get("users") or {}
                include_roles = users_cond.get("includeRoles") or []
                if include_roles:
                    phishing_resistant_policy = policy
                    break

        if phishing_resistant_policy:
            return self._pass(
                f"Policy '{phishing_resistant_policy.get('displayName')}' requires "
                "phishing-resistant MFA for admin roles.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": phishing_resistant_policy.get("id"),
                            "displayName": phishing_resistant_policy.get("displayName"),
                            "authenticationStrength": (
                                phishing_resistant_policy.get("grantControls", {})
                                .get("authenticationStrength", {})
                                .get("displayName")
                            ),
                        },
                        description="CA policy requiring phishing-resistant MFA for admins.",
                    )
                ],
            )

        return self._fail(
            "No enabled CA policy with phishing-resistant authentication strength "
            f"for admin roles found. Reviewed {len(policies)} policies.",
        )
