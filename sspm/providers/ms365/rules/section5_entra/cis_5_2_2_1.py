"""
CIS MS365 5.2.2.1 (L1) – Ensure multifactor authentication is enabled for all
users in administrative roles (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

A Conditional Access policy must exist that requires MFA for all users
assigned to administrative directory roles.
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
class CIS_5_2_2_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.1",
        title="Ensure multifactor authentication is enabled for all users in administrative roles",
        section="5.2.2 Risk-based Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.CRITICAL,
        description=(
            "MFA for privileged accounts is one of the most impactful security "
            "controls available.  A Conditional Access policy must be enabled that "
            "targets users in administrative directory roles and requires MFA as a "
            "grant control."
        ),
        rationale=(
            "Administrative accounts with elevated privileges are high-value targets. "
            "Enforcing MFA dramatically reduces the risk of account compromise from "
            "phishing, password spray, or credential theft attacks."
        ),
        impact=(
            "Administrative users will be required to complete MFA on every sign-in "
            "(unless a 'sign-in frequency' policy manages session lifetime).  Ensure "
            "MFA methods are registered before enforcing."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /identity/conditionalAccess/policies\n"
            "  Look for an enabled policy that:\n"
            "  • Targets 'All' users OR explicitly includes directory role members.\n"
            "  • Has grantControls.builtInControls containing 'mfa'.\n"
            "  • Is not in 'reportOnly' mode (state must be 'enabled')."
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Entra admin center → Protection > Conditional Access > New policy.\n"
            "  2. Assignments: Users → Select roles → All administrator roles.\n"
            "  3. Target resources: All cloud apps.\n"
            "  4. Grant: Require multifactor authentication.\n"
            "  5. Enable the policy."
        ),
        default_value="No MFA policy by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa",
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant",
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
            CISControl(
                version="v7",
                control_id="4.5",
                title="Use Multifactor Authentication for All Administrative Access",
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "mfa", "conditional-access", "admin", "critical"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        # Look for an enabled CA policy that requires MFA for admins
        mfa_admin_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue
            grant = policy.get("grantControls") or {}
            built_in = grant.get("builtInControls") or []
            if "mfa" not in built_in:
                continue

            # Check if this policy applies to administrative roles or all users
            conditions = policy.get("conditions") or {}
            users_cond = conditions.get("users") or {}
            include_roles = users_cond.get("includeRoles") or []
            include_users = users_cond.get("includeUsers") or []

            targets_admins = (
                "All" in include_users
                or "GuestsOrExternalUsers" not in include_users  # All users covered
                or len(include_roles) > 0
            )
            if targets_admins:
                mfa_admin_policy = policy
                break

        if mfa_admin_policy:
            return self._pass(
                f"Conditional Access policy '{mfa_admin_policy.get('displayName')}' "
                "enforces MFA for administrative roles.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": mfa_admin_policy.get("id"),
                            "displayName": mfa_admin_policy.get("displayName"),
                            "state": mfa_admin_policy.get("state"),
                        },
                        description="CA policy requiring MFA found.",
                    )
                ],
            )

        enabled_policies = [p.get("displayName") for p in policies if p.get("state") == "enabled"]
        return self._fail(
            "No enabled Conditional Access policy found that requires MFA for "
            f"administrative roles. ({len(policies)} total policies found, "
            f"{len(enabled_policies)} enabled)",
            evidence=[
                Evidence(
                    source="graph/identity/conditionalAccess/policies",
                    data=[
                        {"displayName": p.get("displayName"), "state": p.get("state")}
                        for p in policies
                    ],
                    description="All CA policies; none match MFA for admin roles requirement.",
                )
            ],
        )
