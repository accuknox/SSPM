"""
CIS MS365 5.2.2.2 (L1) – Ensure multifactor authentication is enabled for
all users (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

An enabled Conditional Access policy must require MFA for all users, not
just administrators.
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
class CIS_5_2_2_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.2",
        title="Ensure multifactor authentication is enabled for all users",
        section="5.2.2 Risk-based Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.CRITICAL,
        description=(
            "All users, not just administrators, should be required to complete MFA. "
            "This is enforced via a Conditional Access policy targeting all cloud apps "
            "and requiring MFA as a grant control."
        ),
        rationale=(
            "Non-administrative accounts are also targeted by attackers. Enforcing "
            "MFA for all users significantly reduces the risk of successful "
            "credential-based attacks such as phishing and password spraying."
        ),
        impact=(
            "All users will be required to register and use MFA.  Allow time for "
            "MFA registration before enforcing the policy.  Consider a staged rollout."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy where:\n"
            "  • conditions.users.includeUsers = ['All'] (or equivalent)\n"
            "  • conditions.applications.includeApplications = ['All']\n"
            "  • grantControls.builtInControls contains 'mfa'\n"
            "  • state = 'enabled' (not 'reportOnly')"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Entra admin center → Protection > Conditional Access > New policy.\n"
            "  2. Assignments: Users → All users (exclude emergency access accounts).\n"
            "  3. Target resources: All cloud apps.\n"
            "  4. Grant: Require multifactor authentication.\n"
            "  5. Enable the policy."
        ),
        default_value="No MFA policy by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.3",
                title="Require MFA for Externally-Exposed Applications",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "mfa", "conditional-access", "critical"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        all_user_mfa_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue
            grant = policy.get("grantControls") or {}
            if "mfa" not in (grant.get("builtInControls") or []):
                continue

            conditions = policy.get("conditions") or {}
            users_cond = conditions.get("users") or {}
            include_users = users_cond.get("includeUsers") or []

            if "All" in include_users:
                all_user_mfa_policy = policy
                break

        if all_user_mfa_policy:
            return self._pass(
                f"Conditional Access policy '{all_user_mfa_policy.get('displayName')}' "
                "requires MFA for all users.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": all_user_mfa_policy.get("id"),
                            "displayName": all_user_mfa_policy.get("displayName"),
                        },
                        description="CA policy requiring MFA for all users found.",
                    )
                ],
            )

        return self._fail(
            "No enabled Conditional Access policy requires MFA for ALL users. "
            f"Reviewed {len(policies)} policies.",
            evidence=[
                Evidence(
                    source="graph/identity/conditionalAccess/policies",
                    data=[
                        {
                            "displayName": p.get("displayName"),
                            "state": p.get("state"),
                            "includeUsers": (
                                (p.get("conditions") or {})
                                .get("users", {})
                                .get("includeUsers", [])
                            ),
                        }
                        for p in policies
                    ],
                    description="All CA policies reviewed.",
                )
            ],
        )
