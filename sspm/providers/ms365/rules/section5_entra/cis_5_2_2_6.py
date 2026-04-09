"""
CIS MS365 5.2.2.6 (L2) – Ensure Identity Protection user risk policies are
configured (Automated)

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
class CIS_5_2_2_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.6",
        title="Ensure Identity Protection user risk policies are configured",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "A Conditional Access policy should be configured that uses Identity "
            "Protection user risk signals to require MFA or block access for "
            "high-risk users."
        ),
        rationale=(
            "Identity Protection user risk policies detect compromised credentials "
            "and risky user behavior. Requiring remediation for high-risk users "
            "helps prevent account compromise from spreading."
        ),
        impact=(
            "Users flagged as high risk will be required to change their password "
            "or complete MFA before accessing resources."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy with:\n"
            "  • conditions.userRiskLevels = ['high'] or ['medium', 'high']"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Users: All users\n"
            "  2. Conditions: User risk = High\n"
            "  3. Grant: Require password change + MFA\n"
            "  4. Enable the policy\n\n"
            "Requires Microsoft Entra ID P2 (E5) licensing."
        ),
        default_value="No user risk policies configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="13.8",
                title="Deploy a Managed Intrusion Detection System",
                ig1=False,
                ig2=False,
                ig3=True,
            ),
        ],
        tags=["identity", "conditional-access", "identity-protection", "user-risk", "e5"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        user_risk_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            conditions = policy.get("conditions") or {}
            user_risk_levels = conditions.get("userRiskLevels") or []

            if "high" in user_risk_levels or "medium" in user_risk_levels:
                user_risk_policy = policy
                break

        if user_risk_policy:
            return self._pass(
                f"Conditional Access policy '{user_risk_policy.get('displayName')}' "
                "uses Identity Protection user risk levels.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": user_risk_policy.get("id"),
                            "displayName": user_risk_policy.get("displayName"),
                            "userRiskLevels": (
                                user_risk_policy.get("conditions", {})
                                .get("userRiskLevels", [])
                            ),
                        },
                        description="CA policy with user risk condition.",
                    )
                ],
            )

        return self._fail(
            "No enabled CA policy with user risk level conditions found. "
            f"Reviewed {len(policies)} policies.",
        )
