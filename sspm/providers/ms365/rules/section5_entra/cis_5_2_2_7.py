"""
CIS MS365 5.2.2.7 (L2) – Ensure Identity Protection sign-in risk policies are
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
class CIS_5_2_2_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.7",
        title="Ensure Identity Protection sign-in risk policies are configured",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "A Conditional Access policy should use Identity Protection sign-in "
            "risk signals to require MFA for risky sign-ins."
        ),
        rationale=(
            "Sign-in risk policies detect anomalous sign-in behaviors like impossible "
            "travel, anonymous IP usage, and malware-linked IPs. Requiring MFA for "
            "risky sign-ins helps prevent unauthorized access."
        ),
        impact=(
            "Users with risky sign-in patterns will be required to complete MFA "
            "or have their sign-in blocked."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy with:\n"
            "  • conditions.signInRiskLevels = ['high'] or ['medium', 'high']"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Users: All users\n"
            "  2. Conditions: Sign-in risk = High\n"
            "  3. Grant: Require MFA\n"
            "  4. Enable the policy\n\n"
            "Requires Microsoft Entra ID P2 (E5) licensing."
        ),
        default_value="No sign-in risk policies configured by default.",
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
        tags=["identity", "conditional-access", "identity-protection", "sign-in-risk", "e5"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        sign_in_risk_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            conditions = policy.get("conditions") or {}
            sign_in_risk_levels = conditions.get("signInRiskLevels") or []

            if "high" in sign_in_risk_levels or "medium" in sign_in_risk_levels:
                sign_in_risk_policy = policy
                break

        if sign_in_risk_policy:
            return self._pass(
                f"Conditional Access policy '{sign_in_risk_policy.get('displayName')}' "
                "uses Identity Protection sign-in risk levels.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": sign_in_risk_policy.get("id"),
                            "displayName": sign_in_risk_policy.get("displayName"),
                            "signInRiskLevels": (
                                sign_in_risk_policy.get("conditions", {})
                                .get("signInRiskLevels", [])
                            ),
                        },
                        description="CA policy with sign-in risk condition.",
                    )
                ],
            )

        return self._fail(
            "No enabled CA policy with sign-in risk level conditions found. "
            f"Reviewed {len(policies)} policies.",
        )
