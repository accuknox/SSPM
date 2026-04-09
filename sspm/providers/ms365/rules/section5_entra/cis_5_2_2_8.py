"""
CIS MS365 5.2.2.8 (L2) – Ensure sign-in risk is blocked for medium and high
risk (Automated)

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
class CIS_5_2_2_8(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.8",
        title="Ensure sign-in risk is blocked for medium and high risk",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "A Conditional Access policy should block or require strong remediation "
            "for medium and high sign-in risk levels detected by Identity Protection."
        ),
        rationale=(
            "Medium and high sign-in risk indicates a high probability that the "
            "sign-in is not from the legitimate user. Blocking or requiring immediate "
            "remediation for these sign-ins prevents unauthorized access."
        ),
        impact=(
            "Users with medium or high sign-in risk will be blocked or required to "
            "complete additional verification before accessing resources."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy with:\n"
            "  • conditions.signInRiskLevels includes both 'medium' and 'high'\n"
            "  • grantControls.builtInControls contains 'block' or 'mfa'"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Users: All users\n"
            "  2. Conditions: Sign-in risk >= Medium\n"
            "  3. Grant: Block access (or Require MFA)\n"
            "  4. Enable the policy"
        ),
        default_value="No sign-in risk blocking policy configured by default.",
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

        compliant_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            conditions = policy.get("conditions") or {}
            sign_in_risk_levels = conditions.get("signInRiskLevels") or []
            grant = policy.get("grantControls") or {}
            built_in = grant.get("builtInControls") or []

            has_medium_high = "medium" in sign_in_risk_levels and "high" in sign_in_risk_levels
            has_block_or_mfa = "block" in built_in or "mfa" in built_in

            if has_medium_high and has_block_or_mfa:
                compliant_policy = policy
                break

        if compliant_policy:
            return self._pass(
                f"Policy '{compliant_policy.get('displayName')}' blocks/requires MFA "
                "for medium and high sign-in risk.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": compliant_policy.get("id"),
                            "displayName": compliant_policy.get("displayName"),
                        },
                        description="Compliant sign-in risk CA policy found.",
                    )
                ],
            )

        return self._fail(
            "No enabled CA policy that blocks/requires MFA for both medium and high "
            f"sign-in risk found. Reviewed {len(policies)} policies.",
        )
