"""
CIS MS365 5.2.2.12 (L2) – Ensure the device code sign-in flow is blocked
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
class CIS_5_2_2_12(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.12",
        title="Ensure the device code sign-in flow is blocked",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "The device code flow authentication method should be blocked via "
            "Conditional Access. Device code flow is used by phishing attacks "
            "(device code phishing) to steal authentication tokens."
        ),
        rationale=(
            "Device code flow phishing tricks users into entering a device code "
            "provided by an attacker, allowing the attacker to obtain access tokens "
            "without needing the user's credentials."
        ),
        impact=(
            "Legitimate use cases for device code flow (e.g., TV apps, input-limited "
            "devices) will be blocked. Alternative authentication methods must be used."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy with:\n"
            "  • conditions.authenticationFlows.transferMethods includes 'deviceCodeFlow'\n"
            "  • grantControls.builtInControls contains 'block'"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Users: All users\n"
            "  2. Conditions: Authentication flows > Device code flow\n"
            "  3. Grant: Block access\n"
            "  4. Enable the policy"
        ),
        default_value="Device code flow is allowed by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-conditions-authentication-flows",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.5",
                title="Implement DMARC",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "conditional-access", "device-code-flow", "anti-phishing"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        device_code_block_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            conditions = policy.get("conditions") or {}
            auth_flows = conditions.get("authenticationFlows") or {}
            transfer_methods = auth_flows.get("transferMethods") or []

            if "deviceCodeFlow" not in transfer_methods and "device_code_flow" not in transfer_methods:
                continue

            grant = policy.get("grantControls") or {}
            built_in = grant.get("builtInControls") or []

            if "block" in built_in:
                device_code_block_policy = policy
                break

        if device_code_block_policy:
            return self._pass(
                f"Policy '{device_code_block_policy.get('displayName')}' blocks "
                "the device code sign-in flow.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": device_code_block_policy.get("id"),
                            "displayName": device_code_block_policy.get("displayName"),
                        },
                        description="CA policy blocking device code flow.",
                    )
                ],
            )

        return self._fail(
            "No enabled CA policy blocking device code flow found. "
            f"Reviewed {len(policies)} policies.",
        )
