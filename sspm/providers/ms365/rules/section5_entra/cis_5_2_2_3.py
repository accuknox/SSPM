"""
CIS MS365 5.2.2.3 (L1) – Ensure legacy authentication is blocked via
Conditional Access (Automated)

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

_LEGACY_AUTH_PROTOCOLS = {
    "exchangeActiveSync", "pop", "imap", "smtp", "mapi",
    "other", "exchangeOnlineManagement",
}


@registry.rule
class CIS_5_2_2_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.3",
        title="Ensure legacy authentication is blocked via Conditional Access",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.CRITICAL,
        description=(
            "A Conditional Access policy should block legacy authentication protocols. "
            "Legacy auth (Basic Auth, POP, IMAP, SMTP, MAPI, EAS without MFA) "
            "cannot enforce MFA and should be blocked."
        ),
        rationale=(
            "Legacy authentication protocols do not support modern authentication "
            "methods like MFA. Password spraying and brute force attacks primarily "
            "target legacy auth endpoints. Blocking legacy auth forces users to "
            "use modern, MFA-capable authentication."
        ),
        impact=(
            "Legacy email clients and apps that use Basic Authentication will no "
            "longer be able to connect. Users must migrate to OAuth-capable email "
            "clients."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy that:\n"
            "  • state = 'enabled'\n"
            "  • grantControls.builtInControls contains 'block'\n"
            "  • conditions.clientAppTypes includes legacy auth protocols:\n"
            "    exchangeActiveSync, other, or similar legacy types"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Entra admin center → Protection > Conditional Access > New policy\n"
            "  2. Users: All users (with no exclusions except break-glass)\n"
            "  3. Cloud apps: All cloud apps\n"
            "  4. Conditions: Client apps → Exchange ActiveSync clients + Other clients\n"
            "  5. Grant: Block access\n"
            "  6. Enable the policy"
        ),
        default_value="Legacy authentication is allowed by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication",
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
        tags=["identity", "conditional-access", "legacy-auth", "mfa", "critical"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        block_legacy_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            grant = policy.get("grantControls") or {}
            built_in = grant.get("builtInControls") or []
            if "block" not in built_in:
                continue

            conditions = policy.get("conditions") or {}
            client_app_types = conditions.get("clientAppTypes") or []

            # Check if it covers legacy auth protocols
            legacy_covered = any(
                app_type in (
                    "exchangeActiveSync", "other", "easSupported",
                    "exchangeActiveSync,other"
                )
                for app_type in client_app_types
            ) or "exchangeActiveSync" in client_app_types or "other" in client_app_types

            if legacy_covered:
                block_legacy_policy = policy
                break

        if block_legacy_policy:
            return self._pass(
                f"Conditional Access policy '{block_legacy_policy.get('displayName')}' "
                "blocks legacy authentication.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": block_legacy_policy.get("id"),
                            "displayName": block_legacy_policy.get("displayName"),
                            "clientAppTypes": (
                                (block_legacy_policy.get("conditions") or {})
                                .get("clientAppTypes", [])
                            ),
                        },
                        description="CA policy blocking legacy auth found.",
                    )
                ],
            )

        return self._fail(
            "No enabled Conditional Access policy found that blocks legacy authentication. "
            f"Reviewed {len(policies)} policies.",
            evidence=[
                Evidence(
                    source="graph/identity/conditionalAccess/policies",
                    data=[
                        {"displayName": p.get("displayName"), "state": p.get("state")}
                        for p in policies
                    ],
                    description="All CA policies reviewed.",
                )
            ],
        )
