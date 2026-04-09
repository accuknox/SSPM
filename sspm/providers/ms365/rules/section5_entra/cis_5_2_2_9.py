"""
CIS MS365 5.2.2.9 (L2) – Ensure a managed device is required for
authentication (Automated)

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
class CIS_5_2_2_9(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.2.2.9",
        title="Ensure a managed device is required for authentication",
        section="5.2.2 Conditional Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "A Conditional Access policy should require that users authenticate "
            "only from managed (Intune-compliant or Hybrid Entra joined) devices "
            "to access corporate resources."
        ),
        rationale=(
            "Requiring managed devices ensures that corporate data is only accessed "
            "from devices that meet security compliance requirements, reducing the "
            "risk from unmanaged personal devices."
        ),
        impact=(
            "Users accessing corporate resources from personal or non-compliant "
            "devices will be blocked. All users must have a compliant managed device."
        ),
        audit_procedure=(
            "GET /identity/conditionalAccess/policies\n"
            "Look for an enabled policy with:\n"
            "  • grantControls.builtInControls contains 'compliantDevice' or "
            "'domainJoinedDevice'"
        ),
        remediation=(
            "Create a Conditional Access policy:\n"
            "  1. Users: All users\n"
            "  2. Cloud apps: All cloud apps\n"
            "  3. Grant: Require device to be marked as compliant OR Require Hybrid "
            "Entra joined device\n"
            "  4. Enable the policy"
        ),
        default_value="No device compliance requirement for authentication by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.1",
                title="Establish and Maintain a Secure Configuration Process",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "conditional-access", "device-compliance", "intune"],
    )

    async def check(self, data: CollectedData):
        policies = data.get("conditional_access_policies")
        if policies is None:
            return self._skip("Could not retrieve Conditional Access policies.")

        device_required_policy = None
        for policy in policies:
            if policy.get("state") != "enabled":
                continue

            grant = policy.get("grantControls") or {}
            built_in = grant.get("builtInControls") or []

            if "compliantDevice" in built_in or "domainJoinedDevice" in built_in:
                device_required_policy = policy
                break

        if device_required_policy:
            grant = device_required_policy.get("grantControls") or {}
            return self._pass(
                f"Policy '{device_required_policy.get('displayName')}' requires "
                "a managed device for authentication.",
                evidence=[
                    Evidence(
                        source="graph/identity/conditionalAccess/policies",
                        data={
                            "policyId": device_required_policy.get("id"),
                            "displayName": device_required_policy.get("displayName"),
                            "grantControls": grant.get("builtInControls"),
                        },
                        description="CA policy requiring managed device.",
                    )
                ],
            )

        return self._fail(
            "No enabled CA policy requiring a managed device found. "
            f"Reviewed {len(policies)} policies.",
        )
