"""
CIS MS365 5.1.4.2 (L2) – Ensure the maximum number of devices per user is
limited (Automated)

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

_MAX_DEVICES_UNLIMITED = 0  # 0 or very high number = unlimited


@registry.rule
class CIS_5_1_4_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.4.2",
        title="Ensure the maximum number of devices per user is limited",
        section="5.1.4 Devices",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "The maximum number of devices a user can register in Microsoft Entra ID "
            "should be limited. Unlimited device registration allows users to register "
            "many personal devices."
        ),
        rationale=(
            "Limiting device registration reduces the number of unmanaged devices "
            "that can gain access through device-based policies and reduces the "
            "attack surface by limiting the number of registered devices per user."
        ),
        impact=(
            "Users who have already registered the maximum number of devices will "
            "be unable to register additional devices."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/policies/deviceRegistrationPolicy\n"
            "  Check userDeviceQuota field.\n"
            "  Compliant: userDeviceQuota is not Unlimited (e.g., 5 or fewer)."
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Devices > Device settings.\n"
            "Set 'Maximum number of devices per user' to a specific limit "
            "(e.g., 5 or fewer)."
        ),
        default_value="Maximum devices per user is set to 50 by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-identities",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="1.1",
                title="Establish and Maintain Detailed Enterprise Asset Inventory",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "devices", "device-registration", "quota"],
    )

    async def check(self, data: CollectedData):
        device_reg_policy = data.get("device_registration_policy")
        if device_reg_policy is None:
            return self._skip(
                "Could not retrieve device registration policy. "
                "Requires Policy.Read.All permission (beta)."
            )

        user_device_quota = device_reg_policy.get("userDeviceQuota")

        evidence = [
            Evidence(
                source="graph/beta/policies/deviceRegistrationPolicy",
                data={"userDeviceQuota": user_device_quota},
                description="Device registration policy - user device quota.",
            )
        ]

        # Check if quota is set to a reasonable limit
        # Values: a number > 0 and < high threshold is compliant
        # "Unlimited" might be represented as None, 0, or a very high number
        if user_device_quota is None:
            return self._manual()

        if isinstance(user_device_quota, int) and 0 < user_device_quota <= 50:
            return self._pass(
                f"Maximum devices per user is limited to {user_device_quota}.",
                evidence=evidence,
            )

        # High value or 0 = effectively unlimited
        return self._fail(
            f"Maximum devices per user appears to be {user_device_quota}. "
            "Set a specific reasonable limit (e.g., 5 or fewer).",
            evidence=evidence,
        )
