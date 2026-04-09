"""
CIS MS365 5.1.4.1 (L1) – Ensure the ability to join devices is restricted
(Automated)

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


@registry.rule
class CIS_5_1_4_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.4.1",
        title="Ensure the ability to join devices is restricted",
        section="5.1.4 Devices",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The ability to join devices to Microsoft Entra ID should be restricted "
            "to administrators or specific approved groups. Unrestricted device join "
            "allows any user to join their personal devices to the tenant."
        ),
        rationale=(
            "Restricting device join prevents users from adding unmanaged personal "
            "devices to the tenant's Entra ID, which would allow those devices to "
            "access corporate resources through device-based Conditional Access."
        ),
        impact=(
            "Users will not be able to join their personal devices to Entra ID "
            "without administrator involvement or being in an approved group."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/policies/deviceRegistrationPolicy\n"
            "  Check azureAdJoin.allowedToJoin.@odata.type:\n"
            "  • 'AllowedToJoinAllUsersOrGroups' with specific groups = partial restriction\n"
            "  • 'AllowedToJoinNoUsers' or admin-only = compliant\n"
            "  • 'AllowedToJoinAllUsersOrGroups' with all users = non-compliant"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Devices > Device settings.\n"
            "Set 'Users may join devices to Microsoft Entra' to:\n"
            "  • 'None' (only administrators) or\n"
            "  • 'Selected' (specific groups only)"
        ),
        default_value="All users can join devices to Entra ID by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/devices/device-join-plan",
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
        tags=["identity", "devices", "device-registration", "entra-join"],
    )

    async def check(self, data: CollectedData):
        device_reg_policy = data.get("device_registration_policy")
        if device_reg_policy is None:
            return self._skip(
                "Could not retrieve device registration policy. "
                "Requires Policy.Read.All permission (beta)."
            )

        azure_ad_join = device_reg_policy.get("azureAdJoin") or {}
        allowed_to_join = azure_ad_join.get("allowedToJoin") or {}
        join_type = allowed_to_join.get("@odata.type", "")

        evidence = [
            Evidence(
                source="graph/beta/policies/deviceRegistrationPolicy",
                data={"azureAdJoin.allowedToJoin": allowed_to_join},
                description="Device registration policy - Entra Join setting.",
            )
        ]

        # NoUsers or admin-only = compliant
        if "NoUsers" in join_type:
            return self._pass(
                "Device join to Entra ID is restricted (no users can join without admin approval).",
                evidence=evidence,
            )

        # Selected groups = partially compliant
        if "SelectedGroups" in join_type or "UsersOrGroups" in join_type:
            groups = allowed_to_join.get("groups") or []
            users = allowed_to_join.get("users") or []
            if groups and not users:
                return self._pass(
                    f"Device join is restricted to {len(groups)} specific group(s).",
                    evidence=evidence,
                )

        return self._fail(
            "Device join to Entra ID is not restricted. All users may be able to join devices.",
            evidence=evidence,
        )
