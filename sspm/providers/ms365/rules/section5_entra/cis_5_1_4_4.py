"""
CIS MS365 5.1.4.4 (L1) – Ensure local administrator assignment is limited
during Entra join (Automated)

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
class CIS_5_1_4_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.4.4",
        title="Ensure local administrator assignment is limited during Entra join",
        section="5.1.4 Devices",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "During Microsoft Entra join, the user who joins the device is "
            "automatically added as a local administrator. This should be restricted "
            "so that only designated accounts have local admin rights."
        ),
        rationale=(
            "Automatic local admin assignment to joining users can result in a large "
            "number of devices with the user's account as local admin. This increases "
            "the attack surface and risk of privilege escalation."
        ),
        impact=(
            "Users will not automatically be local admins on devices they join. "
            "LAPS or Intune-managed local admin policies should be used instead."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/policies/deviceRegistrationPolicy\n"
            "  Check azureAdJoin.localAdmins.registeringUsers.localAdminType\n"
            "  Compliant: localAdminType = 'None' or not set to 'Administrator'"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Devices > Device settings.\n"
            "Set 'Registering user is added as local administrator' to None/Disabled.\n"
            "Use LAPS or Intune endpoint privilege management instead."
        ),
        default_value="Registering user is added as local administrator by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/devices/assign-local-admin",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.4",
                title="Restrict Administrator Privileges to Dedicated Administrator Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "devices", "local-admin", "entra-join", "laps"],
    )

    async def check(self, data: CollectedData):
        device_reg_policy = data.get("device_registration_policy")
        if device_reg_policy is None:
            return self._skip(
                "Could not retrieve device registration policy. "
                "Requires Policy.Read.All permission (beta)."
            )

        azure_ad_join = device_reg_policy.get("azureAdJoin") or {}
        local_admins = azure_ad_join.get("localAdmins") or {}
        registering_users = local_admins.get("registeringUsers") or {}
        local_admin_type = registering_users.get("localAdminType")

        evidence = [
            Evidence(
                source="graph/beta/policies/deviceRegistrationPolicy",
                data={
                    "azureAdJoin.localAdmins.registeringUsers.localAdminType": local_admin_type
                },
                description="Device registration policy - registering user local admin setting.",
            )
        ]

        if local_admin_type in (None, "none", "None", "disabled", "Disabled"):
            return self._pass(
                "Registering users are not automatically added as local administrators "
                f"(localAdminType = {local_admin_type}).",
                evidence=evidence,
            )

        if local_admin_type in ("administrator", "Administrator"):
            return self._fail(
                "Registering users are added as local administrators on Entra-joined "
                f"devices (localAdminType = {local_admin_type}).",
                evidence=evidence,
            )

        return self._manual(
            f"Local admin type is '{local_admin_type}'. Verify acceptable configuration:\n"
            "  Microsoft Entra admin center → Identity > Devices > Device settings\n"
            "  Check 'Registering user is added as local administrator' setting"
        )
