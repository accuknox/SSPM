"""
CIS MS365 5.1.4.3 (L1) – Ensure Global Administrator is not added as a local
administrator during Entra join (Automated)

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
class CIS_5_1_4_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.4.3",
        title="Ensure Global Administrator is not added as a local administrator during Entra join",
        section="5.1.4 Devices",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "During Microsoft Entra join, the Global Administrator role members "
            "should not be automatically added as local administrators on the joined "
            "devices. This reduces the attack surface by limiting local admin access."
        ),
        rationale=(
            "If Global Administrators are automatically added as local admins on "
            "Entra-joined devices, compromising one device could be used to escalate "
            "privileges or harvest credentials of the local admin account."
        ),
        impact=(
            "Global Administrators will not be local admins on Entra-joined devices. "
            "Alternative management approaches (LAPS, Intune policies) should be used."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/policies/deviceRegistrationPolicy\n"
            "  Check localAdminPassword settings and \n"
            "  azureAdJoin.localAdmins.enableGlobalAdmins (or similar field).\n\n"
            "Microsoft Entra admin center → Identity > Devices > Device settings:\n"
            "  'Additional local administrators on all Microsoft Entra joined devices'"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Devices > Device settings.\n"
            "In 'Additional local administrators on all Microsoft Entra joined devices':\n"
            "  Do not include Global Administrator role.\n"
            "  Use LAPS or Intune for local admin management instead."
        ),
        default_value="Global Admins are added as local admins during Entra join by default.",
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
        enable_global_admins = local_admins.get("enableGlobalAdmins")

        evidence = [
            Evidence(
                source="graph/beta/policies/deviceRegistrationPolicy",
                data={"azureAdJoin.localAdmins.enableGlobalAdmins": enable_global_admins},
                description="Device registration policy - global admin as local admin setting.",
            )
        ]

        if enable_global_admins is False:
            return self._pass(
                "Global Administrators are not added as local admins during Entra join "
                "(enableGlobalAdmins = false).",
                evidence=evidence,
            )

        if enable_global_admins is True:
            return self._fail(
                "Global Administrators are added as local admins on Entra-joined devices "
                "(enableGlobalAdmins = true).",
                evidence=evidence,
            )

        return self._manual()
