"""
CIS MS365 5.1.4.5 (L1) – Ensure Local Admin Password Solution (LAPS) is
enabled (Automated)

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
class CIS_5_1_4_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.4.5",
        title="Ensure Local Admin Password Solution (LAPS) is enabled",
        section="5.1.4 Devices",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Entra ID LAPS should be enabled to automatically manage "
            "and rotate local administrator passwords on Entra-joined and "
            "Entra-registered devices."
        ),
        rationale=(
            "LAPS ensures that each device has a unique, randomly generated local "
            "admin password that is rotated regularly. This prevents lateral movement "
            "if a local admin password is compromised on one device."
        ),
        impact=(
            "Enabling LAPS requires devices to be configured to use it. "
            "Existing local admin passwords will be replaced by LAPS-managed passwords."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/policies/deviceRegistrationPolicy\n"
            "  Check localAdminPassword.isEnabled = true"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Devices > Device settings.\n"
            "Enable 'Enable Microsoft Entra Local Administrator Password Solution (LAPS)'.\n\n"
            "Then configure LAPS settings in Intune:\n"
            "  Microsoft Intune admin center → Endpoint security > Account protection > "
            "Create policy > Windows LAPS"
        ),
        default_value="LAPS is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.2",
                title="Use Unique Passwords",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "devices", "laps", "local-admin", "passwords"],
    )

    async def check(self, data: CollectedData):
        device_reg_policy = data.get("device_registration_policy")
        if device_reg_policy is None:
            return self._skip(
                "Could not retrieve device registration policy. "
                "Requires Policy.Read.All permission (beta)."
            )

        local_admin_password = device_reg_policy.get("localAdminPassword") or {}
        is_enabled = local_admin_password.get("isEnabled")

        evidence = [
            Evidence(
                source="graph/beta/policies/deviceRegistrationPolicy",
                data={"localAdminPassword.isEnabled": is_enabled},
                description="Device registration policy - LAPS enabled setting.",
            )
        ]

        if is_enabled is True:
            return self._pass(
                "Microsoft Entra LAPS is enabled (localAdminPassword.isEnabled = true).",
                evidence=evidence,
            )

        if is_enabled is False:
            return self._fail(
                "Microsoft Entra LAPS is disabled (localAdminPassword.isEnabled = false). "
                "Local admin passwords are not being managed and rotated automatically.",
                evidence=evidence,
            )

        return self._manual(
            "LAPS status could not be determined from device registration policy. "
            "Verify manually:\n"
            "  Microsoft Entra admin center → Identity > Devices > Device settings\n"
            "  Check 'Enable Microsoft Entra Local Administrator Password Solution (LAPS)'"
        )
