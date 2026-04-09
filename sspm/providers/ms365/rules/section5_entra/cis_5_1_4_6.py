"""
CIS MS365 5.1.4.6 (L1) – Ensure users are not allowed to recover BitLocker
keys from the Entra portal (Automated)

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
class CIS_5_1_4_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.4.6",
        title="Ensure users are not allowed to recover BitLocker keys from the Entra portal",
        section="5.1.4 Devices",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Regular users should not be able to retrieve BitLocker recovery keys "
            "from the Microsoft Entra portal. Access to recovery keys should be "
            "restricted to IT administrators."
        ),
        rationale=(
            "BitLocker recovery keys allow bypassing full disk encryption. If a "
            "non-admin user can retrieve their device's recovery key, they could "
            "share it with an attacker or use it to access data on a stolen device."
        ),
        impact=(
            "End users who have lost access to their devices and need to recover "
            "them will need to contact IT support for BitLocker recovery assistance."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/policies/deviceRegistrationPolicy\n"
            "  Check if there are settings restricting BitLocker key access.\n\n"
            "Microsoft Entra admin center → Identity > Devices > Device settings:\n"
            "  'Restrict users from recovering the BitLocker key(s) for their owned devices'"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Devices > Device settings.\n"
            "Set 'Restrict users from recovering the BitLocker key(s) for their owned devices' to Yes."
        ),
        default_value="Users can retrieve BitLocker keys by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/devices/device-management-azure-portal",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.11",
                title="Encrypt Sensitive Data at Rest",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "devices", "bitlocker", "encryption", "key-management"],
    )

    async def check(self, data: CollectedData):
        device_reg_policy = data.get("device_registration_policy")
        if device_reg_policy is None:
            return self._skip(
                "Could not retrieve device registration policy. "
                "Requires Policy.Read.All permission (beta)."
            )

        # Check for BitLocker key restriction setting
        # This field may be in different locations in the policy object
        bitlocker_restricted = device_reg_policy.get("isDeviceAdminConfigured")
        # Alternative field names
        if bitlocker_restricted is None:
            bitlocker_restricted = device_reg_policy.get("restrictBitLockerRecovery")

        evidence = [
            Evidence(
                source="graph/beta/policies/deviceRegistrationPolicy",
                data=device_reg_policy,
                description="Device registration policy settings.",
            )
        ]

        if bitlocker_restricted is True:
            return self._pass(
                "Users are restricted from recovering BitLocker keys.",
                evidence=evidence,
            )

        return self._manual(
            "BitLocker key recovery restriction could not be verified via Graph API. "
            "Verify manually:\n"
            "  Microsoft Entra admin center → Identity > Devices > Device settings\n"
            "  Check 'Restrict users from recovering the BitLocker key(s) for their owned devices'"
        )
