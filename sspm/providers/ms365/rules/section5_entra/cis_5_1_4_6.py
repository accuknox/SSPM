"""
CIS MS365 5.1.4.6 (L2) – Ensure users are restricted from recovering
BitLocker keys (Automated)

Profile Applicability: E3 Level 2, E5 Level 2

Per the official CIS audit procedure, this is read from the tenant-wide
authorization policy (GET /policies/authorizationPolicy ->
defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice), NOT
from deviceRegistrationPolicy — a prior implementation checked unrelated,
non-existent fields on the wrong resource.
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
        title="Ensure users are restricted from recovering BitLocker keys",
        section="5.1.4 Devices",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
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
            "Using Microsoft Graph:\n"
            "  GET /policies/authorizationPolicy\n"
            "  (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions\n"
            "  Ensure AllowedToReadBitlockerKeysForOwnedDevice is False.\n\n"
            "Microsoft Entra admin center → Identity > Devices > Device settings:\n"
            "  'Restrict users from recovering the BitLocker key(s) for their owned "
            "devices' should be Yes."
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
        auth_policy = data.get("authorization_policy")
        if auth_policy is None:
            return self._skip(
                "Could not retrieve authorization policy. "
                "Requires Policy.Read.All permission."
            )

        default_perms = auth_policy.get("defaultUserRolePermissions") or {}
        can_read_bitlocker_keys = default_perms.get(
            "allowedToReadBitlockerKeysForOwnedDevice"
        )

        evidence = [
            Evidence(
                source="graph/policies/authorizationPolicy",
                data={
                    "defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice": (
                        can_read_bitlocker_keys
                    )
                },
                description="Tenant-wide default user role permissions.",
            )
        ]

        if can_read_bitlocker_keys is False:
            return self._pass(
                "Users are restricted from recovering BitLocker keys "
                "(allowedToReadBitlockerKeysForOwnedDevice = false).",
                evidence=evidence,
            )
        if can_read_bitlocker_keys is True:
            return self._fail(
                "Users can recover BitLocker keys for their owned devices "
                "(allowedToReadBitlockerKeysForOwnedDevice = true).",
                evidence=evidence,
            )
        return self._manual()
