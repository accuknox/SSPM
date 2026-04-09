"""
CIS MS365 4.2 (L2) – Ensure that personal device enrollment is blocked in
Microsoft Intune (Automated)

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
class CIS_4_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-4.2",
        title="Ensure that personal device enrollment is blocked in Microsoft Intune",
        section="4 Microsoft Intune",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Personal device enrollment in Microsoft Intune should be blocked to "
            "ensure only corporate-owned and managed devices can enroll. This "
            "prevents unmanaged personal devices from accessing corporate resources."
        ),
        rationale=(
            "Personal devices may not meet corporate security standards and could "
            "expose corporate data to risk. Restricting enrollment to corporate "
            "devices ensures all enrolled devices are under organizational control."
        ),
        impact=(
            "Employees will not be able to enroll personal devices into Intune "
            "or access corporate resources from personal devices via Intune-protected apps."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /deviceManagement/deviceEnrollmentConfigurations\n"
            "  Look for enrollment restriction configuration with type "
            "'singlePlatformRestriction' or 'defaultDeviceEnrollmentRestrictions'\n"
            "  Check platformRestrictions[windows].personalDeviceEnrollmentBlocked = true\n\n"
            "Microsoft Intune admin center → Devices > Enrollment > "
            "Enrollment restrictions"
        ),
        remediation=(
            "Microsoft Intune admin center → Devices > Enrollment > "
            "Enrollment restrictions.\n"
            "Edit the Default enrollment restriction:\n"
            "  • Device type restrictions: Block personal Windows devices\n"
            "  • Or: Block personal devices for all platforms based on requirements"
        ),
        default_value="Personal device enrollment is allowed by default.",
        references=[
            "https://learn.microsoft.com/en-us/intune/intune-service/enrollment/enrollment-restrictions-set",
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
        tags=["intune", "enrollment", "device-management", "byod"],
    )

    async def check(self, data: CollectedData):
        enrollment_configs = data.get("intune_enrollment_restrictions")
        if enrollment_configs is None:
            return self._skip(
                "Could not retrieve enrollment restriction configurations. "
                "Requires DeviceManagementServiceConfig.Read.All permission."
            )

        if not enrollment_configs:
            return self._skip("No enrollment configurations found.")

        # Look for enrollment restriction configs
        restriction_configs = [
            c for c in enrollment_configs
            if "deviceEnrollmentPlatformRestrictionsConfiguration" in c.get("@odata.type", "")
            or "deviceEnrollmentLimitConfiguration" in c.get("@odata.type", "")
        ]

        if not restriction_configs:
            return self._manual(
                "Enrollment configurations found but restriction type not identified. "
                "Verify personal device enrollment blocking manually:\n"
                "  Microsoft Intune admin center → Devices > Enrollment > "
                "Enrollment restrictions"
            )

        # Check if any restriction blocks personal devices
        blocks_personal = False
        for config in restriction_configs:
            platform_restrictions = config.get("platformRestrictions") or {}
            for platform, restrictions in platform_restrictions.items():
                if restrictions.get("personalDeviceEnrollmentBlocked"):
                    blocks_personal = True
                    break

        evidence = [
            Evidence(
                source="graph/deviceManagement/deviceEnrollmentConfigurations",
                data=[
                    {"displayName": c.get("displayName"), "odataType": c.get("@odata.type")}
                    for c in restriction_configs
                ],
                description="Enrollment restriction configurations found.",
            )
        ]

        if blocks_personal:
            return self._pass(
                "Personal device enrollment is blocked in at least one enrollment "
                "restriction policy.",
                evidence=evidence,
            )

        return self._fail(
            "No enrollment restriction policy found that blocks personal device enrollment.",
            evidence=evidence,
        )
