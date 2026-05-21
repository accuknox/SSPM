"""
CIS MS365 4.1 (L1) – Ensure that devices without a compliance policy are
marked as not compliant (Automated)

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
class CIS_4_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-4.1",
        title="Ensure that devices without a compliance policy are marked as not compliant",
        section="4 Microsoft Intune",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Intune should be configured so that devices without a "
            "compliance policy assigned are automatically marked as non-compliant. "
            "This ensures that all devices must meet compliance requirements to "
            "access corporate resources via Conditional Access."
        ),
        rationale=(
            "If devices without compliance policies are considered compliant, "
            "they can access corporate resources without meeting any security "
            "requirements. Marking them as non-compliant ensures no device can "
            "bypass compliance checks."
        ),
        impact=(
            "Devices that have not been assigned a compliance policy will be "
            "marked as non-compliant and may lose access to corporate resources "
            "if Conditional Access is enforced."
        ),
        audit_procedure=(
            "Microsoft Intune admin center → Devices > Compliance policies > "
            "Compliance policy settings.\n"
            "Verify 'Mark devices with no compliance policy assigned as' is set to "
            "'Not compliant'.\n\n"
            "Or via Microsoft Graph:\n"
            "  GET /deviceManagement/settings\n"
            "  Check deviceComplianceCheckinThresholdDays and "
            "secureByDefault (or equivalent) fields."
        ),
        remediation=(
            "Microsoft Intune admin center → Devices > Compliance policies > "
            "Compliance policy settings.\n"
            "Set 'Mark devices with no compliance policy assigned as' to 'Not compliant'."
        ),
        default_value="Devices without compliance policy are marked as compliant by default.",
        references=[
            "https://learn.microsoft.com/en-us/intune/intune-service/protect/device-compliance-get-started",
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
        tags=["intune", "device-compliance", "conditional-access"],
    )

    async def check(self, data: CollectedData):
        compliance_policies = data.get("device_compliance_policies")
        if compliance_policies is None:
            return self._skip(
                "Could not retrieve device compliance policies. "
                "Requires DeviceManagementConfiguration.Read.All permission."
            )

        # Check if any compliance policies exist
        if not compliance_policies:
            return self._fail(
                "No device compliance policies found in Intune. "
                "Devices may be considered compliant by default.",
                evidence=[
                    Evidence(
                        source="graph/deviceManagement/deviceCompliancePolicies",
                        data=[],
                        description="No compliance policies configured.",
                    )
                ],
            )

        # We cannot directly check the "default compliance" setting from this endpoint
        # The actual setting requires GET /deviceManagement/settings
        # Provide a partial check with manual guidance
        return self._manual(
            f"{len(compliance_policies)} compliance policy/policies found. Default compliance setting requires manual verification."
        )
