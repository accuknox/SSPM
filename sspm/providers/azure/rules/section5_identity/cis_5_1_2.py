"""CIS Azure 5.1.2 – Ensure that 'Require Multifactor Authentication to register or join devices with Microsoft Entra' is set to 'Yes' (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_1_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.1.2",
        title="Ensure that 'Require Multifactor Authentication to register or join devices with Microsoft Entra' is set to 'Yes'",
        section="5.1 Security Defaults (Per-User MFA)",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Require MFA when users register or join devices to Microsoft Entra ID to ensure that "
            "only authenticated users can enroll devices into the directory."
        ),
        rationale=(
            "Requiring MFA for device registration prevents an attacker who has compromised only a "
            "user's password from enrolling a rogue device, which could then be used to obtain "
            "compliant-device-conditional access tokens."
        ),
        impact=(
            "Users registering or joining devices must complete an MFA challenge. Ensure users "
            "have an MFA method registered before enforcing this setting."
        ),
        audit_procedure=(
            "Entra admin center → Devices → Device settings → "
            "Require Multifactor Authentication to register or join devices with Microsoft Entra: "
            "verify it is set to 'Yes'."
        ),
        remediation=(
            "Entra admin center → Devices → Device settings → "
            "Require Multifactor Authentication to register or join devices with Microsoft Entra → "
            "set to 'Yes' → Save."
        ),
        default_value="Set to 'No' by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/devices/device-management-azure-portal",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.3", title="Require MFA for Externally-Exposed Applications", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Device registration MFA setting is not available via Graph application permissions; "
            "verify manually via Entra admin center → Devices → Device settings."
        )
