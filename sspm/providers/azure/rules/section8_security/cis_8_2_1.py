"""CIS Azure 8.2.1 – Ensure That Microsoft Defender for IoT Hub Is Set To 'On' (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_2_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.2.1",
        title="Ensure That Microsoft Defender for IoT Hub Is Set To 'On'",
        section="8.2 Microsoft Defender for IoT",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Microsoft Defender for IoT provides agentless threat detection and security "
            "monitoring for IoT/OT devices connected through Azure IoT Hub, detecting anomalous "
            "device behavior and protocol-level attacks."
        ),
        rationale=(
            "IoT devices often run unpatched firmware and lack native security controls. "
            "Defender for IoT provides the visibility needed to detect compromised devices "
            "before they pivot into enterprise networks."
        ),
        impact="Defender for IoT incurs per-device monthly pricing.",
        audit_procedure=(
            "Azure portal → IoT Hub → Defender for IoT → verify that Defender for IoT is "
            "toggled to On for each IoT Hub in the subscription."
        ),
        remediation=(
            "Azure portal → IoT Hub → Defender for IoT → toggle to On → Save."
        ),
        default_value="Defender for IoT is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.1", title="Centralize Security Event Alerting", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
