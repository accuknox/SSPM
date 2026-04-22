"""CIS Azure 8.1.3.4 – Ensure that 'Agentless scanning for machines' Component Status is Set to 'On' (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_3_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.3.4",
        title="Ensure that 'Agentless scanning for machines' Component Status is Set to 'On'",
        section="8.1.3 Defender Plan: Servers",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Agentless scanning for machines uses disk snapshot analysis to detect vulnerabilities "
            "and malware on VMs without requiring an installed agent, covering machines that "
            "cannot run a monitoring agent."
        ),
        rationale=(
            "Agentless scanning extends coverage to ephemeral, non-persistent, or locked-down "
            "machines where agent installation is impractical, closing vulnerability blind spots."
        ),
        impact="Agentless scanning creates temporary disk snapshots, which may incur minor storage costs.",
        audit_procedure=(
            "Defender for Cloud → Environment settings → subscription → Servers plan → "
            "Settings: verify Agentless scanning for machines is toggled On."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Servers → Settings → "
            "Agentless scanning for machines → toggle to On → Save."
        ),
        default_value="Agentless scanning component is off by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="7.1", title="Establish and Maintain a Vulnerability Management Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._skip(
            "This control requires manual verification in the Azure portal: "
            "Defender for Cloud → Environment settings → Servers → Settings → "
            "confirm Agentless scanning for machines is On."
        )
