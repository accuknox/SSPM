"""CIS Azure 8.1.3.2 – Ensure 'Vulnerability assessment for machines' Component Status is set to 'On' (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_3_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.3.2",
        title="Ensure that 'Vulnerability assessment for machines' Component Status is set to 'On'",
        section="8.1.3 Defender Plan: Servers",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "The Vulnerability assessment component within Defender for Servers scans Azure VMs "
            "and Arc-enabled servers for OS and application vulnerabilities using an integrated "
            "scanner (Qualys or Microsoft Defender Vulnerability Management)."
        ),
        rationale=(
            "Continuous vulnerability assessment ensures that newly disclosed CVEs are detected "
            "on running machines, enabling timely patching before adversaries exploit them."
        ),
        impact="Enabling the component may increase agent deployment and scanning overhead.",
        audit_procedure=(
            "Defender for Cloud → Environment settings → subscription → Servers plan → "
            "Settings: verify Vulnerability assessment for machines is toggled On."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Servers → Settings → "
            "Vulnerability assessment for machines → toggle to On → Save."
        ),
        default_value="Vulnerability assessment component is off by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-vm",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="7.1", title="Establish and Maintain a Vulnerability Management Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
