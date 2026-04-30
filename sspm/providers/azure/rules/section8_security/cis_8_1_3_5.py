"""CIS Azure 8.1.3.5 – Ensure that 'File Integrity Monitoring' Component Status is Set to 'On' (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_3_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.3.5",
        title="Ensure that 'File Integrity Monitoring' Component Status is Set to 'On'",
        section="8.1.3 Defender Plan: Servers",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "File Integrity Monitoring (FIM) tracks changes to operating system files, Windows "
            "registries, and application configuration files on Azure VMs to detect tampering "
            "or malicious modifications."
        ),
        rationale=(
            "Detecting unauthorized file changes is a key indicator of compromise. FIM provides "
            "an audit trail that supports both detection and forensic investigation of intrusions."
        ),
        impact="FIM generates additional monitoring data, which may increase Log Analytics workspace costs.",
        audit_procedure=(
            "Defender for Cloud → Environment settings → subscription → Servers plan → "
            "Settings: verify File Integrity Monitoring is toggled On."
        ),
        remediation=(
            "Defender for Cloud → Environment settings → subscription → Servers → Settings → "
            "File Integrity Monitoring → toggle to On → Save."
        ),
        default_value="File Integrity Monitoring component is off by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.8", title="Deploy a Host-Based Intrusion Detection Solution", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
