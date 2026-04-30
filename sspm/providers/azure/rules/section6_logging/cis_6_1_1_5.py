"""CIS Azure 6.1.1.5 – Ensure that Network Security Group Flow Logs are Captured and Sent to Log Analytics (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_1_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.1.5",
        title="Ensure that Network Security Group Flow Logs are Captured and Sent to Log Analytics",
        section="6.1.1 Configuring Diagnostic Settings",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "NSG flow logs record information about IP traffic flowing through Network Security "
            "Groups. These logs should be enabled and sent to a Log Analytics workspace for "
            "centralized analysis and long-term retention."
        ),
        rationale=(
            "NSG flow logs provide visibility into network traffic patterns, enabling detection "
            "of unusual traffic, lateral movement, and data exfiltration attempts. Without them, "
            "network-level forensic investigation is severely hampered."
        ),
        impact=(
            "NSG flow logs incur storage costs. Traffic Analytics (if enabled) incurs additional "
            "Log Analytics ingestion costs. Plan capacity accordingly."
        ),
        audit_procedure=(
            "Azure Network Watcher → Flow logs: verify that flow logs are enabled for all NSGs "
            "and that Traffic Analytics is configured to send data to a Log Analytics workspace."
        ),
        remediation=(
            "Azure Network Watcher → Flow logs → Create flow log → select NSG → enable flow "
            "logs → configure storage account for raw logs → enable Traffic Analytics and select "
            "a Log Analytics workspace → Save."
        ),
        default_value="NSG flow logs are not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.2", title="Collect Audit Logs", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying NSG flow log configuration requires manual review via Azure Network Watcher "
            "→ Flow logs in the Azure portal."
        )
