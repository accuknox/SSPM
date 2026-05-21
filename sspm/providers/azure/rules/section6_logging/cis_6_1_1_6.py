"""CIS Azure 6.1.1.6 – Ensure that Virtual Network Flow Logs are Captured and Sent to Log Analytics (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_1_6(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.1.6",
        title="Ensure that Virtual Network Flow Logs are Captured and Sent to Log Analytics",
        section="6.1.1 Configuring Diagnostic Settings",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Virtual Network (VNet) flow logs capture information about IP traffic flowing "
            "through virtual networks. These logs should be enabled and sent to a Log Analytics "
            "workspace for centralized monitoring and analysis."
        ),
        rationale=(
            "VNet flow logs provide granular visibility into network-level traffic across the "
            "virtual network, complementing NSG flow logs. They enable detection of abnormal "
            "traffic patterns, unauthorized communications, and potential exfiltration activity."
        ),
        impact=(
            "VNet flow logs incur storage and Log Analytics ingestion costs. Plan capacity "
            "and retention policies based on traffic volume."
        ),
        audit_procedure=(
            "Azure Network Watcher → Flow logs: verify that VNet flow logs are enabled for all "
            "virtual networks and configured to send data to a Log Analytics workspace."
        ),
        remediation=(
            "Azure Network Watcher → Flow logs → Create flow log → select Virtual Network → "
            "enable flow logs → configure storage account → enable Traffic Analytics and "
            "select a Log Analytics workspace → Save."
        ),
        default_value="VNet flow logs are not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.2", title="Collect Audit Logs", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying VNet flow log configuration requires manual review via Azure Network Watcher "
            "→ Flow logs in the Azure portal."
        )
