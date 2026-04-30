"""CIS Azure 7.6 – Ensure that Network Watcher is 'Enabled' for Azure Regions That are in Use (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_6(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.6",
        title="Ensure that Network Watcher is 'Enabled' for Azure Regions That are in Use",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Network Watcher should be enabled in every region where Azure resources are "
            "provisioned so that packet captures, connection monitoring, and topology diagnostics "
            "are available on demand."
        ),
        rationale=(
            "Network Watcher cannot be enabled retroactively during an incident without manual "
            "intervention — enabling it ahead of time ensures diagnostic data is collectable when "
            "needed."
        ),
        impact="No cost impact; Network Watcher itself is free (individual tools billed separately).",
        audit_procedure=(
            "Compare resource locations with network watcher locations. Every region containing "
            "VNets should have a Network Watcher."
        ),
        remediation="Azure portal → Network Watcher → Overview → Enable for each missing region.",
        default_value="Network Watcher is auto-enabled on first VNet creation.",
        references=[
            "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="13.6", title="Collect Network Traffic Flow Logs", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        watchers = data.get("network_watchers")
        vnets = data.get("virtual_networks")
        if watchers is None or vnets is None:
            return self._skip("Network watchers or VNets could not be retrieved.")

        watcher_regions = {w.get("location", "").lower() for w in watchers if w.get("location")}
        vnet_regions = {v.get("location", "").lower() for v in vnets if v.get("location")}
        missing = sorted(vnet_regions - watcher_regions)

        evidence = [Evidence(
            source="arm:networkWatchers",
            data={"missing_regions": missing},
        )]
        if not vnet_regions:
            return self._pass("No VNets exist — no regions require Network Watcher.")
        if missing:
            return self._fail(
                f"Network Watcher missing in {len(missing)} region(s) with VNets: "
                f"{', '.join(missing)}.",
                evidence=evidence,
            )
        return self._pass(
            f"Network Watcher is enabled in all {len(vnet_regions)} region(s) with VNets.",
            evidence=evidence,
        )
