"""CIS Azure 7.8 – Ensure that Virtual Network Flow Log Retention Days is Set to >= 90 (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_8(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.8",
        title="Ensure that Virtual Network Flow Log Retention Days is Set to Greater than or Equal to 90",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Virtual Network flow logs (VNet flow logs) retained for at least 90 days support "
            "incident investigation, anomaly detection, and compliance reporting at the VNet level."
        ),
        rationale=(
            "Short retention windows conceal stealthy, long-dwell attacks. Many compliance "
            "frameworks require at minimum 90 days of log retention for network traffic data."
        ),
        impact="Minor increase in storage cost for extended log retention.",
        audit_procedure=(
            "ARM: enumerate VNet flow logs via Network Watcher; each flow log's "
            "properties.retentionPolicy.enabled must be true and properties.retentionPolicy.days >= 90."
        ),
        remediation=(
            "Network Watcher → Flow logs → select VNet flow log → Retention (days) → set >= 90 → Save."
        ),
        default_value="VNet flow log retention is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.3", title="Ensure Adequate Audit Log Storage", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        flow_logs = data.get("flow_logs")
        if flow_logs is None:
            return self._skip("Flow logs could not be retrieved.")
        if not flow_logs:
            return self._skip("No VNet flow logs are configured — nothing to evaluate.")

        offenders: list[str] = []
        for fl in flow_logs:
            props = fl.get("properties", {})
            name = fl.get("name", "?")
            retention = props.get("retentionPolicy", {}) or {}
            if not retention.get("enabled") or int(retention.get("days", 0)) < 90:
                offenders.append(
                    f"{name} ({'enabled' if retention.get('enabled') else 'disabled'}, "
                    f"{retention.get('days', 0)}d)"
                )

        evidence = [Evidence(source="arm:flowLogs", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} VNet flow log(s) have retention < 90 days: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(flow_logs)} VNet flow log(s) have retention >= 90 days.",
            evidence=evidence,
        )
