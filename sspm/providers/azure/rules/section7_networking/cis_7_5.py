"""CIS Azure 7.5 – Ensure NSG Flow Log Retention is >= 90 Days (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.5",
        title="Ensure that Network Security Group Flow Log Retention Days is Set to Greater than or Equal to 90",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "NSG flow logs retained for at least 90 days support incident investigation, anomaly "
            "detection, and compliance reporting."
        ),
        rationale=(
            "Short retention windows hide stealthy, long-dwell attacks. Many compliance frameworks "
            "require 90-day minimum log retention."
        ),
        impact="Minor storage cost growth.",
        audit_procedure=(
            "ARM: enumerate flow logs per Network Watcher; each flow log's "
            "retentionPolicy.enabled must be true and retentionPolicy.days >= 90."
        ),
        remediation=(
            "Network Watcher → NSG flow logs → select flow log → Retention (days) → ≥ 90 → Save."
        ),
        default_value="Flow log retention is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.10", title="Retain Audit Logs", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        flow_logs = data.get("flow_logs")
        if flow_logs is None:
            return self._skip("Flow logs could not be retrieved.")
        if not flow_logs:
            return self._fail("No NSG flow logs are configured in any Network Watcher.")

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
                f"{len(offenders)} flow log(s) have retention < 90 days: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(flow_logs)} flow log(s) have retention >= 90 days.",
            evidence=evidence,
        )
