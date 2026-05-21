"""CIS Azure 6.1.2.3 – Ensure that Activity Log Alert Exists for Create or Update Network Security Group (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


_OPERATION = "microsoft.network/networksecuritygroups/write"


@registry.rule
class CIS_6_1_2_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.2.3",
        title="Ensure that Activity Log Alert Exists for Create or Update Network Security Group",
        section="6.1.2 Monitoring Using Activity Log Alerts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "An activity log alert must exist for the Create or Update Network Security Group "
            "operation to notify administrators of changes to NSG configurations."
        ),
        rationale=(
            "Network Security Groups control inbound and outbound traffic to Azure resources. "
            "Unauthorized creation or modification of NSGs could expose resources to attack. "
            "Alerting on this operation ensures timely detection of configuration changes."
        ),
        impact="Alert notifications require a configured action group.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/microsoft.insights/activityLogAlerts — "
            "find an enabled alert with condition operationName = "
            "microsoft.network/networksecuritygroups/write."
        ),
        remediation=(
            "Azure Monitor → Alerts → Create → Activity Log → Scope = subscription → "
            "Signal = Network Security Groups Create or Update → Create action group → Create."
        ),
        default_value="No activity log alerts exist by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        alerts = data.get("activity_log_alerts")
        if alerts is None:
            return self._skip("Activity log alerts could not be retrieved.")
        found = any(
            alert.get("properties", {}).get("enabled", False)
            and any(
                (c.get("field", "").lower() == "operationname"
                 and (c.get("equals") or "").lower() == _OPERATION)
                for c in alert.get("properties", {}).get("condition", {}).get("allOf", [])
            )
            for alert in alerts
        )
        evidence = [Evidence(source="arm:activityLogAlerts", data={"operation": _OPERATION, "found": found})]
        if found:
            return self._pass(f"Activity log alert for '{_OPERATION}' exists and is enabled.", evidence=evidence)
        return self._fail(f"No enabled activity log alert found for operation '{_OPERATION}'.", evidence=evidence)
