"""CIS Azure 6.1.2.6 – Ensure that Activity Log Alert Exists for Delete Security Solution (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


_OPERATION = "microsoft.security/securitysolutions/delete"


@registry.rule
class CIS_6_1_2_6(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.2.6",
        title="Ensure that Activity Log Alert Exists for Delete Security Solution",
        section="6.1.2 Monitoring Using Activity Log Alerts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "An activity log alert must exist for the Delete Security Solution operation to "
            "notify administrators when security solutions are removed."
        ),
        rationale=(
            "Deletion of a security solution removes threat protection from the subscription. "
            "Alerting on this operation ensures that unauthorized removal of security controls "
            "is detected immediately."
        ),
        impact="Alert notifications require a configured action group.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/microsoft.insights/activityLogAlerts — "
            "find an enabled alert with condition operationName = "
            "microsoft.security/securitysolutions/delete."
        ),
        remediation=(
            "Azure Monitor → Alerts → Create → Activity Log → Scope = subscription → "
            "Signal = Security Solutions Delete → Create action group → Create."
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
