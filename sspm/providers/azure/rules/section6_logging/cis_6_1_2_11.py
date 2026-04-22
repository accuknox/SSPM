"""CIS Azure 6.1.2.11 – Ensure that an Activity Log Alert Exists for Service Health (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


_CATEGORY = "servicehealth"


@registry.rule
class CIS_6_1_2_11(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.2.11",
        title="Ensure that an Activity Log Alert Exists for Service Health",
        section="6.1.2 Monitoring Using Activity Log Alerts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "An activity log alert must exist for Service Health events to notify administrators "
            "of Azure service incidents, planned maintenance, and health advisories that may "
            "affect the subscription's resources."
        ),
        rationale=(
            "Service Health alerts notify administrators of Azure platform events that could "
            "impact availability. Without this alert, teams may be unaware of ongoing incidents "
            "until users report problems, delaying incident response."
        ),
        impact="Alert notifications require a configured action group.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/microsoft.insights/activityLogAlerts — "
            "find an enabled alert with condition field = category and equals = ServiceHealth."
        ),
        remediation=(
            "Azure Monitor → Alerts → Create → Activity Log → Scope = subscription → "
            "Signal = Service Health → configure event types (Incident, Maintenance, etc.) → "
            "Create action group → Create."
        ),
        default_value="No activity log alerts exist by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/service-health/alerts-activity-log-service-notifications-portal",
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
                (c.get("field", "").lower() == "category"
                 and (c.get("equals") or "").lower() == _CATEGORY)
                for c in alert.get("properties", {}).get("condition", {}).get("allOf", [])
            )
            for alert in alerts
        )
        evidence = [Evidence(source="arm:activityLogAlerts", data={"category": _CATEGORY, "found": found})]
        if found:
            return self._pass("Activity log alert for Service Health events exists and is enabled.", evidence=evidence)
        return self._fail("No enabled activity log alert found for Service Health events.", evidence=evidence)
