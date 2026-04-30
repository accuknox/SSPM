"""CIS Azure 6.1.1.1 – Ensure that a 'Diagnostic Setting' Exists for Subscription Activity Logs (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_1_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.1.1",
        title="Ensure that a 'Diagnostic Setting' Exists for Subscription Activity Logs",
        section="6.1.1 Configuring Diagnostic Settings",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "A subscription-scoped Diagnostic Setting should forward Activity Logs to a Log "
            "Analytics workspace, storage account, or Event Hub so that administrative actions "
            "are retained outside the 90-day default window."
        ),
        rationale=(
            "Activity Logs capture control-plane events (who did what, when). Without a diagnostic "
            "setting, logs are retained for only 90 days and cannot be queried centrally, hindering "
            "forensic investigation."
        ),
        impact="Minor storage/ingestion cost; no operational impact.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Insights/diagnosticSettings — expect "
            "at least one setting."
        ),
        remediation=(
            "Azure Monitor → Activity log → Diagnostic settings → Add diagnostic setting, selecting "
            "the ``Administrative``, ``Alert``, ``Policy``, ``Security`` categories and a destination."
        ),
        default_value="No diagnostic settings exist by default (90-day retention only).",
        references=[
            "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.2", title="Collect Audit Logs", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        settings = data.get("activity_log_diagnostic_settings")
        if settings is None:
            return self._skip("Activity log diagnostic settings could not be retrieved.")

        evidence = [Evidence(
            source="arm:diagnosticSettings",
            data={"count": len(settings)},
        )]
        if settings:
            return self._pass(
                f"{len(settings)} diagnostic setting(s) configured for subscription activity logs.",
                evidence=evidence,
            )
        return self._fail(
            "No diagnostic setting exists for subscription activity logs.",
            evidence=evidence,
        )
