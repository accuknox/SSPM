"""CIS Azure 6.1.1.2 – Ensure Diagnostic Setting Captures Appropriate Categories (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


_REQUIRED_CATEGORIES = {"administrative", "alert", "policy", "security"}


@registry.rule
class CIS_6_1_1_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.1.2",
        title="Ensure Diagnostic Setting Captures Appropriate Categories",
        section="6.1.1 Configuring Diagnostic Settings",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "The subscription-level diagnostic setting should capture at least the "
            "Administrative, Alert, Policy, and Security log categories to ensure comprehensive "
            "coverage of control-plane activity."
        ),
        rationale=(
            "Capturing only a subset of log categories leaves gaps in the audit trail. "
            "Administrative events record resource lifecycle changes; Alert events capture "
            "fired alerts; Policy records compliance evaluations; Security records security "
            "center findings. All four are required for a complete picture."
        ),
        impact="Minimal storage/ingestion cost for the additional categories.",
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Insights/diagnosticSettings — "
            "for each setting inspect properties.logs and verify that Administrative, Alert, "
            "Policy, and Security categories all have enabled=true."
        ),
        remediation=(
            "Azure Monitor → Activity log → Diagnostic settings → edit the existing setting → "
            "tick Administrative, Alert, Policy, and Security categories → Save."
        ),
        default_value="No diagnostic settings exist by default.",
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

        found_setting = None
        for setting in settings:
            logs = setting.get("properties", {}).get("logs", []) or []
            enabled_categories = {
                (log.get("category") or "").lower()
                for log in logs
                if log.get("enabled")
            }
            if _REQUIRED_CATEGORIES.issubset(enabled_categories):
                found_setting = setting.get("name", "unknown")
                break

        evidence = [Evidence(
            source="arm:diagnosticSettings",
            data={
                "required_categories": sorted(_REQUIRED_CATEGORIES),
                "compliant_setting": found_setting,
            },
        )]
        if found_setting:
            return self._pass(
                f"Diagnostic setting '{found_setting}' captures all required categories "
                f"(Administrative, Alert, Policy, Security).",
                evidence=evidence,
            )
        return self._fail(
            "No diagnostic setting captures all required categories: "
            "Administrative, Alert, Policy, and Security must all be enabled.",
            evidence=evidence,
        )
