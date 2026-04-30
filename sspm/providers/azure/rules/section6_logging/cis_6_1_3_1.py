"""CIS Azure 6.1.3.1 – Ensure Application Insights are Configured (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_3_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.3.1",
        title="Ensure Application Insights are Configured",
        section="6.1.3 Configuring Application Insights",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "At least one Application Insights component should be configured in the subscription "
            "to enable application-level performance monitoring and diagnostics."
        ),
        rationale=(
            "Application Insights provides telemetry for application performance, availability, "
            "and usage. Without it, application-level anomalies, errors, and performance "
            "degradation may go undetected, making it harder to identify security-relevant "
            "application behaviour."
        ),
        impact=(
            "Application Insights incurs Log Analytics ingestion costs proportional to "
            "application telemetry volume. Configure sampling to manage costs."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Insights/components — verify "
            "that at least one Application Insights component exists."
        ),
        remediation=(
            "Azure portal → Application Insights → Create → configure resource group, name, "
            "region, and Log Analytics workspace → Create."
        ),
        default_value="No Application Insights components exist by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.2", title="Collect Audit Logs", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        components = data.get("app_insights_components")
        if components is None:
            return self._skip("Application Insights components could not be retrieved.")

        evidence = [Evidence(
            source="arm:appInsightsComponents",
            data={"count": len(components)},
        )]
        if components:
            return self._pass(
                f"{len(components)} Application Insights component(s) configured in the subscription.",
                evidence=evidence,
            )
        return self._fail(
            "No Application Insights components are configured in the subscription.",
            evidence=evidence,
        )
