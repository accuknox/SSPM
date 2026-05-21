"""CIS Azure 6.1.5 – Ensure Basic, Free, and Consumption SKUs are not used on Production artifacts requiring monitoring and SLA (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.5",
        title="Ensure Basic, Free, and Consumption SKUs are not used on Production artifacts requiring monitoring and SLA",
        section="6 Management and Governance Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Production Azure resources that require monitoring, SLA guarantees, and full "
            "diagnostic capabilities should not use Basic, Free, or Consumption-tier SKUs, "
            "as these tiers often lack the monitoring features, SLA coverage, and diagnostic "
            "capabilities required for production workloads."
        ),
        rationale=(
            "Basic, Free, and Consumption SKUs are designed for development, testing, and "
            "low-criticality workloads. Using them in production environments may result in "
            "reduced observability, no SLA guarantees, and limited diagnostic data, making "
            "it harder to detect and respond to security incidents and outages."
        ),
        impact=(
            "Upgrading to paid SKUs will incur additional costs. Plan capacity and budget "
            "accordingly. Evaluate each service's SKU requirements based on business criticality."
        ),
        audit_procedure=(
            "Review the SKU configuration of production resources including Log Analytics "
            "workspaces, API Management instances, App Service Plans, and other services. "
            "Verify that no production-critical resource uses Basic, Free, or Consumption tiers."
        ),
        remediation=(
            "Upgrade production resources from Basic, Free, or Consumption SKUs to Standard "
            "or Premium tiers that provide the required monitoring capabilities, diagnostic "
            "support, and SLA guarantees for production workloads."
        ),
        default_value="New resources default to various SKUs depending on the service type.",
        references=[
            "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="2.1", title="Establish and Maintain a Software Inventory", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying SKU tiers across all production resources requires manual review of "
            "each resource's pricing tier configuration in the Azure portal."
        )
