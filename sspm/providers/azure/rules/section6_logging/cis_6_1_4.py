"""CIS Azure 6.1.4 – Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.1.4",
        title="Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it",
        section="6 Management and Governance Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Resource-level diagnostic settings should be enabled for all Azure services that "
            "support diagnostic logging, forwarding logs to a Log Analytics workspace, storage "
            "account, or Event Hub for centralized monitoring and retention."
        ),
        rationale=(
            "Resource diagnostic logs capture service-specific operational data that is essential "
            "for security monitoring, troubleshooting, and forensic investigation. Without "
            "resource-level logging, activity within individual services is invisible to the "
            "security team."
        ),
        impact=(
            "Enabling diagnostic settings across all resources may incur significant Log Analytics "
            "ingestion costs depending on the number of resources and log volume. Plan retention "
            "policies and sampling strategies to manage costs."
        ),
        audit_procedure=(
            "Use Azure Policy (built-in initiative 'Enable Azure Monitor for VMs' and similar) "
            "or manually inspect each resource type's Monitoring → Diagnostic settings blade to "
            "verify that logging is configured and forwarding to an appropriate destination."
        ),
        remediation=(
            "For each resource that supports diagnostic logging, navigate to the resource → "
            "Monitoring → Diagnostic settings → Add diagnostic setting → select all relevant "
            "log and metric categories → configure destination → Save. Consider using Azure "
            "Policy with DeployIfNotExists effects to enforce this at scale."
        ),
        default_value="Resource diagnostic settings are not configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="8.2", title="Collect Audit Logs", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying that resource-level diagnostic logging is enabled for all supported "
            "services requires manual inspection of each resource's diagnostic settings or "
            "a review of Azure Policy compliance reports."
        )
