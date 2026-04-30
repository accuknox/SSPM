"""CIS Azure 2.1.7 – Ensure that Diagnostic Log Delivery is Configured for Azure Databricks (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_7(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.7",
        title="Ensure that Diagnostic Log Delivery is Configured for Azure Databricks",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Azure Databricks should have diagnostic settings configured to deliver audit logs "
            "and cluster event logs to a destination such as Log Analytics, Storage Account, "
            "or Event Hub. This ensures that access, authentication, and operational events "
            "are retained for security investigation and compliance."
        ),
        rationale=(
            "Without diagnostic log delivery, security events such as user logins, notebook "
            "access, job executions, and cluster starts are not retained beyond the default "
            "Databricks audit log retention window. Long-term retention in a customer-controlled "
            "destination is required for incident response and compliance audits."
        ),
        impact=(
            "Log delivery to Log Analytics or Storage Account incurs additional storage and "
            "ingestion costs proportional to workspace activity."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/{subscriptionId}/providers/Microsoft.Databricks/workspaces "
            "— for each workspace, call: GET {workspaceId}/providers/microsoft.insights/"
            "diagnosticSettings to verify that at least one diagnostic setting is configured "
            "with log categories enabled and a valid destination (storageAccountId, "
            "workspaceId, or eventHubAuthorizationRuleId)."
        ),
        remediation=(
            "For each Databricks workspace: Azure Portal → Databricks workspace → "
            "Monitoring → Diagnostic settings → Add diagnostic setting → select log categories "
            "(e.g., dbfs, clusters, accounts, jobs, notebook, ssh, workspace, secrets, "
            "sqlPermissions, instancePools) → configure destination → Save."
        ),
        default_value="No diagnostic settings are configured for Databricks workspaces by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/account-settings/audit-log-delivery",
            "https://www.cisecurity.org/benchmark/azure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="8.2",
                title="Collect Audit Logs",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        workspaces = data.get("databricks_workspaces")
        if workspaces is None:
            return self._skip("Databricks workspaces could not be retrieved.")
        if not workspaces:
            return self._pass("No Databricks workspaces in subscription.")

        return self._skip(
            "Databricks diagnostic log delivery requires per-workspace diagnostic settings "
            "that are not yet collected by this scanner. Review each workspace manually via "
            "Azure Portal → Databricks workspace → Monitoring → Diagnostic settings."
        )
