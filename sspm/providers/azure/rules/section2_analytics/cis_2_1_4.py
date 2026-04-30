"""CIS Azure 2.1.4 – Ensure that Users and Groups are Synced from Microsoft Entra ID to Azure Databricks (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.4",
        title="Ensure that Users and Groups are Synced from Microsoft Entra ID to Azure Databricks",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Azure Databricks should use Microsoft Entra ID (formerly Azure Active Directory) "
            "as the identity provider, with users and groups synchronized via SCIM provisioning. "
            "This ensures that Databricks access is governed by the organization's central "
            "identity management processes."
        ),
        rationale=(
            "Without Entra ID sync, Databricks may have stale accounts for departed employees "
            "or contractors, or accounts managed outside of standard HR/IT processes. Centralized "
            "identity management enables consistent joiner/mover/leaver workflows and reduces "
            "the risk of orphaned high-privilege accounts."
        ),
        impact=(
            "SCIM provisioning requires an Entra ID enterprise application configuration and "
            "a Databricks admin access token. Users provisioned via SCIM cannot be manually "
            "added with conflicting attributes."
        ),
        audit_procedure=(
            "In Microsoft Entra ID, navigate to Enterprise Applications → search for the "
            "Databricks application → Provisioning → verify that Provisioning Status is 'On' "
            "and the last sync completed successfully. In the Databricks workspace, navigate to "
            "Settings → Identity and Access → confirm users/groups originate from Entra ID."
        ),
        remediation=(
            "Configure SCIM provisioning: In Entra ID → Enterprise Applications → Azure "
            "Databricks SCIM Provisioning → Provisioning → set Provisioning Mode to Automatic. "
            "In Databricks, generate a PAT token for the provisioning service principal and "
            "provide it as the Secret Token. Map the required attributes and start provisioning."
        ),
        default_value="No automatic user sync is configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/users-groups/scim/aad",
            "https://www.cisecurity.org/benchmark/azure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.1",
                title="Establish and Maintain an Inventory of Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
