"""CIS Azure 2.1.12 – Ensure Azure Databricks groups are reviewed periodically (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_12(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.12",
        title="Ensure Azure Databricks groups are reviewed periodically",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.LOW,
        description=(
            "Azure Databricks workspace groups and their memberships should be reviewed on a "
            "periodic basis (at least quarterly) to ensure that access rights remain appropriate "
            "and that no stale or unauthorized memberships exist."
        ),
        rationale=(
            "Over time, group memberships in Databricks workspaces can become stale as employees "
            "change roles, leave the organization, or no longer require access to data assets. "
            "Periodic review ensures the principle of least privilege is maintained and reduces "
            "the risk of unauthorized data access by former employees or over-privileged users."
        ),
        impact=(
            "Periodic access reviews require organizational processes (e.g., manager attestation) "
            "and may result in users losing access if reviews are not completed promptly."
        ),
        audit_procedure=(
            "In the Databricks workspace, navigate to Settings → Identity and Access → Groups. "
            "Review each group's membership and verify that all members still require the "
            "access level provided by the group. Pay particular attention to admin groups and "
            "groups with access to sensitive catalogs or high-value clusters. Document the "
            "review date and any changes made."
        ),
        remediation=(
            "Establish a recurring access review process (at least quarterly) for Databricks "
            "groups. Use Microsoft Entra ID Access Reviews for groups synced via SCIM. Remove "
            "any users who no longer require access. Consider implementing Unity Catalog "
            "fine-grained permissions to reduce reliance on broad group-based access."
        ),
        default_value="No automated group review process is configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/users-groups/groups",
            "https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview",
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
