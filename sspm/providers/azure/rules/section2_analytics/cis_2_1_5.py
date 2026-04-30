"""CIS Azure 2.1.5 – Ensure that Unity Catalog is Configured for Azure Databricks (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.5",
        title="Ensure that Unity Catalog is Configured for Azure Databricks",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Unity Catalog provides centralized governance for all data assets within Azure "
            "Databricks, including databases, tables, views, volumes, and models. It should "
            "be enabled and configured so that data access is controlled through a single "
            "governance layer rather than per-workspace legacy access controls."
        ),
        rationale=(
            "Without Unity Catalog, data governance is fragmented across workspaces with "
            "inconsistent access controls, limited audit logging, and no cross-workspace data "
            "sharing governance. Unity Catalog enables fine-grained access control, data "
            "lineage, and centralized auditing — all critical for a secure data platform."
        ),
        impact=(
            "Migrating existing workspaces to Unity Catalog requires a metastore upgrade and "
            "may require changes to existing notebooks and jobs. Some legacy features may "
            "behave differently under Unity Catalog governance."
        ),
        audit_procedure=(
            "In the Databricks workspace, navigate to Catalog → verify that a Unity Catalog "
            "metastore is attached (the catalog explorer shows catalogs beyond 'hive_metastore'). "
            "In the Databricks Account Console, confirm a metastore is created and assigned to "
            "the workspace. Check that data objects are governed by Unity Catalog privileges "
            "rather than legacy Table ACLs."
        ),
        remediation=(
            "In the Databricks Account Console, create a Unity Catalog metastore in the same "
            "region as the workspace. Assign the metastore to the workspace. Migrate existing "
            "tables using the Unity Catalog migration tool or create new external/managed tables "
            "in Unity Catalog. Configure data governance policies (grants, row filters, "
            "column masks) as required."
        ),
        default_value="New workspaces on the Premium plan are Unity Catalog enabled by default; older workspaces may use legacy Hive metastore.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/data-governance/unity-catalog/",
            "https://www.cisecurity.org/benchmark/azure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.2",
                title="Establish and Maintain a Data Inventory",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
