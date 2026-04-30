"""CIS Azure 2.1.1 – Ensure that Azure Databricks is deployed in a customer-managed virtual network (VNet) (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.1",
        title="Ensure that Azure Databricks is deployed in a customer-managed virtual network (VNet)",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Azure Databricks workspaces should be deployed inside a customer-managed virtual "
            "network (VNet injection) rather than the default Databricks-managed VNet. This "
            "gives full control over network policies, routing, and peering."
        ),
        rationale=(
            "Deploying Databricks in a customer-managed VNet allows organizations to apply "
            "network security groups, custom DNS, firewall rules, and private endpoints. "
            "Without VNet injection, traffic traverses a Microsoft-managed network with "
            "limited visibility and control."
        ),
        impact=(
            "VNet injection must be configured at workspace creation time and cannot be "
            "changed afterwards. Migrating existing workspaces requires recreation."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/{subscriptionId}/providers/Microsoft.Databricks/workspaces "
            "— for each workspace verify that "
            "properties.parameters.customVirtualNetworkId.value is non-empty."
        ),
        remediation=(
            "When creating a new Databricks workspace, select 'Deploy Azure Databricks workspace "
            "in your own Virtual Network' and provide the VNet resource ID, public subnet name, "
            "and private subnet name."
        ),
        default_value="Databricks workspaces are deployed in a Databricks-managed VNet by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/cloud-configurations/azure/vnet-inject",
            "https://www.cisecurity.org/benchmark/azure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="12.2",
                title="Establish and Maintain a Secure Network Architecture",
                ig1=False,
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

        offenders = []
        for ws in workspaces:
            vnet_id = (
                ws.get("properties", {})
                .get("parameters", {})
                .get("customVirtualNetworkId", {})
                .get("value", "")
            )
            if not vnet_id:
                offenders.append(ws.get("name", ws.get("id", "unknown")))

        evidence = [
            Evidence(
                source="arm:Microsoft.Databricks/workspaces",
                data={"total": len(workspaces), "without_custom_vnet": len(offenders)},
            )
        ]
        if not offenders:
            return self._pass(
                "All Databricks workspaces are deployed in a customer-managed VNet.",
                evidence=evidence,
            )
        return self._fail(
            f"{len(offenders)} Databricks workspace(s) are not deployed in a customer-managed "
            f"VNet: {', '.join(offenders)}.",
            evidence=evidence,
        )
