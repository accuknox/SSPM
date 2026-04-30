"""CIS Azure 2.1.2 – Ensure that Network Security Groups are Configured for Databricks Subnets (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.2",
        title="Ensure that Network Security Groups are Configured for Databricks Subnets",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Network Security Groups (NSGs) should be associated with the public and private "
            "subnets used by Azure Databricks to control inbound and outbound traffic at the "
            "subnet level."
        ),
        rationale=(
            "NSGs act as a distributed firewall for the Databricks cluster nodes. Without "
            "custom subnets (and their associated NSGs), traffic to and from worker nodes "
            "cannot be restricted, increasing the attack surface of the data platform."
        ),
        impact=(
            "Custom subnet names must be specified at workspace creation. Poorly configured "
            "NSG rules can block required Databricks control-plane traffic."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/{subscriptionId}/providers/Microsoft.Databricks/workspaces "
            "— for each workspace verify that both "
            "properties.parameters.customPublicSubnetName.value and "
            "properties.parameters.customPrivateSubnetName.value are non-empty, indicating "
            "custom (customer-managed) subnets with associated NSGs are in use."
        ),
        remediation=(
            "Deploy the Databricks workspace using VNet injection (see 2.1.1). Provide "
            "dedicated public and private subnet names within the customer-managed VNet, and "
            "attach an NSG to each subnet before workspace creation."
        ),
        default_value=(
            "Databricks creates and manages its own NSGs on the default Databricks-managed VNet."
        ),
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/cloud-configurations/azure/vnet-inject",
            "https://www.cisecurity.org/benchmark/azure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="12.3",
                title="Securely Manage Network Infrastructure",
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
            params = ws.get("properties", {}).get("parameters", {})
            public_subnet = params.get("customPublicSubnetName", {}).get("value", "")
            private_subnet = params.get("customPrivateSubnetName", {}).get("value", "")
            if not public_subnet or not private_subnet:
                offenders.append(ws.get("name", ws.get("id", "unknown")))

        evidence = [
            Evidence(
                source="arm:Microsoft.Databricks/workspaces",
                data={"total": len(workspaces), "without_custom_subnets": len(offenders)},
            )
        ]
        if not offenders:
            return self._pass(
                "All Databricks workspaces use custom subnets with NSG configuration.",
                evidence=evidence,
            )
        return self._fail(
            f"{len(offenders)} Databricks workspace(s) do not have custom public/private "
            f"subnets configured (NSGs cannot be verified): {', '.join(offenders)}.",
            evidence=evidence,
        )
