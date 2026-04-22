"""CIS Azure 2.1.11 – Ensure Private Endpoints are Used to Access Azure Databricks Workspaces (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_11(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.11",
        title="Ensure Private Endpoints are Used to Access Azure Databricks Workspaces",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Azure Private Link should be used to access Azure Databricks workspaces via "
            "private endpoints. Private endpoints assign a private IP address from the "
            "customer VNet to the Databricks workspace, ensuring all traffic remains on "
            "the Microsoft backbone network."
        ),
        rationale=(
            "Without private endpoints, access to the Databricks workspace travels over "
            "public internet routes even within Azure. Private endpoints eliminate public "
            "internet exposure, prevent data exfiltration via network-level controls, and "
            "enable network policies such as NSG rules to apply to workspace access traffic."
        ),
        impact=(
            "Private endpoint configuration requires additional DNS configuration (private "
            "DNS zones for azuredatabricks.net) and may require changes to firewalls and "
            "routing for clients to reach the private endpoint IP."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/{subscriptionId}/providers/Microsoft.Databricks/workspaces "
            "— for each workspace verify that "
            "properties.privateEndpointConnections is a non-empty list, indicating at least "
            "one private endpoint connection exists."
        ),
        remediation=(
            "Azure Portal → Databricks workspace → Networking → Private endpoint connections → "
            "Add private endpoint → configure VNet, subnet, and DNS integration → Create. "
            "After creating the private endpoint, disable public network access (see 2.1.10)."
        ),
        default_value="No private endpoints are configured for Databricks workspaces by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/cloud-configurations/azure/private-link",
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
            pe_connections = (
                ws.get("properties", {}).get("privateEndpointConnections") or []
            )
            if not pe_connections:
                offenders.append(ws.get("name", ws.get("id", "unknown")))

        evidence = [
            Evidence(
                source="arm:Microsoft.Databricks/workspaces",
                data={"total": len(workspaces), "without_private_endpoint": len(offenders)},
            )
        ]
        if not offenders:
            return self._pass(
                "All Databricks workspaces have at least one private endpoint configured.",
                evidence=evidence,
            )
        return self._fail(
            f"{len(offenders)} Databricks workspace(s) have no private endpoint connections: "
            f"{', '.join(offenders)}.",
            evidence=evidence,
        )
