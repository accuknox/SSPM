"""CIS Azure 2.1.9 – Ensure 'No Public IP' is Set to 'Enabled' (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_9(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.9",
        title="Ensure 'No Public IP' is Set to 'Enabled'",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "Azure Databricks cluster nodes should not have public IP addresses. The 'No Public IP' "
            "feature (Secure Cluster Connectivity) ensures that cluster worker and driver nodes "
            "are assigned only private IP addresses, routing all outbound traffic through a "
            "NAT gateway or Azure Firewall."
        ),
        rationale=(
            "Cluster nodes with public IP addresses are directly reachable from the internet, "
            "increasing the attack surface. With No Public IP enabled, nodes are not directly "
            "accessible from outside the VNet, reducing exposure to network-based attacks "
            "and data exfiltration risks."
        ),
        impact=(
            "Enabling No Public IP requires a NAT gateway or equivalent egress path for "
            "cluster nodes to reach Databricks control plane endpoints. Without this, cluster "
            "creation will fail."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/{subscriptionId}/providers/Microsoft.Databricks/workspaces "
            "— for each workspace verify that "
            "properties.parameters.enableNoPublicIp.value is true."
        ),
        remediation=(
            "No Public IP must be configured at workspace creation time. For new workspaces: "
            "Azure Portal → Create Databricks workspace → Networking → enable 'No Public IP'. "
            "For existing workspaces with VNet injection, update the workspace properties via "
            "ARM or Terraform to set enableNoPublicIp = true (requires workspace restart)."
        ),
        default_value="No Public IP is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/security/network/secure-cluster-connectivity",
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
            no_public_ip = (
                ws.get("properties", {})
                .get("parameters", {})
                .get("enableNoPublicIp", {})
                .get("value")
            )
            if no_public_ip is not True:
                offenders.append(ws.get("name", ws.get("id", "unknown")))

        evidence = [
            Evidence(
                source="arm:Microsoft.Databricks/workspaces",
                data={"total": len(workspaces), "public_ip_enabled": len(offenders)},
            )
        ]
        if not offenders:
            return self._pass(
                "All Databricks workspaces have 'No Public IP' enabled.",
                evidence=evidence,
            )
        return self._fail(
            f"{len(offenders)} Databricks workspace(s) do not have 'No Public IP' enabled "
            f"(cluster nodes may have public IP addresses): {', '.join(offenders)}.",
            evidence=evidence,
        )
