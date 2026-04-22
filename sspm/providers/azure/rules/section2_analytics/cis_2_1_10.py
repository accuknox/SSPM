"""CIS Azure 2.1.10 – Ensure 'Allow Public Network Access' is set to 'Disabled' (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_10(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.10",
        title="Ensure 'Allow Public Network Access' is set to 'Disabled'",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "The 'Allow Public Network Access' setting on an Azure Databricks workspace controls "
            "whether the workspace can be accessed from the public internet. This should be "
            "set to 'Disabled' so that all access goes through private endpoints within a VNet."
        ),
        rationale=(
            "Allowing public network access to the Databricks workspace exposes the workspace "
            "URL to the internet. Disabling public access ensures that only clients within "
            "the VNet (or connected networks via VPN/ExpressRoute) can reach the workspace, "
            "significantly reducing the attack surface."
        ),
        impact=(
            "Disabling public network access requires all users and automation to connect "
            "through a private endpoint or VPN/ExpressRoute. Remote developers accessing the "
            "workspace directly via internet will lose access."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/{subscriptionId}/providers/Microsoft.Databricks/workspaces "
            "— for each workspace verify that properties.publicNetworkAccess is 'Disabled' "
            "(case-insensitive)."
        ),
        remediation=(
            "Azure Portal → Databricks workspace → Networking → Public network access → "
            "set to 'Disabled' → Save. Ensure private endpoints are configured before "
            "disabling public access to avoid loss of connectivity."
        ),
        default_value="Public network access is enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/cloud-configurations/azure/private-link",
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
            public_access = (
                ws.get("properties", {}).get("publicNetworkAccess") or ""
            ).lower()
            if public_access != "disabled":
                offenders.append(ws.get("name", ws.get("id", "unknown")))

        evidence = [
            Evidence(
                source="arm:Microsoft.Databricks/workspaces",
                data={"total": len(workspaces), "public_network_access_enabled": len(offenders)},
            )
        ]
        if not offenders:
            return self._pass(
                "All Databricks workspaces have public network access disabled.",
                evidence=evidence,
            )
        return self._fail(
            f"{len(offenders)} Databricks workspace(s) have public network access enabled: "
            f"{', '.join(offenders)}.",
            evidence=evidence,
        )
