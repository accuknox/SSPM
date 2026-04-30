"""CIS Azure 7.11 – Ensure Subnets Are Associated with Network Security Groups (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_11(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.11",
        title="Ensure Subnets Are Associated with Network Security Groups",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Every subnet (excluding the reserved GatewaySubnet) should have an associated "
            "Network Security Group to filter and control inbound and outbound traffic at the "
            "subnet level."
        ),
        rationale=(
            "Subnets without NSG associations have no network-layer access controls. An NSG "
            "on each subnet provides defense-in-depth and limits lateral movement in the event "
            "of a compromise."
        ),
        impact="Existing traffic flows must be evaluated against NSG rules before association "
               "to avoid unintended disruption.",
        audit_procedure=(
            "ARM: list all VNets and their subnets. For each subnet (excluding GatewaySubnet), "
            "verify properties.networkSecurityGroup is a non-null object with an id."
        ),
        remediation=(
            "Azure portal → Virtual networks → select VNet → Subnets → select subnet → "
            "Network security group → assign an NSG → Save."
        ),
        default_value="Subnets are not automatically associated with NSGs.",
        references=[
            "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.3", title="Securely Manage Network Infrastructure", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vnets = data.get("virtual_networks")
        if vnets is None:
            return self._skip("Virtual networks could not be retrieved.")
        if not vnets:
            return self._pass("No virtual networks found in subscription.")

        offenders: list[str] = []
        for vnet in vnets:
            vnet_name = vnet.get("name", "?")
            subnets = vnet.get("properties", {}).get("subnets", []) or []
            for subnet in subnets:
                subnet_name = subnet.get("name", "?")
                # Skip the reserved gateway subnet
                if subnet_name == "GatewaySubnet":
                    continue
                nsg = subnet.get("properties", {}).get("networkSecurityGroup") or {}
                if not nsg.get("id"):
                    offenders.append(f"{vnet_name}/{subnet_name}")

        evidence = [Evidence(source="arm:virtualNetworks", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} subnet(s) lack an NSG association: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            "All subnets (excluding GatewaySubnet) have an associated NSG.",
            evidence=evidence,
        )
