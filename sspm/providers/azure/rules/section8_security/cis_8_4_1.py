"""CIS Azure 8.4.1 – Ensure an Azure Bastion Host Exists (Automated, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_4_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.4.1",
        title="Ensure an Azure Bastion Host Exists",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L2],
        severity=Severity.MEDIUM,
        description=(
            "At least one Azure Bastion host should be deployed so that administrators can reach "
            "Azure VMs over RDP/SSH without exposing public IPs or VPN tunnels."
        ),
        rationale=(
            "Bastion provides session recording, Entra ID authentication, and removes the need "
            "for VM public IPs — shrinking the attack surface dramatically compared to ad-hoc "
            "jump boxes or direct RDP/SSH from the Internet."
        ),
        impact="Bastion is a paid service (per-hour + egress).",
        audit_procedure=(
            "ARM: list /providers/Microsoft.Network/bastionHosts — at least one host must exist "
            "when VMs are present."
        ),
        remediation=(
            "Portal → Create a resource → Bastion → attach to a hub VNet → AzureBastionSubnet."
        ),
        default_value="Bastion is not deployed by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.7", title="Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise's AAA Infrastructure", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        bastions = data.get("bastion_hosts")
        if bastions is None:
            return self._skip("Bastion hosts could not be retrieved.")

        names = [b.get("name", "?") for b in bastions]
        evidence = [Evidence(source="arm:bastionHosts", data={"bastions": names})]
        if bastions:
            return self._pass(
                f"{len(bastions)} Bastion host(s) deployed: {', '.join(names[:10])}.",
                evidence=evidence,
            )
        return self._fail("No Azure Bastion host is deployed in this subscription.", evidence=evidence)
