"""CIS Azure 8.5 – Ensure Azure DDoS Network Protection is Enabled on Virtual Networks (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.5",
        title="Ensure Azure DDoS Network Protection is Enabled on Virtual Networks",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Azure DDoS Network Protection should be enabled on all Virtual Networks hosting "
            "public-facing workloads to provide adaptive tuning, attack telemetry, and "
            "automatic mitigation of volumetric DDoS attacks."
        ),
        rationale=(
            "DDoS attacks can render public-facing applications unavailable, causing revenue "
            "loss and reputational damage. DDoS Network Protection provides always-on traffic "
            "monitoring and automated attack mitigation tailored to the specific VNet."
        ),
        impact="DDoS Network Protection is a paid service charged per protected VNet per month.",
        audit_procedure=(
            "ARM: GET each VNet — properties.enableDdosProtection must be true."
        ),
        remediation=(
            "VNet → DDoS protection → Enable DDoS Network Protection → select or create a "
            "DDoS protection plan → Save."
        ),
        default_value="DDoS protection is not enabled on VNets by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.3", title="Securely Manage Network Infrastructure", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vnets = data.get("virtual_networks")
        if vnets is None:
            return self._skip("Virtual Networks could not be retrieved.")
        if not vnets:
            return self._pass("No Virtual Networks in subscription.")

        offenders: list[str] = []
        for v in vnets:
            name = v.get("name", "?")
            props = v.get("properties", {})
            if not props.get("enableDdosProtection"):
                offenders.append(name)

        evidence = [Evidence(
            source="arm:Microsoft.Network/virtualNetworks",
            data={"vnets_without_ddos": offenders},
        )]
        if offenders:
            return self._fail(
                f"{len(offenders)} Virtual Network(s) do not have DDoS Network Protection enabled: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(vnets)} Virtual Network(s) have DDoS Network Protection enabled.",
            evidence=evidence,
        )
