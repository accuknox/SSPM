"""CIS Azure 8.3.8 – Ensure Private Endpoints are Used to Access Azure Key Vault (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_3_8(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.3.8",
        title="Ensure Private Endpoints are Used to Access Azure Key Vault",
        section="8.3 Key Vault",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Azure Key Vault should be accessed through Private Endpoints so that vault "
            "traffic stays within the virtual network and never traverses the public internet."
        ),
        rationale=(
            "Private Endpoints ensure that Key Vault operations are not exposed to the "
            "internet, reducing the risk of credential harvesting from network eavesdropping "
            "or Man-in-the-Middle attacks on the management plane."
        ),
        impact="Clients must be connected to an approved VNet or use approved network paths.",
        audit_procedure=(
            "ARM: GET each vault — properties.privateEndpointConnections must be a non-empty list."
        ),
        remediation=(
            "Key Vault → Networking → Private endpoint connections → Add → "
            "select VNet and subnet → Create."
        ),
        default_value="No private endpoints are configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.2", title="Establish and Maintain a Secure Network Architecture", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vaults = data.get("key_vaults")
        if vaults is None:
            return self._skip("Key Vaults could not be retrieved.")
        if not vaults:
            return self._pass("No Key Vaults in subscription.")

        offenders: list[str] = []
        for v in vaults:
            name = v.get("name", "?")
            connections = v.get("properties", {}).get("privateEndpointConnections") or []
            if not connections:
                offenders.append(name)

        evidence = [Evidence(source="arm:keyVaults", data={"vaults_without_private_endpoint": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} Key Vault(s) have no private endpoint configured: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(vaults)} Key Vault(s) have at least one private endpoint configured.",
            evidence=evidence,
        )
