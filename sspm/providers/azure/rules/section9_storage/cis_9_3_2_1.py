"""CIS Azure 9.3.2.1 – Ensure Private Endpoints are Used to Access Storage Accounts (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_2_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.2.1",
        title="Ensure Private Endpoints are Used to Access Storage Accounts",
        section="9.3.2 Networking",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Storage accounts should be accessed via private endpoints to keep traffic on the "
            "Microsoft backbone network and eliminate exposure to the public Internet."
        ),
        rationale=(
            "Private endpoints assign a private IP address from a VNet to the storage account, "
            "preventing data from traversing the public Internet. This eliminates the risk of "
            "data exfiltration through public storage endpoints and simplifies network controls."
        ),
        impact="Applications must be deployed in or connected to the VNet containing the private "
               "endpoint, or use VNet peering/VPN to access private endpoints.",
        audit_procedure=(
            "ARM: GET each storage account — "
            "properties.privateEndpointConnections must be a non-empty list."
        ),
        remediation=(
            "Azure portal → Storage account → Networking → Private endpoint connections → "
            "Add private endpoint → configure VNet and subnet → Create."
        ),
        default_value="Storage accounts have no private endpoints by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.2", title="Establish and Maintain a Secure Network Architecture", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        accounts = data.get("storage_accounts")
        if accounts is None:
            return self._skip("Storage accounts could not be retrieved.")
        if not accounts:
            return self._pass("No storage accounts in subscription.")

        offenders: list[str] = []
        for sa in accounts:
            name = sa.get("name", "?")
            connections = (sa.get("properties") or {}).get("privateEndpointConnections") or []
            if not connections:
                offenders.append(name)

        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) have no private endpoint connections: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) have at least one private endpoint.",
            evidence=evidence,
        )
