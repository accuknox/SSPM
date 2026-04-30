"""CIS Azure 9.3.5 – Ensure 'Allow trusted Microsoft services to access this storage account' is Enabled (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.5",
        title="Ensure 'Allow trusted Microsoft services to access this storage account' is Enabled for Storage Account Access",
        section="9 Storage Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "When network access to a storage account is restricted by firewall rules, the "
            "'Allow trusted Microsoft services' exception should be enabled so that first-party "
            "Azure services (Azure Backup, Azure Monitor, Azure Defender, etc.) can still access "
            "the account."
        ),
        rationale=(
            "Blocking trusted Microsoft services while restricting network access can prevent "
            "critical Azure platform services from functioning correctly — including backup jobs, "
            "diagnostics export, and security monitoring. Enabling this exception ensures "
            "platform services continue to operate while the public endpoint remains restricted."
        ),
        impact="Only trusted Microsoft services receive this bypass; customer traffic is unaffected.",
        audit_procedure=(
            "ARM: GET each storage account — "
            "properties.networkAcls.bypass must contain 'AzureServices'."
        ),
        remediation=(
            "az storage account update --name <name> --bypass AzureServices Logging Metrics "
            "(or via portal: Storage account → Networking → Firewall → "
            "Allow trusted Microsoft services: Enabled → Save)."
        ),
        default_value="AzureServices bypass is enabled by default on new accounts.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security#trusted-microsoft-services",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.3", title="Securely Manage Network Infrastructure", ig1=False, ig2=True, ig3=True),
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
            bypass = (sa.get("properties") or {}).get("networkAcls", {}).get("bypass") or ""
            if "AzureServices" not in bypass:
                offenders.append(name)

        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) do not allow trusted Microsoft services: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) allow trusted Microsoft services.",
            evidence=evidence,
        )
