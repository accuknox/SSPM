"""CIS Azure 9.3.6 – Ensure the Minimum TLS Version for Storage Accounts is Set to Version 1.2 (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_6(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.6",
        title="Ensure the Minimum TLS Version for Storage Accounts is Set to TLS 1.2",
        section="9 Storage Accounts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Storage accounts must reject TLS 1.0 and 1.1; ``minimumTlsVersion`` should be "
            "``TLS1_2`` or higher."
        ),
        rationale=(
            "TLS 1.0/1.1 are deprecated, carry known cryptographic weaknesses, and fail most "
            "compliance regimes (PCI, FedRAMP, HIPAA)."
        ),
        impact="Very old clients (Windows 7 stock, legacy IoT) cannot connect.",
        audit_procedure=(
            "ARM: GET each storage account — properties.minimumTlsVersion must be 'TLS1_2' or higher."
        ),
        remediation=(
            "az storage account update --name <sa> --min-tls-version TLS1_2."
        ),
        default_value="TLS1_0 on accounts created before 2020.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.10", title="Encrypt Sensitive Data in Transit", ig1=False, ig2=True, ig3=True),
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
            tls = (sa.get("properties", {}).get("minimumTlsVersion") or "").upper()
            if tls not in ("TLS1_2", "TLS1_3"):
                offenders.append(f"{name} ({tls or 'TLS1_0'})")

        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) permit TLS < 1.2: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) require TLS 1.2+.",
            evidence=evidence,
        )
