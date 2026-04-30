"""CIS Azure 9.3.4 – Ensure 'Secure transfer required' is Set to 'Enabled' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.4",
        title="Ensure 'Secure transfer required' is Set to 'Enabled'",
        section="9 Storage Accounts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Storage accounts must require HTTPS for REST API calls and enforce SMB 3.0 + "
            "encryption for SMB mounts. ``properties.supportsHttpsTrafficOnly`` must be true."
        ),
        rationale=(
            "Clear-text HTTP/SMB exposes credentials, SAS tokens, and data to network observers. "
            "Enforcing secure transport eliminates downgrade attacks."
        ),
        impact="Legacy clients incapable of TLS/SMB3 will be rejected.",
        audit_procedure=(
            "ARM: GET each storage account — properties.supportsHttpsTrafficOnly must be true."
        ),
        remediation=(
            "az storage account update --name <sa> --https-only true."
        ),
        default_value="Enabled on new accounts.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
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

        offenders = [
            sa.get("name", "?")
            for sa in accounts
            if not sa.get("properties", {}).get("supportsHttpsTrafficOnly", False)
        ]
        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) permit HTTP transfer: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) require HTTPS.",
            evidence=evidence,
        )
