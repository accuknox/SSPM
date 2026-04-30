"""CIS Azure 9.3.8 – Ensure that 'Allow Blob Anonymous Access' is Set to 'Disabled' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_8(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.8",
        title="Ensure that 'Allow Blob Anonymous Access' is Set to 'Disabled'",
        section="9 Storage Accounts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "``allowBlobPublicAccess`` must be false to prevent any container in the account "
            "from being configured for anonymous (public) read."
        ),
        rationale=(
            "Even if current containers are private, leaving the account-level toggle on allows "
            "a future misconfiguration to expose blobs to the entire Internet."
        ),
        impact=(
            "Static-website and legitimate public-download scenarios must move to SAS tokens "
            "or Azure Front Door with restricted policies."
        ),
        audit_procedure=(
            "ARM: GET each storage account — properties.allowBlobPublicAccess must be false."
        ),
        remediation=(
            "az storage account update --name <sa> --allow-blob-public-access false."
        ),
        default_value="Disabled on accounts created after Nov 2021; otherwise enabled.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.3", title="Configure Data Access Control Lists", ig1=True, ig2=True, ig3=True),
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
            if sa.get("properties", {}).get("allowBlobPublicAccess") is not False
        ]
        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) allow anonymous blob access: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) block anonymous blob access.",
            evidence=evidence,
        )
