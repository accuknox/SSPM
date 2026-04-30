"""CIS Azure 9.3.1.3 – Ensure Storage Account Access Keys are Disabled (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_1_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.1.3",
        title="Ensure that 'Allow storage account key access' is Disabled",
        section="9 Storage Accounts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Shared Key authorization on storage accounts should be disabled so that all access "
            "uses Entra ID identities (which support MFA, Conditional Access, and auditing)."
        ),
        rationale=(
            "Shared keys are effectively God-mode passwords that cannot be MFA-protected, "
            "scoped, or easily rotated. Leaking one key compromises every container and blob."
        ),
        impact=(
            "Applications and tooling must be migrated to Azure AD authentication or SAS tokens."
        ),
        audit_procedure=(
            "ARM: GET each storage account — properties.allowSharedKeyAccess must be false."
        ),
        remediation=(
            "az storage account update --name <sa> --allow-shared-key-access false "
            "(after migrating all clients to Entra ID auth)."
        ),
        default_value="Shared key access is allowed.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent",
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
            if sa.get("properties", {}).get("allowSharedKeyAccess") is not False
        ]
        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) allow shared key access: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) block shared key access.",
            evidence=evidence,
        )
