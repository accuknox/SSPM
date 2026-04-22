"""CIS Azure 9.3.7 – Ensure 'Cross Tenant Replication' on Storage Accounts is Disabled (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_7(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.7",
        title="Ensure 'Cross Tenant Replication' on Storage Accounts is Disabled",
        section="9 Storage Accounts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "``allowCrossTenantReplication`` must be false so that object replication objects "
            "cannot be configured to push data to storage accounts in other Entra ID tenants."
        ),
        rationale=(
            "Cross-tenant replication is a powerful data-exfiltration primitive: a compromised "
            "contributor role can silently mirror blobs to an attacker-controlled tenant."
        ),
        impact=(
            "Only intra-tenant object replication is permitted; legitimate cross-tenant flows "
            "must be redesigned."
        ),
        audit_procedure=(
            "ARM: GET each storage account — properties.allowCrossTenantReplication must be false."
        ),
        remediation=(
            "az storage account update --name <sa> --allow-cross-tenant-replication false."
        ),
        default_value="Enabled.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/blobs/object-replication-overview",
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
            if sa.get("properties", {}).get("allowCrossTenantReplication") is not False
        ]
        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) allow cross-tenant replication: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) block cross-tenant replication.",
            evidence=evidence,
        )
