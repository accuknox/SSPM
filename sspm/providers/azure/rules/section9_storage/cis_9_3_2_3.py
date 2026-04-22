"""CIS Azure 9.3.2.3 – Ensure Default Network Access Rule for Storage Accounts is Deny (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_2_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.2.3",
        title="Ensure Default Network Access Rule for Storage Accounts is Set to Deny",
        section="9 Storage Accounts",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "``networkAcls.defaultAction`` should be ``Deny`` on every storage account — access "
            "must be explicitly granted via IP allow-list or service endpoint / private link."
        ),
        rationale=(
            "A default-allow posture bypasses network hardening and exposes blob/file/queue "
            "endpoints to the entire Internet."
        ),
        impact="Any client not covered by an allow-rule will lose access.",
        audit_procedure=(
            "ARM: GET each storage account — properties.networkAcls.defaultAction must be 'Deny'."
        ),
        remediation=(
            "az storage account update --name <sa> --default-action Deny "
            "(add bypass/IP rules as needed)."
        ),
        default_value="Allow.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security",
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

        offenders: list[str] = []
        for sa in accounts:
            name = sa.get("name", "?")
            acls = sa.get("properties", {}).get("networkAcls", {}) or {}
            default = (acls.get("defaultAction") or "").lower()
            if default != "deny":
                offenders.append(f"{name} ({default or 'allow'})")

        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) default to Allow: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) default to Deny.",
            evidence=evidence,
        )
