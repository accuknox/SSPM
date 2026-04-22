"""CIS Azure 9.3.3.1 – Ensure that 'Default to Microsoft Entra authorization in the Azure portal' is Set to 'Enabled' (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_9_3_3_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-9.3.3.1",
        title="Ensure that 'Default to Microsoft Entra authorization in the Azure portal' is Set to 'Enabled'",
        section="9.3.3 Identity and Access Management",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Storage accounts should default to Microsoft Entra ID (formerly Azure AD) "
            "authorization in the Azure portal. This setting ensures that Azure portal access "
            "to storage data uses identity-based authorization rather than storage account keys."
        ),
        rationale=(
            "Defaulting to Entra ID authorization in the portal enforces RBAC-based access "
            "rather than key-based access, providing audit trails, conditional access support, "
            "and integration with identity governance policies."
        ),
        impact="Users accessing storage data through the portal must have appropriate RBAC roles "
               "assigned (e.g., Storage Blob Data Reader/Contributor).",
        audit_procedure=(
            "ARM: GET each storage account — "
            "properties.defaultToOAuthAuthentication must be true."
        ),
        remediation=(
            "az storage account update --name <name> --default-auth-entra-id true "
            "(or via portal: Storage account → Configuration → "
            "Default to Microsoft Entra authorization: Enabled → Save)."
        ),
        default_value="Storage accounts default to key-based authorization in the portal.",
        references=[
            "https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-data-operations-portal",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.1", title="Establish and Maintain an Inventory of Accounts", ig1=True, ig2=True, ig3=True),
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
            if not (sa.get("properties") or {}).get("defaultToOAuthAuthentication", False):
                offenders.append(name)

        evidence = [Evidence(source="arm:storageAccounts", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} storage account(s) do not default to Entra ID authorization: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(accounts)} storage account(s) default to Entra ID authorization.",
            evidence=evidence,
        )
