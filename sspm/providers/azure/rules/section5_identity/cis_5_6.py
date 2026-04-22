"""CIS Azure 5.6 – Ensure that 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' is set to 'Permit no one' (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_6(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.6",
        title="Ensure that 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering Microsoft Entra tenant' is set to 'Permit no one'",
        section="5 Identity Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "The settings 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering "
            "Microsoft Entra tenant' control which users can transfer Azure subscriptions to or from "
            "the tenant. Both settings should be set to 'Permit no one' to prevent unauthorized "
            "subscription transfers."
        ),
        rationale=(
            "Allowing subscriptions to be moved out of the tenant can result in loss of visibility "
            "and control over Azure resources. Allowing subscriptions to enter the tenant from "
            "another can introduce resources with unknown security postures. Restricting both "
            "directions prevents unauthorized transfer of subscriptions."
        ),
        impact=(
            "Legitimate subscription transfers will require explicit authorization from a Global "
            "Administrator. This is an acceptable operational constraint given the security benefit."
        ),
        audit_procedure=(
            "Azure portal → Microsoft Entra ID → Properties → Access management for Azure resources: "
            "verify that 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering "
            "Microsoft Entra tenant' are both set to 'Permit no one'."
        ),
        remediation=(
            "Azure portal → Microsoft Entra ID → Properties → Access management for Azure resources "
            "→ set both 'Subscription leaving Microsoft Entra tenant' and 'Subscription entering "
            "Microsoft Entra tenant' to 'Permit no one' → Save."
        ),
        default_value="Subscription movement is permitted by default to users with appropriate permissions.",
        references=[
            "https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/manage-azure-subscription-policy",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.4", title="Restrict Administrator Privileges to Dedicated Administrator Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Subscription tenant transfer policies are not accessible via Graph or ARM application "
            "permissions; verify manually via Azure portal → Microsoft Entra ID → Properties → "
            "Access management for Azure resources."
        )
