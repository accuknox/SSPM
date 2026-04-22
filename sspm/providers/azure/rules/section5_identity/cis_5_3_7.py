"""CIS Azure 5.3.7 – Ensure All Non-privileged Role Assignments are Periodically Reviewed (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_3_7(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.3.7",
        title="Ensure All Non-privileged Role Assignments are Periodically Reviewed",
        section="5.3 Periodic Identity Reviews",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "All non-privileged role assignments in Microsoft Entra ID and Azure RBAC (e.g., "
            "Reader, Contributor on specific resource groups) should be reviewed on a periodic "
            "basis to confirm they remain necessary and appropriate."
        ),
        rationale=(
            "Non-privileged role assignments accumulate over time as projects change and employees "
            "move between teams. Regular reviews prevent unnecessary access accumulation and "
            "ensure the principle of least privilege is maintained across the organization."
        ),
        impact=(
            "Requires a scheduled review cadence. Microsoft Entra ID Access Reviews can automate "
            "this process. Revoking unnecessary assignments may require users to request access "
            "again through a governed process."
        ),
        audit_procedure=(
            "Entra admin center → Identity Governance → Access Reviews: verify that recurring "
            "reviews exist targeting non-privileged Azure RBAC role assignments and Entra ID "
            "roles such as Reader at various scopes."
        ),
        remediation=(
            "Configure recurring Access Reviews in Entra Identity Governance targeting "
            "non-privileged role assignments at subscription and resource group scopes. Remove "
            "role assignments that reviewers do not confirm as still required."
        ),
        default_value="No periodic review process for non-privileged role assignments is configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.1", title="Establish and Maintain an Inventory of Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Periodic review of non-privileged role assignments requires configured Access Reviews "
            "in Entra Identity Governance; verify via Entra admin center → Identity Governance → "
            "Access Reviews."
        )
