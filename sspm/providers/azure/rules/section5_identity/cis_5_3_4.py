"""CIS Azure 5.3.4 – Ensure that All 'Privileged' Role Assignments are Periodically Reviewed (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_3_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.3.4",
        title="Ensure that All 'Privileged' Role Assignments are Periodically Reviewed",
        section="5.3 Periodic Identity Reviews",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "All privileged role assignments in Microsoft Entra ID and Azure RBAC should be "
            "reviewed on a periodic basis to ensure that only the right individuals hold "
            "elevated permissions."
        ),
        rationale=(
            "Over time, privileged role assignments accumulate as organizational roles change. "
            "Regular reviews prevent privilege creep, ensuring that former employees, contractors, "
            "or service accounts do not retain unnecessary elevated access."
        ),
        impact=(
            "Requires a scheduled review cadence. Microsoft Entra Privileged Identity Management "
            "(PIM) access reviews can automate this process for Entra ID roles, while Azure RBAC "
            "access reviews handle subscription-level roles."
        ),
        audit_procedure=(
            "Entra admin center → Identity Governance → Access Reviews: verify recurring reviews "
            "exist for privileged Entra ID roles (e.g., Global Administrator, Privileged Role "
            "Administrator) and Azure RBAC roles (Owner, Contributor) at the subscription level."
        ),
        remediation=(
            "Configure recurring Access Reviews in Entra Identity Governance targeting all "
            "privileged roles. Enable PIM for Entra ID roles and configure periodic access reviews "
            "within PIM. Remove role assignments that are no longer needed after each review."
        ),
        default_value="No periodic review process for privileged role assignments is configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-create-azure-ad-roles-and-resource-roles-review",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.1", title="Establish and Maintain an Inventory of Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Periodic review of privileged role assignments requires configured Access Reviews in "
            "Entra Identity Governance or PIM; verify via Entra admin center → Identity Governance "
            "→ Access Reviews."
        )
