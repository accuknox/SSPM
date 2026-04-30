"""CIS Azure 5.3.2 – Ensure that Guest Users are Reviewed on a Regular Basis (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_3_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.3.2",
        title="Ensure that Guest Users are Reviewed on a Regular Basis",
        section="5.3 Periodic Identity Reviews",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Guest users invited into Microsoft Entra ID should be reviewed periodically to "
            "ensure that only current, authorized external collaborators retain access to the "
            "tenant and its resources."
        ),
        rationale=(
            "Guest accounts that are no longer needed represent unnecessary access paths. "
            "Regular reviews identify stale accounts that should be removed, reducing the "
            "attack surface and meeting least-privilege requirements."
        ),
        impact=(
            "Requires a scheduled review process. Microsoft Entra ID Access Reviews can automate "
            "periodic reviews of guest users with auto-removal of accounts that reviewers do not "
            "confirm."
        ),
        audit_procedure=(
            "Entra admin center → Identity Governance → Access Reviews: verify that a recurring "
            "access review exists targeting guest users. Additionally review the guest user list "
            "under Users → All users (filter: Guest) for stale accounts."
        ),
        remediation=(
            "Create a recurring Access Review in Entra Identity Governance targeting all guest "
            "users or specific groups. Configure auto-apply to remove access for unreviewed "
            "accounts. Remove guest accounts that no longer require access."
        ),
        default_value="No automatic review process for guest users exists by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.1", title="Establish and Maintain an Inventory of Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Regular review of guest users requires a manual process or configured Access Reviews "
            "in Entra Identity Governance; verify via Entra admin center → Identity Governance → "
            "Access Reviews."
        )
