"""CIS Azure 5.5 – Ensure that a Custom Role is Assigned Permissions for Administering Resource Locks (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.5",
        title="Ensure that a Custom Role is Assigned Permissions for Administering Resource Locks",
        section="5 Identity Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "A dedicated custom RBAC role with only the permissions required to manage resource "
            "locks (Microsoft.Authorization/locks/*) should be created and assigned to the "
            "personnel responsible for administering locks on mission-critical resources."
        ),
        rationale=(
            "Resource locks prevent accidental deletion or modification of critical Azure "
            "resources. Restricting lock administration to a dedicated role ensures that only "
            "authorized personnel can remove or modify locks, reducing the risk of accidental "
            "or unauthorized removal of data-protection controls."
        ),
        impact=(
            "Creating and maintaining a custom role requires additional RBAC administration "
            "overhead. Assignments should be limited to a small number of trusted administrators."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/providers/Microsoft.Authorization/roleDefinitions?$filter=type eq 'CustomRole' — "
            "verify that at least one custom role exists with Microsoft.Authorization/locks/* in "
            "its actions and that this role is assigned to appropriate personnel."
        ),
        remediation=(
            "Create a custom RBAC role with the action Microsoft.Authorization/locks/* and assign "
            "it to the administrators responsible for managing resource locks. Remove lock "
            "administration permissions from overly broad roles where possible."
        ),
        default_value="No custom role for resource lock administration exists by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.4", title="Restrict Administrator Privileges to Dedicated Administrator Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying that a custom role exists for resource lock administration and is correctly "
            "assigned requires manual review of custom RBAC role definitions and assignments in "
            "the Azure portal or via ARM."
        )
