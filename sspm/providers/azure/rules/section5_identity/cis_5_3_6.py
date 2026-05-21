"""CIS Azure 5.3.6 – Ensure 'Tenant Creator' Role Assignments are Periodically Reviewed (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_3_6(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.3.6",
        title="Ensure 'Tenant Creator' Role Assignments are Periodically Reviewed",
        section="5.3 Periodic Identity Reviews",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "The 'Tenant Creator' Entra ID role grants the ability to create new Microsoft Entra "
            "tenants. Assignments to this role should be reviewed periodically to ensure only "
            "authorized individuals retain this sensitive capability."
        ),
        rationale=(
            "The ability to create new tenants can be used to establish shadow IT environments "
            "outside the control of the organization's security team. Minimizing and regularly "
            "reviewing this role reduces the risk of unauthorized tenant sprawl."
        ),
        impact=(
            "Removing unneeded Tenant Creator role assignments has no operational impact on "
            "existing tenants or their resources."
        ),
        audit_procedure=(
            "Entra admin center → Roles and administrators → Tenant Creator: review all current "
            "role assignments and confirm each is still required and authorized."
        ),
        remediation=(
            "Entra admin center → Roles and administrators → Tenant Creator → remove any "
            "assignments that are no longer required. Consider using PIM to require just-in-time "
            "activation for this role."
        ),
        default_value="No periodic review process is configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#tenant-creator",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.1", title="Establish and Maintain an Inventory of Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Tenant Creator role assignments must be reviewed manually via Entra admin center → "
            "Roles and administrators → Tenant Creator."
        )
