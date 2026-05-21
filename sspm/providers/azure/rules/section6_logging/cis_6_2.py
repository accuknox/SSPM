"""CIS Azure 6.2 – Ensure that Resource Locks are set for Mission-Critical Azure Resources (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_2(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-6.2",
        title="Ensure that Resource Locks are set for Mission-Critical Azure Resources",
        section="6 Management and Governance Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Azure Resource Locks (CanNotDelete or ReadOnly) should be applied to "
            "mission-critical resources such as key infrastructure, storage accounts containing "
            "logs, Key Vaults, and networking components to prevent accidental or unauthorized "
            "deletion or modification."
        ),
        rationale=(
            "Resource locks provide an additional layer of protection against accidental or "
            "malicious deletion and modification. Even users with Owner or Contributor roles "
            "cannot delete or modify locked resources without first removing the lock, providing "
            "an auditable barrier for critical infrastructure changes."
        ),
        impact=(
            "ReadOnly locks prevent write operations on the resource, which may interfere with "
            "normal operations. CanNotDelete locks prevent deletion but allow modifications. "
            "Plan lock types carefully based on the operational requirements of each resource."
        ),
        audit_procedure=(
            "ARM: GET /subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.Authorization/locks "
            "for each mission-critical resource group. Verify that CanNotDelete or ReadOnly locks "
            "are applied to critical resources. Also review at the subscription and resource level."
        ),
        remediation=(
            "Azure portal → navigate to the mission-critical resource → Locks → Add lock → "
            "select lock type (CanNotDelete or ReadOnly) → provide a name and notes → OK. "
            "Alternatively, use Azure Policy to enforce lock requirements at scale."
        ),
        default_value="No resource locks are applied by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="11.1", title="Establish and Maintain a Data Recovery Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying that resource locks are applied to mission-critical resources requires "
            "manual review of lock configurations in the Azure portal or via ARM for each "
            "critical resource and resource group."
        )
