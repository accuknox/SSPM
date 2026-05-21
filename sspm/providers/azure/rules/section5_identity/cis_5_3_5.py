"""CIS Azure 5.3.5 – Ensure Disabled User Accounts do not Have Read, Write, or Owner Permissions (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_3_5(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.3.5",
        title="Ensure Disabled User Accounts do not Have Read, Write, or Owner Permissions",
        section="5.3 Periodic Identity Reviews",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Disabled user accounts in Microsoft Entra ID should have all Azure RBAC role "
            "assignments removed to ensure that dormant identities cannot be re-enabled and "
            "immediately used to access resources."
        ),
        rationale=(
            "Disabled accounts that retain role assignments present a risk: if re-enabled "
            "intentionally or accidentally, the account immediately regains access to all "
            "previously assigned resources without requiring additional authorization steps."
        ),
        impact=(
            "Removing role assignments from disabled accounts may require re-assignment if "
            "accounts are re-enabled for legitimate purposes. Maintain a record of removed "
            "assignments for re-onboarding scenarios."
        ),
        audit_procedure=(
            "Export disabled users from Entra admin center → Users → All users (filter: "
            "Sign-in blocked). Cross-reference each disabled account's object ID against Azure "
            "RBAC role assignments at the subscription and resource group level via ARM or "
            "PowerShell: Get-AzRoleAssignment | Where-Object {disabled account object IDs}."
        ),
        remediation=(
            "For each disabled user account that holds Azure RBAC assignments, remove the "
            "role assignments via the Azure portal (Subscriptions → Access control (IAM) → "
            "Role assignments) or PowerShell: Remove-AzRoleAssignment."
        ),
        default_value="Azure does not automatically remove role assignments when an account is disabled.",
        references=[
            "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-remove",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.3", title="Disable Dormant Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Checking whether disabled accounts hold RBAC permissions requires correlating "
            "Entra ID account status with ARM role assignments; verify manually via the Azure "
            "portal or PowerShell."
        )
