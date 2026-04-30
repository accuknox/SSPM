"""CIS Azure 5.3.1 – Ensure that Azure Admin Accounts Are Not Used for Daily Operations (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_3_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.3.1",
        title="Ensure that Azure Admin Accounts Are Not Used for Daily Operations",
        section="5.3 Periodic Identity Reviews",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Accounts with privileged administrative roles in Microsoft Entra ID or Azure RBAC "
            "should not be used for routine, non-administrative tasks such as browsing the web, "
            "reading email, or accessing productivity applications."
        ),
        rationale=(
            "Using privileged accounts for daily operations increases the risk that credentials "
            "are exposed through phishing, malware, or accidental disclosure. Dedicated admin "
            "accounts limit the blast radius of a compromise."
        ),
        impact=(
            "Administrators must maintain separate accounts for privileged and non-privileged "
            "tasks, increasing management overhead but significantly reducing risk."
        ),
        audit_procedure=(
            "Review sign-in logs and Entra ID role assignments. Confirm that accounts holding "
            "privileged roles show sign-in activity only during administrative tasks and not "
            "regular productivity workloads."
        ),
        remediation=(
            "Create dedicated, cloud-only administrator accounts for privileged role assignments. "
            "Remove privileged roles from accounts used for daily operations and enforce the use "
            "of dedicated admin accounts via Conditional Access policies."
        ),
        default_value="No separation of admin and daily-use accounts is enforced by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.4", title="Restrict Administrator Privileges to Dedicated Administrator Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Determining whether admin accounts are used for daily operations requires manual "
            "review of sign-in logs and role assignments in the Entra admin center."
        )
