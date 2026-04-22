"""CIS Azure 5.3.3 – Ensure That Use of the 'User Access Administrator' Role is Restricted (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


# Built-in "User Access Administrator" role definition ID
UAA_ROLE_ID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"


@registry.rule
class CIS_5_3_3(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.3.3",
        title="Ensure That Use of the 'User Access Administrator' Role is Restricted",
        section="5.3 Periodic Identity Reviews",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "The User Access Administrator role can manage user access to Azure resources "
            "and elevate access to tenant root. It should be assigned to as few principals "
            "as possible and preferably only eligibly through PIM."
        ),
        rationale=(
            "A principal holding this role can grant itself or anyone else any other role on any "
            "resource within the subscription — effectively a root escalation path."
        ),
        impact="No impact if the role is unused; normal access management still works.",
        audit_procedure=(
            "ARM: list role assignments at subscription scope and filter for role definition "
            f"{UAA_ROLE_ID} (User Access Administrator). Expect zero active assignments."
        ),
        remediation=(
            "Remove permanent User Access Administrator assignments. Use Privileged Identity "
            "Management to make the role eligible, time-bound, and approval-gated."
        ),
        default_value="No User Access Administrator assignments exist by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.8", title="Define and Maintain Role-Based Access Control", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        assignments = data.get("role_assignments")
        if assignments is None:
            return self._skip("Role assignments could not be retrieved.")

        uaa_assignments = [
            a for a in assignments
            if (a.get("properties", {}).get("roleDefinitionId") or "").lower().endswith(
                UAA_ROLE_ID
            )
        ]

        evidence = [Evidence(
            source="arm:roleAssignments",
            data={"count": len(uaa_assignments)},
        )]
        if not uaa_assignments:
            return self._pass(
                "No active User Access Administrator assignments at subscription scope.",
                evidence=evidence,
            )
        return self._fail(
            f"{len(uaa_assignments)} active User Access Administrator assignment(s). "
            "Remove permanent assignments and require PIM elevation instead.",
            evidence=evidence,
        )
