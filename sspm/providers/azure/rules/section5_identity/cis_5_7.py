"""CIS Azure 5.7 – Ensure there are between 2 and 3 Subscription Owners (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


# Built-in "Owner" role definition ID
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"


@registry.rule
class CIS_5_7(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.7",
        title="Ensure there are between 2 and 3 Subscription Owners",
        section="5 Identity Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Each subscription should have between 2 and 3 Owners. One is insufficient for "
            "continuity of operations; four or more dilutes accountability and expands the "
            "privileged account attack surface."
        ),
        rationale=(
            "Multiple owners ensure administrative continuity (e.g. when an owner leaves the "
            "organization). Too many owners, however, broadens the blast radius of a compromise."
        ),
        impact="No operational impact; rebalance Owner assignments as needed.",
        audit_procedure=(
            "ARM: list role assignments at subscription scope with role definition "
            f"{OWNER_ROLE_ID} (Owner). Count unique principal IDs."
        ),
        remediation="Add or remove Owner assignments until the count is between 2 and 3.",
        default_value="The subscription creator is the sole Owner by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.1", title="Establish and Maintain an Inventory of Accounts", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        assignments = data.get("role_assignments")
        if assignments is None:
            return self._skip("Role assignments could not be retrieved.")

        owners: set[str] = set()
        for a in assignments:
            props = a.get("properties", {})
            role_id = (props.get("roleDefinitionId") or "").lower()
            if role_id.endswith(OWNER_ROLE_ID):
                pid = props.get("principalId")
                if pid:
                    owners.add(pid)

        evidence = [Evidence(
            source="arm:roleAssignments",
            data={"owner_count": len(owners)},
        )]
        if 2 <= len(owners) <= 3:
            return self._pass(
                f"Subscription has {len(owners)} Owners (within recommended 2-3).",
                evidence=evidence,
            )
        return self._fail(
            f"Subscription has {len(owners)} Owner(s); recommended range is 2-3.",
            evidence=evidence,
        )
