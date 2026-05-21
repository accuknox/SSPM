"""CIS Azure 5.4 – Ensure that No Custom Subscription Administrator Roles Exist (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_5_4(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-5.4",
        title="Ensure that No Custom Subscription Administrator Roles Exist",
        section="5 Identity Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Custom roles with owner-equivalent permissions (``*`` on ``actions`` and no ``notActions``) "
            "provide administrative capabilities that bypass the segregation of duties enforced by "
            "built-in roles."
        ),
        rationale=(
            "Classic/custom subscription administrators with wildcard action scopes are difficult to "
            "audit and can silently grant themselves access across the subscription. Built-in roles "
            "(Owner, Contributor, Reader) should cover standard administrative needs."
        ),
        impact="No impact if no such custom roles exist.",
        audit_procedure=(
            "ARM: list role definitions and flag any ``CustomRole`` whose ``permissions.actions`` "
            "contains ``*``."
        ),
        remediation="Remove or scope down custom roles granting ``*`` actions.",
        default_value="No custom roles exist by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.8", title="Define and Maintain Role-Based Access Control", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        roles = data.get("role_definitions")
        if roles is None:
            return self._skip("Role definitions could not be retrieved.")

        offenders: list[str] = []
        for role in roles:
            props = role.get("properties", {})
            if props.get("type") != "CustomRole":
                continue
            for perm in props.get("permissions", []):
                if "*" in (perm.get("actions") or []):
                    offenders.append(props.get("roleName", role.get("name", "?")))
                    break

        evidence = [Evidence(
            source="arm:roleDefinitions",
            data={"offenders": offenders},
        )]
        if offenders:
            return self._fail(
                f"{len(offenders)} custom role(s) grant wildcard actions: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            "No custom roles grant wildcard subscription-administrator permissions.",
            evidence=evidence,
        )
