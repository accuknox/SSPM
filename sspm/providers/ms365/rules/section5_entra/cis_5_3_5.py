"""
CIS MS365 5.3.5 (L2) – Ensure approval is required for Privileged Role
Administrator activation (Automated)

Profile Applicability: E5 Level 2
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    Evidence,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_5_3_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.3.5",
        title="Ensure approval is required for Privileged Role Administrator activation",
        section="5.3 Privileged Identity Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "The Privileged Role Administrator role in PIM should require approval "
            "before activation. This role can modify all other PIM role settings, "
            "making it critical to protect."
        ),
        rationale=(
            "The Privileged Role Administrator can grant themselves or others "
            "any directory role. Requiring approval for its activation prevents "
            "unauthorized privilege escalation."
        ),
        impact=(
            "Privileged Role Administrator activation will require an approver, "
            "adding latency to PIM management tasks."
        ),
        audit_procedure=(
            "GET /policies/roleManagementPolicies\n"
            "  Filter for Privileged Role Administrator role\n"
            "  Check approval rules: isApprovalRequired = true"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity governance > PIM > "
            "Microsoft Entra roles > Privileged Role Administrator > Role settings:\n"
            "  • Enable approval for activation\n"
            "  • Add approvers"
        ),
        default_value="Approval is not required for role activation by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.4",
                title="Restrict Administrator Privileges to Dedicated Administrator Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "pim", "privileged-role-admin", "approval", "e5"],
    )

    async def check(self, data: CollectedData):
        role_mgmt_policies = data.get("role_management_policies")
        if role_mgmt_policies is None:
            return self._skip(
                "Could not retrieve role management policies. "
                "Requires RoleManagement.Read.All permission."
            )

        if not role_mgmt_policies:
            return self._skip("No role management policies found.")

        # Look for Privileged Role Administrator policy
        pra_policy = None
        for policy in role_mgmt_policies:
            description = policy.get("description", "").lower()
            display_name = policy.get("displayName", "").lower()
            if "privileged role administrator" in description or "privileged role administrator" in display_name:
                pra_policy = policy
                break

        if pra_policy is None:
            return self._manual(
                "Privileged Role Administrator PIM policy not found. Verify manually:\n"
                "  Microsoft Entra admin center → Identity governance > PIM > "
                "Microsoft Entra roles > Privileged Role Administrator > Role settings"
            )

        rules = pra_policy.get("rules") or []
        approval_required = False
        for rule in rules:
            if rule.get("@odata.type", "").lower().endswith("approvalrule"):
                settings = rule.get("setting") or {}
                if settings.get("isApprovalRequired"):
                    approval_required = True
                    break

        evidence = [
            Evidence(
                source="graph/policies/roleManagementPolicies",
                data={"policyId": pra_policy.get("id"), "approvalRequired": approval_required},
                description="Privileged Role Administrator PIM policy.",
            )
        ]

        if approval_required:
            return self._pass(
                "Approval is required for Privileged Role Administrator activation.",
                evidence=evidence,
            )

        return self._fail(
            "Approval is not required for Privileged Role Administrator activation in PIM.",
            evidence=evidence,
        )
