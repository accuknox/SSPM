"""
CIS MS365 5.3.4 (L2) – Ensure approval is required for Global Administrator
role activation (Automated)

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
class CIS_5_3_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.3.4",
        title="Ensure approval is required for Global Administrator role activation",
        section="5.3 Privileged Identity Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "The Global Administrator role in Privileged Identity Management (PIM) "
            "should require explicit approval before activation. This adds an "
            "additional human verification layer to the most privileged role."
        ),
        rationale=(
            "Requiring approval for Global Administrator activation ensures that a "
            "second person is aware of and approves the activation. This prevents "
            "unauthorized or accidental activation of the highest privilege role."
        ),
        impact=(
            "Global Administrator role activation will require an approver to be "
            "available to approve the request, adding latency to emergency admin access."
        ),
        audit_procedure=(
            "GET /policies/roleManagementPolicies\n"
            "  Filter for Global Administrator role\n"
            "  Check rules for approval settings:\n"
            "  • isApprovalRequired = true\n"
            "  • approvers list is not empty"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity governance > "
            "Privileged Identity Management > Microsoft Entra roles.\n"
            "Select Global Administrator > Role settings:\n"
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
        tags=["identity", "pim", "global-admin", "approval", "e5"],
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

        # Look for Global Administrator policy
        ga_policy = None
        for policy in role_mgmt_policies:
            # The policy may reference the role by name or description
            description = policy.get("description", "").lower()
            display_name = policy.get("displayName", "").lower()
            if "global administrator" in description or "global administrator" in display_name:
                ga_policy = policy
                break

        if ga_policy is None:
            return self._manual(
                "Global Administrator PIM policy not found. Verify manually:\n"
                "  Microsoft Entra admin center → Identity governance > PIM > "
                "Microsoft Entra roles > Global Administrator > Role settings"
            )

        # Check for approval requirement in the rules
        rules = ga_policy.get("rules") or []
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
                data={"policyId": ga_policy.get("id"), "approvalRequired": approval_required},
                description="Global Administrator PIM role management policy.",
            )
        ]

        if approval_required:
            return self._pass(
                "Approval is required for Global Administrator role activation.",
                evidence=evidence,
            )

        return self._fail(
            "Approval is not required for Global Administrator role activation in PIM.",
            evidence=evidence,
        )
