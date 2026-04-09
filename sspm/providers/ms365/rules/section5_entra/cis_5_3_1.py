"""
CIS MS365 5.3.1 (L2) – Ensure Privileged Identity Management is used to
manage roles (Automated)

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
class CIS_5_3_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.3.1",
        title="Ensure Privileged Identity Management is used to manage roles",
        section="5.3 Privileged Identity Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Privileged Identity Management (PIM) should be used to manage "
            "directory role assignments, providing just-in-time (JIT) privileged "
            "access with approval workflows and time limits."
        ),
        rationale=(
            "PIM replaces permanent role assignments with time-limited, just-in-time "
            "access that requires explicit activation. This dramatically reduces the "
            "window of opportunity for attackers who compromise privileged accounts."
        ),
        impact=(
            "Administrators will need to activate their roles before performing "
            "privileged tasks. Permanent assignments should be moved to eligible "
            "assignments in PIM."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/privilegedAccess/aadRoles/roleAssignments\n"
            "  Look for 'Eligible' assignments (not just 'Active' permanent ones)\n\n"
            "Microsoft Entra admin center → Identity governance > Privileged Identity Management"
        ),
        remediation=(
            "1. Enable PIM for the tenant (requires Entra ID P2)\n"
            "2. Configure role settings with activation requirements\n"
            "3. Convert permanent role assignments to eligible assignments\n"
            "4. Require MFA and justification for role activation"
        ),
        default_value="Roles are permanently assigned without PIM by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure",
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
        tags=["identity", "pim", "privileged-access", "jit", "e5"],
    )

    async def check(self, data: CollectedData):
        pim_assignments = data.get("pim_role_assignments")
        if pim_assignments is None:
            return self._skip(
                "Could not retrieve PIM role assignments. "
                "Requires PrivilegedAccess.ReadWrite.AzureAD or Entra ID P2 licensing."
            )

        if not pim_assignments:
            return self._fail(
                "No PIM role assignments found. Roles may be permanently assigned "
                "without using Privileged Identity Management.",
                evidence=[
                    Evidence(
                        source="graph/beta/privilegedAccess/aadRoles/roleAssignments",
                        data=[],
                        description="No PIM role assignments found.",
                    )
                ],
            )

        # Check for eligible (JIT) assignments
        eligible_assignments = [
            a for a in pim_assignments
            if a.get("assignmentState", "").lower() == "eligible"
        ]

        evidence = [
            Evidence(
                source="graph/beta/privilegedAccess/aadRoles/roleAssignments",
                data={
                    "totalAssignments": len(pim_assignments),
                    "eligibleAssignments": len(eligible_assignments),
                },
                description="PIM role assignment summary.",
            )
        ]

        if eligible_assignments:
            return self._pass(
                f"PIM is in use with {len(eligible_assignments)} eligible (JIT) "
                f"assignments out of {len(pim_assignments)} total.",
                evidence=evidence,
            )

        return self._fail(
            f"{len(pim_assignments)} PIM assignments found but none are 'Eligible'. "
            "PIM may not be used for just-in-time access.",
            evidence=evidence,
        )
