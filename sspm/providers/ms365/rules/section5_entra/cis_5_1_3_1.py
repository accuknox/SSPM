"""
CIS MS365 5.1.3.1 (L2) – Ensure a dynamic group for guest users is created
(Automated)

Profile Applicability: E3 Level 2, E5 Level 2
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
class CIS_5_1_3_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.3.1",
        title="Ensure a dynamic group for guest users is created",
        section="5.1.3 Groups",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "A dynamic group should be created that automatically includes all "
            "guest users in the tenant. This group can then be used in Conditional "
            "Access policies and access reviews to manage guest user access."
        ),
        rationale=(
            "A dynamic group for guests enables consistent policy enforcement across "
            "all guest accounts without manual group maintenance. This group can be "
            "used as the target for stricter Conditional Access policies and access reviews."
        ),
        impact=(
            "Creating a dynamic group requires Azure AD Premium P1 licensing. "
            "The group membership is automatically maintained by the dynamic membership rule."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /groups?$filter=membershipRule ne null&$select=id,displayName,"
            "membershipRule,membershipRuleProcessingState\n"
            "  Look for a group with membershipRule that includes "
            "user.userType -eq 'Guest'."
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Groups > New group.\n"
            "  • Group type: Security or Microsoft 365\n"
            "  • Membership type: Dynamic User\n"
            "  • Dynamic query: user.userType -eq 'Guest'\n\n"
            "This group can then be used in Conditional Access and access reviews."
        ),
        default_value="No dynamic group for guests exists by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.1",
                title="Establish an Access Granting Process",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "groups", "guests", "dynamic-membership"],
    )

    async def check(self, data: CollectedData):
        groups = data.get("groups")
        if groups is None:
            return self._skip(
                "Could not retrieve groups data. "
                "Requires Group.Read.All permission."
            )

        # Look for a dynamic group targeting guests
        guest_dynamic_groups = []
        for group in groups:
            rule = group.get("membershipRule") or ""
            if (
                "userType" in rule
                and ("Guest" in rule or "guest" in rule)
                and group.get("membershipRuleProcessingState") == "On"
            ):
                guest_dynamic_groups.append(group)

        if guest_dynamic_groups:
            return self._pass(
                f"Dynamic group(s) targeting guest users found: "
                + ", ".join(g.get("displayName", g["id"]) for g in guest_dynamic_groups),
                evidence=[
                    Evidence(
                        source="graph/groups",
                        data=[
                            {
                                "id": g.get("id"),
                                "displayName": g.get("displayName"),
                                "membershipRule": g.get("membershipRule"),
                            }
                            for g in guest_dynamic_groups
                        ],
                        description="Dynamic groups for guest users.",
                    )
                ],
            )

        return self._fail(
            "No dynamic group targeting guest users found. "
            "Guest users cannot be consistently targeted by policies.",
            evidence=[
                Evidence(
                    source="graph/groups",
                    data={"totalGroupsChecked": len(groups)},
                    description="No dynamic groups with guest membership rules found.",
                )
            ],
        )
