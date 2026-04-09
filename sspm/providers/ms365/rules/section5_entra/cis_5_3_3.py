"""
CIS MS365 5.3.3 (L2) – Ensure access reviews for privileged roles are
configured (Automated)

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
class CIS_5_3_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.3.3",
        title="Ensure access reviews for privileged roles are configured",
        section="5.3 Privileged Identity Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Access reviews should be configured for privileged roles (especially "
            "Global Administrator) to ensure that role assignments are periodically "
            "reviewed and excessive access is removed."
        ),
        rationale=(
            "Privileged role assignments can accumulate over time as users change "
            "roles or leave the organization. Regular access reviews ensure that "
            "privileged access is periodically validated."
        ),
        impact=(
            "Role assignment reviewers must periodically review and confirm "
            "or deny existing role assignments."
        ),
        audit_procedure=(
            "GET /identityGovernance/accessReviews/definitions\n"
            "Look for access reviews targeting directory roles:\n"
            "  • scope.@odata.type referencing directoryRoles\n"
            "  • Status: active or scheduled"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity governance > Access reviews.\n"
            "Create access reviews for:\n"
            "  • Global Administrator\n"
            "  • Privileged Role Administrator\n"
            "  • Other high-privilege roles\n"
            "Set recurrence to quarterly or more frequent."
        ),
        default_value="No access reviews for privileged roles by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-create-roles-and-resource-roles-review",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.1",
                title="Establish and Maintain an Inventory of Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "access-reviews", "privileged-roles", "governance", "e5"],
    )

    async def check(self, data: CollectedData):
        access_reviews = data.get("access_reviews")
        if access_reviews is None:
            return self._skip(
                "Could not retrieve access reviews. "
                "Requires AccessReview.Read.All permission."
            )

        # Look for reviews targeting privileged directory roles
        role_reviews = []
        for review in (access_reviews or []):
            scope = review.get("scope") or {}
            scope_type = scope.get("@odata.type", "") or ""
            query = scope.get("query", "") or ""

            # Check if scope targets directory roles
            is_role_review = (
                "directoryRole" in scope_type.lower()
                or "roleDefinition" in query
                or "/roleAssignments" in query
            )

            if is_role_review and review.get("status", "").lower() not in ("completed", "stopped"):
                role_reviews.append(review)

        if role_reviews:
            return self._pass(
                f"{len(role_reviews)} active access review(s) targeting privileged roles found.",
                evidence=[
                    Evidence(
                        source="graph/identityGovernance/accessReviews/definitions",
                        data=[
                            {
                                "id": r.get("id"),
                                "displayName": r.get("displayName"),
                                "status": r.get("status"),
                            }
                            for r in role_reviews
                        ],
                        description="Active access reviews for privileged roles.",
                    )
                ],
            )

        total_reviews = len(access_reviews or [])
        return self._fail(
            f"No active access reviews targeting privileged roles found. "
            f"Total access reviews in tenant: {total_reviews}.",
        )
