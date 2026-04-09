"""
CIS MS365 5.3.2 (L2) – Ensure access reviews for guest users are configured
(Automated)

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
class CIS_5_3_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.3.2",
        title="Ensure access reviews for guest users are configured",
        section="5.3 Privileged Identity Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Access reviews should be configured for guest users to ensure that "
            "guest access is periodically reviewed and revoked when no longer needed."
        ),
        rationale=(
            "Guest users are often added for specific projects and may retain access "
            "long after it is no longer needed. Regular access reviews ensure guest "
            "access is periodically validated and inappropriate access is removed."
        ),
        impact=(
            "Reviewers (typically group owners or managers) must periodically review "
            "and approve or deny guest access. This requires time commitment from reviewers."
        ),
        audit_procedure=(
            "GET /identityGovernance/accessReviews/definitions\n"
            "Look for active access review definitions that:\n"
            "  • Target guest users (userType = 'Guest')\n"
            "  • Are scheduled (not one-time)\n"
            "  • Are in 'active' state"
        ),
        remediation=(
            "Microsoft Entra admin center → Identity governance > Access reviews.\n"
            "Create a new access review:\n"
            "  • Scope: Guest users\n"
            "  • Recurrence: Quarterly or more frequent\n"
            "  • Reviewers: Group owners or specific reviewers\n"
            "  • Auto-apply results: enabled"
        ),
        default_value="No access reviews configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview",
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
        tags=["identity", "access-reviews", "guests", "governance", "e5"],
    )

    async def check(self, data: CollectedData):
        access_reviews = data.get("access_reviews")
        if access_reviews is None:
            return self._skip(
                "Could not retrieve access reviews. "
                "Requires AccessReview.Read.All permission."
            )

        # Look for reviews targeting guest users
        guest_reviews = []
        for review in (access_reviews or []):
            scope = review.get("scope") or {}
            query = scope.get("query", "") or ""
            scope_type = scope.get("@odata.type", "") or ""

            # Check if it targets guests
            if "guest" in query.lower() or "userType eq 'Guest'" in query:
                if review.get("status", "").lower() in ("active", "inProgress", "notStarted"):
                    guest_reviews.append(review)

        if guest_reviews:
            return self._pass(
                f"{len(guest_reviews)} active access review(s) targeting guest users found.",
                evidence=[
                    Evidence(
                        source="graph/identityGovernance/accessReviews/definitions",
                        data=[
                            {
                                "id": r.get("id"),
                                "displayName": r.get("displayName"),
                                "status": r.get("status"),
                            }
                            for r in guest_reviews
                        ],
                        description="Active access reviews for guest users.",
                    )
                ],
            )

        total_reviews = len(access_reviews or [])
        return self._fail(
            f"No active access reviews targeting guest users found. "
            f"Total access reviews in tenant: {total_reviews}.",
            evidence=[
                Evidence(
                    source="graph/identityGovernance/accessReviews/definitions",
                    data={"totalReviews": total_reviews},
                    description="Access reviews checked for guest user targeting.",
                )
            ],
        )
