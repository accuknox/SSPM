"""
CIS MS365 1.2.1 (L2) – Ensure that only organizationally approved public groups
exist (Automated)

Profile Applicability: E3 Level 2, E5 Level 2

Microsoft 365 (Unified) Groups set to 'Public' visibility are accessible to all
users in the organisation without requiring membership approval.
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
class CIS_1_2_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.2.1",
        title="Ensure that only organizationally approved public groups exist",
        section="1.2 Groups",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Microsoft 365 Groups with 'Public' visibility allow any tenant user "
            "to join and access group content (email, files, calendar) without "
            "owner approval. Groups should use 'Private' visibility unless there "
            "is a specific business justification for public access."
        ),
        rationale=(
            "Public groups expose sensitive business information to all employees "
            "by default. Restricting groups to 'Private' ensures that only "
            "approved members can access group content."
        ),
        impact=(
            "Changing existing public groups to private will prevent non-members "
            "from joining without owner approval and may disrupt users who relied "
            "on self-service join functionality."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /groups?$filter=groupTypes/any(c:c eq 'Unified')"
            "&$select=id,displayName,visibility&$top=999\n"
            "  Check visibility field for each group.\n"
            "  Any group with visibility = 'Public' is potentially non-compliant "
            "(unless organisationally approved)."
        ),
        remediation=(
            "For each public group that lacks business justification:\n"
            "  1. Microsoft 365 admin center → Groups > Active groups.\n"
            "  2. Select the group → Settings → Privacy → change to Private.\n"
            "  Or via PowerShell:\n"
            "  Set-UnifiedGroup -Identity <group> -AccessType Private"
        ),
        default_value="Groups can be created as Public by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/solutions/groups-teams-access-governance",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.3",
                title="Configure Data Access Control Lists",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["groups", "m365-groups", "access-control", "data-protection"],
    )

    async def check(self, data: CollectedData):
        groups = data.get("groups")
        if groups is None:
            return self._skip(
                "Could not retrieve groups data. Requires Group.Read.All permission."
            )

        # Filter to M365 (Unified) groups only
        unified_groups = [
            g for g in groups if "Unified" in (g.get("groupTypes") or [])
        ]
        public_groups = [
            g for g in unified_groups if g.get("visibility") == "Public"
        ]

        if not public_groups:
            return self._pass(
                f"No public Microsoft 365 Groups found. "
                f"Checked {len(unified_groups)} Unified Groups.",
                evidence=[
                    Evidence(
                        source="graph/groups",
                        data={"unifiedGroupCount": len(unified_groups), "publicGroupCount": 0},
                        description="All M365 Groups are Private or undisclosed.",
                    )
                ],
            )

        return self._fail(
            f"{len(public_groups)} public Microsoft 365 Group(s) found. "
            "Verify each is organisationally approved.",
            evidence=[
                Evidence(
                    source="graph/groups",
                    data=[
                        {"id": g.get("id"), "displayName": g.get("displayName"), "visibility": "Public"}
                        for g in public_groups
                    ],
                    description="Public M365 Groups that require review.",
                )
            ],
        )
