"""
CIS MS365 7.2.6 (L1) – Ensure SharePoint external sharing is managed through
Entra B2B (Automated)

Profile Applicability: E3 Level 1, E5 Level 1
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
class CIS_7_2_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.6",
        title="Ensure SharePoint external sharing is restricted",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "SharePoint external sharing should be configured to restrict sharing "
            "to only authenticated external users. Anonymous 'Anyone' links should "
            "be disabled."
        ),
        rationale=(
            "Anonymous sharing links allow anyone with the link to access content "
            "without authentication. Restricting to authenticated external users "
            "ensures access can be revoked and is attributed to a known identity."
        ),
        impact="'Anyone with the link' sharing links will no longer be available.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check sharingCapability != 1 (not ExternalUserAndGuestSharing which allows Anyone links)"
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Set SharePoint sharing to 'New and existing guests' or more restrictive."
        ),
        default_value="Anyone links may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off",
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
        tags=["sharepoint", "external-sharing", "anonymous-links", "data-protection"],
    )

    async def check(self, data: CollectedData):
        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip("Could not retrieve SharePoint settings.")

        sharing_cap = settings.get("sharingCapability")

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={"sharingCapability": sharing_cap},
                description="SharePoint sharing capability setting.",
            )
        ]

        # 0=Disabled, 1=ExternalUserAndGuestSharing (Anyone), 2=ExternalUserSharingOnly, 3=ExistingOnly
        if sharing_cap == 1:
            return self._fail(
                "SharePoint external sharing allows 'Anyone with link' (anonymous) access "
                "(sharingCapability = 1). Anonymous sharing should be disabled.",
                evidence=evidence,
            )

        if sharing_cap in (0, 2, 3):
            cap_names = {0: "Disabled", 2: "New and existing external users", 3: "Existing external users only"}
            return self._pass(
                f"SharePoint external sharing is appropriately restricted: "
                f"{cap_names.get(sharing_cap, sharing_cap)}",
                evidence=evidence,
            )

        return self._manual(
            f"SharePoint sharing capability = {sharing_cap}. Verify manually:\n"
            "  SharePoint admin center → Policies > Sharing"
        )
