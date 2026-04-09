"""
CIS MS365 7.2.4 (L1) – Ensure OneDrive content sharing is restricted
(Automated)

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

_COMPLIANT_SHARING_VALUES = {0, 3}  # Disabled or ExistingExternalUserSharingOnly


@registry.rule
class CIS_7_2_4(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.4",
        title="Ensure OneDrive content sharing is restricted",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "OneDrive sharing should be restricted to existing external users or "
            "disabled entirely to prevent unrestricted sharing of personal files "
            "with unknown external parties."
        ),
        rationale=(
            "Unrestricted OneDrive sharing can result in sensitive personal files "
            "being shared with anyone on the internet. Restricting sharing reduces "
            "the risk of unintended data disclosure."
        ),
        impact="Users will be unable to share OneDrive files with new external users.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check: oneDriveDefaultShareLinkType and sharingCapability for OneDrive"
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Set OneDrive sharing to 'Existing external users' or 'Only people in your organization'."
        ),
        default_value="OneDrive sharing may allow external sharing by default.",
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
        tags=["sharepoint", "onedrive", "sharing", "data-protection"],
    )

    async def check(self, data: CollectedData):
        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip(
                "Could not retrieve SharePoint settings. "
                "Requires SharePoint Administrator role."
            )

        onedrive_sharing = settings.get("oneDriveSharingCapability")
        if onedrive_sharing is None:
            # Fall back to general sharing capability
            onedrive_sharing = settings.get("sharingCapability")

        if onedrive_sharing is None:
            return self._manual(
                "OneDrive sharing capability setting not found. Verify manually:\n"
                "  SharePoint admin center → Policies > Sharing\n"
                "  Check OneDrive sharing level"
            )

        cap_names = {
            0: "Disabled",
            1: "ExternalUserAndGuestSharing (Anyone links)",
            2: "ExternalUserSharingOnly",
            3: "ExistingExternalUserSharingOnly",
        }

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={"oneDriveSharingCapability": onedrive_sharing},
                description="OneDrive sharing capability setting.",
            )
        ]

        if onedrive_sharing in _COMPLIANT_SHARING_VALUES:
            return self._pass(
                f"OneDrive sharing is restricted: {cap_names.get(onedrive_sharing, onedrive_sharing)}",
                evidence=evidence,
            )

        return self._fail(
            f"OneDrive sharing is too permissive: {cap_names.get(onedrive_sharing, onedrive_sharing)}",
            evidence=evidence,
        )
