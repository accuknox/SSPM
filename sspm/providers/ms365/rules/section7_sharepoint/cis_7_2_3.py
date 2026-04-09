"""
CIS MS365 7.2.3 (L1) – Ensure external content sharing is restricted (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

SharePoint and OneDrive external sharing must be restricted to prevent
accidental or intentional data exposure to external users.
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

# Sharing capability values (from Graph API)
# 0 = Disabled, 1 = ExternalUserAndGuestSharing, 2 = ExternalUserSharingOnly,
# 3 = ExistingExternalUserSharingOnly
_SHARING_DISABLED = 0
_SHARING_EXTERNAL_GUEST = 1  # anyone with the link
_SHARING_EXTERNAL_USERS = 2  # new and existing external users
_SHARING_EXISTING_ONLY = 3   # existing external users only

_COMPLIANT_VALUES = {_SHARING_DISABLED, _SHARING_EXISTING_ONLY}


@registry.rule
class CIS_7_2_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.3",
        title="Ensure external content sharing is restricted",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "SharePoint and OneDrive tenant-level external sharing settings should be "
            "restricted to 'Existing external users' or 'Only people in your "
            "organisation' to prevent unrestricted data exposure via sharing links."
        ),
        rationale=(
            "Unrestricted external sharing allows any user to share files with "
            "anyone, including unauthenticated 'Anyone with the link' access.  "
            "This significantly increases the risk of unintended data disclosure."
        ),
        impact=(
            "Users will be unable to share content with new external users without "
            "additional configuration.  Business processes relying on anonymous sharing "
            "links will need to be reviewed."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /admin/sharepoint/settings\n"
            "  Check: sharingCapability should be 0 (Disabled) or 3 (Existing users only).\n\n"
            "Or in SharePoint admin center:\n"
            "  https://admin.microsoft.com/sharepoint → Policies > Sharing.\n"
            "  External sharing slider should be at most 'Existing external users'."
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Set external sharing for SharePoint and OneDrive to 'Existing external "
            "users' or 'Only people in your organization'.\n\n"
            "PowerShell: Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly"
        ),
        default_value="ExternalUserAndGuestSharing (any external user, guest links enabled).",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off",
            "https://learn.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant",
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

        sharing_cap = settings.get("sharingCapability")
        if sharing_cap is None:
            return self._manual(
                "SharePoint settings retrieved but sharingCapability field not found. "
                "Verify manually in SharePoint admin center → Policies > Sharing."
            )

        if sharing_cap in _COMPLIANT_VALUES:
            cap_names = {0: "Disabled", 3: "ExistingExternalUserSharingOnly"}
            return self._pass(
                f"SharePoint external sharing is restricted: "
                f"sharingCapability = {cap_names.get(sharing_cap, sharing_cap)}",
                evidence=[
                    Evidence(
                        source="graph/admin/sharepoint/settings",
                        data={"sharingCapability": sharing_cap},
                        description="SharePoint tenant sharing capability value.",
                    )
                ],
            )

        cap_names = {
            1: "ExternalUserAndGuestSharing (Anyone links)",
            2: "ExternalUserSharingOnly (new + existing external users)",
        }
        return self._fail(
            f"SharePoint external sharing is too permissive: "
            f"sharingCapability = {cap_names.get(sharing_cap, sharing_cap)}",
            evidence=[
                Evidence(
                    source="graph/admin/sharepoint/settings",
                    data=settings,
                    description="Current SharePoint tenant settings.",
                )
            ],
        )
