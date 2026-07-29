"""
CIS MS365 7.2.11 (L1) – Ensure the default sharing link permission is set to
View (Automated)

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
class CIS_7_2_11(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.11",
        title="Ensure the default sharing link permission is set to View",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The default permission for sharing links in SharePoint and OneDrive "
            "should be set to 'View' rather than 'Edit'. This ensures users "
            "who create sharing links don't inadvertently grant edit permissions."
        ),
        rationale=(
            "When the default link permission is 'Edit', users can modify shared "
            "content unless the sharer specifically selects 'View'. Setting the "
            "default to 'View' follows the principle of least privilege."
        ),
        impact="Users will need to explicitly select 'Edit' permission when creating sharing links.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check: defaultLinkPermission\n"
            "  1 = View (compliant)\n"
            "  2 = Edit (non-compliant)"
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Set default link permission to 'View'.\n\n"
            "PowerShell:\n"
            "  Set-SPOTenant -DefaultLinkPermission View"
        ),
        default_value="Default link permission is Edit.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/change-default-sharing-link",
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
        tags=["sharepoint", "sharing-links", "permissions", "data-protection"],
    )

    async def check(self, data: CollectedData):
        # DefaultLinkPermission has no Microsoft Graph equivalent —
        # /admin/sharepoint/settings does not expose it.
        settings, skip = self._spo_tenant_or_skip(data, "DefaultLinkPermission")
        if skip is not None:
            return skip

        default_link_permission = settings.get("DefaultLinkPermission")

        evidence = [
            Evidence(
                source="sharepoint/Get-SPOTenant",
                data={"DefaultLinkPermission": default_link_permission},
                description="SharePoint default link permission setting.",
            )
        ]

        # SharingPermissionType enum: None=0, View=1, Edit=2. The script casts
        # it to a string; accept the integer form too.
        names = {0: "None", 1: "View", 2: "Edit"}
        if isinstance(default_link_permission, int) and not isinstance(
            default_link_permission, bool
        ):
            permission = names.get(
                default_link_permission, str(default_link_permission)
            )
        else:
            permission = str(default_link_permission or "")

        if permission == "View":
            return self._pass(
                "Default sharing link permission is 'View'.",
                evidence=evidence,
            )

        return self._fail(
            f"Default sharing link permission is "
            f"'{permission or default_link_permission}'; CIS requires 'View'.",
            evidence=evidence,
        )
