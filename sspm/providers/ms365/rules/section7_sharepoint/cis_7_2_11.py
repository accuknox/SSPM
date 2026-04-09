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
        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip("Could not retrieve SharePoint settings.")

        default_link_permission = settings.get("defaultLinkPermission")

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={"defaultLinkPermission": default_link_permission},
                description="SharePoint default link permission setting.",
            )
        ]

        # 1 = View, 2 = Edit
        if default_link_permission == 1:
            return self._pass(
                "Default sharing link permission is 'View' (defaultLinkPermission = 1).",
                evidence=evidence,
            )

        if default_link_permission == 2:
            return self._fail(
                "Default sharing link permission is 'Edit' (defaultLinkPermission = 2). "
                "Should be set to 'View'.",
                evidence=evidence,
            )

        return self._manual(
            f"Default link permission = {default_link_permission}. Verify manually:\n"
            "  SharePoint admin center → Policies > Sharing\n"
            "  Check default link permission"
        )
