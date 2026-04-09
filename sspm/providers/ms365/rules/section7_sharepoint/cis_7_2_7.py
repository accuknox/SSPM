"""
CIS MS365 7.2.7 (L1) – Ensure the default sharing link type is restricted
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


@registry.rule
class CIS_7_2_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.7",
        title="Ensure the default sharing link type is not set to 'Anyone with the link'",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "The default sharing link type in SharePoint and OneDrive should not "
            "be set to 'Anyone with the link' (anonymous access). The default "
            "should be set to 'Only people in your organization' or a more "
            "restrictive option."
        ),
        rationale=(
            "When users create sharing links, the default link type pre-selects "
            "the sharing mode. If the default is 'Anyone', users may inadvertently "
            "create anonymous sharing links without considering the security implications."
        ),
        impact="Users will need to explicitly select 'Anyone' links if needed.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check: defaultSharingLinkType\n"
            "  0 = None (users choose)\n"
            "  1 = Direct (specific people)\n"
            "  2 = Internal (organization)\n"
            "  3 = Anonymous (Anyone) - non-compliant"
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Set default link type to 'Only people in your organization'.\n\n"
            "PowerShell:\n"
            "  Set-SPOTenant -DefaultSharingLinkType Internal"
        ),
        default_value="Default sharing link type may be set to Anyone.",
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
        tags=["sharepoint", "sharing-links", "anonymous", "data-protection"],
    )

    async def check(self, data: CollectedData):
        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip("Could not retrieve SharePoint settings.")

        default_link_type = settings.get("defaultSharingLinkType")

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={"defaultSharingLinkType": default_link_type},
                description="SharePoint default sharing link type.",
            )
        ]

        # 3 = Anonymous (Anyone with the link) = non-compliant
        if default_link_type == 3:
            return self._fail(
                "Default sharing link type is 'Anyone with the link' (anonymous). "
                "This should be changed to a more restrictive setting.",
                evidence=evidence,
            )

        link_type_names = {0: "None (user choice)", 1: "Direct (specific people)", 2: "Internal (organization)"}
        if default_link_type in link_type_names:
            return self._pass(
                f"Default sharing link type is: {link_type_names[default_link_type]} "
                f"(defaultSharingLinkType = {default_link_type})",
                evidence=evidence,
            )

        return self._manual(
            f"Default sharing link type = {default_link_type}. Verify manually:\n"
            "  SharePoint admin center → Policies > Sharing"
        )
