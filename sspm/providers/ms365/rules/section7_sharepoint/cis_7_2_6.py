"""
CIS MS365 7.2.6 (L2) – Ensure SharePoint external sharing is restricted
(Automated)

Profile Applicability: E3 Level 2, E5 Level 2

CIS audits this with ``Get-SPOTenant | fl SharingDomainRestrictionMode,
SharingAllowedDomainList``. Microsoft Graph exposes both properties on
``/admin/sharepoint/settings`` (as ``sharingDomainRestrictionMode`` and
``sharingAllowedDomainList``), so no SharePoint PowerShell session is needed.
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
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.HIGH,
        description=(
            "External sharing in SharePoint and OneDrive should be limited by "
            "domain, so that content can only be shared with an approved list of "
            "external domains. The recommended state is 'Limit external sharing "
            "by domain' > 'Allow only specific domains'."
        ),
        rationale=(
            "Attackers will often attempt to expose sensitive information to "
            "external entities through sharing, and restricting the domains that "
            "users can share documents with will reduce that surface area."
        ),
        impact=(
            "Users will be prevented from sharing documents with domains outside "
            "of the organization unless those domains are on the allow list."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /admin/sharepoint/settings\n"
            "  Check: sharingDomainRestrictionMode = allowList and\n"
            "         sharingAllowedDomainList contains the approved domains.\n\n"
            "Using SharePoint Online PowerShell:\n"
            "  Get-SPOTenant | fl SharingDomainRestrictionMode,SharingAllowedDomainList"
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Expand 'More external sharing settings', check 'Limit external "
            "sharing by domain', and add the approved domains.\n\n"
            "PowerShell:\n"
            "  Set-SPOTenant -SharingDomainRestrictionMode AllowList "
            "-SharingAllowedDomainList \"domain1.com domain2.com\""
        ),
        default_value=(
            "'Limit external sharing by domain' is unchecked "
            "(SharingDomainRestrictionMode: None)."
        ),
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
        if "sharepoint_settings" in (data.errors or {}):
            return self._skip(
                "Could not retrieve SharePoint settings: "
                f"{data.errors.get('sharepoint_settings')}"
            )

        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip(
                "Could not retrieve SharePoint settings. Requires the "
                "SharePointTenantSettings.Read.All application permission."
            )

        # Graph reports these as a string enum ("none" | "allowList" |
        # "blockList") and a list; Get-SPOTenant reports the PascalCase
        # equivalents. Accept either so the rule works from both sources.
        mode = settings.get("sharingDomainRestrictionMode")
        if mode is None:
            mode = settings.get("SharingDomainRestrictionMode")
        domains = (
            settings.get("sharingAllowedDomainList")
            or settings.get("SharingAllowedDomainList")
            or []
        )
        if isinstance(domains, str):
            domains = domains.split()

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={
                    "sharingDomainRestrictionMode": mode,
                    "sharingAllowedDomainList": domains,
                },
                description="SharePoint external sharing domain restriction settings.",
            )
        ]

        mode_name = str(mode).lower() if mode is not None else ""

        if mode_name == "allowlist" and domains:
            return self._pass(
                "External sharing is limited by domain: "
                f"{len(domains)} allowed domain(s) configured "
                f"({', '.join(str(d) for d in domains[:5])}"
                f"{', …' if len(domains) > 5 else ''}).",
                evidence=evidence,
            )

        if mode_name == "allowlist":
            return self._fail(
                "SharingDomainRestrictionMode is 'allowList' but "
                "SharingAllowedDomainList is empty, so no external domain is "
                "actually approved for sharing.",
                evidence=evidence,
            )

        if mode_name == "blocklist":
            return self._fail(
                "External sharing is restricted by a block list "
                "(SharingDomainRestrictionMode = 'blockList'). CIS requires an "
                "allow list of approved domains ('allowList') instead.",
                evidence=evidence,
            )

        return self._fail(
            "External sharing is not limited by domain "
            f"(SharingDomainRestrictionMode = '{mode}'). Content can be shared "
            "with any external domain.",
            evidence=evidence,
        )
