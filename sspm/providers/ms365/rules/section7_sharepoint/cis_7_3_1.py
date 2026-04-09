"""
CIS MS365 7.3.1 (L1) – Ensure SharePoint infected files cannot be downloaded
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
class CIS_7_3_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.3.1",
        title="Ensure SharePoint infected files are prevented from being downloaded",
        section="7.3 Security",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "SharePoint Online should be configured to prevent users from downloading "
            "files that have been detected as infected with malware."
        ),
        rationale=(
            "Allowing downloads of infected files can spread malware to user devices. "
            "Blocking infected file downloads protects users from accidentally "
            "downloading and executing malware."
        ),
        impact="Users will not be able to download files detected as infected.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check: disallowInfectedFileDownload = true"
        ),
        remediation=(
            "SharePoint admin center → Settings > Allow or prevent the download of infected files.\n\n"
            "PowerShell:\n"
            "  Set-SPOTenant -DisallowInfectedFileDownload $true"
        ),
        default_value="Infected file downloads may be allowed by default.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/virus-detection-in-sharepoint-and-onedrive",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="10.5",
                title="Enable Anti-Exploitation Features",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["sharepoint", "malware", "infected-files", "antivirus"],
    )

    async def check(self, data: CollectedData):
        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip("Could not retrieve SharePoint settings.")

        disallow_infected = settings.get("disallowInfectedFileDownload")

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={"disallowInfectedFileDownload": disallow_infected},
                description="SharePoint infected file download restriction.",
            )
        ]

        if disallow_infected is True:
            return self._pass(
                "Infected file downloads are blocked in SharePoint "
                "(disallowInfectedFileDownload = true).",
                evidence=evidence,
            )

        if disallow_infected is False:
            return self._fail(
                "Infected file downloads are allowed in SharePoint "
                "(disallowInfectedFileDownload = false).",
                evidence=evidence,
            )

        return self._manual(
            "Infected file download setting not found. Verify manually:\n"
            "  SharePoint admin center → Settings\n"
            "  Check infected file download settings"
        )
