"""
CIS MS365 1.3.7 (L2) – Ensure that third-party storage services are restricted
in Microsoft 365 on the web (Manual)

Profile Applicability: E3 Level 2, E5 Level 2
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_1_3_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.7",
        title="Ensure that third-party storage services are restricted in Microsoft 365 on the web",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Microsoft 365 web apps (Word, Excel, PowerPoint Online) can connect "
            "to third-party storage services. This should be restricted to prevent "
            "data from being saved to unapproved cloud storage providers."
        ),
        rationale=(
            "Third-party storage services are not subject to the same governance "
            "and compliance controls as OneDrive. Restricting storage options "
            "ensures data stays within approved and governed storage systems."
        ),
        impact=(
            "Users will not be able to open or save files directly to third-party "
            "storage services like Dropbox or Box from Office web apps."
        ),
        audit_procedure=(
            "Microsoft 365 admin center → Settings > Org settings > Office on the web.\n"
            "Verify that 'Allow users to open files stored in third-party storage "
            "services in Office on the web' is not enabled.\n\n"
            "There is no Microsoft Graph API for this setting."
        ),
        remediation=(
            "Microsoft 365 admin center → Settings > Org settings > Office on the web.\n"
            "Disable 'Allow users to open files stored in third-party storage services "
            "in Office on the web'."
        ),
        default_value="Third-party storage may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/admin/misc/third-party-storage",
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
        tags=["data-protection", "storage", "office-online", "third-party"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
