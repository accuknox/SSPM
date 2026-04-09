"""
CIS MS365 2.4.3 (L2) – Ensure Microsoft Defender for Cloud Apps is enabled
(Manual)

Profile Applicability: E5 Level 2
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
class CIS_2_4_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.4.3",
        title="Ensure Microsoft Defender for Cloud Apps is enabled",
        section="2.4 Microsoft Defender",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Microsoft Defender for Cloud Apps (formerly MCAS) provides Cloud "
            "Access Security Broker (CASB) capabilities including visibility into "
            "cloud app usage, threat detection, and data protection."
        ),
        rationale=(
            "Defender for Cloud Apps provides visibility into shadow IT, enforces "
            "data protection policies across cloud apps, and detects threats like "
            "unusual access patterns and potential account compromises."
        ),
        impact=(
            "Enabling Defender for Cloud Apps requires E5 licensing and initial "
            "configuration effort. Some features require additional licensing."
        ),
        audit_procedure=(
            "Microsoft Defender portal (https://security.microsoft.com):\n"
            "  Navigate to Cloud apps section\n"
            "  Verify Defender for Cloud Apps is connected and active\n\n"
            "Microsoft Defender for Cloud Apps portal (https://portal.cloudappsecurity.com):\n"
            "  Verify the portal is accessible and configured."
        ),
        remediation=(
            "Microsoft 365 Defender portal:\n"
            "  Settings > Cloud apps > Defender for Cloud Apps\n"
            "  Enable Defender for Cloud Apps and configure the initial settings."
        ),
        default_value="Defender for Cloud Apps is not enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/defender-cloud-apps/what-is-defender-for-cloud-apps",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="16.1",
                title="Establish and Maintain a Secure Application Development Process",
                ig1=False,
                ig2=False,
                ig3=True,
            ),
        ],
        tags=["defender", "cloud-apps", "casb", "e5"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Microsoft Defender for Cloud Apps is enabled:\n"
            "  1. Go to https://security.microsoft.com\n"
            "  2. Check for Cloud apps in the navigation menu\n"
            "  3. Verify Defender for Cloud Apps is connected and active\n"
            "  4. Review connected apps and policies\n\n"
            "Requires Microsoft 365 E5 or Defender for Cloud Apps license."
        )
