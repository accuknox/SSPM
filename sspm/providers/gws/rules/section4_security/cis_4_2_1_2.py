"""
CIS GWS 4.2.1.2 (L2) – Ensure third-party applications are reviewed
periodically (Manual)

Profile Applicability: Enterprise Level 2
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
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_4_2_1_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.2.1.2",
        title="Ensure third-party applications are reviewed periodically",
        section="4.2.1 API Controls",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.MEDIUM,
        description=(
            "Establishes a regular review process for all third-party "
            "applications that have been granted OAuth access to Google "
            "Workspace data.  Periodic review ensures that applications no "
            "longer in use, or applications with excessive permissions, "
            "are revoked."
        ),
        rationale=(
            "OAuth tokens for third-party applications persist until "
            "explicitly revoked.  Applications that are no longer used, "
            "have been abandoned by their developers, or have been "
            "compromised remain as latent access vectors.  Regular audits "
            "allow the organisation to maintain a minimal OAuth footprint."
        ),
        impact=(
            "Revoking access to previously authorised applications may "
            "break integrations that are still in use.  The review process "
            "should include communication with application owners to confirm "
            "whether access is still required."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → API controls → App access control\n"
            "  3. Review the list of connected third-party applications\n"
            "  4. Verify that a review has been performed within the last "
            "90 days and that unused or excessive-permission apps have been "
            "revoked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → API controls → App access control\n"
            "  3. Review each listed application and its granted scopes\n"
            "  4. Revoke access for applications that are no longer required "
            "or have excessive permissions\n"
            "  5. Establish a recurring calendar reminder for periodic review"
        ),
        default_value=(
            "No automatic review mechanism exists; review must be performed "
            "manually on a regular basis."
        ),
        references=[
            "https://support.google.com/a/answer/7281227",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="2.3",
                title="Address Unauthorized Software",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["api", "third-party", "review"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
