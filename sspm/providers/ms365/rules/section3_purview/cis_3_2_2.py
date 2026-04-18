"""
CIS MS365 3.2.2 (L1) – Ensure DLP policies are enabled for Microsoft Teams
(Automated)

Profile Applicability: E5 Level 1
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
class CIS_3_2_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-3.2.2",
        title="Ensure DLP policies are enabled for Microsoft Teams",
        section="3.2 Data Loss Prevention",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "DLP policies should be extended to cover Microsoft Teams chat and "
            "channel messages to prevent sensitive data from being shared through "
            "Teams conversations."
        ),
        rationale=(
            "As Teams adoption increases, users may share sensitive information "
            "through chat messages and channels. DLP policies for Teams ensure "
            "that sensitive data is detected and protected in Teams conversations."
        ),
        impact=(
            "Teams messages containing sensitive data will be blocked or flagged. "
            "Users will receive policy tips when they attempt to share sensitive data."
        ),
        audit_procedure=(
            "Microsoft Purview compliance portal:\n"
            "  Data loss prevention > Policies\n"
            "  Check each policy's location settings for Teams coverage.\n\n"
            "Compliant: At least one DLP policy includes Teams as a location."
        ),
        remediation=(
            "Microsoft Purview compliance portal → Data loss prevention > Policies.\n"
            "Edit existing DLP policies or create new ones that include:\n"
            "  • Location: Microsoft Teams chat and channel messages\n"
            "  • Apply appropriate sensitive information type rules"
        ),
        default_value="DLP policies do not include Teams by default.",
        references=[
            "https://learn.microsoft.com/en-us/purview/dlp-microsoft-teams",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.1",
                title="Establish and Maintain a Data Management Process",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["purview", "dlp", "teams", "data-protection", "compliance", "e5"],
    )

    async def check(self, data: CollectedData):
        dlp_policies = data.get("dlp_policies")
        if dlp_policies is None:
            return self._skip(
                "Could not retrieve DLP policies data. "
                "Requires InformationProtectionPolicy.Read.All permission."
            )

        # Check if any policy covers Teams
        # In the beta endpoint, sensitivity labels are returned; for actual DLP
        # policies with Teams coverage we need Compliance portal APIs
        # Returning a manual finding if we can't determine Teams coverage
        if not dlp_policies:
            return self._fail(
                "No DLP policies found. Microsoft Teams DLP protection is not configured.",
                evidence=[
                    Evidence(
                        source="graph/beta/security/informationProtection",
                        data=[],
                        description="No DLP policies found.",
                    )
                ],
            )

        # We can't easily determine Teams coverage from the sensitivity labels endpoint
        return self._manual(
            f"DLP policies found ({len(dlp_policies)}) but Teams location coverage cannot be verified via Graph API."
        )
