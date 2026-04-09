"""
CIS MS365 3.3.1 (L1) – Ensure sensitivity label policies are published
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
class CIS_3_3_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-3.3.1",
        title="Ensure sensitivity label policies are published",
        section="3.3 Information Protection",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Sensitivity labels allow users and administrators to classify and "
            "protect content based on its sensitivity. Sensitivity label policies "
            "must be published to make labels available to users."
        ),
        rationale=(
            "Sensitivity labels help protect sensitive data by enabling encryption, "
            "access controls, and content markings. Publishing label policies makes "
            "them available in Office apps, Teams, SharePoint, and Exchange."
        ),
        impact=(
            "Users will be prompted or required to apply sensitivity labels to "
            "content they create. This may require user training and change management."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/informationProtection/policy/labels\n"
            "  Check if labels exist and are configured.\n\n"
            "Compliant: At least one sensitivity label policy is published."
        ),
        remediation=(
            "Microsoft Purview compliance portal → Information protection > Labels.\n"
            "  1. Create sensitivity labels (e.g., Public, Internal, Confidential, Highly Confidential)\n"
            "  2. Create a label policy to publish the labels to users\n"
            "  3. Assign the policy to all users or specific groups"
        ),
        default_value="No sensitivity labels are configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/purview/sensitivity-labels",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.2",
                title="Establish and Maintain a Data Inventory",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["purview", "sensitivity-labels", "data-classification", "compliance"],
    )

    async def check(self, data: CollectedData):
        sensitivity_labels = data.get("sensitivity_labels")
        if sensitivity_labels is None:
            return self._skip(
                "Could not retrieve sensitivity labels data. "
                "Requires InformationProtectionPolicy.Read.All permission."
            )

        # Note: the collector uses dlp_policies key for beta sensitivity labels
        # Try sensitivity_labels first, fall back to dlp_policies
        labels = sensitivity_labels
        if not labels:
            labels = data.get("dlp_policies") or []

        if labels:
            return self._pass(
                f"{len(labels)} sensitivity label(s) found.",
                evidence=[
                    Evidence(
                        source="graph/beta/informationProtection/policy/labels",
                        data={"labelCount": len(labels)},
                        description="Sensitivity labels are configured.",
                    )
                ],
            )

        return self._fail(
            "No sensitivity labels found. Content classification and protection "
            "via sensitivity labels is not configured.",
            evidence=[
                Evidence(
                    source="graph/beta/informationProtection/policy/labels",
                    data=[],
                    description="No sensitivity labels found.",
                )
            ],
        )
