"""
CIS MS365 3.2.1 (L1) – Ensure DLP policies are enabled (Automated)

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
class CIS_3_2_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-3.2.1",
        title="Ensure DLP policies are enabled",
        section="3.2 Data Loss Prevention",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Data Loss Prevention (DLP) policies should be created and enabled to "
            "protect sensitive information from unauthorized sharing. At minimum, "
            "policies protecting common sensitive data types (PII, financial data, "
            "health information) should be in place."
        ),
        rationale=(
            "DLP policies prevent accidental or intentional sharing of sensitive "
            "information such as credit card numbers, Social Security numbers, and "
            "health data. Without DLP policies, users may inadvertently share "
            "sensitive data through email, Teams, or SharePoint."
        ),
        impact=(
            "DLP policies may block or restrict some email messages and file sharing "
            "operations that contain sensitive data. Users may need to provide "
            "business justification to override DLP restrictions."
        ),
        audit_procedure=(
            "Using Microsoft Graph (beta):\n"
            "  GET /beta/security/informationProtection/sensitivityLabels\n"
            "  Or check Purview compliance portal:\n"
            "  https://compliance.microsoft.com → Data loss prevention > Policies\n\n"
            "Compliant: At least one DLP policy is enabled."
        ),
        remediation=(
            "Microsoft Purview compliance portal → Data loss prevention > Policies.\n"
            "Create DLP policies for:\n"
            "  • U.S. Personally Identifiable Information (PII)\n"
            "  • U.S. Financial Data\n"
            "  • Health Insurance Portability and Accountability Act (HIPAA)\n"
            "  Or use industry-specific templates."
        ),
        default_value="No DLP policies are configured by default.",
        references=[
            "https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp",
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
        tags=["purview", "dlp", "data-protection", "compliance"],
    )

    async def check(self, data: CollectedData):
        dlp_policies = data.get("dlp_policies")
        if dlp_policies is None:
            return self._skip(
                "Could not retrieve DLP policies data. "
                "Requires InformationProtectionPolicy.Read.All permission."
            )

        if dlp_policies:
            return self._pass(
                f"{len(dlp_policies)} DLP policy/policies found.",
                evidence=[
                    Evidence(
                        source="graph/beta/security/informationProtection",
                        data={"policyCount": len(dlp_policies)},
                        description="DLP policies are configured.",
                    )
                ],
            )

        return self._fail(
            "No DLP policies are configured. Sensitive data may be shared without restriction.",
            evidence=[
                Evidence(
                    source="graph/beta/security/informationProtection",
                    data=[],
                    description="No DLP policies found.",
                )
            ],
        )
