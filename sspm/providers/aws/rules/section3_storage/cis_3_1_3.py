"""CIS AWS 3.1.3 – Ensure all data in Amazon S3 has been discovered, classified, and secured (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_3_1_3(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-3.1.3",
        title="Ensure all data in Amazon S3 has been discovered, classified, and secured when necessary",
        section="3.1 Storage – S3",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "Data stored in Amazon S3 should be discovered, classified based on sensitivity, "
            "and secured with appropriate access controls. Amazon Macie or similar data "
            "classification tools should be used to identify sensitive data."
        ),
        rationale=(
            "Without data classification, organizations cannot apply appropriate security "
            "controls proportional to data sensitivity. Unclassified sensitive data (PII, PHI, "
            "financial records) may be stored without adequate protection."
        ),
        impact=(
            "Enabling Macie incurs costs. Remediating discovered sensitive data exposures "
            "may require significant application changes."
        ),
        audit_procedure=(
            "1. Check if Amazon Macie is enabled:\n"
            "aws macie2 get-macie-session\n"
            "2. Review Macie findings for sensitive data discoveries.\n"
            "3. Verify that buckets containing sensitive data have appropriate access controls, "
            "encryption, and data retention policies."
        ),
        remediation=(
            "1. Enable Amazon Macie to discover and classify sensitive data.\n"
            "2. Review Macie findings and remediate exposed sensitive data.\n"
            "3. Apply appropriate bucket policies, encryption, and access controls based on "
            "data classification."
        ),
        default_value="No data classification is performed by default.",
        references=[
            "https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.1", title="Establish and Maintain a Data Management Process", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="5.1", title="Establish Secure Configurations", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verify that Amazon Macie or an equivalent data classification tool is enabled and "
            "has scanned all S3 buckets. Review findings and ensure sensitive data is secured "
            "with appropriate controls. Run: aws macie2 get-macie-session to check Macie status."
        )
