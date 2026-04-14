"""CIS AWS 3.1.2 – Ensure MFA Delete is enabled on S3 buckets (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_3_1_2(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-3.1.2",
        title="Ensure MFA Delete is enabled on S3 buckets",
        section="3.1 Storage – S3",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.HIGH,
        description=(
            "Once MFA Delete is enabled on your S3 bucket, any operation to delete an object "
            "version or change the versioning state of the bucket will require an MFA token in "
            "addition to the standard credentials. This provides an additional layer of "
            "protection against accidental or malicious deletions."
        ),
        rationale=(
            "MFA Delete prevents unauthorized or accidental deletion of S3 object versions. "
            "This is particularly important for sensitive data where version history serves "
            "as a backup mechanism."
        ),
        impact=(
            "Deleting S3 object versions requires an MFA device. This adds operational overhead "
            "for legitimate deletions."
        ),
        audit_procedure=(
            "aws s3api get-bucket-versioning --bucket <bucket-name>\n"
            "Check: MFADelete == 'Enabled'"
        ),
        remediation=(
            "Enable MFA Delete requires root account credentials:\n"
            "aws s3api put-bucket-versioning --bucket <bucket-name> "
            "--versioning-configuration Status=Enabled,MFADelete=Enabled "
            "--mfa '<serial-number> <token>'"
        ),
        default_value="MFA Delete is disabled by default.",
        references=[
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.3", title="Configure Data Access Control Lists", ig1=True, ig2=True, ig3=True),
            CISControl(version="v8", control_id="6.5", title="Require MFA for Administrative Access", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="14.6", title="Protect Information through Access Control Lists", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verify that MFA Delete is enabled on S3 buckets containing sensitive data. "
            "Run: aws s3api get-bucket-versioning --bucket <bucket-name> and check that "
            "MFADelete == 'Enabled'. Note: enabling MFA Delete requires root account credentials "
            "and an MFA device."
        )
