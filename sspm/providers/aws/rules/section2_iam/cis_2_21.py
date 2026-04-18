"""CIS AWS 2.21 – Ensure AWS resource policies do not allow unrestricted access using 'Principal': '*' (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_21(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.21",
        title="Ensure AWS resource policies do not allow unrestricted access using 'Principal': '*'",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Resource-based policies (S3 bucket policies, KMS key policies, SNS topic policies, "
            "SQS queue policies, etc.) that use Principal: '*' without conditions allow "
            "unauthenticated public access and should be reviewed and restricted."
        ),
        rationale=(
            "Resource policies with Principal: '*' grant access to any AWS principal or even "
            "unauthenticated users if combined with public access settings. This can lead to "
            "data exposure, unauthorized API calls, or resource abuse."
        ),
        impact=(
            "Restricting Principal: '*' in resource policies may break public-facing services "
            "that legitimately require broad access (e.g., public S3 static websites)."
        ),
        audit_procedure=(
            "For each resource type, review resource-based policies:\n"
            "S3: aws s3api get-bucket-policy --bucket <name>\n"
            "KMS: aws kms get-key-policy --key-id <id> --policy-name default\n"
            "SNS: aws sns get-topic-attributes --topic-arn <arn>\n"
            "SQS: aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy\n"
            "Look for statements with Principal: '*' or Principal: {AWS: '*'} without restrictive conditions."
        ),
        remediation=(
            "1. Review all resource policies with Principal: '*'.\n"
            "2. If the broad access is not intentional, restrict the Principal to specific "
            "accounts, roles, or services.\n"
            "3. If broad access is required, add Condition blocks to limit access to "
            "specific source IPs, VPCs, or organizations."
        ),
        default_value="Resource policies are not created by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.3", title="Configure Data Access Control Lists", ig1=True, ig2=True, ig3=True),
            CISControl(version="v8", control_id="6.8", title="Define and Maintain Role-Based Access Control", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
