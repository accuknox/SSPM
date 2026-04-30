"""CIS AWS 6.1.1 – Ensure EBS volume encryption is enabled in all regions (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_6_1_1(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-6.1.1",
        title="Ensure EBS volume encryption is enabled in all regions",
        section="6.1 Networking – EBS",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Enabling encryption by default for Amazon EBS volumes ensures that all new EBS "
            "volumes created in all regions are automatically encrypted. This protects data "
            "at rest without requiring changes to application code."
        ),
        rationale=(
            "Default EBS encryption ensures that all new volumes are encrypted even if "
            "developers or operators forget to explicitly enable encryption at volume creation. "
            "This provides a consistent security baseline across all workloads."
        ),
        impact=(
            "Encryption is only applied to new volumes. Existing unencrypted volumes are "
            "not automatically encrypted."
        ),
        audit_procedure=(
            "For each region:\n"
            "aws ec2 get-ebs-encryption-by-default --region <region>\n"
            "Check: EbsEncryptionByDefault == true"
        ),
        remediation=(
            "For each region:\n"
            "aws ec2 enable-ebs-encryption-by-default --region <region>"
        ),
        default_value="EBS encryption by default is not enabled.",
        references=[
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.11", title="Encrypt Sensitive Data at Rest", ig1=False, ig2=True, ig3=True),
            CISControl(version="v7", control_id="14.8", title="Encrypt Sensitive Information at Rest", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        ebs_encryption = data.get("ebs_encryption_by_default")
        if ebs_encryption is None:
            return self._skip(
                "Could not retrieve EBS encryption by default settings. "
                "Ensure the ebs_encryption_by_default collector is enabled."
            )

        # Expected format: {region: {"EbsEncryptionByDefault": True/False}}
        violations = []
        compliant = []
        for region, config in ebs_encryption.items():
            if config.get("EbsEncryptionByDefault", False):
                compliant.append(region)
            else:
                violations.append(region)

        evidence = [Evidence(
            source="ec2:GetEbsEncryptionByDefault",
            data={"regions_without_encryption": violations, "regions_with_encryption": compliant},
            description="EBS default encryption status by region.",
        )]

        if violations:
            return self._fail(
                f"EBS encryption by default is not enabled in {len(violations)} region(s): "
                f"{', '.join(violations)}",
                evidence=evidence,
            )
        return self._pass(
            f"EBS encryption by default is enabled in all {len(compliant)} checked region(s). Compliant.",
            evidence=evidence,
        )
