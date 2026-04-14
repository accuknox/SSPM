"""CIS AWS 3.3.1 – Ensure that encryption is enabled for EFS file systems (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_3_3_1(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-3.3.1",
        title="Ensure that encryption is enabled for EFS file systems",
        section="3.3 Storage – EFS",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Amazon EFS file systems should have encryption at rest enabled. Encryption protects "
            "the data stored in the file system from unauthorized access at the storage layer."
        ),
        rationale=(
            "EFS stores data persistently on disk. Without encryption at rest, any compromise "
            "of the underlying storage infrastructure could expose sensitive data. Encryption "
            "ensures data confidentiality even if physical storage media is accessed."
        ),
        impact=(
            "Encryption cannot be enabled on an existing unencrypted EFS file system. "
            "Data must be migrated to a new encrypted file system."
        ),
        audit_procedure=(
            "aws efs describe-file-systems --region <region>\n"
            "For each file system, check Encrypted == true."
        ),
        remediation=(
            "1. Create a new EFS file system with encryption enabled:\n"
            "aws efs create-file-system --encrypted\n"
            "2. Migrate data from the unencrypted file system to the new encrypted one.\n"
            "3. Update mount points in applications.\n"
            "4. Delete the unencrypted file system."
        ),
        default_value="EFS file systems are not encrypted by default unless specified.",
        references=[
            "https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.11", title="Encrypt Sensitive Data at Rest", ig1=False, ig2=True, ig3=True),
            CISControl(version="v7", control_id="14.8", title="Encrypt Sensitive Information at Rest", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        file_systems = data.get("efs_file_systems")
        if file_systems is None:
            return self._skip(
                "Could not retrieve EFS file systems. "
                "Ensure the efs_file_systems collector is enabled."
            )

        violations = []
        for fs in file_systems:
            if not fs.get("Encrypted", False):
                violations.append(
                    f"{fs.get('FileSystemId')} ({fs.get('Region', 'unknown')})"
                )

        evidence = [Evidence(
            source="efs:DescribeFileSystems",
            data={"unencrypted_file_systems": violations, "total": len(file_systems)},
            description="EFS file systems without encryption at rest.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} EFS file system(s) are not encrypted: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(file_systems)} EFS file system(s) have encryption enabled. Compliant.",
            evidence=evidence,
        )
