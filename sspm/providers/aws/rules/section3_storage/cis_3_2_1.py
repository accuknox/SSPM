"""CIS AWS 3.2.1 – Ensure that encryption-at-rest is enabled for RDS instances (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_3_2_1(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-3.2.1",
        title="Ensure that encryption-at-rest is enabled for RDS instances",
        section="3.2 Storage – RDS",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Amazon RDS instances should have storage encryption enabled to protect data "
            "at rest. Encryption is applied to the underlying storage for a DB instance, "
            "its automated backups, read replicas, and snapshots."
        ),
        rationale=(
            "Enabling encryption ensures that even if the underlying storage is compromised, "
            "the data remains protected. This is essential for compliance with regulations "
            "like HIPAA, PCI-DSS, and GDPR."
        ),
        impact=(
            "Encryption cannot be enabled on an existing unencrypted RDS instance. "
            "A new encrypted instance must be created and data migrated."
        ),
        audit_procedure=(
            "aws rds describe-db-instances --region <region>\n"
            "For each instance, check StorageEncrypted == true."
        ),
        remediation=(
            "1. Create a snapshot of the unencrypted instance.\n"
            "2. Copy the snapshot with encryption enabled.\n"
            "3. Restore the encrypted snapshot to a new RDS instance.\n"
            "4. Update application connection strings.\n"
            "5. Delete the original unencrypted instance."
        ),
        default_value="RDS instances are not encrypted by default.",
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        instances = data.get("rds_instances")
        if instances is None:
            return self._skip(
                "Could not retrieve RDS instances. "
                "Ensure the rds_instances collector is enabled."
            )

        violations = []
        for inst in instances:
            if not inst.get("StorageEncrypted", False):
                violations.append(
                    f"{inst.get('DBInstanceIdentifier')} ({inst.get('Region', 'unknown')})"
                )

        evidence = [Evidence(
            source="rds:DescribeDBInstances",
            data={"unencrypted_instances": violations, "total": len(instances)},
            description="RDS instances without storage encryption.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} RDS instance(s) do not have encryption-at-rest enabled: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(instances)} RDS instance(s) have encryption-at-rest enabled. Compliant.",
            evidence=evidence,
        )
