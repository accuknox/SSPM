"""CIS AWS 3.2.3 – Ensure that RDS instances are not publicly accessible (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_3_2_3(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-3.2.3",
        title="Ensure that RDS instances are not publicly accessible",
        section="3.2 Storage – RDS",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Ensure that RDS database instances are not publicly accessible. Public "
            "accessibility means the instance has a public IP address and can be reached "
            "from the internet, bypassing network-level controls."
        ),
        rationale=(
            "Publicly accessible RDS instances expose the database to internet-based attacks "
            "including brute force, SQL injection, and exploitation of database engine "
            "vulnerabilities. Databases should only be accessible from within the VPC."
        ),
        impact=(
            "Applications that currently connect to the database via its public endpoint must "
            "be updated to use private VPC connectivity."
        ),
        audit_procedure=(
            "aws rds describe-db-instances --region <region>\n"
            "For each instance, check PubliclyAccessible == false."
        ),
        remediation=(
            "aws rds modify-db-instance --db-instance-identifier <id> "
            "--no-publicly-accessible --apply-immediately"
        ),
        default_value="RDS instances may be publicly accessible depending on creation settings.",
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html"
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
            if inst.get("PubliclyAccessible", False):
                violations.append(
                    f"{inst.get('DBInstanceIdentifier')} ({inst.get('Region', 'unknown')})"
                )

        evidence = [Evidence(
            source="rds:DescribeDBInstances",
            data={"publicly_accessible": violations, "total": len(instances)},
            description="RDS instances that are publicly accessible.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} RDS instance(s) are publicly accessible: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"No RDS instances are publicly accessible ({len(instances)} total). Compliant.",
            evidence=evidence,
        )
