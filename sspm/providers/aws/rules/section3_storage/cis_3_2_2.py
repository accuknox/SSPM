"""CIS AWS 3.2.2 – Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_3_2_2(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-3.2.2",
        title="Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances",
        section="3.2 Storage – RDS",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "Enabling Auto Minor Version Upgrade ensures that the RDS database instance "
            "automatically receives minor engine version upgrades during the next scheduled "
            "maintenance window. Minor version upgrades often contain security patches."
        ),
        rationale=(
            "Minor version upgrades frequently include security patches that fix known "
            "vulnerabilities. Enabling automatic minor version upgrades reduces the window "
            "of exposure to these vulnerabilities."
        ),
        impact=(
            "Automatic minor version upgrades may briefly restart the database instance "
            "during the maintenance window."
        ),
        audit_procedure=(
            "aws rds describe-db-instances --region <region>\n"
            "For each instance, check AutoMinorVersionUpgrade == true."
        ),
        remediation=(
            "aws rds modify-db-instance --db-instance-identifier <id> "
            "--auto-minor-version-upgrade --apply-immediately"
        ),
        default_value="Auto Minor Version Upgrade is enabled by default for new RDS instances.",
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html"
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
            if not inst.get("AutoMinorVersionUpgrade", True):
                violations.append(
                    f"{inst.get('DBInstanceIdentifier')} ({inst.get('Region', 'unknown')})"
                )

        evidence = [Evidence(
            source="rds:DescribeDBInstances",
            data={"auto_upgrade_disabled": violations, "total": len(instances)},
            description="RDS instances without Auto Minor Version Upgrade enabled.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} RDS instance(s) do not have Auto Minor Version Upgrade enabled: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(instances)} RDS instance(s) have Auto Minor Version Upgrade enabled. Compliant.",
            evidence=evidence,
        )
