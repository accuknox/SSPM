"""CIS AWS 3.2.4 – Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_3_2_4(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-3.2.4",
        title="Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS",
        section="3.2 Storage – RDS",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "Amazon RDS Multi-AZ deployments provide enhanced availability and durability for "
            "production database instances. When Multi-AZ is configured, Amazon RDS automatically "
            "provisions and maintains a synchronous standby replica in a different Availability Zone."
        ),
        rationale=(
            "Multi-AZ deployments ensure that the database is highly available. In the event of "
            "a planned or unplanned maintenance event, Amazon RDS automatically fails over to "
            "the standby, minimizing downtime."
        ),
        impact=(
            "Multi-AZ deployments incur additional cost as a standby instance is always running "
            "in a separate Availability Zone."
        ),
        audit_procedure=(
            "aws rds describe-db-instances --region <region>\n"
            "For each non-Aurora production instance, check MultiAZ == true."
        ),
        remediation=(
            "aws rds modify-db-instance --db-instance-identifier <id> "
            "--multi-az --apply-immediately\n"
            "Note: This may cause a brief failover during the modification."
        ),
        default_value="Multi-AZ is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.2", title="Establish and Maintain a Secure Network Architecture", ig1=False, ig2=True, ig3=True),
            CISControl(version="v7", control_id="2.10", title="Disable Unnecessary or Unauthorized Software", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Review RDS instances to confirm production databases use Multi-AZ deployments. "
            "Run: aws rds describe-db-instances and check MultiAZ field for all production "
            "instances. Non-production instances may not require Multi-AZ."
        )
