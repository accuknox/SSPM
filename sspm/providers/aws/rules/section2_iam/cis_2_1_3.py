"""CIS AWS 2.1.3 – Ensure Organizations management account is not used for workloads (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_3(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.1.3",
        title="Ensure Organizations management account is not used for workloads",
        section="2.1 Identity and Access Management – AWS Organizations",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.HIGH,
        description=(
            "Ensure the AWS Organizations management account is used only for organizational "
            "governance tasks and does not host production workloads."
        ),
        rationale=(
            "The management account has unique privileges that cannot be restricted by SCPs. "
            "Hosting workloads in the management account increases the blast radius of a security "
            "incident and circumvents the guardrails applied to member accounts."
        ),
        impact=(
            "Workloads currently hosted in the management account must be migrated to dedicated "
            "member accounts."
        ),
        audit_procedure=(
            "1. Sign in to the Organizations management account.\n"
            "2. Review running EC2 instances, RDS databases, Lambda functions, and other "
            "workload services to verify no production workloads are present.\n"
            "3. Check IAM users and roles to ensure only organizational administrators have access."
        ),
        remediation=(
            "1. Identify all workloads running in the management account.\n"
            "2. Migrate workloads to appropriate member accounts (e.g., production, staging).\n"
            "3. Apply SCPs to member accounts but not the management account to enforce separation."
        ),
        default_value="The management account can host workloads by default.",
        references=[
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.12", title="Segment Data Processing and Storage Based on Sensitivity", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
