"""CIS AWS 2.1.5 – Ensure delegated admin manages AWS Organizations policies (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_5(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.1.5",
        title="Ensure delegated admin manages AWS Organizations policies",
        section="2.1 Identity and Access Management – AWS Organizations",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "Ensure a dedicated member account is configured as delegated administrator for "
            "AWS Organizations to manage policies (SCPs, RCPs) instead of using the management "
            "account directly."
        ),
        rationale=(
            "Using a delegated administrator for Organizations policy management reduces direct "
            "access to the management account and enables separation of duties between "
            "organizational governance and policy management."
        ),
        impact=(
            "Configuring delegated administration requires changes to how policies are managed "
            "and who has access to do so."
        ),
        audit_procedure=(
            "Run: aws organizations list-delegated-administrators\n"
            "Verify that a dedicated member account is registered as a delegated administrator "
            "for policy management services."
        ),
        remediation=(
            "1. Identify a dedicated security/governance account.\n"
            "2. From the management account, run: "
            "aws organizations register-delegated-administrator "
            "--account-id <ACCOUNT_ID> --service-principal organizations.amazonaws.com\n"
            "3. Grant appropriate permissions to the delegated admin account."
        ),
        default_value="No delegated administrators are configured by default.",
        references=[
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_delegate_policies.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.4", title="Restrict Administrator Privileges to Dedicated Administrator Accounts", ig1=True, ig2=True, ig3=True),
            CISControl(version="v8", control_id="6.8", title="Define and Maintain Role-Based Access Control", ig1=False, ig2=False, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Run: aws organizations list-delegated-administrators to verify a dedicated member "
            "account is configured as delegated administrator for AWS Organizations policy "
            "management. The management account should not be used directly for day-to-day "
            "policy management."
        )
