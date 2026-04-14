"""CIS AWS 2.1.2 – Ensure authorization guardrails for all AWS Organization accounts (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_2(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.1.2",
        title="Ensure authorization guardrails for all AWS Organization accounts",
        section="2.1 Identity and Access Management – AWS Organizations",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.HIGH,
        description=(
            "Ensure baseline authorization policies (SCPs and/or RCPs) are attached to all "
            "member accounts in AWS Organizations."
        ),
        rationale=(
            "Without baseline guardrail authorization policies, each account can grant excessive "
            "permissions. Service Control Policies (SCPs) define the maximum available permissions "
            "for IAM principals; Resource Control Policies (RCPs) define maximum available "
            "permissions for resources."
        ),
        impact=(
            "Attaching overly restrictive SCPs or RCPs may inadvertently break workloads if "
            "policies are not carefully scoped."
        ),
        audit_procedure=(
            "Run: aws organizations list-policies --filter SERVICE_CONTROL_POLICY\n"
            "Verify that policies exist and are attached to all accounts or OUs.\n"
            "Also check: aws organizations list-policies --filter RESOURCE_CONTROL_POLICY"
        ),
        remediation=(
            "1. In the AWS Organizations console, create SCPs that define minimum security "
            "guardrails (e.g., deny disabling CloudTrail, deny leaving the organization).\n"
            "2. Attach the SCPs to the root or all OUs.\n"
            "3. Consider also creating RCPs to restrict resource-level permissions."
        ),
        default_value="No SCPs or RCPs are attached to accounts by default.",
        references=[
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.6", title="Centralize Account Management", ig1=False, ig2=True, ig3=True),
            CISControl(version="v8", control_id="6.7", title="Centralize Access Control", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verify via AWS CLI or Console: aws organizations list-policies --filter "
            "SERVICE_CONTROL_POLICY and confirm policies are attached to all accounts/OUs. "
            "Also check for Resource Control Policies (RCPs)."
        )
