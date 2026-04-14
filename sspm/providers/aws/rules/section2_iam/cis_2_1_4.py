"""CIS AWS 2.1.4 – Ensure Organizational Units are structured by environment and sensitivity (Manual, L2)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_4(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.1.4",
        title="Ensure Organizational Units are structured by environment and sensitivity",
        section="2.1 Identity and Access Management – AWS Organizations",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L2],
        severity=Severity.MEDIUM,
        description=(
            "Ensure OUs are structured by environment (production, non-production, sandbox) "
            "and data sensitivity rather than mirroring the corporate organizational chart."
        ),
        rationale=(
            "Structuring OUs by environment and sensitivity enables consistent application of "
            "security policies (SCPs/RCPs) based on risk level rather than business unit. "
            "This prevents inadvertent permission gaps and simplifies compliance auditing."
        ),
        impact="Restructuring OUs requires re-attaching policies and migrating accounts.",
        audit_procedure=(
            "1. Navigate to AWS Organizations in the management account.\n"
            "2. Review the OU structure and verify OUs are organized by environment "
            "(e.g., Production, Non-Production, Sandbox) and sensitivity level.\n"
            "3. Verify that SCPs appropriate for each environment are attached to corresponding OUs."
        ),
        remediation=(
            "1. Design an OU structure based on environment (Production, Staging, Development, "
            "Sandbox) and sensitivity (High Security, Standard).\n"
            "2. Move accounts into appropriate OUs.\n"
            "3. Attach environment-appropriate SCPs to each OU."
        ),
        default_value="AWS Organizations does not enforce any particular OU structure.",
        references=[
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_ou-structure.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Review the AWS Organizations OU structure to verify it is organized by environment "
            "(production, non-production, sandbox) and data sensitivity, not by corporate "
            "organizational chart. Confirm appropriate SCPs are attached to each environment OU."
        )
