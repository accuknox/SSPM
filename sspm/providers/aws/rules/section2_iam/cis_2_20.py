"""CIS AWS 2.20 – Ensure access to AWSCloudShellFullAccess is restricted (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_20(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.20",
        title="Ensure access to AWSCloudShellFullAccess is restricted",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "AWS CloudShell is a browser-based shell that provides a command-line environment "
            "with pre-configured AWS CLI and credentials. The AWSCloudShellFullAccess managed "
            "policy grants unrestricted access to CloudShell and should be restricted to "
            "authorized users only."
        ),
        rationale=(
            "CloudShell automatically provides AWS CLI credentials with the permissions of "
            "the logged-in user. If a user with broad permissions has CloudShell access, "
            "an attacker who compromises their browser session could use CloudShell to "
            "perform unauthorized actions. Restricting CloudShell access reduces this risk."
        ),
        impact=(
            "Users who rely on CloudShell for administrative tasks will need alternative "
            "access methods."
        ),
        audit_procedure=(
            "1. Check if AWSCloudShellFullAccess is attached to any users, groups, or roles:\n"
            "aws iam list-entities-for-policy "
            "--policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess\n"
            "2. Review the list and ensure only authorized personnel have this policy."
        ),
        remediation=(
            "1. Review the list of entities with AWSCloudShellFullAccess.\n"
            "2. Detach the policy from any unauthorized users or groups.\n"
            "3. If CloudShell access is required, create a more restricted policy that "
            "limits which users can access CloudShell."
        ),
        default_value="AWSCloudShellFullAccess is not attached to any entity by default.",
        references=[
            "https://docs.aws.amazon.com/cloudshell/latest/userguide/sec-auth-with-identities.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.1", title="Establish an Access Granting Process", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="14.1", title="Segment the Network Based on Sensitivity", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
