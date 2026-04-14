"""CIS AWS 2.15 – Ensure a support role has been created to manage incidents with AWS Support (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


def _policy_grants_support_access(document: dict) -> bool:
    """Return True if the policy document grants support:* or AWSSupportAccess-equivalent access."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if action in ("support:*", "*") or action.lower().startswith("support:"):
                return True
    return False


@registry.rule
class CIS_2_15(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.15",
        title="Ensure a support role has been created to manage incidents with AWS Support",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "AWS provides a support center that can be used to notify AWS of security or other "
            "incidents. It is recommended that an IAM role or policy be created to allow "
            "authorized users to manage AWS support cases."
        ),
        rationale=(
            "Creating a dedicated IAM support role ensures that the right people can open and "
            "manage AWS support tickets during incidents without requiring broader permissions. "
            "This enables efficient incident response."
        ),
        impact="No operational impact — this adds support access to a dedicated role/user.",
        audit_procedure=(
            "Check if any IAM entity has the AWSSupportAccess managed policy attached:\n"
            "aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess\n"
            "Or check for customer-managed policies with support:* actions."
        ),
        remediation=(
            "1. Create an IAM role named (e.g.) AWSSupportRole with the AWSSupportAccess managed policy.\n"
            "aws iam create-role --role-name AWSSupportRole --assume-role-policy-document <trust-policy>\n"
            "aws iam attach-role-policy --role-name AWSSupportRole "
            "--policy-arn arn:aws:iam::aws:policy/AWSSupportAccess\n"
            "2. Assign the role to authorized personnel."
        ),
        default_value="No support role or policy is created by default.",
        references=[
            "https://docs.aws.amazon.com/awssupport/latest/user/getting-started.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        users = data.get("iam_users") or []
        policies = data.get("iam_policies") or []

        # Check if any user has AWSSupportAccess attached
        support_found = False
        found_in = []

        for user in users:
            name = user.get("UserName", "")
            for p in user.get("_attached_policies", []):
                if "AWSSupportAccess" in p.get("PolicyName", "") or "support" in p.get("PolicyArn", "").lower():
                    support_found = True
                    found_in.append(f"user:{name}")

        # Check customer-managed policies for support:* grants
        for policy in policies:
            doc = policy.get("_document", {})
            if _policy_grants_support_access(doc):
                support_found = True
                found_in.append(f"policy:{policy.get('PolicyName')}")

        evidence = [Evidence(
            source="iam:ListAttachedUserPolicies / iam:GetPolicyVersion",
            data={"support_access_found_in": found_in},
            description="IAM entities with AWS Support access.",
        )]

        if support_found:
            return self._pass(
                f"AWS Support access found in: {', '.join(found_in[:5])}. Compliant.",
                evidence=evidence,
            )
        return self._fail(
            "No IAM role or policy granting AWS Support access (AWSSupportAccess) was found. "
            "Create a support role to enable incident management.",
            evidence=evidence,
        )
