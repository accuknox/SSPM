"""CIS Azure 2.1.6 – Ensure that Usage is Restricted and Expiry is Enforced for Databricks Personal Access Tokens (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_1_6(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-2.1.6",
        title="Ensure that Usage is Restricted and Expiry is Enforced for Databricks Personal Access Tokens",
        section="2.1 Azure Databricks",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Databricks Personal Access Tokens (PATs) allow programmatic access to the "
            "Databricks REST API. Token usage should be restricted to service principals "
            "and automated processes, and all tokens must have an expiry date enforced "
            "via workspace token policy."
        ),
        rationale=(
            "Long-lived or non-expiring PATs are a common credential leakage risk. If a PAT "
            "is compromised and has no expiry, an attacker retains persistent access to the "
            "workspace. Restricting token creation to service accounts and enforcing maximum "
            "lifetimes reduces the blast radius of any credential exposure."
        ),
        impact=(
            "Enforcing token expiry will cause existing non-expiring tokens to become invalid "
            "after the policy is applied. Automated pipelines using long-lived tokens must "
            "be updated to rotate tokens before expiry."
        ),
        audit_procedure=(
            "In the Databricks workspace, navigate to Settings → Workspace Admin → Advanced → "
            "Personal Access Tokens. Verify that: (1) 'Personal Access Tokens' is enabled only "
            "for required users/service principals via permissions, (2) a maximum token lifetime "
            "is configured (Token Policy → Maximum token lifetime). Review the list of existing "
            "tokens under Settings → Developer → Access Tokens for non-expiring tokens."
        ),
        remediation=(
            "Configure token policy: Settings → Workspace Admin → Advanced → Personal Access "
            "Tokens → set Maximum Token Lifetime (e.g., 90 days). Restrict who can create tokens "
            "via token permissions (Settings → Workspace Admin → Access Control → Token "
            "Permissions). Revoke any existing tokens without an expiry date and re-issue them "
            "with appropriate lifetimes."
        ),
        default_value="Token creation is allowed for all users with no enforced maximum lifetime by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/access-control/tokens",
            "https://www.cisecurity.org/benchmark/azure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.6",
                title="Centralize Account Management",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
