"""
CIS GWS 4.2.1.1 (L2) – Ensure application access to Google services is
restricted (Manual)

Profile Applicability: Enterprise Level 2
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_4_2_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.2.1.1",
        title="Ensure application access to Google services is restricted",
        section="4.2.1 API Controls",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.HIGH,
        description=(
            "Restricts which third-party applications can access Google "
            "Workspace data via OAuth 2.0 by configuring API access controls.  "
            "Only applications that have been explicitly trusted by the "
            "administrator should be permitted to access Google services on "
            "behalf of users."
        ),
        rationale=(
            "Unrestricted API access allows any OAuth application to request "
            "access to Google Workspace data when a user grants consent.  "
            "Users may not fully understand the permissions they are granting.  "
            "Restricting API access to approved applications reduces the risk "
            "of data exfiltration via malicious or compromised OAuth apps."
        ),
        impact=(
            "Third-party applications not in the trusted list will be blocked "
            "from accessing Google Workspace APIs.  Administrators should "
            "maintain and communicate the approved application list."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → API controls → App access control\n"
            "  3. Verify that 'Trust internal, domain-owned apps' is "
            "appropriately configured\n"
            "  4. Verify that only approved applications are listed in "
            "the trusted apps list"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → API controls → App access control\n"
            "  3. Configure the API access control policy to restrict access "
            "to trusted apps only\n"
            "  4. Add approved applications to the trusted apps list\n"
            "  5. Click Save"
        ),
        default_value=(
            "All apps are allowed to access Google services via OAuth by "
            "default (non-compliant for EL2)."
        ),
        references=[
            "https://support.google.com/a/answer/7281227",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="2.5",
                title="Allowlist Authorized Software",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["api", "oauth", "apps"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
