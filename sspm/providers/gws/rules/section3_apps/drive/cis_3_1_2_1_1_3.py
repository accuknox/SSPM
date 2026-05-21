"""
CIS GWS 3.1.2.1.1.3 (L2) – Ensure document sharing is being controlled by
domain with allowlists (Manual)

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
class CIS_3_1_2_1_1_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.2.1.1.3",
        title="Ensure document sharing is being controlled by domain with allowlists",
        section="3.1.2 Drive and Docs",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.MEDIUM,
        description=(
            "Control sharing of documents to external domains by either blocking "
            "domains or only allowing sharing with specific named domains in an "
            "allowlist."
        ),
        rationale=(
            "Attackers often attempt to expose sensitive information through sharing. "
            "Restricting the domains that users can share documents with reduces "
            "the attack surface for data exfiltration."
        ),
        impact=(
            "Users will not be able to share documents with domains outside the "
            "allowlist unless additional permissions are granted."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings → Sharing options\n"
            "  4. Under 'Sharing outside of <Company>', ensure 'ALLOWLISTED DOMAINS - "
            "Files owned by users in <Company> can be shared with Google Accounts "
            "in compatible allowlisted domains' is selected\n"
            "  5. Ensure 'Warn when files owned by users or shared drives in "
            "<Company> are shared with users in allowlisted domains' is checked"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Navigate to Apps → Google Workspace → Drive and Docs\n"
            "  3. Under Sharing settings → Sharing options\n"
            "  4. Under 'Sharing outside of <Company>', select 'ALLOWLISTED DOMAINS'\n"
            "  5. Set 'Warn when files are shared with users in allowlisted domains' "
            "to checked\n"
            "  6. Click Save"
        ),
        default_value=(
            "Sharing outside of <Company> is ON - Files can be shared outside of "
            "<Company>. This applies to files in all shared drives as well."
        ),
        references=[
            "https://support.google.com/a/answer/60781",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.3",
                title="Configure Data Access Control Lists",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["drive", "sharing", "allowlist", "domain-control"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
