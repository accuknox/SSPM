"""
CIS GWS 4.2.1.4 (L2) – Ensure domain-wide delegation for applications is
reviewed periodically (Manual)

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
class CIS_4_2_1_4(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.2.1.4",
        title="Ensure domain-wide delegation for applications is reviewed periodically",
        section="4.2.1 API Controls",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.HIGH,
        description=(
            "Establishes a periodic review process for service accounts "
            "that have been granted domain-wide delegation (DWD) in Google "
            "Workspace.  DWD allows a service account to impersonate any "
            "user in the domain, representing an extremely powerful and "
            "dangerous privilege that must be tightly controlled."
        ),
        rationale=(
            "Domain-wide delegation grants a service account the ability to "
            "access data for every user in the organisation.  If a service "
            "account with DWD is compromised, an attacker can access all "
            "email, calendar, Drive files, and other data across the entire "
            "organisation.  Regular review ensures only necessary service "
            "accounts retain this privilege."
        ),
        impact=(
            "Revoking DWD from service accounts may break dependent "
            "integrations.  Reviews should be coordinated with application "
            "owners.  DWD should be granted only to service accounts with "
            "a documented, legitimate business requirement."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → API controls → Domain-wide delegation\n"
            "  3. Review each service account listed and the OAuth scopes "
            "it has been granted\n"
            "  4. Verify that a review has been performed within the last "
            "90 days and that unnecessary delegations have been removed"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → API controls → Domain-wide delegation\n"
            "  3. For each service account, review the OAuth scopes and "
            "confirm they are still required\n"
            "  4. Delete entries for service accounts that no longer require "
            "DWD or have excessive scopes\n"
            "  5. Apply the principle of least privilege to all remaining "
            "DWD entries\n"
            "  6. Establish a recurring calendar reminder for periodic review"
        ),
        default_value=(
            "No automatic review mechanism exists; review must be performed "
            "manually on a regular basis."
        ),
        references=[
            "https://support.google.com/a/answer/162106",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.4",
                title="Restrict Administrator Privileges to Dedicated Administrator Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["api", "domain-wide-delegation", "review"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
