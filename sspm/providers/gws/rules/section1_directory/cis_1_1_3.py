"""
CIS GWS 1.1.3 (L1) – Ensure that admin accounts are not used for daily tasks
(Manual)

Profile Applicability: Enterprise Level 1
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
class CIS_1_1_3(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-1.1.3",
        title="Ensure that admin accounts are not used for daily tasks",
        section="1.1 Admin Accounts",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Super administrator accounts should be dedicated solely to "
            "administrative tasks and not used for day-to-day work such as "
            "reading email, accessing Drive files, or browsing the web."
        ),
        rationale=(
            "Using a privileged account for everyday tasks significantly increases "
            "the risk of that account being compromised through phishing, malware, "
            "or accidental data exposure.  Dedicated admin accounts minimise "
            "the blast radius of a credential compromise."
        ),
        impact=(
            "Super admins must maintain two accounts: one for administrative tasks "
            "and one for regular work.  This adds minor overhead but significantly "
            "reduces the risk of privileged account compromise."
        ),
        audit_procedure=(
            "Review super admin account usage:\n"
            "  1. Log in to https://admin.google.com as an administrator\n"
            "  2. Navigate to Reports → Audit → Admin\n"
            "  3. Verify that super admin accounts show activity only in the "
            "Admin console (not Gmail, Drive, Calendar, etc.)\n\n"
            "Also verify that super admin accounts do not have active Gmail mailboxes "
            "configured for regular correspondence."
        ),
        remediation=(
            "1. Create separate accounts for super admins' regular work if not already done.\n"
            "2. Ensure super admin accounts are used only for administrative functions.\n"
            "3. Consider using dedicated admin workstations for admin tasks.\n"
            "4. Review admin audit logs periodically for non-admin activity."
        ),
        default_value="Admin accounts may be used for daily tasks by default.",
        references=[
            "https://support.google.com/a/answer/33325",
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
        tags=["identity", "admin", "super-admin", "privileged-access"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
