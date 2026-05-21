"""
CIS GWS 3.1.9.1.1 (L1) – Ensure users access to Google Workspace Marketplace
apps is restricted (Manual)

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
class CIS_3_1_9_1_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.9.1.1",
        title="Ensure users access to Google Workspace Marketplace apps is restricted",
        section="3.1.9 Google Workspace Marketplace",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Restricts users from installing or accessing Google Workspace "
            "Marketplace applications unless they have been reviewed and "
            "approved by an administrator.  Unrestricted Marketplace access "
            "allows users to grant third-party apps broad OAuth permissions "
            "to Google Workspace data."
        ),
        rationale=(
            "Third-party Marketplace apps can request access to Gmail, Drive, "
            "Calendar, and other Google Workspace services.  Without "
            "administrative controls, users may unknowingly grant excessive "
            "permissions to malicious or poorly secured apps, resulting in "
            "data exfiltration or account compromise."
        ),
        impact=(
            "Users will only be able to install apps that an administrator has "
            "explicitly added to the approved allowlist.  This requires "
            "administrators to actively manage and approve apps, but "
            "significantly reduces the risk from unvetted third-party "
            "integrations."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace Marketplace apps → Settings\n"
            "  3. Verify that 'Allow users to install and run apps from the "
            "Marketplace' is set to 'Allow only selected apps' or "
            "'Do not allow users to install and run apps'"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace Marketplace apps → Settings\n"
            "  3. Select 'Allow only selected apps' and configure the "
            "allowlist of approved apps, or select 'Do not allow users to "
            "install and run apps'\n"
            "  4. Click Save"
        ),
        default_value=(
            "Users are allowed to install any Marketplace app by default "
            "(non-compliant)."
        ),
        references=[
            "https://support.google.com/a/answer/6089179",
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
        tags=["marketplace", "apps", "access"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
