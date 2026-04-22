"""
CIS GWS 4.2.6.1 (L1) – Ensure less secure app access is disabled (Manual)

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
class CIS_4_2_6_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.2.6.1",
        title="Ensure less secure app access is disabled",
        section="4.2.6 Less Secure Apps",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Disables access for applications that use legacy authentication "
            "protocols (basic authentication) to access Google Workspace "
            "services such as Gmail, Calendar, and Contacts.  Less secure "
            "apps bypass modern authentication protections including 2SV "
            "and OAuth."
        ),
        rationale=(
            "Legacy authentication protocols transmit credentials without "
            "modern security controls.  Applications using these protocols "
            "bypass 2-Step Verification, making accounts protected by 2SV "
            "vulnerable to credential attacks.  Disabling less secure app "
            "access forces all applications to use OAuth 2.0, which supports "
            "modern security controls."
        ),
        impact=(
            "Applications relying on basic authentication (e.g., older "
            "email clients, legacy IMAP/POP3 configurations) will lose "
            "access.  Users must migrate to OAuth-capable clients.  "
            "Administrators should audit app usage before disabling and "
            "communicate migration paths to affected users."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Less secure apps\n"
            "  3. Verify that 'Disable access to less secure apps' is "
            "selected for all organisational units"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Access and data control → "
            "Less secure apps\n"
            "  3. Select 'Disable access to less secure apps (Recommended)'\n"
            "  4. Apply this setting to all organisational units\n"
            "  5. Click Save"
        ),
        default_value=(
            "Less secure app access is disabled by default for new "
            "tenants; verify current state for existing tenants."
        ),
        references=[
            "https://support.google.com/a/answer/6260879",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.8",
                title="Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["less-secure-apps", "legacy-auth"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
