"""
CIS GWS 4.1.2.1 (L2) – Ensure Super Admin account recovery is disabled
(Manual)

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
class CIS_4_1_2_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-4.1.2.1",
        title="Ensure Super Admin account recovery is disabled",
        section="4.1.2 Account Recovery",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.HIGH,
        description=(
            "Disables the self-service account recovery option for Super "
            "Administrator accounts.  Self-service recovery for Super Admins "
            "creates a high-privilege account takeover vector if an attacker "
            "can control the recovery email or phone number."
        ),
        rationale=(
            "Super Admin accounts have unrestricted access to all Google "
            "Workspace data and settings.  Allowing self-service recovery "
            "for these accounts means an attacker who controls a recovery "
            "contact can gain Super Admin access.  Recovery for Super Admins "
            "should follow a documented out-of-band process."
        ),
        impact=(
            "Super Admins who lose access to their account will not be able "
            "to use the automated recovery process.  Organisations must have "
            "a documented manual recovery procedure and at least two active "
            "Super Admin accounts to mitigate lockout risk."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Account recovery\n"
            "  3. Verify that 'Super admin account recovery' is disabled"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Security → Authentication → Account recovery\n"
            "  3. Disable 'Super admin account recovery'\n"
            "  4. Click Save"
        ),
        default_value=(
            "Super Admin account recovery is enabled by default (non-compliant "
            "for EL2)."
        ),
        references=[
            "https://support.google.com/a/answer/9436964",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.3",
                title="Disable Dormant Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["account-recovery", "super-admin"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
