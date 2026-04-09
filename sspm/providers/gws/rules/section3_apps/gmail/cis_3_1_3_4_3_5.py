"""
CIS GWS 3.1.3.4.3.5 (L1) – Ensure groups are protected from inbound
emails spoofing your domain (Manual)

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
class CIS_3_1_3_4_3_5(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.4.3.5",
        title="Ensure groups are protected from inbound emails spoofing your domain",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "If a group receives an email that is spoofing your domain it is sent "
            "to the spam folder.  This extends domain spoofing protection to Google "
            "Groups, preventing spoofed messages from reaching group members."
        ),
        rationale=(
            "You should protect your groups from any emails that spoof your domain."
        ),
        impact=(
            "Emails that are spoofing your domain and are received by a group are "
            "sent to the spam folder."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Spoofing and authentication, ensure 'Protect your "
            "Groups from inbound emails spoofing your domain' is checked\n"
            "  4. Ensure Action is set to 'Move email to spam'"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety - Spoofing and authentication, set 'Protect your "
            "Groups from inbound emails spoofing your domain' to checked\n"
            "  4. Set Action to 'Move email to spam'\n"
            "  5. Click Save"
        ),
        default_value=(
            "Protect against any unauthenticated emails is unchecked; "
            "Action is 'Keep email in inbox and display warning' (default)."
        ),
        references=[
            "https://support.google.com/a/answer/9157861",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.3",
                title="Maintain and Enforce Network-Based URL Filters",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["gmail", "spoofing", "groups", "phishing", "domain-spoofing", "safety"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify groups are protected from inbound emails spoofing your domain:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Under Safety → Spoofing and authentication\n"
            "  4. Ensure 'Protect your Groups from inbound emails spoofing your "
            "domain' is checked\n"
            "  5. Ensure Action is set to 'Move email to spam'"
        )
