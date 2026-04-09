"""
CIS GWS 3.1.3.7.2 (L1) – Ensure email is sent over a secure TLS connection
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
class CIS_3_1_3_7_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.7.2",
        title="Ensure email is sent over a secure TLS connection",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Configures Gmail to require Transport Layer Security (TLS) for "
            "both inbound and outbound email connections.  TLS encrypts email "
            "in transit, protecting against eavesdropping and man-in-the-middle "
            "attacks."
        ),
        rationale=(
            "Email sent over unencrypted connections can be intercepted and "
            "read by third parties.  Requiring TLS for all inbound and outbound "
            "messages ensures that email content is encrypted in transit."
        ),
        impact=(
            "Email from domains that do not support TLS may be rejected or "
            "quarantined.  TLS compliance rules should be configured "
            "thoughtfully to avoid disrupting critical mail flows."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Compliance\n"
            "  4. Select Secure transport (TLS) compliance → Configure\n"
            "  5. Ensure Inbound is set to require TLS for all messages\n"
            "  6. Ensure Outbound is set to require TLS for all messages"
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Compliance\n"
            "  4. Select Secure transport (TLS) compliance → Configure\n"
            "  5. Set Inbound to require TLS for all messages\n"
            "  6. Set Outbound to require TLS for all messages\n"
            "  7. Click Save"
        ),
        default_value=(
            "Secure transport is enabled with best-effort TLS by default; "
            "strict TLS enforcement must be explicitly configured."
        ),
        references=[
            "https://support.google.com/a/answer/2520500",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.10",
                title="Encrypt Sensitive Data in Transit",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["gmail", "tls", "encryption", "compliance", "secure-transport"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify email is sent over a secure TLS connection:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select Compliance\n"
            "  4. Select Secure transport (TLS) compliance → Configure\n"
            "  5. Ensure Inbound is set to require TLS for all messages\n"
            "  6. Ensure Outbound is set to require TLS for all messages"
        )
