"""
CIS GWS 3.1.3.5.2 (L1) – Ensure automatic forwarding options are disabled
(Automated)

Profile Applicability: Enterprise Level 1
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    Evidence,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.gws.rules.base import GWSRule


@registry.rule
class CIS_3_1_3_5_2(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.5.2",
        title="Ensure automatic forwarding options are disabled",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL1],
        severity=Severity.HIGH,
        description=(
            "Prevents users from automatically forwarding all incoming email to "
            "an external address.  Automatic forwarding is a common data "
            "exfiltration technique used after account compromise."
        ),
        rationale=(
            "Automatic email forwarding to external addresses can lead to "
            "sensitive data leaving the organisation without detection.  "
            "Disabling this feature reduces the risk of data exfiltration "
            "following an account compromise."
        ),
        impact=(
            "Users will not be able to configure automatic forwarding rules "
            "that send all incoming email to an external address."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Ensure 'Allow users to automatically forward incoming email "
            "to another address' is unchecked\n\n"
            "Automated check: queries Gmail API autoForwarding settings for all "
            "active users via domain-wide delegation (requires gmail.settings.basic scope)."
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Uncheck 'Allow users to automatically forward incoming email "
            "to another address'\n"
            "  5. Click Save\n\n"
            "For any users currently forwarding, disable their forwarding rules "
            "in Gmail settings or via the Gmail API."
        ),
        default_value=(
            "Allow users to automatically forward incoming email to another "
            "address is checked (enabled) by default."
        ),
        references=[
            "https://support.google.com/a/answer/2525336",
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
        tags=["gmail", "forwarding", "data-exfiltration", "end-user-access"],
    )

    async def check(self, data: CollectedData):
        forwarding_users: list | None = data.get("gmail_forwarding_enabled")

        if forwarding_users is None:
            return self._manual(
                "Gmail per-user forwarding settings could not be collected.  "
                "Ensure the 'gmail.settings.basic' scope is authorised in "
                "Domain-wide Delegation, then re-run the scan.\n\n"
                "Manual verification:\n"
                "  1. Log in to https://admin.google.com\n"
                "  2. Select Apps → Google Workspace → Gmail → End User Access\n"
                "  3. Ensure 'Allow users to automatically forward incoming email "
                "to another address' is unchecked"
            )

        if not forwarding_users:
            total = len(data.get("users") or [])
            return self._pass(
                f"No active users have automatic email forwarding enabled "
                f"(checked {total} user accounts)."
            )

        evidence = [
            Evidence(
                source="Gmail API – autoForwarding settings",
                data=rec,
                description=f"{rec['email']} is forwarding to {rec['forwardTo']}",
            )
            for rec in forwarding_users
        ]

        sample = ", ".join(r["email"] for r in forwarding_users[:5])
        return self._fail(
            f"{len(forwarding_users)} user(s) have automatic email forwarding enabled: "
            f"{sample}" + (" …" if len(forwarding_users) > 5 else ""),
            evidence=evidence,
        )
