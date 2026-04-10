"""
CIS GWS 3.1.3.5.1 (L2) – Ensure POP and IMAP access is disabled for all
users in Google Workspace Gmail (Automated)

Profile Applicability: Enterprise Level 2
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
class CIS_3_1_3_5_1(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-3.1.3.5.1",
        title="Ensure POP and IMAP access is disabled for all users in Google Workspace Gmail",
        section="3.1.3 Gmail",
        benchmark="CIS Google Workspace Foundations Benchmark v1.3.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.GWS_EL2],
        severity=Severity.MEDIUM,
        description=(
            "Disabling POP and IMAP prevents users from accessing Gmail via "
            "legacy mail protocols that do not support modern authentication.  "
            "These protocols bypass MFA controls and expose credentials to "
            "brute-force and credential-stuffing attacks."
        ),
        rationale=(
            "POP and IMAP access use basic authentication and do not support "
            "multi-factor authentication, making accounts vulnerable to "
            "credential-based attacks.  Disabling them forces users to "
            "authenticate through the more secure OAuth-based web or app flows."
        ),
        impact=(
            "Users will not be able to access Gmail via POP or IMAP clients "
            "such as traditional desktop mail applications."
        ),
        audit_procedure=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Ensure 'POP Access' is unchecked\n"
            "  5. Ensure 'IMAP Access' is unchecked\n\n"
            "Automated check: queries Gmail API settings for all active users "
            "via domain-wide delegation (requires gmail.settings.basic scope)."
        ),
        remediation=(
            "Google Workspace Admin Console:\n"
            "  1. Log in to https://admin.google.com\n"
            "  2. Select Apps → Google Workspace → Gmail\n"
            "  3. Select End User Access\n"
            "  4. Uncheck 'POP Access'\n"
            "  5. Uncheck 'IMAP Access'\n"
            "  6. Click Save"
        ),
        default_value="POP and IMAP access are both enabled by default.",
        references=[
            "https://support.google.com/a/answer/105694",
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
        tags=["gmail", "pop", "imap", "legacy-auth", "end-user-access"],
    )

    async def check(self, data: CollectedData):
        imap_users: list | None = data.get("gmail_imap_enabled")
        pop_users: list | None = data.get("gmail_pop_enabled")

        # If both lists are unavailable the gmail.settings.basic scope is likely
        # missing from DWD — fall back to manual.
        if imap_users is None and pop_users is None:
            return self._manual(
                "Gmail per-user settings could not be collected.  "
                "Ensure the 'gmail.settings.basic' scope is authorised in "
                "Domain-wide Delegation, then re-run the scan.\n\n"
                "Manual verification:\n"
                "  1. Log in to https://admin.google.com\n"
                "  2. Select Apps → Google Workspace → Gmail → End User Access\n"
                "  3. Ensure 'POP Access' and 'IMAP Access' are both unchecked"
            )

        violations: list[str] = []
        evidence: list[Evidence] = []

        for email in (imap_users or []):
            violations.append(email)
            evidence.append(Evidence(
                source="Gmail API – IMAP settings",
                data={"email": email, "imap": "enabled"},
                description=f"{email}: IMAP is enabled",
            ))

        for email in (pop_users or []):
            violations.append(email)
            evidence.append(Evidence(
                source="Gmail API – POP settings",
                data={"email": email, "pop": "enabled"},
                description=f"{email}: POP is enabled",
            ))

        if violations:
            return self._fail(
                f"{len(violations)} user(s) have POP or IMAP access enabled: "
                f"{', '.join(violations[:5])}"
                + (" …" if len(violations) > 5 else ""),
                evidence=evidence,
            )

        total = len(data.get("users") or [])
        return self._pass(
            f"No active users have POP or IMAP access enabled "
            f"(checked {total} user accounts)."
        )
