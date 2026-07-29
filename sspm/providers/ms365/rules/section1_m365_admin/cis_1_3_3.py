"""
CIS MS365 1.3.3 (L2) – Ensure 'External sharing' of calendars is not
available (Automated)

Profile Applicability: E3 Level 2, E5 Level 2
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
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_1_3_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.3",
        title="Ensure 'External sharing' of calendars is not available",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Sharing calendar details externally can expose sensitive information "
            "about employee schedules and business operations. External calendar "
            "sharing should be disabled unless there is a specific business need."
        ),
        rationale=(
            "Calendar data can reveal meeting participants, meeting subjects, and "
            "availability patterns that could be leveraged by attackers for social "
            "engineering, spear phishing, or physical security attacks."
        ),
        impact=(
            "Users will not be able to share their full calendar details with "
            "external recipients. Free/busy information may still be shared based "
            "on configuration."
        ),
        audit_procedure=(
            "Exchange admin center → Organization > Sharing.\n"
            "Check Organization Sharing policies for external sharing with "
            "calendar details enabled.\n\n"
            "Or via Exchange Online PowerShell:\n"
            "  Get-SharingPolicy | Select Name, Domains, Enabled\n"
            "  Look for policies with CalendarSharing or FreeBusySimple permissions "
            "applied to anonymous or external domains."
        ),
        remediation=(
            "Exchange admin center → Organization > Sharing.\n"
            "Edit or remove sharing policies that allow external calendar detail sharing.\n\n"
            "PowerShell:\n"
            "  Set-SharingPolicy -Identity 'Default Sharing Policy' -Enabled $false\n"
            "  Or restrict to FreeBusySimple for external domains."
        ),
        default_value="External calendar sharing may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies",
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
        tags=["exchange", "calendar", "sharing", "data-protection"],
    )

    async def check(self, data: CollectedData):
        if "sharing_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange sharing policy: "
                f"{data.errors.get('sharing_policy')}"
            )

        policy = data.get("sharing_policy")
        if policy is None:
            return self._skip(
                "Calendar external sharing requires the Exchange Online "
                "PowerShell bridge (Connect-ExchangeOnline with certificate "
                "app-only auth), which is not configured for this scan. "
                "Verify manually: Get-SharingPolicy -Identity 'Default "
                "Sharing Policy' | Select Name, Domains, Enabled — Enabled "
                "must be False, or Domains must not grant full calendar "
                "detail sharing to anonymous/external domains."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-SharingPolicy",
                data=policy,
                description="Default Sharing Policy.",
            )
        ]

        if not policy.get("Enabled"):
            return self._pass(
                "The Default Sharing Policy is disabled (Enabled=False).",
                evidence=evidence,
            )

        # Domains is a list of "Domain:Permission" strings, e.g.
        # "Anonymous:CalendarSharingFreeBusySimple" (free/busy only — safe)
        # vs "Anonymous:CalendarSharingFreeBusyDetail" or a bare
        # "CalendarSharing" permission (full calendar details — unsafe).
        domains = policy.get("Domains") or []
        unsafe_entries = [
            d
            for d in domains
            if "CalendarSharing" in d and "FreeBusySimple" not in d
        ]

        if unsafe_entries:
            return self._fail(
                "The Default Sharing Policy is enabled and grants full "
                "calendar detail sharing (not just free/busy) to: "
                + ", ".join(unsafe_entries),
                evidence=evidence,
            )

        return self._pass(
            "The Default Sharing Policy is enabled but does not grant full "
            "calendar detail sharing to any external/anonymous domain "
            "(only free/busy sharing, if any, is permitted).",
            evidence=evidence,
        )
