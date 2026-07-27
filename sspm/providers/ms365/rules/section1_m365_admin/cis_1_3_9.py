"""
CIS MS365 1.3.9 (L1) – Ensure shared bookings pages are restricted to select
users (Automated)

Profile Applicability: E3 Level 1, E5 Level 1
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
class CIS_1_3_9(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.9",
        title="Ensure shared bookings pages are restricted to select users",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.LOW,
        description=(
            "Shared Bookings allows you to invite your team members and create "
            "booking pages and let your customers book time with you and your "
            "team. The recommended state is to restrict the "
            "OwaMailboxPolicy-Default policy or disable Bookings at the "
            "organization level."
        ),
        rationale=(
            "Shared Bookings pages can be exploited by threat actors to "
            "impersonate legitimate users using convincing internal email "
            "addresses. A compromised low-privilege account could be used to "
            "mimic high-profile identities (e.g., the CEO) and bypass "
            "impersonation filters to initiate fraudulent actions like fund "
            "transfers."
        ),
        impact=(
            "Users will not be able to create new Bookings calendars/pages "
            "unless explicitly permitted, and external customers will not be "
            "able to book appointments if Bookings is disabled at the "
            "organization level."
        ),
        audit_procedure=(
            "Ensure Shared Bookings is turned off in the OWA Default policy. "
            "If booking is disabled at the tenant (OrganizationConfig) level "
            "this is also a compliant state.\n\n"
            "To audit using PowerShell:\n"
            "  1. Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "  2. Run: Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default | "
            "fl BookingsMailboxCreationEnabled\n"
            "  3. Ensure BookingsMailboxCreationEnabled is set to False.\n\n"
            "Optionally: Get-OrganizationConfig | fl BookingsEnabled — if False, "
            "also compliant."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default "
            "-BookingsMailboxCreationEnabled $false\n\n"
            "Or disable Bookings entirely at the organization level:\n"
            "  Set-OrganizationConfig -BookingsEnabled $false"
        ),
        default_value="BookingsMailboxCreationEnabled is True by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/bookings/bookings-faq",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/set-owamailboxpolicy",
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
        tags=["bookings", "external-sharing", "data-protection"],
    )

    async def check(self, data: CollectedData):
        if "owa_mailbox_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the OWA mailbox policy: "
                f"{data.errors.get('owa_mailbox_policy')}"
            )

        owa_policy = data.get("owa_mailbox_policy")
        if owa_policy is None:
            return self._manual(
                "Shared Bookings restriction requires the Exchange Online "
                "PowerShell bridge (Connect-ExchangeOnline with certificate "
                "app-only auth), which is not configured for this scan. "
                "Verify manually: Get-OwaMailboxPolicy -Identity "
                "OwaMailboxPolicy-Default | fl BookingsMailboxCreationEnabled "
                "(should be False), or Get-OrganizationConfig | fl "
                "BookingsEnabled (should be False)."
            )

        org_config = data.get("organization_config")
        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default",
                data={
                    "BookingsMailboxCreationEnabled": owa_policy.get(
                        "BookingsMailboxCreationEnabled"
                    )
                },
                description="OWA mailbox default policy.",
            )
        ]

        bookings_mailbox_creation_enabled = owa_policy.get(
            "BookingsMailboxCreationEnabled"
        )
        if bookings_mailbox_creation_enabled is False:
            return self._pass(
                "BookingsMailboxCreationEnabled is False on "
                "OwaMailboxPolicy-Default.",
                evidence=evidence,
            )

        # Also compliant if Bookings is disabled entirely at the org level,
        # per the audit procedure's alternate compliant state.
        if org_config is not None and org_config.get("BookingsEnabled") is False:
            evidence.append(
                Evidence(
                    source="Exchange Online PowerShell: Get-OrganizationConfig",
                    data={"BookingsEnabled": org_config.get("BookingsEnabled")},
                    description="Organization configuration.",
                )
            )
            return self._pass(
                "Bookings is disabled at the organization level "
                "(BookingsEnabled=False), which is also compliant even "
                "though BookingsMailboxCreationEnabled is not False.",
                evidence=evidence,
            )

        return self._fail(
            "BookingsMailboxCreationEnabled is "
            f"{bookings_mailbox_creation_enabled!r} on OwaMailboxPolicy-Default, "
            "and Bookings is not disabled at the organization level.",
            evidence=evidence,
        )
