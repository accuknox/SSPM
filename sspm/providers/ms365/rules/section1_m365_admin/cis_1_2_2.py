"""
CIS MS365 1.2.2 (L1) – Ensure sign-in to shared mailboxes is blocked (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Shared mailboxes should have their associated user account disabled to prevent
direct sign-in.
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
class CIS_1_2_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.2.2",
        title="Ensure sign-in to shared mailboxes is blocked",
        section="1.2 Groups",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Shared mailboxes in Exchange Online have an associated user account. "
            "This account should have sign-in blocked (accountEnabled = false) to "
            "prevent it from being used as a direct sign-in account, which could "
            "bypass MFA and other controls."
        ),
        rationale=(
            "Shared mailbox accounts often have weak or no password protections. "
            "Blocking sign-in ensures that only properly authenticated users who "
            "are delegates can access the shared mailbox through their own account."
        ),
        impact=(
            "Blocking sign-in to shared mailboxes prevents direct authentication "
            "as the shared mailbox account. Users must access the mailbox via "
            "delegation from their own account."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /users?$filter=assignedLicenses/$count eq 0 and userType eq 'Member'"
            "&$select=id,displayName,userPrincipalName,accountEnabled,mail&$top=999\n"
            "  Also check: GET /users?$select=id,userPrincipalName,accountEnabled,"
            "assignedLicenses,onPremisesExtensionAttributes&$top=999\n"
            "  Shared mailboxes typically have no licenses assigned. "
            "  Compliant: accountEnabled = false for shared mailbox accounts."
        ),
        remediation=(
            "For each shared mailbox user with sign-in enabled:\n"
            "  1. Microsoft 365 admin center → Users > Active users.\n"
            "  2. Select the shared mailbox user → Block sign-in.\n"
            "  Or via PowerShell:\n"
            "  Get-Mailbox -RecipientTypeDetails SharedMailbox | "
            "ForEach-Object { Set-AzureADUser -ObjectId $_.ExternalDirectoryObjectId "
            "-AccountEnabled $false }"
        ),
        default_value="Shared mailbox accounts have sign-in enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes",
            "https://learn.microsoft.com/en-us/exchange/collaboration-exo/shared-mailboxes",
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
        tags=["identity", "shared-mailbox", "account-security", "exchange"],
    )

    async def check(self, data: CollectedData):
        users = data.get("users")
        if users is None:
            return self._skip("Could not retrieve users data.")

        # Shared mailbox accounts: no licenses assigned, Member user type, accountEnabled
        # This is a heuristic since the Graph users endpoint doesn't expose recipientTypeDetails
        no_license_enabled = [
            u for u in users
            if not (u.get("assignedLicenses") or [])
            and u.get("accountEnabled") is True
            and u.get("userType") == "Member"
            and u.get("userPrincipalName", "").endswith(".onmicrosoft.com") is False
        ]

        if not no_license_enabled:
            return self._pass(
                "No unlicensed member accounts with sign-in enabled found. "
                "Shared mailbox accounts appear to have sign-in blocked.",
                evidence=[
                    Evidence(
                        source="graph/users",
                        data={"totalUsersChecked": len(users)},
                        description="No potential shared mailbox accounts with sign-in enabled.",
                    )
                ],
            )

        return self._fail(
            f"{len(no_license_enabled)} unlicensed member account(s) have sign-in "
            "enabled. These may be shared mailboxes—verify and block sign-in.",
            evidence=[
                Evidence(
                    source="graph/users",
                    data=[
                        {
                            "id": u.get("id"),
                            "userPrincipalName": u.get("userPrincipalName"),
                            "accountEnabled": True,
                            "assignedLicenseCount": 0,
                        }
                        for u in no_license_enabled[:50]
                    ],
                    description="Unlicensed member accounts with sign-in enabled (first 50).",
                )
            ],
        )
