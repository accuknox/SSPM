"""
CIS MS365 6.3.1 (L2) – Ensure users cannot install add-ins in Outlook
(Manual)

Profile Applicability: E3 Level 2, E5 Level 2
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
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_6_3_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.3.1",
        title="Ensure users cannot install add-ins in Outlook",
        section="6.3 Add-ins",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Users should not be allowed to install Outlook add-ins from the "
            "Office Store without administrator approval. Unrestricted add-in "
            "installation can introduce malicious or data-exfiltrating plugins."
        ),
        rationale=(
            "Outlook add-ins have access to email data and can exfiltrate "
            "sensitive information. Restricting installation to admin-approved "
            "add-ins ensures only vetted tools access email data."
        ),
        impact="Users must request admin deployment of Outlook add-ins.",
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-RoleAssignmentPolicy | Select Name, AssignedRoles\n"
            "  Look for policies with 'My Custom Apps' or 'My Marketplace Apps' roles\n\n"
            "Compliant: No users have 'My Custom Apps' or 'My Marketplace Apps' roles."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  $policy = Get-RoleAssignmentPolicy 'Default Role Assignment Policy'\n"
            "  Set-RoleAssignmentPolicy -Identity $policy.Identity "
            "-Roles (($policy.AssignedRoles) -notlike 'My*Apps*')"
        ),
        default_value="Users can install Outlook add-ins by default.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/add-ins-for-outlook/specify-who-can-install-and-manage-add-ins",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="2.5",
                title="Allowlist Authorized Software",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["exchange", "outlook", "add-ins", "app-control"],
    )

    async def check(self, data: CollectedData):
        return self._manual(
            "Verify Outlook add-in installation restrictions:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-RoleAssignmentPolicy 'Default Role Assignment Policy' | "
            "Select-Object Name, AssignedRoles\n\n"
            "Compliant: 'My Custom Apps' and 'My Marketplace Apps' are not in AssignedRoles."
        )
