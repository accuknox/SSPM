"""
CIS MS365 6.3.1 (L2) – Ensure users installing Outlook add-ins is not allowed
(Automated)

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
        title="Ensure users installing Outlook add-ins is not allowed",
        section="6.3 Add-ins",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-EXOMailbox -PropertySets Policy | Select-Object -Unique "
            "RoleAssignmentPolicy\n"
            "  For each policy returned: Get-RoleAssignmentPolicy -Identity "
            "<policy>\n\n"
            "Compliant: 'My Custom Apps', 'My Marketplace Apps', and 'My "
            "ReadWriteMailbox Apps' are NOT present in AssignedRoles for any "
            "policy."
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
        # Get-RoleAssignmentPolicy has no Microsoft Graph equivalent; it is
        # only reachable via Exchange Online Remote PowerShell.
        if "role_assignment_policies" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange role assignment policies: "
                f"{data.errors.get('role_assignment_policies')}"
            )

        return self._manual(
            message=(
                "Role assignment policies cannot be read via Microsoft Graph. "
                "Verify manually via Exchange Online PowerShell: "
                "Get-RoleAssignmentPolicy - ensure 'My Custom Apps', "
                "'My Marketplace Apps', and 'My ReadWriteMailbox Apps' are not "
                "present in AssignedRoles for any policy."
            )
        )
