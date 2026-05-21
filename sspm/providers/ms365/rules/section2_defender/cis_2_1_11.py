"""
CIS MS365 2.1.11 (L1) – Ensure that an anti-malware policy has comprehensive
attachment filtering (Manual)

Profile Applicability: E3 Level 1, E5 Level 1
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
class CIS_2_1_11(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.11",
        title="Ensure that an anti-malware policy has comprehensive attachment filtering",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "The anti-malware policy should have comprehensive file type filtering "
            "that goes beyond the default set. Additional dangerous file types such "
            "as .ps1, .bat, .cmd, and others should be blocked."
        ),
        rationale=(
            "Attackers use many file types to deliver malware. Comprehensive filtering "
            "ensures that less common but equally dangerous file types are also "
            "blocked at the email gateway."
        ),
        impact=(
            "Legitimate emails with the blocked file types will be quarantined. "
            "Users will need to use alternative methods to share these file types."
        ),
        audit_procedure=(
            "Using Exchange Online PowerShell:\n"
            "  Get-MalwareFilterPolicy | Select Name, EnableFileFilter, FileTypes\n\n"
            "Verify FileTypes includes common script and executable extensions:\n"
            "  .ace, .ani, .app, .cmd, .exe, .js, .msi, .ps1, .reg, .vbe, .vbs, .wsh"
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true\n"
            "  Set-MalwareFilterPolicy -Identity Default -FileTypes "
            "'ace','ani','app','cab','cmd','com','exe','gz','hta','img','iso',"
            "'jar','jnlp','js','mde','msi','msp','ps1','ps2','reg','scr','tar',"
            "'uue','vbe','vbs','wsc','wsf','wsh'"
        ),
        default_value="Default file type filtering includes common types but may not be comprehensive.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="9.6",
                title="Block Unnecessary File Types",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "anti-malware", "attachment-filter", "email-security"],
    )

    async def check(self, data: CollectedData):
        return self._manual()
