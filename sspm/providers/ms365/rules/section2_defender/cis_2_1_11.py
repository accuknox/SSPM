"""
CIS MS365 2.1.11 (L1) – Ensure comprehensive attachment filtering is applied
(Automated)

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
class CIS_2_1_11(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.11",
        title="Ensure comprehensive attachment filtering is applied",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
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
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-MalwareFilterPolicy and Get-MalwareFilterRule.\n\n"
            "A comprehensive policy must: define at least 120 of CIS's reference "
            "list of 184 file extensions (a 90% threshold), have the "
            "corresponding rule's State = Enabled, and EnableFileFilter = True."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true\n"
            "  Set-MalwareFilterPolicy -Identity Default -FileTypes "
            "'ace','ani','app','cab','cmd','com','exe','gz','hta','img','iso',"
            "'jar','jnlp','js','mde','msi','msp','ps1','ps2','reg','scr','tar',"
            "'uue','vbe','vbs','wsc','wsf','wsh',... (through the full CIS "
            "reference list of 184 extensions)\n"
            "  Enable-MalwareFilterRule -Identity Default"
        ),
        default_value="Default file type filtering includes common types but may not be comprehensive.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-malwarefilterrule",
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

    _MIN_FILE_TYPES = 120

    async def check(self, data: CollectedData):
        if "malware_filter_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the malware filter policy: "
                f"{data.errors.get('malware_filter_policy')}"
            )

        policies = data.get("malware_filter_policy")
        if policies is None:
            return self._manual(
                "Comprehensive attachment filtering requires the Exchange "
                "Online PowerShell bridge (Connect-ExchangeOnline with "
                "certificate app-only auth), which is not configured for "
                "this scan. Verify manually: Get-MalwareFilterPolicy | "
                "Select-Object EnableFileFilter, FileTypes and "
                "Get-MalwareFilterRule | Select-Object State (the policy "
                "must define at least 120 of CIS's 184 reference file "
                "extensions, EnableFileFilter=True, and the rule "
                "State=Enabled)."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-MalwareFilterPolicy",
                data=policies,
                description="Malware filter policies.",
            )
        ]

        # NOTE: Get-MalwareFilterRule (rule State=Enabled) is not collected
        # by the PowerShell bridge, so we cannot verify the corresponding
        # rule's enabled state here. We check what is available:
        # EnableFileFilter and the size of the FileTypes list.
        compliant = [
            p
            for p in policies
            if p.get("EnableFileFilter") is True
            and len(p.get("FileTypes") or []) >= self._MIN_FILE_TYPES
        ]
        if compliant:
            names = ", ".join(p.get("Identity", "<unknown>") for p in compliant)
            return self._pass(
                f"Found policy(ies) with comprehensive file filtering: "
                f"{names} (EnableFileFilter=True and >= "
                f"{self._MIN_FILE_TYPES} file types defined). NOTE: the "
                "corresponding rule's State=Enabled was not verified "
                "(Get-MalwareFilterRule data is not collected) — confirm "
                "the rule is enabled and applies to all recipients.",
                evidence=evidence,
            )

        return self._fail(
            "No malware filter policy defines at least "
            f"{self._MIN_FILE_TYPES} file extensions with EnableFileFilter="
            f"True (checked {len(policies)} policy(ies)).",
            evidence=evidence,
        )
