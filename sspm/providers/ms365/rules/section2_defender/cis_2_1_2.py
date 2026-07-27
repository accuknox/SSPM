"""
CIS MS365 2.1.2 (L1) – Ensure the Common Attachment Types Filter is enabled
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
class CIS_2_1_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.2",
        title="Ensure the Common Attachment Types Filter is enabled",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "The Common Attachment Types Filter in Exchange Online Protection blocks "
            "email messages that contain file types commonly used in malware attacks "
            "(e.g., .exe, .vbs, .js). This filter should be enabled on anti-malware policies."
        ),
        rationale=(
            "Common attachment types used in malware distribution include executable "
            "files, scripts, and other dangerous file types. Blocking these at the "
            "email gateway prevents them from reaching end users."
        ),
        impact=(
            "Emails with blocked attachment types will be quarantined or rejected. "
            "Users who legitimately need to send/receive these file types will need "
            "alternative delivery methods."
        ),
        audit_procedure=(
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-MalwareFilterPolicy -Identity Default | "
            "Select-Object EnableFileFilter\n\n"
            "Verify EnableFileFilter is True."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Anti-malware.\n"
            "Edit the default anti-malware policy:\n"
            "  • Enable 'Common attachments filter'\n\n"
            "PowerShell:\n"
            "  Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true"
        ),
        default_value="Common Attachment Types Filter is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-malwarefilterpolicy",
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
        if "malware_filter_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the malware filter policy: "
                f"{data.errors.get('malware_filter_policy')}"
            )

        policies = data.get("malware_filter_policy")
        if policies is None:
            return self._manual(
                "The Common Attachment Types Filter setting requires the "
                "Exchange Online PowerShell bridge (Connect-ExchangeOnline "
                "with certificate app-only auth), which is not configured "
                "for this scan. Verify manually: Get-MalwareFilterPolicy "
                "-Identity Default | Select-Object EnableFileFilter (should "
                "be True)."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-MalwareFilterPolicy",
                data=policies,
                description="Malware filter policies.",
            )
        ]

        compliant = [p for p in policies if p.get("EnableFileFilter") is True]
        if compliant:
            names = ", ".join(p.get("Identity", "<unknown>") for p in compliant)
            return self._pass(
                f"The Common Attachment Types Filter is enabled on: {names}.",
                evidence=evidence,
            )

        return self._fail(
            "The Common Attachment Types Filter (EnableFileFilter) is not "
            f"enabled on any of the {len(policies)} malware filter policy(ies).",
            evidence=evidence,
        )
