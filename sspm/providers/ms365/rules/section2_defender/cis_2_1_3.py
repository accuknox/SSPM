"""
CIS MS365 2.1.3 (L1) – Ensure notifications for internal users sending malware
is Enabled (Automated)

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
class CIS_2_1_3(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-2.1.3",
        title="Ensure notifications for internal users sending malware is Enabled",
        section="2.1 Microsoft Defender for Office 365",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Anti-malware policies should be configured to notify administrators "
            "when internal users send messages containing malware. This provides "
            "early warning of compromised internal accounts."
        ),
        rationale=(
            "When an internal user sends malware, it typically indicates a compromised "
            "account or endpoint. Timely notifications allow security teams to "
            "investigate and respond before significant damage occurs."
        ),
        impact=(
            "Administrators will receive notifications when malware is detected in "
            "messages sent by internal users. This may increase alert volume."
        ),
        audit_procedure=(
            "Connect to Exchange Online using Connect-ExchangeOnline.\n"
            "Run: Get-MalwareFilterPolicy | fl Identity, "
            "EnableInternalSenderAdminNotifications, InternalSenderAdminAddress\n\n"
            "Ensure EnableInternalSenderAdminNotifications is True and "
            "InternalSenderAdminAddress is defined."
        ),
        remediation=(
            "Microsoft Defender portal → Email & Collaboration > Policies & Rules > "
            "Threat policies > Anti-malware.\n"
            "Edit the default policy to enable notifications for internal senders.\n\n"
            "PowerShell:\n"
            "  Set-MalwareFilterPolicy -Identity Default "
            "-EnableInternalSenderAdminNotifications $true "
            "-InternalSenderAdminAddress admin@contoso.com"
        ),
        default_value="Internal sender admin notifications are disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure",
            "https://learn.microsoft.com/en-us/powershell/module/exchange/get-malwarefilterpolicy",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="17.4",
                title="Establish and Maintain an Incident Response Process",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["defender", "anti-malware", "notifications", "email-security"],
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
                "Internal sender malware notification settings require the "
                "Exchange Online PowerShell bridge (Connect-ExchangeOnline "
                "with certificate app-only auth), which is not configured "
                "for this scan. Verify manually: Get-MalwareFilterPolicy | "
                "fl Identity, EnableInternalSenderAdminNotifications, "
                "InternalSenderAdminAddress (should be True and a defined "
                "address, respectively)."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-MalwareFilterPolicy",
                data=policies,
                description="Malware filter policies.",
            )
        ]

        compliant = [
            p
            for p in policies
            if p.get("EnableInternalSenderAdminNotifications") is True
            and p.get("InternalSenderAdminAddress")
        ]
        if compliant:
            names = ", ".join(p.get("Identity", "<unknown>") for p in compliant)
            return self._pass(
                "Internal sender malware admin notifications are enabled "
                f"with a configured address on: {names}.",
                evidence=evidence,
            )

        return self._fail(
            "No malware filter policy has both "
            "EnableInternalSenderAdminNotifications=True and a defined "
            f"InternalSenderAdminAddress (checked {len(policies)} policy(ies)).",
            evidence=evidence,
        )
