"""
CIS MS365 6.5.2 (L2) – Ensure MailTips are enabled for end users (Automated)

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
class CIS_6_5_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-6.5.2",
        title="Ensure MailTips are enabled for end users",
        section="6.5 Client Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "MailTips should be enabled to provide users with informational messages "
            "when composing emails that may indicate issues or potential problems, "
            "such as sending to external recipients or large distribution lists."
        ),
        rationale=(
            "MailTips warn users before sending emails that might be sent to the "
            "wrong recipient, contain sensitive data recipients shouldn't see, or "
            "indicate other potential issues, reducing accidental data exposure."
        ),
        impact="No negative impact; MailTips provide helpful reminders to users.",
        audit_procedure=(
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-OrganizationConfig | fl MailTips*\n\n"
            "Compliant: MailTipsAllTipsEnabled = True, "
            "MailTipsExternalRecipientsTipsEnabled = True, "
            "MailTipsGroupMetricsEnabled = True, and "
            "MailTipsLargeAudienceThreshold is set to an acceptable value "
            "(default 25)."
        ),
        remediation=(
            "Exchange Online PowerShell:\n"
            "  Set-OrganizationConfig -MailTipsAllTipsEnabled $true "
            "-MailTipsExternalRecipientsTipsEnabled $true "
            "-MailTipsGroupMetricsEnabled $true -MailTipsLargeAudienceThreshold 25"
        ),
        default_value="MailTips settings may vary.",
        references=[
            "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/mailtips/mailtips",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="14.1",
                title="Establish and Maintain a Security Awareness Program",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["exchange", "mailtips", "user-awareness", "data-protection"],
    )

    async def check(self, data: CollectedData):
        # Get-OrganizationConfig has no Microsoft Graph equivalent; it is only
        # reachable via Exchange Online Remote PowerShell.
        if "organization_config" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange organization configuration: "
                f"{data.errors.get('organization_config')}"
            )

        org_config = data.get("organization_config")
        if org_config is None:
            return self._skip(
                "MailTips settings require the Exchange Online PowerShell "
                "bridge (Connect-ExchangeOnline with certificate app-only "
                "auth), which is not configured for this scan. Verify "
                "manually: Get-OrganizationConfig | fl MailTips* - "
                "MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, "
                "and MailTipsGroupMetricsEnabled must be True, and "
                "MailTipsLargeAudienceThreshold should be set appropriately "
                "(default 25)."
            )

        all_tips = org_config.get("MailTipsAllTipsEnabled")
        external_tips = org_config.get("MailTipsExternalRecipientsTipsEnabled")
        group_metrics = org_config.get("MailTipsGroupMetricsEnabled")
        threshold = org_config.get("MailTipsLargeAudienceThreshold")

        evidence = [
            Evidence(
                source="Get-OrganizationConfig",
                data={
                    "MailTipsAllTipsEnabled": all_tips,
                    "MailTipsExternalRecipientsTipsEnabled": external_tips,
                    "MailTipsGroupMetricsEnabled": group_metrics,
                    "MailTipsLargeAudienceThreshold": threshold,
                },
                description="Organization-level MailTips settings.",
            )
        ]

        problems = []
        if not all_tips:
            problems.append("MailTipsAllTipsEnabled is not True")
        if not external_tips:
            problems.append("MailTipsExternalRecipientsTipsEnabled is not True")
        if not group_metrics:
            problems.append("MailTipsGroupMetricsEnabled is not True")
        if threshold is None or threshold > 25:
            problems.append(
                f"MailTipsLargeAudienceThreshold is {threshold} (should be 25 or less)"
            )

        if problems:
            return self._fail(
                "MailTips are not fully enabled: " + "; ".join(problems),
                evidence=evidence,
            )

        return self._pass(
            "MailTips are enabled: MailTipsAllTipsEnabled, "
            "MailTipsExternalRecipientsTipsEnabled, and "
            "MailTipsGroupMetricsEnabled are all True, and "
            f"MailTipsLargeAudienceThreshold is {threshold}.",
            evidence=evidence,
        )
