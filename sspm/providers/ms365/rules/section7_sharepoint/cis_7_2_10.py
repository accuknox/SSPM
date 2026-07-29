"""
CIS MS365 7.2.10 (L2) – Ensure reauthentication with verification code is
restricted (Automated)

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
class CIS_7_2_10(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.10",
        title="Ensure reauthentication with verification code is restricted",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "SharePoint should be configured to require reauthentication with a "
            "verification code within a limited time period for external users "
            "accessing shared content."
        ),
        rationale=(
            "Requiring reauthentication ensures that external users who receive "
            "sharing links must periodically re-verify their identity, reducing "
            "the risk of unauthorized access from shared links."
        ),
        impact="External users will need to re-verify their email periodically.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check: emailAttestationRequired = true and emailAttestationReAuthDays"
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Enable 'People who use a verification code must reauthenticate after "
            "this many days' and set to 30 days or fewer."
        ),
        default_value="Reauthentication for verification codes may not be required.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.3",
                title="Configure Automatic Session Locking on Enterprise Assets",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["sharepoint", "verification-code", "reauthentication", "external-sharing"],
    )

    # CIS: EmailAttestationRequired True, EmailAttestationReAuthDays <= 15.
    MAX_REAUTH_DAYS = 15

    async def check(self, data: CollectedData):
        # These properties have no Microsoft Graph equivalent —
        # /admin/sharepoint/settings does not expose them.
        settings, skip = self._spo_tenant_or_skip(
            data, "EmailAttestationRequired,EmailAttestationReAuthDays"
        )
        if skip is not None:
            return skip

        attestation_required = settings.get("EmailAttestationRequired")
        reauth_days = settings.get("EmailAttestationReAuthDays")

        evidence = [
            Evidence(
                source="sharepoint/Get-SPOTenant",
                data={
                    "EmailAttestationRequired": attestation_required,
                    "EmailAttestationReAuthDays": reauth_days,
                },
                description="Email attestation reauthentication settings.",
            )
        ]

        if attestation_required is not True:
            return self._fail(
                "Reauthentication with a verification code is not required for "
                "external users "
                f"(EmailAttestationRequired = {attestation_required}).",
                evidence=evidence,
            )

        if isinstance(reauth_days, int) and reauth_days <= self.MAX_REAUTH_DAYS:
            return self._pass(
                "Reauthentication with a verification code is required every "
                f"{reauth_days} days.",
                evidence=evidence,
            )

        return self._fail(
            "Reauthentication with a verification code is required, but the "
            f"interval of {reauth_days} days exceeds the CIS maximum of "
            f"{self.MAX_REAUTH_DAYS} days.",
            evidence=evidence,
        )
