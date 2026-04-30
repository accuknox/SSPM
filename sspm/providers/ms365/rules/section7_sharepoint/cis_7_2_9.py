"""
CIS MS365 7.2.9 (L2) – Ensure guest access expires automatically (Automated)

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
class CIS_7_2_9(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.9",
        title="Ensure guest access to SharePoint and OneDrive expires automatically",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Guest access to SharePoint sites and OneDrive should be configured "
            "to expire automatically so that stale guest access is revoked."
        ),
        rationale=(
            "Guest access that does not expire can persist indefinitely after the "
            "original business need is gone. Automatic expiration ensures guest "
            "access is regularly reviewed and renewed."
        ),
        impact="External users will need to request re-invitation after their access expires.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check: externalUserExpirationRequired = true and externalUserExpireInDays"
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Enable 'Guest access expires after this many days' and set to 30 days or fewer."
        ),
        default_value="Guest access does not expire by default.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview",
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
        tags=["sharepoint", "guest-access", "expiration", "external-users"],
    )

    async def check(self, data: CollectedData):
        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip("Could not retrieve SharePoint settings.")

        expiration_required = settings.get("externalUserExpirationRequired")
        expire_days = settings.get("externalUserExpireInDays")

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={
                    "externalUserExpirationRequired": expiration_required,
                    "externalUserExpireInDays": expire_days,
                },
                description="Guest access expiration settings.",
            )
        ]

        if expiration_required is True and expire_days and expire_days <= 180:
            return self._pass(
                f"Guest access expires automatically after {expire_days} days.",
                evidence=evidence,
            )

        if expiration_required is False:
            return self._fail(
                "Guest access does not expire automatically. External users retain "
                "access indefinitely once granted.",
                evidence=evidence,
            )

        return self._manual()
