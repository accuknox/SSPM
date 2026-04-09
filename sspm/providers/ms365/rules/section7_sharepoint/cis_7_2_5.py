"""
CIS MS365 7.2.5 (L1) – Ensure that SharePoint external users cannot share
items they don't own (Automated)

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
class CIS_7_2_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.5",
        title="Ensure that SharePoint external users cannot share items they don't own",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "External users should not be able to re-share content they don't own. "
            "This prevents external users from sharing organizational content with "
            "other unauthorized parties."
        ),
        rationale=(
            "If external users can re-share items they have access to, content can "
            "spread to unapproved parties exponentially. Restricting re-sharing "
            "limits data exposure to explicitly authorized recipients."
        ),
        impact="External users will not be able to share content they access but don't own.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check: preventExternalUsersFromResharing = true"
        ),
        remediation=(
            "SharePoint admin center → Policies > Sharing.\n"
            "Disable 'Allow guests to share items they don't own'.\n\n"
            "PowerShell:\n"
            "  Set-SPOTenant -PreventExternalUsersFromResharing $true"
        ),
        default_value="External users can re-share by default.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.3",
                title="Configure Data Access Control Lists",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["sharepoint", "external-sharing", "re-sharing", "data-protection"],
    )

    async def check(self, data: CollectedData):
        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip("Could not retrieve SharePoint settings.")

        prevent_resharing = settings.get("preventExternalUsersFromResharing")

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={"preventExternalUsersFromResharing": prevent_resharing},
                description="SharePoint resharing restriction setting.",
            )
        ]

        if prevent_resharing is True:
            return self._pass(
                "External users cannot re-share items they don't own "
                "(preventExternalUsersFromResharing = true).",
                evidence=evidence,
            )

        if prevent_resharing is False:
            return self._fail(
                "External users are allowed to re-share items they don't own "
                "(preventExternalUsersFromResharing = false).",
                evidence=evidence,
            )

        return self._manual(
            "Re-sharing prevention setting not found. Verify manually:\n"
            "  SharePoint admin center → Policies > Sharing\n"
            "  Check 'Allow guests to share items they don't own'"
        )
