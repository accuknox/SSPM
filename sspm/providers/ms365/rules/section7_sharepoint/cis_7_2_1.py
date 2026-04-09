"""
CIS MS365 7.2.1 (L1) – Ensure modern authentication for SharePoint is required
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
class CIS_7_2_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.2.1",
        title="Ensure modern authentication for SharePoint applications is required",
        section="7.2 Policies",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "SharePoint Online should require modern authentication to enable "
            "MFA and Conditional Access policies to apply to SharePoint connections. "
            "Legacy authentication should be blocked for SharePoint."
        ),
        rationale=(
            "Legacy authentication bypasses MFA and Conditional Access, making "
            "SharePoint resources accessible with just a password. Modern auth "
            "enables comprehensive security controls."
        ),
        impact="Legacy SharePoint clients that don't support modern auth will be blocked.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check: isLegacyAuthProtocolsEnabled = false (legacy auth disabled)"
        ),
        remediation=(
            "SharePoint admin center → Settings > SharePoint > Restrict access to "
            "legacy authentication.\n\n"
            "Or via PowerShell:\n"
            "  Set-SPOTenant -LegacyAuthProtocolsEnabled $false"
        ),
        default_value="Legacy authentication may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/control-access-based-on-network-location",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.3",
                title="Require MFA for Externally-Exposed Applications",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["sharepoint", "modern-auth", "legacy-auth", "mfa"],
    )

    async def check(self, data: CollectedData):
        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip(
                "Could not retrieve SharePoint settings. "
                "Requires SharePoint Administrator role."
            )

        # Check legacy auth setting
        legacy_auth_enabled = settings.get("isLegacyAuthProtocolsEnabled")

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={"isLegacyAuthProtocolsEnabled": legacy_auth_enabled},
                description="SharePoint legacy authentication setting.",
            )
        ]

        if legacy_auth_enabled is False:
            return self._pass(
                "Legacy authentication is disabled for SharePoint "
                "(isLegacyAuthProtocolsEnabled = false).",
                evidence=evidence,
            )

        if legacy_auth_enabled is True:
            return self._fail(
                "Legacy authentication is enabled for SharePoint "
                "(isLegacyAuthProtocolsEnabled = true). "
                "Modern authentication is not being enforced.",
                evidence=evidence,
            )

        return self._manual(
            "Legacy auth setting not found in SharePoint settings. Verify manually:\n"
            "  SharePoint admin center → Settings > SharePoint"
        )
