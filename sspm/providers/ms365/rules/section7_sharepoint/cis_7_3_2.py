"""
CIS MS365 7.3.2 (L1) – Ensure OneDrive sync is restricted for unmanaged
devices (Automated)

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
class CIS_7_3_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-7.3.2",
        title="Ensure OneDrive sync is restricted for unmanaged devices",
        section="7.3 Security",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "OneDrive sync should be restricted to domain-joined devices. "
            "Preventing sync to unmanaged personal devices reduces the risk of "
            "corporate data being stored on unmanaged endpoints."
        ),
        rationale=(
            "When OneDrive sync is allowed on any device, users can sync corporate "
            "data to personal devices that may not have appropriate security controls "
            "(encryption, antivirus, remote wipe capability)."
        ),
        impact="Users will not be able to sync OneDrive to personal unmanaged devices.",
        audit_procedure=(
            "GET /admin/sharepoint/settings\n"
            "Check: isUnmanagedSyncAppForTenantRestricted = true"
        ),
        remediation=(
            "SharePoint admin center → Settings > OneDrive sync.\n"
            "Enable 'Allow syncing only on computers joined to specific domains'.\n\n"
            "PowerShell:\n"
            "  Set-SPOTenant -IsUnmanagedSyncAppForTenantRestricted $true"
        ),
        default_value="OneDrive sync is not restricted by device management status by default.",
        references=[
            "https://learn.microsoft.com/en-us/sharepoint/allow-syncing-only-on-specific-domains",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="3.12",
                title="Segment Data Processing and Storage Based on Sensitivity",
                ig1=False,
                ig2=False,
                ig3=True,
            ),
        ],
        tags=["sharepoint", "onedrive", "sync", "unmanaged-devices"],
    )

    async def check(self, data: CollectedData):
        settings = data.get("sharepoint_settings")
        if settings is None:
            return self._skip("Could not retrieve SharePoint settings.")

        sync_restricted = settings.get("isUnmanagedSyncAppForTenantRestricted")

        evidence = [
            Evidence(
                source="graph/admin/sharepoint/settings",
                data={"isUnmanagedSyncAppForTenantRestricted": sync_restricted},
                description="OneDrive sync restriction for unmanaged devices.",
            )
        ]

        if sync_restricted is True:
            return self._pass(
                "OneDrive sync is restricted to managed devices "
                "(isUnmanagedSyncAppForTenantRestricted = true).",
                evidence=evidence,
            )

        if sync_restricted is False:
            return self._fail(
                "OneDrive sync is allowed on unmanaged devices "
                "(isUnmanagedSyncAppForTenantRestricted = false). "
                "Corporate data can be synced to personal devices.",
                evidence=evidence,
            )

        return self._manual(
            "OneDrive sync restriction setting not found. Verify manually:\n"
            "  SharePoint admin center → Settings > OneDrive sync"
        )
