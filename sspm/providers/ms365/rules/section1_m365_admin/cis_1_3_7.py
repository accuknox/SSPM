"""
CIS MS365 1.3.7 (L2) – Ensure 'third-party storage services' are restricted in
'Microsoft 365 on the web' (Automated)

Profile Applicability: E3 Level 2, E5 Level 2

Available via Microsoft Graph: the integration is gated by a first-party
service principal (appId c1f33bc0-bdb4-4248-ba9b-096807ddb43e). If it does
not exist, or exists with accountEnabled = False, the control passes.
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
class CIS_1_3_7(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.7",
        title="Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web'",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "Microsoft 365 web apps (Word, Excel, PowerPoint Online) can connect "
            "to third-party storage services. This should be restricted to prevent "
            "data from being saved to unapproved cloud storage providers."
        ),
        rationale=(
            "Third-party storage services are not subject to the same governance "
            "and compliance controls as OneDrive. Restricting storage options "
            "ensures data stays within approved and governed storage systems."
        ),
        impact=(
            "Users will not be able to open or save files directly to third-party "
            "storage services like Dropbox or Box from Office web apps."
        ),
        audit_procedure=(
            "Microsoft Graph:\n"
            "  $SP = Get-MgServicePrincipal -Filter \"appId eq "
            "'c1f33bc0-bdb4-4248-ba9b-096807ddb43e'\"\n"
            "  Passes if the service principal does not exist, or exists with "
            "AccountEnabled = False.\n\n"
            "Microsoft 365 admin center → Settings > Org settings > Microsoft 365 "
            "on the web.\n"
            "Verify 'Let users open files stored in third-party storage services "
            "in Microsoft 365 on the web' is not checked."
        ),
        remediation=(
            "Microsoft 365 admin center → Settings > Org settings > Office on the web.\n"
            "Disable 'Allow users to open files stored in third-party storage services "
            "in Office on the web'."
        ),
        default_value="Third-party storage may be enabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/admin/misc/third-party-storage",
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
        tags=["data-protection", "storage", "office-online", "third-party"],
    )

    async def check(self, data: CollectedData):
        if "third_party_storage_service_principal" in (data.errors or {}):
            return self._skip(
                "Could not retrieve service principal data: "
                f"{data.errors.get('third_party_storage_service_principal')}"
            )

        sp = data.get("third_party_storage_service_principal")
        evidence = [
            Evidence(
                source="graph/servicePrincipals",
                data={
                    "exists": sp is not None,
                    "accountEnabled": sp.get("accountEnabled") if sp else None,
                },
                description="Third-party storage integration service principal.",
            )
        ]

        if sp is not None and sp.get("accountEnabled") is False:
            return self._pass(
                "Third-party storage services in Microsoft 365 on the web are "
                "restricted (service principal exists and is disabled).",
                evidence=evidence,
            )
        # Per CIS's own audit script, absence of the service principal is
        # itself a FAIL: the integration defaults to enabled, so users can
        # still open third-party storage until the SP is explicitly created
        # and disabled.
        return self._fail(
            "Third-party storage services in Microsoft 365 on the web are not "
            "restricted "
            + (
                "(service principal does not exist)."
                if sp is None
                else "(service principal exists and is enabled)."
            ),
            evidence=evidence,
        )
