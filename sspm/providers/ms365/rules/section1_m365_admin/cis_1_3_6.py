"""
CIS MS365 1.3.6 (L2) – Ensure the customer lockbox feature is enabled
(Automated)

Profile Applicability: E5 Level 2

Customer Lockbox ensures that Microsoft cannot access tenant content to perform
a service operation without explicit approval from the customer.

Per the official CIS audit procedure, this is read via Exchange Online
PowerShell (Get-OrganizationConfig -> CustomerLockBoxEnabled). There is no
Microsoft Graph field for this (the organization resource has no
"isCustomerLockboxEnabled" property — that assumption was incorrect).
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
class CIS_1_3_6(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.6",
        title="Ensure the customer lockbox feature is enabled",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "Customer Lockbox provides an additional layer of control by requiring "
            "explicit customer approval before Microsoft support engineers can access "
            "tenant data to resolve a service request."
        ),
        rationale=(
            "Customer Lockbox ensures that Microsoft access to customer data is "
            "auditable and requires customer approval, supporting compliance "
            "requirements around data access controls."
        ),
        impact=(
            "When Microsoft needs to access tenant data to resolve a support case, "
            "a Global Administrator must approve the request within 12 hours. "
            "If not approved, Microsoft cannot access the data."
        ),
        audit_procedure=(
            "Exchange Online PowerShell:\n"
            "  Connect-ExchangeOnline\n"
            "  Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled\n"
            "  Verify the value is True.\n\n"
            "Microsoft 365 admin center → Settings > Org settings > Security & privacy "
            "> Customer Lockbox → verify 'Require approval for all data access "
            "requests' is checked."
        ),
        remediation=(
            "Microsoft 365 admin center → Settings > Org settings > Security & privacy.\n"
            "Enable 'Customer Lockbox'.\n\n"
            "Requires Microsoft 365 E5 or Microsoft 365 E5 Compliance add-on."
        ),
        default_value="Customer Lockbox is disabled by default.",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/compliance/customer-lockbox-requests",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.1",
                title="Establish an Access Granting Process",
                ig1=False,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["compliance", "customer-lockbox", "data-protection", "e5"],
    )

    async def check(self, data: CollectedData):
        if "organization_config" in (data.errors or {}):
            return self._skip(
                "Could not retrieve Exchange organization configuration: "
                f"{data.errors.get('organization_config')}"
            )

        org_config = data.get("organization_config")
        if org_config is None:
            return self._manual(
                "CustomerLockBoxEnabled requires the Exchange Online "
                "PowerShell bridge (Connect-ExchangeOnline with certificate "
                "app-only auth), which is not configured for this scan. "
                "Verify manually: Get-OrganizationConfig | Select-Object "
                "CustomerLockBoxEnabled — must be True."
            )

        evidence = [
            Evidence(
                source="Exchange Online PowerShell: Get-OrganizationConfig",
                data={"CustomerLockBoxEnabled": org_config.get("CustomerLockBoxEnabled")},
                description="Organization configuration.",
            )
        ]

        if org_config.get("CustomerLockBoxEnabled") is True:
            return self._pass(
                "Customer Lockbox is enabled (CustomerLockBoxEnabled=True).",
                evidence=evidence,
            )

        return self._fail(
            "Customer Lockbox is not enabled "
            f"(CustomerLockBoxEnabled={org_config.get('CustomerLockBoxEnabled')!r}).",
            evidence=evidence,
        )
