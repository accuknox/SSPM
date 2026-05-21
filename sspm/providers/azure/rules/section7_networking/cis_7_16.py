"""CIS Azure 7.16 – Ensure Azure Network Security Perimeter is Used to Secure Azure PaaS Resources (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_16(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.16",
        title="Ensure Azure Network Security Perimeter is Used to Secure Azure Platform-as-a-service Resources",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Azure Network Security Perimeter (NSP) should be used to define a logical network "
            "isolation boundary for PaaS resources (such as Azure Storage, Key Vault, and SQL) "
            "to control inbound and outbound network access beyond private endpoints alone."
        ),
        rationale=(
            "PaaS services often have public endpoints that can be accessed from the Internet "
            "even when private endpoints are configured. NSP provides an additional perimeter "
            "control to restrict access to associated resources from unauthorized networks."
        ),
        impact="NSP is a newer feature (preview/GA depending on region); verify service compatibility "
               "before enforcing.",
        audit_procedure=(
            "Azure portal → Network Security Perimeters (search) → verify that critical PaaS "
            "resources (Storage Accounts, Key Vaults, SQL Servers, Service Bus, etc.) are "
            "associated with an NSP profile. Check that NSP access rules restrict inbound "
            "and outbound traffic to approved networks and subscriptions only."
        ),
        remediation=(
            "Azure portal → Network Security Perimeter → Create perimeter → Associate PaaS "
            "resources → Configure inbound and outbound access rules to restrict to known "
            "networks and subscriptions."
        ),
        default_value="PaaS resources are not associated with any Network Security Perimeter by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/private-link/network-security-perimeter-concepts",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="12.2", title="Establish and Maintain a Secure Network Architecture", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verifying that Azure PaaS resources are associated with a Network Security Perimeter "
            "requires manual review. Check the Azure portal under Network Security Perimeters to "
            "confirm that critical PaaS resources have appropriate NSP profiles configured with "
            "restrictive inbound and outbound access rules."
        )
