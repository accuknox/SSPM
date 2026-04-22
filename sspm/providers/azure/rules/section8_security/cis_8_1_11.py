"""CIS Azure 8.1.11 – Ensure that non-deprecated Microsoft Cloud Security Benchmark policies are not set to 'Disabled' (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_11(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.11",
        title="Ensure that non-deprecated Microsoft Cloud Security Benchmark policies are not set to 'Disabled'",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "The Microsoft Cloud Security Benchmark (MCSB) initiative is automatically assigned "
            "to every subscription. Each policy effect within it should not be set to 'Disabled', "
            "ensuring that all applicable security recommendations are evaluated."
        ),
        rationale=(
            "Disabling MCSB policy definitions reduces the scope of Defender for Cloud "
            "recommendations, creating blind spots in the security posture assessment. "
            "Organizations should only disable deprecated or explicitly inapplicable policies."
        ),
        impact="None — this is a configuration review control.",
        audit_procedure=(
            "Azure Policy → Assignments → locate Microsoft Cloud Security Benchmark initiative → "
            "review Policy parameters: verify no non-deprecated policy effect is set to 'Disabled'."
        ),
        remediation=(
            "Azure Policy → Assignments → Microsoft Cloud Security Benchmark → Edit assignment → "
            "Parameters: change any Disabled effect to AuditIfNotExists or Audit as appropriate."
        ),
        default_value="All MCSB policies are enabled (non-Disabled) by default.",
        references=[
            "https://learn.microsoft.com/en-us/security/benchmark/azure/introduction",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="4.1", title="Establish and Maintain a Secure Configuration Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._skip(
            "This control requires manual verification in the Azure portal: "
            "Azure Policy → Assignments → Microsoft Cloud Security Benchmark → "
            "confirm no non-deprecated policy effect is set to 'Disabled'."
        )
