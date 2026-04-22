"""CIS Azure 8.1.16 – Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is Enabled (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_8_1_16(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-8.1.16",
        title="Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is Enabled",
        section="8 Security Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.MEDIUM,
        description=(
            "Microsoft Defender External Attack Surface Management (EASM) continuously discovers "
            "and maps an organization's internet-exposed assets, providing visibility into "
            "shadow IT, misconfigured services, and exploitable vulnerabilities visible from "
            "the outside."
        ),
        rationale=(
            "Attackers enumerate external attack surfaces before launching targeted attacks. "
            "EASM gives defenders the same view so they can remediate externally exploitable "
            "weaknesses before they are discovered by adversaries."
        ),
        impact="EASM is a standalone paid service.",
        audit_procedure=(
            "Azure portal → Microsoft Defender EASM → verify that an EASM workspace has been "
            "created and linked to the organization's known domains/IPs."
        ),
        remediation=(
            "Azure portal → Create a resource → search 'Microsoft Defender EASM' → create a "
            "workspace → add known seeds (domains, IP ranges, ASNs) → start discovery."
        ),
        default_value="EASM is not deployed by default.",
        references=[
            "https://learn.microsoft.com/en-us/azure/external-attack-surface-management/",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="7.1", title="Establish and Maintain a Vulnerability Management Process", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._skip(
            "This control requires manual verification in the Azure portal: "
            "confirm that a Microsoft Defender EASM workspace has been created and "
            "configured with organizational seeds."
        )
