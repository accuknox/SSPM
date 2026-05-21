"""CIS Azure 7.9 – Ensure 'Authentication type' is Set to 'Azure Active Directory' only for Azure VPN Gateway Point-to-Site Configuration (Automated, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_7_9(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-7.9",
        title="Ensure 'Authentication type' is Set to 'Azure Active Directory' only for Azure VPN Gateway Point-to-Site Configuration",
        section="7 Networking Services",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Azure VPN Gateway point-to-site (P2S) configurations should use Azure Active "
            "Directory (AAD/Entra ID) as the sole authentication type. Certificate-based or "
            "RADIUS authentication alone does not leverage conditional access or MFA policies."
        ),
        rationale=(
            "AAD authentication for VPN gateways enables conditional access, MFA enforcement, "
            "and integration with identity governance. Non-AAD methods rely on certificates or "
            "passwords that can be compromised without triggering identity-based controls."
        ),
        impact="Clients must use the Azure VPN client that supports AAD authentication.",
        audit_procedure=(
            "ARM: GET each VPN gateway (gatewayType=Vpn) — "
            "properties.vpnClientConfiguration.vpnAuthenticationTypes must contain only 'AAD'."
        ),
        remediation=(
            "Azure portal → Virtual network gateways → select gateway → Point-to-site "
            "configuration → Authentication type → Azure Active Directory → Save."
        ),
        default_value="VPN gateways default to certificate-based authentication.",
        references=[
            "https://learn.microsoft.com/en-us/azure/vpn-gateway/openvpn-azure-ad-tenant",
        ],
        cis_controls=[
            CISControl(version="v8", control_id="6.3", title="Require MFA for Externally-Exposed Applications", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        vpn_gateways = data.get("vpn_gateways")
        if vpn_gateways is None:
            return self._skip("VPN gateways could not be retrieved.")
        if not vpn_gateways:
            return self._skip("No VPN gateways found in subscription.")

        # Only evaluate gateways of type "Vpn"
        vpn_type_gateways = [
            gw for gw in vpn_gateways
            if (gw.get("properties", {}).get("gatewayType") or "").lower() == "vpn"
        ]
        if not vpn_type_gateways:
            return self._skip("No VPN-type gateways found in subscription.")

        offenders: list[str] = []
        for gw in vpn_type_gateways:
            name = gw.get("name", "?")
            vpn_client_config = gw.get("properties", {}).get("vpnClientConfiguration") or {}
            auth_types = vpn_client_config.get("vpnAuthenticationTypes") or []
            # Compliant only if auth types list contains exactly ["AAD"] (case-insensitive)
            auth_types_lower = [t.lower() for t in auth_types]
            if auth_types_lower != ["aad"]:
                offenders.append(f"{name} (auth: {auth_types or 'not configured'})")

        evidence = [Evidence(source="arm:virtualNetworkGateways", data={"offenders": offenders})]
        if offenders:
            return self._fail(
                f"{len(offenders)} VPN gateway(s) do not use AAD-only authentication: "
                f"{', '.join(offenders[:10])}.",
                evidence=evidence,
            )
        return self._pass(
            f"All {len(vpn_type_gateways)} VPN gateway(s) use AAD-only authentication.",
            evidence=evidence,
        )
