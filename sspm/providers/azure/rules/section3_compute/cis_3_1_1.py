"""CIS Azure 3.1.1 – Ensure only MFA Enabled Identities can Access Privileged Virtual Machine (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.azure.rules.base import AzureRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_3_1_1(AzureRule):
    metadata = RuleMetadata(
        id="azure-cis-3.1.1",
        title="Ensure only MFA Enabled Identities can Access Privileged Virtual Machine",
        section="3.1 Virtual Machines",
        benchmark="CIS Microsoft Azure Foundations Benchmark v6.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AZURE_L1],
        severity=Severity.HIGH,
        description=(
            "Only identities with multi-factor authentication (MFA) enabled should be granted "
            "privileged access (e.g., Virtual Machine Contributor, Owner, or custom admin roles) "
            "to Azure Virtual Machines. This prevents single-factor credential compromise from "
            "resulting in unauthorized administrative control of VM resources."
        ),
        rationale=(
            "Virtual Machines often host critical workloads and sensitive data. If an identity "
            "with privileged VM access does not have MFA enforced, a compromised password alone "
            "is sufficient to gain full control of the VM — including the ability to install "
            "malware, exfiltrate data, or pivot to other resources. MFA provides a critical "
            "second factor that significantly raises the bar for attackers."
        ),
        impact=(
            "Enforcing MFA for all privileged VM identities may require migration from legacy "
            "authentication methods. Service principals used for automation should use managed "
            "identities or certificate-based authentication rather than passwords."
        ),
        audit_procedure=(
            "1. ARM: GET /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/"
            "roleAssignments?$filter=atScope() — identify all identities with privileged roles "
            "(Owner, Contributor, Virtual Machine Contributor) on VMs or the subscription.\n"
            "2. Microsoft Graph: For each user identity, GET /users/{id}/authentication/methods "
            "— verify that at least one strong authentication method (e.g., Microsoft "
            "Authenticator, FIDO2, phone) is registered.\n"
            "3. Entra ID: Review Conditional Access policies to confirm that MFA is required "
            "for access to Azure Management (app ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013) "
            "for all users with VM privileges."
        ),
        remediation=(
            "1. In Microsoft Entra ID, create or update a Conditional Access policy: "
            "Assignments → Users: All users (or a group of privileged VM admins) → "
            "Cloud apps: Microsoft Azure Management → Grant: Require multi-factor authentication "
            "→ Enable policy.\n"
            "2. Ensure all users with VM privileged roles have MFA registration completed: "
            "Entra ID → Users → per-user MFA or registration campaign.\n"
            "3. For service principals performing VM operations, use managed identities or "
            "certificates instead of password-based authentication."
        ),
        default_value="MFA is not enforced for VM access by default unless Conditional Access policies are configured.",
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-azure-management",
            "https://learn.microsoft.com/en-us/azure/virtual-machines/overview",
            "https://www.cisecurity.org/benchmark/azure",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="6.5",
                title="Require MFA for Administrative Access",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual()
