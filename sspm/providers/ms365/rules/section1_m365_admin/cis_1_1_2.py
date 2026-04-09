"""
CIS MS365 1.1.2 (L1) – Ensure two emergency access accounts have been defined (Manual)

Profile Applicability: E3 Level 1, E5 Level 1

This control cannot be fully automated because it requires human inspection
of account naming, licensing status, conditional access exclusions, and
organisational policy documentation.
"""

from __future__ import annotations

from sspm.core.models import (
    AssessmentStatus,
    CISControl,
    CISProfile,
    RuleMetadata,
    Severity,
)
from sspm.core.registry import registry
from sspm.providers.base import CollectedData
from sspm.providers.ms365.rules.base import MS365Rule


@registry.rule
class CIS_1_1_2(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.1.2",
        title="Ensure two emergency access accounts have been defined",
        section="1.1 Users",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.HIGH,
        description=(
            "Emergency access ('break glass') accounts are limited for emergency "
            "scenarios where normal administrative accounts are unavailable. They must "
            "not be assigned to a specific user, must use .onmicrosoft.com domain, "
            "be cloud-only, unlicensed, and assigned the Global Administrator role. "
            "At least one must be excluded from all Conditional Access policies."
        ),
        rationale=(
            "In the event of losing access to administrative functions, an organisation "
            "may experience significant loss in its ability to provide support, lose "
            "insight into its security posture, and potentially suffer financial losses."
        ),
        impact=(
            "Failure to implement emergency access accounts can weaken security posture. "
            "Microsoft recommends FIDO2 security keys or certificate-based authentication "
            "for MFA compliance (required from 10/15/2024)."
        ),
        audit_procedure=(
            "Step 1 – Verify organisational policy:\n"
            "  • Confirm a documented policy authorises emergency access accounts.\n"
            "  • FIDO2 keys should be locked in a secure fireproof location.\n"
            "  • Passwords ≥ 16 characters, randomly generated.\n\n"
            "Step 2 – Verify two accounts exist (Microsoft 365 admin center):\n"
            "  • Navigate to https://admin.microsoft.com → Users > Active Users.\n"
            "  • Confirm two designated emergency access accounts with:\n"
            "    - Names that do NOT identify a specific person.\n"
            "    - Default .onmicrosoft.com domain.\n"
            "    - Cloud-only (no on-premises sync).\n"
            "    - Unlicensed.\n"
            "    - Global Administrator role assigned.\n\n"
            "Step 3 – Conditional Access exclusion:\n"
            "  • In Entra admin center → Protection > Conditional Access.\n"
            "  • Confirm at least one emergency account is excluded from ALL CA rules."
        ),
        remediation=(
            "1. Create two cloud-only, unlicensed accounts using the .onmicrosoft.com "
            "domain with names that do not identify a specific person.\n"
            "2. Assign the Global Administrator role to each.\n"
            "3. Configure FIDO2 passkey or certificate-based MFA.\n"
            "4. Exclude at least one account from all Conditional Access policies.\n"
            "5. Store credentials securely (fireproof vault, split across trustees).\n"
            "6. Document and test break-glass procedures quarterly."
        ),
        references=[
            "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access",
            "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.4",
                title="Restrict Administrator Privileges to Dedicated Administrator Accounts",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "admin", "break-glass", "emergency-access"],
    )

    async def check(self, data: CollectedData):
        # This is a MANUAL control; return a MANUAL finding with audit guidance.
        # Optionally provide partial automation hints if data is available.
        users = data.get("users") or []

        # Partial automation: count how many users use the default .onmicrosoft.com
        # domain and are unlicensed (heuristic hint, not definitive)
        candidate_hints = [
            u.get("userPrincipalName", "")
            for u in users
            if (
                ".onmicrosoft.com" in u.get("userPrincipalName", "").lower()
                and not u.get("assignedLicenses")
            )
        ]

        msg = (
            "Manual verification required. "
            "Check that two emergency access accounts are defined, cloud-only, "
            "unlicensed, use .onmicrosoft.com domain, have Global Administrator role, "
            "and at least one is excluded from all Conditional Access policies."
        )
        if candidate_hints:
            msg += (
                f"\n\nHint: {len(candidate_hints)} unlicensed .onmicrosoft.com "
                f"account(s) found that may be emergency accounts: "
                + ", ".join(candidate_hints[:5])
            )
        else:
            msg += (
                "\n\nHint: No unlicensed .onmicrosoft.com accounts found. "
                "Emergency access accounts may not be configured."
            )

        return self._manual(message=msg)
