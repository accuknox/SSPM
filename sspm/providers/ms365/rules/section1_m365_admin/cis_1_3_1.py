"""
CIS MS365 1.3.1 (L1) – Ensure the 'Password expiration policy' is set to
'Set passwords to never expire (recommended)' (Automated)

Profile Applicability: E3 Level 1, E5 Level 1

Modern guidance (NIST SP 800-63B) recommends against periodic forced password
rotation for cloud-managed accounts.  Frequent forced resets lead to
predictable password patterns and reduce security.  MFA is the recommended
compensating control.
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
class CIS_1_3_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-1.3.1",
        title="Ensure the 'Password expiration policy' is set to 'Set passwords to never expire'",
        section="1.3 Settings",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L1, CISProfile.E5_L1],
        severity=Severity.MEDIUM,
        description=(
            "Microsoft recommends setting passwords to never expire for cloud-managed "
            "accounts. NIST SP 800-63B guidance states that forcing periodic password "
            "changes actually reduces security by incentivising predictable patterns. "
            "MFA provides a stronger compensating control."
        ),
        rationale=(
            "Forcing users to change passwords regularly often results in weak, "
            "predictable password patterns (e.g. appending a number to the previous "
            "password). Setting passwords to never expire, combined with MFA and "
            "breach detection, is the current best practice."
        ),
        impact=(
            "Users will no longer receive password expiration reminders. "
            "Ensure MFA is enforced as a compensating control."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /organization\n"
            "  Check: passwordPolicies property should NOT include "
            "'DisablePasswordExpiration' at the user level, OR\n"
            "  GET /domains and check passwordNotificationWindowInDays / "
            "passwordValidityPeriodInDays.\n\n"
            "Alternatively:\n"
            "  Microsoft 365 admin center → Settings > Org Settings > Security & "
            "privacy > Password expiration policy.\n"
            "  Confirm 'Set passwords to never expire (recommended)' is checked."
        ),
        remediation=(
            "Navigate to Microsoft 365 admin center → Settings > Org Settings > "
            "Security & privacy > Password expiration policy.\n"
            "Select 'Set passwords to never expire (recommended)' and save."
        ),
        default_value="Passwords expire after 90 days (legacy default).",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations",
            "https://pages.nist.gov/800-63-3/sp800-63b.html",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="5.2",
                title="Use Unique Passwords",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "password-policy", "settings"],
    )

    async def check(self, data: CollectedData):
        domains = data.get("domains")
        if domains is None:
            return self._skip("Could not retrieve domain data.")

        # For each verified domain, check passwordValidityPeriodInDays
        # A value of 2147483647 (max int32) means "never expire"
        expiring_domains = [
            d
            for d in domains
            if d.get("isVerified")
            and d.get("passwordValidityPeriodInDays") not in (None, 2147483647)
        ]

        if not expiring_domains:
            return self._pass(
                "Password expiration policy is set to 'never expire' for all domains.",
                evidence=[
                    Evidence(
                        source="graph/domains",
                        data=[
                            {
                                "id": d.get("id"),
                                "passwordValidityPeriodInDays": d.get(
                                    "passwordValidityPeriodInDays"
                                ),
                            }
                            for d in domains
                            if d.get("isVerified")
                        ],
                        description="All verified domains have no password expiration.",
                    )
                ],
            )

        domain_details = [
            f"{d.get('id')} (expires in {d.get('passwordValidityPeriodInDays')} days)"
            for d in expiring_domains
        ]
        return self._fail(
            f"Password expiration is enabled for {len(expiring_domains)} domain(s): "
            + "; ".join(domain_details),
            evidence=[
                Evidence(
                    source="graph/domains",
                    data=expiring_domains,
                    description="Domains with password expiration enabled.",
                )
            ],
        )
