"""
CIS MS365 5.1.6.1 (L2) – Ensure that collaboration invitations are sent to
allowed domains only (Automated)

Profile Applicability: E3 Level 2, E5 Level 2

Per the official CIS audit procedure, this control is about the legacy B2B
invitation allow/block domain list (GET /beta/legacy/policies, type
'B2BManagementPolicy', definition -> B2BManagementPolicy.
InvitationsAllowedAndBlockedDomainsPolicy) — NOT the cross-tenant access
policy or authorizationPolicy.allowInvitesFrom, which govern different
settings (who can invite guests at all, and cross-tenant trust) and don't
verify domain allow/block lists.
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
class CIS_5_1_6_1(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.6.1",
        title="Ensure that collaboration invitations are sent to allowed domains only",
        section="5.1.6 Guest Access",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.MEDIUM,
        description=(
            "External collaboration invitations should be restricted to approved "
            "domains. This prevents users from inviting external users from "
            "unapproved or potentially risky domains."
        ),
        rationale=(
            "Restricting collaboration to approved domains reduces the risk of "
            "data being shared with unauthorized external parties and ensures "
            "that collaboration only happens with trusted partners."
        ),
        impact=(
            "Users will not be able to invite external users from non-approved "
            "domains. Only users from approved partner domains can be invited."
        ),
        audit_procedure=(
            "Using Microsoft Graph:\n"
            "  GET /beta/legacy/policies\n"
            "  Filter for type == 'B2BManagementPolicy'; parse the JSON-encoded "
            "'definition' field for "
            "B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy.\n"
            "  Compliant: an AllowedDomains property is present (empty, or "
            "listing only approved domains) AND no BlockedDomains property is "
            "present.\n"
            "  Non-compliant: a BlockedDomains property is present.\n\n"
            "Microsoft Entra admin center → Identity > External Identities > "
            "External collaboration settings → 'Allow invitations only to the "
            "specified domains' with approved Target domains."
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > External identities > "
            "External collaboration settings.\n"
            "In 'Collaboration restrictions', select 'Allow invitations only to the "
            "specified domains' and add approved domains."
        ),
        default_value="Invitations can be sent to all external domains by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/external-id/allow-deny-list",
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
        tags=["identity", "guests", "external-collaboration", "b2b"],
    )

    async def check(self, data: CollectedData):
        if "b2b_invitation_domains_policy" in (data.errors or {}):
            return self._skip(
                "Could not retrieve the B2B invitation domains policy: "
                f"{data.errors.get('b2b_invitation_domains_policy')}"
            )

        domains_policy = data.get("b2b_invitation_domains_policy")
        if domains_policy is None:
            # CIS's audit script prints "No policy found." without declaring a
            # verdict, but the control's stated Default Value is "Allow
            # invitations to be sent to any domain (most inclusive)" — the
            # absence of a B2BManagementPolicy *is* that unrestricted default.
            return self._fail(
                "No B2B invitation domain policy is configured, so the tenant "
                "is at its default of allowing collaboration invitations to be "
                "sent to any domain.",
                evidence=[
                    Evidence(
                        source="graph/beta/legacy/policies (B2BManagementPolicy)",
                        data={"B2BManagementPolicy": None},
                        description=(
                            "No B2BManagementPolicy object exists for this tenant."
                        ),
                    )
                ],
            )

        evidence = [
            Evidence(
                source="graph/beta/legacy/policies (B2BManagementPolicy)",
                data=domains_policy,
                description="B2B invitation allowed/blocked domains policy.",
            )
        ]

        if "BlockedDomains" in domains_policy:
            return self._fail(
                "A BlockedDomains list is configured, which CIS considers "
                "non-compliant regardless of contents.",
                evidence=evidence,
            )
        if "AllowedDomains" in domains_policy:
            return self._pass(
                "Collaboration invitations are restricted via an "
                "AllowedDomains policy.",
                evidence=evidence,
            )
        return self._fail(
            "The B2B invitation domains policy defines neither AllowedDomains "
            "nor BlockedDomains, so invitations are not restricted to approved "
            "domains.",
            evidence=evidence,
        )
