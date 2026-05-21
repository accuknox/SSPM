"""
CIS MS365 5.1.6.1 (L2) – Ensure that collaboration invitations are sent to
allowed domains only (Automated)

Profile Applicability: E3 Level 2, E5 Level 2
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
            "  GET /policies/crossTenantAccessPolicy/default\n"
            "  Check inboundTrust and b2bCollaborationInbound settings.\n\n"
            "Also check:\n"
            "  GET /policies/authorizationPolicy\n"
            "  Check allowInvitesFrom"
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
        cross_tenant_policy = data.get("cross_tenant_access_policy")
        if cross_tenant_policy is None:
            return self._skip(
                "Could not retrieve cross-tenant access policy. "
                "Requires Policy.Read.All permission."
            )

        # Check if there's any restriction on inbound B2B collaboration
        b2b_collab = cross_tenant_policy.get("b2bCollaborationInbound") or {}
        users_and_groups = b2b_collab.get("usersAndGroups") or {}
        access_type = users_and_groups.get("accessType")

        evidence = [
            Evidence(
                source="graph/policies/crossTenantAccessPolicy/default",
                data={"b2bCollaborationInbound": b2b_collab},
                description="Cross-tenant access policy B2B collaboration settings.",
            )
        ]

        if access_type == "blocked":
            return self._pass(
                "B2B collaboration from external tenants is blocked by the cross-tenant policy.",
                evidence=evidence,
            )

        # Check authorization policy for allowInvitesFrom
        auth_policy = data.get("authorization_policy")
        if auth_policy and isinstance(auth_policy, dict):
            allow_invites = auth_policy.get("allowInvitesFrom")
            if allow_invites in ("adminsAndGuestInviters", "admins", "none"):
                return self._pass(
                    f"External invitations are restricted (allowInvitesFrom = {allow_invites}).",
                    evidence=[
                        Evidence(
                            source="graph/policies/authorizationPolicy",
                            data={"allowInvitesFrom": allow_invites},
                            description="Authorization policy invitation restriction.",
                        )
                    ],
                )

        return self._manual()
