"""
CIS MS365 5.1.2.5 (L2) – Ensure the option to remain signed in is hidden
(Automated)

Profile Applicability: E3 Level 2, E5 Level 2
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
class CIS_5_1_2_5(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-5.1.2.5",
        title="Ensure the option to remain signed in is hidden",
        section="5.1.2 Account Management",
        benchmark="CIS Microsoft 365 Foundations Benchmark v6.0.1",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.E3_L2, CISProfile.E5_L2],
        severity=Severity.LOW,
        description=(
            "The 'Stay signed in?' prompt allows users to maintain persistent "
            "browser sessions. This should be hidden to prevent long-lived sessions "
            "on shared or unmanaged devices."
        ),
        rationale=(
            "Persistent browser sessions on shared devices allow subsequent users "
            "to access corporate resources without re-authenticating. Hiding the "
            "'Stay signed in?' option reduces the risk of session hijacking."
        ),
        impact=(
            "Users will not be prompted to stay signed in and will have shorter "
            "session lifetimes, requiring more frequent re-authentication."
        ),
        audit_procedure=(
            "Microsoft Entra admin center → Identity > Overview > Company branding.\n"
            "Check the 'Sign-in page' settings:\n"
            "  Show option to remain signed in: should be No/hidden.\n\n"
            "Via Microsoft Graph:\n"
            "  GET /organization/{id}/branding\n"
            "  Check hideKeepMeSignedIn property."
        ),
        remediation=(
            "Microsoft Entra admin center → Identity > Overview > Company branding.\n"
            "Edit the default branding:\n"
            "  Set 'Show option to remain signed in' to No."
        ),
        default_value="The 'Stay signed in?' prompt is shown by default.",
        references=[
            "https://learn.microsoft.com/en-us/entra/fundamentals/how-to-customize-branding",
        ],
        cis_controls=[
            CISControl(
                version="v8",
                control_id="4.3",
                title="Configure Automatic Session Locking on Enterprise Assets",
                ig1=True,
                ig2=True,
                ig3=True,
            ),
        ],
        tags=["identity", "session", "branding", "sign-in"],
    )

    async def check(self, data: CollectedData):
        branding = data.get("branding")
        if branding:
            hide_kmsi = branding.get("hideKeepMeSignedIn")
            if hide_kmsi is True:
                from sspm.core.models import Evidence
                return self._pass(
                    "The 'Stay signed in?' option is hidden (hideKeepMeSignedIn = true).",
                    evidence=[
                        Evidence(
                            source="graph/organization/branding",
                            data={"hideKeepMeSignedIn": hide_kmsi},
                            description="Company branding sign-in setting.",
                        )
                    ],
                )
            elif hide_kmsi is False:
                from sspm.core.models import Evidence
                return self._fail(
                    "The 'Stay signed in?' option is shown (hideKeepMeSignedIn = false).",
                    evidence=[
                        Evidence(
                            source="graph/organization/branding",
                            data={"hideKeepMeSignedIn": hide_kmsi},
                            description="Company branding sign-in setting.",
                        )
                    ],
                )

        return self._manual(
            "Verify the 'Stay signed in?' setting via Microsoft Entra admin center:\n"
            "  1. Go to https://entra.microsoft.com\n"
            "  2. Navigate to Identity > Overview > Company branding\n"
            "  3. Edit the default branding\n"
            "  4. Verify 'Show option to remain signed in' is set to No"
        )
