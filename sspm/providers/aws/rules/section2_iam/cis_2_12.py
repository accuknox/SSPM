"""CIS AWS 2.12 – Ensure access keys are rotated every 90 days or less (Automated, L1)"""
from __future__ import annotations

from datetime import datetime, timezone

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData

_THRESHOLD_DAYS = 90


def _days_since(date_str: str) -> int | None:
    if not date_str or date_str in ("N/A", "no_information", ""):
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


@registry.rule
class CIS_2_12(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.12",
        title="Ensure access keys are rotated every 90 days or less",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "Access keys consist of an access key ID and secret access key, which are used to "
            "sign programmatic requests to AWS. It is recommended that all access keys be "
            "regularly rotated to reduce the risk of compromised credentials."
        ),
        rationale=(
            "Rotating access keys limits the window of exposure if a key is compromised. "
            "Keys that have not been rotated in over 90 days may be stale or forgotten, "
            "and are more likely to be associated with inactive accounts."
        ),
        impact=(
            "Applications using access keys must be updated to use the new keys after rotation."
        ),
        audit_procedure=(
            "aws iam generate-credential-report && aws iam get-credential-report\n"
            "For each active access key, check access_key_N_last_rotated.\n"
            "Flag any key not rotated within 90 days."
        ),
        remediation=(
            "1. Create a new access key for the user.\n"
            "2. Update all applications to use the new key.\n"
            "3. Deactivate and then delete the old key.\n"
            "IAM → Users → <username> → Security credentials → Access keys."
        ),
        default_value="Access keys do not expire or rotate automatically.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.1", title="Establish and Maintain an Inventory of Accounts", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="16.1", title="Maintain an Inventory of Authentication Systems", ig1=False, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        report = data.get("credential_report")
        if report is None:
            return self._skip("Could not retrieve IAM credential report.")

        violations = []
        for row in report:
            user = row.get("user", "")
            if user == "<root_account>":
                continue
            for key_num in ("1", "2"):
                active = str(row.get(f"access_key_{key_num}_active", "false")).lower() == "true"
                if not active:
                    continue
                rotated = row.get(f"access_key_{key_num}_last_rotated", "")
                days = _days_since(rotated)
                if days is not None and days > _THRESHOLD_DAYS:
                    violations.append(f"{user} (access_key_{key_num} rotated {days} days ago)")

        evidence = [Evidence(
            source="iam:GetCredentialReport",
            data={"stale_access_keys": violations},
            description=f"Active access keys not rotated within {_THRESHOLD_DAYS} days.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} access key(s) have not been rotated within {_THRESHOLD_DAYS} days: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All active access keys have been rotated within the last {_THRESHOLD_DAYS} days. Compliant.",
            evidence=evidence,
        )
