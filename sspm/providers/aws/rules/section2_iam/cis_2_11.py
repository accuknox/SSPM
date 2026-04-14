"""CIS AWS 2.11 – Ensure credentials unused for 45 days or more are disabled (Automated, L1)"""
from __future__ import annotations

from datetime import datetime, timezone

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData

_THRESHOLD_DAYS = 45


def _days_since(date_str: str) -> int | None:
    """Return number of days since the given ISO date string, or None if not parseable."""
    if not date_str or date_str in ("N/A", "no_information", ""):
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


@registry.rule
class CIS_2_11(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.11",
        title="Ensure credentials unused for 45 days or more are disabled",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "AWS IAM users can access AWS resources using different types of credentials "
            "(passwords or access keys). It is recommended that all credentials that have been "
            "unused for 45 or more days be disabled or removed."
        ),
        rationale=(
            "Disabling or removing unnecessary credentials reduces the attack surface. "
            "Unused credentials may belong to inactive accounts that are not monitored and "
            "represent a risk if compromised."
        ),
        impact="Users with unused credentials will lose access until credentials are re-activated.",
        audit_procedure=(
            "aws iam generate-credential-report && aws iam get-credential-report\n"
            "For each user, check password_last_used and access_key_N_last_used_date.\n"
            "Flag any credential not used within 45 days."
        ),
        remediation=(
            "For passwords: IAM → Users → <username> → Security credentials → Disable console access.\n"
            "For access keys: IAM → Users → <username> → Security credentials → "
            "Deactivate or delete unused access keys."
        ),
        default_value="Credentials are active until manually disabled.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html"
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

            # Check password
            password_enabled = str(row.get("password_enabled", "false")).lower() == "true"
            if password_enabled:
                days = _days_since(row.get("password_last_used", ""))
                if days is not None and days >= _THRESHOLD_DAYS:
                    violations.append(f"{user} (password unused {days} days)")

            # Check access keys
            for key_num in ("1", "2"):
                active = str(row.get(f"access_key_{key_num}_active", "false")).lower() == "true"
                if not active:
                    continue
                last_used = row.get(f"access_key_{key_num}_last_used_date", "")
                days = _days_since(last_used)
                if days is None:
                    # Key exists but never used — check rotation date as a proxy
                    rotated = row.get(f"access_key_{key_num}_last_rotated", "")
                    days = _days_since(rotated)
                if days is not None and days >= _THRESHOLD_DAYS:
                    violations.append(f"{user} (access_key_{key_num} unused {days} days)")

        evidence = [Evidence(
            source="iam:GetCredentialReport",
            data={"unused_credentials": violations},
            description=f"Credentials unused for {_THRESHOLD_DAYS}+ days.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} credential(s) have not been used in {_THRESHOLD_DAYS}+ days: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"All active credentials have been used within the last {_THRESHOLD_DAYS} days. Compliant.",
            evidence=evidence,
        )
