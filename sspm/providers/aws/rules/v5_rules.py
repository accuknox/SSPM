"""
CIS AWS Foundations Benchmark v5.0.0 – rule registry.

Each v5 rule is a thin subclass of the corresponding legacy rule.  The check
logic is inherited unchanged; only the rule ID, section label, and benchmark
reference are updated to match the v5.0.0 section numbering.

New rules introduced in v5.0.0 that have no legacy equivalent are implemented
directly at the bottom of this module.

v5.0.0 section layout
---------------------
1  Identity and Access Management  (1.1–1.21)
2  Storage                          (2.1.x S3, 2.2.x RDS, 2.3.x EFS)
3  Logging                          (3.1–3.9)
4  Monitoring                       (4.1–4.16)
5  Networking                       (5.1.x EC2/EBS, 5.2–5.7)
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
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData

_V5_BENCHMARK = "CIS Amazon Web Services Foundations Benchmark v5.0.0"
_V5_VERSION = "v5.0.0"


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def _v5(base_cls: type, rule_id: str, section: str, title: str | None = None) -> type:
    """Create and register a v5 rule that inherits *check()* from *base_cls*."""
    bm = base_cls.metadata
    meta = RuleMetadata(
        id=rule_id,
        title=title or bm.title,
        section=section,
        benchmark=_V5_BENCHMARK,
        benchmark_version=_V5_VERSION,
        assessment_status=bm.assessment_status,
        profiles=list(bm.profiles),
        severity=bm.severity,
        description=bm.description,
        rationale=bm.rationale,
        impact=bm.impact,
        audit_procedure=bm.audit_procedure,
        remediation=bm.remediation,
        default_value=bm.default_value,
        references=list(bm.references),
        cis_controls=list(bm.cis_controls),
    )
    cls = type(
        rule_id.replace("-", "_").replace(".", "_"),
        (base_cls,),
        {"metadata": meta},
    )
    registry.register(cls())
    return cls


def _v5_from_registry(old_id: str, rule_id: str, section: str) -> type | None:
    """Create a v5 rule by looking up *old_id* in the registry."""
    base_rule = registry.get(old_id)
    if base_rule is None:
        return None
    return _v5(type(base_rule), rule_id, section)


# ---------------------------------------------------------------------------
# Section 1 – Identity and Access Management
# ---------------------------------------------------------------------------
_IAM = "1 Identity and Access Management"

from sspm.providers.aws.rules.section2_iam.cis_2_2 import CIS_2_2        # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_3 import CIS_2_3        # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_4 import CIS_2_4        # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_5 import CIS_2_5        # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_6 import CIS_2_6        # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_7 import CIS_2_7        # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_8 import CIS_2_8        # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_9 import CIS_2_9        # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_10 import CIS_2_10      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_11 import CIS_2_11      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_12 import CIS_2_12      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_13 import CIS_2_13      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_14 import CIS_2_14      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_15 import CIS_2_15      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_16 import CIS_2_16      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_17 import CIS_2_17      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_18 import CIS_2_18      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_19 import CIS_2_19      # noqa: E402
from sspm.providers.aws.rules.section2_iam.cis_2_20 import CIS_2_20      # noqa: E402

_v5(CIS_2_2,  "aws-cis-v5-1.1",  _IAM)
_v5(CIS_2_3,  "aws-cis-v5-1.2",  _IAM)
_v5(CIS_2_4,  "aws-cis-v5-1.3",  _IAM)
_v5(CIS_2_5,  "aws-cis-v5-1.4",  _IAM)
_v5(CIS_2_6,  "aws-cis-v5-1.5",  _IAM)
_v5(CIS_2_7,  "aws-cis-v5-1.6",  _IAM)
_v5(CIS_2_8,  "aws-cis-v5-1.7",  _IAM)
_v5(CIS_2_9,  "aws-cis-v5-1.8",  _IAM)
_v5(CIS_2_10, "aws-cis-v5-1.9",  _IAM)
# 1.10 is new in v5.0.0 – implemented below
_v5(CIS_2_11, "aws-cis-v5-1.11", _IAM)
# 1.12 is new in v5.0.0 – implemented below
_v5(CIS_2_12, "aws-cis-v5-1.13", _IAM)
_v5(CIS_2_13, "aws-cis-v5-1.14", _IAM)
_v5(CIS_2_14, "aws-cis-v5-1.15", _IAM)
_v5(CIS_2_15, "aws-cis-v5-1.16", _IAM)
_v5(CIS_2_16, "aws-cis-v5-1.17", _IAM)
_v5(CIS_2_17, "aws-cis-v5-1.18", _IAM)
_v5(CIS_2_18, "aws-cis-v5-1.19", _IAM)
_v5(CIS_2_19, "aws-cis-v5-1.20", _IAM)
_v5(CIS_2_20, "aws-cis-v5-1.21", _IAM)


# 1.10 – Do not create access keys during initial setup (Manual, L1)
@registry.rule
class CIS_V5_1_10(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-v5-1.10",
        title="Do not create access keys during initial setup for IAM users with a console password",
        section=_IAM,
        benchmark=_V5_BENCHMARK,
        benchmark_version=_V5_VERSION,
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "AWS console defaults to no access keys being created during IAM user creation. "
            "This setting should be kept in place to reduce the risk of unnecessary access key "
            "exposure during user account setup."
        ),
        rationale=(
            "Access keys created at the same time as a user account are more likely to be "
            "shared in an insecure manner or to be forgotten without ever being used. "
            "Creating keys only when specifically needed reduces credential sprawl."
        ),
        impact="Administrators must create access keys for users as a separate step after account creation.",
        audit_procedure=(
            "aws iam generate-credential-report && aws iam get-credential-report\n"
            "For each user, compare access_key_N_last_rotated with the user creation date.\n"
            "Flag users whose access keys were created within one day of account creation "
            "and also have a console password (password_enabled = true)."
        ),
        remediation=(
            "For each identified user:\n"
            "1. Determine whether the access key is actively in use.\n"
            "2. If not in use, deactivate and delete the key:\n"
            "   aws iam delete-access-key --user-name <username> --access-key-id <key-id>\n"
            "3. Update the organisation's IAM provisioning process to create access keys "
            "   as a separate, explicit step."
        ),
        default_value="No access keys are created for new IAM users by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="5.1", title="Establish and Maintain an Inventory of Accounts", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="16.11", title="Lock Workstation Sessions After Inactivity", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Manually verify that access keys are not created during initial IAM user setup. "
            "Use the IAM credential report to compare key creation dates against user creation "
            "dates and flag same-day key creation for users with console passwords."
        )


# 1.12 – Ensure there is only one active access key per IAM user (Automated, L1)
@registry.rule
class CIS_V5_1_12(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-v5-1.12",
        title="Ensure there is only one active access key for any single IAM user",
        section=_IAM,
        benchmark=_V5_BENCHMARK,
        benchmark_version=_V5_VERSION,
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "Access keys are long-term credentials for an IAM user. Having more than one "
            "active access key per user increases the attack surface and makes credential "
            "rotation and auditing more complex."
        ),
        rationale=(
            "Multiple active access keys are harder to track and rotate. Limiting each user "
            "to one active key simplifies auditing, reduces the blast radius of a compromised "
            "key, and enforces accountability."
        ),
        impact=(
            "Users with two active access keys must deactivate one. Applications relying "
            "on multiple keys will need to be updated."
        ),
        audit_procedure=(
            "aws iam generate-credential-report && aws iam get-credential-report\n"
            "For each user, check if both access_key_1_active AND access_key_2_active are true."
        ),
        remediation=(
            "For each user with two active access keys:\n"
            "1. Identify which key is in active use.\n"
            "2. Deactivate the unused key:\n"
            "   aws iam update-access-key --user-name <username> "
            "--access-key-id <key-id> --status Inactive\n"
            "3. After confirming no breakage, delete it:\n"
            "   aws iam delete-access-key --user-name <username> --access-key-id <key-id>"
        ),
        default_value="IAM allows up to two access keys per user.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
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
            key1_active = str(row.get("access_key_1_active", "false")).lower() == "true"
            key2_active = str(row.get("access_key_2_active", "false")).lower() == "true"
            if key1_active and key2_active:
                violations.append(user)

        evidence = [Evidence(
            source="iam:GetCredentialReport",
            data={"users_with_multiple_active_keys": violations},
            description="IAM users with more than one active access key.",
        )]

        if violations:
            return self._fail(
                f"{len(violations)} IAM user(s) have more than one active access key: "
                f"{', '.join(violations[:10])}{'...' if len(violations) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            "All IAM users have at most one active access key. Compliant.",
            evidence=evidence,
        )


# ---------------------------------------------------------------------------
# Section 2 – Storage
# ---------------------------------------------------------------------------
_S3 = "2.1 Storage – Simple Storage Service (S3)"
_RDS = "2.2 Storage – Relational Database Service (RDS)"
_EFS = "2.3 Storage – Elastic File System (EFS)"

from sspm.providers.aws.rules.section3_storage.cis_3_1_1 import CIS_3_1_1  # noqa: E402
from sspm.providers.aws.rules.section3_storage.cis_3_1_2 import CIS_3_1_2  # noqa: E402
from sspm.providers.aws.rules.section3_storage.cis_3_1_3 import CIS_3_1_3  # noqa: E402
from sspm.providers.aws.rules.section3_storage.cis_3_1_4 import CIS_3_1_4  # noqa: E402
from sspm.providers.aws.rules.section3_storage.cis_3_2_1 import CIS_3_2_1  # noqa: E402
from sspm.providers.aws.rules.section3_storage.cis_3_2_2 import CIS_3_2_2  # noqa: E402
from sspm.providers.aws.rules.section3_storage.cis_3_2_3 import CIS_3_2_3  # noqa: E402
from sspm.providers.aws.rules.section3_storage.cis_3_2_4 import CIS_3_2_4  # noqa: E402
from sspm.providers.aws.rules.section3_storage.cis_3_3_1 import CIS_3_3_1  # noqa: E402

_v5(CIS_3_1_1, "aws-cis-v5-2.1.1", _S3)
_v5(CIS_3_1_2, "aws-cis-v5-2.1.2", _S3)
_v5(CIS_3_1_3, "aws-cis-v5-2.1.3", _S3)
_v5(CIS_3_1_4, "aws-cis-v5-2.1.4", _S3)
_v5(CIS_3_2_1, "aws-cis-v5-2.2.1", _RDS)
_v5(CIS_3_2_2, "aws-cis-v5-2.2.2", _RDS)
_v5(CIS_3_2_3, "aws-cis-v5-2.2.3", _RDS)
_v5(CIS_3_2_4, "aws-cis-v5-2.2.4", _RDS)
_v5(CIS_3_3_1, "aws-cis-v5-2.3.1", _EFS)


# ---------------------------------------------------------------------------
# Section 3 – Logging
# ---------------------------------------------------------------------------
_LOG = "3 Logging"

from sspm.providers.aws.rules.section4_logging.cis_4_1 import CIS_4_1    # noqa: E402
from sspm.providers.aws.rules.section4_logging.cis_4_2 import CIS_4_2    # noqa: E402
from sspm.providers.aws.rules.section4_logging.cis_4_3 import CIS_4_3    # noqa: E402
from sspm.providers.aws.rules.section4_logging.cis_4_4 import CIS_4_4    # noqa: E402
from sspm.providers.aws.rules.section4_logging.cis_4_5 import CIS_4_5    # noqa: E402
from sspm.providers.aws.rules.section4_logging.cis_4_6 import CIS_4_6    # noqa: E402
from sspm.providers.aws.rules.section4_logging.cis_4_7 import CIS_4_7    # noqa: E402
from sspm.providers.aws.rules.section4_logging.cis_4_8 import CIS_4_8    # noqa: E402
from sspm.providers.aws.rules.section4_logging.cis_4_9 import CIS_4_9    # noqa: E402

_v5(CIS_4_1, "aws-cis-v5-3.1", _LOG)
_v5(CIS_4_2, "aws-cis-v5-3.2", _LOG)
_v5(CIS_4_3, "aws-cis-v5-3.3", _LOG)
_v5(CIS_4_4, "aws-cis-v5-3.4", _LOG)
_v5(CIS_4_5, "aws-cis-v5-3.5", _LOG)
_v5(CIS_4_6, "aws-cis-v5-3.6", _LOG)
_v5(CIS_4_7, "aws-cis-v5-3.7", _LOG)
_v5(CIS_4_8, "aws-cis-v5-3.8", _LOG)
_v5(CIS_4_9, "aws-cis-v5-3.9", _LOG)


# ---------------------------------------------------------------------------
# Section 4 – Monitoring
# Monitoring rules use a dynamic factory in the legacy module; we recreate
# them directly here so no import-order dependency is required.
# ---------------------------------------------------------------------------
_MON = "4 Monitoring"
_MON_PROFILES_L1 = [CISProfile.AWS_L1]
_MON_PROFILES_L2 = [CISProfile.AWS_L2]


def _v5_monitoring(
    rule_id: str,
    title: str,
    description: str,
    filter_keywords: list[str],
    rule_description: str,
    severity: Severity = Severity.MEDIUM,
    profiles: list | None = None,
    cis_controls: list | None = None,
) -> type:
    _profiles = profiles if profiles is not None else _MON_PROFILES_L1

    @registry.rule
    class _V5Mon(AWSRule):
        metadata = RuleMetadata(
            id=rule_id,
            title=title,
            section=_MON,
            benchmark=_V5_BENCHMARK,
            benchmark_version=_V5_VERSION,
            assessment_status=AssessmentStatus.MANUAL,
            profiles=_profiles,
            severity=severity,
            description=description,
            rationale=(
                "Real-time monitoring of API calls and CloudTrail events enables faster "
                "detection of and response to security incidents."
            ),
            impact="SNS notifications may generate alerts for legitimate administrative activity.",
            audit_procedure=(
                "1. Identify an active multi-region CloudTrail with CloudWatch Logs.\n"
                "2. Check the log group for a metric filter matching the pattern.\n"
                "3. Verify a CloudWatch alarm exists on that metric.\n"
                "4. Verify the alarm's SNS topic has at least one active subscription."
            ),
            remediation=(
                "1. Create a metric filter on the CloudTrail log group.\n"
                "2. Create a CloudWatch alarm on the metric.\n"
                "3. Create an SNS topic and subscribe a notification endpoint.\n"
                "4. Set the alarm action to the SNS topic ARN."
            ),
            default_value="No metric filters or alarms are created by default.",
            cis_controls=cis_controls or [],
        )
        _filter_keywords = filter_keywords
        _rule_desc = rule_description

        async def check(self, data: CollectedData):
            return self._check_monitoring_rule(data, self._filter_keywords, self._rule_desc)

    _V5Mon.__name__ = rule_id.replace("-", "_").replace(".", "_")
    _V5Mon.__qualname__ = _V5Mon.__name__
    return _V5Mon


_v5_monitoring(
    rule_id="aws-cis-v5-4.1",
    title="Ensure unauthorized API calls are monitored",
    description="Real-time monitoring of unauthorized API calls detects access attempts.",
    filter_keywords=["AccessDenied", "UnauthorizedAccess"],
    rule_description="unauthorized API calls",
    severity=Severity.HIGH,
    profiles=_MON_PROFILES_L2,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.2",
    title="Ensure management console sign-in without MFA is monitored",
    description="Monitoring console logins without MFA helps detect compromised credentials.",
    filter_keywords=["ConsoleLogin", "MFAUsed"],
    rule_description="Management Console sign-in without MFA",
    severity=Severity.HIGH,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.3",
    title="Ensure usage of the 'root' account is monitored",
    description="Any use of the root account should trigger an immediate alert.",
    filter_keywords=["userIdentity.type", "Root"],
    rule_description="root account usage",
    severity=Severity.CRITICAL,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.4",
    title="Ensure IAM policy changes are monitored",
    description="Monitoring IAM policy changes detects privilege escalation attempts.",
    filter_keywords=["DeleteGroupPolicy", "PutGroupPolicy", "PutUserPolicy", "PutRolePolicy"],
    rule_description="IAM policy changes",
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.5",
    title="Ensure CloudTrail configuration changes are monitored",
    description="Changes to CloudTrail could disable audit logging.",
    filter_keywords=["CreateTrail", "DeleteTrail", "UpdateTrail", "StopLogging"],
    rule_description="CloudTrail configuration changes",
    severity=Severity.HIGH,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.6",
    title="Ensure AWS Management Console authentication failures are monitored",
    description="Repeated authentication failures may indicate a brute-force attack.",
    filter_keywords=["ConsoleLogin", "Failed authentication"],
    rule_description="Management Console authentication failures",
    profiles=_MON_PROFILES_L2,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.7",
    title="Ensure disabling or scheduled deletion of customer created CMKs is monitored",
    description="KMS key deletion or disabling can render data permanently inaccessible.",
    filter_keywords=["DisableKey", "ScheduleKeyDeletion"],
    rule_description="CMK disabling or scheduled deletion",
    severity=Severity.HIGH,
    profiles=_MON_PROFILES_L2,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.8",
    title="Ensure S3 bucket policy changes are monitored",
    description="S3 bucket policy changes could expose data to the public.",
    filter_keywords=["PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl"],
    rule_description="S3 bucket policy changes",
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.9",
    title="Ensure AWS Config configuration changes are monitored",
    description="Changes to AWS Config could disable compliance monitoring.",
    filter_keywords=["StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel"],
    rule_description="AWS Config configuration changes",
    profiles=_MON_PROFILES_L2,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.10",
    title="Ensure security group changes are monitored",
    description="Unauthorized security group changes can open unintended network access.",
    filter_keywords=["AuthorizeSecurityGroupIngress", "CreateSecurityGroup", "DeleteSecurityGroup"],
    rule_description="security group changes",
    profiles=_MON_PROFILES_L2,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.11",
    title="Ensure Network Access Control List (NACL) changes are monitored",
    description="NACL changes can inadvertently expose or restrict network paths.",
    filter_keywords=["CreateNetworkAcl", "DeleteNetworkAcl", "ReplaceNetworkAclEntry"],
    rule_description="NACL changes",
    profiles=_MON_PROFILES_L2,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.12",
    title="Ensure changes to network gateways are monitored",
    description="Network gateway changes can alter traffic routing unexpectedly.",
    filter_keywords=["CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway"],
    rule_description="network gateway changes",
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.13",
    title="Ensure route table changes are monitored",
    description="Route table changes can alter how network traffic flows through VPCs.",
    filter_keywords=["CreateRoute", "DeleteRoute", "ReplaceRoute", "DeleteRouteTable"],
    rule_description="route table changes",
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.14",
    title="Ensure VPC changes are monitored",
    description="Monitoring VPC changes helps detect unauthorized network infrastructure modifications.",
    filter_keywords=["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection"],
    rule_description="VPC changes",
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)
_v5_monitoring(
    rule_id="aws-cis-v5-4.15",
    title="Ensure AWS Organizations changes are monitored",
    description=(
        "Monitoring AWS Organizations changes helps detect unauthorized modifications to "
        "organizational structure, SCPs, and account membership."
    ),
    filter_keywords=["organizations.amazonaws.com"],
    rule_description="AWS Organizations changes",
    severity=Severity.HIGH,
    cis_controls=[
        CISControl(version="v8", control_id="8.5", title="Collect Detailed Audit Logs", ig1=False, ig2=True, ig3=True),
        CISControl(version="v7", control_id="6.3", title="Enable Detailed Logging", ig1=False, ig2=True, ig3=True),
    ],
)

# 4.16 – Security Hub (Automated, L2) — inherit from legacy CIS_5_16
from sspm.providers.aws.rules.section5_monitoring.cis_5_monitoring_rules import CIS_5_16  # noqa: E402

_v5(CIS_5_16, "aws-cis-v5-4.16", _MON)


# ---------------------------------------------------------------------------
# Section 5 – Networking
# ---------------------------------------------------------------------------
_EC2 = "5.1 Networking – Elastic Compute Cloud (EC2)"
_NET = "5 Networking"

from sspm.providers.aws.rules.section6_networking.cis_6_1_1 import CIS_6_1_1  # noqa: E402
from sspm.providers.aws.rules.section6_networking.cis_6_1_2 import CIS_6_1_2  # noqa: E402
from sspm.providers.aws.rules.section6_networking.cis_6_2 import CIS_6_2      # noqa: E402
from sspm.providers.aws.rules.section6_networking.cis_6_3 import CIS_6_3      # noqa: E402
from sspm.providers.aws.rules.section6_networking.cis_6_4 import CIS_6_4      # noqa: E402
from sspm.providers.aws.rules.section6_networking.cis_6_5 import CIS_6_5      # noqa: E402
from sspm.providers.aws.rules.section6_networking.cis_6_6 import CIS_6_6      # noqa: E402
from sspm.providers.aws.rules.section6_networking.cis_6_7 import CIS_6_7      # noqa: E402

_v5(CIS_6_1_1, "aws-cis-v5-5.1.1", _EC2)
_v5(CIS_6_1_2, "aws-cis-v5-5.1.2", _EC2)
_v5(CIS_6_2,   "aws-cis-v5-5.2",   _NET)
_v5(CIS_6_3,   "aws-cis-v5-5.3",   _NET)
_v5(CIS_6_4,   "aws-cis-v5-5.4",   _NET)
_v5(CIS_6_5,   "aws-cis-v5-5.5",   _NET)
_v5(CIS_6_6,   "aws-cis-v5-5.6",   _NET)
_v5(CIS_6_7,   "aws-cis-v5-5.7",   _NET)
