"""
CIS AWS Section 5 – Monitoring rules (5.1–5.15), Manual, Level 1, and 5.16 Automated, Level 2.

Rules 5.1–5.15 check that CloudWatch metric filters and alarms exist for various security
events. Per the CIS AWS Foundations Benchmark v7.0.0, these are classified as Manual.
However, since we have the CloudWatch data, we implement the actual checks using the
_check_monitoring_rule helper and mark them as Manual per the benchmark.

Rule 5.16 checks that AWS Security Hub is enabled.
"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData

_BENCHMARK = "CIS Amazon Web Services Foundations Benchmark v7.0.0"
_SECTION = "5 Monitoring"
_PROFILES_L1 = [CISProfile.AWS_L1]
_PROFILES_L2 = [CISProfile.AWS_L2]


def _monitoring_rule(
    rule_id: str,
    title: str,
    description: str,
    filter_keywords: list[str],
    rule_description: str,
    severity: Severity = Severity.MEDIUM,
    profiles: list | None = None,
) -> type:
    _profiles = profiles if profiles is not None else _PROFILES_L1

    @registry.rule
    class _Rule(AWSRule):
        metadata = RuleMetadata(
            id=rule_id,
            title=title,
            section=_SECTION,
            benchmark=_BENCHMARK,
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
                "1. Identify active multi-region CloudTrail with CloudWatch Logs.\n"
                "2. Check log group for a metric filter matching the pattern.\n"
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
        )

        _filter_keywords = filter_keywords
        _rule_desc = rule_description

        async def check(self, data: CollectedData):
            return self._check_monitoring_rule(data, self._filter_keywords, self._rule_desc)

    _Rule.__name__ = rule_id.replace("-", "_").replace(".", "_")
    _Rule.__qualname__ = _Rule.__name__
    return _Rule


# ---------------------------------------------------------------------------
# 5.1 – Unauthorized API calls
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.1",
    title="Ensure a log metric filter and alarm exist for unauthorized API calls",
    description=(
        "Real-time monitoring of API calls enables detection of unauthorized access attempts. "
        "A log metric filter and alarm should exist for unauthorized API calls."
    ),
    filter_keywords=["AccessDenied", "UnauthorizedAccess"],
    rule_description="unauthorized API calls",
    severity=Severity.HIGH,
    profiles=_PROFILES_L2,
)

# ---------------------------------------------------------------------------
# 5.2 – Management Console sign-in without MFA
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.2",
    title="Ensure a log metric filter and alarm exist for Management Console sign-in without MFA",
    description=(
        "Monitoring console logins without MFA helps detect use of compromised credentials. "
        "A log metric filter and alarm should exist for console sign-in without MFA."
    ),
    filter_keywords=["ConsoleLogin", "MFAUsed"],
    rule_description="Management Console sign-in without MFA",
    severity=Severity.HIGH,
)

# ---------------------------------------------------------------------------
# 5.3 – Root account usage
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.3",
    title='Ensure a log metric filter and alarm exist for usage of the "root" account',
    description=(
        "Any use of the root account should be alerted on immediately. "
        "A log metric filter and alarm should exist for root account usage."
    ),
    filter_keywords=["userIdentity.type", "Root"],
    rule_description="root account usage",
    severity=Severity.CRITICAL,
)

# ---------------------------------------------------------------------------
# 5.4 – IAM policy changes
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.4",
    title="Ensure a log metric filter and alarm exist for IAM policy changes",
    description=(
        "Monitoring IAM policy changes detects privilege escalation attempts. "
        "A log metric filter and alarm should exist for IAM policy changes."
    ),
    filter_keywords=["DeleteGroupPolicy", "PutGroupPolicy", "PutUserPolicy", "PutRolePolicy"],
    rule_description="IAM policy changes",
)

# ---------------------------------------------------------------------------
# 5.5 – CloudTrail configuration changes
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.5",
    title="Ensure a log metric filter and alarm exist for CloudTrail configuration changes",
    description=(
        "Changes to CloudTrail could disable audit logging. "
        "A log metric filter and alarm should exist for CloudTrail configuration changes."
    ),
    filter_keywords=["CreateTrail", "DeleteTrail", "UpdateTrail", "StopLogging"],
    rule_description="CloudTrail configuration changes",
    severity=Severity.HIGH,
)

# ---------------------------------------------------------------------------
# 5.6 – AWS Management Console authentication failures
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.6",
    title="Ensure a log metric filter and alarm exist for AWS Management Console authentication failures",
    description=(
        "Repeated authentication failures may indicate a brute-force attack. "
        "A log metric filter and alarm should exist for Management Console authentication failures."
    ),
    filter_keywords=["ConsoleLogin", "Failed authentication"],
    rule_description="Management Console authentication failures",
    profiles=_PROFILES_L2,
)

# ---------------------------------------------------------------------------
# 5.7 – Disabling or scheduled deletion of customer created CMKs
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.7",
    title="Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs",
    description=(
        "KMS key deletion or disabling can render data permanently inaccessible. "
        "A log metric filter and alarm should exist for CMK disabling or scheduled deletion."
    ),
    filter_keywords=["DisableKey", "ScheduleKeyDeletion"],
    rule_description="CMK disabling or scheduled deletion",
    severity=Severity.HIGH,
    profiles=_PROFILES_L2,
)

# ---------------------------------------------------------------------------
# 5.8 – S3 bucket policy changes
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.8",
    title="Ensure a log metric filter and alarm exist for S3 bucket policy changes",
    description=(
        "S3 bucket policy changes could expose data to the public. "
        "A log metric filter and alarm should exist for S3 bucket policy changes."
    ),
    filter_keywords=["PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl"],
    rule_description="S3 bucket policy changes",
)

# ---------------------------------------------------------------------------
# 5.9 – AWS Config configuration changes
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.9",
    title="Ensure a log metric filter and alarm exist for AWS Config configuration changes",
    description=(
        "Changes to AWS Config could disable compliance monitoring. "
        "A log metric filter and alarm should exist for AWS Config configuration changes."
    ),
    filter_keywords=["StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel"],
    rule_description="AWS Config configuration changes",
    profiles=_PROFILES_L2,
)

# ---------------------------------------------------------------------------
# 5.10 – Security group changes
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.10",
    title="Ensure a log metric filter and alarm exist for security group changes",
    description=(
        "Unauthorized security group changes can open unintended network access. "
        "A log metric filter and alarm should exist for security group changes."
    ),
    filter_keywords=["AuthorizeSecurityGroupIngress", "CreateSecurityGroup", "DeleteSecurityGroup"],
    rule_description="security group changes",
    profiles=_PROFILES_L2,
)

# ---------------------------------------------------------------------------
# 5.11 – Changes to Network Access Control Lists (NACL)
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.11",
    title="Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)",
    description=(
        "NACL changes can inadvertently expose or restrict network paths. "
        "A log metric filter and alarm should exist for NACL changes."
    ),
    filter_keywords=["CreateNetworkAcl", "DeleteNetworkAcl", "ReplaceNetworkAclEntry"],
    rule_description="NACL changes",
    profiles=_PROFILES_L2,
)

# ---------------------------------------------------------------------------
# 5.12 – Changes to network gateways
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.12",
    title="Ensure a log metric filter and alarm exist for changes to network gateways",
    description=(
        "Network gateway changes can alter traffic routing unexpectedly. "
        "A log metric filter and alarm should exist for network gateway changes."
    ),
    filter_keywords=["CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway"],
    rule_description="network gateway changes",
)

# ---------------------------------------------------------------------------
# 5.13 – Route table changes
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.13",
    title="Ensure a log metric filter and alarm exist for route table changes",
    description=(
        "Route table changes can alter how network traffic flows through VPCs. "
        "A log metric filter and alarm should exist for route table changes."
    ),
    filter_keywords=["CreateRoute", "DeleteRoute", "ReplaceRoute", "DeleteRouteTable"],
    rule_description="route table changes",
)

# ---------------------------------------------------------------------------
# 5.14 – VPC changes
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.14",
    title="Ensure a log metric filter and alarm exist for VPC changes",
    description=(
        "Monitoring VPC changes helps detect unauthorized network infrastructure modifications. "
        "A log metric filter and alarm should exist for VPC changes."
    ),
    filter_keywords=["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection"],
    rule_description="VPC changes",
)

# ---------------------------------------------------------------------------
# 5.15 – AWS Organizations changes
# ---------------------------------------------------------------------------
_monitoring_rule(
    rule_id="aws-cis-5.15",
    title="Ensure a log metric filter and alarm exist for AWS Organizations changes",
    description=(
        "Monitoring AWS Organizations changes helps detect unauthorized modifications to "
        "organizational structure, SCPs, and account membership. "
        "A log metric filter and alarm should exist for Organizations changes."
    ),
    filter_keywords=["organizations.amazonaws.com"],
    rule_description="AWS Organizations changes",
    severity=Severity.HIGH,
)


# ---------------------------------------------------------------------------
# 5.16 – Ensure AWS Security Hub is enabled (Automated, L2)
# ---------------------------------------------------------------------------
@registry.rule
class CIS_5_16(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-5.16",
        title="Ensure AWS Security Hub is enabled",
        section=_SECTION,
        benchmark=_BENCHMARK,
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=_PROFILES_L2,
        severity=Severity.MEDIUM,
        description=(
            "AWS Security Hub provides a comprehensive view of your security state in AWS "
            "and helps you check your environment against security industry standards and "
            "best practices. It should be enabled to centralize security findings."
        ),
        rationale=(
            "Security Hub aggregates security findings from multiple AWS services and "
            "third-party tools, providing a single pane of glass for security posture. "
            "Without it, security findings from GuardDuty, Inspector, Macie, and others "
            "must be checked individually."
        ),
        impact="Security Hub incurs cost based on the number of security checks and findings.",
        audit_procedure=(
            "aws securityhub describe-hub --region <primary-region>\n"
            "Verify that HubArn is returned (Security Hub is enabled)."
        ),
        remediation=(
            "aws securityhub enable-security-hub --region <region>\n"
            "Enable in the primary region and consider enabling in all active regions."
        ),
        default_value="Security Hub is not enabled by default.",
        references=[
            "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        security_hub = data.get("security_hub")
        if security_hub is None:
            return self._skip(
                "Could not retrieve Security Hub status. "
                "Ensure the security_hub collector is enabled."
            )

        hub_arn = security_hub.get("HubArn", "")
        evidence = [Evidence(
            source="securityhub:DescribeHub",
            data={"HubArn": hub_arn, "enabled": bool(hub_arn)},
            description="AWS Security Hub enable status.",
        )]

        if hub_arn:
            return self._pass(
                f"AWS Security Hub is enabled (HubArn: {hub_arn}). Compliant.",
                evidence=evidence,
            )
        return self._fail(
            "AWS Security Hub is not enabled. Enable Security Hub to centralize security findings.",
            evidence=evidence,
        )
