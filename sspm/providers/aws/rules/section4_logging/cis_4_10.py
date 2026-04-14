"""CIS AWS 4.10 – Ensure all AWS-managed web front-end services have access logging enabled (Manual, L1)"""
from __future__ import annotations

from sspm.core.models import AssessmentStatus, CISProfile, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_4_10(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-4.10",
        title="Ensure all AWS-managed web front-end services have access logging enabled",
        section="4 Logging",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.MANUAL,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.MEDIUM,
        description=(
            "Enable access logging for AWS web front-end services including CloudFront, "
            "API Gateway, Application Load Balancer, and Classic Load Balancer to capture "
            "detailed records of all requests made to these services."
        ),
        rationale=(
            "Access logs for web front-end services help detect malicious activity, "
            "troubleshoot issues, and support forensic investigations. Without these logs, "
            "web-layer attacks (DDoS, injection, etc.) may go undetected."
        ),
        impact="Access logging incurs storage costs in S3 or CloudWatch Logs.",
        audit_procedure=(
            "CloudFront: aws cloudfront list-distributions → check Logging.Enabled\n"
            "API Gateway: aws apigateway get-stages → check accessLogSettings\n"
            "ALB: aws elbv2 describe-load-balancers → check attributes for access_logs.s3.enabled\n"
            "Classic ELB: aws elb describe-load-balancers → check AccessLog.Enabled"
        ),
        remediation=(
            "Enable access logging for each service:\n"
            "CloudFront: Edit distribution → Logging → Enable\n"
            "API Gateway: Stage → Logs/Tracing → Enable Access Logging\n"
            "ALB: Load Balancer → Attributes → Access logs → Enable\n"
            "Classic ELB: Load Balancer → Attributes → Access logs → Enable"
        ),
        default_value="Access logging is not enabled by default for any of these services.",
        references=[
            "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
            "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html"
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        return self._manual(
            "Verify that access logging is enabled for all AWS web front-end services:\n"
            "1. CloudFront: Check each distribution's Logging settings.\n"
            "2. API Gateway: Check each stage's access log settings.\n"
            "3. Application Load Balancer: Check access_logs.s3.enabled attribute.\n"
            "4. Classic Load Balancer: Check AccessLog settings.\n"
            "Use AWS Console or the respective CLI commands to verify each service."
        )
