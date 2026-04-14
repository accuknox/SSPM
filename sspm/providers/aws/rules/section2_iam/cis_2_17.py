"""CIS AWS 2.17 – Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed (Automated, L1)"""
from __future__ import annotations

from datetime import datetime, timezone

from sspm.core.models import AssessmentStatus, CISControl, CISProfile, Evidence, RuleMetadata, Severity
from sspm.core.registry import registry
from sspm.providers.aws.rules.base import AWSRule
from sspm.providers.base import CollectedData


@registry.rule
class CIS_2_17(AWSRule):
    metadata = RuleMetadata(
        id="aws-cis-2.17",
        title="Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed",
        section="2 Identity and Access Management",
        benchmark="CIS Amazon Web Services Foundations Benchmark v7.0.0",
        assessment_status=AssessmentStatus.AUTOMATED,
        profiles=[CISProfile.AWS_L1],
        severity=Severity.HIGH,
        description=(
            "To enable HTTPS connections to your website or application in AWS, you need an "
            "SSL/TLS server certificate. You can use IAM to store certificates. Expired SSL/TLS "
            "certificates should be removed to prevent accidental use or confusion."
        ),
        rationale=(
            "Removing expired certificates prevents them from being accidentally re-associated "
            "with resources, which could cause SSL errors or indicate a certificate management "
            "process failure. It also reduces the attack surface."
        ),
        impact="Removing an expired certificate that is still in use will cause SSL failures.",
        audit_procedure=(
            "aws iam list-server-certificates\n"
            "For each certificate, check the Expiration field in ServerCertificateMetadata.\n"
            "Any certificate with Expiration in the past is expired."
        ),
        remediation=(
            "aws iam delete-server-certificate --server-certificate-name <name>\n"
            "Before deleting, verify the certificate is not actively used by any ELB or CloudFront."
        ),
        default_value="No SSL/TLS certificates are stored in IAM by default.",
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html"
        ],
        cis_controls=[
            CISControl(version="v8", control_id="3.1", title="Establish and Maintain a Data Management Process", ig1=True, ig2=True, ig3=True),
            CISControl(version="v7", control_id="13.1", title="Maintain an Inventory of Sensitive Information", ig1=True, ig2=True, ig3=True),
        ],
    )

    async def check(self, data: CollectedData) -> "Finding":
        certificates = data.get("ssl_certificates")
        if certificates is None:
            return self._skip(
                "Could not retrieve SSL/TLS certificates from IAM. "
                "Ensure the ssl_certificates collector is enabled."
            )

        now = datetime.now(timezone.utc)
        expired = []
        for cert in certificates:
            meta = cert.get("ServerCertificateMetadata", cert)
            expiry_str = str(meta.get("Expiration", ""))
            name = meta.get("ServerCertificateName", "unknown")
            if not expiry_str:
                continue
            try:
                expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                if expiry < now:
                    days_expired = (now - expiry).days
                    expired.append(f"{name} (expired {days_expired} days ago)")
            except ValueError:
                pass

        evidence = [Evidence(
            source="iam:ListServerCertificates",
            data={"expired_certificates": expired, "total_certificates": len(certificates)},
            description="Expired SSL/TLS certificates stored in IAM.",
        )]

        if expired:
            return self._fail(
                f"{len(expired)} expired SSL/TLS certificate(s) found in IAM: "
                f"{', '.join(expired[:10])}{'...' if len(expired) > 10 else ''}",
                evidence=evidence,
            )
        return self._pass(
            f"No expired SSL/TLS certificates found in IAM ({len(certificates)} total). Compliant.",
            evidence=evidence,
        )
