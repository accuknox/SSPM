"""Unit tests for all AWS CIS rules."""

from __future__ import annotations

import pytest

from sspm.core.models import FindingStatus
from sspm.providers.base import CollectedData

# Section 2 – IAM
from sspm.providers.aws.rules.section2_iam.cis_2_1_1 import CIS_2_1_1
from sspm.providers.aws.rules.section2_iam.cis_2_1_2 import CIS_2_1_2
from sspm.providers.aws.rules.section2_iam.cis_2_1_3 import CIS_2_1_3
from sspm.providers.aws.rules.section2_iam.cis_2_1_4 import CIS_2_1_4
from sspm.providers.aws.rules.section2_iam.cis_2_1_5 import CIS_2_1_5
from sspm.providers.aws.rules.section2_iam.cis_2_1_6 import CIS_2_1_6
from sspm.providers.aws.rules.section2_iam.cis_2_2 import CIS_2_2
from sspm.providers.aws.rules.section2_iam.cis_2_3 import CIS_2_3
from sspm.providers.aws.rules.section2_iam.cis_2_4 import CIS_2_4
from sspm.providers.aws.rules.section2_iam.cis_2_5 import CIS_2_5
from sspm.providers.aws.rules.section2_iam.cis_2_6 import CIS_2_6
from sspm.providers.aws.rules.section2_iam.cis_2_7 import CIS_2_7
from sspm.providers.aws.rules.section2_iam.cis_2_8 import CIS_2_8
from sspm.providers.aws.rules.section2_iam.cis_2_9 import CIS_2_9
from sspm.providers.aws.rules.section2_iam.cis_2_10 import CIS_2_10
from sspm.providers.aws.rules.section2_iam.cis_2_11 import CIS_2_11
from sspm.providers.aws.rules.section2_iam.cis_2_12 import CIS_2_12
from sspm.providers.aws.rules.section2_iam.cis_2_13 import CIS_2_13
from sspm.providers.aws.rules.section2_iam.cis_2_14 import CIS_2_14
from sspm.providers.aws.rules.section2_iam.cis_2_15 import CIS_2_15
from sspm.providers.aws.rules.section2_iam.cis_2_16 import CIS_2_16
from sspm.providers.aws.rules.section2_iam.cis_2_17 import CIS_2_17
from sspm.providers.aws.rules.section2_iam.cis_2_18 import CIS_2_18
from sspm.providers.aws.rules.section2_iam.cis_2_19 import CIS_2_19
from sspm.providers.aws.rules.section2_iam.cis_2_20 import CIS_2_20
from sspm.providers.aws.rules.section2_iam.cis_2_21 import CIS_2_21

# Section 3 – Storage
from sspm.providers.aws.rules.section3_storage.cis_3_1_1 import CIS_3_1_1
from sspm.providers.aws.rules.section3_storage.cis_3_1_2 import CIS_3_1_2
from sspm.providers.aws.rules.section3_storage.cis_3_1_3 import CIS_3_1_3
from sspm.providers.aws.rules.section3_storage.cis_3_1_4 import CIS_3_1_4
from sspm.providers.aws.rules.section3_storage.cis_3_2_1 import CIS_3_2_1
from sspm.providers.aws.rules.section3_storage.cis_3_2_2 import CIS_3_2_2
from sspm.providers.aws.rules.section3_storage.cis_3_2_3 import CIS_3_2_3
from sspm.providers.aws.rules.section3_storage.cis_3_2_4 import CIS_3_2_4
from sspm.providers.aws.rules.section3_storage.cis_3_3_1 import CIS_3_3_1

# Section 4 – Logging
from sspm.providers.aws.rules.section4_logging.cis_4_1 import CIS_4_1
from sspm.providers.aws.rules.section4_logging.cis_4_2 import CIS_4_2
from sspm.providers.aws.rules.section4_logging.cis_4_3 import CIS_4_3
from sspm.providers.aws.rules.section4_logging.cis_4_4 import CIS_4_4
from sspm.providers.aws.rules.section4_logging.cis_4_5 import CIS_4_5
from sspm.providers.aws.rules.section4_logging.cis_4_6 import CIS_4_6
from sspm.providers.aws.rules.section4_logging.cis_4_7 import CIS_4_7
from sspm.providers.aws.rules.section4_logging.cis_4_8 import CIS_4_8
from sspm.providers.aws.rules.section4_logging.cis_4_9 import CIS_4_9
from sspm.providers.aws.rules.section4_logging.cis_4_10 import CIS_4_10

# Section 5 – Monitoring (dynamically created classes, imported via registry side-effects)
import sspm.providers.aws.rules.section5_monitoring.cis_5_monitoring_rules  # noqa: F401
from sspm.providers.aws.rules.section5_monitoring.cis_5_monitoring_rules import CIS_5_16
from sspm.core.registry import registry as _registry

# Section 6 – Networking
from sspm.providers.aws.rules.section6_networking.cis_6_1_1 import CIS_6_1_1
from sspm.providers.aws.rules.section6_networking.cis_6_1_2 import CIS_6_1_2
from sspm.providers.aws.rules.section6_networking.cis_6_2 import CIS_6_2
from sspm.providers.aws.rules.section6_networking.cis_6_3 import CIS_6_3
from sspm.providers.aws.rules.section6_networking.cis_6_4 import CIS_6_4
from sspm.providers.aws.rules.section6_networking.cis_6_5 import CIS_6_5
from sspm.providers.aws.rules.section6_networking.cis_6_6 import CIS_6_6
from sspm.providers.aws.rules.section6_networking.cis_6_7 import CIS_6_7
from sspm.providers.aws.rules.section6_networking.cis_6_8 import CIS_6_8


def _aws(**kwargs) -> CollectedData:
    return CollectedData(provider="aws", target="123456789012", data=kwargs)


# ---------------------------------------------------------------------------
# Helper to look up dynamically-created monitoring rule classes
# ---------------------------------------------------------------------------

def _get_monitoring_rule(rule_id: str):
    """Look up a dynamically-created monitoring rule class from the registry."""
    rule = _registry._rules.get(rule_id)  # noqa: SLF001
    if rule is None:
        raise KeyError(f"Monitoring rule {rule_id!r} not found in registry")
    return rule


# ---------------------------------------------------------------------------
# 2.1.1 – Centralized root access (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_1()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.1.2 – Authorization guardrails (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_1_2:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_2()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.1.3 – Management account not for workloads (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_1_3:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_3()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.1.4 – OUs structured by environment (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_1_4:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_4()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.1.5 – Delegated admin manages policies (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_1_5:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_5()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.1.6 – Delegated admins manage integrated services (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_1_6:
    @pytest.fixture
    def rule(self):
        return CIS_2_1_6()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.2 – Maintain contact details (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_2:
    @pytest.fixture
    def rule(self):
        return CIS_2_2()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.3 – Security contact registered (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_3:
    @pytest.fixture
    def rule(self):
        return CIS_2_3()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.4 – No root access key
# ---------------------------------------------------------------------------

class TestCIS_2_4:
    @pytest.fixture
    def rule(self):
        return CIS_2_4()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_no_keys(self, rule):
        finding = await rule.check(_aws(iam_account_summary={"AccountAccessKeysPresent": 0}))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_keys_exist(self, rule):
        finding = await rule.check(_aws(iam_account_summary={"AccountAccessKeysPresent": 1}))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.5 – MFA for root
# ---------------------------------------------------------------------------

class TestCIS_2_5:
    @pytest.fixture
    def rule(self):
        return CIS_2_5()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_mfa_enabled(self, rule):
        finding = await rule.check(_aws(iam_account_summary={"AccountMFAEnabled": 1}))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_mfa_disabled(self, rule):
        finding = await rule.check(_aws(iam_account_summary={"AccountMFAEnabled": 0}))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.6 – Hardware MFA for root
# ---------------------------------------------------------------------------

class TestCIS_2_6:
    @pytest.fixture
    def rule(self):
        return CIS_2_6()

    async def test_manual_when_no_mfa_at_all(self, rule):
        # No MFA enabled at all → manual
        finding = await rule.check(_aws(
            iam_account_summary={"AccountMFAEnabled": 0},
            iam_virtual_mfa_devices=[],
        ))
        assert finding.status == FindingStatus.MANUAL

    async def test_manual_when_virtual_mfa(self, rule):
        # Root has virtual MFA → manual
        finding = await rule.check(_aws(
            iam_account_summary={"AccountMFAEnabled": 1},
            iam_virtual_mfa_devices=[{
                "User": {"Arn": "arn:aws:iam::123456789012:root"}
            }],
        ))
        assert finding.status == FindingStatus.MANUAL

    async def test_pass_when_hardware_mfa(self, rule):
        # MFA enabled but no virtual device for root → hardware
        finding = await rule.check(_aws(
            iam_account_summary={"AccountMFAEnabled": 1},
            iam_virtual_mfa_devices=[],
        ))
        assert finding.status == FindingStatus.PASS


# ---------------------------------------------------------------------------
# 2.7 – Eliminate root use (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_7:
    @pytest.fixture
    def rule(self):
        return CIS_2_7()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.8 – Password minimum length
# ---------------------------------------------------------------------------

class TestCIS_2_8:
    @pytest.fixture
    def rule(self):
        return CIS_2_8()

    async def test_fail_when_no_policy(self, rule):
        # No password_policy key → FAIL (not SKIP per rule design)
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.FAIL

    async def test_pass_when_length_14(self, rule):
        finding = await rule.check(_aws(password_policy={"MinimumPasswordLength": 14}))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_length_too_short(self, rule):
        finding = await rule.check(_aws(password_policy={"MinimumPasswordLength": 8}))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.9 – Password reuse prevention
# ---------------------------------------------------------------------------

class TestCIS_2_9:
    @pytest.fixture
    def rule(self):
        return CIS_2_9()

    async def test_fail_when_no_policy(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.FAIL

    async def test_pass_when_reuse_24(self, rule):
        finding = await rule.check(_aws(password_policy={"PasswordReusePrevention": 24}))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_reuse_too_low(self, rule):
        finding = await rule.check(_aws(password_policy={"PasswordReusePrevention": 5}))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.10 – MFA for IAM users with console password
# ---------------------------------------------------------------------------

class TestCIS_2_10:
    @pytest.fixture
    def rule(self):
        return CIS_2_10()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_all_users_have_mfa(self, rule):
        finding = await rule.check(_aws(credential_report=[
            {"user": "alice", "password_enabled": "true", "mfa_active": "true"},
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_user_missing_mfa(self, rule):
        finding = await rule.check(_aws(credential_report=[
            {"user": "alice", "password_enabled": "true", "mfa_active": "false"},
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.11 – Disable credentials unused for 45 days
# ---------------------------------------------------------------------------

class TestCIS_2_11:
    @pytest.fixture
    def rule(self):
        return CIS_2_11()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_credentials_recent(self, rule):
        finding = await rule.check(_aws(credential_report=[
            {"user": "alice", "password_enabled": "true",
             "password_last_used": "2026-05-01T00:00:00Z"},
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_credentials_stale(self, rule):
        finding = await rule.check(_aws(credential_report=[
            {
                "user": "alice",
                "password_enabled": "true",
                "password_last_used": "2025-01-01T00:00:00Z",
                "access_key_1_active": "false",
                "access_key_2_active": "false",
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.12 – Access keys rotated every 90 days
# ---------------------------------------------------------------------------

class TestCIS_2_12:
    @pytest.fixture
    def rule(self):
        return CIS_2_12()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_keys_recent(self, rule):
        finding = await rule.check(_aws(credential_report=[
            {
                "user": "alice",
                "access_key_1_active": "true",
                "access_key_1_last_rotated": "2026-04-01T00:00:00Z",
                "access_key_2_active": "false",
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_key_stale(self, rule):
        finding = await rule.check(_aws(credential_report=[
            {
                "user": "alice",
                "access_key_1_active": "true",
                "access_key_1_last_rotated": "2024-01-01T00:00:00Z",
                "access_key_2_active": "false",
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.13 – IAM users get permissions via groups
# ---------------------------------------------------------------------------

class TestCIS_2_13:
    @pytest.fixture
    def rule(self):
        return CIS_2_13()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_no_direct_policies(self, rule):
        finding = await rule.check(_aws(iam_users=[
            {"UserName": "alice", "_attached_policies": [], "_inline_policies": []}
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_direct_policy(self, rule):
        finding = await rule.check(_aws(iam_users=[
            {"UserName": "alice",
             "_attached_policies": [{"PolicyName": "ReadOnly"}],
             "_inline_policies": []}
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.14 – No full *:* admin policies
# ---------------------------------------------------------------------------

class TestCIS_2_14:
    @pytest.fixture
    def rule(self):
        return CIS_2_14()

    async def test_pass_when_no_violations(self, rule):
        finding = await rule.check(_aws(
            iam_policies=[{"PolicyName": "ReadOnly", "_document": {
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
            }}],
            iam_users=[{"UserName": "alice", "_attached_policies": []}],
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_full_admin_policy(self, rule):
        finding = await rule.check(_aws(
            iam_policies=[{"PolicyName": "AdminAll", "_document": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }}],
            iam_users=[],
        ))
        assert finding.status == FindingStatus.FAIL

    async def test_fail_when_admin_access_attached_to_user(self, rule):
        finding = await rule.check(_aws(
            iam_policies=[],
            iam_users=[{"UserName": "alice",
                        "_attached_policies": [{"PolicyName": "AdministratorAccess",
                                                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}],
        ))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.15 – Support role exists
# ---------------------------------------------------------------------------

class TestCIS_2_15:
    @pytest.fixture
    def rule(self):
        return CIS_2_15()

    async def test_pass_when_support_access_found(self, rule):
        finding = await rule.check(_aws(
            iam_users=[{"UserName": "support",
                        "_attached_policies": [{"PolicyName": "AWSSupportAccess",
                                                "PolicyArn": "arn:aws:iam::aws:policy/AWSSupportAccess"}]}],
            iam_policies=[],
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_support_access(self, rule):
        finding = await rule.check(_aws(
            iam_users=[{"UserName": "alice", "_attached_policies": []}],
            iam_policies=[],
        ))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.16 – IAM instance roles for EC2
# ---------------------------------------------------------------------------

class TestCIS_2_16:
    @pytest.fixture
    def rule(self):
        return CIS_2_16()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_all_instances_have_profile(self, rule):
        finding = await rule.check(_aws(ec2_instances=[
            {"InstanceId": "i-001", "State": {"Name": "running"},
             "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/role"}}
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_instance_missing_profile(self, rule):
        finding = await rule.check(_aws(ec2_instances=[
            {"InstanceId": "i-001", "State": {"Name": "running"}, "Region": "us-east-1"}
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.17 – Expired SSL/TLS certificates removed
# ---------------------------------------------------------------------------

class TestCIS_2_17:
    @pytest.fixture
    def rule(self):
        return CIS_2_17()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_certificates(self, rule):
        finding = await rule.check(_aws(ssl_certificates=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_no_expired_certs(self, rule):
        finding = await rule.check(_aws(ssl_certificates=[
            {"ServerCertificateMetadata": {
                "ServerCertificateName": "my-cert",
                "Expiration": "2099-01-01T00:00:00Z",
            }}
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_expired_cert_exists(self, rule):
        finding = await rule.check(_aws(ssl_certificates=[
            {"ServerCertificateMetadata": {
                "ServerCertificateName": "old-cert",
                "Expiration": "2020-01-01T00:00:00Z",
            }}
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.18 – IAM Access Analyzer enabled
# ---------------------------------------------------------------------------

class TestCIS_2_18:
    @pytest.fixture
    def rule(self):
        return CIS_2_18()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_analyzer_active(self, rule):
        finding = await rule.check(_aws(access_analyzers={
            "us-east-1": [{"status": "ACTIVE", "name": "default"}]
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_analyzer(self, rule):
        finding = await rule.check(_aws(access_analyzers={
            "us-east-1": []
        }))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 2.19 – Centrally managed IAM users (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_19:
    @pytest.fixture
    def rule(self):
        return CIS_2_19()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.20 – CloudShell access restricted (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_20:
    @pytest.fixture
    def rule(self):
        return CIS_2_20()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 2.21 – No unrestricted Principal * (Manual)
# ---------------------------------------------------------------------------

class TestCIS_2_21:
    @pytest.fixture
    def rule(self):
        return CIS_2_21()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 3.1.1 – S3 bucket policy denies HTTP
# ---------------------------------------------------------------------------

class TestCIS_3_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_3_1_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_https_enforced(self, rule):
        finding = await rule.check(_aws(s3_all_bucket_policies={
            "my-bucket": {
                "Statement": [{
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }]
            }
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_deny_http(self, rule):
        finding = await rule.check(_aws(s3_all_bucket_policies={
            "my-bucket": {
                "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]
            }
        }))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 3.1.2 – MFA Delete enabled (Manual)
# ---------------------------------------------------------------------------

class TestCIS_3_1_2:
    @pytest.fixture
    def rule(self):
        return CIS_3_1_2()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 3.1.3 – S3 data discovered and classified (Manual)
# ---------------------------------------------------------------------------

class TestCIS_3_1_3:
    @pytest.fixture
    def rule(self):
        return CIS_3_1_3()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 3.1.4 – S3 Block Public Access
# ---------------------------------------------------------------------------

class TestCIS_3_1_4:
    @pytest.fixture
    def rule(self):
        return CIS_3_1_4()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_all_blocks_enabled(self, rule):
        finding = await rule.check(_aws(s3_public_access_block={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_block_missing(self, rule):
        finding = await rule.check(_aws(s3_public_access_block={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 3.2.1 – RDS encryption at rest
# ---------------------------------------------------------------------------

class TestCIS_3_2_1:
    @pytest.fixture
    def rule(self):
        return CIS_3_2_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_encrypted(self, rule):
        finding = await rule.check(_aws(rds_instances=[
            {"DBInstanceIdentifier": "db1", "StorageEncrypted": True, "Region": "us-east-1"}
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_not_encrypted(self, rule):
        finding = await rule.check(_aws(rds_instances=[
            {"DBInstanceIdentifier": "db1", "StorageEncrypted": False, "Region": "us-east-1"}
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 3.2.2 – RDS Auto Minor Version Upgrade
# ---------------------------------------------------------------------------

class TestCIS_3_2_2:
    @pytest.fixture
    def rule(self):
        return CIS_3_2_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_auto_upgrade_enabled(self, rule):
        finding = await rule.check(_aws(rds_instances=[
            {"DBInstanceIdentifier": "db1", "AutoMinorVersionUpgrade": True, "Region": "us-east-1"}
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_auto_upgrade_disabled(self, rule):
        finding = await rule.check(_aws(rds_instances=[
            {"DBInstanceIdentifier": "db1", "AutoMinorVersionUpgrade": False, "Region": "us-east-1"}
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 3.2.3 – RDS not publicly accessible
# ---------------------------------------------------------------------------

class TestCIS_3_2_3:
    @pytest.fixture
    def rule(self):
        return CIS_3_2_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_instances(self, rule):
        finding = await rule.check(_aws(rds_instances=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_not_public(self, rule):
        finding = await rule.check(_aws(rds_instances=[
            {"DBInstanceIdentifier": "db1", "PubliclyAccessible": False, "Region": "us-east-1"}
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_publicly_accessible(self, rule):
        finding = await rule.check(_aws(rds_instances=[
            {"DBInstanceIdentifier": "db1", "PubliclyAccessible": True, "Region": "us-east-1"}
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 3.2.4 – RDS Multi-AZ (Manual)
# ---------------------------------------------------------------------------

class TestCIS_3_2_4:
    @pytest.fixture
    def rule(self):
        return CIS_3_2_4()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 3.3.1 – EFS encryption
# ---------------------------------------------------------------------------

class TestCIS_3_3_1:
    @pytest.fixture
    def rule(self):
        return CIS_3_3_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_encrypted(self, rule):
        finding = await rule.check(_aws(efs_file_systems=[
            {"FileSystemId": "fs-001", "Encrypted": True, "Region": "us-east-1"}
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_not_encrypted(self, rule):
        finding = await rule.check(_aws(efs_file_systems=[
            {"FileSystemId": "fs-001", "Encrypted": False, "Region": "us-east-1"}
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 4.1 – CloudTrail enabled in all regions (Manual)
# ---------------------------------------------------------------------------

class TestCIS_4_1:
    @pytest.fixture
    def rule(self):
        return CIS_4_1()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 4.2 – CloudTrail log file validation
# ---------------------------------------------------------------------------

class TestCIS_4_2:
    @pytest.fixture
    def rule(self):
        return CIS_4_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_fail_when_no_trails(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[]))
        assert finding.status == FindingStatus.FAIL

    async def test_pass_when_validation_enabled(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[
            {"Name": "my-trail", "LogFileValidationEnabled": True}
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_validation_disabled(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[
            {"Name": "my-trail", "LogFileValidationEnabled": False}
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 4.3 – AWS Config enabled
# ---------------------------------------------------------------------------

class TestCIS_4_3:
    @pytest.fixture
    def rule(self):
        return CIS_4_3()

    async def test_fail_when_no_recorders(self, rule):
        # Empty list returns FAIL (Config is not enabled)
        finding = await rule.check(_aws(config_recorders=[], config_recorder_statuses=[]))
        assert finding.status == FindingStatus.FAIL

    async def test_pass_when_recorder_active(self, rule):
        finding = await rule.check(_aws(
            config_recorders=[{
                "name": "default",
                "recordingGroup": {"allSupported": True},
            }],
            config_recorder_statuses=[{
                "name": "default",
                "recording": True,
                "lastStatus": "SUCCESS",
            }],
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_recorder_not_recording(self, rule):
        finding = await rule.check(_aws(
            config_recorders=[{
                "name": "default",
                "recordingGroup": {"allSupported": True},
            }],
            config_recorder_statuses=[{
                "name": "default",
                "recording": False,
                "lastStatus": "FAILURE",
            }],
        ))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 4.4 – CloudTrail S3 bucket not public (Manual)
# ---------------------------------------------------------------------------

class TestCIS_4_4:
    @pytest.fixture
    def rule(self):
        return CIS_4_4()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 4.5 – CloudTrail trails encrypted with KMS
# ---------------------------------------------------------------------------

class TestCIS_4_5:
    @pytest.fixture
    def rule(self):
        return CIS_4_5()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_fail_when_no_trails(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[]))
        assert finding.status == FindingStatus.FAIL

    async def test_pass_when_kms_set(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[
            {"Name": "my-trail", "KMSKeyId": "arn:aws:kms:us-east-1:123:key/abc"}
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_kms(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[
            {"Name": "my-trail"}
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 4.6 – KMS key rotation enabled
# ---------------------------------------------------------------------------

class TestCIS_4_6:
    @pytest.fixture
    def rule(self):
        return CIS_4_6()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_rotation_enabled(self, rule):
        finding = await rule.check(_aws(kms_keys=[
            {
                "KeyId": "key-1",
                "_detail": {"KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT", "KeyState": "Enabled"},
                "_rotation": True,
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_rotation_disabled(self, rule):
        finding = await rule.check(_aws(kms_keys=[
            {
                "KeyId": "key-1",
                "_detail": {"KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT", "KeyState": "Enabled"},
                "_rotation": False,
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 4.7 – VPC flow logging enabled
# ---------------------------------------------------------------------------

class TestCIS_4_7:
    @pytest.fixture
    def rule(self):
        return CIS_4_7()

    async def test_skip_when_no_vpcs(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_all_vpcs_have_flow_logs(self, rule):
        finding = await rule.check(_aws(
            ec2_vpcs=[{"VpcId": "vpc-001", "Region": "us-east-1"}],
            ec2_flow_logs=[{"FlowLogStatus": "ACTIVE", "ResourceId": "vpc-001"}],
        ))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_vpc_missing_flow_logs(self, rule):
        finding = await rule.check(_aws(
            ec2_vpcs=[{"VpcId": "vpc-001", "Region": "us-east-1"}],
            ec2_flow_logs=[],
        ))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 4.8 – S3 object-level write event logging
# ---------------------------------------------------------------------------

class TestCIS_4_8:
    @pytest.fixture
    def rule(self):
        return CIS_4_8()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_write_logging_enabled(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[
            {
                "Name": "my-trail",
                "IsMultiRegionTrail": True,
                "_status": {"IsLogging": True},
                "_event_selectors": [{
                    "ReadWriteType": "WriteOnly",
                    "IncludeManagementEvents": True,
                    "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]}],
                }],
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_write_logging(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[
            {
                "Name": "my-trail",
                "IsMultiRegionTrail": True,
                "_status": {"IsLogging": True},
                "_event_selectors": [],
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 4.9 – S3 object-level read event logging
# ---------------------------------------------------------------------------

class TestCIS_4_9:
    @pytest.fixture
    def rule(self):
        return CIS_4_9()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_read_logging_enabled(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[
            {
                "Name": "my-trail",
                "IsMultiRegionTrail": True,
                "_status": {"IsLogging": True},
                "_event_selectors": [{
                    "ReadWriteType": "ReadOnly",
                    "IncludeManagementEvents": True,
                    "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]}],
                }],
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_no_read_logging(self, rule):
        finding = await rule.check(_aws(cloudtrail_trails=[
            {
                "Name": "my-trail",
                "IsMultiRegionTrail": True,
                "_status": {"IsLogging": True},
                "_event_selectors": [],
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 4.10 – Object-level events in CloudTrail (Manual)
# ---------------------------------------------------------------------------

class TestCIS_4_10:
    @pytest.fixture
    def rule(self):
        return CIS_4_10()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# Section 5 monitoring rules – helper
# ---------------------------------------------------------------------------

def _monitoring_data(log_group: str, keywords: list[str], metric_name: str, alarm_name: str, sns_arn: str):
    """Build minimal CollectedData to satisfy a monitoring rule's PASS path."""
    return _aws(
        cloudtrail_trails=[{
            "Name": "my-trail",
            "IsMultiRegionTrail": True,
            "CloudWatchLogsLogGroupArn": f"arn:aws:logs:us-east-1:123456789012:log-group:{log_group}:*",
            "_status": {"IsLogging": True},
            "_event_selectors": [{
                "IncludeManagementEvents": True,
                "ReadWriteType": "All",
            }],
        }],
        cloudwatch_metric_filters={
            log_group: [{
                "filterPattern": " ".join(keywords),
                "metricTransformations": [{"metricName": metric_name}],
            }]
        },
        cloudwatch_alarms=[{
            "AlarmName": alarm_name,
            "MetricName": metric_name,
            "AlarmActions": [sns_arn],
        }],
        sns_subscriptions={
            sns_arn: [{"SubscriptionArn": f"arn:aws:sns:us-east-1:123:{alarm_name}-sub"}]
        },
    )


# ---------------------------------------------------------------------------
# 5.1 – Unauthorized API calls
# ---------------------------------------------------------------------------

class TestCIS_5_1:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.1")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL

    async def test_pass_when_fully_configured(self, rule):
        data = _monitoring_data(
            "my-log-group",
            ["AccessDenied", "UnauthorizedAccess"],
            "UnauthorizedAPICalls",
            "UnauthorizedAPICallsAlarm",
            "arn:aws:sns:us-east-1:123:alerts",
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS


# ---------------------------------------------------------------------------
# 5.2 – Console sign-in without MFA
# ---------------------------------------------------------------------------

class TestCIS_5_2:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.2")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL

    async def test_pass_when_configured(self, rule):
        data = _monitoring_data(
            "my-log-group",
            ["ConsoleLogin", "MFAUsed"],
            "ConsoleNoMFA",
            "ConsoleNoMFAAlarm",
            "arn:aws:sns:us-east-1:123:alerts",
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS


# ---------------------------------------------------------------------------
# 5.3 – Root account usage
# ---------------------------------------------------------------------------

class TestCIS_5_3:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.3")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL

    async def test_pass_when_configured(self, rule):
        data = _monitoring_data(
            "my-log-group",
            ["userIdentity.type", "Root"],
            "RootUsage",
            "RootUsageAlarm",
            "arn:aws:sns:us-east-1:123:alerts",
        )
        finding = await rule.check(data)
        assert finding.status == FindingStatus.PASS


# ---------------------------------------------------------------------------
# 5.4 – IAM policy changes
# ---------------------------------------------------------------------------

class TestCIS_5_4:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.4")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.5 – CloudTrail configuration changes
# ---------------------------------------------------------------------------

class TestCIS_5_5:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.5")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.6 – Console authentication failures
# ---------------------------------------------------------------------------

class TestCIS_5_6:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.6")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.7 – CMK disabling/deletion
# ---------------------------------------------------------------------------

class TestCIS_5_7:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.7")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.8 – S3 bucket policy changes
# ---------------------------------------------------------------------------

class TestCIS_5_8:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.8")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.9 – AWS Config changes
# ---------------------------------------------------------------------------

class TestCIS_5_9:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.9")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.10 – Security group changes
# ---------------------------------------------------------------------------

class TestCIS_5_10:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.10")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.11 – NACL changes
# ---------------------------------------------------------------------------

class TestCIS_5_11:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.11")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.12 – Network gateway changes
# ---------------------------------------------------------------------------

class TestCIS_5_12:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.12")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.13 – Route table changes
# ---------------------------------------------------------------------------

class TestCIS_5_13:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.13")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.14 – VPC changes
# ---------------------------------------------------------------------------

class TestCIS_5_14:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.14")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.15 – AWS Organizations changes
# ---------------------------------------------------------------------------

class TestCIS_5_15:
    @pytest.fixture
    def rule(self):
        return _get_monitoring_rule("aws-cis-5.15")

    async def test_manual_when_no_trail(self, rule):
        finding = await rule.check(_aws(
            cloudtrail_trails=[],
            cloudwatch_metric_filters={},
            cloudwatch_alarms=[],
            sns_subscriptions={},
        ))
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 5.16 – Security Hub enabled
# ---------------------------------------------------------------------------

class TestCIS_5_16:
    @pytest.fixture
    def rule(self):
        return CIS_5_16()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_hub_enabled(self, rule):
        finding = await rule.check(_aws(security_hub={
            "HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_hub_disabled(self, rule):
        finding = await rule.check(_aws(security_hub={"HubArn": ""}))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 6.1.1 – EBS encryption by default
# ---------------------------------------------------------------------------

class TestCIS_6_1_1:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_1()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_all_regions_encrypted(self, rule):
        finding = await rule.check(_aws(ebs_encryption_by_default={
            "us-east-1": {"EbsEncryptionByDefault": True}
        }))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_region_not_encrypted(self, rule):
        finding = await rule.check(_aws(ebs_encryption_by_default={
            "us-east-1": {"EbsEncryptionByDefault": False}
        }))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 6.1.2 – No unrestricted CIFS access
# ---------------------------------------------------------------------------

class TestCIS_6_1_2:
    @pytest.fixture
    def rule(self):
        return CIS_6_1_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_no_unrestricted_cifs(self, rule):
        finding = await rule.check(_aws(ec2_security_groups=[
            {
                "GroupId": "sg-001",
                "GroupName": "private-sg",
                "Region": "us-east-1",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 445, "ToPort": 445,
                     "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
                ]
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_unrestricted_cifs(self, rule):
        finding = await rule.check(_aws(ec2_security_groups=[
            {
                "GroupId": "sg-001",
                "GroupName": "open-sg",
                "Region": "us-east-1",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 445, "ToPort": 445,
                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ]
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 6.2 – NACLs restrict admin ports
# ---------------------------------------------------------------------------

class TestCIS_6_2:
    @pytest.fixture
    def rule(self):
        return CIS_6_2()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_skip_when_no_nacls(self, rule):
        finding = await rule.check(_aws(ec2_nacls=[]))
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_nacl_restricts_admin(self, rule):
        # NACL with no rules allowing 22/3389 from 0.0.0.0/0
        finding = await rule.check(_aws(ec2_nacls=[
            {
                "NetworkAclId": "acl-001",
                "Region": "us-east-1",
                "Entries": [
                    {"RuleNumber": 100, "Protocol": "6", "RuleAction": "deny",
                     "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22},
                     "Egress": False}
                ]
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_nacl_allows_ssh(self, rule):
        finding = await rule.check(_aws(ec2_nacls=[
            {
                "NetworkAclId": "acl-001",
                "Region": "us-east-1",
                "Entries": [
                    {"RuleNumber": 100, "Protocol": "6", "RuleAction": "allow",
                     "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22},
                     "Egress": False}
                ]
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 6.3 – No unrestricted SSH/RDP IPv4
# ---------------------------------------------------------------------------

class TestCIS_6_3:
    @pytest.fixture
    def rule(self):
        return CIS_6_3()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_restricted(self, rule):
        finding = await rule.check(_aws(ec2_security_groups=[
            {
                "GroupId": "sg-001",
                "GroupName": "private",
                "Region": "us-east-1",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                     "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
                ]
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_unrestricted_ssh(self, rule):
        finding = await rule.check(_aws(ec2_security_groups=[
            {
                "GroupId": "sg-001",
                "GroupName": "open",
                "Region": "us-east-1",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ]
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 6.4 – No unrestricted SSH/RDP IPv6
# ---------------------------------------------------------------------------

class TestCIS_6_4:
    @pytest.fixture
    def rule(self):
        return CIS_6_4()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_restricted(self, rule):
        finding = await rule.check(_aws(ec2_security_groups=[
            {
                "GroupId": "sg-001",
                "GroupName": "private",
                "Region": "us-east-1",
                "IpPermissions": [],
                "Ipv6Ranges": [],
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_unrestricted_ipv6_ssh(self, rule):
        finding = await rule.check(_aws(ec2_security_groups=[
            {
                "GroupId": "sg-001",
                "GroupName": "open",
                "Region": "us-east-1",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                     "IpRanges": [],
                     "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
                ],
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 6.5 – Default security group no rules
# ---------------------------------------------------------------------------

class TestCIS_6_5:
    @pytest.fixture
    def rule(self):
        return CIS_6_5()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_default_sg_empty(self, rule):
        finding = await rule.check(_aws(ec2_security_groups=[
            {
                "GroupId": "sg-default",
                "GroupName": "default",
                "Region": "us-east-1",
                "IpPermissions": [],
                "IpPermissionsEgress": [],
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_default_sg_has_rules(self, rule):
        finding = await rule.check(_aws(ec2_security_groups=[
            {
                "GroupId": "sg-default",
                "GroupName": "default",
                "Region": "us-east-1",
                "IpPermissions": [
                    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
                "IpPermissionsEgress": [],
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 6.6 – VPC peering does not allow unrestricted access (Manual)
# ---------------------------------------------------------------------------

class TestCIS_6_6:
    @pytest.fixture
    def rule(self):
        return CIS_6_6()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL


# ---------------------------------------------------------------------------
# 6.7 – EC2 uses IMDSv2
# ---------------------------------------------------------------------------

class TestCIS_6_7:
    @pytest.fixture
    def rule(self):
        return CIS_6_7()

    async def test_skip_when_no_data(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.SKIPPED

    async def test_pass_when_imdsv2_required(self, rule):
        finding = await rule.check(_aws(ec2_instances=[
            {
                "InstanceId": "i-001",
                "State": {"Name": "running"},
                "Region": "us-east-1",
                "MetadataOptions": {"HttpTokens": "required"},
            }
        ]))
        assert finding.status == FindingStatus.PASS

    async def test_fail_when_imdsv1_allowed(self, rule):
        finding = await rule.check(_aws(ec2_instances=[
            {
                "InstanceId": "i-001",
                "State": {"Name": "running"},
                "Region": "us-east-1",
                "MetadataOptions": {"HttpTokens": "optional"},
            }
        ]))
        assert finding.status == FindingStatus.FAIL


# ---------------------------------------------------------------------------
# 6.8 – Rotation for access keys (Manual)
# ---------------------------------------------------------------------------

class TestCIS_6_8:
    @pytest.fixture
    def rule(self):
        return CIS_6_8()

    async def test_always_manual(self, rule):
        finding = await rule.check(_aws())
        assert finding.status == FindingStatus.MANUAL
