"""
AWS data collector.

Fetches configuration snapshots from IAM, CloudTrail, S3, CloudWatch Logs,
CloudWatch Alarms, AWS Config, EC2, KMS, SNS, RDS, EFS, Security Hub,
IAM Access Analyzer, and related services using boto3.

Data keys (used by rules via ``CollectedData.get("<key>")``)
------------------------------------------------------------
IAM:
    "credential_report"         – list[dict] parsed from the IAM credential report CSV
    "password_policy"           – account password policy dict (or None if not set)
    "iam_account_summary"       – dict from GetAccountSummary
    "iam_users"                 – list of IAM user dicts (with attached/inline policies)
    "iam_virtual_mfa_devices"   – list of virtual MFA device dicts
    "iam_policies"              – list of customer-managed policy dicts with document
    "ssl_certificates"          – list of IAM server certificate metadata dicts
    "access_analyzers"          – {region: [analyzer_dicts]} from IAM Access Analyzer

CloudTrail:
    "cloudtrail_trails"         – list of trail dicts enriched with _status and
                                  _event_selectors keys

S3:
    "s3_bucket_acls"            – {bucket_name: acl_dict}
    "s3_bucket_policies"        – {bucket_name: policy_doc_or_None}  (CloudTrail buckets)
    "s3_bucket_logging"         – {bucket_name: logging_dict_or_None}
    "s3_all_bucket_policies"    – {bucket_name: policy_doc_or_None}  (all buckets)
    "s3_bucket_versioning"      – {bucket_name: versioning_config_dict}
    "s3_public_access_block"    – account-level S3 public access block config dict

CloudWatch Logs:
    "cloudwatch_metric_filters" – {log_group_name: [filter_dicts]}

CloudWatch Alarms:
    "cloudwatch_alarms"         – list of alarm dicts

AWS Config:
    "config_recorders"          – list of configuration recorder dicts
    "config_recorder_statuses"  – list of recorder status dicts

EC2 / VPC (all enabled regions):
    "ec2_security_groups"       – list of security group dicts (with Region key)
    "ec2_vpcs"                  – list of VPC dicts (with Region key)
    "ec2_flow_logs"             – list of flow log dicts
    "ec2_instances"             – list of EC2 instance dicts (with Region key)
    "ec2_route_tables"          – list of route table dicts (with Region key)
    "ec2_nacls"                 – list of Network ACL dicts (with Region key)
    "ebs_encryption_by_default" – {region: {"EbsEncryptionByDefault": bool}}

KMS:
    "kms_keys"                  – list of {KeyId, KeyArn, _detail, _rotation} dicts

SNS:
    "sns_subscriptions"         – {topic_arn: [subscription_dicts]}

RDS:
    "rds_instances"             – list of RDS DB instance dicts (with Region key)

EFS:
    "efs_file_systems"          – list of EFS file system dicts (with Region key)

Security Hub:
    "security_hub"              – Security Hub describe-hub response dict (or None)
"""

from __future__ import annotations

import csv
import io
import json
import logging
import time
from typing import Any

from sspm.providers.aws.auth import AWSAuth
from sspm.providers.base import CollectedData

log = logging.getLogger(__name__)


class AWSCollector:
    """Fetches AWS account configuration data for CIS benchmark evaluation."""

    def __init__(self, auth: AWSAuth) -> None:
        self._auth = auth
        self._data: dict[str, Any] = {}
        self._errors: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def collect(self, account_id: str) -> CollectedData:
        self._account_id = account_id
        self._collect_all()
        return CollectedData(
            provider="aws",
            target=account_id,
            data=self._data,
            errors=self._errors,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _store(self, key: str, value: Any) -> None:
        self._data[key] = value

    def _safe(self, key: str, fn) -> None:
        try:
            self._store(key, fn())
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not collect %r: %s", key, exc)
            self._errors[key] = str(exc)

    def _paginate(self, client, method: str, list_key: str, **kwargs) -> list:
        """Call a paginated boto3 method and collect all results."""
        results = []
        paginator = client.get_paginator(method)
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(list_key, []))
        return results

    # ------------------------------------------------------------------
    # Collection orchestration
    # ------------------------------------------------------------------

    def _collect_all(self) -> None:
        # ── Section 2: IAM ────────────────────────────────────────────
        log.info("[1/11] IAM – generating credential report …")
        self._safe("credential_report", self._get_credential_report)

        log.info("[1/11] IAM – password policy, account summary …")
        self._safe("password_policy", self._get_password_policy)
        self._safe("iam_account_summary", self._get_account_summary)

        log.info("[1/11] IAM – listing and enriching users …")
        self._safe("iam_users", self._get_iam_users)

        log.info("[1/11] IAM – MFA devices and customer policies …")
        self._safe("iam_virtual_mfa_devices", self._get_virtual_mfa_devices)
        self._safe("iam_policies", self._get_customer_managed_policies)

        log.info("[1/11] IAM – SSL certificates …")
        self._safe("ssl_certificates", self._get_ssl_certificates)

        log.info("[1/11] IAM Access Analyzer – per region …")
        self._safe("access_analyzers", self._get_access_analyzers)

        # ── Section 4: CloudTrail ─────────────────────────────────────
        log.info("[2/11] CloudTrail – describing trails and statuses …")
        self._safe("cloudtrail_trails", self._get_cloudtrail_trails)

        log.info("[2/11] S3 – checking CloudTrail bucket ACLs, policies, logging …")
        self._safe("s3_bucket_acls", self._get_s3_cloudtrail_bucket_acls)
        self._safe("s3_bucket_policies", self._get_s3_cloudtrail_bucket_policies)
        self._safe("s3_bucket_logging", self._get_s3_cloudtrail_bucket_logging)

        # ── Section 3: S3 (all buckets) ───────────────────────────────
        log.info("[3/11] S3 – all bucket policies and versioning …")
        self._safe("s3_all_bucket_policies", self._get_s3_all_bucket_policies)
        self._safe("s3_bucket_versioning", self._get_s3_bucket_versioning)
        self._safe("s3_public_access_block", self._get_s3_public_access_block)

        # ── Section 5: Monitoring ─────────────────────────────────────
        log.info("[4/11] CloudWatch – metric filters …")
        self._safe("cloudwatch_metric_filters", self._get_metric_filters)

        log.info("[4/11] CloudWatch – alarms …")
        self._safe("cloudwatch_alarms", self._get_cloudwatch_alarms)

        # ── Section 4 (Config) ────────────────────────────────────────
        log.info("[5/11] AWS Config – recorders …")
        self._safe("config_recorders", self._get_config_recorders)
        self._safe("config_recorder_statuses", self._get_config_recorder_statuses)

        # ── Section 6/2: EC2 / VPC (multi-region, single pass) ───────
        regions = self._get_regions()
        log.info("[6/11] EC2 – scanning %d region(s): %s", len(regions), ", ".join(regions))
        try:
            self._collect_ec2_regional()
        except Exception as exc:
            log.warning("EC2 regional collection failed: %s", exc)

        # ── Section 4: KMS ────────────────────────────────────────────
        log.info("[7/11] KMS – customer managed keys …")
        self._safe("kms_keys", self._get_kms_keys)

        # ── Section 5: SNS ────────────────────────────────────────────
        log.info("[8/11] SNS – subscriptions for alarm actions …")
        self._safe("sns_subscriptions", self._get_sns_subscriptions)

        # ── Section 3: RDS ────────────────────────────────────────────
        log.info("[9/11] RDS – DB instances (multi-region) …")
        self._safe("rds_instances", self._get_rds_instances)

        # ── Section 3: EFS ────────────────────────────────────────────
        log.info("[10/11] EFS – file systems (multi-region) …")
        self._safe("efs_file_systems", self._get_efs_file_systems)

        # ── Section 5: Security Hub ───────────────────────────────────
        log.info("[11/11] Security Hub – status …")
        self._safe("security_hub", self._get_security_hub)

        log.info("Data collection complete.")

    # ------------------------------------------------------------------
    # IAM collectors
    # ------------------------------------------------------------------

    def _get_credential_report(self) -> list[dict]:
        iam = self._auth.client("iam")
        for attempt in range(10):
            resp = iam.generate_credential_report()
            if resp.get("State") == "COMPLETE":
                break
            log.info("  IAM – credential report not ready yet (attempt %d/10), waiting 2s …", attempt + 1)
            time.sleep(2)
        report = iam.get_credential_report()
        content = report["Content"]
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)

    def _get_password_policy(self) -> dict | None:
        iam = self._auth.client("iam")
        try:
            resp = iam.get_account_password_policy()
            return resp.get("PasswordPolicy")
        except iam.exceptions.NoSuchEntityException:
            return None
        except Exception:
            try:
                # boto3 older versions
                from botocore.exceptions import ClientError
                raise
            except Exception:
                return None

    def _get_account_summary(self) -> dict:
        iam = self._auth.client("iam")
        resp = iam.get_account_summary()
        return resp.get("SummaryMap", {})

    def _get_iam_users(self) -> list[dict]:
        iam = self._auth.client("iam")
        users = self._paginate(iam, "list_users", "Users")
        log.info("  IAM – enriching %d user(s) (policies, groups, MFA) …", len(users))
        enriched = []
        for u in users:
            name = u["UserName"]
            try:
                attached = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
                inline = iam.list_user_policies(UserName=name).get("PolicyNames", [])
                groups = iam.list_groups_for_user(UserName=name).get("Groups", [])
                mfa_devs = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
            except Exception as exc:  # noqa: BLE001
                log.debug("Error fetching details for user %s: %s", name, exc)
                attached, inline, groups, mfa_devs = [], [], [], []
            enriched.append({
                **u,
                "_attached_policies": attached,
                "_inline_policies": inline,
                "_groups": groups,
                "_mfa_devices": mfa_devs,
            })
        return enriched

    def _get_virtual_mfa_devices(self) -> list[dict]:
        iam = self._auth.client("iam")
        return self._paginate(iam, "list_virtual_mfa_devices", "VirtualMFADevices",
                              AssignmentStatus="Any")

    def _get_ssl_certificates(self) -> list[dict]:
        """Return list of IAM server certificates with metadata."""
        iam = self._auth.client("iam")
        certs = self._paginate(iam, "list_server_certificates", "ServerCertificateMetadataList")
        return [{"ServerCertificateMetadata": c} for c in certs]

    def _get_access_analyzers(self) -> dict[str, list]:
        """Return {region: [analyzer_dicts]} for IAM Access Analyzer in each region."""
        result: dict[str, list] = {}
        for region in self._get_regions():
            try:
                client = self._auth.client("accessanalyzer", region=region)
                analyzers = self._paginate(client, "list_analyzers", "analyzers")
                result[region] = analyzers
            except Exception as exc:
                log.debug("Access Analyzer error in %s: %s", region, exc)
                result[region] = []
        return result

    def _get_customer_managed_policies(self) -> list[dict]:
        iam = self._auth.client("iam")
        policies = self._paginate(iam, "list_policies", "Policies", Scope="Local")
        log.info("  IAM – fetching documents for %d customer-managed policy/policies …", len(policies))
        enriched = []
        for p in policies:
            try:
                version_id = p["DefaultVersionId"]
                doc_resp = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=version_id)
                doc = doc_resp["PolicyVersion"].get("Document", {})
            except Exception as exc:  # noqa: BLE001
                log.debug("Error fetching policy version for %s: %s", p["Arn"], exc)
                doc = {}
            enriched.append({**p, "_document": doc})
        return enriched

    # ------------------------------------------------------------------
    # CloudTrail collectors
    # ------------------------------------------------------------------

    def _get_cloudtrail_trails(self) -> list[dict]:
        ct = self._auth.client("cloudtrail")
        resp = ct.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", [])
        enriched = []
        for trail in trails:
            name = trail.get("TrailARN") or trail.get("Name")
            try:
                status = ct.get_trail_status(Name=name)
                status.pop("ResponseMetadata", None)
            except Exception as exc:  # noqa: BLE001
                log.debug("Error fetching trail status for %s: %s", name, exc)
                status = {}
            try:
                selectors_resp = ct.get_event_selectors(TrailName=name)
                selectors = selectors_resp.get("EventSelectors", [])
            except Exception as exc:  # noqa: BLE001
                log.debug("Error fetching event selectors for %s: %s", name, exc)
                selectors = []
            enriched.append({
                **trail,
                "_status": status,
                "_event_selectors": selectors,
            })
        return enriched

    # ------------------------------------------------------------------
    # S3 collectors (for CloudTrail buckets)
    # ------------------------------------------------------------------

    def _cloudtrail_bucket_names(self) -> list[str]:
        trails = self._data.get("cloudtrail_trails", [])
        return list({t.get("S3BucketName") for t in trails if t.get("S3BucketName")})

    def _get_s3_cloudtrail_bucket_acls(self) -> dict[str, dict]:
        s3 = self._auth.client("s3")
        result: dict[str, dict] = {}
        for bucket in self._cloudtrail_bucket_names():
            try:
                result[bucket] = s3.get_bucket_acl(Bucket=bucket)
            except Exception as exc:  # noqa: BLE001
                log.debug("S3 ACL error for %s: %s", bucket, exc)
        return result

    def _get_s3_cloudtrail_bucket_policies(self) -> dict[str, dict | None]:
        s3 = self._auth.client("s3")
        result: dict[str, dict | None] = {}
        for bucket in self._cloudtrail_bucket_names():
            try:
                resp = s3.get_bucket_policy(Bucket=bucket)
                result[bucket] = json.loads(resp.get("Policy", "{}"))
            except s3.exceptions.from_code("NoSuchBucketPolicy") if hasattr(s3, "exceptions") else Exception:
                result[bucket] = None
            except Exception as exc:  # noqa: BLE001
                log.debug("S3 policy error for %s: %s", bucket, exc)
                result[bucket] = None
        return result

    def _get_s3_cloudtrail_bucket_logging(self) -> dict[str, dict | None]:
        s3 = self._auth.client("s3")
        result: dict[str, dict | None] = {}
        for bucket in self._cloudtrail_bucket_names():
            try:
                resp = s3.get_bucket_logging(Bucket=bucket)
                result[bucket] = resp.get("LoggingEnabled")
            except Exception as exc:  # noqa: BLE001
                log.debug("S3 logging error for %s: %s", bucket, exc)
                result[bucket] = None
        return result

    def _get_all_s3_bucket_names(self) -> list[str]:
        """Return names of all S3 buckets in the account."""
        s3 = self._auth.client("s3")
        resp = s3.list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]

    def _get_s3_all_bucket_policies(self) -> dict[str, dict | None]:
        """Return {bucket_name: policy_doc_or_None} for all S3 buckets."""
        s3 = self._auth.client("s3")
        result: dict[str, dict | None] = {}
        buckets = self._get_all_s3_bucket_names()
        log.info("  S3 – fetching policies for %d bucket(s) …", len(buckets))
        for bucket in buckets:
            try:
                resp = s3.get_bucket_policy(Bucket=bucket)
                result[bucket] = json.loads(resp.get("Policy", "{}"))
            except Exception as exc:  # noqa: BLE001
                err_code = getattr(getattr(exc, "response", {}).get("Error", {}), "get", lambda k, d=None: d)("Code", "")
                if hasattr(exc, "response") and exc.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
                    result[bucket] = None
                else:
                    log.debug("S3 all-buckets policy error for %s: %s", bucket, exc)
                    result[bucket] = None
        return result

    def _get_s3_bucket_versioning(self) -> dict[str, dict]:
        """Return {bucket_name: versioning_config} for all S3 buckets."""
        s3 = self._auth.client("s3")
        result: dict[str, dict] = {}
        buckets = self._get_all_s3_bucket_names()
        log.info("  S3 – fetching versioning for %d bucket(s) …", len(buckets))
        for bucket in buckets:
            try:
                resp = s3.get_bucket_versioning(Bucket=bucket)
                resp.pop("ResponseMetadata", None)
                result[bucket] = resp
            except Exception as exc:  # noqa: BLE001
                log.debug("S3 versioning error for %s: %s", bucket, exc)
                result[bucket] = {}
        return result

    def _get_s3_public_access_block(self) -> dict:
        """Return account-level S3 Block Public Access configuration."""
        s3control = self._auth.client("s3control")
        try:
            resp = s3control.get_public_access_block(AccountId=self._account_id)
            return resp.get("PublicAccessBlockConfiguration", {})
        except Exception as exc:  # noqa: BLE001
            log.debug("S3 public access block error: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # CloudWatch Logs – metric filters
    # ------------------------------------------------------------------

    def _get_metric_filters(self) -> dict[str, list]:
        """Return {log_group_name: [filter_dicts]} for all log groups."""
        logs = self._auth.client("logs")
        # Collect all metric filters
        filters = self._paginate(logs, "describe_metric_filters", "metricFilters")
        by_group: dict[str, list] = {}
        for f in filters:
            group = f.get("logGroupName", "")
            by_group.setdefault(group, []).append(f)
        return by_group

    # ------------------------------------------------------------------
    # CloudWatch alarms
    # ------------------------------------------------------------------

    def _get_cloudwatch_alarms(self) -> list[dict]:
        cw = self._auth.client("cloudwatch")
        return self._paginate(cw, "describe_alarms", "MetricAlarms")

    # ------------------------------------------------------------------
    # AWS Config
    # ------------------------------------------------------------------

    def _get_config_recorders(self) -> list[dict]:
        cfg = self._auth.client("config")
        resp = cfg.describe_configuration_recorders()
        return resp.get("ConfigurationRecorders", [])

    def _get_config_recorder_statuses(self) -> list[dict]:
        cfg = self._auth.client("config")
        resp = cfg.describe_configuration_recorder_status()
        return resp.get("ConfigurationRecordersStatus", [])

    # ------------------------------------------------------------------
    # EC2 / VPC (multi-region) — single pass through all regions
    # ------------------------------------------------------------------

    def _get_regions(self) -> list[str]:
        """Return enabled regions, cached for the lifetime of this collection run."""
        if not hasattr(self, "_cached_regions"):
            try:
                self._cached_regions = self._auth.list_regions()
            except Exception:
                self._cached_regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
        return self._cached_regions

    def _collect_ec2_regional(self) -> None:
        """
        Single pass through all enabled regions collecting all EC2/VPC data.
        Populates: ec2_security_groups, ec2_vpcs, ec2_flow_logs,
                   ec2_instances, ec2_route_tables, ec2_nacls,
                   ebs_encryption_by_default.
        """
        security_groups: list[dict] = []
        vpcs: list[dict] = []
        flow_logs: list[dict] = []
        instances: list[dict] = []
        route_tables: list[dict] = []
        nacls: list[dict] = []
        ebs_encryption: dict[str, dict] = {}

        for region in self._get_regions():
            log.info("  EC2 collecting region: %s …", region)
            try:
                ec2 = self._auth.client("ec2", region=region)

                try:
                    for page in ec2.get_paginator("describe_security_groups").paginate():
                        for sg in page.get("SecurityGroups", []):
                            security_groups.append({**sg, "Region": region})
                except Exception as exc:
                    log.debug("EC2 SG error in %s: %s", region, exc)

                try:
                    for page in ec2.get_paginator("describe_vpcs").paginate():
                        for vpc in page.get("Vpcs", []):
                            vpcs.append({**vpc, "Region": region})
                except Exception as exc:
                    log.debug("EC2 VPC error in %s: %s", region, exc)

                try:
                    for page in ec2.get_paginator("describe_flow_logs").paginate():
                        for fl in page.get("FlowLogs", []):
                            flow_logs.append({**fl, "Region": region})
                except Exception as exc:
                    log.debug("Flow log error in %s: %s", region, exc)

                try:
                    for page in ec2.get_paginator("describe_instances").paginate():
                        for reservation in page.get("Reservations", []):
                            for inst in reservation.get("Instances", []):
                                instances.append({**inst, "Region": region})
                except Exception as exc:
                    log.debug("EC2 instances error in %s: %s", region, exc)

                try:
                    for page in ec2.get_paginator("describe_route_tables").paginate():
                        for rt in page.get("RouteTables", []):
                            route_tables.append({**rt, "Region": region})
                except Exception as exc:
                    log.debug("Route table error in %s: %s", region, exc)

                try:
                    for page in ec2.get_paginator("describe_network_acls").paginate():
                        for nacl in page.get("NetworkAcls", []):
                            nacls.append({**nacl, "Region": region})
                except Exception as exc:
                    log.debug("NACL error in %s: %s", region, exc)

                try:
                    resp = ec2.get_ebs_encryption_by_default()
                    ebs_encryption[region] = {
                        "EbsEncryptionByDefault": resp.get("EbsEncryptionByDefault", False)
                    }
                except Exception as exc:
                    log.debug("EBS encryption by default error in %s: %s", region, exc)
                    ebs_encryption[region] = {"EbsEncryptionByDefault": False}

            except Exception as exc:
                log.debug("Could not connect to EC2 in region %s: %s", region, exc)

        self._store("ec2_security_groups", security_groups)
        self._store("ec2_vpcs", vpcs)
        self._store("ec2_flow_logs", flow_logs)
        self._store("ec2_instances", instances)
        self._store("ec2_route_tables", route_tables)
        self._store("ec2_nacls", nacls)
        self._store("ebs_encryption_by_default", ebs_encryption)
        log.info(
            "  EC2 done – %d SGs, %d VPCs, %d flow logs, %d instances, %d route tables, "
            "%d NACLs, %d regions EBS encryption checked",
            len(security_groups), len(vpcs), len(flow_logs), len(instances),
            len(route_tables), len(nacls), len(ebs_encryption),
        )

    # ------------------------------------------------------------------
    # KMS
    # ------------------------------------------------------------------

    def _get_kms_keys(self) -> list[dict]:
        kms = self._auth.client("kms")
        keys = self._paginate(kms, "list_keys", "Keys")
        enriched = []
        for k in keys:
            kid = k["KeyId"]
            try:
                detail = kms.describe_key(KeyId=kid)["KeyMetadata"]
            except Exception:
                detail = {}
            # Skip AWS-managed keys (we care about customer-managed)
            if detail.get("KeyManager") == "AWS":
                continue
            try:
                rotation = kms.get_key_rotation_status(KeyId=kid)
                rotation_enabled = rotation.get("KeyRotationEnabled", False)
            except Exception:
                rotation_enabled = None
            enriched.append({**k, "_detail": detail, "_rotation": rotation_enabled})
        return enriched

    # ------------------------------------------------------------------
    # SNS subscriptions
    # ------------------------------------------------------------------

    def _get_sns_subscriptions(self) -> dict[str, list]:
        """
        Collect subscriptions for all SNS topics referenced in CloudWatch alarm actions.
        Returns {topic_arn: [subscription_dicts]}.
        """
        sns = self._auth.client("sns")
        alarms = self._data.get("cloudwatch_alarms", [])
        topic_arns: set[str] = set()
        for alarm in alarms:
            for arn in alarm.get("AlarmActions", []):
                if arn.startswith("arn:aws:sns:"):
                    topic_arns.add(arn)

        result: dict[str, list] = {}
        for topic_arn in topic_arns:
            try:
                subs = self._paginate(sns, "list_subscriptions_by_topic",
                                      "Subscriptions", TopicArn=topic_arn)
                result[topic_arn] = subs
            except Exception as exc:  # noqa: BLE001
                log.debug("SNS subscriptions error for %s: %s", topic_arn, exc)
                result[topic_arn] = []
        return result

    # ------------------------------------------------------------------
    # RDS
    # ------------------------------------------------------------------

    def _get_rds_instances(self) -> list[dict]:
        """Return all RDS DB instances across all regions."""
        instances: list[dict] = []
        for region in self._get_regions():
            try:
                rds = self._auth.client("rds", region=region)
                for page in rds.get_paginator("describe_db_instances").paginate():
                    for inst in page.get("DBInstances", []):
                        instances.append({**inst, "Region": region})
            except Exception as exc:
                log.debug("RDS error in %s: %s", region, exc)
        log.info("  RDS done – %d instance(s) across all regions", len(instances))
        return instances

    # ------------------------------------------------------------------
    # EFS
    # ------------------------------------------------------------------

    def _get_efs_file_systems(self) -> list[dict]:
        """Return all EFS file systems across all regions."""
        file_systems: list[dict] = []
        for region in self._get_regions():
            try:
                efs = self._auth.client("efs", region=region)
                for page in efs.get_paginator("describe_file_systems").paginate():
                    for fs in page.get("FileSystems", []):
                        file_systems.append({**fs, "Region": region})
            except Exception as exc:
                log.debug("EFS error in %s: %s", region, exc)
        log.info("  EFS done – %d file system(s) across all regions", len(file_systems))
        return file_systems

    # ------------------------------------------------------------------
    # Security Hub
    # ------------------------------------------------------------------

    def _get_security_hub(self) -> dict | None:
        """Return Security Hub describe-hub response, or None if not enabled."""
        try:
            sh = self._auth.client("securityhub")
            resp = sh.describe_hub()
            resp.pop("ResponseMetadata", None)
            return resp
        except Exception as exc:
            # Security Hub raises an exception if not enabled
            log.debug("Security Hub not enabled or error: %s", exc)
            return {"HubArn": "", "_error": str(exc)}
