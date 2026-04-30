# AccuKnox SSPM – AWS Provider

Scan an **AWS account** against the **CIS Amazon Web Services Foundations Benchmark v7.0.0** using the `sspm scan aws` command.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Generating AWS Credentials](#generating-aws-credentials)
   - [Option A – IAM User with Long-term Credentials](#option-a--iam-user-with-long-term-credentials)
   - [Option B – IAM Role with Temporary Credentials (STS)](#option-b--iam-role-with-temporary-credentials-sts)
   - [Option C – AWS CLI Named Profile](#option-c--aws-cli-named-profile)
   - [Option D – Environment Variables / Instance Metadata](#option-d--environment-variables--instance-metadata)
3. [Required IAM Permissions](#required-iam-permissions)
4. [CLI Reference](#cli-reference)
5. [Usage Examples](#usage-examples)
6. [Output Files](#output-files)
7. [CIS Rules Coverage](#cis-rules-coverage)
8. [Security Recommendations](#security-recommendations)

---

## Prerequisites

- **Python 3.11+** and the `accuknox-sspm` package installed:
  ```bash
  pip install accuknox-sspm
  # or development install from source
  pip install -e .
  ```
- **boto3** is installed automatically as a dependency.
- An AWS account with the ability to create an **IAM user** or **IAM role** with read-only permissions.

---

## Generating AWS Credentials

The scanner is **read-only** — it never creates, modifies, or deletes AWS resources. Choose the credential method that best fits your environment.

---

### Option A – IAM User with Long-term Credentials

Best for: one-off scans, CI environments without instance roles.

#### Step 1 — Create a dedicated IAM user

1. Sign in to the **AWS Management Console**.
2. Navigate to **IAM → Users → Create user**.
3. Enter a username: `accuknox-sspm` (or any name you prefer).
4. On the **Set permissions** step, choose **Attach policies directly**.
5. Attach the managed policy `SecurityAudit` (covers most read-only APIs).
6. Also attach `ReadOnlyAccess` for broader coverage, or use the [custom policy](#required-iam-permissions) below for least privilege.
7. Complete the wizard and click **Create user**.

#### Step 2 — Create access keys

1. Click the newly created user → **Security credentials** tab.
2. Under **Access keys**, click **Create access key**.
3. Choose **Command Line Interface (CLI)** as the use case.
4. Click through the confirmation and click **Create access key**.
5. **Copy both values immediately** — the secret key is shown only once:
   - **Access key ID** → `--access-key-id`
   - **Secret access key** → `--secret-access-key`

> **Rotate access keys** at least every 90 days (also enforced by CIS rule 2.12).

---

### Option B – IAM Role with Temporary Credentials (STS)

Best for: cross-account scanning, CI/CD pipelines, least-privilege setups.

#### Step 1 — Create a scanner IAM role

1. Navigate to **IAM → Roles → Create role**.
2. Choose **AWS account** as the trusted entity type.
3. Enter the **account ID** that will assume this role (your CI/CD account or your own account ID).
4. (Optional) add an **External ID** for extra security when sharing the role with a third party.
5. Attach `SecurityAudit` (and optionally the [custom policy](#required-iam-permissions)).
6. Name the role `accuknox-sspm-scanner` and create it.
7. Note the **Role ARN** (e.g. `arn:aws:iam::123456789012:role/accuknox-sspm-scanner`).

#### Step 2 — Assume the role and export temporary credentials

```bash
# Assume the role via AWS CLI
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/accuknox-sspm-scanner \
  --role-session-name sspm-scan \
  --duration-seconds 3600

# The output contains:
# Credentials.AccessKeyId
# Credentials.SecretAccessKey
# Credentials.SessionToken

# Export them for use by sspm
export AWS_ACCESS_KEY_ID=<AccessKeyId>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
export AWS_SESSION_TOKEN=<SessionToken>

sspm scan aws --region us-east-1
```

Or pass them directly to the CLI:

```bash
sspm scan aws \
  --access-key-id     <AccessKeyId>    \
  --secret-access-key <SecretAccessKey> \
  --session-token     <SessionToken>   \
  --region us-east-1
```

---

### Option C – AWS CLI Named Profile

Best for: local workstation use; leverages your existing `~/.aws/credentials` setup.

#### Step 1 — Configure the AWS CLI (if not already done)

```bash
# Install the AWS CLI
pip install awscli

# Interactive setup — creates ~/.aws/credentials and ~/.aws/config
aws configure --profile sspm-scanner
# AWS Access Key ID [None]: <your-access-key-id>
# AWS Secret Access Key [None]: <your-secret-access-key>
# Default region name [None]: us-east-1
# Default output format [None]: json
```

The credentials are stored in `~/.aws/credentials`:

```ini
[sspm-scanner]
aws_access_key_id     = AKIA...
aws_secret_access_key = wJalr...
```

#### Step 2 — Use the profile with sspm

```bash
sspm scan aws --profile sspm-scanner --region us-east-1
```

#### Configuring a role-based profile

If you want the profile to assume a role automatically:

```ini
# ~/.aws/config
[profile sspm-scanner]
role_arn       = arn:aws:iam::123456789012:role/accuknox-sspm-scanner
source_profile = default
region         = us-east-1
```

```bash
sspm scan aws --profile sspm-scanner
```

---

### Option D – Environment Variables / Instance Metadata

Best for: AWS Lambda, EC2 with an instance role, ECS tasks, GitHub Actions with OIDC.

If `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (and optionally `AWS_SESSION_TOKEN`) are already set in the environment, or if the process is running on an EC2/ECS/Lambda instance with an attached IAM role, **no credential flags are required** — boto3 resolves them automatically via the [standard credential chain](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html).

```bash
# EC2 / ECS / Lambda — no credential flags needed
sspm scan aws --region us-east-1

# Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=wJalr...
export AWS_DEFAULT_REGION=us-east-1
sspm scan aws
```

---

## Required IAM Permissions

The scanner only makes **read and list** API calls. The AWS managed policy `SecurityAudit` covers most of them. If you prefer a minimal custom policy, attach the following:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SSPMAWSReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListUserPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:ListEntitiesForPolicy",
        "iam:ListRoles",
        "iam:ListInstanceProfiles",
        "iam:GetRole",
        "iam:ListServerCertificates",
        "iam:ListAccessKeys",
        "iam:GetLoginProfile",
        "access-analyzer:ListAnalyzers",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:ListTrails",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "logs:DescribeMetricFilters",
        "cloudwatch:DescribeAlarms",
        "sns:ListSubscriptionsByTopic",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels",
        "kms:ListKeys",
        "kms:GetKeyRotationStatus",
        "kms:DescribeKey",
        "kms:ListAliases",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeInstances",
        "ec2:DescribeEbsDefaultKmsKeyId",
        "ec2:GetEbsEncryptionByDefault",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeRouteTables",
        "rds:DescribeDBInstances",
        "elasticfilesystem:DescribeFileSystems",
        "securityhub:DescribeHub",
        "support:DescribeTrustedAdvisorChecks",
        "cloudfront:ListDistributions",
        "apigateway:GET",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "sts:GetCallerIdentity",
        "organizations:DescribeOrganization",
        "organizations:ListAccounts",
        "organizations:ListPolicies"
      ],
      "Resource": "*"
    }
  ]
}
```

> The `SecurityAudit` managed policy is broader but simpler to attach. Use the custom policy above for strict least-privilege environments.

---

## CLI Reference

```
sspm scan aws [OPTIONS]
```

| Option | Env Variable | Default | Description |
|--------|-------------|---------|-------------|
| `--access-key-id TEXT` | `AWS_ACCESS_KEY_ID` | — | AWS access key ID. If omitted, uses the standard credential chain (env vars, `~/.aws`, instance role). |
| `--secret-access-key TEXT` | `AWS_SECRET_ACCESS_KEY` | — | AWS secret access key. |
| `--session-token TEXT` | `AWS_SESSION_TOKEN` | — | STS session token (required when using temporary credentials). |
| `--profile TEXT` | `AWS_PROFILE` | — | Named AWS CLI profile from `~/.aws/credentials`. |
| `--region TEXT` | `AWS_DEFAULT_REGION` | `us-east-1` | Home region for global API calls (IAM, CloudTrail, STS). Multi-region data (EC2 SGs, VPCs) is collected from all enabled regions automatically. |
| `--account-alias TEXT` | `SSPM_AWS_ACCOUNT_ALIAS` | account ID | Human-readable label for the account used in report filenames and titles. |
| `--profile-filter TEXT` | — | — | Limit scan to a CIS profile: `"AWS Level 1"` or `"AWS Level 2"`. |
| `--rule TEXT` | — | — | Limit scan to one or more specific rule IDs (repeatable). |
| `--output TEXT / -o` | — | `sspm-aws-report` | Output file stem. Generates `<stem>.html` and `<stem>.sarif.json`. |
| `--no-html` | — | `false` | Skip HTML report generation. |
| `--no-sarif` | — | `false` | Skip SARIF report generation. |
| `--verbose / -v` | — | `false` | Print individual findings to the terminal during the scan. |

---

## Usage Examples

### Basic scan using an AWS CLI profile

```bash
sspm scan aws \
  --profile sspm-scanner \
  --region us-east-1
```

### Scan using explicit long-term credentials

```bash
sspm scan aws \
  --access-key-id     AKIAIOSFODNN7EXAMPLE        \
  --secret-access-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  --region us-east-1 \
  --account-alias my-prod-account \
  --output prod-cis-report \
  --verbose
```

### Scan using temporary STS credentials

```bash
# Assume role first
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/accuknox-sspm-scanner \
  --role-session-name sspm \
  --query Credentials \
  --output json)

sspm scan aws \
  --access-key-id     $(echo $CREDS | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['AccessKeyId'])") \
  --secret-access-key $(echo $CREDS | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['SecretAccessKey'])") \
  --session-token     $(echo $CREDS | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['SessionToken'])") \
  --region us-east-1
```

### Scan using environment variables (CI/CD)

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-east-1
export SSPM_AWS_ACCOUNT_ALIAS=staging

sspm scan aws --output staging-report
```

### Level 1 controls only

```bash
sspm scan aws \
  --profile sspm-scanner \
  --profile-filter "AWS Level 1" \
  --output l1-report
```

### Level 2 controls only

```bash
sspm scan aws \
  --profile sspm-scanner \
  --profile-filter "AWS Level 2" \
  --output l2-report
```

### Run a single rule

```bash
sspm scan aws \
  --profile sspm-scanner \
  --rule aws-cis-2.14
```

### Run multiple specific rules

```bash
sspm scan aws \
  --profile sspm-scanner \
  --rule aws-cis-2.4 \
  --rule aws-cis-2.5 \
  --rule aws-cis-2.10
```

### SARIF output only (skip HTML)

```bash
sspm scan aws \
  --profile sspm-scanner \
  --no-html \
  --output aws-sarif-only
```

### List all AWS rules (without scanning)

```bash
sspm rules list --provider aws
```

---

## Output Files

Running `sspm scan aws` produces two files by default (configurable with `--output`):

| File | Format | Description |
|------|--------|-------------|
| `sspm-aws-report.html` | HTML | Interactive report with a summary dashboard, per-rule findings, remediation steps, and evidence |
| `sspm-aws-report.sarif.json` | SARIF 2.1.0 | Machine-readable findings compatible with GitHub Advanced Security, VS Code SARIF Viewer, and any SARIF-aware toolchain |

### Generating a report from an existing SARIF file

```bash
# Re-render HTML from a saved SARIF file
sspm report html sspm-aws-report.sarif.json

# Print a summary table to the terminal
sspm report summary sspm-aws-report.sarif.json
```

### Finding statuses in the report

| Status | Meaning |
|--------|---------|
| `PASS` | Control is compliant |
| `FAIL` | Control is non-compliant; remediation required |
| `MANUAL` | Cannot be automated; human review required |
| `SKIPPED` | Prerequisites not met (e.g. CloudTrail not enabled) |
| `ERROR` | Unexpected error during rule evaluation |

---

## CIS Rules Coverage

**70 rules** across 5 sections of *CIS Amazon Web Services Foundations Benchmark v7.0.0*.

### Section 2 — Identity and Access Management (IAM)

#### 2.1 – AWS Organizations

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `aws-cis-2.1.1` | Ensure centralized root access in AWS Organizations | L2 | High | Manual |
| `aws-cis-2.1.2` | Ensure authorization guardrails for all AWS Organization accounts | L2 | High | Manual |
| `aws-cis-2.1.3` | Ensure Organizations management account is not used for workloads | L2 | High | Manual |
| `aws-cis-2.1.4` | Ensure Organizational Units are structured by environment and sensitivity | L2 | Medium | Manual |
| `aws-cis-2.1.5` | Ensure delegated admin manages AWS Organizations policies | L2 | Medium | Manual |
| `aws-cis-2.1.6` | Ensure delegated admins manage AWS Organizations-integrated services | L2 | Medium | Manual |

#### 2.2–2.21 – IAM

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `aws-cis-2.2` | Maintain current AWS account contact details | L1 | Medium | Manual |
| `aws-cis-2.3` | Ensure security contact information is registered | L1 | Medium | Manual |
| `aws-cis-2.4` | Ensure no 'root' user account access key exists | L1 | Critical | Auto |
| `aws-cis-2.5` | Ensure MFA is enabled for the 'root' user account | L1 | Critical | Auto |
| `aws-cis-2.6` | Ensure hardware MFA is enabled for the 'root' user account | L2 | High | Manual |
| `aws-cis-2.7` | Eliminate use of the 'root' user for administrative and daily tasks | L1 | High | Manual |
| `aws-cis-2.8` | Ensure IAM password policy requires minimum length of 14 or greater | L1 | Medium | Auto |
| `aws-cis-2.9` | Ensure IAM password policy prevents password reuse | L1 | Medium | Auto |
| `aws-cis-2.10` | Ensure MFA is enabled for all IAM users that have a console password | L1 | High | Auto |
| `aws-cis-2.11` | Ensure credentials unused for 45 days or more are disabled | L1 | High | Auto |
| `aws-cis-2.12` | Ensure access keys are rotated every 90 days or less | L1 | High | Auto |
| `aws-cis-2.13` | Ensure IAM users receive permissions only through groups | L1 | Medium | Auto |
| `aws-cis-2.14` | Ensure IAM policies that allow full `*:*` administrative privileges are not attached | L1 | Critical | Auto |
| `aws-cis-2.15` | Ensure a support role has been created to manage incidents with AWS Support | L1 | Medium | Auto |
| `aws-cis-2.16` | Ensure IAM instance roles are used for AWS resource access from instances | L2 | High | Auto |
| `aws-cis-2.17` | Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed | L1 | High | Auto |
| `aws-cis-2.18` | Ensure that IAM Access Analyzer is enabled for all regions | L1 | Medium | Auto |
| `aws-cis-2.19` | Ensure IAM users are managed centrally via identity federation or AWS Organizations | L2 | Medium | Manual |
| `aws-cis-2.20` | Ensure access to AWSCloudShellFullAccess is restricted | L1 | Medium | Manual |
| `aws-cis-2.21` | Ensure AWS resource policies do not allow unrestricted access using `Principal: '*'` | L1 | High | Manual |

### Section 3 — Storage

#### 3.1 – S3

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `aws-cis-3.1.1` | Ensure S3 Bucket Policy is set to deny HTTP requests | L2 | High | Auto |
| `aws-cis-3.1.2` | Ensure MFA Delete is enabled on S3 buckets | L2 | High | Manual |
| `aws-cis-3.1.3` | Ensure all data in Amazon S3 has been discovered, classified, and secured when necessary | L2 | Medium | Manual |
| `aws-cis-3.1.4` | Ensure that S3 is configured with 'Block Public Access' enabled | L1 | High | Auto |

#### 3.2 – RDS

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `aws-cis-3.2.1` | Ensure that encryption-at-rest is enabled for RDS instances | L1 | High | Auto |
| `aws-cis-3.2.2` | Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances | L1 | Medium | Auto |
| `aws-cis-3.2.3` | Ensure that RDS instances are not publicly accessible | L1 | High | Auto |
| `aws-cis-3.2.4` | Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS | L1 | Medium | Manual |

#### 3.3 – EFS

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `aws-cis-3.3.1` | Ensure that encryption is enabled for EFS file systems | L1 | High | Auto |

### Section 4 — Logging

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `aws-cis-4.1` | Ensure CloudTrail is enabled in all regions | L1 | High | Manual |
| `aws-cis-4.2` | Ensure CloudTrail log file validation is enabled | L2 | Medium | Auto |
| `aws-cis-4.3` | Ensure AWS Config is enabled in all regions | L2 | Medium | Auto |
| `aws-cis-4.4` | Ensure that server access logging is enabled on the CloudTrail S3 bucket | L1 | Medium | Manual |
| `aws-cis-4.5` | Ensure CloudTrail logs are encrypted at rest using KMS CMKs | L2 | Medium | Auto |
| `aws-cis-4.6` | Ensure rotation for customer-created symmetric CMKs is enabled | L2 | Medium | Auto |
| `aws-cis-4.7` | Ensure VPC flow logging is enabled in all VPCs | L2 | Medium | Auto |
| `aws-cis-4.8` | Ensure that object-level logging for write events is enabled for S3 buckets | L2 | Medium | Auto |
| `aws-cis-4.9` | Ensure that object-level logging for read events is enabled for S3 buckets | L2 | Medium | Auto |
| `aws-cis-4.10` | Ensure all AWS-managed web front-end services have access logging enabled | L1 | Medium | Manual |

### Section 5 — Monitoring

All monitoring rules (5.1–5.15) check the same chain:
**Active multi-region CloudTrail** → **CloudWatch Logs** → **Metric filter** → **CloudWatch alarm** → **SNS topic with active subscription**

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `aws-cis-5.1` | Ensure a log metric filter and alarm exist for unauthorized API calls | L2 | High | Manual |
| `aws-cis-5.2` | Ensure a log metric filter and alarm exist for Management Console sign-in without MFA | L1 | High | Manual |
| `aws-cis-5.3` | Ensure a log metric filter and alarm exist for usage of the "root" account | L1 | Critical | Manual |
| `aws-cis-5.4` | Ensure a log metric filter and alarm exist for IAM policy changes | L1 | Medium | Manual |
| `aws-cis-5.5` | Ensure a log metric filter and alarm exist for CloudTrail configuration changes | L1 | High | Manual |
| `aws-cis-5.6` | Ensure a log metric filter and alarm exist for AWS Management Console authentication failures | L2 | Medium | Manual |
| `aws-cis-5.7` | Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs | L2 | High | Manual |
| `aws-cis-5.8` | Ensure a log metric filter and alarm exist for S3 bucket policy changes | L1 | Medium | Manual |
| `aws-cis-5.9` | Ensure a log metric filter and alarm exist for AWS Config configuration changes | L2 | Medium | Manual |
| `aws-cis-5.10` | Ensure a log metric filter and alarm exist for security group changes | L2 | Medium | Manual |
| `aws-cis-5.11` | Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) | L2 | Medium | Manual |
| `aws-cis-5.12` | Ensure a log metric filter and alarm exist for changes to network gateways | L1 | Medium | Manual |
| `aws-cis-5.13` | Ensure a log metric filter and alarm exist for route table changes | L1 | Medium | Manual |
| `aws-cis-5.14` | Ensure a log metric filter and alarm exist for VPC changes | L1 | Medium | Manual |
| `aws-cis-5.15` | Ensure a log metric filter and alarm exist for AWS Organizations changes | L1 | High | Manual |
| `aws-cis-5.16` | Ensure AWS Security Hub is enabled | L2 | Medium | Auto |

### Section 6 — Networking

#### 6.1 – EC2 / EBS

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `aws-cis-6.1.1` | Ensure EBS volume encryption is enabled in all regions | L1 | High | Auto |
| `aws-cis-6.1.2` | Ensure CIFS access is restricted to trusted networks to prevent unauthorized access | L2 | High | Manual |

#### 6.2–6.8 – VPC / Security Groups

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `aws-cis-6.2` | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports | L1 | High | Auto |
| `aws-cis-6.3` | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports | L1 | High | Auto |
| `aws-cis-6.4` | Ensure no security groups allow ingress from ::/0 to remote server administration ports | L1 | High | Auto |
| `aws-cis-6.5` | Ensure the default security group of every VPC restricts all traffic | L2 | High | Auto |
| `aws-cis-6.6` | Ensure routing tables for VPC peering are 'least access' | L2 | Medium | Manual |
| `aws-cis-6.7` | Ensure that the EC2 Metadata Service only allows IMDSv2 | L1 | High | Auto |
| `aws-cis-6.8` | Ensure VPC Endpoints are used for access to AWS Services | L2 | Medium | Manual |

---

## Security Recommendations

- **Read-only permissions only.** The IAM user/role should have no `*:Write*`, `*:Create*`, `*:Delete*`, or `*:Put*` permissions. Use `SecurityAudit` or the [custom policy](#required-iam-permissions) above.

- **Do not use the root account.** Create a dedicated IAM user or role for scanning. Using root credentials is flagged by CIS rule 2.7 itself.

- **Prefer temporary credentials.** STS assume-role sessions expire automatically. They are safer than long-term IAM user access keys, especially in CI/CD pipelines.

- **Store credentials securely.**
  - Local use: `~/.aws/credentials` (mode `600`), never in source control.
  - CI/CD: use your platform's secrets manager (GitHub Actions secrets, GitLab CI variables, HashiCorp Vault).
  - Never hard-code credentials in scripts or commit them to git.

- **Rotate access keys regularly.** CIS rule 2.12 enforces a 90-day rotation period. Set a calendar reminder or automate rotation via AWS Secrets Manager.

- **Restrict by IP (optional).** Add an IAM condition to the scanner's policy to restrict credential use to your scanner's IP range:
  ```json
  {
    "Condition": {
      "IpAddress": {
        "aws:SourceIp": ["203.0.113.0/24"]
      }
    }
  }
  ```

- **Use a cross-account role for multi-account scanning.** Create the scanner role in each target account and assume it from a central "scanner" account rather than creating IAM users in every account.

- **Audit scanner activity.** The IAM user/role appears in CloudTrail logs. Review the `sspm-scanner` principal periodically for unexpected API calls.
