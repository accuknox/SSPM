# AccuKnox SSPM – Azure Provider

Scan a **Microsoft Azure subscription** against the **CIS Microsoft Azure Foundations Benchmark v6.0.0** using the `sspm scan azure` command.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Setting Up Credentials](#setting-up-credentials)
   - [Step 1 – Create the App Registration](#step-1--create-the-app-registration)
   - [Step 2 – Create a Client Secret](#step-2--create-a-client-secret)
   - [Step 3 – Add Microsoft Graph API Permission](#step-3--add-microsoft-graph-api-permission)
   - [Step 4 – Grant Admin Consent](#step-4--grant-admin-consent)
   - [Step 5 – Assign Reader Role on the Subscription](#step-5--assign-reader-role-on-the-subscription)
   - [Step 6 – Collect the Subscription ID](#step-6--collect-the-subscription-id)
   - [Step 7 – Verify Access](#step-7--verify-access)
3. [Required Permissions Summary](#required-permissions-summary)
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
- `msal` and `httpx` are installed automatically as dependencies — no `azure-*` SDK required.
- An Azure account with:
  - Permission to create **App Registrations** in Microsoft Entra ID (Application Administrator or Global Administrator).
  - Permission to assign the **Reader** role on the target subscription (Owner or User Access Administrator on the subscription).
  - Permission to **grant admin consent** on Graph API permissions (Global Administrator).

---

## Setting Up Credentials

The scanner authenticates to both the **Azure Resource Manager (ARM) API** and **Microsoft Graph** using an Entra ID App Registration with app-only (client credentials) permissions.

---

### Step 1 – Create the App Registration

1. Sign in to **[portal.azure.com](https://portal.azure.com)**.
2. Search for **"App registrations"** in the top search bar → click it.
3. Click **"+ New registration"**.
4. Fill in the form:
   - **Name:** `accuknox-sspm` (or any descriptive name)
   - **Supported account types:** `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI:** leave blank
5. Click **Register**.
6. On the overview page, **copy and save**:
   - **Application (client) ID** → your `--client-id`
   - **Directory (tenant) ID** → your `--tenant-id`

---

### Step 2 – Create a Client Secret

1. In the app registration, left sidebar → **Certificates & secrets**.
2. Click **"+ New client secret"**.
3. Set:
   - **Description:** `sspm-scanner`
   - **Expires:** 12 months (or your organisation's policy)
4. Click **Add**.
5. **Immediately copy the `Value` column** — it is only shown once.
   - This is your `--client-secret`.

> **Tip:** For production use, prefer a **certificate** over a client secret.
> Upload a self-signed certificate under *Certificates & secrets → Certificates*
> and use it instead of a secret.

---

### Step 3 – Add Microsoft Graph API Permission

The scanner needs one Graph permission to check identity security policies (Section 5 rules).

1. Left sidebar → **API permissions**.
2. Click **"+ Add a permission"**.
3. Click **"Microsoft Graph"**.
4. Click **"Application permissions"** (not Delegated).
5. Search for `Policy.Read.All` → tick the checkbox.
6. Click **"Add permissions"**.

You will see it listed as **"Not granted for \<tenant\>"** — that is fixed in the next step.

---

### Step 4 – Grant Admin Consent

> A **Global Administrator** account is required for this step.

1. Still on the **API permissions** page.
2. Click **"Grant admin consent for \<your tenant name\>"**.
3. Click **Yes** in the confirmation dialog.
4. The status column should now show a **green checkmark** → `Granted for <tenant>`.

If you do not have Global Administrator access, ask your Azure AD admin to click **Grant admin consent** on your behalf.

---

### Step 5 – Assign Reader Role on the Subscription

1. Search for **"Subscriptions"** in the top Azure portal search bar → click it.
2. Click the subscription you want to scan.
3. Left sidebar → **Access control (IAM)**.
4. Click **"+ Add"** → **"Add role assignment"**.
5. **Role tab:**
   - Search for `Reader` → select it → click **Next**.
6. **Members tab:**
   - **Assign access to:** `User, group, or service principal`
   - Click **"+ Select members"**
   - Search for `accuknox-sspm` (the app name from Step 1)
   - Click on it → click **Select**
   - Click **Next**.
7. **Review + assign tab:** click **"Review + assign"**.

The `Reader` role grants read access to all resource metadata needed for the CIS benchmark checks.

---

### Step 6 – Collect the Subscription ID

1. Still on the subscription page → **Overview**.
2. Copy the **Subscription ID** field.
   - This is your `--subscription-id`.

Or via Azure CLI:

```bash
az account show --query id -o tsv
```

---

### Step 7 – Verify Access

Run these two curl commands to confirm both tokens are issued successfully before running the full scan:

```bash
# Test ARM token (Reader access to subscription)
curl -s -X POST \
  "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_secret=<CLIENT_SECRET>" \
  -d "scope=https://management.azure.com/.default" \
  | python3 -m json.tool | grep -E "access_token|error"

# Test Graph token (Policy.Read.All)
curl -s -X POST \
  "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_secret=<CLIENT_SECRET>" \
  -d "scope=https://graph.microsoft.com/.default" \
  | python3 -m json.tool | grep -E "access_token|error"
```

Both responses should contain `"access_token": "eyJ..."`. If you see `"error"`, recheck Steps 1–5.

---

## Required Permissions Summary

| Layer | Permission | Purpose |
|-------|-----------|---------|
| **Azure RBAC** | `Reader` (on the subscription) | All ARM API calls — storage, NSGs, Key Vaults, network watchers, Defender, Bastion, role assignments, diagnostic settings, etc. |
| **Microsoft Graph** | `Policy.Read.All` (Application) | Section 5 identity rules — reads `/policies/identitySecurityDefaultsEnforcementPolicy` |

### Values you need

| Value | Where to find it | CLI flag / env var |
|-------|-----------------|-------------------|
| Tenant ID | Entra app overview → Directory (tenant) ID | `--tenant-id` / `AZURE_TENANT_ID` |
| Client ID | Entra app overview → Application (client) ID | `--client-id` / `AZURE_CLIENT_ID` |
| Client Secret | Step 2 — Certificates & secrets (copy immediately) | `--client-secret` / `AZURE_CLIENT_SECRET` |
| Subscription ID | Step 6 — Subscription overview | `--subscription-id` / `AZURE_SUBSCRIPTION_ID` |

---

## CLI Reference

```
sspm scan azure [OPTIONS]
```

| Option | Env Variable | Default | Description |
|--------|-------------|---------|-------------|
| `--tenant-id TEXT` | `AZURE_TENANT_ID` | **required** | Microsoft Entra tenant ID (GUID). |
| `--client-id TEXT` | `AZURE_CLIENT_ID` | **required** | App registration client ID (GUID). |
| `--client-secret TEXT` | `AZURE_CLIENT_SECRET` | **required** | App registration client secret value. |
| `--subscription-id TEXT` | `AZURE_SUBSCRIPTION_ID` | **required** | Azure subscription ID to scan. |
| `--subscription-label TEXT` | `SSPM_AZURE_SUBSCRIPTION_LABEL` | subscription ID | Human-readable label used in report titles and filenames. |
| `--profile TEXT` | — | — | Limit scan to a CIS profile: `"Azure Level 1"` or `"Azure Level 2"`. |
| `--rule TEXT` | — | — | Limit scan to one or more specific rule IDs (repeatable). |
| `--output TEXT / -o` | — | `sspm-azure-report` | Output file stem. Generates `<stem>.html` and `<stem>.sarif.json`. |
| `--no-html` | — | `false` | Skip HTML report generation. |
| `--no-sarif` | — | `false` | Skip SARIF report generation. |
| `--verbose / -v` | — | `false` | Print individual findings to the terminal during the scan. |

---

## Usage Examples

### Basic scan using CLI flags

```bash
sspm scan azure \
  --tenant-id       xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --client-id       yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy \
  --client-secret   "your-secret-value"                  \
  --subscription-id zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz \
  --subscription-label prod-subscription                  \
  --output azure-cis-report                              \
  --verbose
```

### Scan using environment variables (recommended for CI/CD)

```bash
export AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_CLIENT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
export AZURE_CLIENT_SECRET="your-secret-value"
export AZURE_SUBSCRIPTION_ID=zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz
export SSPM_AZURE_SUBSCRIPTION_LABEL=prod-subscription

sspm scan azure --output azure-cis-report --verbose
```

### Level 1 controls only

```bash
sspm scan azure \
  --tenant-id <TENANT_ID> --client-id <CLIENT_ID> \
  --client-secret <SECRET> --subscription-id <SUB_ID> \
  --profile "Azure Level 1" \
  --output azure-l1-report
```

### Level 2 controls only

```bash
sspm scan azure \
  --tenant-id <TENANT_ID> --client-id <CLIENT_ID> \
  --client-secret <SECRET> --subscription-id <SUB_ID> \
  --profile "Azure Level 2" \
  --output azure-l2-report
```

### Run a single rule

```bash
sspm scan azure \
  --tenant-id <TENANT_ID> --client-id <CLIENT_ID> \
  --client-secret <SECRET> --subscription-id <SUB_ID> \
  --rule azure-cis-7.1
```

### Run multiple specific rules

```bash
sspm scan azure \
  --tenant-id <TENANT_ID> --client-id <CLIENT_ID> \
  --client-secret <SECRET> --subscription-id <SUB_ID> \
  --rule azure-cis-7.1 \
  --rule azure-cis-7.2 \
  --rule azure-cis-9.3.4
```

### SARIF output only (skip HTML)

```bash
sspm scan azure \
  --tenant-id <TENANT_ID> --client-id <CLIENT_ID> \
  --client-secret <SECRET> --subscription-id <SUB_ID> \
  --no-html \
  --output azure-sarif-only
```

### List all Azure rules (without scanning)

```bash
sspm rules list --provider azure
```

---

## Output Files

Running `sspm scan azure` produces two files by default (configurable with `--output`):

| File | Format | Description |
|------|--------|-------------|
| `sspm-azure-report.html` | HTML | Interactive report with a summary dashboard, per-rule findings, remediation steps, and evidence |
| `sspm-azure-report.sarif.json` | SARIF 2.1.0 | Machine-readable findings compatible with GitHub Advanced Security, VS Code SARIF Viewer, and any SARIF-aware toolchain |

### Generating a report from an existing SARIF file

```bash
# Re-render HTML from a saved SARIF file
sspm report html sspm-azure-report.sarif.json

# Print a summary table to the terminal
sspm report summary sspm-azure-report.sarif.json
```

### Finding statuses in the report

| Status | Meaning |
|--------|---------|
| `PASS` | Control is compliant |
| `FAIL` | Control is non-compliant; remediation required |
| `MANUAL` | Cannot be automated; human review required |
| `SKIPPED` | Prerequisites not met (e.g. no Key Vaults in subscription) |
| `ERROR` | Unexpected error during rule evaluation |

---

## CIS Rules Coverage

**27 rules** across 5 sections of *CIS Microsoft Azure Foundations Benchmark v6.0.0*.

### Section 5 — Identity Services

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `azure-cis-5.1.1` | Ensure that 'Security Defaults' is Enabled in Microsoft Entra ID | L1 | High | Auto |
| `azure-cis-5.1.3` | Ensure that 'Multifactor Authentication' is 'Enabled' for All Users | L1 | High | Manual |
| `azure-cis-5.3.3` | Ensure That Use of the 'User Access Administrator' Role is Restricted | L1 | Medium | Auto |
| `azure-cis-5.4` | Ensure that No Custom Subscription Administrator Roles Exist | L1 | Medium | Auto |
| `azure-cis-5.7` | Ensure there are between 2 and 3 Subscription Owners | L1 | Medium | Auto |

### Section 6 — Management and Governance

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `azure-cis-6.1.1.1` | Ensure that a 'Diagnostic Setting' Exists for Subscription Activity Logs | L1 | Medium | Auto |
| `azure-cis-6.1.1.4` | Ensure that Logging for Azure Key Vault is 'Enabled' | L1 | High | Auto |

### Section 7 — Networking Services

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `azure-cis-7.1` | Ensure that RDP Access from the Internet is Evaluated and Restricted | L1 | High | Auto |
| `azure-cis-7.2` | Ensure that SSH Access from the Internet is Evaluated and Restricted | L1 | High | Auto |
| `azure-cis-7.5` | Ensure that NSG Flow Log Retention is Greater than or Equal to 90 Days | L2 | Medium | Auto |
| `azure-cis-7.6` | Ensure that Network Watcher is 'Enabled' for Azure Regions That are in Use | L1 | Medium | Auto |

### Section 8 — Security Services

#### 8.1 Microsoft Defender for Cloud

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `azure-cis-8.1.1.1` | Ensure that Microsoft Defender for Cloud CSPM Plan is Set to 'On' | L2 | Medium | Auto |
| `azure-cis-8.1.3.1` | Ensure that Microsoft Defender for Servers is Set to 'On' | L2 | Medium | Auto |
| `azure-cis-8.1.13` | Ensure 'Additional email addresses' is Configured with a Security Contact Email | L1 | Medium | Auto |

#### 8.3 Key Vault

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `azure-cis-8.3.5` | Ensure the Key Vault is Recoverable (Soft Delete + Purge Protection) | L1 | High | Auto |
| `azure-cis-8.3.6` | Enable Role Based Access Control for Azure Key Vault | L2 | Medium | Auto |
| `azure-cis-8.3.7` | Ensure that Public Network Access is Disabled for Azure Key Vault | L2 | High | Auto |

#### 8.4 Azure Bastion

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `azure-cis-8.4.1` | Ensure an Azure Bastion Host Exists | L2 | Medium | Auto |

### Section 9 — Storage Services

#### 9.1 Azure Files

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `azure-cis-9.1.1` | Ensure that 'Soft Delete' is Enabled for Azure File Shares | L1 | Medium | Auto |

#### 9.2 Azure Blob Storage

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `azure-cis-9.2.1` | Ensure Soft Delete for Blobs is Enabled on Storage Accounts | L1 | Medium | Auto |

#### 9.3 Storage Accounts

| Rule ID | Title | Level | Severity | Type |
|---------|-------|-------|----------|------|
| `azure-cis-9.3.1.3` | Ensure that 'Allow storage account key access' is Disabled | L1 | High | Auto |
| `azure-cis-9.3.2.2` | Ensure that 'Public Network Access' is Disabled for Storage Accounts | L1 | High | Auto |
| `azure-cis-9.3.2.3` | Ensure Default Network Access Rule for Storage Accounts is Set to Deny | L1 | High | Auto |
| `azure-cis-9.3.4` | Ensure 'Secure transfer required' is Set to 'Enabled' | L1 | High | Auto |
| `azure-cis-9.3.6` | Ensure the Minimum TLS Version for Storage Accounts is Set to TLS 1.2 | L1 | Medium | Auto |
| `azure-cis-9.3.7` | Ensure 'Cross Tenant Replication' on Storage Accounts is Disabled | L1 | Medium | Auto |
| `azure-cis-9.3.8` | Ensure that 'Allow Blob Anonymous Access' is Set to 'Disabled' | L1 | High | Auto |

---

## Security Recommendations

- **Read-only permissions only.** The app registration should only have `Reader` on the subscription and `Policy.Read.All` on Graph. Never grant any write or modify permissions — the scanner is entirely read-only.

- **Single-tenant app registration.** Keep *Supported account types* as `Accounts in this organizational directory only`. Multi-tenant registrations expand the authentication surface unnecessarily.

- **Rotate the client secret before expiry.** Set a calendar reminder at 11 months if you chose a 12-month expiry. Secrets that expire silently break scheduled scans.

- **Store credentials securely.**
  - Local use: export env vars in your shell session or use a `.env` file with `chmod 600`; never commit credentials to source control.
  - CI/CD: use your platform's secrets manager (GitHub Actions secrets, GitLab CI variables, Azure Key Vault + OIDC, HashiCorp Vault).

- **Prefer OIDC / Federated Identity over client secrets (CI/CD).** For GitHub Actions or Azure Pipelines, configure a Federated Identity Credential on the app registration. This eliminates the need to store any secret at all:
  1. App registration → **Certificates & secrets → Federated credentials → Add credential**.
  2. Choose your OIDC provider (GitHub Actions, Kubernetes, etc.) and configure the subject claim.
  3. In your pipeline, use `azure/login` with `client-id`, `tenant-id`, `subscription-id` — no secret required.

- **Restrict token issuance by IP (optional).** Use Conditional Access → Named Locations and a service-principal-targeted policy to restrict where the app can acquire tokens:
  - Entra admin center → **Protection → Conditional Access → Named locations** → add your scanner's IP range.
  - Create a CA policy targeting the `accuknox-sspm` service principal with the location condition.

- **Audit scanner activity.** The app registration appears in **Entra ID sign-in logs** (non-interactive sign-ins). Review it periodically for unexpected token issuances or access patterns.

- **Limit scope to one subscription at a time.** Assign `Reader` only on the specific subscription being scanned, not at the management-group or tenant root scope, to minimise blast radius if credentials are compromised.
