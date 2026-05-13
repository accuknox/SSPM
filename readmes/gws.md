# AccuKnox SSPM – Google Workspace Provider

Scan a **Google Workspace tenant** against the **CIS Google Workspace Foundations Benchmark v1.3.0** using the `sspm scan gws` command.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Setting Up Credentials](#setting-up-credentials)
   - [Step 1 – Create a Google Cloud Project](#step-1--create-a-google-cloud-project)
   - [Step 2 – Enable Required APIs](#step-2--enable-required-apis)
   - [Step 3 – Create a Service Account](#step-3--create-a-service-account)
   - [Step 4 – Download the Service Account Key](#step-4--download-the-service-account-key)
   - [Step 5 – Enable Domain-Wide Delegation](#step-5--enable-domain-wide-delegation)
   - [Step 6 – Authorize the Service Account in Google Workspace Admin](#step-6--authorize-the-service-account-in-google-workspace-admin)
   - [Step 7 – Verify Access](#step-7--verify-access)
3. [Required OAuth Scopes](#required-oauth-scopes)
4. [CLI Reference](#cli-reference)
5. [Usage Examples](#usage-examples)
6. [Output Files](#output-files)
7. [Security Recommendations](#security-recommendations)

---

## Prerequisites

- **Python 3.11+** and the `accuknox-sspm` package installed:
  ```bash
  pip install accuknox-sspm
  # or development install from source
  pip install -e .
  ```
- A **Google Workspace Super Administrator** account to authorize domain-wide delegation.
- A **Google Cloud project** (can be a free project — no billing required for the APIs used).
- The `cryptography` Python package (installed automatically as a dependency):
  ```bash
  pip install cryptography
  ```

---

## Setting Up Credentials

The scanner authenticates using a **Service Account with Domain-Wide Delegation (DWD)**. This allows the service account to impersonate Workspace users to read their Gmail settings — no user interaction or OAuth consent screen is shown.

---

### Step 1 – Create a Google Cloud Project

> Skip this step if you already have a Google Cloud project to use.

1. Go to the [Google Cloud Console](https://console.cloud.google.com).
2. Click the project selector at the top → **New Project**.
3. Enter a project name (e.g. `accuknox-sspm`) and click **Create**.
4. Make sure the new project is selected in the project selector.

---

### Step 2 – Enable Required APIs

The scanner uses several Google APIs that must be enabled in your Cloud project.

1. In the Cloud Console, navigate to **APIs & Services → Enable APIs and Services**.
2. Search for and enable each of the following APIs:

| API | Used for |
|-----|---------|
| **Admin SDK API** | Directory API (users, groups, org units, domains) |
| **Groups Settings API** | Group sharing and visibility settings |
| **Alert Center API** | Alert rules and security notifications |
| **Gmail API** | Per-user IMAP, POP, and auto-forwarding settings |

You can also enable them all at once via the Cloud Shell:

```bash
gcloud services enable \
  admin.googleapis.com \
  groupssettings.googleapis.com \
  alertcenter.googleapis.com \
  gmail.googleapis.com \
  --project YOUR_PROJECT_ID
```

---

### Step 3 – Create a Service Account

1. Navigate to **IAM & Admin → Service Accounts → Create Service Account**.
2. Fill in the details:
   - **Service account name**: `accuknox-sspm`
   - **Service account ID**: `accuknox-sspm` (auto-filled)
   - **Description**: AccuKnox SSPM scanner
3. Click **Create and Continue**.
4. Skip the optional role and user access steps — click **Done**.
5. Note the service account's **email address** (format: `accuknox-sspm@<project-id>.iam.gserviceaccount.com`).

---

### Step 4 – Download the Service Account Key

1. On the Service Accounts list, click the `accuknox-sspm` service account.
2. Go to the **Keys** tab → **Add Key → Create new key**.
3. Choose **JSON** format and click **Create**.
4. A JSON file is downloaded automatically — this is your **service account key file**.
5. Move it to a secure location:
   ```bash
   mv ~/Downloads/accuknox-sspm-*.json ~/.config/accuknox-sspm-key.json
   chmod 600 ~/.config/accuknox-sspm-key.json
   ```

> This key file grants access to your Workspace tenant. Treat it like a password — never commit it to source control.

---

### Step 5 – Enable Domain-Wide Delegation

1. On the service account detail page, click **Edit** (pencil icon).
2. Check the box **Enable G Suite Domain-wide Delegation**.
3. Enter a product name for the consent screen: `AccuKnox SSPM`.
4. Click **Save**.
5. Back on the service account detail page, click **View Client ID** and copy the numeric **Client ID** (e.g. `123456789012345678901`). You will need this in Step 6.

---

### Step 6 – Authorize the Service Account in Google Workspace Admin

This step grants the service account permission to act on behalf of users in your domain.

1. Sign in to the [Google Workspace Admin Console](https://admin.google.com) as a **Super Administrator**.
2. Navigate to **Security → Access and data control → API controls → Manage Domain-Wide Delegation**.
3. Click **Add new**.
4. Fill in the form:
   - **Client ID**: paste the numeric Client ID from Step 5
   - **OAuth Scopes**: paste all of the following scopes as a comma-separated list:
     ```
     https://www.googleapis.com/auth/admin.directory.user.readonly,
     https://www.googleapis.com/auth/admin.directory.domain.readonly,
     https://www.googleapis.com/auth/admin.directory.orgunit.readonly,
     https://www.googleapis.com/auth/admin.directory.group.readonly,
     https://www.googleapis.com/auth/admin.reports.audit.readonly,
     https://www.googleapis.com/auth/admin.reports.usage.readonly,
     https://www.googleapis.com/auth/apps.alerts,
     https://www.googleapis.com/auth/apps.groups.settings,
     https://www.googleapis.com/auth/gmail.settings.basic
     ```
5. Click **Authorize**.

> Changes may take up to a few minutes to propagate across Google's systems.

---

### Step 7 – Verify Access

Test that the service account can authenticate before running a full scan:

```bash
# Test using the sspm tool directly (dry run with a single rule)
sspm scan gws \
  --service-account-key ~/.config/accuknox-sspm-key.json \
  --admin-email admin@yourdomain.com \
  --customer-domain yourdomain.com \
  --rule gws-cis-1.1.1
```

If you see a scan result (PASS / FAIL / MANUAL) rather than an authentication error, the setup is complete.

---

## Required OAuth Scopes

All scopes below must be added to the Domain-Wide Delegation entry in the Google Workspace Admin Console.

| OAuth Scope | Purpose |
|-------------|---------|
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | List all user accounts |
| `https://www.googleapis.com/auth/admin.directory.domain.readonly` | List verified domains |
| `https://www.googleapis.com/auth/admin.directory.orgunit.readonly` | List organizational units |
| `https://www.googleapis.com/auth/admin.directory.group.readonly` | List groups |
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | Audit log access (Admin Reports API) |
| `https://www.googleapis.com/auth/admin.reports.usage.readonly` | Usage reports (Admin Reports API) |
| `https://www.googleapis.com/auth/apps.alerts` | Alert Center API — security alert rules |
| `https://www.googleapis.com/auth/apps.groups.settings` | Group sharing and security settings |
| `https://www.googleapis.com/auth/gmail.settings.basic` | Per-user Gmail IMAP, POP, and auto-forwarding settings (read-only, via DWD impersonation) |

> **Note:** Some controls (Google Calendar, Drive sharing, Gmail Safety/Spam/Compliance, and Chat settings) are not available through any public API. Rules for those controls return a `MANUAL` finding pointing the auditor to the Admin Console.

---

## CLI Reference

```
sspm scan gws [OPTIONS]
```

| Option | Env Variable | Required | Description |
|--------|-------------|----------|-------------|
| `--service-account-key PATH` | `SSPM_GWS_SA_KEY` | Yes | Path to the service account JSON key file downloaded in Step 4 |
| `--admin-email TEXT` | `SSPM_GWS_ADMIN_EMAIL` | Yes | Email of a Super Administrator account the service account will impersonate |
| `--customer-domain TEXT` | `SSPM_GWS_CUSTOMER_DOMAIN` | No | Primary domain of the Workspace tenant (e.g. `yourdomain.com`). Used as a label in reports |
| `--rule TEXT` | — | No | Limit scan to one or more specific rule IDs (repeatable) |
| `--output TEXT / -o` | — | No | Output file stem (default: `sspm-gws-report`). Generates `<stem>.html` and `<stem>.sarif.json` |
| `--no-html` | — | No | Skip HTML report generation |
| `--no-sarif` | — | No | Skip SARIF report generation |
| `--verbose / -v` | — | No | Print individual findings to the terminal during the scan |

---

## Usage Examples

### Basic scan with a key file

```bash
sspm scan gws \
  --service-account-key ~/.config/accuknox-sspm-key.json \
  --admin-email admin@yourdomain.com \
  --customer-domain yourdomain.com \
  --output gws-cis-report
```

### Scan using environment variables (CI/CD)

```bash
export SSPM_GWS_SA_KEY=/path/to/service-account-key.json
export SSPM_GWS_ADMIN_EMAIL=admin@yourdomain.com
export SSPM_GWS_CUSTOMER_DOMAIN=yourdomain.com

sspm scan gws --output gws-report --verbose
```

### Passing the key as a JSON string (useful in CI secrets)

```bash
# Store the entire JSON key content in a CI secret variable: GWS_KEY_JSON
echo "$GWS_KEY_JSON" > /tmp/gws-key.json
sspm scan gws \
  --service-account-key /tmp/gws-key.json \
  --admin-email admin@yourdomain.com
rm /tmp/gws-key.json
```

### Run a single rule

```bash
sspm scan gws \
  --service-account-key ~/.config/accuknox-sspm-key.json \
  --admin-email admin@yourdomain.com \
  --rule gws-cis-1.1.1
```

### SARIF output only

```bash
sspm scan gws \
  --service-account-key ~/.config/accuknox-sspm-key.json \
  --admin-email admin@yourdomain.com \
  --no-html \
  --output gws-sarif-only
```

### List all GWS rules (without scanning)

```bash
sspm rules list --provider gws
```

---

## Output Files

Running `sspm scan gws` produces two files by default:

| File | Format | Description |
|------|--------|-------------|
| `sspm-gws-report.html` | HTML | Interactive report with summary dashboard, per-rule findings, remediation steps, and evidence |
| `sspm-gws-report.sarif.json` | SARIF 2.1.0 | Machine-readable findings compatible with GitHub Advanced Security, VS Code SARIF Viewer, and any SARIF-aware toolchain |

### Finding statuses in the report

| Status | Meaning |
|--------|---------|
| `PASS` | Control is compliant |
| `FAIL` | Control is non-compliant; remediation required |
| `MANUAL` | Cannot be automated; human review required (Admin Console settings not accessible via API) |
| `SKIPPED` | Prerequisites not met |
| `ERROR` | Unexpected error during rule evaluation |

---

## Security Recommendations

- **Use a dedicated service account.** Create one specifically for scanning so it can be revoked independently without affecting other integrations.

- **Store the key file securely.**
  - Local use: `chmod 600 key.json`, never in source control.
  - CI/CD: store the JSON content as an encrypted secret variable, write it to a temp file during the job, and delete it after.

- **Rotate the service account key.** Google recommends rotating keys periodically. To rotate:
  1. Create a new key for the same service account.
  2. Update the scan configuration to use the new key.
  3. Delete the old key from the Cloud Console.

- **Limit the impersonated admin account.** The `--admin-email` should be a Super Administrator. Consider creating a dedicated admin account with the minimum required role (e.g. Groups Admin + User Management Admin + Reports Admin) rather than using your primary super admin account.

- **Review DWD grants periodically.** In the Workspace Admin Console → Security → API controls, review the list of apps with domain-wide delegation and remove any that are no longer needed.

- **Monitor service account usage.** Audit logs in the Cloud Console (IAM → Audit Logs) and Workspace Admin Console (Reports → Audit → Admin) show API calls made by the service account.
