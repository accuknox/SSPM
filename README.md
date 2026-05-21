# AccuKnox SSPM

**SaaS Security Posture Management** – automated security posture scanning for
popular SaaS platforms against industry-standard benchmarks (CIS, NIST, etc.).

Initial targets:
- **Microsoft 365** against *CIS Microsoft 365 Foundations Benchmark v6.0.1*
- **Google Workspace** against *CIS Google Workspace Foundations Benchmark v1.3.0*
- **AWS** against *CIS AWS Foundations Benchmark v1.2.0*
- **Microsoft Azure** against *CIS Microsoft Azure Foundations Benchmark v6.0.0*

Output: **SARIF 2.1.0** JSON, compatible with GitHub Advanced Security,
Azure DevOps, VS Code (SARIF Viewer), and any SARIF-aware toolchain.

---

## Architecture

### Core Abstractions

```
SaaS Platform ──► BaseProvider.collect() ──► CollectedData
                                                    │
                                    ┌───────────────┼───────────────┐
                                    ▼               ▼               ▼
                               Rule.check()   Rule.check()   Rule.check()
                                    │               │               │
                                    └───────────────┼───────────────┘
                                                    ▼
                                              ScanResult
                                                    │
                                            SarifReporter
                                                    │
                                          report.sarif.json
```

| Component | Responsibility |
|-----------|----------------|
| `BaseProvider` | Authenticate and collect all configuration data from a SaaS platform in one pass |
| `CollectedData` | Immutable snapshot of the target's configuration, keyed by data-source name |
| `BaseRule` | Evaluate one security control against `CollectedData`, return a `Finding` |
| `ScanEngine` | Orchestrate collection + rule evaluation, build `ScanResult` |
| `RuleRegistry` | Self-registration and auto-discovery of rule classes |
| `reporter.to_sarif()` | Convert `ScanResult` → SARIF 2.1.0 document |

### Rule Structure

Every rule is a Python class that:
1. Inherits from `MS365Rule` or `GWSRule` (both inherit `BaseRule`)
2. Defines a `metadata: RuleMetadata` class attribute capturing all CIS fields
3. Implements `async def check(self, data: CollectedData) -> Finding`
4. Calls `@registry.rule` decorator to self-register

**Finding statuses:**

| Status | Meaning | SARIF `kind` |
|--------|---------|--------------|
| `PASS` | Control is compliant | `pass` |
| `FAIL` | Control is non-compliant | `fail` |
| `MANUAL` | Cannot be automated; human review required | `open` |
| `ERROR` | Rule evaluation raised an unexpected exception | `review` |
| `SKIPPED` | Prerequisites not met (missing data / license) | `none` |

### RuleMetadata Fields

Mirrors the CIS benchmark *Recommendation Definition* structure:

```python
RuleMetadata(
    id          = "ms365-cis-1.1.1",       # Unique rule identifier
    title       = "...",                    # Short title
    section     = "1.1 Users",             # Benchmark section
    benchmark   = "CIS MS365 v6.0.1",
    assessment_status = AssessmentStatus.AUTOMATED,  # or MANUAL
    profiles    = [CISProfile.E3_L1, CISProfile.E5_L1],
    severity    = Severity.HIGH,
    description = "...",
    rationale   = "...",
    impact      = "...",
    audit_procedure  = "...",
    remediation      = "...",
    default_value    = "...",
    references       = ["https://..."],
    cis_controls     = [CISControl(version="v8", control_id="5.4", ...)],
    tags             = ["identity", "admin"],
)
```

---

## Microsoft 365 Coverage

The MS365 provider targets *CIS Microsoft 365 Foundations Benchmark v6.0.1*
across all 9 admin center sections:

| Section | Admin Center | Controls |
|---------|-------------|---------|
| 1 | Microsoft 365 admin center | Users, Groups, Settings |
| 2 | Microsoft 365 Defender | Email & collaboration, System |
| 3 | Microsoft Purview | Audit, DLP, Information Protection |
| 4 | Microsoft Intune | Device compliance, Enrollment |
| 5 | Microsoft Entra ID | Users, Devices, CA, MFA, ID Governance |
| 6 | Exchange admin center | Audit, Mail flow, Settings |
| 7 | SharePoint admin center | Policies, Settings |
| 8 | Microsoft Teams | Meetings, Messaging, Users |
| 9 | Microsoft Fabric | Tenant settings |

### Setting Up Credentials for Scanning

The scanner authenticates to Microsoft Graph using an **Entra ID App
Registration** with app-only (client credentials) permissions.  A
**Global Administrator** or **Privileged Role Administrator** must complete
the one-time setup below.

---

#### Step 1 — Create the App Registration

1. Sign in to the **Microsoft Entra admin center**: <https://entra.microsoft.com>
2. Navigate to **Identity → Applications → App registrations**.
3. Click **New registration**.
4. Fill in the form:
   - **Name:** `accuknox-sspm` (or any descriptive name)
   - **Supported account types:** *Accounts in this organizational directory only
     (Single tenant)*
   - **Redirect URI:** leave blank
5. Click **Register**.
6. On the overview page, copy and save:
   - **Application (client) ID** → this is your `--client-id`
   - **Directory (tenant) ID** → this is your `--tenant-id`

---

#### Step 2 — Create a Client Secret

1. In the app registration, go to **Certificates & secrets →
   Client secrets**.
2. Click **New client secret**.
3. Set a **Description** (e.g. `sspm-scanner`) and choose an **Expiry**
   (recommended: 12 months; rotate before expiry).
4. Click **Add**.
5. **Immediately copy the secret `Value`** — it is only shown once.
   This is your `--client-secret`.

> **Tip:** For production use, prefer a **certificate** over a client
> secret.  Upload a self-signed certificate under *Certificates & secrets →
> Certificates* and pass the `.pem` path instead of a secret.

---

#### Step 3 — Grant Microsoft Graph API Permissions

1. In the app registration, go to **API permissions → Add a permission →
   Microsoft Graph → Application permissions**.
2. Search for and add **each** of the following permissions:

   | Permission | Purpose |
   |-----------|---------|
   | `User.Read.All` | Read all user accounts and properties |
   | `RoleManagement.Read.Directory` | Read directory role assignments |
   | `Policy.Read.All` | Read Conditional Access and other policies |
   | `Directory.Read.All` | Read directory objects (groups, devices, apps) |
   | `Reports.Read.All` | Read usage and activity reports |
   | `SecurityEvents.Read.All` | Read Defender secure score and security data |
   | `Organization.Read.All` | Read tenant organisation settings and domains |
   | `Application.Read.All` | Read registered applications and service principals |
   | `AuditLog.Read.All` | Read Entra ID sign-in and audit logs |
   | `DeviceManagementConfiguration.Read.All` | Read Intune device compliance policies |
   | `DeviceManagementServiceConfig.Read.All` | Read Intune enrollment restrictions |
   | `InformationProtectionPolicy.Read.All` | Read Purview sensitivity labels and DLP |
   | `SharePointTenantSettings.Read.All` | Read SharePoint tenant-level sharing settings |
   | `AccessReview.Read.All` | Read Identity Governance access review definitions |
   | `RoleManagementPolicy.Read.Directory` | Read PIM role management policies |

3. Click **Add permissions** after selecting all of the above.
4. Click **Grant admin consent for \<your tenant\>**, then confirm.  
   All permissions should show a green **Granted** status.

---

#### Step 4 — Record Your Tenant Domain

Find your primary tenant domain:

- **Microsoft 365 admin center** → Settings → Domains, **or**
- **Entra admin center** → Identity → Overview (shown as *Primary domain*).

It typically looks like `contoso.onmicrosoft.com` or `contoso.com`.  
This is your `--tenant-domain`.

---

#### Step 5 — Verify Credential Access (optional)

Test that the credentials work before running a full scan:

```bash
# Quick test: fetch the tenant organisation object
curl -s -X POST \
  "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_secret=<CLIENT_SECRET>" \
  -d "scope=https://graph.microsoft.com/.default" \
  | python3 -m json.tool | grep -E "access_token|error"
```

A response containing `"access_token"` confirms the credentials are valid.

---

#### Summary: Values You Need

| Value | Where to find it | CLI flag / env var |
|-------|-----------------|-------------------|
| Tenant ID | Entra app overview → Directory (tenant) ID | `--tenant-id` / `SSPM_TENANT_ID` |
| Client ID | Entra app overview → Application (client) ID | `--client-id` / `SSPM_CLIENT_ID` |
| Client Secret | Created in Step 2 (copy immediately) | `--client-secret` / `SSPM_CLIENT_SECRET` |
| Tenant Domain | Primary domain from Step 4 | `--tenant-domain` / `SSPM_TENANT_DOMAIN` |

---

#### Security Recommendations for the App Registration

- **Principle of least privilege:** only grant the permissions listed above.
  Do not add `*.Write` or `*.ReadWrite` permissions — the scanner is read-only.
- **Restrict to your tenant:** keep *Supported account types* as single-tenant.
- **Rotate the client secret** before expiry; set a calendar reminder.
- **Audit usage:** the app registration appears in Entra ID sign-in logs.
  Review it periodically for unexpected activity.
- **Consider IP restriction:** use Conditional Access *Named Locations* and
  a service principal policy to restrict token issuance to your scanner's
  IP range.

---

> **Note:** Exchange Online and SharePoint Online controls that require
> PowerShell modules (EXO, PnP, Teams) return `MANUAL` or `SKIPPED`
> findings when Graph API equivalents are unavailable.

---

## Google Workspace Coverage

The GWS provider targets *CIS Google Workspace Foundations Benchmark v1.3.0*:

| Section | Area | Automated | Manual |
|---------|------|-----------|--------|
| 1 | Account / Admin Settings | Super admin count, 2SV enrollment & enforcement | Admin account hygiene, directory sharing |
| 3.1.1 | Calendar | — | 6 controls |
| 3.1.2 | Drive & Docs | — | 13 controls |
| 3.1.3 | Gmail | SPF, DKIM, DMARC (DNS); IMAP/POP per-user; auto-forwarding per-user | Attachment safety, link protection, spoofing, TLS, compliance |
| 3.1.4 | Google Chat | — | File sharing, external access, webhooks |
| 3.1.6 | Groups for Business | Group external visibility & membership access | — |

### Setting Up Credentials for Scanning

The scanner authenticates using a **Google Service Account** with
**Domain-Wide Delegation (DWD)** enabled.  A **Super Administrator** must
complete the one-time setup below.

---

#### Step 1 — Create a Service Account

1. Go to the **Google Cloud Console**: <https://console.cloud.google.com>
2. Select or create a project for the scanner.
3. Navigate to **IAM & Admin → Service Accounts**.
4. Click **Create Service Account**.
5. Fill in the form:
   - **Name:** `accuknox-sspm` (or any descriptive name)
   - **Description:** `AccuKnox SSPM scanner`
6. Click **Create and Continue**, skip optional role grants, click **Done**.
7. Click the new service account, go to the **Keys** tab.
8. Click **Add Key → Create new key → JSON**, then click **Create**.
9. Save the downloaded `.json` key file securely — this is your
   `--service-account-file`.

---

#### Step 2 — Enable Domain-Wide Delegation

1. In the **Google Cloud Console**, open the service account.
2. Click **Edit** (pencil icon).
3. Expand **Advanced settings** and tick
   **Enable Google Workspace Domain-wide Delegation**.
4. Click **Save**.
5. Note the **Client ID** shown on the service account overview
   (a long numeric string) — you will need it in Step 3.

---

#### Step 3 — Enable Required APIs in Google Cloud

In the **Google Cloud Console** for your project
(<https://console.cloud.google.com/apis/library>), enable both:

| API | Used for |
|-----|---------|
| **Admin SDK API** (`admin.googleapis.com`) | Directory (users, domains, OUs) and Reports |
| **Google Workspace Alert Center API** (`alertcenter.googleapis.com`) | Alert rules (Section 6 checks) |

Navigate to **APIs & Services → Library**, search for each, and click **Enable**.

---

#### Step 4 — Authorise the Service Account in Google Workspace

1. Sign in to the **Google Workspace Admin Console**: <https://admin.google.com>
2. Navigate to **Security → Access and data control →
   API controls → Manage Domain-wide Delegation**.
3. Click **Add new**.
4. Enter the **Client ID** from Step 2 (the long numeric string).
5. In the **OAuth Scopes** field, paste the following scopes exactly
   (comma-separated, no spaces):

   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/apps.alerts,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/gmail.settings.basic
   ```

   | Scope | Purpose |
   |-------|---------|
   | `admin.directory.user.readonly` | Read user accounts, admin status, 2SV enrollment |
   | `admin.directory.domain.readonly` | Read verified domains |
   | `admin.directory.orgunit.readonly` | Read organisational units |
   | `admin.directory.group.readonly` | Read all groups in the domain |
   | `admin.reports.audit.readonly` | Read Admin audit logs |
   | `admin.reports.usage.readonly` | Read usage reports |
   | `apps.alerts` | Read Alert Center alert rules (Section 6) |
   | `apps.groups.settings` | Read group security settings (Section 3.1.6) |
   | `gmail.settings.basic` | Read per-user IMAP, POP, forwarding settings (Section 3.1.3) |

6. Click **Authorise**.

---

#### Step 5 — Record Your Primary Domain

Find your primary domain:

- **Google Workspace Admin Console** → Account → Domains → Manage domains.

It typically looks like `example.com`.  This is your `--domain`.
Only verified domains are scanned for DNS checks (SPF, DKIM, DMARC).

---

#### Summary: Values You Need

| Value | Where to find it | CLI flag / env var |
|-------|-----------------|-------------------|
| Service Account JSON | Downloaded in Step 1 | `--service-account-file` / `SSPM_GWS_SA_FILE` |
| Admin Email | Super Admin account email | `--admin-email` / `SSPM_GWS_ADMIN_EMAIL` |
| Domain | Primary domain from Step 5 | `--domain` / `SSPM_GWS_DOMAIN` |

---

#### Security Recommendations for the Service Account

- **Read-only scopes only:** the scopes listed above are all read-only.
  Do not add any `.readonly`-less or write scopes.
- **Dedicated project:** use a separate GCP project for the scanner to
  isolate the service account from production workloads.
- **Restrict key access:** store the JSON key file with `chmod 600` and
  never commit it to version control.
- **Rotate keys periodically:** delete and recreate the JSON key
  annually or after any suspected exposure.
- **Audit service account usage:** review Admin SDK audit logs for
  unexpected access by the service account.

---

## Azure Coverage

The Azure provider targets *CIS Microsoft Azure Foundations Benchmark v6.0.0*
at the subscription scope. Authentication uses Entra ID app-only credentials;
data is collected directly from Azure Resource Manager (ARM) and Microsoft
Graph REST APIs — no `azure-mgmt-*` SDK dependency.

| Section | Area | Rules |
|---------|------|-------|
| 5 | Identity & RBAC | Security defaults, MFA (manual), User Access Administrator hygiene, custom subscription admin roles, subscription owner count |
| 6 | Logging & Monitoring | Subscription activity log diagnostic settings, Key Vault audit logging |
| 7 | Networking | RDP/SSH from Internet, NSG flow-log retention ≥ 90 days, Network Watcher coverage |
| 8 | Security Services | Defender CSPM On, Defender for Servers On, security-contact email, Key Vault purge protection / RBAC / public-access, Bastion presence |
| 9 | Storage Accounts | File/blob soft delete, shared-key access off, public network access off, default Deny ACL, HTTPS only, TLS 1.2, cross-tenant replication off, blob anonymous access off |

### Setting Up Credentials for Scanning

The scanner uses an **Entra ID App Registration** with the **Reader** role on
the target subscription. A **Global Administrator** (or user with equivalent
delegated rights) must complete the one-time setup below.

---

#### Step 1 — Create the App Registration

Follow the same procedure as the MS365 setup (Steps 1 & 2 above) to create an
app registration and a client secret. Capture:

- **Application (client) ID** → `--client-id`
- **Directory (tenant) ID** → `--tenant-id`
- **Client secret value** → `--client-secret`

---

#### Step 2 — Grant Subscription-Level RBAC

1. In the **Azure portal**, open the subscription you want to scan.
2. Go to **Access control (IAM) → Add → Add role assignment**.
3. Select the built-in role **Reader**.
4. **Members:** *User, group, or service principal* → search for the app
   registration name from Step 1.
5. Click **Review + assign**.

The Reader role grants read access to all resource metadata needed by the
benchmark (no data-plane permissions are required for configuration checks).

> **Tip:** For Key Vault diagnostic-setting and Defender for Cloud checks,
> Reader is sufficient. To evaluate data-plane policies (keys / secrets
> listing), additionally grant the app the **Key Vault Reader** role.

---

#### Step 3 — Grant Microsoft Graph Permissions (Identity checks)

The Section 5 identity checks (e.g. `azure-cis-5.1.1` – security defaults)
query Microsoft Graph. In the app registration:

1. **API permissions → Add a permission → Microsoft Graph → Application**.
2. Add **`Policy.Read.All`** (read tenant identity-security policy).
3. Click **Grant admin consent for \<your tenant\>**.

---

#### Step 4 — Capture the Subscription ID

`az account show --query id -o tsv` or **Subscriptions** in the Azure portal.
This is your `--subscription-id`.

---

#### Summary: Values You Need

| Value | Where to find it | CLI flag / env var |
|-------|-----------------|-------------------|
| Tenant ID | Entra app overview → Directory (tenant) ID | `--tenant-id` / `AZURE_TENANT_ID` |
| Client ID | Entra app overview → Application (client) ID | `--client-id` / `AZURE_CLIENT_ID` |
| Client Secret | Created in Step 1 | `--client-secret` / `AZURE_CLIENT_SECRET` |
| Subscription ID | Subscriptions blade | `--subscription-id` / `AZURE_SUBSCRIPTION_ID` |

---

## Microsoft 365 Coverage

```bash
pip install -e ".[dev]"     # development install with test dependencies
# or
pip install accuknox-sspm   # production install
```

**Requirements:** Python 3.11+

---

## Usage

### CLI

```bash
# Scan an MS365 tenant
sspm scan ms365 \
  --tenant-id  <TENANT_ID>      \
  --client-id  <CLIENT_ID>      \
  --client-secret <SECRET>      \
  --tenant-domain contoso.onmicrosoft.com \
  --output contoso-report.sarif.json \
  --verbose

# Scan a Google Workspace domain
sspm scan gws \
  --service-account-file /path/to/sa-key.json \
  --admin-email admin@example.com \
  --domain example.com \
  --output gws-report.sarif.json \
  --verbose

# Scan an Azure subscription
sspm scan azure \
  --tenant-id       <TENANT_ID>        \
  --client-id       <CLIENT_ID>        \
  --client-secret   <SECRET>           \
  --subscription-id <SUBSCRIPTION_ID>  \
  --output azure-report                \
  --verbose

# Filter to a specific CIS profile
sspm scan ms365 ... --profile "E3 Level 1"
sspm scan gws   ... --profile "Enterprise Level 1"
sspm scan azure ... --profile "Azure Level 1"

# Run specific rules only
sspm scan ms365 ... \
  --rule ms365-cis-5.2.2.1 \
  --rule ms365-cis-5.2.2.2

# List all registered rules
sspm rules list

# Summarise an existing report
sspm report summary contoso-report.sarif.json
```

Credentials can also be provided via environment variables:
```bash
# MS365
export SSPM_TENANT_ID=<TENANT_ID>
export SSPM_CLIENT_ID=<CLIENT_ID>
export SSPM_CLIENT_SECRET=<SECRET>
sspm scan ms365 --tenant-domain contoso.onmicrosoft.com

# GWS
export SSPM_GWS_SA_FILE=/path/to/sa-key.json
export SSPM_GWS_ADMIN_EMAIL=admin@example.com
export SSPM_GWS_DOMAIN=example.com
sspm scan gws

# Azure
export AZURE_TENANT_ID=<TENANT_ID>
export AZURE_CLIENT_ID=<CLIENT_ID>
export AZURE_CLIENT_SECRET=<SECRET>
export AZURE_SUBSCRIPTION_ID=<SUBSCRIPTION_ID>
sspm scan azure
```

### Python API

```python
import asyncio
from sspm.core.engine import ScanEngine
from sspm.core.reporter import write_sarif
from sspm.providers.ms365.provider import MS365Provider

provider = MS365Provider(
    tenant_id="...",
    client_id="...",
    client_secret="...",
    tenant_domain="contoso.onmicrosoft.com",
)

engine = ScanEngine(provider=provider, profile_filter="E3 Level 1")
result = asyncio.run(engine.scan())

print(result.summary())
# {'total': 11, 'passed': 3, 'failed': 5, 'manual': 2, 'errors': 0, 'skipped': 1}

write_sarif(result, "contoso-report.sarif.json")
```

---

## SARIF Output

The scanner produces a **SARIF 2.1.0** document:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "AccuKnox SSPM",
        "organization": "AccuKnox",
        "rules": [ /* one reportingDescriptor per rule */ ]
      }
    },
    "results": [
      {
        "ruleId": "ms365-cis-5.2.2.1",
        "kind": "fail",
        "level": "error",
        "message": { "text": "No CA policy requires MFA for admin roles." },
        "locations": [{ "logicalLocations": [{ "name": "contoso.onmicrosoft.com" }] }],
        "relatedLocations": [ /* evidence */ ]
      },
      {
        "ruleId": "ms365-cis-1.1.2",
        "kind": "open",
        "level": "none",
        "message": { "text": "Manual verification required…" }
      }
    ]
  }]
}
```

**SARIF `kind` mapping:**

| Finding Status | SARIF `kind` | SARIF `level` |
|---------------|-------------|---------------|
| PASS | `pass` | `none` |
| FAIL (critical/high) | `fail` | `error` |
| FAIL (medium) | `fail` | `warning` |
| FAIL (low) | `fail` | `note` |
| MANUAL | `open` | `none` |
| ERROR | `review` | `note` |
| SKIPPED | `none` | `none` |

---

## Adding New Rules

1. Create a new file under `sspm/providers/<provider>/rules/section<N>_<name>/cis_<x>_<y>_<z>.py`
2. Define a class inheriting `MS365Rule` or `GWSRule`
3. Set `metadata = RuleMetadata(...)` with all CIS fields
4. Implement `async def check(self, data: CollectedData) -> Finding`
5. Decorate with `@registry.rule`

The rule is auto-discovered at runtime — no manual registration needed.

```python
from sspm.core.registry import registry
from sspm.providers.gws.rules.base import GWSRule  # or MS365Rule

@registry.rule
class CIS_X_Y_Z(GWSRule):
    metadata = RuleMetadata(
        id="gws-cis-X.Y.Z",
        ...
    )

    async def check(self, data: CollectedData):
        value = data.get("some_data_key")
        if value is None:
            return self._skip("Data not available.")
        if value == expected:
            return self._pass("Control is compliant.")
        return self._fail("Control is non-compliant.", evidence=[...])
```

## Adding a New SaaS Provider

1. Create `sspm/providers/<provider>/provider.py` subclassing `BaseProvider`
2. Implement `collect()` to return a `CollectedData` snapshot
3. Create rules subclassing `BaseRule` with `provider = "<provider>"`
4. Call `registry.autodiscover("sspm.providers.<provider>.rules")`

---

## Running Tests

```bash
pytest tests/ -v
```

---

## License

Copyright © 2026 AccuKnox. All rights reserved.  
Proprietary and confidential.
