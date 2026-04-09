# AccuKnox SSPM

**SaaS Security Posture Management** – automated security posture scanning for
popular SaaS platforms against industry-standard benchmarks (CIS, NIST, etc.).

Initial target: **Microsoft 365** against
*CIS Microsoft 365 Foundations Benchmark v6.0.1*.

Output: **SARIF 2.1.0** JSON, compatible with GitHub Advanced Security,
Azure DevOps, VS Code (SARIF Viewer), and any SARIF-aware toolchain.

---

## Project Structure

```
sspm/
├── pyproject.toml                      # Package metadata and dependencies
├── sspm/
│   ├── cli.py                          # Click-based CLI entry point
│   ├── core/
│   │   ├── models.py                   # Shared data models (Rule, Finding, ScanResult…)
│   │   ├── engine.py                   # Scan orchestration engine
│   │   ├── registry.py                 # Rule auto-discovery and registry
│   │   └── reporter.py                 # SARIF 2.1.0 report generator
│   └── providers/
│       ├── base.py                     # Abstract BaseProvider and BaseRule
│       └── ms365/
│           ├── auth.py                 # MSAL client-credentials authentication
│           ├── collector.py            # Microsoft Graph API data collection
│           ├── provider.py             # MS365Provider (wires auth + collection)
│           └── rules/
│               ├── base.py             # MS365Rule base class with helpers
│               ├── section1_m365_admin/
│               │   ├── cis_1_1_1.py   # Admin accounts cloud-only (Automated)
│               │   ├── cis_1_1_2.py   # Emergency access accounts (Manual)
│               │   └── cis_1_3_1.py   # Password expiration policy (Automated)
│               ├── section2_defender/
│               │   └── cis_2_1_9.py   # DKIM enabled for all domains (Automated)
│               ├── section3_purview/
│               │   └── cis_3_1_1.py   # Audit log search enabled (Automated)
│               ├── section5_entra/
│               │   ├── cis_5_1_2_1.py # Per-user MFA disabled (Automated)
│               │   ├── cis_5_2_2_1.py # MFA for admin roles via CA (Automated)
│               │   └── cis_5_2_2_2.py # MFA for all users via CA (Automated)
│               ├── section6_exchange/
│               │   └── cis_6_2_1.py   # Block external mail forwarding (Automated)
│               ├── section7_sharepoint/
│               │   └── cis_7_2_3.py   # External content sharing restricted (Automated)
│               └── section8_teams/
│                   └── cis_8_5_1.py   # Anonymous meeting join disabled (Automated)
└── tests/
    ├── test_engine.py                  # Engine unit tests
    ├── test_rules_ms365.py             # Rule-level unit tests
    └── test_reporter.py                # SARIF output tests
```

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
1. Inherits from `MS365Rule` (which inherits `BaseRule`)
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

## Installation

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

# Filter to CIS E3 Level 1 controls only
sspm scan ms365 ... --profile "E3 Level 1"

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
export SSPM_TENANT_ID=<TENANT_ID>
export SSPM_CLIENT_ID=<CLIENT_ID>
export SSPM_CLIENT_SECRET=<SECRET>
sspm scan ms365 --tenant-domain contoso.onmicrosoft.com
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
  "$schema": "https://raw.githubusercontent.com/.../sarif-schema-2.1.0.json",
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

1. Create a new file under `sspm/providers/ms365/rules/section<N>_<name>/cis_<x>_<y>_<z>.py`
2. Define a class inheriting `MS365Rule`
3. Set `metadata = RuleMetadata(...)` with all CIS fields
4. Implement `async def check(self, data: CollectedData) -> Finding`
5. Decorate with `@registry.rule`

The rule is auto-discovered at runtime — no manual registration needed.

```python
from sspm.core.registry import registry
from sspm.providers.ms365.rules.base import MS365Rule

@registry.rule
class CIS_X_Y_Z(MS365Rule):
    metadata = RuleMetadata(
        id="ms365-cis-X.Y.Z",
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
