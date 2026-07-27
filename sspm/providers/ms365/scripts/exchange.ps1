#Requires -Modules ExchangeOnlineManagement
<#
.SYNOPSIS
    Collects Exchange Online (and two EXO-hosted Teams-protection) settings
    needed by CIS MS365 rules that have no Microsoft Graph equivalent.

.PARAMETER AppId
    Entra app registration client ID (certificate-based app-only auth).
.PARAMETER Organization
    Tenant's onmicrosoft.com domain, e.g. contoso.onmicrosoft.com.
.PARAMETER CertificatePath
    Path to a .pfx certificate file. Optional if an access token is supplied
    instead via the SSPM_MS365_EXO_ACCESS_TOKEN env var.

Secrets are read from environment variables (never argv), so they never
appear in process lists or logs:
    SSPM_MS365_CERT_PASSWORD    - certificate password (cert auth only)
    SSPM_MS365_EXO_ACCESS_TOKEN - pre-acquired OAuth access token for the
                                   https://outlook.office365.com/.default
                                   scope (token auth; skips the cert entirely)

.OUTPUTS
    A single-line JSON object on stdout: { "result": {...}, "errors": {...} }
    Every collected key is present in exactly one of "result" or "errors".
#>
param(
    [Parameter(Mandatory = $true)][string]$AppId,
    [Parameter(Mandatory = $true)][string]$Organization,
    [string]$CertificatePath
)

$ErrorActionPreference = "Stop"
$result = @{}
$errors = @{}

function Invoke-Collect {
    param(
        [string]$Key,
        [scriptblock]$Script
    )
    try {
        $value = & $Script
        $result[$Key] = $value
    } catch {
        $errors[$Key] = $_.Exception.Message
    }
}

$certPassword = $env:SSPM_MS365_CERT_PASSWORD
$securePassword = if ($certPassword) { ConvertTo-SecureString -String $certPassword -AsPlainText -Force } else { $null }
$accessToken = $env:SSPM_MS365_EXO_ACCESS_TOKEN

try {
    if ($accessToken) {
        # Access-token app-only auth — no certificate needed. Requires the
        # Exchange.ManageAsApp API permission and the Exchange Administrator
        # role assigned to the app's service principal.
        Connect-ExchangeOnline -AccessToken $accessToken -Organization $Organization -ShowBanner:$false | Out-Null
    } elseif ($CertificatePath) {
        $connectArgs = @{
            AppId             = $AppId
            Organization      = $Organization
            CertificateFilePath = $CertificatePath
            ShowBanner        = $false
        }
        if ($securePassword) {
            $connectArgs["CertificatePassword"] = $securePassword
        }
        Connect-ExchangeOnline @connectArgs | Out-Null
    } else {
        throw "Neither an access token (SSPM_MS365_EXO_ACCESS_TOKEN) nor -CertificatePath was supplied."
    }

    # --- Singletons ---
    Invoke-Collect "owa_mailbox_policy" { Get-OwaMailboxPolicy -Identity "OwaMailboxPolicy-Default" }
    Invoke-Collect "organization_config" { Get-OrganizationConfig }
    Invoke-Collect "transport_config" { Get-TransportConfig }
    Invoke-Collect "atp_policy_for_o365" { Get-AtpPolicyForO365 }
    Invoke-Collect "hosted_outbound_spam_filter_policy" { Get-HostedOutboundSpamFilterPolicy -Identity "Default" }
    Invoke-Collect "hosted_connection_filter_policy" { Get-HostedConnectionFilterPolicy -Identity "Default" }
    Invoke-Collect "sharing_policy" { Get-SharingPolicy -Identity "Default Sharing Policy" }
    Invoke-Collect "admin_audit_log_config" { Get-AdminAuditLogConfig }

    # --- Arrays ---
    # @(...) alone is NOT enough: PowerShell unwraps a single-element array
    # back to a bare object the moment it crosses the `& $Script` boundary
    # inside Invoke-Collect (confirmed against a live tenant — a lone
    # "Default" policy came back as an object, not a 1-element array, which
    # then broke every rule iterating it with a list comprehension).
    # Write-Output -NoEnumerate inside the scriptblock itself is required to
    # survive that boundary; @(...) is kept too since -NoEnumerate needs an
    # actual array/collection to operate on, not a bare pipeline of objects.
    Invoke-Collect "transport_rules" { Write-Output -NoEnumerate @(Get-TransportRule) }
    Invoke-Collect "malware_filter_policy" { Write-Output -NoEnumerate @(Get-MalwareFilterPolicy) }
    Invoke-Collect "hosted_content_filter_policy" { Write-Output -NoEnumerate @(Get-HostedContentFilterPolicy) }
    Invoke-Collect "mailbox_audit_bypass_association" {
        Write-Output -NoEnumerate @(Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled })
    }
    Invoke-Collect "external_in_outlook" { Write-Output -NoEnumerate @(Get-ExternalInOutlook) }
    Invoke-Collect "role_assignment_policies" { Write-Output -NoEnumerate @(Get-RoleAssignmentPolicy) }
    Invoke-Collect "safe_links_policies" { Write-Output -NoEnumerate @(Get-SafeLinksPolicy) }
    Invoke-Collect "safe_attachments_policies" { Write-Output -NoEnumerate @(Get-SafeAttachmentPolicy) }
    Invoke-Collect "anti_phishing_policies" { Write-Output -NoEnumerate @(Get-AntiPhishPolicy) }
    # NOTE: mailbox_audit_settings on a large tenant may be slow / large —
    # not paginated here; revisit if this proves too slow in practice.
    Invoke-Collect "mailbox_audit_settings" {
        Write-Output -NoEnumerate @(Get-EXOMailbox -PropertySets Audit -ResultSize Unlimited)
    }

    # EXO-hosted cmdlets that logically feed Teams/Defender rules.
    Invoke-Collect "teams_protection_policy" { Write-Output -NoEnumerate @(Get-TeamsProtectionPolicy) }
    Invoke-Collect "report_submission_policy" { Write-Output -NoEnumerate @(Get-ReportSubmissionPolicy) }
} finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}

@{ result = $result; errors = $errors } | ConvertTo-Json -Depth 8 -Compress
