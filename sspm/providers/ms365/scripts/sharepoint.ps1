#Requires -Modules Microsoft.Online.SharePoint.PowerShell
<#
.SYNOPSIS
    Connects to SharePoint Online Management Shell (certificate-based
    app-only auth) and collects tenant settings.

    Collects the "spo_tenant" key: the Get-SPOTenant properties that CIS
    section 7 audits by name and that Microsoft Graph's
    /admin/sharepoint/settings does not expose (link defaults, guest
    expiration, email attestation, infected-file download, B2B integration).

    CIS 7.2.8's audit procedure in the official PDF is UI-only (SharePoint
    admin center) with no confirmed PowerShell property, so it is not
    collected here — that control stays MANUAL, which is how CIS classifies
    it anyway.

.PARAMETER AppId
    Entra app registration client ID (certificate-based app-only auth).
.PARAMETER TenantId
    Entra tenant ID (GUID).
.PARAMETER CertificatePath
    Path to a .pfx certificate file.
.PARAMETER AdminUrl
    SharePoint admin center URL, e.g. https://contoso-admin.sharepoint.com.
.PARAMETER CertificatePassword
    Certificate password, read from the SSPM_MS365_CERT_PASSWORD env var
    (never passed on argv, so it never appears in process lists or logs).

.OUTPUTS
    A single-line JSON object on stdout: { "result": {...}, "errors": {...} }
#>
param(
    [Parameter(Mandatory = $true)][string]$AppId,
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$CertificatePath,
    [Parameter(Mandatory = $true)][string]$AdminUrl
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

try {
    $connectArgs = @{
        Url                 = $AdminUrl
        ClientId            = $AppId
        Tenant              = $TenantId
        CertificatePath     = $CertificatePath
    }
    if ($securePassword) {
        $connectArgs["CertificatePassword"] = $securePassword
    }
    Connect-SPOService @connectArgs

    # DefaultSharingLinkType and DefaultLinkPermission are .NET enums that
    # ConvertTo-Json would otherwise emit as bare integers; cast them to
    # strings so the rules can match on the same names CIS's audit steps use.
    Invoke-Collect "spo_tenant" {
        $tenant = Get-SPOTenant
        [ordered]@{
            SharingCapability                        = [string]$tenant.SharingCapability
            SharingDomainRestrictionMode             = [string]$tenant.SharingDomainRestrictionMode
            SharingAllowedDomainList                 = $tenant.SharingAllowedDomainList
            SharingBlockedDomainList                 = $tenant.SharingBlockedDomainList
            PreventExternalUsersFromResharing        = $tenant.PreventExternalUsersFromResharing
            EnableAzureADB2BIntegration              = $tenant.EnableAzureADB2BIntegration
            DefaultSharingLinkType                   = [string]$tenant.DefaultSharingLinkType
            DefaultLinkPermission                    = [string]$tenant.DefaultLinkPermission
            ExternalUserExpirationRequired           = $tenant.ExternalUserExpirationRequired
            ExternalUserExpireInDays                 = $tenant.ExternalUserExpireInDays
            EmailAttestationRequired                 = $tenant.EmailAttestationRequired
            EmailAttestationReAuthDays               = $tenant.EmailAttestationReAuthDays
            DisallowInfectedFileDownload             = $tenant.DisallowInfectedFileDownload
            LegacyAuthProtocolsEnabled               = $tenant.LegacyAuthProtocolsEnabled
            IsUnmanagedSyncClientForTenantRestricted = $tenant.IsUnmanagedSyncClientForTenantRestricted
            OneDriveSharingCapability                = [string]$tenant.OneDriveSharingCapability
        }
    }
} finally {
    Disconnect-SPOService -ErrorAction SilentlyContinue | Out-Null
}

@{ result = $result; errors = $errors } | ConvertTo-Json -Depth 8 -Compress
