#Requires -Modules Microsoft.Online.SharePoint.PowerShell
<#
.SYNOPSIS
    Connects to SharePoint Online Management Shell (certificate-based
    app-only auth) and collects tenant settings.

    Session plumbing only for now: no Get-SPOTenant property is wired to a
    collector key yet. CIS 7.2.8's audit procedure in the official PDF is
    UI-only (SharePoint admin center) with no confirmed PowerShell property,
    so guessing one here would risk a silently wrong PASS/FAIL. Wire it up
    once the exact property is verified against a live tenant.

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

    # TODO: verify the exact Get-SPOTenant property against a live tenant
    # for CIS 7.2.8, then add an Invoke-Collect call here, e.g.:
    #   Invoke-Collect "spo_tenant_settings" { Get-SPOTenant }
} finally {
    Disconnect-SPOService -ErrorAction SilentlyContinue | Out-Null
}

@{ result = $result; errors = $errors } | ConvertTo-Json -Depth 8 -Compress
