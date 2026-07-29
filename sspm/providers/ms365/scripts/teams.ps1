#Requires -Modules MicrosoftTeams
<#
.SYNOPSIS
    Collects Microsoft Teams tenant settings needed by CIS MS365 rules that
    have no Microsoft Graph equivalent.

.PARAMETER AppId
    Entra app registration client ID (certificate-based app-only auth).
.PARAMETER TenantId
    Entra tenant ID (GUID).
.PARAMETER CertificatePath
    Path to a .pfx certificate file. Optional if access tokens are supplied
    instead via env vars.

Secrets are read from environment variables (never argv), so they never
appear in process lists or logs:
    SSPM_MS365_CERT_PASSWORD        - certificate password (cert auth only)
    SSPM_MS365_GRAPH_ACCESS_TOKEN   - pre-acquired token for the MS Graph
                                       .default scope
    SSPM_MS365_TEAMS_ACCESS_TOKEN   - pre-acquired token for the
                                       "Skype and Teams Tenant Admin API"
                                       resource (48ac35b8-9aa8-4d74-927d-
                                       1f4a14a0b239/.default)
    Both token env vars must be set together (token auth; skips the cert
    entirely) — Connect-MicrosoftTeams -AccessTokens requires both.

.OUTPUTS
    A single-line JSON object on stdout: { "result": {...}, "errors": {...} }
#>
param(
    [Parameter(Mandatory = $true)][string]$AppId,
    [Parameter(Mandatory = $true)][string]$TenantId,
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
$graphAccessToken = $env:SSPM_MS365_GRAPH_ACCESS_TOKEN
$teamsAccessToken = $env:SSPM_MS365_TEAMS_ACCESS_TOKEN

try {
    if ($graphAccessToken -and $teamsAccessToken) {
        # Access-token app-only auth — no certificate needed. Requires the
        # Organization.Read.All Graph permission and the Teams Administrator
        # role assigned to the app's service principal.
        Connect-MicrosoftTeams -AccessTokens @($graphAccessToken, $teamsAccessToken) | Out-Null
    } elseif ($CertificatePath) {
        $connectArgs = @{
            ApplicationId       = $AppId
            TenantId            = $TenantId
            CertificateFilePath = $CertificatePath
        }
        if ($securePassword) {
            $connectArgs["CertificatePassword"] = $securePassword
        }
        Connect-MicrosoftTeams @connectArgs | Out-Null
    } else {
        throw "Neither access tokens (SSPM_MS365_GRAPH_ACCESS_TOKEN + SSPM_MS365_TEAMS_ACCESS_TOKEN) nor -CertificatePath was supplied."
    }

    # All keys here are singletons ("-Identity Global" or tenant-wide) — no
    # array-unwrapping risk.
    Invoke-Collect "teams_client_configuration" { Get-CsTeamsClientConfiguration -Identity "Global" }
    Invoke-Collect "teams_external_access_policy" { Get-CsExternalAccessPolicy -Identity "Global" }
    Invoke-Collect "teams_tenant_federation_configuration" { Get-CsTenantFederationConfiguration }
    Invoke-Collect "teams_meeting_policy" { Get-CsTeamsMeetingPolicy -Identity "Global" }
    Invoke-Collect "teams_messaging_policy" { Get-CsTeamsMessagingPolicy -Identity "Global" }
} finally {
    Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
}

@{ result = $result; errors = $errors } | ConvertTo-Json -Depth 8 -Compress
