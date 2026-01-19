<#
.SYNOPSIS
    Established connection to required PowerShell modules and requests access tokens for EntraOps PowerShell Module

.DESCRIPTION
    Connection to Azure Management and Microsoft Graph API by using Connect-AzAccount and Connect-MgGraph.

.PARAMETER ClearGraphCache
    If set to $true, the cache of Microsoft Graph SDK will be cleared. Default is $false.

.PARAMETER MgGraphCacheFolder
    Folder where the cache of Microsoft Graph SDK is stored and will be deleted

.EXAMPLE
    Disconnect from Azure Management and Microsoft Graph API, clearing Contexts, delete Graph SDK and EntraOps cache
    Disconnect-EntraOps -ClearGraphCache $true
#>

function Disconnect-EntraOps {
    param (
        [Parameter(Mandatory = $False)]
        [boolean]$ClearGraphCache = $false
        ,
        [Parameter(Mandatory = $false)]
        [string]$MgGraphCacheFolder = '$env:USERPROFILE\.graph'
    )

    # Disconnect from Azure PowerShell
    Disconnect-AzAccount | Out-Null
    Clear-AzContext -Scope Process -Force

    # Delete EntraOps cache
    Clear-EntraOpsCache

    # Clear sensitive connection info from Global scope
    if ($null -ne $Global:MgGraphConnectionInfo) {
        # Clear any plaintext tokens
        if ($Global:MgGraphConnectionInfo.AccessToken) {
            $Global:MgGraphConnectionInfo.AccessToken = $null
        }
        # Dispose SecureString
        if ($Global:MgGraphConnectionInfo.SecureAccessToken) {
            $Global:MgGraphConnectionInfo.SecureAccessToken.Dispose()
        }
        Remove-Variable -Name MgGraphConnectionInfo -Scope Global -Force -ErrorAction SilentlyContinue
    }

    # Disconnect from Microsoft Graph SDK if connected
    $MgContext = Get-MgContext
    if ($null -ne $MgContext -and $ClearGraphCache -eq $true -and (Test-Path $MgGraphCacheFolder)) {
        Remove-Item "$MgGraphCacheFolder" -Recurse -Force
    }
    if ($null -ne $MgContext) {
        Disconnect-MgGraph | Out-Null
    }
}