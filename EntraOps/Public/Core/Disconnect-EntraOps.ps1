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

    # Disconnect from Microsoft Graph SDK if connected
    $MgContext = Get-MgContext
    if ($null -ne $MgContext -and $ClearGraphCache -eq $true -and (Test-Path $MgGraphCacheFolder)) {
        Remove-Item "$MgGraphCacheFolder" -Recurse -Force
    }
    if ($null -ne $MgContext) {
        Disconnect-MgGraph | Out-Null
    }
}