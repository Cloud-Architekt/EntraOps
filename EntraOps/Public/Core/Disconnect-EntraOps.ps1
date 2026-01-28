<#
.SYNOPSIS
    Disconnect from Azure and Microsoft Graph connections and clear EntraOps cache.

.DESCRIPTION
    Disconnects from Azure Resource Management and Microsoft Graph API by using Disconnect-AzAccount and Disconnect-MgGraph.
    Clears all EntraOps cache (memory and persistent) and optionally clears Microsoft Graph SDK cache.

.PARAMETER ClearGraphCache
    If set to $true, the Microsoft Graph SDK cache folder will be deleted. Default is $false.

.PARAMETER MgGraphCacheFolder
    Folder where the cache of Microsoft Graph SDK is stored and will be deleted. Default is '$env:USERPROFILE\.graph'

.PARAMETER ClearEntraOpsCache
    Type of EntraOps cache to clear. Options: All (default), Memory, Persistent, Expired. Default is 'All'.

.EXAMPLE
    Disconnect from Azure and Microsoft Graph API, clearing all EntraOps cache
    Disconnect-EntraOps

.EXAMPLE
    Disconnect and clear both EntraOps and Microsoft Graph SDK cache
    Disconnect-EntraOps -ClearGraphCache $true

.EXAMPLE
    Disconnect and clear only expired EntraOps cache entries
    Disconnect-EntraOps -ClearEntraOpsCache Expired
#>

function Disconnect-EntraOps {
    param (
        [Parameter(Mandatory = $False)]
        [boolean]$ClearGraphCache = $false
        ,
        [Parameter(Mandatory = $false)]
        [string]$MgGraphCacheFolder = '$env:USERPROFILE\.graph'
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Memory", "Persistent", "Expired")]
        [string]$ClearEntraOpsCache = "All"
    )

    # Disconnect from Azure PowerShell
    Write-Verbose "Disconnecting from Azure PowerShell..."
    Disconnect-AzAccount | Out-Null
    Clear-AzContext -Scope Process -Force

    # Clear EntraOps cache (memory and/or persistent based on parameter)
    Write-Verbose "Clearing EntraOps cache (Type: $ClearEntraOpsCache)..."
    Clear-EntraOpsCache -CacheType $ClearEntraOpsCache

    # Disconnect from Microsoft Graph SDK if connected
    $MgContext = Get-MgContext
    if ($null -ne $MgContext) {
        Write-Verbose "Disconnecting from Microsoft Graph..."
        Disconnect-MgGraph | Out-Null
        
        # Optionally delete Microsoft Graph SDK cache folder
        if ($ClearGraphCache -eq $true -and (Test-Path $MgGraphCacheFolder)) {
            Write-Verbose "Clearing Microsoft Graph SDK cache folder: $MgGraphCacheFolder"
            Remove-Item "$MgGraphCacheFolder" -Recurse -Force
        }
    }
    
    Write-Host "Successfully disconnected from EntraOps session" -ForegroundColor Green
}