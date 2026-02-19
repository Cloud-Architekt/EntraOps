<#
.SYNOPSIS
    Get EntraOps Privileged EAM data as result of the cmdlet.

.DESCRIPTION
    Get information from EntraOps about classification based on Enterprise Access Model and return as result.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.PARAMETER DefaultCacheTTL
    Cache TTL (in seconds) for regular API responses during this execution. If not specified, uses current session value.

.PARAMETER StaticDataCacheTTL
    Cache TTL (in seconds) for static data like role definitions during this execution. If not specified, uses current session value.

.EXAMPLE
    Store EntraOps data of Entra-related RBAC systems in a variable
    $EntraOpsData = Get-EntraOpsPrivilegedEAM -RbacSystem ("EntraID", "IdentityGovernance","ResourceApps")

.EXAMPLE
    Run with custom cache TTL of 6 hours
    $EntraOpsData = Get-EntraOpsPrivilegedEAM -DefaultCacheTTL 21600 -StaticDataCacheTTL 21600
#>

function Get-EntraOpsPrivilegedEAM {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet("EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "ResourceApps", "Defender")
        ,
        [Parameter(Mandatory = $False)]
        [System.Boolean]$ClearCache = $false
        ,
        [Parameter(Mandatory = $False)]
        [System.Int32]$DefaultCacheTTL = 0 # Default is 0 to indicate no change
        ,
        [Parameter(Mandatory = $False)]
        [System.Int32]$StaticDataCacheTTL = 0 # Default is 0 to indicate no change
        ,
        [Parameter(Mandatory = $False)]
        [switch]$IncludeActivatedPIMAssignments
    )

    # Store original TTL values to restore after execution
    $OriginalDefaultTTL = $__EntraOpsSession.DefaultCacheTTL
    $OriginalStaticTTL = $__EntraOpsSession.StaticDataCacheTTL

    # Check if custom TTL values were provided
    $CustomTTLProvided = ($PSBoundParameters.ContainsKey('DefaultCacheTTL') -or $PSBoundParameters.ContainsKey('StaticDataCacheTTL'))
    
    # Use provided values or keep original
    $EffectiveDefaultTTL = if ($PSBoundParameters.ContainsKey('DefaultCacheTTL')) { $DefaultCacheTTL } else { $OriginalDefaultTTL }
    $EffectiveStaticTTL = if ($PSBoundParameters.ContainsKey('StaticDataCacheTTL')) { $StaticDataCacheTTL } else { $OriginalStaticTTL }

    # Set TTL values for this execution
    $__EntraOpsSession.DefaultCacheTTL = $EffectiveDefaultTTL
    $__EntraOpsSession.StaticDataCacheTTL = $EffectiveStaticTTL

    # Notify user only if custom TTL was provided
    if ($CustomTTLProvided) {
        Write-Host ""
        Write-Host "════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  ⏱️  Cache TTL Modified for This Execution" -ForegroundColor Cyan
        Write-Host "════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Default Cache TTL    : $([Math]::Round($EffectiveDefaultTTL / 3600, 1)) hours (was $([Math]::Round($OriginalDefaultTTL / 3600, 1)) hours)" -ForegroundColor Yellow
        Write-Host "  Static Data Cache TTL: $([Math]::Round($EffectiveStaticTTL / 3600, 1)) hours (was $([Math]::Round($OriginalStaticTTL / 3600, 1)) hours)" -ForegroundColor Yellow
        Write-Host "  ℹ️  Cache will be restored to original values after completion" -ForegroundColor Gray
        Write-Host "════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
    }

    try {
        if ($ClearCache -eq $true) {
            Write-Host "Clearing cache before analyzing RBAC and classification data"
            Clear-EntraOpsCache
        }

        #region Entra ID
        if ($RbacSystems -contains "EntraID") {
            $EntraIdParams = @{}
            if ($IncludeActivatedPIMAssignments) {
                $EntraIdParams['IncludeActivatedPIMAssignments'] = $true
            }
            $EamAzureAD = Get-EntraOpsPrivilegedEamEntraId @EntraIdParams
            $EamAzureAD | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        }
        #endregion

        #region Entra Resource Apps
        if ($RbacSystems -contains "ResourceApps") {
            $EamAzureAdResourceApps = Get-EntraOpsPrivilegedEamResourceApps
            $EamAzureAdResourceApps | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        }
        #endregion

        #region Device Management
        if ($RbacSystems -contains "DeviceManagement") {
            $EamDeviceMgmt = Get-EntraOpsPrivilegedEAMIntune
            $EamDeviceMgmt | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        }
        #endregion

        #region Identity Governance
        if ($RbacSystems -contains "IdentityGovernance") {
            $EamIdGov = Get-EntraOpsPrivilegedEAMIdGov
            $EamIdGov | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        }
        #endregion

        #region Defender
        if ($RbacSystems -contains "Defender") {
            $EamDefender = Get-EntraOpsPrivilegedEamDefender
            $EamDefender | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        }
        #endregion
    } finally {
        # Restore original TTL values
        $__EntraOpsSession.DefaultCacheTTL = $OriginalDefaultTTL
        $__EntraOpsSession.StaticDataCacheTTL = $OriginalStaticTTL
        
        Write-Verbose "Cache TTL restored to original values: Default=$([Math]::Round($OriginalDefaultTTL / 3600, 1))h, Static=$([Math]::Round($OriginalStaticTTL / 3600, 1))h"
    }
}