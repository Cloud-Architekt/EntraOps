<#
.SYNOPSIS
    Get EntraOps Privileged EAM data as result of the cmdlet.

.DESCRIPTION
    Get information from EntraOps about classification based on Enterprise Access Model and return as result.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.EXAMPLE
    Store EntraOps data of Entra-related RBAC systems in a variable
    $EntraOpsData = Get-EntraOpsPrivilegedEAM -RbacSystem ("EntraID", "IdentityGovernance","ResourceApps")
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
    )

    if ($ClearCache -eq $true) {
        Write-Host "Clearing cache before analyzing RBAC and classification data"
        Clear-EntraOpsCache
    }

    #region Entra ID
    if ($RbacSystems -contains "EntraID") {
        $EamAzureAD = Get-EntraOpsPrivilegedEamEntraId
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
        $EamDeviceMgmt = $EamDeviceMgmt | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
    }
    #endregion

    #region Identity Governance
    if ($RbacSystems -contains "IdentityGovernance") {
        $EamIdGov = Get-EntraOpsPrivilegedEAMIdGov
        $EamIdGov | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
    }
    #endregion
}