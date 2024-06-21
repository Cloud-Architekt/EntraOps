<#
.SYNOPSIS
    Export and save EntraOps Privileged EAM data to JSON files.

.DESCRIPTION
    Get information from EntraOps about classification based on Enterprise Access Model and save them as JSON to folder.

.PARAMETER ExportFolder
    Folder where the JSON files should be stored. Default is ./PrivilegedEAM.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.EXAMPLE
    Export and save JSON files of EntraOps to default folder
    Save-EntraOpsPrivilegedEAMJson
#>

function Save-EntraOpsPrivilegedEAMJson {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$ExportFolder = $DefaultFolderClassifiedEam
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps")]
        [Array]$RbacSystems = ("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps")
    )

    Write-Output "Clearing cache before analyzing RBAC and classification data"
    Clear-EntraOpsCache

    #region Azure
    if ($RbacSystems -contains "Azure") {
        $ExportFolder = "$($DefaultFolderClassifiedEam)/Azure"

        if ((Test-Path -path "$($ExportFolder)")) {
            Remove-Item "$($ExportFolder)" -Force -Recurse
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        else {
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        $EamAzure = Get-EntraOpsPrivilegedEamAzure
        $EamAzure = $EamAzure | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        $EamAzure | Convertto-Json -Depth 10 | Out-File -Path "$($ExportFolder)/Azure.json"
        foreach ($PrivilegedObject in $EamAzure) {
            $ObjectType = $PrivilegedObject.ObjectType
            $SingleJSONExportPath = "$($ExportFolder)/$ObjectType"
            If (!(test-path $SingleJSONExportPath)) {
                New-Item -ItemType Directory -Force -Path $SingleJSONExportPath
            }
            $PrivilegedObject | Convertto-Json -Depth 10 | Out-File -Path "$SingleJSONExportPath/$($PrivilegedObject.ObjectId).json" -Force
        }
    }
    #endregion

    #region Azure Billing
    if ($RbacSystems -contains "AzureBilling") {
        $ExportFolder = "$($DefaultFolderClassifiedEam)/AzureBilling"

        if ((Test-Path -path "$($ExportFolder)")) {
            Remove-Item "$($ExportFolder)" -Force -Recurse
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        else {
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        $EamAzureBilling = Get-EntraOpsPrivilegedEamAzureBilling -SampleMode $true -GlobalExclusion $false
        $EamAzureBilling = $EamAzureBilling | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        $EamAzureBilling | Convertto-Json -Depth 10 | Out-File -Path "$($ExportFolder)/AzureBilling.json" -Force
        foreach ($PrivilegedObject in $EamAzureBilling) {
            $ObjectType = $PrivilegedObject.ObjectType
            $SingleJSONExportPath = "$($ExportFolder)/$ObjectType"
            If (!(test-path $SingleJSONExportPath)) {
                New-Item -ItemType Directory -Force -Path $SingleJSONExportPath
            }
            $PrivilegedObject | Convertto-Json -Depth 10 | Out-File -Path "$SingleJSONExportPath/$($PrivilegedObject.ObjectId).json" -Force
        }
    }
    #endregion

    #region Entra ID
    if ($RbacSystems -contains "EntraID") {
        $ExportFolder = "$($DefaultFolderClassifiedEam)/EntraID"

        if ((Test-Path -path "$($ExportFolder)")) {
            Remove-Item "$($ExportFolder)" -Force -Recurse
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        else {
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }

        $EamAzureAD = Get-EntraOpsPrivilegedEamEntraId
        $EamAzureAD = $EamAzureAD | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        $EamAzureAD | Convertto-Json -Depth 10 | Out-File -Path "$($ExportFolder)/EntraID.json" -Force
        foreach ($PrivilegedObject in $EamAzureAD) {
            $ObjectType = $PrivilegedObject.ObjectType
            $SingleJSONExportPath = "$($ExportFolder)/$ObjectType"
            If (!(test-path $SingleJSONExportPath)) {
                New-Item -ItemType Directory -Force -Path $SingleJSONExportPath
            }
            $PrivilegedObject | Convertto-Json -Depth 10 | Out-File -Path "$SingleJSONExportPath/$($PrivilegedObject.ObjectId).json" -Force
        }
    }
    #endregion

    #region Entra Resource Apps
    if ($RbacSystems -contains "ResourceApps") {
        $ExportFolder = "$($DefaultFolderClassifiedEam)/ResourceApps"

        if ((Test-Path -path "$($ExportFolder)")) {
            Remove-Item "$($ExportFolder)" -Force -Recurse
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        else {
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }

        $EamAzureAdResourceApps = Get-EntraOpsPrivilegedEamResourceApps
        $EamAzureAdResourceApps = $EamAzureAdResourceApps | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        $EamAzureAdResourceApps | Convertto-Json -Depth 10 | Out-File -Path "$($ExportFolder)/ResourceApps.json"
        foreach ($PrivilegedObject in $EamAzureAdResourceApps) {
            $ObjectType = $PrivilegedObject.ObjectType
            $SingleJSONExportPath = "$($ExportFolder)/$ObjectType"
            If (!(test-path $SingleJSONExportPath)) {
                New-Item -ItemType Directory -Force -Path $SingleJSONExportPath
            }
            $PrivilegedObject | Convertto-Json -Depth 10 | Out-File -Path "$SingleJSONExportPath/$($PrivilegedObject.ObjectId).json" -Force
        }
    }
    #endregion

    #region Device Management
    if ($RbacSystems -contains "DeviceManagement") {
        $ExportFolder = "$($DefaultFolderClassifiedEam)/DeviceManagement"
        $EamDeviceMgmt = Get-EntraOpsPrivilegedEAMIntune
        $EamDeviceMgmt = $EamDeviceMgmt | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }

        if ((Test-Path -path "$($ExportFolder)")) {
            Remove-Item "$($ExportFolder)" -Force -Recurse
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        else {
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        $EamDeviceMgmt | Convertto-Json -Depth 10 | Out-File -Path "$($ExportFolder)/DeviceManagement.json"
        foreach ($PrivilegedObject in $EamDeviceMgmt) {
            $ObjectType = $PrivilegedObject.ObjectType
            $SingleJSONExportPath = "$($ExportFolder)/$ObjectType"
            If (!(test-path $SingleJSONExportPath)) {
                New-Item -ItemType Directory -Force -Path $SingleJSONExportPath
            }
            $PrivilegedObject | Convertto-Json -Depth 10 | Out-File -Path "$SingleJSONExportPath/$($PrivilegedObject.ObjectId).json" -Force
        }
    }
    #endregion

    #region Identity Governance
    if ($RbacSystems -contains "IdentityGovernance") {
        $ExportFolder = "$($DefaultFolderClassifiedEam)/IdentityGovernance"

        $EamIdGov = Get-EntraOpsPrivilegedEAMIdGov
        $EamIdGov | Measure-Object
        $EamIdGov = $EamIdGov | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }

        if ((Test-Path -path "$($ExportFolder)")) {
            Remove-Item "$($ExportFolder)" -Force -Recurse
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        else {
            New-Item "$($ExportFolder)" -ItemType Directory -Force
        }
        $EamIdGov | Convertto-Json -Depth 10 | Out-File -Path "$($ExportFolder)/IdentityGovernance.json"
        foreach ($PrivilegedObject in $EamIdGov) {
            $ObjectType = $PrivilegedObject.ObjectType
            $SingleJSONExportPath = "$($ExportFolder)/$ObjectType"
            If (!(test-path $SingleJSONExportPath)) {
                New-Item -ItemType Directory -Force -Path $SingleJSONExportPath
            }
            $PrivilegedObject | Convertto-Json -Depth 10 | Out-File -Path "$SingleJSONExportPath/$($PrivilegedObject.ObjectId).json" -Force
        }
    }
    #endregion
}