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
        [ValidateSet("EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")
    )

    Write-Output "Clearing cache before analyzing RBAC and classification data"
    Clear-EntraOpsCache

    #region Entra ID
    if ($RbacSystems -contains "EntraID") {
        $EntraExportFolder = "$($DefaultFolderClassifiedEam)/EntraID"

        if ((Test-Path -path "$($EntraExportFolder)")) {
            Remove-Item "$($EntraExportFolder)" -Force -Recurse | Out-Null
            New-Item "$($EntraExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($EntraExportFolder)" -ItemType Directory -Force | Out-Null
        }

        $EamAzureAD = Get-EntraOpsPrivilegedEamEntraId
        $EamAzureAD = $EamAzureAD | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        $EamAzureAD = $EamAzureAD | sort-object ObjectDisplayName, ObjectType
        $EamAzureAD | Convertto-Json -Depth 10 | Out-File -Path "$($EntraExportFolder)/EntraID.json" -Force
        
        # Optimization: Create directories first
        $EamAzureAD | Group-Object ObjectType | ForEach-Object {
             $Dir = "$($EntraExportFolder)/$($_.Name)"
             if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        }

        # Optimization: Parallel File Write
        $EamAzureAD | ForEach-Object -Parallel {
            $Obj = $_
            $Path = "$using:EntraExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
        } -ThrottleLimit 50
    }
    #endregion

    #region Entra Resource Apps
    if ($RbacSystems -contains "ResourceApps") {
        $ResAppExportFolder = "$($DefaultFolderClassifiedEam)/ResourceApps"

        if ((Test-Path -path "$($ResAppExportFolder)")) {
            Remove-Item "$($ResAppExportFolder)" -Force -Recurse | Out-Null
            New-Item "$($ResAppExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($ResAppExportFolder)" -ItemType Directory -Force | Out-Null
        }

        $EamAzureAdResourceApps = Get-EntraOpsPrivilegedEamResourceApps
        $EamAzureAdResourceApps = $EamAzureAdResourceApps | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
        $EamAzureAdResourceApps | Convertto-Json -Depth 10 | Out-File -Path "$($ResAppExportFolder)/ResourceApps.json"

        # Optimization: Create directories first
        $EamAzureAdResourceApps | Group-Object ObjectType | ForEach-Object {
             $Dir = "$($ResAppExportFolder)/$($_.Name)"
             if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        }

        # Optimization: Parallel File Write
        $EamAzureAdResourceApps | ForEach-Object -Parallel {
            $Obj = $_
            $Path = "$using:ResAppExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
        } -ThrottleLimit 50
    }
    #endregion

    #region Device Management
    if ($RbacSystems -contains "DeviceManagement") {
        $DevMgmtExportFolder = "$($DefaultFolderClassifiedEam)/DeviceManagement"
        $EamDeviceMgmt = Get-EntraOpsPrivilegedEAMIntune
        $EamDeviceMgmt = $EamDeviceMgmt | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }

        if ((Test-Path -path "$($DevMgmtExportFolder)")) {
            Remove-Item "$($DevMgmtExportFolder)" -Force -Recurse | Out-Null
            New-Item "$($DevMgmtExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($DevMgmtExportFolder)" -ItemType Directory -Force | Out-Null
        }
        $EamDeviceMgmt | Convertto-Json -Depth 10 | Out-File -Path "$($DevMgmtExportFolder)/DeviceManagement.json"
        
        # Optimization: Create directories first
        $EamDeviceMgmt | Group-Object ObjectType | ForEach-Object {
             $Dir = "$($DevMgmtExportFolder)/$($_.Name)"
             if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        }

        # Optimization: Parallel File Write
        $EamDeviceMgmt | ForEach-Object -Parallel {
            $Obj = $_
            $Path = "$using:DevMgmtExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
        } -ThrottleLimit 50
    }
    #endregion

    #region Identity Governance
    if ($RbacSystems -contains "IdentityGovernance") {
        $IdGovExportFolder = "$($DefaultFolderClassifiedEam)/IdentityGovernance"

        $EamIdGov = Get-EntraOpsPrivilegedEAMIdGov
        $EamIdGov | Measure-Object
        $EamIdGov = $EamIdGov | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }

        if ((Test-Path -path "$($IdGovExportFolder)")) {
            Remove-Item "$($IdGovExportFolder)" -Force -Recurse | Out-Null
            New-Item "$($IdGovExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($IdGovExportFolder)" -ItemType Directory -Force | Out-Null
        }
        $EamIdGov | Convertto-Json -Depth 10 | Out-File -Path "$($IdGovExportFolder)/IdentityGovernance.json"
        
        # Optimization: Create directories first
        $EamIdGov | Group-Object ObjectType | ForEach-Object {
             $Dir = "$($IdGovExportFolder)/$($_.Name)"
             if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        }

        # Optimization: Parallel File Write
        $EamIdGov | ForEach-Object -Parallel {
            $Obj = $_
            $Path = "$using:IdGovExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
        } -ThrottleLimit 50
    }
    #endregion
    #region Defender
    if ($RbacSystems -contains "Defender") {
        $DefenderExportFolder = "$($DefaultFolderClassifiedEam)/Defender"

        $EamDefender = Get-EntraOpsPrivilegedEAMDefender
        $EamDefender | Measure-Object
        $EamDefender = $EamDefender | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }

        if ((Test-Path -path "$($DefenderExportFolder)")) {
            Remove-Item "$($DefenderExportFolder)" -Force -Recurse | Out-Null
            New-Item "$($DefenderExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($DefenderExportFolder)" -ItemType Directory -Force | Out-Null
        }
        $EamDefender | Convertto-Json -Depth 10 | Out-File -Path "$($DefenderExportFolder)/Defender.json"
        
        # Optimization: Create directories first
        $EamDefender | Group-Object ObjectType | ForEach-Object {
             $Dir = "$($DefenderExportFolder)/$($_.Name)"
             if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        }

        # Optimization: Parallel File Write
        $EamDefender | ForEach-Object -Parallel {
            $Obj = $_
            $Path = "$using:DefenderExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
        } -ThrottleLimit 50
    }
    #endregion
}