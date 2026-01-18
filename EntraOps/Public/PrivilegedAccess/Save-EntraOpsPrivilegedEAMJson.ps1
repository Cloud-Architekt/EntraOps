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

    #region Initialize and Clear Cache
    Write-Output "Clearing cache before analyzing RBAC and classification data"
    Clear-EntraOpsCache
    #endregion

    #region Parallel Processing: Entra ID and Resource Apps
    # These two RBAC systems can be processed in parallel as they are independent
    Write-Host "Starting parallel processing of EntraID and ResourceApps..."
    
    $ParallelJobs = @()
    
    # Job 1: Entra ID
    if ($RbacSystems -contains "EntraID") {
        $ParallelJobs += @{
            Name        = "EntraID"
            ScriptBlock = {
                param($DefaultFolderClassifiedEam)
                
                $EntraExportFolder = "$DefaultFolderClassifiedEam/EntraID"

                if ((Test-Path -path "$EntraExportFolder")) {
                    Remove-Item "$EntraExportFolder" -Force -Recurse
                    New-Item "$EntraExportFolder" -ItemType Directory -Force | Out-Null
                } else {
                    New-Item "$EntraExportFolder" -ItemType Directory -Force | Out-Null
                }

                Write-Host "Processing EntraID RBAC system..."
                $EamAzureAD = Get-EntraOpsPrivilegedEamEntraId
                $EamAzureAD | Convertto-Json -Depth 10 | Out-File -Path "$EntraExportFolder/EntraID.json" -Force
                
                # Create directories first
                $EamAzureAD | Group-Object ObjectType | ForEach-Object {
                    $Dir = "$EntraExportFolder/$($_.Name)"
                    if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
                }

                # Parallel File Write
                $EamAzureAD | ForEach-Object -Parallel {
                    $Obj = $_
                    $Path = "$using:EntraExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
                    $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
                } -ThrottleLimit 50
                
                Write-Host "Completed EntraID processing: $($EamAzureAD.Count) objects exported"
            }
        }
    }
    
    # Job 2: Resource Apps
    if ($RbacSystems -contains "ResourceApps") {
        $ParallelJobs += @{
            Name        = "ResourceApps"
            ScriptBlock = {
                param($DefaultFolderClassifiedEam)
                
                $ResAppExportFolder = "$DefaultFolderClassifiedEam/ResourceApps"

                if ((Test-Path -path "$ResAppExportFolder")) {
                    Remove-Item "$ResAppExportFolder" -Force -Recurse
                    New-Item "$ResAppExportFolder" -ItemType Directory -Force | Out-Null
                    Sequential Processing: Device Management
                    # Must be processed sequentially after parallel jobs
                    if ($RbacSystems -contains "DeviceManagement") {
                        Write-Host "Processing DeviceManagement RBAC system..."
                        $DevMgmtExportFolder = "$($DefaultFolderClassifiedEam)/DeviceManagement"
                        $EamDeviceMgmt = Get-EntraOpsPrivilegedEAMIntune

                        if ((Test-Path -path "$($DevMgmtExportFolder)")) {
                            Remove-Item "$($DevMgmtExportFolder)" -Force -Recurse
                            New-Item "$($DevMgmtExportFolder)" -ItemType Directory -Force | Out-Null
                        } else {
                            New-Item "$($DevMgmtExportFolder)" -ItemType Directory -Force | Out-Null
                        }
                        $EamDeviceMgmt | Convertto-Json -Depth 10 | Out-File -Path "$($DevMgmtExportFolder)/DeviceManagement.json" -Force
        
                        # Create directories first
                        $EamDeviceMgmt | Group-Object ObjectType | ForEach-Object {
                            $Dir = "$($DevMgmtExportFolder)/$($_.Name)"
                            if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
                        }

                        # Parallel File Write
                        $EamDeviceMgmt | ForEach-Object -Parallel {
                            $Obj = $_
                            $Path = "$using:DevMgmtExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
                            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
                        } -ThrottleLimit 50
        
                        WritSequential Processing: Identity Governance
                        # Must be processed sequentially in defined order
                        if ($RbacSystems -contains "IdentityGovernance") {
                            Write-Host "Processing IdentityGovernance RBAC system..."
                            $IdGovExportFolder = "$($DefaultFolderClassifiedEam)/IdentityGovernance"

                            $EamIdGov = Get-EntraOpsPrivilegedEAMIdGov
                            $EamIdGov | Measure-Object

                            if ((Test-Path -path "$($IdGovExportFolder)")) {
                                Remove-Item "$($IdGovExportFolder)" -Force -Recurse
                                New-Item "$($IdGovExportFolder)" -ItemType Directory -Force | Out-Null
                            } else {
                                New-Item "$($IdGovExportFolder)" -ItemType Directory -Force | Out-Null
                            }
                            $EamIdGov | Convertto-Json -Depth 10 | Out-File -Path "$($IdGovExportFolder)/IdentityGovernance.json" -Force
        
                            # Create directories first
                            $EamIdGov | Group-Object ObjectType | ForEach-Object {
                                $Dir = "$($IdGovExportFolder)/$($_.Name)"
                                if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
                            }

                            # Parallel File Write
                            $EamIdGov | ForEach-Object -Parallel {
                                $Obj = $_
                                $Path = "$using:IdGovExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
                                $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
                            } -ThrottleLimit 50
        
                            Write-Host "Completed IdentityGovernance processing: $($EamIdGov.Count) objects exported"
                            New-Item "$($DevMgmtExportFolder)" -ItemType Directory -Force
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

                        if ((Test-Path -path "$($IdGovExportFolder)")) {
                            Remove-Item "$($IdGovExportFolder)" -Force -Recurse
                            New-Item "$($IdGovExportFolder)" -ItemType Directory -Force
                        } else {
                            New-Item "$($IdGovExportFolder)" -ItemType Directory -Force
                        }
                        $EamIdGov | Convertto-Json -Depth 10 | Out-File -Path "$($IdGovExportFolder)/IdentityGovernance.json"
        
                        # Optimization: Create directories first
                        $EamIdGov | Group-Object ObjectType | ForEach-Object {
                            $Dir = "$($IdGovExportFolder)/$($_.Name)"
                            if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
                        }

                        # OpSequential Processing: Defender
                        # Must be processed sequentially in defined order
                        if ($RbacSystems -contains "Defender") {
                            Write-Host "Processing Defender RBAC system..."
                            $DefenderExportFolder = "$($DefaultFolderClassifiedEam)/Defender"

                            $EamDefender = Get-EntraOpsPrivilegedEAMDefender
                            $EamDefender | Measure-Object

                            if ((Test-Path -path "$($DefenderExportFolder)")) {
                                Remove-Item "$($DefenderExportFolder)" -Force -Recurse
                                New-Item "$($DefenderExportFolder)" -ItemType Directory -Force | Out-Null
                            } else {
                                New-Item "$($DefenderExportFolder)" -ItemType Directory -Force | Out-Null
                            }
                            $EamDefender | Convertto-Json -Depth 10 | Out-File -Path "$($DefenderExportFolder)/Defender.json" -Force
        
                            # Create directories first
                            $EamDefender | Group-Object ObjectType | ForEach-Object {
                                $Dir = "$($DefenderExportFolder)/$($_.Name)"
                                if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
                            }

                            # Parallel File Write
                            $EamDefender | ForEach-Object -Parallel {
                                $Obj = $_
                                $Path = "$using:DefenderExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
                                $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
                            } -ThrottleLimit 50
        
                            Write-Host "Completed Defender processing: $($EamDefender.Count) objects exported"
                        }
                        #endregion
    
                        Write-Host "`nAll RBAC systems processing completed successfully!"
                        # Optimization: Parallel File Write
                        $EamDefender | ForEach-Object -Parallel {
                            $Obj = $_
                            $Path = "$using:DefenderExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
                            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
                        } -ThrottleLimit 50
                    }
                    #endregion
                }