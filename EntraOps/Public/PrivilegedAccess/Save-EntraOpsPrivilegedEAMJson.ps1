<#
.SYNOPSIS
    Export and save EntraOps Privileged EAM data to JSON files.

.DESCRIPTION
    Get information from EntraOps about classification based on Enterprise Access Model and save them as JSON to folder.

.PARAMETER ExportFolder
    Folder where the JSON files should be stored. Default is ./PrivilegedEAM.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.PARAMETER UseCache
    Use existing cache instead of clearing it before analysis. Default is $false (cache is cleared for fresh data).
    Set to $true to leverage cached data from previous calls for better performance.

.EXAMPLE
    Export and save JSON files of EntraOps to default folder
    Save-EntraOpsPrivilegedEAMJson

.EXAMPLE
    Export using cached data for better performance
    Save-EntraOpsPrivilegedEAMJson -UseCache $true
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
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$UseCache = $false
    )

    if (-not $UseCache) {
        Write-Output "Clearing cache before analyzing RBAC and classification data"
        Clear-EntraOpsCache
    } else {
        Write-Output "Using existing cache for analysis (UseCache = $true)"
        Write-Verbose "Current cache contains $($__EntraOpsSession.GraphCache.Count) entries"
    }

    #region Entra ID
    if ($RbacSystems -contains "EntraID") {
        $EntraExportFolder = "$($DefaultFolderClassifiedEam)/EntraID"

        if ((Test-Path -path "$($EntraExportFolder)")) {
            Write-Host "Cleaning up old files in $EntraExportFolder..." -ForegroundColor Gray
            $FilesToDelete = Get-ChildItem -Path "$($EntraExportFolder)" -Recurse -File -Force -ErrorAction SilentlyContinue
            $TotalToDelete = $FilesToDelete.Count
            
            if ($TotalToDelete -gt 0) {
               $i = 0
               foreach ($File in $FilesToDelete) {
                   $i++
                   if ($i % 20 -eq 0 -or $i -eq $TotalToDelete) {
                       Write-Progress -Activity "Cleaning up EntraID" -Status "Deleting file $i of $TotalToDelete" -PercentComplete (($i / $TotalToDelete) * 100)
                   }
                   Remove-Item $File.FullName -Force -ErrorAction SilentlyContinue
               }
            }
            Remove-Item "$($EntraExportFolder)" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
            Write-Progress -Activity "Cleaning up EntraID" -Completed
            New-Item "$($EntraExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($EntraExportFolder)" -ItemType Directory -Force | Out-Null
        }

        $EamAzureAD = Get-EntraOpsPrivilegedEAMEntraId

        if ($null -ne $EamAzureAD -and $EamAzureAD.Count -gt 0) {
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
        } else {
             Write-Warning "Result for Entra ID is empty because of an issue or empty entries in the RBAC system."
        }
    }
    #endregion

    #region Entra Resource Apps
    if ($RbacSystems -contains "ResourceApps") {
        $ResAppExportFolder = "$($DefaultFolderClassifiedEam)/ResourceApps"

        if ((Test-Path -path "$($ResAppExportFolder)")) {
            Write-Host "Cleaning up old files in $ResAppExportFolder..." -ForegroundColor Gray
            $FilesToDelete = Get-ChildItem -Path "$($ResAppExportFolder)" -Recurse -File -Force -ErrorAction SilentlyContinue
            $TotalToDelete = $FilesToDelete.Count
            
            if ($TotalToDelete -gt 0) {
               $i = 0
               foreach ($File in $FilesToDelete) {
                   $i++
                   if ($i % 20 -eq 0 -or $i -eq $TotalToDelete) {
                       Write-Progress -Activity "Cleaning up ResourceApps" -Status "Deleting file $i of $TotalToDelete" -PercentComplete (($i / $TotalToDelete) * 100)
                   }
                   Remove-Item $File.FullName -Force -ErrorAction SilentlyContinue
               }
            }
            Remove-Item "$($ResAppExportFolder)" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
            Write-Progress -Activity "Cleaning up ResourceApps" -Completed
            New-Item "$($ResAppExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($ResAppExportFolder)" -ItemType Directory -Force | Out-Null
        }

        $EamAzureAdResourceApps = Get-EntraOpsPrivilegedEAMResourceApps

        if ($null -ne $EamAzureAdResourceApps -and $EamAzureAdResourceApps.Count -gt 0) {
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
        } else {
             Write-Warning "Result for Resource Apps is empty because of an issue or empty entries in the RBAC system."
        }
    }
    #endregion

    #region Device Management
    if ($RbacSystems -contains "DeviceManagement") {
        $DevMgmtExportFolder = "$($DefaultFolderClassifiedEam)/DeviceManagement"

        if ((Test-Path -path "$($DevMgmtExportFolder)")) {
            Write-Host "Cleaning up old files in $DevMgmtExportFolder..." -ForegroundColor Gray
            $FilesToDelete = Get-ChildItem -Path "$($DevMgmtExportFolder)" -Recurse -File -Force -ErrorAction SilentlyContinue
            $TotalToDelete = $FilesToDelete.Count
            
            if ($TotalToDelete -gt 0) {
               $i = 0
               foreach ($File in $FilesToDelete) {
                   $i++
                   if ($i % 20 -eq 0 -or $i -eq $TotalToDelete) {
                       Write-Progress -Activity "Cleaning up DeviceManagement" -Status "Deleting file $i of $TotalToDelete" -PercentComplete (($i / $TotalToDelete) * 100)
                   }
                   Remove-Item $File.FullName -Force -ErrorAction SilentlyContinue
               }
            }
            Remove-Item "$($DevMgmtExportFolder)" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
            Write-Progress -Activity "Cleaning up DeviceManagement" -Completed
            New-Item "$($DevMgmtExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($DevMgmtExportFolder)" -ItemType Directory -Force | Out-Null
        }

        $EamDeviceMgmt = Get-EntraOpsPrivilegedEAMIntune

        if ($null -ne $EamDeviceMgmt -and $EamDeviceMgmt.Count -gt 0) {
            $EamDeviceMgmt = $EamDeviceMgmt | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
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
        } else {
             Write-Warning "Result for Device Management (Intune) is empty because of an issue or empty entries in the RBAC system."
        }
    }
    #endregion

    #region Identity Governance
    if ($RbacSystems -contains "IdentityGovernance") {
        $IdGovExportFolder = "$($DefaultFolderClassifiedEam)/IdentityGovernance"

        if ((Test-Path -path "$($IdGovExportFolder)")) {
            Write-Host "Cleaning up old files in $IdGovExportFolder..." -ForegroundColor Gray
            $FilesToDelete = Get-ChildItem -Path "$($IdGovExportFolder)" -Recurse -File -Force -ErrorAction SilentlyContinue
            $TotalToDelete = $FilesToDelete.Count
            
            if ($TotalToDelete -gt 0) {
               $i = 0
               foreach ($File in $FilesToDelete) {
                   $i++
                   if ($i % 20 -eq 0 -or $i -eq $TotalToDelete) {
                       Write-Progress -Activity "Cleaning up IdentityGovernance" -Status "Deleting file $i of $TotalToDelete" -PercentComplete (($i / $TotalToDelete) * 100)
                   }
                   Remove-Item $File.FullName -Force -ErrorAction SilentlyContinue
               }
            }
            Remove-Item "$($IdGovExportFolder)" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
            Write-Progress -Activity "Cleaning up IdentityGovernance" -Completed
            New-Item "$($IdGovExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($IdGovExportFolder)" -ItemType Directory -Force | Out-Null
        }

        $EamIdGov = Get-EntraOpsPrivilegedEAMIdGov
        $EamIdGov | Measure-Object

        if ($null -ne $EamIdGov -and $EamIdGov.Count -gt 0) {
            $EamIdGov = $EamIdGov | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
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
        } else {
             Write-Warning "Result for Identity Governance is empty because of an issue or empty entries in the RBAC system."
        }
    }
    #endregion
    #region Defender
    if ($RbacSystems -contains "Defender") {
        $DefenderExportFolder = "$($DefaultFolderClassifiedEam)/Defender"

        if ((Test-Path -path "$($DefenderExportFolder)")) {
            Write-Host "Cleaning up old files in $DefenderExportFolder..." -ForegroundColor Gray
            $FilesToDelete = Get-ChildItem -Path "$($DefenderExportFolder)" -Recurse -File -Force -ErrorAction SilentlyContinue
            $TotalToDelete = $FilesToDelete.Count
            
            if ($TotalToDelete -gt 0) {
               $i = 0
               foreach ($File in $FilesToDelete) {
                   $i++
                   if ($i % 20 -eq 0 -or $i -eq $TotalToDelete) {
                       Write-Progress -Activity "Cleaning up Defender" -Status "Deleting file $i of $TotalToDelete" -PercentComplete (($i / $TotalToDelete) * 100)
                   }
                   Remove-Item $File.FullName -Force -ErrorAction SilentlyContinue
               }
            }
            Remove-Item "$($DefenderExportFolder)" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
            Write-Progress -Activity "Cleaning up Defender" -Completed
            New-Item "$($DefenderExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($DefenderExportFolder)" -ItemType Directory -Force | Out-Null
        }

        $EamDefender = Get-EntraOpsPrivilegedEAMDefender
        $EamDefender | Measure-Object

        if ($null -ne $EamDefender -and $EamDefender.Count -gt 0) {
            $EamDefender = $EamDefender | where-object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId }
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
        } else {
             Write-Warning "Result for Defender is empty because of an issue or empty entries in the RBAC system."
        }
    }
    #endregion

    # Display Throttle Statistics Summary
    if ($__EntraOpsSession.ContainsKey('RetryStatistics') -and $__EntraOpsSession.RetryStatistics.TotalRetries -gt 0) {
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "  ⚠ API Throttling Summary" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        
        $Stats = $__EntraOpsSession.RetryStatistics
        Write-Host "  Total Retries       : $($Stats.TotalRetries)" -ForegroundColor Yellow
        Write-Host "  Throttled Requests  : $($Stats.ThrottledRequests)" -ForegroundColor Yellow
        
        if ($Stats.FailedRequests -gt 0) {
            Write-Host "  ❌ Failed Requests   : $($Stats.FailedRequests)" -ForegroundColor Red
            Write-Error "Some requests failed completely after exhausting retries. Check logs for details."
        } else {
            Write-Host "  ✓ All requests succeeded after retries" -ForegroundColor Green
        }
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host ""
    }
}