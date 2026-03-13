<#
.SYNOPSIS
    Updates (Restricted Management) Administrative Units based on EntraOps classification.

.DESCRIPTION
    (Restricted Management) Administrative Units for the different Enterprise Access Levels will be updated based on the classification of EntraOps.
    Objects will be assigned to the corresponding Administrative Units based on the classification.

.PARAMETER ApplyToAccessTierLevel
    Array of Access Tier Levels to be processed. Default is ControlPlane, ManagementPlane.

.PARAMETER FilterObjectType
    Array of object types to be processed. Default is User, Group. Service Principal and application objects are not supported to be assigned to AUs.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.EXAMPLE
    Update administrative units for EntraID, IdentityGovernance and ResourceApps RBAC systems with User and Group objectss
    Update-EntraOpsPrivilegedAdministrativeUnit -RbacSystems ("EntraID", "IdentityGovernance") -FilterObjectType ("User", "Group") -RestrictedAUMode "Selected"
#>

function Update-EntraOpsPrivilegedAdministrativeUnit {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet("ControlPlane", "ManagementPlane")]
        [Array]$ApplyToAccessTierLevel = ("ControlPlane", "ManagementPlane")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("User", "Group")]
        [Array]$FilterObjectType = ("User", "Group")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("None", "Selected", "All")]
        [string]$RestrictedAuMode = "Selected" #Default value will not create RMAU for Tier0 and EntraID and Identity Governance RBACs

    )

    $FirstPartyApps = Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json" | ConvertFrom-Json

    # Summary tracking across all AUs
    $SyncSummary = [System.Collections.Generic.List[psobject]]::new()
    $TotalAdded = 0
    $TotalRemoved = 0
    $TotalSkipped = 0
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " EntraOps - Administrative Unit Sync" -ForegroundColor Cyan
    Write-Host " RBAC Systems : $($RbacSystems -join ', ')" -ForegroundColor Cyan
    Write-Host " Access Tiers : $($ApplyToAccessTierLevel -join ', ')" -ForegroundColor Cyan
    Write-Host " Object Types : $($FilterObjectType -join ', ')" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""

    $RbacSystemCounter = 0
    foreach ($RbacSystem in $RbacSystems) {
        $RbacSystemCounter++
        Write-Progress -Activity "Updating Administrative Units" -Status "Processing RBAC system $RbacSystemCounter of $($RbacSystems.Count): $RbacSystem" -PercentComplete (($RbacSystemCounter / $RbacSystems.Count) * 100)
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " RBAC System: $RbacSystem ($RbacSystemCounter/$($RbacSystems.Count))" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        # Get EAM classification files
        if ($RbacSystem -eq "EntraID") {
            $ClassificationTemplateSubFolder = "AadResources"
        } elseif ($RbacSystem -eq "ResourceApps") {
            $ClassificationTemplateSubFolder = "AppRoles"
        } else {
            $ClassificationTemplateSubFolder = $RbacSystem
        }
        $Classification = "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json"
        $ClassificationTemplates = "$DefaultFolderClassification/Templates/Classification_$($ClassificationTemplateSubFolder).json"

        $PrivilegedEamClassificationFiles = @()
        $PrivilegedEamClassificationFiles = Get-ChildItem -Path $ClassificationTemplates -Filter "*.json"
        $PrivilegedEamClassifications = $PrivilegedEamClassificationFiles | foreach-object { Get-Content -Path $_.FullName | ConvertFrom-Json } | where-object { $_.EAMTierLevelName -in $ApplyToAccessTierLevel } | select-object -unique EAMTierLevelName, EAMTierLevelTagValue

        #region Assign all principals in Privileged EAM to restricted AUs
        $PrivilegedEam = @()
        $PrivilegedEam += Get-ChildItem -Path $Classification | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
        $PrivilegedEam = $PrivilegedEam | Where-Object { $_.ObjectType -in $FilterObjectType }    

        $PrivilegedEamCount = ($PrivilegedEam | Where-Object { $null -eq $_.Classification }).count
        if ($PrivilegedEamCount -gt 0) {
            Write-Warning "Numbers of objects without classification: $PrivilegedEamCount"
            $WarningMessages.Add([PSCustomObject]@{ Type = "UnclassifiedObjects"; Message = "$PrivilegedEamCount object(s) without classification in $RbacSystem" })
        }
        $PrivilegedEamClassifiedObjects = $PrivilegedEam | where-object { $_.Classification.AdminTierLevel -notcontains $null -and $_.RoleSystem -eq $RbacSystem }

        $TierLevelIndex = 0
        foreach ($TierLevel in $PrivilegedEamClassifications) {
            $TierLevelIndex++
            Write-Progress -Activity "Updating Administrative Units" -Status "$RbacSystem - Processing tier $TierLevelIndex of $($PrivilegedEamClassifications.Count): Tier$($TierLevel.EAMTierLevelTagValue)-$($TierLevel.EAMTierLevelName)" -PercentComplete (($TierLevelIndex / $PrivilegedEamClassifications.Count) * 100)
            
            $AdminUnitId = $null
            $AdminUnitName = "Tier" + $TierLevel.EAMTierLevelTagValue + "-" + $TierLevel.EAMTierLevelName + "." + $RbacSystem
            $AuAdded = 0
            $AuRemoved = 0
            $AuFailed = 0
            $AuStatus = "OK"

            Write-Host ""
            Write-Host "  AU: $AdminUnitName" -ForegroundColor White

            $AdminUnitId = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$AdminUnitName'" -DisableCache).id
            if ($null -eq $AdminUnitId) {
                Write-Warning "  [SKIP] Could not find AU: $AdminUnitName"
                $WarningMessages.Add([PSCustomObject]@{ Type = "AuNotFound"; Message = "Could not find AU: $AdminUnitName" })
                $SyncSummary.Add([PSCustomObject]@{
                        RbacSystem    = $RbacSystem
                        AdminUnit     = $AdminUnitName
                        MembersBefore = "N/A"
                        Added         = 0
                        Removed       = 0
                        Failed        = 0
                        Status        = "NOT FOUND"
                    })
                continue
            }

            $EntraOpsPrivilegedObjects = @()
            $EntraOpsPrivilegedObjects = ($PrivilegedEamClassifiedObjects | Where-Object { $_.Classification.AdminTierLevel -contains $TierLevel.EAMTierLevelTagValue -and $_.Classification.AdminTierLevelName -contains $TierLevel.EAMTierLevelName -and $_.RoleSystem -eq $RbacSystem })
            $CurrentAdminUnitMembers = @()
            $CurrentAdminUnitMembers = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members" -OutputType PSObject -DisableCache)

            $CurrentMemberCount = @($CurrentAdminUnitMembers.Id).Count
            $DesiredMemberCount = @($EntraOpsPrivilegedObjects.ObjectId).Count
            Write-Host "  Current members : $CurrentMemberCount | Desired: $DesiredMemberCount" -ForegroundColor Gray

            # Check if AU members already exists for sync, or just adding new items
            if ($Null -eq $CurrentAdminUnitMembers.Id) {
                Write-Host "  AU is empty - adding all $DesiredMemberCount objects" -ForegroundColor Yellow
                # Add all members to the AU
                foreach ($PrivObj in $EntraOpsPrivilegedObjects) {
                    try {
                        $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($PrivObj.ObjectId)" -OutputType PSObject
                        $AdminUnitMemberObjectType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                        Write-Host "  [+] ADD  [$AdminUnitMemberObjectType] $($AdminUnitMember.displayName)" -ForegroundColor Green

                        $OdataBody = @{
                            '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($PrivObj.ObjectId)"
                        } | ConvertTo-Json
                        Invoke-EntraOpsMsGraphQuery -Method "POST" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -DisableCache -Body $OdataBody -OutputType PSObject
                        $AuAdded++
                    } catch {
                        Write-Warning "  [!] FAIL ADD $($PrivObj.ObjectId): $_"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "FAIL ADD $($PrivObj.ObjectId) to $AdminUnitName`: $_" })
                        $AuFailed++
                    }
                }
            }
            # Check if privileged objects exists which should be synced to existing AU
            elseif ($null -ne $EntraOpsPrivilegedObjects.ObjectId) {
                # Add or remove members from the AU which are not in scope of classification
                $Diff = Compare-Object $($EntraOpsPrivilegedObjects.ObjectId) $($CurrentAdminUnitMembers.Id)
                $ToRemove = @($Diff | Where-Object { $_.SideIndicator -eq "=>" })
                $ToAdd = @($Diff | Where-Object { $_.SideIndicator -eq "<=" })

                if ($Diff.Count -eq 0) {
                    Write-Host "  No changes required - AU is already in sync" -ForegroundColor DarkGreen
                } else {
                    Write-Host "  Delta: +$($ToAdd.Count) to add  -$($ToRemove.Count) to remove" -ForegroundColor Yellow
                }

                foreach ($Entry in $ToRemove) {
                    try {
                        $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/directoryObjects/$($Entry.InputObject)" -OutputType PSObject
                        $MemberType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                        Write-Host "  [-] REM  [$MemberType] $($AdminUnitMember.displayName)" -ForegroundColor Yellow
                        Invoke-EntraOpsMsGraphQuery -Method "DELETE" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/$($Entry.InputObject)/`$ref" -OutputType PSObject
                        $AuRemoved++
                    } catch {
                        Write-Warning "  [!] FAIL REMOVE $($Entry.InputObject): $_"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "FAIL REMOVE $($Entry.InputObject) from $AdminUnitName`: $_" })
                        $AuFailed++
                    }
                }

                foreach ($Entry in $ToAdd) {
                    try {
                        $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($Entry.InputObject)" -DisableCache -OutputType PSObject
                        $MemberType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                        Write-Host "  [+] ADD  [$MemberType] $($AdminUnitMember.displayName)" -ForegroundColor Green

                        $OdataBody = @{
                            '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($Entry.InputObject)"
                        } | ConvertTo-Json

                        Invoke-EntraOpsMsGraphQuery -Method "POST" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -DisableCache -Body $OdataBody -OutputType PSObject
                        $AuAdded++
                    } catch {
                        Write-Warning "  [!] FAIL ADD $($Entry.InputObject): $_"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "FAIL ADD $($Entry.InputObject) to $AdminUnitName`: $_" })
                        $AuFailed++
                    }
                }
            }
            # No privileged objects found for the AU, cleanup existing assignments
            else {
                Write-Warning "  [SKIP] No classified objects found for $AdminUnitName. Existing members untouched for safety - remove manually if needed."
                $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No classified objects found for $AdminUnitName - existing members untouched" })
                $AuStatus = "SKIPPED"
            }

            if ($AuFailed -gt 0) { $AuStatus = "ERRORS" }
            $TotalAdded += $AuAdded
            $TotalRemoved += $AuRemoved

            $SyncSummary.Add([PSCustomObject]@{
                    RbacSystem    = $RbacSystem
                    AdminUnit     = $AdminUnitName
                    MembersBefore = $CurrentMemberCount
                    Added         = $AuAdded
                    Removed       = $AuRemoved
                    Failed        = $AuFailed
                    Status        = $AuStatus
                })
        }
        #endregion
    }

    # Final summary
    Write-Host ""
    Write-Host "========================================================="  -ForegroundColor Cyan
    Write-Host " Administrative Unit Sync - Complete" -ForegroundColor Cyan
    Write-Host "  Total added  : $TotalAdded" -ForegroundColor Green
    Write-Host "  Total removed: $TotalRemoved" -ForegroundColor Yellow
    if (($SyncSummary | Where-Object { $_.Failed -gt 0 }).Count -gt 0) {
        Write-Host "  Failures     : $(($SyncSummary | Measure-Object -Property Failed -Sum).Sum)" -ForegroundColor Red
    }
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages
    $SyncSummary | Format-Table -AutoSize -Property RbacSystem, AdminUnit, MembersBefore,
    @{Name = 'Added'; Expression = { $_.Added }; Align = 'Right' },
    @{Name = 'Removed'; Expression = { $_.Removed }; Align = 'Right' },
    @{Name = 'Failed'; Expression = { $_.Failed }; Align = 'Right' },
    Status
}