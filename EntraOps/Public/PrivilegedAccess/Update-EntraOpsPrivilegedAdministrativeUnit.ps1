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

    foreach ($RbacSystem in $RbacSystems) {

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
        if ($PrivilegedEamCount -gt 0) { Write-Warning "Numbers of objects without classification: $PrivilegedEamCount" }
        $PrivilegedEamClassifiedObjects = $PrivilegedEam | where-object { $_.Classification.AdminTierLevel -notcontains $null -and $_.RoleSystem -eq $RbacSystem }

        foreach ($TierLevel in $PrivilegedEamClassifications) {
            $AdminUnitId = $null
            $AdminUnitName = "Tier" + $TierLevel.EAMTierLevelTagValue + "-" + $TierLevel.EAMTierLevelName + "." + $RbacSystem
            $AdminUnitId = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$AdminUnitName'" -DisableCache).id
            if ($null -eq $AdminUnitId) {
                throw "Can not find any AU with the name $AdminUnitName"
            }
            $EntraOpsPrivilegedObjects = @()
            $EntraOpsPrivilegedObjects = ($PrivilegedEamClassifiedObjects | Where-Object { $_.Classification.AdminTierLevel -contains $TierLevel.EAMTierLevelTagValue -and $_.Classification.AdminTierLevelName -contains $TierLevel.EAMTierLevelName -and $_.RoleSystem -eq $RbacSystem })
            $CurrentAdminUnitMembers = @()
            $CurrentAdminUnitMembers = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/administrativeUnits/$($AdminUnitId)/members" -OutputType PSObject -DisableCache)

            # Check if AU members already exists for sync, or just adding new items
            if ($Null -eq $CurrentAdminUnitMembers.Id) {
                # Add all members to the AU
                $EntraOpsPrivilegedObjects | foreach-object {

                    $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($_.ObjectId)" -OutputType PSObject
                    $AdminUnitMemberObjectType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                    Write-Host "Adding $($AdminUnitMemberObjectType) $($AdminUnitMember.displayName) to $($AdminUnitName)"

                    $OdataBody = @{
                        '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($_.ObjectId)"
                    } | ConvertTo-Json
                    Invoke-EntraOpsMsGraphQuery -Method "POST" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -DisableCache -Body $OdataBody -OutputType PSObject
                }
            }
            # Check if privileged objects exists which should be synced to existing AU
            elseif ($null -ne $EntraOpsPrivilegedObjects.Id) {
                # Add or remove members from the AU which are not in scope of classification
                $Diff = Compare-Object $EntraOpsPrivilegedObjects.ObjectId $CurrentAdminUnitMembers.Id
                $Diff | ForEach-Object {
                    if ($_.SideIndicator -eq "=>") {
                        $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/directoryObjects/$($_.InputObject)" -OutputType PSObject
                        Write-Host "Removing $($AdminUnitMember.displayName) from $($AdminUnitName)"
                        try {
                            Invoke-EntraOpsMsGraphQuery -Method "DELETE" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/$($_.InputObject)/`$ref" -OutputType PSObject
                        } catch {
                            Write-Warning "Removal for $($AdminUnitMember.displayName) has been failed!"
                        }

                    } elseif ($_.SideIndicator -eq "<=") {
                        try {
                            $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($_.InputObject)" -DisableCache -OutputType PSObject
                            Write-Host "Adding $($AdminUnitMember.displayName) to $($AdminUnitName)"

                            $OdataBody = @{
                                '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($_.InputObject)"
                            } | ConvertTo-Json

                            Invoke-EntraOpsMsGraphQuery -Method "POST" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -DisableCache -Body $OdataBody -OutputType PSObject
                        } catch {
                            Write-Warning "Can not add $($AdminUnitMember.displayName)"
                            Write-Host $_.Exception
                        }
                    }
                }
            }
            # No privileged objects found for the AU, cleanup existing assignments
            else {
                Write-Warning "No privileges objects found for entire $($AdminUnitName). Skipping AU sync. Removing all existing members from $($AdminUnitName) will not be applied for security reasons. Remove them manually if needed."
            }
        }
        #endregion
    }
}