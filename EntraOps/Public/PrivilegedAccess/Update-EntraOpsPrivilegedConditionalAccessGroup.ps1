<#
.SYNOPSIS
    Update membership on security groups based on EntraOps classification which can be used for targeting Conditional Access policies.

.DESCRIPTION
    Security Groups for the different Enterprise Access Levels will be updated based on the classification of EntraOps.
    Objects will be assigned to the corresponding Administrative Units based on the classification.
    This security groups can be used for targeting Conditional Access policies.

.PARAMETER ApplyToAccessTierLevel
    Array of Access Tier Levels to be processed. Default is ControlPlane, ManagementPlane.

.PARAMETER FilterObjectType
    Array of object types to be processed. Default is User, Group.

.PARAMETER GroupPrefix
    String to define the prefix of the Conditional Access Inclusion Groups. Default is "sug_Entra.CA.IncludeUsers.PrivilegedAccounts."

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.EXAMPLE
    Update Conditional Access Target Groups for EntraID, IdentityGovernance and ResourceApps RBAC systems with assigned User and Group objects
    Update-EntraOpsPrivilegedConditionalAccessGroup -GroupPrefix "sug_Entra.CA.IncludeUsers.PrivilegedAccounts." -RbacSystems ("EntraID", "IdentityGovernance")
#>

function Update-EntraOpsPrivilegedConditionalAccessGroup {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet("ControlPlane", "ManagementPlane")]
        [Array]$ApplyToAccessTierLevel = ("ControlPlane", "ManagementPlane")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("User", "Group")]
        [Array] $FilterObjectType = ("User", "Group")
        ,
        [Parameter(Mandatory = $False)]
        [string]$GroupPrefix = "sug_Entra.CA.IncludeUsers.PrivilegedAccounts."
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("EntraID", "IdentityGovernance", "DeviceManagement", "Defender")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "DeviceManagement", "Defender")
        ,
        [Parameter(Mandatory = $false)]
        [String]$AdminUnitName
    )


    # Get all unique AdminTierLevels which needs to be iterated for assigning objects to Conditional Access Target Groups
    $PrivilegedEamTierLevels = Get-ChildItem -Path "$($DefaultFolderClassification)/Templates" -File -Recurse -Exclude *.Param.json | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
    $SelectedPrivilegedEamTierLevels = $PrivilegedEamTierLevels | where-object { $_.EAMTierLevelName -in $ApplyToAccessTierLevel } | select-object -unique @{Name = 'AdminTierLevel'; Expression = 'EAMTierLevelTagValue' }, @{Name = 'AdminTierLevelName'; Expression = 'EAMTierLevelName' }
    #endregion

    foreach ($RbacSystem in $RbacSystems) {

        $ClassificationEamFile = "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json"

        #region Get principals from EAM classification files and filter out objects without classification and objects not related to the RBAC system or object type filter
        $PrivilegedEam = @()
        $PrivilegedEam += Get-ChildItem -Path $ClassificationEamFile | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
        $PrivilegedEam = $PrivilegedEam | Where-Object { $_.ObjectType -in $FilterObjectType }
        $PrivilegedEamCount = ($PrivilegedEam | Where-Object { $null -eq $_.ClassificationEamFile }).count
        if ($PrivilegedEamCount -gt 0) { Write-Warning "Numbers of objects without classification: $PrivilegedEamCount" }
        $PrivilegedEamClassifiedObjects = $PrivilegedEam | where-object { $_.Classification.AdminTierLevel -notcontains $null -and $_.RoleSystem -eq $RbacSystem }

        #region Assign all principals in Privileged EAM to Conditional Access Target Groups
        foreach ($TierLevel in $SelectedPrivilegedEamTierLevels) {
            $GroupName = "$GroupPrefix" + $TierLevel.AdminTierLevelName + "." + $($RbacSystem)
            $GroupId = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/v1.0/groups?`$filter=DisplayName eq '$GroupName'" -OutputType PSObject -DisableCache).id
            $PrivilegedObjects = @()
            $PrivilegedObjects = ($PrivilegedEamClassifiedObjects | Where-Object { $_.Classification.AdminTierLevelName -contains $TierLevel.AdminTierLevelName -and $_.RoleSystem -eq $RbacSystem })
            $CurrentGroupMembers = @()
            $CurrentGroupMembers = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/groups/$($GroupId)/members" -OutputType PSObject -DisableCache)

            # Check if group members already exists for sync, or just adding new items
            if ($Null -eq $CurrentGroupMembers.Id) {
                $PrivilegedObjects | foreach-object {
                    $GroupMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/directoryObjects/$($_.ObjectId)" -DisableCache -OutputType PSObject
                    Write-Host "Adding $($GroupMember.displayName) to $($GroupName)"

                    $OdataBody = @{
                        '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($_.ObjectId)"
                    } | ConvertTo-Json

                    try {
                        Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/groups/$($GroupId)/members/`$ref" -Body $OdataBody -OutputType PSObject
                    } catch {
                        Write-Warning "Failed to add $($GroupMember.displayName) to $($GroupName). Error: $_"
                    }
                }
            } elseif ($null -ne $PrivilegedObjects.ObjectId) {
                Compare-Object $PrivilegedObjects.ObjectId $CurrentGroupMembers.Id | ForEach-Object {
                    if ($_.SideIndicator -eq "=>") {
                        Write-Warning "$($_.InputObject) will be removed from $($GroupName)!"
                        Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/beta/groups/$($GroupId)/members/$($_.InputObject)/`$ref" -OutputType PSObject
                    } elseif ($_.SideIndicator -eq "<=") {
                        $GroupMember = Invoke-MgGraphRequest -Method GET -Uri "/beta/directoryObjects/$($_.InputObject)" -OutputType PSObject
                        Write-Host "Adding $($GroupMember.displayName) to $($GroupName)"

                        $OdataBody = @{
                            '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($_.InputObject)"
                        } | ConvertTo-Json

                        Invoke-MgGraphRequest -Method POST -Uri "/beta/groups/$($GroupId)/members/`$ref" -Body $OdataBody -OutputType PSObject
                    }
                }
            }
            # No privileged objects found for the AU, cleanup existing assignments
            else {
                Write-Warning "No privileges objects found for entire $($GroupName). Skipping CA group sync. Removing all existing members from $($AdminUnitName) will not be applied for security reasons. Remove them manually if needed."
            }
        }
        #endregion
    }
}