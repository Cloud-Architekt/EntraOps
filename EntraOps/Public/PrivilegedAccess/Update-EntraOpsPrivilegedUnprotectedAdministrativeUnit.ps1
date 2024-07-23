<#
.SYNOPSIS
    Add privileged users without any protection (by role-assignable groups, assigned directory role or existing RMAU membership) to an Restricted Management Administrative Units to avoid delegated management by lower privileged user.

.DESCRIPTION
    Add privileged users without any protection (by role-assignable groups, assigned directory role or existing RMAU membership) to an Restricted Management Administrative Units to avoid delegated management by lower privileged user.

.PARAMETER ApplyToAccessTierLevel
    Array of Access Tier Levels to be processed. Default is ControlPlane, ManagementPlane.

.PARAMETER FilterObjectType
    Array of object types to be processed. Default is User, Group. Service Principal and application objects are not supported to be protected by RMAU.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.EXAMPLE
    Assign privileged users without any protection but privileges in RBAC Systems "IdentityGovernance" to Restricted Management Administrative Units
    Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit -RbacSystems ("IdentityGovernance")
#>

function Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit {

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
        [ValidateSet("EntraID", "IdentityGovernance", "DeviceManagement")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance")
    )

    # Get all privileged EAM objects
    $PrivilegedEamObjects = foreach ($RbacSystem in $RbacSystems) {
        Get-Content "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json" | ConvertFrom-Json
    }

    # Get all privileged EAM objects without any restricted management and their tier levels
    $UnprotectedPrivilegedUser = $PrivilegedEamObjects | Where-Object { $_.RestrictedManagementByRAG -ne $True -and $_.RestrictedManagementByAadRole -ne $True -and $_.RestrictedManagementByRMAU -ne $True -and $_.ObjectType -in $FilterObjectType }

    # Get all unique AdminTierLevels which needs to be iterated for assigning objects to Conditional Access Target Groups
    $PrivilegedEamClassificationTierLevels = $UnprotectedPrivilegedUser | ForEach-Object {
        $Classification = $_.Classification
        $Classification | where-object { $_.AdminTierLevelName -in $ApplyToAccessTierLevel } | select-object -unique AdminTierLevel, AdminTierLevelName
    }
    $PrivilegedEamTierLevels = $PrivilegedEamClassificationTierLevels | select-object -unique AdminTierLevel, AdminTierLevelName

    #region Assign all unprotected principals in Privileged EAM to restricted AUs or remove from RMAU if no longer privileged
    foreach ($TierLevel in $PrivilegedEamTierLevels) {

        # Get Administrative Unit Id for related tier level
        $AdminUnitId = $null
        $AdminUnitName = "Tier" + $TierLevel.AdminTierLevel + "-" + $TierLevel.AdminTierLevelName + ".UnprotectedAccounts"
        $AdminUnitId = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$AdminUnitName'" -DisableCache -OutputType PSObject).id

        if ($null -eq $AdminUnitId) {
            throw "Can not find any AU with the name $AdminUnitName! Error: $_"
        }

        # Get privileged object for related tier level
        $UnprotectedPrivilegedUserOnTierLevel = ($UnprotectedPrivilegedUser | Where-Object { $_.Classification.AdminTierLevel -contains $TierLevel.AdminTierLevel -and $_.Classification.AdminTierLevelName -contains $TierLevel.AdminTierLevelName })
        $CurrentAdminUnitMembers = @()
        $CurrentAdminUnitMembers = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/administrativeUnits/$($AdminUnitId)/members" -OutputType PSObject -DisableCache)

        # Check if AU members already exists
        if ($null -eq $CurrentAdminUnitMembers.Id) {
            $UnprotectedPrivilegedUserOnTierLevel | foreach-object {

                $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/directoryObjects/$($_.ObjectId)" -OutputType PSObject -DisableCache
                $AdminUnitMemberObjectType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                Write-Host "Adding $($AdminUnitMemberObjectType) $($AdminUnitMember.displayName) to $($AdminUnitName)"

                $OdataBody = @{
                    '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($_.ObjectId)"
                } | ConvertTo-Json

                Invoke-EntraOpsMsGraphQuery -Method "POST" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -Body $OdataBody -OutputType PSObject
            }
        }
        elseif ($null -eq $UnprotectedPrivilegedUserOnTierLevel) {

            # Keep user in RMAU if no other RMAU is protecting the user or user is no longer privileged
            $CurrentAdminUnitMembers | ForEach-Object {

                $AssignmentsToAUs = (Invoke-EntraOpsMsGraphQuery -Uri "/beta/users/$($_.id)/memberOf/Microsoft.Graph.AdministrativeUnit" -OutputType PSObject -DisableCache).value
                $AssignmentsToOtherRMAUs = $AssignmentsToAUs | Where-Object { $_.isMemberManagementRestricted -eq $True -and $_.id -ne $AdminUnitId }

                if ($null -ne $AssignmentsToOtherRMAUs -or $_.id -notin $($PrivilegedEamObjects.ObjectId)) {
                    $CurrentAdminUnitMembers | ForEach-Object {
                        try {
                            $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($_.Id)" -OutputType PSObject -DisableCache
                            Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/$($_.Id)/`$ref" -OutputType PSObject -DisableCache
                        }
                        catch {
                            Write-Warning "Removal for $($AdminUnitMember.displayName) has been failed!"
                        }
                    }
                }
                else {
                    Write-Warning "Object $($AdminUnitMember.displayName) will keep in RMAU because of missing protection by regular RMAU!"
                }
            }
        }
        else {
            Compare-Object $UnprotectedPrivilegedUserOnTierLevel.ObjectId $CurrentAdminUnitMembers.Id | ForEach-Object {
                if ($_.SideIndicator -eq "=>") {

                    $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/directoryObjects/$($_.InputObject)" -OutputType PSObject
                    Write-Host "Removing $($AdminUnitMember.displayName) from $($AdminUnitName)"
                    try {
                        Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/$($_.InputObject)/`$ref" -OutputType PSObject
                    }
                    catch {
                        Write-Warning "Removal for $($AdminUnitMember.displayName) has been failed!"
                    }

                }
                elseif ($_.SideIndicator -eq "<=") {
                    try {
                        $AdminUnitMember = (Get-MgDirectoryObject -DirectoryObjectId $_.InputObject)
                        Write-Host "Adding $($AdminUnitMember.displayName) to $($AdminUnitName)"

                        $OdataBody = @{
                            '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($_.InputObject)"
                        } | ConvertTo-Json

                        Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -Body $OdataBody -OutputType PSObject
                    }
                    catch {
                        Write-Warning "Duplicated entry for $($AdminUnitMember.displayName)"
                    }
                }
            }
        }
    }
}