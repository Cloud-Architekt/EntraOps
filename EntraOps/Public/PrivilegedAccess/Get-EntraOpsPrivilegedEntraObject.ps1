<#
.SYNOPSIS
    Details of Entra Object which is a user, group or service principal with assigned privileged roles and memberships

.DESCRIPTION
    Get essential information about privileged object and details of protection level, owned objects and relation to associated device or work account.

.PARAMETER AadObjectId
    Object Id of the Microsoft Entra object to get details for.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER CustomSecurityUserAttribute
    Custom security attribute for user object to get classification details. Default is "privilegedUser".

.PARAMETER CustomSecurityServicePrincipalAttribute
    Custom security attribute for service principal object to get classification details. Default is "privilegedWorkloadIdentitiy".

.PARAMETER CustomSecurityUserPawAttribute
    Custom security attribute for user object to get relation to PAW device. Default is "associatedSecureAdminWorkstation".

.PARAMETER CustomSecurityUserWorkAccountAttribute
    Custom security attribute for user object to get relation to work account. Default is "associatedWorkAccount".

.EXAMPLE
    Details of privileged object by using ObjectId
    Get-EntraOpsPrivilegedEntraObject -AadObjectId "bdf10e92-30c7-4cc8-93e7-2982ea6cf371"
#>
function Get-EntraOpsPrivilegedEntraObject {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $True)]
        [System.String]$AadObjectId
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$CustomSecurityUserAttribute = "privilegedUser"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$CustomSecurityServicePrincipalAttribute = "privilegedWorkloadIdentitiy"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$CustomSecurityUserPawAttribute = "associatedSecureAdminWorkstation"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$CustomSecurityUserWorkAccountAttribute = "associatedWorkAccount"
    )

    try {
        $ObjectDetails = Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/directoryObjects/$AadObjectId") -OutputType PSObject
    }
    catch {
        $ObjectDetails = $null
        Write-Verbose "No object has been found with Id: $AadObjectId"
        Write-Warning $_.Exception.Message
    }

    #region Memberships to calculate protection level
    Write-Verbose -Message "Lookup for $($ObjectDetails.'@odata.type') - $($ObjectDetails.displayName) $($AadObjectId)"
    try {
        $ObjectMemberships = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/directoryObjects/$AadObjectId/transitiveMemberOf") -OutputType PSObject)
        $AadRolesActive = (Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/transitiveRoleAssignments?$count=true&`$filter=principalId eq '$AadObjectId'" -ConsistencyLevel "eventual")
        $AadRolesEligible = (Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleEligibilitySchedules") | Where-Object { $_.principalId -in $ObjectMemberships.id -or $_.principalId -eq $AadObjectId }
        $RestrictedManagementByAadRole = ("" -ne $AadRolesActive.value -or $null -ne $AadRolesEligible)
        $RestrictedManagementByRMAU = ($ObjectDetails.isManagementRestricted -eq $true)
    }
    catch {
        Write-Warning "No group or role assignment status available"
    }
    #endregion

    #region Default empty arrays
    $WorkAccount = @()
    $PawDevice = @()
    $DeviceOwner = @()

    switch ( $ObjectDetails.'@odata.type' ) {
        #region User object details
        '#microsoft.graph.user' {
            $ObjectType = 'user'
            if ($ObjectDetails.UserType -eq "Member") {
                $ObjectSubType = "Member"
            }
            else { $ObjectSubType = "Guest" }


            # User Sign-in Name
            $ObjectSignInName = $ObjectDetails.UserPrincipalName

            if ($ObjectDetails.userType -ne "Member" -or $ObjectDetails.UserPrincipalName -like "*#EXT#@*") {
                $OutsideOfAadTenant = $True
            }
            else { $OutsideOfAadTenant = $False }

            # Object Classification
            try {
                $ObjectCustomSec = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/users/$($AAdObjectId)" + '?$select=customSecurityAttributes') -OutputType PSObject).customSecurityAttributes.$($CustomSecurityUserAttribute)
            }
            catch {
                Write-Warning "No custom security attribute for $($AadObjectId)"
            }
            $AdminTierLevel = (($ObjectCustomSec) | select-object -Unique adminTierLevel).AdminTierLevel
            $AdminTierLevelName = (($ObjectCustomSec) | select-object -Unique adminTierLevelName).AdminTierLevelName

            # Administrative Unit Assignments
            $RestrictedManagementByRAG = $ObjectMemberships.isAssignableToRole -contains $true
            $AuMemberships = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/users/$($AAdObjectId)/memberOf/microsoft.graph.administrativeUnit" -OutputType PSObject | Select-Object id, displayName)

            # No owners for user objects
            $Owners = @()

            # Relation between PAW and user
            if ($null -ne $ObjectCustomSec.$($CustomSecurityUserPawAttribute)) {
                $PawDevice = @($ObjectCustomSec.$($CustomSecurityUserPawAttribute))
            }
            else {
                $PawDevice = @()
            }
            if ($null -ne $ObjectCustomSec.$($CustomSecurityUserWorkAccountAttribute)) {
                $WorkAccount = @($ObjectCustomSec.$($CustomSecurityUserWorkAccountAttribute))
            }
            else {
                $WorkAccount = @()
            }
            # Object Ownership of Privileged User
            $ObjectOwner = @((Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/users/$AadObjectId/ownedObjects" + '?$select=id') -OutputType PSObject).id)

            # Device Ownership of Privileged User
            $DeviceOwner = @((Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/users/$AadObjectId/ownedDevices" + '?$select=id') -OutputType PSObject).id)
            # Workaround for null result for device ownership
            if ($DeviceOwner.Count -eq "1" -and $null -in $DeviceOwner) {
                $DeviceOwner = @()
            }
        }
        #endregion

        #region Group object details
        '#microsoft.graph.group' {
            $ObjectType = 'group'
            if ($ObjectDetails.isAssignableToRole -eq $True) {
                $ObjectSubType = "Role-assignable"
                $RestrictedManagementByRAG = $true
            }
            else {
                $ObjectSubType = "Security"
                $RestrictedManagementByRAG = $false
            }
            $OutsideOfAadTenant = $false

            # Owners
            $Owners = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/groups/$AadObjectId/owners") -OutputType PSObject).id

            # No support for custom security attributes
            $AdminTierLevel = ""
            $AdminTierLevelName = ""

            # Administrative Unit Assignments
            $AuMemberships = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/groups/$($AAdObjectId)/memberOf/microsoft.graph.administrativeUnit" -OutputType PSObject | Select-Object id, displayName)
        }
        #endregion

        #region Service Principal object details
        '#microsoft.graph.servicePrincipal' {
            $SPObject = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/serviceprincipals/$($AAdObjectId)" -OutputType PSObject
            $ObjectSignInName = $SPObject.appId
            $ObjectType = 'servicePrincipal'
            $ObjectSubType = $SPObject.ServicePrincipalType

            # Owners
            $Owners = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/serviceprincipals/$AadObjectId/owners") -OutputType PSObject).id

            # Administrative Units and Restricted Management does not apply to service principals
            $AuMemberships = @()
            $RestrictedManagementByRAG = $false
            $RestrictedManagementByRMAU = $false
            $RestrictedManagementByAadRole = $false

            # Details of classified object from custom security attribute
            try {
                $ObjectCustomSec = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/servicePrincipals/$($AAdObjectId)" + '?$select=customSecurityAttributes') -OutputType PSObject).customSecurityAttributes.$($CustomSecurityServicePrincipalAttribute)
            }
            catch {
                Write-Warning "No custom security attribute for $($AadObjectId)"
            }
            $AdminTierLevel = (($ObjectCustomSec) | select-object -Unique adminTier).AdminTier
            $AdminTierLevelName = (($ObjectCustomSec) | select-object -Unique adminTierLevelName).AdminTierLevelName
            $OutsideOfAadTenant = ($SPObject.AppOwnerOrganizationId -ne $TenantId)
        }
        #endregion
        #region Unknown object
        '' {
            $ObjectDetails = [PSCustomObject]@{
                'id'          = "$($AadObjectId)"
                'displayName' = "Identity not found"
            }
            $ObjectType = 'unknown'
            $ObjectSubType = 'unknown'
        }
        #endregion
    }

    # Handling Empty arrays for schema
    if ($null -eq $AuMemberships -or $null -eq $AuMemberships.id) { $AuMemberships = @() }
    if ($null -eq $ObjectOwner -or $ObjectOwner -eq "") { $ObjectOwner = @() }
    if ($null -eq $Owners) { $Owners = @() }
    if ($null -eq $ObjectDetails.passwordPolicies) { $PasswordPolicies = @() } else { $PasswordPolicies = $ObjectDetails.passwordPolicies }
    if ($null -eq $ObjectSignInName) { $ObjectSignInName = "" }

    if ($null -ne $ObjectDetails) {
        [PSCustomObject]@{
            'ObjectId'                      = $ObjectDetails.Id
            'ObjectType'                    = $ObjectType
            'ObjectSubType'                 = $ObjectSubType
            'ObjectDisplayName'             = $ObjectDetails.displayName
            'ObjectSignInName'              = $ObjectSignInName
            'OwnedObjects'                  = $ObjectOwner
            'OwnedDevices'                  = $DeviceOwner
            'Owners'                        = $Owners
            'AdminTierLevel'                = if ($null -eq $AdminTierLevel -and $ObjectType -ne "group") { "Unclassified" } else { $AdminTierLevel.ToString() }
            'AdminTierLevelName'            = if ($null -eq $AdminTierLevelName -and $ObjectType -ne "group") { "Unclassified" } else { $AdminTierLevelName }
            'AssociatedWorkAccount'         = $WorkAccount
            'AssociatedPawDevice'           = $PawDevice
            'OnPremSynchronized'            = if ($null -eq $ObjectDetails.onPremisesSyncEnabled) { $false } else { $ObjectDetails.onPremisesSyncEnabled }
            'RestrictedManagementByRAG'     = $RestrictedManagementByRAG
            'RestrictedManagementByAadRole' = $RestrictedManagementByAadRole
            'RestrictedManagementByRMAU'    = $RestrictedManagementByRMAU
            'AssignedAdministrativeUnits'   = $AuMemberships
            'PasswordPolicyAssigned'        = $PasswordPolicies
            'OutsideOfHomeTenant'           = $OutsideOfAadTenant
        }
    }
}
