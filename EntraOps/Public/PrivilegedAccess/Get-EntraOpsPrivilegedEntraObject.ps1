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
    } catch {
        $ObjectDetails = $null
        Write-Verbose "No object has been found with Id: $AadObjectId"
        Write-Warning $_.Exception.Message
    }

    # Variables for ownership or other object relationships
    [System.Collections.ArrayList]$Owners = @()
    [System.Collections.ArrayList]$Sponsors = @()
    [System.Collections.ArrayList]$ObjectOwner = @()
    [System.Collections.ArrayList]$DeviceOwner = @()
    [System.Collections.ArrayList]$WorkAccount = @()
    [System.Collections.ArrayList]$PawDevice = @()    
    [System.Collections.ArrayList]$AssignedAdministrativeUnits = @()    

    #region Calculate object details common for all object types and protection by RMAU membership
    Write-Verbose -Message "Lookup for $($ObjectDetails.'@odata.type') - $($ObjectDetails.displayName) $($AadObjectId)"
    try {
        $ObjectMemberships = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/directoryObjects/$AadObjectId/transitiveMemberOf") -OutputType PSObject)
        $RestrictedManagementByRMAU = $($ObjectDetails.isManagementRestricted)
    } catch {
        Write-Warning "No group or role assignment status available"
    }
    #endregion

    #region Calculate protection by AAD Role assignment or eligibility (available only for user and group objects)
    if ( $ObjectDetails.'@odata.type' -in @('#microsoft.graph.user', '#microsoft.graph.group') ) {
        $AadRolesActive = (Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/transitiveRoleAssignments?$count=true&`$filter=principalId eq '$AadObjectId'" -ConsistencyLevel "eventual")
        $AadRolesEligible = (Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleEligibilitySchedules") | Where-Object { $_.principalId -in $ObjectMemberships.id -or $_.principalId -eq $AadObjectId }
        $RestrictedManagementByAadRole = ($null -ne $AadRolesActive.id -or $null -ne $AadRolesEligible.id)
    } else {
        $RestrictedManagementByAadRole = $false
    }
    #endregion

    switch ( $ObjectDetails.'@odata.type' ) {
        #region User object details
        '#microsoft.graph.user' {

            # odata type by directoryObject includes value of user which could be either user or agentUser
            $ObjectType = 'user'
            $UserDetails = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/users/$($AadObjectId)" -OutputType PSObject
            $IdentityParent = $($UserDetails.identityParent).id

            if ($null -ne $UserDetails.'@odata.type') {
                $ObjectSubType = $UserDetails.'@odata.type'.Replace("#microsoft.graph.", "")
            } else {
                $ObjectSubType = $UserDetails.UserType
            }

            # Sponsors (using $expand for efficiency)
            try {
                Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/users/$AadObjectId/sponsors") -OutputType PSObject | ForEach-Object { $Sponsors.Add($_.id) | out-null }
            } catch {
                Write-Warning "No sponsors supported for $($AadObjectId)"                
            }

            # User Sign-in Name
            $ObjectSignInName = $ObjectDetails.UserPrincipalName

            if ($ObjectDetails.userType -ne "Member" -or $ObjectDetails.UserPrincipalName -like "*#EXT#@*") {
                $OutsideOfAadTenant = $True
            } else { $OutsideOfAadTenant = $False }

            # Object Classification
            try {
                $ObjectCustomSec = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/users/$($AAdObjectId)" + '?$select=customSecurityAttributes') -OutputType PSObject).customSecurityAttributes.$($CustomSecurityUserAttribute)
            } catch {
                Write-Warning "No custom security attribute for $($AadObjectId)"
            }
            $AdminTierLevel = (($ObjectCustomSec) | select-object -Unique adminTierLevel).AdminTierLevel
            $AdminTierLevelName = (($ObjectCustomSec) | select-object -Unique adminTierLevelName).AdminTierLevelName

            # Administrative Unit Assignments
            $RestrictedManagementByRAG = $ObjectMemberships.isAssignableToRole -contains $true
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/users/$($AAdObjectId)/memberOf/microsoft.graph.administrativeUnit" -OutputType PSObject | Select-Object id, displayName | ForEach-Object { $AssignedAdministrativeUnits.Add($_) | out-null }

            # Relation between PAW and user
            if ($null -ne $ObjectCustomSec.$($CustomSecurityUserPawAttribute)) {
                $ObjectCustomSec.$($CustomSecurityUserPawAttribute) | ForEach-Object { $PawDevice.Add($_) | out-null }
            }
            if ($null -ne $ObjectCustomSec.$($CustomSecurityUserWorkAccountAttribute)) {
                $ObjectCustomSec.$($CustomSecurityUserWorkAccountAttribute) | ForEach-Object { $WorkAccount.Add($_) | out-null }                
            } else {
                try {
                    $IdentityAccountQuery = "
                        IdentityAccountInfo
                        | where SourceProvider == 'AzureActiveDirectory'
                        | where SourceProviderAccountId == '$($AadObjectId)'
                        | summarize arg_max(TimeGenerated, *) by AccountId
                        | where IsPrimary == false
                        | project TimeGenerated, DisplayName, SourceProviderAccountId, IdentityId, IdentityLinkBy, IdentityLinkType, IsPrimary, AccountId
                        | join kind = leftouter (
                            IdentityAccountInfo
                                | where SourceProvider == 'AzureActiveDirectory'
                                | summarize arg_max(TimeGenerated, *) by AccountId
                                | where IsPrimary == true
                                | project IdentityId, AccountObjectId = SourceProviderAccountId, AccountUpn
                        ) on IdentityId
                        | extend AssociatedPrimaryAccount = bag_pack_columns(AccountObjectId, AccountUpn, IdentityLinkType, IdentityId)
                        | project AccountObjectId = SourceProviderAccountId                    
                    "
                    $IdentityAccountResult = Invoke-EntraOpsGraphSecurityQuery -Query $IdentityAccountQuery -Timespan "P14D"
                    $IdentityAccountResult.AccountObjectId | ForEach-Object { $WorkAccount.Add($_) | out-null }   
                } catch {
                    Write-Warning "Query for associated work account failed for $($AadObjectId): $($_.Exception.Message)"
                }
            }
            
            # Device Ownership of Privileged User
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/users/$AadObjectId/ownedDevices" + '?$select=id') -OutputType PSObject | ForEach-Object { $DeviceOwner.Add($_.id) | out-null }
        }
        #endregion


        #region Group object details
        '#microsoft.graph.group' {
            $ObjectType = 'group'
            if ($ObjectDetails.isAssignableToRole -eq $True) {
                $ObjectSubType = "Role-assignable"
                $RestrictedManagementByRAG = $true
            } else {
                $ObjectSubType = "Security"
                $RestrictedManagementByRAG = $false
            }
            $OutsideOfAadTenant = $false

            # No support for custom security attributes
            $AdminTierLevel = ""
            $AdminTierLevelName = ""

            # Administrative Unit Assignments
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/groups/$($AAdObjectId)/memberOf/microsoft.graph.administrativeUnit" -OutputType PSObject | Select-Object id, displayName | ForEach-Object { $AssignedAdministrativeUnits.Add($_) | out-null }
        }
        #endregion

        #region Service Principal object details
        '#microsoft.graph.servicePrincipal' {
            $SPObject = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/serviceprincipals/$($AAdObjectId)" -OutputType PSObject
            $ObjectSignInName = $SPObject.appId
            $ObjectType = 'servicePrincipal'
            $ObjectSubType = $SPObject.ServicePrincipalType

            # Restricted by Role Assignale Groups does not apply
            $RestrictedManagementByRAG = $false

            # Details of classified object from custom security attribute
            try {
                $ObjectCustomSec = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/servicePrincipals/$($AAdObjectId)" + '?$select=customSecurityAttributes') -OutputType PSObject).customSecurityAttributes.$($CustomSecurityServicePrincipalAttribute)
            } catch {
                Write-Warning "No custom security attribute for $($AadObjectId)"
            }
            $AdminTierLevel = (($ObjectCustomSec) | select-object -Unique adminTier).AdminTier
            $AdminTierLevelName = (($ObjectCustomSec) | select-object -Unique adminTierLevelName).AdminTierLevelName
            $OutsideOfAadTenant = ($SPObject.AppOwnerOrganizationId -ne $TenantId)

            #region Agent identity object details$
            if ( $SPObject.'@odata.type' -like "*agentIdentity*" ) {

                $ObjectSubType = $SPObject.'@odata.type'.Replace("#microsoft.graph.", "")

                if ($ObjectSubType -ne "agentIdentityBlueprintPrincipal") {
                    $BlueprintAppId = $($SPObject.agentAppId)
                    $AgentIdentityBlueprintPrincipalObject = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/servicePrincipals(appId='$($BlueprintAppId)')/microsoft.graph.agentIdentityBlueprintPrincipal" -OutputType PSObject
                    $IdentityParent = $AgentIdentityBlueprintPrincipalObject.appId
                } else {
                    $AgentIdentityBlueprintPrincipalObject = $SPObject
                }

                $OutsideOfAadTenant = ($AgentIdentityBlueprintPrincipalObject.AppOwnerOrganizationId -ne $TenantId)

                # Sponsors (using $expand for efficiency)
                try {
                    Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/serviceprincipals/$($AadObjectId)/sponsors") -OutputType PSObject | ForEach-Object { $Sponsors.Add($_.id) | out-null }
                } catch {
                    Write-Warning "No sponsors supported for $($AadObjectId)"
                }

            }
            #endregion
        }
        #endregion

        #region Application object details
        '#microsoft.graph.application' {
            $AppObject = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/applications/$($AAdObjectId)" -OutputType PSObject
            $SPObject = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/serviceprincipals(appId='$($AppObject.appId)')" -OutputType PSObject
            $ObjectSignInName = $AppObject.appId
            $ObjectType = 'application'
            $ObjectSubType = ""

            # Administrative Units and Restricted Management does not apply to service principals
            $RestrictedManagementByRAG = $false

            # Details of classified object from custom security attribute
            try {
                $ObjectCustomSec = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/servicePrincipals/$($SPObject.Id)" + '?$select=customSecurityAttributes') -OutputType PSObject).customSecurityAttributes.$($CustomSecurityServicePrincipalAttribute)
            } catch {
                Write-Warning "No custom security attribute for $($AadObjectId)"
            }
            $AdminTierLevel = (($ObjectCustomSec) | select-object -Unique adminTier).AdminTier
            $AdminTierLevelName = (($ObjectCustomSec) | select-object -Unique adminTierLevelName).AdminTierLevelName
            $OutsideOfAadTenant = $False
            if ($null -ne $SPObject) {
                Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/servicePrincipals/$($SPObject.id)/ownedObjects" -OutputType PSObject | ForEach-Object { $ObjectOwner.Add($_.id) | out-null }
            }
            #endregion
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

    #region Collect assigned administrative units for unsupported object types
    if ($ObjectType -notin @("user", "group", "devices")) {
        # Administrative Unit Assignments
        $Body = @{
            securityEnabledOnly = "false"
        } | ConvertTo-Json
        $AssignedAdminUnitIds = Invoke-EntraOpsMsGraphQuery -Method POST -Body $Body -Uri "/beta/directoryObjects/$($AAdObjectId)/getMemberObjects" -OutputType PSObject -DisableCache
        $AllAdminUnitIds = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/administrativeunits" -OutputType PSObject            
        $AllAdminUnitIds | Where-object { $_.Id -in $AssignedAdminUnitIds } | select-object id, displayName | ForEach-Object { $AssignedAdministrativeUnits.Add($_) | out-null }
    }
    #endregion

    #region Collect Owners and Owned Objects

    # Owners for non-user objects (since owners are not existent for user objects)
    if ($ObjectType -ne "user") {
        try {
            # Use $expand to fetch owners with main object call is not possible for directoryObjects, so keep separate call
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/directoryObjects/$AadObjectId/owners?`$select=id") -OutputType PSObject | ForEach-Object { $Owners.Add($_.id) | out-null }
        } catch {
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/directoryObjects/$AadObjectId/owners") -OutputType PSObject | ForEach-Object { $Owners.Add($_.id) | out-null }
        }
    }
    # Owned Objects
    Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$AadObjectId/ownedObjects" -OutputType PSObject | ForEach-Object { $ObjectOwner.Add($_.id) | out-null }

    #endregion

    # Set empty arrays to avoid null values for arrays in schema
    if ([string]::IsNullOrEmpty($RestrictedManagementByRMAU)) { $RestrictedManagementByRMAU = $false }        
    if ([string]::IsNullOrEmpty($Owners)) { $Owners = @() }    
    if ([string]::IsNullOrEmpty($Sponsors)) { $Sponsors = @() }    
    if ([string]::IsNullOrEmpty($ObjectOwner)) { $ObjectOwner = @() }
    if ([string]::IsNullOrEmpty($DeviceOwner)) { $DeviceOwner = @() }
    if ([string]::IsNullOrEmpty($WorkAccount)) { $WorkAccount = @() }
    if ([string]::IsNullOrEmpty($PawDevice )) { $PawDevice = @() }
    if ([string]::IsNullOrEmpty($AssignedAdministrativeUnits.id)) { $AssignedAdministrativeUnits = @() }
    if ([string]::IsNullOrEmpty($ObjectSignInName)) { $ObjectSignInName = "" }    
    if ([string]::IsNullOrEmpty($ObjectDetails.passwordPolicies)) { $PasswordPolicies = @()
    } else {
        $PasswordPolicies = $ObjectDetails.passwordPolicies
    }

    # Make sure that first character is uppercase
    if (![string]::IsNullOrEmpty($ObjectSubType)) {
        $ObjectSubType = $ObjectSubType.Substring(0, 1).ToUpper() + $ObjectSubType.Substring(1)
    }

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
            'Sponsors'                      = $Sponsors
            'IdentityParent'                = $IdentityParent 
            'AdminTierLevel'                = if ($null -eq $AdminTierLevel -and $ObjectType -ne "group") { "Unclassified" } else { $AdminTierLevel.ToString() }
            'AdminTierLevelName'            = if ($null -eq $AdminTierLevelName -and $ObjectType -ne "group") { "Unclassified" } else { $AdminTierLevelName }
            'AssociatedWorkAccount'         = $WorkAccount
            'AssociatedPawDevice'           = $PawDevice
            'OnPremSynchronized'            = if ($null -eq $ObjectDetails.onPremisesSyncEnabled) { $false } else { $ObjectDetails.onPremisesSyncEnabled }
            'RestrictedManagementByRAG'     = $RestrictedManagementByRAG
            'RestrictedManagementByAadRole' = $RestrictedManagementByAadRole
            'RestrictedManagementByRMAU'    = $RestrictedManagementByRMAU
            'AssignedAdministrativeUnits'   = $AssignedAdministrativeUnits
            'PasswordPolicyAssigned'        = $PasswordPolicies
            'OutsideOfHomeTenant'           = $OutsideOfAadTenant
        }
    }

}