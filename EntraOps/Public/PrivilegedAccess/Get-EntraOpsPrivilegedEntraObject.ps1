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
    Custom security attribute for user object to get classification details. Default will be set by parameter in EntraOpsConfig.json file.

.PARAMETER CustomSecurityServicePrincipalAttribute
    Custom security attribute for service principal object to get classification details. Default will be set by parameter in EntraOpsConfig.json file.

.PARAMETER CustomSecurityUserPawAttribute
    Custom security attribute for user object to get relation to PAW device. Default will be set by parameter in EntraOpsConfig.json file.

.PARAMETER CustomSecurityUserWorkAccountAttribute
    Custom security attribute for user object to get relation to work account. Default will be set by parameter in EntraOpsConfig.json file.

.PARAMETER XdrHunting
    Boolean to indicate if ThreatHunting.Read.All permission is granted for current session to get associated work account from XDR data. Default is set by scope of MgGraph.

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
        [System.String]$CustomSecurityUserAttribute = $EntraOpsConfig.CustomSecurityAttributes.PrivilegedUserAttribute
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$CustomSecurityUserPawAttribute = $EntraOpsConfig.CustomSecurityAttributes.PrivilegedUserPawAttribute
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$CustomSecurityServicePrincipalAttribute = $EntraOpsConfig.CustomSecurityAttributes.PrivilegedServicePrincipalAttribute
        ,        
        [Parameter(Mandatory = $false)]
        [System.String]$CustomSecurityUserWorkAccountAttribute = $EntraOpsConfig.CustomSecurityAttributes.UserWorkAccountAttribute
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$XdrHunting = $(if ($Global:XdrAvdHuntingAccess -is [bool]) { $Global:XdrAvdHuntingAccess } else { $false })
        ,
        [Parameter(Mandatory = $false)]
        [PSObject]$InputObject
    )

    $StopwatchTotal = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $ObjectDetails = $null
        
        # Smart Fallback: Use InputObject if available and valid (contains critical properties)
        if ($null -ne $InputObject) {
            # Check for critical property usually missing in v1.0 but present in beta
            if ($null -ne $InputObject.isManagementRestricted) {
                $ObjectDetails = $InputObject
                Write-Verbose "Using pre-fetched object details for $AadObjectId (Skipped API call)"
            } else {
                Write-Verbose "InputObject provided but missing critical 'isManagementRestricted' property. Falling back to API fetch."
            }
        }
        
        # Fallback to API call if object details are still null
        if ($null -eq $ObjectDetails) {
            $ObjectDetails = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($AadObjectId)?`$select=id,displayName,userPrincipalName,userType,isAssignableToRole,isManagementRestricted,onPremisesSyncEnabled,passwordPolicies" -OutputType PSObject
        }
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
    $StopwatchRegion = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if ($null -ne $ObjectDetails) {
            Write-Verbose -Message "Lookup for $($ObjectDetails.'@odata.type') - $($ObjectDetails.displayName) $($AadObjectId)"
            $RestrictedManagementByRMAU = $($ObjectDetails.isManagementRestricted)
        }
    } catch {
        Write-Warning "No group or role assignment status available"
    }
    #endregion

    #region Get transitive memberships of object
    try {
        $ObjectMemberships = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/directoryObjects/$AadObjectId/transitiveMemberOf") -OutputType PSObject)
    } catch {
        Write-Warning "No transitive memberships available"
    }
    #endregion    
    $StopwatchRegion.Stop()
    Write-Verbose "[Performance] Object details and RMAU protection: $($StopwatchRegion.ElapsedMilliseconds)ms"
    #endregion

    #region Calculate protection by AAD Role assignment or eligibility (available only for user and group objects)
    $StopwatchRegion = [System.Diagnostics.Stopwatch]::StartNew()
    if ( $ObjectDetails.'@odata.type' -in @('#microsoft.graph.user', '#microsoft.graph.group') ) {
        $AadRolesActive = (Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/transitiveRoleAssignments?$count=true&`$filter=principalId eq '$($AadObjectId)'" -ConsistencyLevel "eventual")
        $AadRolesEligible = (Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleEligibilitySchedules") | Where-Object { $_.principalId -in $ObjectMemberships.id -or $_.principalId -eq $AadObjectId }
        $RestrictedManagementByAadRole = ($null -ne $AadRolesActive.id -or $null -ne $AadRolesEligible.id)
    } else {
        $RestrictedManagementByAadRole = $false
    }
    $StopwatchRegion.Stop()
    Write-Verbose "[Performance] AAD Role protection check: $($StopwatchRegion.ElapsedMilliseconds)ms"
    #endregion

    switch ( $ObjectDetails.'@odata.type' ) {
        #region User object details
        '#microsoft.graph.user' {
            $StopwatchRegion = [System.Diagnostics.Stopwatch]::StartNew()

            # odata type by directoryObject includes value of user which could be either user or agentUser
            $ObjectType = 'user'
            # Combine initial query with customSecurityAttributes to reduce API calls
            $UserDetails = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/users/$($AadObjectId)?`$select=id,userPrincipalName,userType,displayName,customSecurityAttributes,identityParentId" -OutputType PSObject
            $IdentityParent = $($UserDetails.identityParentId)

            if ($null -ne $UserDetails.'@odata.type') {
                $ObjectSubType = $UserDetails.'@odata.type'.Replace("#microsoft.graph.", "")
            } else {
                $ObjectSubType = $UserDetails.UserType
            }

            # Sponsors
            try {
                Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/users/$AadObjectId/sponsors?`$select=id" -OutputType PSObject | ForEach-Object { $Sponsors.Add($_.id) | out-null }
            } catch {
                Write-Warning "No sponsors supported for $($AadObjectId)"                
            }

            # Owned Objects
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/users/$AadObjectId/ownedObjects?`$select=id") -OutputType PSObject | ForEach-Object { $ObjectOwner.Add($_.id) | out-null }            


            # User Sign-in Name
            $ObjectSignInName = $ObjectDetails.UserPrincipalName

            if ($ObjectDetails.userType -ne "Member" -or $ObjectDetails.UserPrincipalName -like "*#EXT#@*") {
                $OutsideOfAadTenant = $True
            } else { $OutsideOfAadTenant = $False }

            # Object Classification (already retrieved in initial query)
            try {
                $ObjectCustomSec = $UserDetails.customSecurityAttributes.$($CustomSecurityUserAttribute)
            } catch {
                Write-Warning "No custom security attribute for $($AadObjectId)"
            }
            $AdminTierLevel = (($ObjectCustomSec) | select-object -Unique adminTierLevel).AdminTierLevel
            $AdminTierLevelName = (($ObjectCustomSec) | select-object -Unique adminTierLevelName).AdminTierLevelName

            # Administrative Unit Assignments
            $RestrictedManagementByRAG = $ObjectMemberships.isAssignableToRole -contains $true
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/users/$($AAdObjectId)/memberOf/microsoft.graph.administrativeUnit?`$select=id,displayName" -OutputType PSObject | Select-Object id, displayName | ForEach-Object { $AssignedAdministrativeUnits.Add($_) | out-null }

            # Relation between PAW and user
            if ($null -ne $ObjectCustomSec.$($CustomSecurityUserPawAttribute)) {
                $ObjectCustomSec.$($CustomSecurityUserPawAttribute) | ForEach-Object { $PawDevice.Add($_) | out-null }
            }
            if ($null -ne $ObjectCustomSec.$($CustomSecurityUserWorkAccountAttribute)) {
                $ObjectCustomSec.$($CustomSecurityUserWorkAccountAttribute) | ForEach-Object { $WorkAccount.Add($_) | out-null }                
            } elseif ( $XdrHunting -eq $true ) {
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
            } else {
                Write-Verbose "Custom Security Attribute not present and XDR Hunting permission not granted, skipping associated work account lookup for $($AadObjectId)"
            }
            
            # Device Ownership of Privileged User
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/users/$AadObjectId/ownedDevices" + '?$select=id') -OutputType PSObject | ForEach-Object { $DeviceOwner.Add($_.id) | out-null }
            
            $StopwatchRegion.Stop()
            Write-Verbose "[Performance] User object details: $($StopwatchRegion.ElapsedMilliseconds)ms"
        }
        #endregion


        #region Group object details
        '#microsoft.graph.group' {
            $StopwatchRegion = [System.Diagnostics.Stopwatch]::StartNew()
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

            # Owners
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/groups/$AadObjectId/owners?`$select=id" -OutputType PSObject | ForEach-Object { $Owners.Add($_.id) | out-null }

            # Administrative Unit Assignments
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/groups/$($AAdObjectId)/memberOf/microsoft.graph.administrativeUnit?`$select=id,displayName" -OutputType PSObject | Select-Object id, displayName | ForEach-Object { $AssignedAdministrativeUnits.Add($_) | out-null }
            
            $StopwatchRegion.Stop()
            Write-Verbose "[Performance] Group object details: $($StopwatchRegion.ElapsedMilliseconds)ms"
        }
        #endregion

        #region Service Principal object details
        '#microsoft.graph.servicePrincipal' {
            $StopwatchRegion = [System.Diagnostics.Stopwatch]::StartNew()
            # Combine initial query with customSecurityAttributes to reduce API calls
            $SPObject = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/serviceprincipals/$($AAdObjectId)?`$select=id,appId,servicePrincipalType,appOwnerOrganizationId,customSecurityAttributes,agentAppId" -OutputType PSObject
            $ObjectSignInName = $SPObject.appId
            $ObjectType = 'servicePrincipal'
            $ObjectSubType = $SPObject.ServicePrincipalType

            #region Collect Owners and Owned Objects
            $StopwatchRegion = [System.Diagnostics.Stopwatch]::StartNew()

            # Owners
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/servicePrincipals/$AadObjectId/owners?`$select=id") -OutputType PSObject | ForEach-Object { $Owners.Add($_.id) | out-null }

            # Owned Objects
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/servicePrincipals/$AadObjectId/ownedObjects?`$select=id") -OutputType PSObject | ForEach-Object { $ObjectOwner.Add($_.id) | out-null }            

            $StopwatchRegion.Stop()
            Write-Verbose "[Performance] Owners and owned objects collection: $($StopwatchRegion.ElapsedMilliseconds)ms"
            #endregion

            # Restricted by Role Assignale Groups does not apply
            $RestrictedManagementByRAG = $false

            # Details of classified object from custom security attribute (already retrieved in initial query)
            try {
                $ObjectCustomSec = $SPObject.customSecurityAttributes.$($CustomSecurityServicePrincipalAttribute)
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

                # Sponsors
                try {
                    Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/serviceprincipals/$($AadObjectId)/sponsors?`$select=id" -OutputType PSObject | ForEach-Object { $Sponsors.Add($_.id) | out-null }
                } catch {
                    Write-Warning "No sponsors supported for $($AadObjectId)"
                }

            }
            #endregion
            
            $StopwatchRegion.Stop()
            Write-Verbose "[Performance] Service Principal object details: $($StopwatchRegion.ElapsedMilliseconds)ms"
        }
        #endregion

        #region Application object details
        '#microsoft.graph.application' {
            $StopwatchRegion = [System.Diagnostics.Stopwatch]::StartNew()
            # Use $select to minimize data transfer
            $AppObject = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/applications/$($AAdObjectId)?`$select=id,appId,displayName" -OutputType PSObject
            # Combine service principal query with customSecurityAttributes to reduce API calls
            $SPObject = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/serviceprincipals(appId='$($AppObject.appId)')?`$select=id,customSecurityAttributes" -OutputType PSObject
            Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/applications/$AadObjectId/owners?`$select=id") -OutputType PSObject | ForEach-Object { $Owners.Add($_.id) | out-null }
            $ObjectSignInName = $AppObject.appId
            $ObjectType = 'application'
            $ObjectSubType = ""

            # Administrative Units and Restricted Management does not apply to service principals
            $RestrictedManagementByRAG = $false

            # Details of classified object from custom security attribute (already retrieved in SP query)
            try {
                $ObjectCustomSec = $SPObject.customSecurityAttributes.$($CustomSecurityServicePrincipalAttribute)
            } catch {
                Write-Warning "No custom security attribute for $($AadObjectId)"
            }
            $AdminTierLevel = (($ObjectCustomSec) | select-object -Unique adminTier).AdminTier
            $AdminTierLevelName = (($ObjectCustomSec) | select-object -Unique adminTierLevelName).AdminTierLevelName
            $OutsideOfAadTenant = $False
            if ($null -ne $SPObject) {
                Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/servicePrincipals/$($SPObject.id)/ownedObjects?`$select=id" -OutputType PSObject | ForEach-Object { $ObjectOwner.Add($_.id) | out-null }
            }
            
            $StopwatchRegion.Stop()
            Write-Verbose "[Performance] Application object details: $($StopwatchRegion.ElapsedMilliseconds)ms"
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
    $StopwatchRegion = [System.Diagnostics.Stopwatch]::StartNew()
    if ($ObjectType -notin @("user", "group", "devices")) {
        # Administrative Unit Assignments - Optimized with hashtable lookup
        $Body = @{
            securityEnabledOnly = "false"
        } | ConvertTo-Json
        $AssignedAdminUnitIds = Invoke-EntraOpsMsGraphQuery -Method POST -Body $Body -Uri "/beta/directoryObjects/$($AAdObjectId)/getMemberObjects" -OutputType PSObject -DisableCache
        
        # Optimization: Build hashtable lookup for O(1) access instead of O(N) Where-Object filtering
        $AllAdminUnits = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/administrativeunits?`$select=id,displayName" -OutputType PSObject
        $AdminUnitLookup = @{}
        foreach ($AU in $AllAdminUnits) {
            $AdminUnitLookup[$AU.id] = $AU
        }
        
        # Use hashtable lookup for fast filtering
        foreach ($AuId in $AssignedAdminUnitIds) {
            if ($AdminUnitLookup.ContainsKey($AuId)) {
                $AssignedAdministrativeUnits.Add($AdminUnitLookup[$AuId]) | out-null
            }
        }
    }
    $StopwatchRegion.Stop()
    Write-Verbose "[Performance] Administrative units collection: $($StopwatchRegion.ElapsedMilliseconds)ms"
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

    # Sort lists for deterministic output
    if ($Owners.Count -gt 0) { $Owners.Sort() }
    if ($Sponsors.Count -gt 0) { $Sponsors.Sort() }
    if ($ObjectOwner.Count -gt 0) { $ObjectOwner.Sort() }
    if ($DeviceOwner.Count -gt 0) { $DeviceOwner.Sort() }
    if ($WorkAccount.Count -gt 0) { $WorkAccount.Sort() }
    if ($PawDevice.Count -gt 0) { $PawDevice.Sort() }
    
    # Sort AssignedAdministrativeUnits by displayName then id if it contains items
    if ($AssignedAdministrativeUnits.Count -gt 0) {
        $SortedUnits = $AssignedAdministrativeUnits | Sort-Object displayName, id
        if ($SortedUnits -is [System.Collections.ArrayList]) {
            $AssignedAdministrativeUnits = $SortedUnits
        } else {
            $AssignedAdministrativeUnits = [System.Collections.ArrayList]@($SortedUnits)
        }
    }

    if ($null -ne $ObjectDetails) {
        $StopwatchTotal.Stop()
        Write-Verbose "[Performance] Total execution time: $($StopwatchTotal.ElapsedMilliseconds)ms"
        
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