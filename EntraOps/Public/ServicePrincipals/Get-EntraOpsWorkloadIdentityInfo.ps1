<#
.SYNOPSIS
    Get information of service principals and application in Microsoft Entra ID for creating content for the WatchList "WorkloadIdentityInfo".

.DESCRIPTION
    Get information of service principals and application in Microsoft Entra ID for creating content for the WatchList "WorkloadIdentityInfo".

.PARAMETER CustomSecurityServicePrincipalAttribute
    Custom Security Attribute to be used for the service principal to get Attributes "adminTier", "adminTierLevelName", "service" and "associatedWorkload" for detailed enrichment to classify the service principal. Default attribute set name is "privilegedWorkloadIdentitiy".

.EXAMPLE
    Get information of service principals and application in Microsoft Entra ID for creating content for the WatchList "WorkloadIdentityInfo".
    Get-EntraOpsWorkloadIdentityInfo
#>

function Get-EntraOpsWorkloadIdentityInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$CustomSecurityServicePrincipalAttribute = "privilegedWorkloadIdentitiy"
    )

    # Global Variables
    $ErrorActionPreference = "Stop"

    #region New watchlist items
    $NewWatchlistItems = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()
    Write-Verbose "Query tenant service principals - https://graph.microsoft.com/v1.0/serviceprincipals"
    $ServicePrincipals = Invoke-GkSeMgGraphRequest -Uri "https://graph.microsoft.com/v1.0/serviceprincipals"

    Write-Verbose "Query tenant applications - https://graph.microsoft.com/v1.0/applications"
    $Applications = Invoke-GkSeMgGraphRequest -Uri "https://graph.microsoft.com/v1.0/applications"

    Write-Verbose "Query directory role templates for mapping ID to name and further details"
    $DirectoryRoleDefinitions = Invoke-GkSeMgGraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions" | Select-Object displayName, templateId, isPrivileged, isBuiltin

    Write-Verbose "Query app roles for mapping ID to name"
    $SPObjectWithAppRoles = $ServicePrincipals | Where-Object { $_.AppRoles -ne $null }
    $AppRoles = foreach ($SPObjectWithAppRole in $SPObjectWithAppRoles) {

        $SPObjectWithAppRole.AppRoles | ForEach-Object {

            [PSCustomObject]@{
                "AppId"                    = $SPObjectWithAppRole.appId
                "ServicePrincipalObjectId" = $SPObjectWithAppRole.id
                "AppRoleId"                = $_.id
                "AppRoleDisplayName"       = $_.value
            }
        }
    }

    Write-Verbose "Query list of first party apps"
    try {
        $ProgressPreference = 'SilentlyContinue'
        $FirstPartyApps = Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json" | ConvertFrom-Json
    }
    catch {
        Write-Warning "Issue to query list of first party apps from GitHub - $($_.Exception)"
    }

    Write-Verbose "Get details for enrichment of service principals"
    $ServicePrincipals | ForEach-Object -Parallel {
        $ServicePrincipal = $_

        #region Function to get tenant information
        function Get-AADTenantInformation {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [System.String]$AppTenantId
            )

            $ConnectedTenants = Get-AzTenant | select-object TenantId, DefaultDomain
            if ($ConnectedTenants.TenantId -contains $AppTenantId) {
                $KnownTenant = $ConnectedTenants | where-object { $_.TenantId -eq $AppTenantId } | select-object DefaultDomain, TenantId
                $Tenant = [PSCustomObject]@{
                    TenantName = $KnownTenant.DefaultDomain
                    TenantId   = $KnownTenant.TenantId
                }
            }
            elseif ($AppTenantId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a") {
                $Tenant = [PSCustomObject]@{
                    TenantName = "Microsoft"
                    TenantId   = $($AppTenantId)
                }
            }
            elseif ($AppTenantId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47") {
                $Tenant = [PSCustomObject]@{
                    TenantName = "Microsoft"
                    TenantId   = $($AppTenantId)
                }
            }
            elseif ($null -eq $AppTenantId) {
                $Tenant = $null
            }
            else {
                $Tenant = [PSCustomObject]@{
                    TenantName = "Unknown"
                    TenantId   = ($AppTenantId)
                }
            }
            $Tenant
        }
        #endregion        

        try {
            Write-Verbose "Collecting data for $($ServicePrincipal.displayName)"

            # Custom Security Attributes
            $ObjectCustomSec = (Invoke-MgGraphRequest -Method Get -Uri ("https://graph.microsoft.com/beta/servicePrincipals/$($ServicePrincipal.Id)" + '?$select=customSecurityAttributes') -OutputType PSObject).customSecurityAttributes.$($CustomSecurityServicePrincipalAttribute)
            if ($Null -eq $ObjectCustomSec) {
                $adminTier = "Unclassified"
                $adminTierLevelName = "Unclassified"
                $service = "Unclassified"
                $associatedWorkload = ""
            }
            else {
                $adminTier = $ObjectCustomSec.adminTier
                $adminTierLevelName = $ObjectCustomSec.adminTierLevelName
                $AssociatedService = @()
                $AssociatedService += $ObjectCustomSec.service
                $AssociatedWorkload = @()
                $AssociatedWorkload += $ObjectCustomSec.associatedWorkload
            }

            # App Owner Tenant
            if ($null -eq $ServicePrincipal.AppOwnerOrganizationId) {
                $AppOwnerTenant = [PSCustomObject]@{
                    TenantId   = $Null
                    TenantName = $Null
                }
            }
            else {
                $AppOwnerTenant = Get-AADTenantInformation -AppTenantId $ServicePrincipal.AppOwnerOrganizationId
            }           

            Write-Verbose "Query Application of ServicePrincipal `"$($ServicePrincipal.displayName)`""
            try {
                $Application = $using:Applications | Where-Object appId -eq $ServicePrincipal.AppId
            }
            catch {
                Write-Verbose "Can not find app registration for $($ServicePrincipal.DisplayName)"
            }

            Write-Verbose "Query Application Permissions of ServicePrincipal `"$($ServicePrincipal.displayName)`""
            try {
                $AssignedAppRoles = New-Object System.Collections.ArrayList
                $SPRoleAssignments = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipal.id)/appRoleAssignments" -Verbose:$False)['value']
                $SPRoleAssignments = foreach ($SPRoleAssignment in $SPRoleAssignments) {
                    $AppRole = $using:AppRoles | Where-Object { $_.appRoleId -eq $SPRoleAssignment.appRoleId -and $_.ServicePrincipalObjectId -eq $SPRoleAssignment.resourceId }

                    [PSCustomObject]@{
                        "ResourceAppId"       = $AppRole.AppId
                        "ResourceDisplayName" = $SPRoleAssignment.resourceDisplayName
                        "AppRoleId"           = $SPRoleAssignment.appRoleId
                        "AppRoleDisplayName"  = $AppRole.AppRoleDisplayName
                    }
                }
                $AssignedAppRoles = $SPRoleAssignments | ConvertTo-Json -Compress -AsArray
            }
            catch {
                Write-Error -Message $_.Exception
                throw $_.Exception
            }

            Write-Verbose "Query Ownership of ServicePrincipal `"$($ServicePrincipal.displayName)`""
            try {
                $ServicePrincipalOwnerships = New-Object System.Collections.ArrayList
                $SpOwners = Invoke-GkSeMgGraphRequest -Uri "https://graph.microsoft.com/v1.0/serviceprincipals/$($ServicePrincipal.id)/owners" | Select-Object id
                foreach ($SpOwner in $SpOwners) {
                    $ServicePrincipalOwnerships.Add($SpOwner.id) | Out-Null
                }
                $ServicePrincipalOwnerships = $ServicePrincipalOwnerships | ConvertTo-Json -Compress -AsArray
            }
            catch {
                Write-Error -Message $_.Exception
                throw $_.Exception
            }

            if ($null -ne $Application.id) {
                Write-Verbose "Query Ownership of Application `"$($ServicePrincipal.displayName)`""
                try {
                    $AppOwnerships = New-Object System.Collections.ArrayList
                    $AppOwners = Invoke-GkSeMgGraphRequest -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.Id)/owners" | Select-Object id
                    foreach ($AppOwner in $AppOwners) {
                        $AppOwnerships.Add($AppOwner.id) | Out-Null
                    }
                    $AppOwnerships = $AppOwnerships | ConvertTo-Json -Compress -AsArray
                }
                catch {
                    Write-Error -Message $_.Exception
                    throw $_.Exception
                }
            }

            Write-Verbose "Query Group Memberships of ServicePrincipal `"$($ServicePrincipal.displayName)`""
            try {
                $GroupMemberships = New-Object System.Collections.ArrayList
                $TransitiveMemberOf = Invoke-GkSeMgGraphRequest -Uri "https://graph.microsoft.com/v1.0/serviceprincipals/$($ServicePrincipal.id)/transitiveMemberOf" | Select-Object id, displayName, isAssignableToRole
                foreach ($GroupMembership in $TransitiveMemberOf) {
                    $GroupMemberships.Add($GroupMembership) | Out-Null
                }
                $GroupMemberships = $GroupMemberships | ConvertTo-Json -Compress -AsArray
            }
            catch {
                Write-Error -Message $_.Exception
                throw $_.Exception
            }

            Write-Verbose "Query Directory Roles of ServicePrincipal `"$($ServicePrincipal.displayName)`""
            try {
                $TransitiveRoleAssignments = New-Object System.Collections.ArrayList

                $HeaderParams = @{
                    'ConsistencyLevel' = "eventual"
                }
                $TransitiveRoleAssignments = (Invoke-MgGraphRequest -Method Get -Headers $HeaderParams -Uri "https://graph.microsoft.com/beta/roleManagement/directory/transitiveRoleAssignments?`$count=true&`$filter=principalId eq '$($ServicePrincipal.Id)'")['value']
                $TransitiveRoleAssignments = foreach ($TransitiveRoleAssignment in $TransitiveRoleAssignments) {
                    $RoleDefinition = $using:DirectoryRoleDefinitions | Where-Object { $_.templateid -eq $TransitiveRoleAssignment.roleDefinitionId }

                    [PSCustomObject]@{
                        "RoleDefinitionName" = $RoleDefinition.displayName
                        "RoleDefinitionId"   = $TransitiveRoleAssignment.roleDefinitionId
                        "ResourceScope"      = $TransitiveRoleAssignment.resourceScope
                        "RoleAssignmentId"   = $TransitiveRoleAssignment.id
                        "IsPrivileged"       = $RoleDefinition.isPrivileged
                    }
                }
                $AssignedRoles = $TransitiveRoleAssignments | ConvertTo-Json -Compress -AsArray
            }
            catch {
                Write-Error -Message $_.Exception
                throw $_.Exception
            }

            if ( $ServicePrincipal.AppId -in $FirstPartyApps.AppId ) {
                $IsFirstPartyApp = $true
            }
            else {
                $IsFirstPartyApp = $false
            }

            if ( $null -ne $ServicePrincipal.appId) {
                $CurrentItem = [PSCustomObject]@{
                    "ServicePrincipalObjectId"   = $ServicePrincipal.Id
                    "AppObjectId"                = $Application.Id
                    "AppId"                      = $ServicePrincipal.AppId
                    "AppDisplayName"             = $ServicePrincipal.DisplayName
                    "CreatedDateTime"            = $ServicePrincipal.createdDateTime
                    "IsAccountEnabled"           = $ServicePrincipal.accountEnabled
                    "DisabledByMicrosoft"        = $ServicePrincipal.DisabledByMicrosoftStatus
                    "VerifiedPublisher"          = $ServicePrincipal.VerifiedPublisher.DisplayName
                    "PublisherName"              = $ServicePrincipal.PublisherName                    
                    "AppOwnerTenantName"         = $AppOwnerTenant.TenantName                    
                    "AppOwnerTenantId"           = $ServicePrincipal.AppOwnerOrganizationId
                    "IsFirstPartyApp"            = $IsFirstPartyApp
                    "ServicePrincipalType"       = $ServicePrincipal.servicePrincipalType
                    "SignInAudience"             = $ServicePrincipal.SignInAudience
                    "UserAssignmentRequired"     = $ServicePrincipal.appRoleAssignmentRequired
                    "ServiceManagementReference" = $ServicePrincipal.serviceManagementReference
                    "ServicePrincipalOwners"     = $ServicePrincipalOwnerships
                    "AppOwners"                  = $AppOwnerships
                    "AssignedAppRoles"           = $AssignedAppRoles
                    "GroupMembership"            = $GroupMemberships
                    "AssignedRoles"              = $AssignedRoles
                    "ObjectAdminTierLevel"       = $adminTier
                    "ObjectAdminTierLevelName"   = $adminTierLevelName            
                    "Tags"                       = @("Entra ID", "Automated Enrichment") | ConvertTo-Json -Compress -AsArray
                }
                ($using:NewWatchlistItems).Add( $CurrentItem ) | Out-Null
            }
        }
        catch {
            Write-Warning "Could not add $($ServicePrincipal.displayName) - Error $($_.Exception)"
            Continue
        }
    }

    #endregion
    return $NewWatchlistItems    
}