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
    $NewWatchlistItems = New-Object System.Collections.ArrayList
    Write-Verbose "Query tenant service principals - https://graph.microsoft.com/v1.0/serviceprincipals"
    $ServicePrincipals = Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/serviceprincipals"

    Write-Verbose "Query tenant applications - https://graph.microsoft.com/v1.0/applications"
    $Applications = Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/applications"

    Write-Verbose "Query directory role templates for mapping ID to name and further details"
    $DirectoryRoleDefinitions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions" | select-object displayName, templateId, isPrivileged, isBuiltin

    Write-Verbose "Query app roles for mapping ID to name"
    $SPObjectWithAppRoles = $ServicePrincipals | where-object { $_.AppRoles -ne $null }
    $AppRoles = foreach ($SPObjectWithAppRole in $SPObjectWithAppRoles) {
        $SPObjectWithAppRole.AppRoles | foreach-object {

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
    #endregion

    $ServicePrincipals | ForEach-Object -Parallel {
        $ServicePrincipal = $_

        #region Copy of Graph Request because of parallel processing, import-module does not work yet
        <#
        .SYNOPSIS
            Executing Query on Microsoft Graph API.

        .DESCRIPTION
            Wrapper to call Microsoft Graph API with pagination support to fetch all data and set default values.

        .EXAMPLE
            Get list of all transitive role assignments for a principal in Microsoft Entra ID by principalId and using ConsistencyLevel.
            Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/transitiveRoleAssignments?$count=true&`$filter=principalId eq '$Principal'" -ConsistencyLevel "eventual"

        .EXAMPLE
            Get list of all role definitions in Microsoft Entra ID.
            Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions"
        #>

        function Invoke-EntraOpsMsGraphQuery {

            param (
                [parameter(Mandatory = $false)]
                [string]$Method = 'GET',

                [parameter(Mandatory = $true)]
                [string]$Uri,

                [parameter(Mandatory = $false)]
                [string]$Body,

                [parameter(Mandatory = $false)]
                [string]$ConsistencyLevel,

                [parameter(Mandatory = $false)]
                [ValidateSet("HashTable", "PSObject", "HttpResponseMessage", "Json")]
                [string]$OutputType = "HashTable"
            )

            # Format headers.
            $HeaderParams = @{
            }


            # Check if the Uri is valid.
            if ($Uri -like "/beta/*" -or $Uri -like "/v1.0/*") {
                $Uri = "https://graph.microsoft.com$Uri"
            }
            elseif ($Uri -like "https://graph.microsoft.com/*") {
            }
            else {
                throw "Invalid Graph URI: $($Uri)!"
            }

            # Add ConsistencyLevel if provided in parameter
            if ($null -ne $ConsistencyLevel) {
                $HeaderParams.Add('ConsistencyLevel', "$ConsistencyLevel")
            }

            # Create empty arrays to store the results
            $QueryRequest = @()
            $QueryResult = @()

            if ($UseAzPwshOnly -eq $True) {
                $AccessToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
                $HeaderParams.Add('Authorization', "Bearer $($AccessToken)")

                # Run the initial query to Graph API
                if ($Method -eq 'GET') {
                    $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -ResponseHeadersVariable $ResponseMessage
                }
                else {
                    $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -Body $Body -ResponseHeadersVariable $ResponseMessage
                }

                # Add the initial query result to the result array
                if ($QueryRequest.value) {
                    $QueryResult += $QueryRequest.value
                }
                else {
                    $QueryResult += $QueryRequest
                }

                # Run another query to fetch data until there are no pages left
                if ($Uri -notlike "*`$top*") {
                    while ($QueryRequest.'@odata.nextLink') {
                        $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -ResponseHeadersVariable $ResponseMessage
                        $QueryResult += $QueryRequest.value
                    }
                }

                switch ($OutputType) {
                    HashTable { $QueryResult = $QueryResult | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10 -AsHashtable }
                    JSON { $QueryResult = $QueryResult | ConvertTo-Json -Depth 10 }
                    PSObject { $QueryResult = $QueryResult }
                    HttpResponseMessage { $QueryResult = $ResponseMessage }
                }
                $QueryResult

            }
            else {
                # Run the initial query to Graph API
                if ($Method -eq 'GET') {
                    $QueryRequest = Invoke-EntraOpsMsGraphQuery -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -OutputType $OutputType
                }
                else {
                    $QueryRequest = Invoke-EntraOpsMsGraphQuery -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -Body $Body -OutputType $OutputType
                }

                # Add the initial query result to the result array
                if ($QueryRequest.value) {
                    $QueryResult += $QueryRequest.value
                }
                else {
                    $QueryResult += $QueryRequest
                }

                # Run another query to fetch data until there are no pages left
                if ($Uri -notlike "*`$top*") {
                    while ($QueryRequest.'@odata.nextLink') {
                        $QueryRequest = Invoke-EntraOpsMsGraphQuery -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -OutputType $OutputType
                        $QueryResult += $QueryRequest.value
                    }
                }
                $QueryResult
            }
        }
        #endregion

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

        try {
            Write-Verbose "Collecting data for $($ServicePrincipal.displayName)"

            # Custom Security Attributes
            $ObjectCustomSec = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/servicePrincipals/$($ServicePrincipal.Id)" + '?$select=customSecurityAttributes') -OutputType PSObject).customSecurityAttributes.$($CustomSecurityServicePrincipalAttribute)
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

            # Associated Managed Identities
            if ($ServicePrincipal.servicePrincipalType -eq "ManagedIdentity") {
                $AppOwnerTenant = Get-AADTenantInformation -AppTenantId $TenantId
                $Query = "resources | where (identity has 'SystemAssigned' or identity has 'UserAssigned') and (name == '$($Sp.displayName)' or identity contains '$($Sp.displayName)') | project id"
                $AzGraphResult = Invoke-EntraOpsAzGraphQuery -KqlQuery $Query
                $associatedWorkload = @()
                $associatedWorkload += $AzGraphResult.id
            }

            # Service Princpal Details
            Write-Verbose "Query Application of ServicePrincipal `"$($ServicePrincipal.displayName)`""
            try {
                $Application = $using:Applications | Where-Object appId -eq $ServicePrincipal.AppId
            }
            catch {
                Write-Verbose "Can not find app registration for $($ServicePrincipal.DisplayName)"
            }

            Write-Verbose "Query Application Permissions of ServicePrincipal `"$($ServicePrincipal.displayName)`""
            try {
                $SPRoleAssignments = (Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/servicePrincipals/$($ServicePrincipal.id)/appRoleAssignments")
                $SPRoleAssignments = foreach ($SPRoleAssignment in $SPRoleAssignments) {
                    $AppRole = $using:AppRoles | where-object { $_.appRoleId -eq $SPRoleAssignment.appRoleId -and $_.ServicePrincipalObjectId -eq $SPRoleAssignment.resourceId }

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

            Write-Verbose "Query Group Memberships of ServicePrincipal `"$($ServicePrincipal.displayName)`""
            try {
                $TransitiveMemberOf = Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/serviceprincipals/$($ServicePrincipal.id)/transitiveMemberOf" | Select-Object id, displayName, isAssignableToRole
                $GroupMemberships = $TransitiveMemberOf | ConvertTo-Json -Compress -AsArray
            }
            catch {
                Write-Error -Message $_.Exception
                throw $_.Exception
            }

            Write-Verbose "Query Directory Roles of ServicePrincipal `"$($ServicePrincipal.displayName)`""
            try {
                $TransitiveRoleAssignments = (Invoke-EntraOpsMsGraphQuery -Method Get -ConsistencyLevel "eventual" -Uri "/beta/roleManagement/directory/transitiveRoleAssignments?`$count=true&`$filter=principalId eq '$($ServicePrincipal.Id)'")
                $TransitiveRoleAssignments = foreach ($TransitiveRoleAssignment in $TransitiveRoleAssignments) {
                    $RoleDefinition = $using:DirectoryRoleDefinitions | where-object { $_.templateid -eq $TransitiveRoleAssignment.roleDefinitionId }

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
                    "AppOwnerTenantName"         = $AppOwnerTenant.TenantName
                    "VerifiedPublisher"          = $ServicePrincipal.VerifiedPublisher.DisplayName
                    "PublisherName"              = $ServicePrincipal.PublisherName
                    "IsFirstPartyApp"            = $IsFirstPartyApp
                    "ServicePrincipalType"       = $ServicePrincipal.servicePrincipalType
                    "SignInAudience"             = $ServicePrincipal.SignInAudience
                    "UserAssignmentRequired"     = $ServicePrincipal.appRoleAssignmentRequired
                    "ServiceManagementReference" = $ServicePrincipal.serviceManagementReference
                    "AssignedAppRoles"           = $AssignedAppRoles
                    "GroupMembership"            = $GroupMemberships
                    "AssignedRoles"              = $AssignedRoles
                    "ObjectAdminTierLevel"       = $adminTier
                    "ObjectAdminTierLevelName"   = $adminTierLevelName
                    "AssociatedWorkload"         = $AssociatedWorkload | ConvertTo-Json -Compress
                    "AssociatedService"          = $AssociatedService | ConvertTo-Json -Compress
                    "Tags"                       = @("Entra ID", "Automated Enrichment") | ConvertTo-Json -Compress
                }
                ($using:NewWatchlistItems).Add( $CurrentItem ) | Out-Null
            }
        }
        catch {
            Continue
        }
    }
    #endregion
    return $NewWatchlistItems
}