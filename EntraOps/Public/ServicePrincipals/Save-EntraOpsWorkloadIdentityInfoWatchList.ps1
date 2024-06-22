<#
.SYNOPSIS
    Get information of service principals and application in Microsoft Entra ID for creating content for the WatchList "WorkloadIdentityInfo".

.DESCRIPTION
    Get information of service principals and application in Microsoft Entra ID for creating content for the WatchList "WorkloadIdentityInfo".

.EXAMPLE
    Using System-assigned Managed Identity to get Service Principal of Schaengel Tenant from Azure KeyVault (Multi-Tenant Use Case) in CloudLab Tenant
    Connect-EntraOps -AuthenticationType "ServicePrincipal" -TenantName "schaengel.onmicrosoft.com" -KeyVaultTenantName "cloudlab.onmicrosoft.com" -KeyVaultName "identityops-kva" -PrefixSecretName "CA-CAAsCode-"
#>
function Save-EntraOpsWorkloadIdentityInfo {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$WatchListName = "WorkloadIdentityInfo"
        ,
        [Parameter(Mandatory = $true)]
        [System.String]$SentinelSubscriptionId
        ,
        [Parameter(Mandatory = $true)]
        [System.String]$SentinelResourceGroupName
        ,
        [Parameter(Mandatory = $true)]
        [System.String]$SentinelWorkspaceName
    )

    # Global Variables
    $ErrorActionPreference = "Stop"

    try {
        Import-Module "SentinelEnrichment" -ErrorAction Stop
    }
    catch {
        throw "Cannot load module SentinelEnrichment. Please install the module from the PowerShell gallery"
    }

    #region Connect to Azure and Microsoft Graph
    try {
        Write-Output "Sign-in with Managed Identity to Azure..."
        Connect-AzAccount -Identity -Subscription $SentinelSubscriptionId
        Write-Output "Succesfully logged into $SentinelSubscriptionId"
        Write-Output "Sign-in to Microsoft Graph with Managed Identity..."
        Connect-MgGraph -Identity
        $MgContext = Get-MgContext
        Write-Output "Succesfully logged to Tenant $($MgContext.TenantId)"
    }
    catch {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
    #endregion

    #region Get list of all tenant service principals, applications, 1st party apps and directory roles and app roles.
    Write-Verbose "Query tenant service principals - https://graph.microsoft.com/v1.0/serviceprincipals"
    $ServicePrincipals = Invoke-GkSeMgGraphRequest -Uri "https://graph.microsoft.com/v1.0/serviceprincipals"

    Write-Verbose "Query tenant applications - https://graph.microsoft.com/v1.0/applications"
    $Applications = Invoke-GkSeMgGraphRequest -Uri "https://graph.microsoft.com/v1.0/applications"

    Write-Verbose "Query directory role templates for mapping ID to name and further details"
    $DirectoryRoleDefinitions = Invoke-GkSeMgGraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions" | select-object displayName, templateId, isPrivileged, isBuiltin

    Write-Verbose "Query app roles for mapping ID to name"
    $SPObjectWithAppRoles = $ServicePrincipals | where-object { $null -ne $_.AppRoles }
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
    #endregion

    #region Gathering details for each Workload Identity and add to Array List
    Write-Verbose "Get details for enrichment of service principals"
    $NewWatchlistItems = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()

    $ServicePrincipals | ForEach-Object -Parallel {
        $ServicePrincipal = $_

        try {
            Write-Verbose "Collecting data for $($ServicePrincipal.displayName)"
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

            if ( $ServicePrincipal.AppId -in $using:FirstPartyApps.AppId ) {
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
                    "AppOwnerTenantId"           = $ServicePrincipal.AppOwnerOrganizationId
                    "IsFirstPartyApp"            = $IsFirstPartyApp
                    "ServicePrincipalType"       = $ServicePrincipal.servicePrincipalType
                    "SignInAudience"             = $ServicePrincipal.SignInAudience
                    "UserAssignmentRequired"     = $ServicePrincipal.appRoleAssignmentRequired
                    "ServiceManagementReference" = $ServicePrincipal.serviceManagementReference
                    "AssignedAppRoles"           = $AssignedAppRoles
                    "GroupMembership"            = $GroupMemberships
                    "AssignedRoles"              = $AssignedRoles
                    "Tags"                       = @("Entra ID", "Automated Enrichment")
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

    #region Update all watchlist items
    Write-Output "Write information to watchlist: $WatchListName"
    if ( $null -ne $NewWatchlistItems ) {

        $WatchListPath = Join-Path $PWD "$($WatchListName).csv"
        $NewWatchlistItems | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
        $Param2 = @{
            WatchListFilePath        = $WatchListPath
            DisplayName              = $WatchListName
            itemsSearchKey           = "ServicePrincipalObjectId"
            SubscriptionId           = $SentinelSubscriptionId
            ResourceGroupName        = $SentinelResourceGroupName
            WorkspaceName            = $SentinelWorkspaceName
            DefaultDuration          = "P14D"
            ReplaceExistingWatchlist = $true
        }
        New-GkSeAzSentinelWatchlist @Param2
    }
    #endregion
}