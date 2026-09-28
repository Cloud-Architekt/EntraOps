<#
.SYNOPSIS
    Create required App Registrations to execute EntraOps in Automation runbook or DevOps pipelines.

.DESCRIPTION
    Create required Workload Identity (new or use existing Service Principal) to execute EntraOps in Automation runbook or DevOps pipelines.

.PARAMETER AppDisplayName
    Display name of the App Registration which will be created.

.PARAMETER ExistingSpObjectId
    ObjectId of the existing Service Principal which should be used. If not provided, a new App Registration will be created. Can be combined with CreateFederatedCredential to complete or repair federation on the existing application.

.PARAMETER ConfigFile
    Location of the config file which will be used to get required parameters. Default is ./EntraOpsConfig.json.

.PARAMETER CreateFederatedCredential
    Switch to create a federated credential for the App Registration.

.PARAMETER GitHubOrg
    GitHub organization or username name where the EntraOps repository is hosted which will be used for creating the federated credential.

.PARAMETER GitHubRepo
    GitHub repository name of EntraOps which will be used for creating the federated credential.

.PARAMETER FederatedEntityType
    Type of the entity (e.g., branch or environment) which will be used for creating the federated credential.
    By default, the value is "Branch".

.PARAMETER FederatedEntityName
    Name of the entity (e.g., branch name "main" or environment name "prod") which will be used for creating the federated credential.
    By default, the value is "main".

.PARAMETER AdoOrgName
    Azure DevOps organization name used in the service connection subject.

.PARAMETER AdoProjectName
    Azure DevOps project name used in the service connection subject.

.PARAMETER AdoServiceConnectionName
    Exact Azure DevOps service connection name.

.PARAMETER AdoFederatedCredentialIssuer
    Exact issuer shown by the Azure DevOps workload identity federation service connection.

.EXAMPLE
    Create App Registration based on the configuration in the config file (default location: ./EntraOpsConfig.json).
    If the Ingestion to Log Analytics is defined in Config file, the required permissions will be added to the Resource Group of the Data Collection Rule.
    Same for defined option to ingest to Sentinel WatchLists, the related permissions will be added to the Resource Group of the Sentinel workspace.
    New-EntraOpsWorkloadIdentity -AppDisplayName "EntraOps Reporting"

.EXAMPLE
    Create App Registration based on the configuration in the config file (default location: ./EntraOpsConfig.json) and create a federated credential for GitHub repository branch defined in parameter.
    New-EntraOpsWorkloadIdentity -AppDisplayName "EntraOps Reporting" -CreateFederatedCredential -GitHubOrg "Cloud-Architekt" -GitHubRepo "EntraOps-TenantName" -FederatedEntityType "Branch" -FederatedEntityName "main"
 #>

function New-EntraOpsWorkloadIdentity {

    [CmdletBinding()]
    param (
        [parameter(Mandatory = $True)]
        [string]$AppDisplayName,

        [Parameter(Mandatory = $False)]
        [string]$ExistingSpObjectId,

        [Parameter(Mandatory = $False)]
        [string]$ConfigFile = "$EntraOpsBasefolder/EntraOpsConfig.json",

        [Parameter(Mandatory = $False)]
        [switch]$CreateFederatedCredential,

        [Parameter(Mandatory = $False)]
        [string]$GitHubOrg,

        [Parameter(Mandatory = $False)]
        [string]$GitHubRepo,

        [Parameter(Mandatory = $False)]
        [ValidateSet("Branch", "Environment")]
        [string]$FederatedEntityType = "Branch",

        [Parameter(Mandatory = $False)]
        [string]$FederatedEntityName = "main",

        # Assign Reader at the ARM tenant root scope ("/") in addition to the root management group.
        # Opt-in because a "/"-scoped assignment is only creatable after elevateAccess, is not shown in the
        # portal RBAC blades, and is therefore routinely missed in access reviews and offboarding. It is only
        # needed to enumerate role assignments made directly at "/"; the root management group assignment
        # already covers every management group, subscription and resource below it.
        [Parameter(Mandatory = $False)]
        [switch]$GrantArmRootScopeReader,

        [Parameter(Mandatory = $False)]
        [string]$AdoOrgName,

        [Parameter(Mandatory = $False)]
        [string]$AdoProjectName,

        [Parameter(Mandatory = $False)]
        [string]$AdoServiceConnectionName,

        [Parameter(Mandatory = $False)]
        [string]$AdoFederatedCredentialIssuer
    )

    $ErrorActionPreference = "Stop"
    $ProvisioningFailures = [System.Collections.Generic.List[string]]::new()

    function Add-EntraOpsProvisioningFailure {
        param ([Parameter(Mandatory = $true)][string]$Message)

        $ProvisioningFailures.Add($Message)
        Write-Warning $Message
    }

    # Load configuration file
    $Config = Get-Content -Path $ConfigFile | ConvertFrom-Json
    if ($CreateFederatedCredential) {
        if ($Config.DevOpsPlatform -eq 'GitHub') {
            $GitHubOrg = $GitHubOrg.Trim()
            $GitHubRepo = $GitHubRepo.Trim()
            $FederatedEntityName = $FederatedEntityName.Trim()
            if ([string]::IsNullOrWhiteSpace($GitHubOrg) -or [string]::IsNullOrWhiteSpace($GitHubRepo) -or [string]::IsNullOrWhiteSpace($FederatedEntityName)) {
                throw "GitHubOrg, GitHubRepo, and FederatedEntityName must contain non-whitespace values when CreateFederatedCredential is specified for GitHub."
            }
        } elseif ($Config.DevOpsPlatform -eq 'AzureDevOps') {
            $AdoOrgName = $AdoOrgName.Trim()
            $AdoProjectName = $AdoProjectName.Trim()
            $AdoServiceConnectionName = $AdoServiceConnectionName.Trim()
            $AdoFederatedCredentialIssuer = $AdoFederatedCredentialIssuer.Trim()
            if ([string]::IsNullOrWhiteSpace($AdoOrgName) -or [string]::IsNullOrWhiteSpace($AdoProjectName) -or
                [string]::IsNullOrWhiteSpace($AdoServiceConnectionName) -or [string]::IsNullOrWhiteSpace($AdoFederatedCredentialIssuer)) {
                throw "AdoOrgName, AdoProjectName, AdoServiceConnectionName, and the exact AdoFederatedCredentialIssuer shown by Azure DevOps are required when CreateFederatedCredential is specified for AzureDevOps."
            }
        }
    }

    #region Import module and check connection to Graph and Azure Resource Manager API
    # Check if required Graph module is available
    Install-EntraOpsRequiredModule -ModuleName Microsoft.Graph.Applications

    # Connect to Graph
    Write-Host "Connect to Microsoft Graph..."
    $GraphScopes = @(
        "AdministrativeUnit.ReadWrite.All",
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory"
    )
    Connect-MgGraph -Scopes $GraphScopes -TenantId $Config.TenantId

    Write-Host "Connect to Azure..."
    $AzContext = Get-AzContext
    if ($AzContext.Tenant.Id -ne $Config.TenantId) {
        Connect-AzAccount -Tenant $Config.TenantId
    }
    #endregion

    #region Create or update existing App Registration
    if ($ExistingSpObjectId) {
        Write-Verbose "Get details of existing Service Principal with ObjectId $ExistingSpObjectId..."
        try {
            $SpObject = Get-MgServicePrincipal -ServicePrincipalId $ExistingSpObjectId
            if ($CreateFederatedCredential) {
                $MatchingApplications = @(Get-MgApplication -Filter "appId eq '$($SpObject.AppId)'")
                if ($MatchingApplications.Count -ne 1) {
                    throw "Expected exactly one application for service principal '$ExistingSpObjectId' with appId '$($SpObject.AppId)', but found $($MatchingApplications.Count)."
                }
                $AppObject = $MatchingApplications[0]
            }
        } catch {
            Write-Error "Failed to get Service Principal with ObjectId $ExistingSpObjectId. Error: $_"
        }
    } else {
        # Create App Registration
        Write-Output "Create App Registration $AppDisplayName..."
        try {
            $AppObject = New-MgApplication -DisplayName $AppDisplayName -SignInAudience AzureADMyOrg
        } catch {
            Write-Error "Failed to create $AppDisplayName. Error: $_"
        }

        # Short delay before contiune and wait sync
        Write-Verbose "Wait 3 seconds before create Service Principal from App Registration..."
        Start-Sleep 3

        # Create Service Principal
        Write-Verbose "Create Service Principal from $AppDisplayName $($AppObject.Id)..."
        try {
            $SpObject = New-MgServicePrincipal -DisplayName $AppDisplayName -AppId $AppObject.AppId
        } catch {
            Write-Error "Failed to create Service Principal for $AppDisplayName. Error: $_"
        }
        #endregion
    }

    #region Add required Microsoft Graph API Permissions for Pull (Read) Operations

    # Get Graph API App Roles to map required App Role Names to App Role IDs
    Write-Verbose "Get Microsoft Graph API App Roles..."
    $MsGraph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

    try {
        $ExistingGraphAppRoleAssignments = [System.Collections.Generic.List[object]]::new()
        foreach ($Assignment in @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpObject.Id -All)) {
            $ExistingGraphAppRoleAssignments.Add($Assignment)
        }
    } catch {
        throw "Failed to read existing Microsoft Graph application permission assignments for $AppDisplayName. No permissions were changed. Error: $($_.Exception.Message)"
    }

    function Add-EntraOpsGraphApplicationPermissions {
        param (
            [Parameter(Mandatory = $true)][string[]]$PermissionNames,
            [Parameter(Mandatory = $true)][string]$Purpose
        )

        foreach ($PermissionName in $PermissionNames) {
            $MatchingRoles = @($MsGraph.AppRoles | Where-Object { $_.Value -eq $PermissionName })
            if ($MatchingRoles.Count -ne 1) {
                Add-EntraOpsProvisioningFailure -Message "Could not resolve the Microsoft Graph application permission '$PermissionName' for $Purpose."
                continue
            }

            $GraphApiPermission = $MatchingRoles[0]
            $ExistingAssignment = $ExistingGraphAppRoleAssignments | Where-Object {
                $_.ResourceId -eq $MsGraph.Id -and $_.AppRoleId -eq $GraphApiPermission.Id
            } | Select-Object -First 1
            if ($ExistingAssignment) {
                Write-Host "- Microsoft Graph API Permission $PermissionName is already assigned"
                continue
            }

            Write-Host "- Adding $($GraphApiPermission.Origin) API Permission $PermissionName"
            try {
                $NewAssignment = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpObject.Id -PrincipalId $SpObject.Id -ResourceId $MsGraph.Id -AppRoleId $GraphApiPermission.Id
                $ExistingGraphAppRoleAssignments.Add($NewAssignment)
            } catch {
                Add-EntraOpsProvisioningFailure -Message "Failed to add Microsoft Graph API Permission '$PermissionName' to $AppDisplayName for $Purpose. Error: $($_.Exception.Message)"
            }
        }
    }

    # Graph API permissions for Pull operations
    $PullPermissionsToAdd = @(
        "AdministrativeUnit.Read.All",
        "Application.Read.All",
        "CustomSecAttributeAssignment.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementRBAC.Read.All",
        "DeviceManagementServiceConfig.Read.All",
        "Directory.Read.All",
        "DirectoryRecommendations.Read.All",
        "EntitlementManagement.Read.All",
        "Group.Read.All",
        "RemoteTenantGroups.Read.All",
        "PrivilegedAccess.Read.AzureADGroup",
        "PrivilegedEligibilitySchedule.Read.AzureADGroup",
        "Policy.Read.All",
        "RoleManagement.Read.All",  
        "TenantGovernance-Relationship.Read.All",  
        "ThreatHunting.Read.All",
        "User.Read.All",
        "Zone.Read.All"
    )

    Write-Output "Adding Pull permissions..."
    Add-EntraOpsGraphApplicationPermissions -PermissionNames $PullPermissionsToAdd -Purpose "Pull operations"
    #endregion

    #region Add required Microsoft Graph API Permissions for Push (Change) Operations

    # Graph API permissions for Push operations
    if ($Config.AutomatedAdministrativeUnitManagement.ApplyAdministrativeUnitAssignments -eq $true -or $Config.AutomatedRmauAssignmentsForUnprotectedObjects.ApplyRmauAssignmentsForUnprotectedObjects -eq $true) {
        $PushPermissionsToAdd = @(
            "AdministrativeUnit.ReadWrite.All"
        )
    
        Write-Output "Adding Push permissions..."
        Add-EntraOpsGraphApplicationPermissions -PermissionNames $PushPermissionsToAdd -Purpose "Push operations"
    } else {
        Write-Output "Skipping Push permissions... (ApplyAdministrativeUnitAssignments and/or ApplyRmauAssignmentsForUnprotectedObjects is set to false)"
    }

    # Graph API permission for updating Entitlement Management catalogs to privileged catalogs
    # Caution: Elevated permission, only assigned if ApplyPrivilegedElmCatalogProtection is enabled in the config file
    # Required permission reference: https://learn.microsoft.com/en-us/graph/api/entitlementmanagement-update?view=graph-rest-beta
    if ($Config.AutomatedElmCatalogProtection.ApplyPrivilegedElmCatalogProtection -eq $true) {
        $ElmPushPermissionsToAdd = @(
            "EntitlementManagement.ReadWrite.All"
        )

        Write-Output "Adding Push permissions for privileged ELM catalog protection..."
        Write-Warning "EntitlementManagement.ReadWrite.All is an elevated permission and should be used with caution."
        Add-EntraOpsGraphApplicationPermissions -PermissionNames $ElmPushPermissionsToAdd -Purpose "privileged ELM catalog protection"
    } else {
        Write-Output "Skipping Push permissions for privileged ELM catalog protection... (ApplyPrivilegedElmCatalogProtection is set to false)"
    }

    #endregion

    #region Add required Microsoft Graph API permission for Tenant Governance Snapshot (UTCM)
    # ConfigurationMonitoring.ReadWrite.All is Microsoft's documented least-privileged permission for
    # the createSnapshot API (required for both delegated and application auth - there is no
    # Read.All-only option for creating a snapshot job, only for reading/listing existing ones).
    # Reference: https://learn.microsoft.com/en-us/graph/api/configurationbaseline-createsnapshot
    if ($Config.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot -eq $true) {
        $TenantGovernancePermissionsToAdd = @(
            "ConfigurationMonitoring.ReadWrite.All"
        )

        Write-Output "Adding Tenant Governance Snapshot permissions..."
        Add-EntraOpsGraphApplicationPermissions -PermissionNames $TenantGovernancePermissionsToAdd -Purpose "Tenant Governance snapshots"
    } else {
        Write-Output "Skipping Tenant Governance Snapshot permissions... (EnableTenantGovernanceSnapshot is set to false)"
    }
    #endregion

    #region Configure Microsoft Tenant Configuration Management (UTCM) service principal permissions
    # The Tenant Governance Snapshot feature relies on the first-party "Microsoft Tenant Configuration
    # Management" service principal to read the configured Microsoft Entra resources on EntraOps'
    # behalf. Delegate the creation and least-privileged permission assignment to the dedicated
    # configuration cmdlet so it can also be run standalone (e.g. after extending
    # TenantGovernanceSnapshot.ResourcesToInclude with new resource types) without re-running the
    # whole workload identity setup.
    # Reference: https://learn.microsoft.com/en-us/graph/utcm-entra-resources
    if ($Config.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot -eq $true) {
        try {
            Register-EntraOpsTenantGovernanceServicePrincipal -ResourcesToInclude $Config.TenantGovernanceSnapshot.ResourcesToInclude -TenantId $Config.TenantId | Out-Null
        } catch {
            Add-EntraOpsProvisioningFailure -Message "Failed to configure the Microsoft Tenant Configuration Management service principal. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Output "Skipping Microsoft Tenant Configuration Management (UTCM) service principal setup... (EnableTenantGovernanceSnapshot is set to false)"
    }
    #endregion

    #region Add required Microsoft Entra ID (scoped) directory role for managing Conditional Access Target Groups
    if ($Config.AutomatedConditionalAccessTargetGroups.ApplyConditionalAccessTargetGroups -eq $true) {
        $AdminUnitName = $Config.AutomatedConditionalAccessTargetGroups.AdminUnitName
        $AdminUnits = @(Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$(ConvertTo-EntraOpsODataStringLiteral -Value $AdminUnitName)'" -OutputType PSObject -DisableCache)
        # -AllowNotFound: a missing AU is the expected first-run state - the create branch below handles it.
        $AdminUnitId = (Select-EntraOpsUniqueGraphObject -InputObject $AdminUnits -ObjectDescription "administrative unit '$AdminUnitName'" -AllowNotFound).id
        #region Create Administrative Unit if it does not exist
        if (-not $AdminUnitId) {
            Write-Host "Creating Administrative Unit $($AdminUnitName)"

            $AuParams = @{
                DisplayName                  = $AdminUnitName
                Description                  = "This administrative unit contains groups for Conditional Access Targeting"
                isMemberManagementRestricted = $true
            }

            $Body = $AuParams | ConvertTo-Json -Depth 10
            try {
                $NewAdminUnitId = (Invoke-MgGraphRequest -Method "POST" -Body $Body -Uri "https://graph.microsoft.com/beta/administrativeUnits").id
            } catch {
                Add-EntraOpsProvisioningFailure -Message "Cannot create required Administrative Unit '$AdminUnitName'. Error: $($_.Exception.Message)"
            }

            # Check if AU has been created successfully, wait for delay and retry if not available yet
            Try {
                Do { Start-Sleep -Seconds 1 }
                Until ($AdminUnitId = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits/$($NewAdminUnitId)" -DisableCache).Id)
                Write-Host "$($AdminUnitName) - $($AdminUnitId) has been created successfully" -f Green
            } Catch {
                Add-EntraOpsProvisioningFailure -Message "Required Administrative Unit '$AdminUnitName' is not available after creation. Error: $($_.Exception.Message)"
            }
        } else {
            Write-Host "Administrative Unit $($AdminUnitName) - $($AdminUnitId) already exists"
        }

        # Add scoped permissions as Group Administrator to the Administrative Unit
        $ScopedGroupAdminRoleParams = @{
            '@odata.type'    = "#microsoft.graph.unifiedRoleAssignment"
            principalId      = $($SpObject.Id)
            roleDefinitionId = "fdd7a751-b60b-444a-984c-02652fe8fa1c" # Group Administrator
            directoryScopeId = "/administrativeUnits/$($AdminUnitId)"
        }

        try {
            $ExistingScopedRoleAssignments = @(Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($SpObject.Id)'" -OutputType PSObject -DisableCache)
            $ExistingScopedGroupAdminRole = $ExistingScopedRoleAssignments | Where-Object {
                $_.roleDefinitionId -eq $ScopedGroupAdminRoleParams.roleDefinitionId -and
                $_.directoryScopeId -eq $ScopedGroupAdminRoleParams.directoryScopeId
            } | Select-Object -First 1

            if ($ExistingScopedGroupAdminRole) {
                Write-Host "The scoped Group Administrator role on Administrative Unit $AdminUnitName is already assigned to $($SpObject.Id)." -f Green
            } else {
                $Body = $ScopedGroupAdminRoleParams | ConvertTo-Json -Depth 10
                $DirectoryRoleAssignmentId = (Invoke-MgGraphRequest -Method "POST" -Body $Body -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments").id
                Write-Host "Assigned permissions to Administrative Unit $($AdminUnitName) for $($SpObject.Id) - $($DirectoryRoleAssignmentId)" -f Green
            }
        } catch {
            Add-EntraOpsProvisioningFailure -Message "Cannot verify or assign the required scoped Group Administrator role on Administrative Unit '$AdminUnitName' to '$($SpObject.Id)'. Error: $($_.Exception.Message)"
        }

    } else {
        Write-Output "Skipping permissions to manage Conditional Access Groups... (ApplyConditionalAccessTargetGroups is set to false)"
    }    
    #endregion

    #region Add required role assignments in Azure RBAC
    function Add-EntraOpsAzureRoleAssignment {
        param (
            [Parameter(Mandatory = $true)][string]$RoleDefinitionName,
            [Parameter(Mandatory = $true)][string]$Scope,
            [Parameter(Mandatory = $true)][string]$ObjectId,
            [string]$ApplicationId,
            [Parameter(Mandatory = $true)][string]$Purpose
        )

        try {
            $ExistingAssignments = @(Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -ErrorAction Stop)
        } catch {
            Add-EntraOpsProvisioningFailure -Message "Failed to check the existing '$RoleDefinitionName' Azure role assignment at '$Scope' for $Purpose. Error: $($_.Exception.Message)"
            return
        }

        if ($ExistingAssignments.Count -gt 0) {
            Write-Output "The '$RoleDefinitionName' role at '$Scope' is already assigned for $Purpose."
            return
        }

        try {
            if ([string]::IsNullOrWhiteSpace($ApplicationId)) {
                New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope | Out-Null
            } else {
                New-AzRoleAssignment -ApplicationId $ApplicationId -RoleDefinitionName $RoleDefinitionName -Scope $Scope | Out-Null
            }
        } catch {
            Add-EntraOpsProvisioningFailure -Message "Failed to assign the '$RoleDefinitionName' Azure role at '$Scope' for $Purpose. Error: $($_.Exception.Message)"
        }
    }

    # Logic to add required role assignment in Azure RBAC
    function Add-AzureRolePermissions ($RoleDefinitionName, $ResourceGroupName, $SubscriptionId) {
        if (!$RoleDefinitionName -or !$ResourceGroupName -or !$SubscriptionId) {
            Add-EntraOpsProvisioningFailure -Message "Resource group name, subscription ID, and role definition name must be configured before assigning Azure permissions for Push operations."
        } else {
            try {
                Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
                $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName
            } catch {
                Add-EntraOpsProvisioningFailure -Message "Failed to resolve Azure resource group '$ResourceGroupName' in subscription '$SubscriptionId' for the '$RoleDefinitionName' assignment. Error: $($_.Exception.Message)"
                return
            }

            Add-EntraOpsAzureRoleAssignment -RoleDefinitionName $RoleDefinitionName -Scope $ResourceGroup.ResourceId -ObjectId $SpObject.Id -Purpose "resource group '$ResourceGroupName'"
        }
    }
    Start-Sleep 5 # Wait for adding permission to new created Service Principal

    if ($Config.LogAnalytics.IngestToLogAnalytics -eq $true) {
        try {
            Write-Output "Adding permissions to Resource Group of Data Collection Rule on $($Config.LogAnalytics.DataCollectionResourceGroupName)..."
            Add-AzureRolePermissions -RoleDefinitionName "Monitoring Metrics Publisher" -ResourceGroupName $Config.LogAnalytics.DataCollectionResourceGroupName -SubscriptionId $Config.LogAnalytics.DataCollectionRuleSubscriptionId
            Add-AzureRolePermissions -RoleDefinitionName "Reader" -ResourceGroupName $Config.LogAnalytics.DataCollectionResourceGroupName -SubscriptionId $Config.LogAnalytics.DataCollectionRuleSubscriptionId    
        } catch {
            Add-EntraOpsProvisioningFailure -Message "Failed to assign required roles on Log Analytics resource group '$($Config.LogAnalytics.DataCollectionResourceGroupName)'. Error: $($_.Exception.Message)"
        }
    }

    if ($Config.SentinelWatchLists.IngestToWatchLists -eq $true) {
        try {
            Write-Output "Adding permissions to Resource Group of Sentinel Workspace on $($Config.SentinelWatchLists.SentinelResourceGroupName)..."
            Add-AzureRolePermissions -RoleDefinitionName "Microsoft Sentinel Contributor" -ResourceGroupName $Config.SentinelWatchLists.SentinelResourceGroupName -SubscriptionId $Config.SentinelWatchLists.SentinelSubscriptionId    
        } catch {
            Add-EntraOpsProvisioningFailure -Message "Failed to assign required roles on Microsoft Sentinel resource group '$($Config.SentinelWatchLists.SentinelResourceGroupName)'. Error: $($_.Exception.Message)"
        }
    }

    # Azure collection and Azure Resource Graph-backed features require Reader on the tenant root
    # management group so all management groups, subscriptions and resources below it are visible.
    if (($Config.RbacSystems -contains "Azure") `
            -or ($Config.AutomatedControlPlaneScopeUpdate.ApplyAutomatedControlPlaneScopeUpdate -eq $true -and $Config.AutomatedControlPlaneScopeUpdate.PrivilegedObjectClassificationSource -contains "PrivilegedRolesFromAzGraph") `
            -or ($Config.SentinelWatchLists.WatchListTemplates -contains "HighValueAssets") -or ($Config.SentinelWatchLists.WatchListWorkloadIdentity -contains "WorkloadIdentityAttackPaths") -or ($Config.SentinelWatchLists.WatchListWorkloadIdentity -contains "ManagedIdentityAssignedResourceId")) {
        Write-Output "Adding permissions as Reader on Tenant Root Group for analyzing RBAC and/or Managed Identity resources..."
        Add-EntraOpsAzureRoleAssignment -RoleDefinitionName "Reader" -Scope "/providers/Microsoft.Management/managementGroups/$($Config.TenantId)" -ObjectId $SpObject.Id -Purpose "Azure collection and Resource Graph analysis"
    }

    # Add required permissions as Reader on the ARM tenant root scope ("/") when Azure is included as
    # RBAC system, to allow scanning of Azure RBAC role assignments (incl. elevateAccess-scoped
    # assignments) across the entire tenant hierarchy.
    if ($Config.RbacSystems -contains "Azure") {
        if ($GrantArmRootScopeReader) {
            Write-Warning "Assigning Reader at the ARM tenant root scope (/). This assignment is only visible via 'az role assignment list --scope /' and is NOT shown in the portal RBAC blades - include it in access reviews and offboarding, and remove it with 'az role assignment delete --scope /' when decommissioning EntraOps."
            Write-Output "Adding permissions as Reader on ARM tenant root scope (/) for scanning Azure RBAC role assignments..."
            $WorkloadIdentityAppId = if ($AppObject) { $AppObject.AppId } else { $SpObject.AppId }
            Add-EntraOpsAzureRoleAssignment -RoleDefinitionName "Reader" -Scope "/" -ObjectId $SpObject.Id -ApplicationId $WorkloadIdentityAppId -Purpose "ARM tenant-root role-assignment discovery"
        } else {
            Write-Output "Skipping Reader assignment on ARM tenant root scope (/). Azure RBAC assignments made directly at '/' (after elevateAccess) will not be visible to EntraOps; everything under the root management group is still covered. Re-run with -GrantArmRootScopeReader to enable tenant-root visibility."
        }
    }
    #endregion    

    #region Add ClientId to environment file
    Write-Output "Write $AppDisplayName AppId to environment file $($ConfigFile)..."
    $Config.ClientId = if ($AppObject) { $AppObject.AppId } else { $SpObject.AppId }
    $Config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFile
    #endregion

    #region Add Federated Credential to Application object
    if ($Config.AuthenticationType -eq "FederatedCredentials" -and $CreateFederatedCredential) {
        if ($Config.DevOpsPlatform -eq "GitHub") {
            Write-Output "Add Federated Credential to $AppDisplayName..."

            switch ($FederatedEntityType) {
                Branch {
                    $Entity = "ref:refs/heads/$($FederatedEntityName)"
                }
                Environment {
                    $Entity = "environment:$($FederatedEntityName)"
                }
            }

            $FederatedCredentialParam = @{
                name      = "$($GitHubRepo)-$($FederatedEntityType)-$($FederatedEntityName)"
                issuer    = "https://token.actions.githubusercontent.com"
                subject   = "repo:$($GitHubOrg)/$($GitHubRepo):$($Entity)"
                audiences = @(
                    "api://AzureADTokenExchange"
                )
            }

            $ExistingFederatedCredentials = @()
            $CanCreateFederatedCredential = $true
            try {
                $ExistingFederatedCredentials = @(Get-MgApplicationFederatedIdentityCredential -ApplicationId $AppObject.Id -All)
            } catch {
                $CanCreateFederatedCredential = $false
                Add-EntraOpsProvisioningFailure -Message "Failed to read existing federated credentials for $AppDisplayName. Error: $($_.Exception.Message)"
            }

            if ($CanCreateFederatedCredential) {
                $ExistingFederatedCredential = $ExistingFederatedCredentials | Where-Object { $_.Name -eq $FederatedCredentialParam.name } | Select-Object -First 1
                if ($ExistingFederatedCredential) {
                    $AudienceDifference = @(Compare-Object -ReferenceObject @($FederatedCredentialParam.audiences) -DifferenceObject @($ExistingFederatedCredential.Audiences))
                    if ($ExistingFederatedCredential.Issuer -ceq $FederatedCredentialParam.issuer -and
                        $ExistingFederatedCredential.Subject -ceq $FederatedCredentialParam.subject -and
                        $AudienceDifference.Count -eq 0) {
                        Write-Output "Federated Credential '$($FederatedCredentialParam.name)' is already configured."
                    } else {
                        Add-EntraOpsProvisioningFailure -Message "Federated Credential '$($FederatedCredentialParam.name)' already exists but its issuer, subject, or audience does not match the requested GitHub identity. Remove or correct the existing credential before rerunning setup."
                    }
                } else {
                    try {
                        New-MgApplicationFederatedIdentityCredential -ApplicationId $AppObject.Id -BodyParameter $FederatedCredentialParam | Out-Null
                    } catch {
                        Add-EntraOpsProvisioningFailure -Message "Failed to add Federated Credential '$($FederatedCredentialParam.name)' to $AppDisplayName. Error: $($_.Exception.Message)"
                    }
                }
            }
        } elseif ($Config.DevOpsPlatform -eq "AzureDevOps") {
            Write-Output "Add Federated Credential to $AppDisplayName for Azure DevOps..."

            $FederatedCredentialParam = @{
                name      = "$($AdoOrgName)-$($AdoProjectName)-$($AdoServiceConnectionName)"
                issuer    = $AdoFederatedCredentialIssuer
                subject   = "sc://$($AdoOrgName)/$($AdoProjectName)/$($AdoServiceConnectionName)"
                audiences = @(
                    "api://AzureADTokenExchange"
                )
            }

            try {
                $ExistingFederatedCredentials = @(Get-MgApplicationFederatedIdentityCredential -ApplicationId $AppObject.Id -All)
                $ExistingFederatedCredential = $ExistingFederatedCredentials | Where-Object { $_.Name -eq $FederatedCredentialParam.name } | Select-Object -First 1
                if ($ExistingFederatedCredential) {
                    $AudienceDifference = @(Compare-Object -ReferenceObject @($FederatedCredentialParam.audiences) -DifferenceObject @($ExistingFederatedCredential.Audiences))
                    if ($ExistingFederatedCredential.Issuer -ceq $FederatedCredentialParam.issuer -and
                        $ExistingFederatedCredential.Subject -ceq $FederatedCredentialParam.subject -and
                        $AudienceDifference.Count -eq 0) {
                        Write-Output "Federated Credential '$($FederatedCredentialParam.name)' is already configured."
                    } else {
                        Add-EntraOpsProvisioningFailure -Message "Federated Credential '$($FederatedCredentialParam.name)' already exists but does not match the Azure DevOps service connection issuer, subject, or audience."
                    }
                } else {
                    New-MgApplicationFederatedIdentityCredential -ApplicationId $AppObject.Id -BodyParameter $FederatedCredentialParam | Out-Null
                }
            } catch {
                Add-EntraOpsProvisioningFailure -Message "Failed to configure the Azure DevOps Federated Credential '$($FederatedCredentialParam.name)' on $AppDisplayName. Error: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "Automation configuration of federated credential for DevOps Platform $($Config.DevOpsPlatform) is not implemented yet."
        }
    } else {
        Write-Verbose "Skipping Federated Credential configuration... (AuthenticationType is not Federated)"
    }
    #endregion

    if ($ProvisioningFailures.Count -gt 0) {
        $FailureSummary = ($ProvisioningFailures | ForEach-Object { "- $_" }) -join [Environment]::NewLine
        throw "Workload identity provisioning did not complete successfully for service principal '$($SpObject.Id)'. Correct the following issue(s), then rerun the command with -ExistingSpObjectId '$($SpObject.Id)':$([Environment]::NewLine)$FailureSummary"
    }
}
