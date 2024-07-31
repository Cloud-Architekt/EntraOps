<#
.SYNOPSIS
    Create required App Registrations to execute EntraOps in Automation runbook or DevOps pipelines.

.DESCRIPTION
    Create required Workload Identity (new or use existing Service Principal) to execute EntraOps in Automation runbook or DevOps pipelines.

.PARAMETER AppDisplayName
    Display name of the App Registration which will be created.

.PARAMETER ExistingSpObjectId
    ObjectId of the existing Service Principal which should be used. If not provided, a new App Registration will be created.

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

        [Parameter(Mandatory = $False, ParameterSetName = "ExistingSpObjectId")]
        [string]$ExistingSpObjectId,

        [Parameter(Mandatory = $False)]
        [string]$ConfigFile = "$EntraOpsBasefolder/EntraOpsConfig.json",

        [Parameter(ParameterSetName = "CreateFederatedCredential")]
        [switch]$CreateFederatedCredential,

        [Parameter(Mandatory, ParameterSetName = "CreateFederatedCredential")]
        [string]$GitHubOrg,

        [Parameter(Mandatory, ParameterSetName = "CreateFederatedCredential")]
        [string]$GitHubRepo,

        [Parameter(Mandatory, ParameterSetName = "CreateFederatedCredential")]
        [ValidateSet("Branch", "Environment")]
        [string]$FederatedEntityType = "Branch",

        [Parameter(Mandatory, ParameterSetName = "CreateFederatedCredential")]
        [string]$FederatedEntityName = "main"
    )

    $ErrorActionPreference = "Stop"

    # Load configuration file
    $Config = Get-Content -Path $ConfigFile | ConvertFrom-Json

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
        }
        catch {
            Write-Error "Failed to get Service Principal with ObjectId $ExistingSpObjectId. Error: $_"
        }
    }
    else {
        # Create App Registration
        Write-Output "Create App Registration $AppDisplayName..."
        try {
            $AppObject = New-MgApplication -DisplayName $AppDisplayName -SignInAudience AzureADMyOrg
        }
        catch {
            Write-Error "Failed to create $AppDisplayName. Error: $_"
        }

        # Short delay before contiune and wait sync
        Write-Verbose "Wait 3 seconds before create Service Principal from App Registration..."
        Start-Sleep 3

        # Create Service Principal
        Write-Verbose "Create Service Principal from $AppDisplayName $($AppObject.Id)..."
        try {
            $SpObject = New-MgServicePrincipal -DisplayName $AppDisplayName -AppId $AppObject.AppId
        }
        catch {
            Write-Error "Failed to create Service Principal for $AppDisplayName. Error: $_"
        }
        #endregion
    }

    #region Add required Microsoft Graph API Permissions for Pull (Read) Operations

    # Get Graph API App Roles to map required App Role Names to App Role IDs
    Write-Verbose "Get Microsoft Graph API App Roles..."
    $MsGraph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

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
        "PrivilegedAccess.Read.AzureADGroup",
        "PrivilegedEligibilitySchedule.Read.AzureADGroup",
        "Policy.Read.All",
        "RoleManagement.Read.All",
        "ThreatHunting.Read.All",
        "User.Read.All"
    )

    Write-Output "Adding Pull permissions..."
    $GraphApiPermissions = $MsGraph.AppRoles | Where-Object { $_.Value -in $PullPermissionsToAdd }
    foreach ($GraphApiPermission in $GraphApiPermissions) {
        Write-Host "- Adding $($GraphApiPermission.Origin) API Permission $($GraphApiPermission.Value)"
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SPObject.Id -PrincipalId $SPObject.Id -ResourceId $MsGraph.Id -AppRoleId $GraphApiPermission.Id | Out-Null
        }
        catch {
            Write-Warning "Failed to add API Permission $($GraphApiPermission.Value) to $AppDisplayName. Error: $_"
        }
    }
    #endregion

    #region Add required Microsoft Graph API Permissions for Push (Change) Operations

    # Graph API permissions for Push operations
    if ($Config.AutomatedAdministrativeUnitManagement.ApplyAdministrativeUnitAssignments -eq $true -or $Config.AutomatedRmauAssignmentsForUnprotectedObjects.ApplyRmauAssignmentsForUnprotectedObjects -eq $true) {
        $PushPermissionsToAdd = @(
            "AdministrativeUnit.ReadWrite.All"
        )
    
        Write-Output "Adding Push permissions..."
        $GraphApiPermissions = $MsGraph.AppRoles | Where-Object { $_.Value -in $PushPermissionsToAdd }
        foreach ($GraphApiPermission in $GraphApiPermissions) {
            Write-Host "- Adding $($GraphApiPermission.Origin) API Permission $($GraphApiPermission.Value)"
            try {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SPObject.Id -PrincipalId $SPObject.Id -ResourceId $MsGraph.Id -AppRoleId $GraphApiPermission.Id | Out-Null
            }
            catch {
                Write-Error "Failed to add API Permission $($GraphApiPermission.Value) to $AppDisplayName. Error: $_"
            }
        }        
    }
    else {
        Write-Output "Skipping Push permissions... (ApplyAdministrativeUnitAssignments and/or ApplyRmauAssignmentsForUnprotectedObjects is set to false)"
    }

    #endregion


    #region Add required Microsoft Entra ID (scoped) directory role for managing Conditional Access Target Groups
    if ($Config.AutomatedConditionalAccessTargetGroups.ApplyConditionalAccessTargetGroups -eq $true) {
        $AdminUnitName = $Config.AutomatedConditionalAccessTargetGroups.AdminUnitName
        $AdminUnitId = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$($AdminUnitName)'" -OutputType PSObject -DisableCache).id
        #region Create Administrative Unit if it does not exist
        if (-not $AdminUnitId) {
            Write-Host "Creating Administrative Unit $($Name)"

            $AuParams = @{
                DisplayName                  = $AdminUnitName
                Description                  = "This administrative unit contains groups for Conditional Access Targeting"
                isMemberManagementRestricted = $true
            }

            $Body = $AuParams | ConvertTo-Json -Depth 10
            try {
                $NewAdminUnitId = (Invoke-MgGraphRequest -Method "POST" -Body $Body -Uri "https://graph.microsoft.com/beta/administrativeUnits").id
            }
            catch {
                Write-Warning "Can not create Administrative Unit $($AdminUnitName)! Error: $_"
            }

            # Check if AU has been created successfully, wait for delay and retry if not available yet
            Try {
                Do { Start-Sleep -Seconds 1 }
                Until ($AdminUnitId = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/administrativeUnits/$($NewAdminUnitId)" -DisableCache).Id)
                Write-Host "$($AdminUnitName) - $($AdminUnitId) has been created successfully" -f Green
            }
            Catch {
                Write-Warning "$($AdminUnitName) not available yet"
            }
        }
        else {
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
            $Body = $ScopedGroupAdminRoleParams | ConvertTo-Json -Depth 10
            $DirectoryRoleAssignmentId = (Invoke-MgGraphRequest -Method "POST" -Body $Body -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments").id
            Write-Host "Assigned permissions to Administrative Unit $($AdminUnitName) for $($SpObject.Id) - $($DirectoryRoleAssignmentId)" -f Green
        }
        catch {
            Write-Warning "Can not assign permissions to Administrative Unit $($AdminUnitName) for $($SpObject.Id)! Error: $_"
        }

    }
    else {
        Write-Output "Skipping permissions to manage Conditional Access Groups... (ApplyConditionalAccessTargetGroups is set to false)"
    }    
    #endregion

    #region Add required role assignments in Azure RBAC
    # Logic to add required role assignment in Azure RBAC
    function Add-AzureRolePermissions ($RoleDefinitionName, $ResourceGroupName, $SubscriptionId) {
        if (!$RoleDefinitionName -or !$ResourceGroupName -or !$SubscriptionId) {
            Write-Error "SentinelResourceGroupName and DataCollectionResourceGroupName needs to be defined in environment file to configure permissions for Push operations."
        }
        else {
            try {
                Set-AzContext -SubscriptionId $SubscriptionId
                Get-AzResourceGroup -Name $ResourceGroupName
            }
            catch {
                Write-Error "Invalid Resource Group Name $($ResourceGroupName) to set $($RoleDefinitionName). Error: $_"
            }
            try {
                New-AzRoleAssignment -ObjectId $SpObject.Id -RoleDefinitionName $RoleDefinitionName -ResourceGroupName $ResourceGroupName
            }
            catch {
                Write-Error "Failed to assign role $($RoleDefinitionName) to $($SpObject.DisplayName) on Resource Group $($ResourceGroupName). Error: $_"
            }
        }
    }
    Start-Sleep 5 # Wait for adding permission to new created Service Principal

    if ($Config.LogAnalytics.IngestToLogAnalytics -eq $true) {
        try {
            Write-Output "Adding permissions to Resource Group of Data Collection Rule on $($DataCollectionRuleResourceGroupId)..."
            Add-AzureRolePermissions -RoleDefinitionName "Monitoring Metrics Publisher" -ResourceGroupName $Config.LogAnalytics.DataCollectionResourceGroupName -SubscriptionId $Config.LogAnalytics.DataCollectionRuleSubscriptionId
            Add-AzureRolePermissions -RoleDefinitionName "Reader" -ResourceGroupName $Config.LogAnalytics.DataCollectionResourceGroupName -SubscriptionId $Config.LogAnalytics.DataCollectionRuleSubscriptionId    
        }
        catch {
            Write-Warning "Failed to assign roles on $($DataCollectionRuleResourceGroupId). Error: $_"
        }
    }
    else {
        Write-Output "Skipping Data Collection Rule permissions... (IngestToLogAnalytics is set to false)"
    }

    if ($Config.SentinelWatchLists.IngestToWatchLists -eq $true) {
        try {
            Write-Output "Adding permissions to Resource Group of Sentinel workspace on $($DataCollectionRuleResourceGroupId)..."
            Add-AzureRolePermissions -RoleDefinitionName "Microsoft Sentinel Contributor" -ResourceGroupName $Config.SentinelWatchLists.SentinelResourceGroupName -SubscriptionId $Config.SentinelWatchLists.SentinelSubscriptionId    
        }
        catch {
            Write-Warning "Failed to assign roles on $($DataCollectionRuleResourceGroupId). Error: $_"
        }
    }
    else {
        Write-Output "Skipping WatchList permissions... (IngestToWatchLists is set to false)"
    }

    # Add required permissions to Reader Permission on Tenant Root group if AutomatedControlPlaneScopeUpdate is using Resource Graph to get sensitive Privileged Roles in Azure Tenant
    # or any WatchList requires information from Azure Resource Graph (e.g., High Value Assets, Workload Identity Attack Paths or Managed Identity Assigned Resource Id)
    if (($Config.AutomatedControlPlaneScopeUpdate.ApplyAutomatedControlPlaneScopeUpdate -eq $true -and $Config.AutomatedControlPlaneScopeUpdate.PrivilegedObjectClassificationSource -contains "PrivilegedRolesFromAzGraph") `
            -or ($Config.SentinelWatchLists.WatchListTemplates -contains "HighValueAssets") -or ($Config.SentinelWatchLists.WatchListWorkloadIdentity -contains "WorkloadIdentityAttackPaths") -or ($Config.SentinelWatchLists.WatchListWorkloadIdentity -contains "ManagedIdentityAssignedResourceId")) {
        Write-Output "Adding permissions as Reader on Tenant Root Group for analyzing RBAC and/or Managed Identity resources..."
        New-AzRoleAssignment -RoleDefinitionName "Reader" -Scope "/providers/Microsoft.Management/managementGroups/$($Config.TenantId)" -ObjectId $SpObject.Id
    }
    #endregion    

    #region Add ClientId to environment file
    Write-Output "Write $AppDisplayName AppId to environment file $($ConfigFile)..."
    $Config.ClientId = $AppObject.AppId
    $Config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFile
    #endregion

    #region Add Federated Credential to Application object
    if ($Config.AuthenticationType -eq "FederatedCredentials" -and $CreateFederatedCredential) {
        if ($Config.DevOpsPlatform -eq "GitHub") {
            Write-Output "Acdd Federated Credential to $AppDisplayName..."

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

            try {
                New-MgApplicationFederatedIdentityCredential -ApplicationId $AppObject.Id -BodyParameter $FederatedCredentialParam
            }
            catch {
                Write-Warning "Failed to add Federated Credential to $AppDisplayName. Error: $_"
            }
        }
        else {
            Write-Warning "Automation configuration of federated credential for DevOps Platform $($Config.DevOpsPlatform) is not implemented yet."
        }
    }
    else {
        Write-Verbose "Skipping Federated Credential configuration... (AuthenticationType is not Federated)"
    }
}