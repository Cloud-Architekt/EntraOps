<#
.SYNOPSIS
    Update classification definition file for Microsoft Entra ID with fine-granular scope of Control Plane permissions based on privileged objects.

.DESCRIPTION
    Classification of Control Plane needs to consider the scope of sensitive permissions. For example, managing group membership of security groups should be managed as Control Plane by default.
    But this enforces to manage service-specific roles (e.g., Knowledge Administrator) as Control Plane. Protection of privileged objects by using Role-assignable groups (PRG), Entra ID Roles or Restricted Management Administrative Units (RMAU) allows to protect them by lower privileged roles with those permissions on directory-level.
    This function checks if privileged objects are protected by the previous mentoined methods and RMAUs with assigned privileged objects.
    A parameter file will be used to generate an updated classification definition file for Microsoft Entra ID and exclude directory roles without impact to privileged objects from Control Plane. All other assignments will be still managed as Control Plane.

.PARAMETER PrivilegedObjectClassificationSource
    Source of privileged objects to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.
    Possible values are "All", "EntraOps", "PrivilegedObjectIds", "PrivilegedRolesFromAzGraph" and "PrivilegedEdgesFromExposureManagement".

.PARAMETER EntraIdClassificationParameterFile
    Path to the classification parameter file for Microsoft Entra ID. Default is ./Classification/Templates/Classification_AadResources.Param.json.

.PARAMETER EntraIdCustomizedClassificationFile
    Path to the customized classification file for Microsoft Entra ID. Default is ./Classification/<TenantName>/Classification_AadResources.json.
    The file path will be recognized by the tenant name in the context of EntraOps and used for the classification.

.PARAMETER EntraOpsEamFolder
    Path to the folder where the EntraOps classification definition files are stored. Default is ./Classification.

.PARAMETER EntraOpsScopes
    Array of EntraOps scopes which should be considered for the analysis. Default selection are all available scopes: Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement and ResourceApps.

.PARAMETER AzureHighPrivilegedRoles
    Array of high privileged roles in Azure RBAC which should be considered for the analysis. Default selection are high-privileged roles: Owner, Role Based Access Control Administrator and User Access Administrator.

.PARAMETER AzureHighPrivilegedScopes
    Scope of high privileged roles in Azure RBAC which should be considered for the analysis. Default selection is all scopes including management groups.

.PARAMETER ExposureCriticalityLevel
    Criticality level of assets in Exposure Management which should be considered for the analysis. Default selection is criticality level <1.

.PARAMETER PrivilegedObjectIds
    Manual list of privileged object IDs to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.

.EXAMPLE
    Get privileged objects from various Microsoft Entra RBACs and Microsoft Azure roles to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "EntraOps" -RBACSystems ("Azure","EntraID","IdentityGovernance","DeviceManagement","ResourceApps")

.EXAMPLE
    Get exposure graph edges from Microsoft Security Exposure Management with relation of "has permissions to", "can authenticate as", "has role on", "has credentials of" or "affecting" to assets with criticality level <1.
    This identitfies objects with direct/indirect permissions which leads in attack/access paths to high sensitive assets which can be identified as Control Plane.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "PrivilegedEdgesFromExposureManagement" -ExposureCriticalityLevel = "<1"

.EXAMPLE
    Get permanent role assignments in Azure RBAC from Azure Resource Graph for high privileged roles (Owner, Role Based Access Control Administrator or User Access Administrator) on specific high-privileged scope ("/", "/providers/microsoft.management/managementgroups/8693dc7e-63c1-47ab-a7ee-acfe488bf52a").
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "PrivilegedRolesFromAzGraph" -AzureHighPrivilegedRoles ("Owner", "Role Based Access Control Administrator", "User Access Administrator") -AzureHighPrivilegedScopes ("/", "/providers/microsoft.management/managementgroups/8693dc7e-63c1-47ab-a7ee-acfe488bf52a")

.EXAMPLE
    Use previous named data sources to identify high-privileged or sensitive objects from EntraOps, Azure RBAC and Exposure Management to update EntraOps classification definition file.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "All"

.EXAMPLE
    Get list of privileged object IDs to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.
    $PrivilegedUser = Get-AzAdUser -filter "startswith(DisplayName,'adm')"
    $PrivilegedGroups = Get-AzAdGroup -filter "startswith(DisplayName,'prg')"
    $PrivilegedObjects = $PrivilegedUser + $PrivilegedGroups
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "PrivilegedObjectIds" -PrivilegedObjectIds $PrivilegedObjects

#>

function Update-EntraOpsClassificationControlPlaneScope {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet("All", "EntraOps", "PrivilegedObjectIds", "PrivilegedRolesFromAzGraph", "PrivilegedEdgesFromExposureManagement")]
        [object]$PrivilegedObjectClassificationSource = "All"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$EntraIdClassificationParameterFile = "$DefaultFolderClassification\Templates\Classification_AadResources.Param.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$EntraIdCustomizedClassificationFile = "$DefaultFolderClassification\$($TenantNameContext)\Classification_AadResources.json"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ })]
        [string]$EntraOpsEamFolder = "$DefaultFolderClassifiedEam"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps")]
        [object]$EntraOpsScopes = ("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps")
        ,
        [Parameter(Mandatory = $false)]
        [object]$AzureHighPrivilegedRoles = ("Owner", "Role Based Access Control Administrator", "User Access Administrator")
        ,
        [Parameter(Mandatory = $false)]
        [string]$AzureHighPrivilegedScopes = "*"
        ,
        [Parameter(Mandatory = $false)]
        [string]$ExposureCriticalityLevel = "<1"
        ,
        [Parameter(Mandatory = $false)]
        [object]$PrivilegedObjectIds
    )

    $PrivilegedObjects = @()

    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    if (!(Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext))")) {
        try {
            New-Item -Path "$($DefaultFolderClassification)/$($TenantNameContext)" -ItemType Directory -Force
        }
        catch {
            Write-Error "Failed to create folder $($EntraIdCustomizedClassificationFile)! $_.Exception.Message"
        }

    }

    #region Get privileged objects from the defined sources in parameter
    if ($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "EntraOps") {
        Write-Output "Get privileged objects from EntraOps..."
        # Get list of all privileged objects in Entra with classification on Control Plane by Custom Security Attribute or EntraOps Classification
        $EntraOpsAllPrivilegedObjects = foreach ($EntraOpsScope in $EntraOpsScopes) {
            try {
                Get-Content -Path $EntraOpsEamFolder\$($EntraOpsScope)\$($EntraOpsScope).json -ErrorAction Stop | ConvertFrom-Json -Depth 10
            }
            catch {
                Write-Warning "No privileged objects found for $($EntraOpsScope) in EntraOps! $_.Exception.Message"
            }
        }

        if ($null -eq $EntraOpsAllPrivilegedObjects) {
            Write-Warning "No privileged objects found in EntraOps!"
        }
        else {
            $EntraOpsPrivilegedObjects = $EntraOpsAllPrivilegedObjects | Where-Object { $_.ObjectAdminTierLevelName -eq "ControlPlane" -or $_.Classification.AdminTierLevelName -contains "ControlPlane" } `
            | Select-Object ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectUserPrincipalName, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices
    
            $PrivilegedObjects += $EntraOpsPrivilegedObjects
        }
    }
    if ($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "AzResourceGraph") {
        Write-Output "Get privileged objects from Azure Resource Graph..."
        # Query template and update them with parameter value of high privileged Azure roles and scopes
        $Query = 'AuthorizationResources
        | where type =~ "microsoft.authorization/roleassignments"
        | extend principalType = tostring(properties["principalType"])
        | extend principalId = tostring(properties["principalId"])
        | extend roleDefinitionId = tolower(tostring(properties["roleDefinitionId"]))
        | extend scope = tolower(tostring(properties["scope"]))
        | where isnotempty(scope)
        | join kind=inner ( AuthorizationResources
        | where type =~ "microsoft.authorization/roledefinitions"
        | extend roleDefinitionId = tolower(id)
        | extend Scope = tolower(properties.assignableScopes)
        | extend RoleName = (properties.roleName)
        | where RoleName in (%AzureHighPrivilegedRoles%)
        ) on roleDefinitionId
        | distinct principalId, principalType'
        $Query = $Query.Replace("%AzureHighPrivilegedRoles%", "'$($AzureHighPrivilegedRoles -join "', '")'")
        if ($null -ne $AzureHighPrivilegedScopes -and $AzureHighPrivilegedScopes -ne "*") {
            $Scopes = "'$($AzureHighPrivilegedScopes -join "', '")'"
            $Query = $Query.Replace("isnotempty(scope)", "scope in ($($Scopes))")
        }
        $HighPrivilegedObjectIdsFromAzGraph = (Invoke-EntraOpsAzGraphQuery -KqlQuery $Query)

        # Get details of high privileged objects
        $HighPrivilegedObjectsFromAzGraph += $HighPrivilegedObjectIdsFromAzGraph | ForEach-Object {
            try {
                if ($null -ne (Get-AzADServicePrincipal -ObjectId $_.principalId -ErrorAction Stop | Out-Null)) {
                    Get-EntraOpsPrivilegedEntraObject -AadObjectId $_.principalId | Where-Object { $_.ObjectType -ne "unknown" }`
                    | Select-Object ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectSignInName, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices    
                }
            }
            catch {
                Write-Warning "High privileged object with id $_.principalId not found! $_"
            }
        }
        $PrivilegedObjects += $HighPrivilegedObjectsFromAzGraph
    }
    if ($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "PrivilegedEdgesFromExposureManagement") {
        Write-Output "Get privileged objects from exposure graph edges and nodes in Exposure Management..."
        $Query = 'let Tier0CloudResources = ExposureGraphNodes
            | where isnotnull(NodeProperties.rawData.criticalityLevel) and (NodeProperties.rawData.criticalityLevel.criticalityLevel %CriticalLevel%) and (NodeProperties.rawData.environmentName == "Azure");
        let Tier0EntraObjects = ExposureGraphNodes
            | where isnotnull(NodeProperties.rawData.criticalityLevel) and (NodeProperties.rawData.criticalityLevel.criticalityLevel %CriticalLevel%) and (NodeProperties.rawData.primaryProvider == "AzureActiveDirectory");
        let Tier0Devices = ExposureGraphNodes
            | where isnotnull(NodeProperties.rawData.criticalityLevel) and (NodeProperties.rawData.criticalityLevel.criticalityLevel %CriticalLevel%) and (NodeLabel == "device") and (NodeProperties.rawData.isAzureADJoined == true);
        let Tier0Assets = union Tier0EntraObjects, Tier0Devices, Tier0CloudResources | project NodeId;
        let SensitiveRelation = dynamic(["has permissions to","can authenticate as","has role on","has credentials of","affecting", "can authenticate as", "Member of", "frequently logged in by"]);
        // Devices are not supported yet, no AadObject Id available in ExposureGraphNodes, DeviceInfo shows only AadDeviceId
        let FilteredNodes = dynamic(["user","group","serviceprincipal","managedidentity","device"]);
        ExposureGraphEdges
        | where EdgeLabel in (SensitiveRelation) and (TargetNodeId in (Tier0Assets) or SourceNodeId in (Tier0Assets)) and SourceNodeLabel in (FilteredNodes)
        | join kind=leftouter ( ExposureGraphNodes
            | mv-expand parse_json(EntityIds)
            | where parse_json(EntityIds).type == "AadObjectId"
            | extend AadObjectId = tostring(parse_json(EntityIds).id)
            | extend TenantId = extract("tenantid=([\\w-]+)", 1, AadObjectId)
            | extend ObjectId = extract("objectid=([\\w-]+)", 1, AadObjectId)
            | project ObjectDisplayName = NodeName, ObjectType = NodeLabel, ObjectId, NodeId) on $left.SourceNodeId == $right.NodeId
        | where isnotempty(ObjectId)
        | summarize make_set(EdgeLabel), make_set(TargetNodeName) by ObjectDisplayName, SourceNodeName, ObjectType, ObjectId, NodeId'
        $Query = $Query.Replace("%CriticalLevel%", $ExposureCriticalityLevel)
        $Body = @{
            "Query" = $Query;
        } | ConvertTo-Json
        $PrivilegedObjectsGraphEdges = (Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/security/runHuntingQuery" -Body $Body).results
        if ($null -ne $PrivilegedObjectsGraphEdges) {
            $PrivilegedObjects += $PrivilegedObjectsGraphEdges | ForEach-Object { Get-EntraOpsPrivilegedEntraObject -AadObjectId $_.ObjectId | Where-Object { $_.ObjectType -ne "unknown" }`
                | Select-Object ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectSignInName, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices
            }
        }
    }
    if ($PrivilegedObjectClassificationSource -contains "PrivilegedObjectIds" -and $null -ne $PrivilegedObjectIds) {
        Write-Output "Get privileged objects from manual list of object ids..."
        $PrivilegedObjects = $PrivilegedObjectIds | ForEach-Object { Get-EntraOpsPrivilegedEntraObject -AadObjectId $_ }
    }
    #endregion

    #region Get classification file and filter for unique privileged objects
    $DirectoryLevelAssignmentScope = @("/")
    $EntraIdRoleClassification = Get-Content -Path $EntraIdClassificationParameterFile
    $PrivilegedObjects = $PrivilegedObjects | sort-object ObjectType, ObjectDisplayName | Select-Object -Unique *
    Write-Output "Identified privileged objects:"
    $PrivilegedObjects | ForEach-Object {
        Write-Output "$($ObjectType) - $($_.ObjectId) - $($_.ObjectDisplayName)"
    }
    #endregion

    #region Privileged User
    Write-Output "Identify directory role scope of privileged users..."
    $PrivilegedUsersWithoutProtection = $PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" -and ($_.RestrictedManagementByRAG -eq $false -and $_.RestrictedManagementByAadRole -eq $False -and $RestrictedManagementByRMAU -eq $False) }
    $PrivilegedUserWithRMAU = $PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" -and $_.RestrictedManagementByRMAU -eq $True }
    $ScopeNamePrivilegedUsers = $PrivilegedUserWithRMAU.AssignedAdministrativeUnits | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" }
    if ($PrivilegedUsersWithoutProtection -gt "0") {
        Write-Warning "Control Plane user without any protection, requires to avoid directory role assignments for user management!"
        Write-Host $PrivilegedUsersWithoutProtection
        $ScopeNamePrivilegedUsers += $DirectoryLevelAssignmentScope
    }
    if ($null -ne $ScopeNamePrivilegedUsers) {
        $ScopeNamePrivilegedUsersJSON = $ScopeNamePrivilegedUsers | Sort-Object | ConvertTo-Json
        $ScopeNamePrivilegedUsersJSON = $ScopeNamePrivilegedUsersJSON.Replace('[', '').Replace(']', '')
        $ScopeNamePrivilegedUsersJSON = $ScopeNamePrivilegedUsersJSON -creplace '\s+', ' '
        $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedUsers>', $ScopeNamePrivilegedUsersJSON)
    }
    else {
        Write-Warning "No privileged user in scope of classification!"
        $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedUsers>', '"/"')
    }
    #endregion

    #region Privileged Devices
    Write-Output "Identify directory role scope of privileged devices..."
    $PrivilegedUsersWithDevices = ($PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" -and $null -ne $_.OwnedDevices }) | Select-Object -ExpandProperty OwnedDevices | Select-Object -Unique
    $PrivilegedDevicesAUs = $PrivilegedUsersWithDevices | ForEach-Object {
        @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/devices/$($_)/memberOf/microsoft.graph.administrativeUnit" -OutputType PSObject | Select-Object id, displayName, isMemberManagementRestricted)
    }
    $PrivilegedDevicesWithoutProtection = $PrivilegedDevicesAUs | Where-Object { $_.isMemberManagementRestricted -eq $False } | Select-Object -Unique id
    $ScopeNamePrivilegedDevices = $PrivilegedDevicesAUs | Where-Object { $_.isMemberManagementRestricted -eq $True } | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" }

    if ($PrivilegedDevicesWithoutProtection -gt "0") {
        Write-Warning "Control Plane devices without any protection, requires to avoid directory role assignments for device object management!"
        Write-Host $PrivilegedDevicesWithoutProtection
        $ScopeNamePrivilegedDevices += $DirectoryLevelAssignmentScope
    }
    if ($null -ne $ScopeNamePrivilegedDevices) {
        $ScopeNamePrivilegedDevicesJSON = $ScopeNamePrivilegedDevices | Sort-Object | ConvertTo-Json
        $ScopeNamePrivilegedDevicesJSON = $ScopeNamePrivilegedDevicesJSON.Replace('[', '').Replace(']', '')
        $ScopeNamePrivilegedDevicesJSON = $ScopeNamePrivilegedDevicesJSON -creplace '\s+', ' '
        $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedDevices>', $ScopeNamePrivilegedDevicesJSON)
    }
    else {
        Write-Warning "No privileged device in scope of classification!"
        $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedDevices>', '"/"')
    }
    #endregion

    #region Privileged Groups
    Write-Output "Identify directory role scope of privileged groups..."
    $PrivilegedGroupsWithoutProtection = $PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" -and ($_.RestrictedManagementByRAG -eq $false -and $RestrictedManagementByRMAU -eq $False) }
    $PrivilegedGroupWithRMAU = $PrivilegedObjects | Where-Object { $_.ObjectType -eq "group" -and $_.RestrictedManagementByRMAU -eq $True }
    $ScopeNamePrivilegedGroups = $PrivilegedGroupWithRMAU.AssignedAdministrativeUnits | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" }
    if ($PrivilegedGroupsWithoutProtection -eq "0") {
        Write-Warning "Control Plane group without any protection, requires to avoid directory role assignments for group management!"
        $ScopeNamePrivilegedGroups += $DirectoryLevelAssignmentScope
    }
    if ($null -ne $ScopeNamePrivilegedGroups) {
        $ScopeNamePrivilegedGroupsJSON = $ScopeNamePrivilegedGroups | Sort-Object | ConvertTo-Json
        $ScopeNamePrivilegedGroupsJSON = $ScopeNamePrivilegedGroupsJSON.Replace('[', '').Replace(']', '')
        $ScopeNamePrivilegedGroupsJSON = $ScopeNamePrivilegedGroupsJSON -creplace '\s+', ' '
        $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedGroups>', $ScopeNamePrivilegedGroupsJSON)
    }
    else {
        Write-Warning "No privileged groups in scope of classification!"
        $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedGroups>', '"/"')
    }

    #endregion

    #region Privileged Service Principals
    Write-Output "Identify directory role scope of service principals and application objects..."
    $PrivilegedServicePrincipals = $PrivilegedObjects | Where-Object { $_.ObjectType -eq "servicePrincipal" }
    if ($PrivilegedServicePrincipals.Count -gt "0") {
        # Get list of object-level role assignment scope which includes Control Plane Service Principals
        $ScopeNameServicePrincipalObject = $PrivilegedServicePrincipals | ForEach-Object { "/$($_.ObjectId)" }

        # Get list of AppIds for service principals stored in ObjectUserPrincipalName (in *PrivilegedEAM results) or ObjectSignInName (in *PrivilegedEntraObject results)
        $AppIds = @()
        $AppIds += ($PrivilegedServicePrincipals | Where-Object { $null -ne $_.ObjectUserPrincipalName -and $_.ObjectSubType -eq "Application" }).ObjectUserPrincipalName
        $AppIds += ($PrivilegedServicePrincipals | Where-Object { $null -ne $_.ObjectSignInName -and $_.ObjectSubType -eq "Application" }).ObjectSignInName

        # Get application object IDs for service principals because directory role assignments can be assigned to application objects
        $ScopeNameApplicationObject = $AppIds | ForEach-Object {
            $AppObject = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/applications(appId='$($_)')?`$select=id,appId" -OutputType PSObject)
            if ($null -ne $AppObject.Id) {
                "/$($AppObject.id)"
            }
        }

        # Always add also directory level assignment scope becuase of missing protection of service principal by RAG, AAD Role or RMAU assignment
        $ScopeNamePrivilegedServicePrincipals = $ScopeNameServicePrincipalObject + $ScopeNameApplicationObject + $DirectoryLevelAssignmentScope
    }
    else {
        Write-Warning "No privileged applications found! It's still recommended to avoid (Cloud) Application on directory scope..."
        $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedGroups>', '"/"')
    }

    if ($null -ne $ScopeNamePrivilegedServicePrincipals) {
        $ScopeNamePrivilegedServicePrincipalsJSON = $ScopeNamePrivilegedServicePrincipals | Sort-Object | Select-Object -Unique | ConvertTo-Json
        $ScopeNamePrivilegedServicePrincipalsJSON = $ScopeNamePrivilegedServicePrincipalsJSON.Replace('[', '').Replace(']', '')
        $ScopeNamePrivilegedServicePrincipalsJSON = $ScopeNamePrivilegedServicePrincipalsJSON -creplace '\s+', ' '
    }        
    $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedServicePrincipals>', $ScopeNamePrivilegedServicePrincipalsJSON)
    
    #endregion

    $EntraIdRoleClassification = $EntraIdRoleClassification | ConvertFrom-Json -Depth 10 | ConvertTo-Json -Depth 10 | Out-File -FilePath $EntraIdCustomizedClassificationFile -Force
}
