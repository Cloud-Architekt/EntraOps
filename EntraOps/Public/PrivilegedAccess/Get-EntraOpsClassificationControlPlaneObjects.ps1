<#
.SYNOPSIS
    Get list of Control Plane objects by classification of various sources (e.g., EntraOps, Microsoft Security Exposure Management and Azure Resource Graph).

.DESCRIPTION
    Classification of Control Plane needs to consider the scope of sensitive permissions. For example, managing group membership of security groups should be managed as Control Plane by default.
    This function creates a list of high-privileged objects by classification of various sources (e.g., EntraOps, Microsoft Security Exposure Management and Azure Resource Graph).

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

function Get-EntraOpsClassificationControlPlaneObjects {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
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
        [ValidateSet("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [object]$EntraOpsScopes = ("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")
        ,
        [Parameter(Mandatory = $false)]
        [object]$AzureHighPrivilegedRoles = ("Owner", "Role Based Access Control Administrator", "User Access Administrator")
        ,
        [Parameter(Mandatory = $false)]
        [object]$AzureHighPrivilegedScopes = "*"
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
            New-Item -Path "$($DefaultFolderClassification)/$($TenantNameContext)" -ItemType Directory -Force | Out-Null
        } catch {
            Write-Error "Failed to create folder $($EntraIdCustomizedClassificationFile)! $_.Exception.Message"
        }
    }

    #region Get list of all privileged objects in Entra with classification on Control Plane by Custom Security Attribute or EntraOps Classification
    if ($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "EntraOps") {
        Write-Host "Get privileged objects from EntraOps..."
        $EntraOpsAllPrivilegedObjects = foreach ($EntraOpsScope in $EntraOpsScopes) {
            try {
                Get-Content -Path $EntraOpsEamFolder\$($EntraOpsScope)\$($EntraOpsScope).json -ErrorAction Stop | ConvertFrom-Json -Depth 10
            } catch {
                Write-Warning "No privileged objects found for $($EntraOpsScope) in EntraOps! $_.Exception.Message"
            }
        }

        if ($null -eq $EntraOpsAllPrivilegedObjects) {
            Write-Warning "No privileged objects found in EntraOps!"
        } else {
            $EntraOpsObjectClassification = $EntraOpsAllPrivilegedObjects | Where-Object { $_.ObjectAdminTierLevelName -eq "ControlPlane" } `
            | Select-Object -Unique ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectUserPrincipalName, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices `
            | ForEach-Object {
                $PrivilegedObject = $_ 
                $ClassificationReason = @("ObjectAdminTierLevelName")
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ObjectSignInName -Value ($PrivilegedObject.ObjectUserPrincipalName) -Force | Out-Null
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationReason -Value $ClassificationReason -Force | Out-Null
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationSource -Value "EntraOps" -Force | Out-Null                
                return $PrivilegedObject
            }
            
            $PrivilegedObjects += $EntraOpsObjectClassification

            $EntraOpsRoleClassification = $EntraOpsAllPrivilegedObjects | Where-Object { $_.Classification.AdminTierLevelName -contains "ControlPlane" } `
            | ForEach-Object {
                $PrivilegedObject = $_ | Select-Object ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectUserPrincipalName, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices, RoleSystem
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ObjectSignInName -Value ($PrivilegedObject.ObjectUserPrincipalName) -Force | Out-Null
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationReason -Value ($PrivilegedObject | Select-Object -Unique RoleSystem) -Force | Out-Null
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationSource -Value "EntraOps" -Force | Out-Null
                return $PrivilegedObject
            }

            $PrivilegedObjects += $EntraOpsRoleClassification
        }
    }
    #endregion

    #region Get list of all privileged objects by Azure Resource Graph
    if ($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "AzResourceGraph") {
        Write-Host "Get privileged objects from Azure Resource Graph..."
        # Query template and update them with parameter value of high privileged Azure roles and scopes
        $Query = 'AuthorizationResources
    | where type =~ "microsoft.authorization/roleassignments"
    | extend PrincipalType = tolower(tostring(properties["principalType"]))
    | extend PrincipalId = tostring(properties["principalId"])
    | extend RoleDefinitionId = tolower(tostring(properties["roleDefinitionId"]))
    | extend RoleScope = tolower(tostring(properties["scope"]))
    | where isnotempty(RoleScope)
    | join kind=inner ( AuthorizationResources
    | where type =~ "microsoft.authorization/roledefinitions"
    | extend RoleDefinitionId = tolower(id)
    | extend RoleName = (properties.roleName)
    | where RoleName in (%AzureHighPrivilegedRoles%)
    ) on RoleDefinitionId
    | project PrincipalId, PrincipalType, RoleScope, RoleName'
        $Query = $Query.Replace("%AzureHighPrivilegedRoles%", "'$($AzureHighPrivilegedRoles -join "', '")'")
        if ($null -ne $AzureHighPrivilegedScopes -and $AzureHighPrivilegedScopes -ne "*") {
            $Scopes = "'$($AzureHighPrivilegedScopes -join "', '")'"
            $Query = $Query.Replace("isnotempty(RoleScope)", "RoleScope in ($($Scopes))")
        }

        # Get details of high privileged objects
        $HighPrivilegedObjectIdsFromAzGraph = (Invoke-EntraOpsAzGraphQuery -KqlQuery $Query)
        $PrivilegedObjects += $HighPrivilegedObjectIdsFromAzGraph | Select-Object -Unique PrincipalId, PrincipalType | foreach-object {
            $HighPrivilegedObjectId = $_
            try {
                if ($null -ne (Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($HighPrivilegedObjectId.PrincipalId)" )) {
                    $HighPrivilegedRoles = $HighPrivilegedObjectIdsFromAzGraph | Where-Object { $_.PrincipalId -eq $HighPrivilegedObjectId.PrincipalId -and $_.PrincipalType -eq $HighPrivilegedObjectId.PrincipalType } | Select-Object -Unique RoleScope, RoleName
                    $PrivilegedObject = Get-EntraOpsPrivilegedEntraObject -AadObjectId $HighPrivilegedObjectId.PrincipalId | Where-Object { $_.ObjectType -ne "unknown" }`
                    | Select-Object ObjectId, @{Name = 'ObjectType'; Expression = { $_.'ObjectType'.tolower() } }, ObjectSubType, ObjectDisplayName, ObjectSignInName, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices
                    $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationReason -Value $HighPrivilegedRoles -Force | Out-Null
                    $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationSource -Value "Azure Resource Graph" -Force | Out-Null
                    return $PrivilegedObject
                }
            } catch {
                Write-Warning "High privileged object with id $($HighPrivilegedObjectId.PrincipalId) not found! $_"
            }
        }
    }
    #endregion

    #region Get list of all privileged objects by Microsoft Exposure Management
    if ($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "PrivilegedEdgesFromExposureManagement") {
        Write-Host "Get privileged objects from exposure graph edges and nodes in Exposure Management..."
        $Query = '
        let Tier0CloudResources = ExposureGraphNodes
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
        | extend ClassificationReason = bag_pack_columns(EdgeLabel, TargetNodeName)
        | summarize by ObjectDisplayName, SourceNodeName, tolower(ObjectType), ObjectId, NodeId, tostring(ClassificationReason)'
        $Query = $Query.Replace("%CriticalLevel%", $ExposureCriticalityLevel)
        $Body = @{
            "Query" = $Query;
        } | ConvertTo-Json
        $PrivilegedObjectsGraphEdges = (Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/security/runHuntingQuery" -Body $Body).results
        if ($null -ne $PrivilegedObjectsGraphEdges) {
            $PrivilegedObjects += $PrivilegedObjectsGraphEdges | Select-Object -Unique ObjectDisplayName, ObjectId, ObjectType | ForEach-Object {
                $GraphEdge = $_
                $PrivilegedObject = Get-EntraOpsPrivilegedEntraObject -AadObjectId $GraphEdge.ObjectId | Where-Object { $_.ObjectType -ne "unknown" }`
                | Select-Object ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectSignInName, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices
                $ClassificationReason = @()
                $ClassificationReason += ($PrivilegedObjectsGraphEdges | Where-Object { $_.ObjectId -eq $GraphEdge.ObjectId -and $_.ObjectType -eq $GraphEdge.ObjectType }).ClassificationReason | ConvertFrom-Json
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationReason -Value $ClassificationReason -Force | Out-Null
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationSource -Value "XSPM" -Force | Out-Null
                return $PrivilegedObject
            }
        }
    }
    #endregion

    #region Get list of all privileged objects by manual list of ObjectIds
    if ($PrivilegedObjectClassificationSource -contains "PrivilegedObjectIds" -and $null -ne $PrivilegedObjectIds) {
        Write-Host "Get privileged objects from manual list of object ids..."
        $PrivilegedObjects = $PrivilegedObjectIds | ForEach-Object {
            $PrivilegedObject = Get-EntraOpsPrivilegedEntraObject -AadObjectId $_
            $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationReason -Value @("Manual") -Force | Out-Null
            $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationSource -Value "Manual" -Force | Out-Null
        }
    }
    #endregion

    #region Summarize and return list of privileged objects
    $PrivilegedObjects | Select-Object -Unique ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectSignInName, RestrictedManagementByAadRole, RestrictedManagementByRAG, RestrictedManagementByRMAU, OwnedDevices, AssignedAdministrativeUnits | ForEach-Object {
        $PrivilegedObject = $_
        $Classifications = $PrivilegedObjects | Where-Object { $_.ObjectId -eq $PrivilegedObject.ObjectId -and $_.ObjectType -eq $PrivilegedObject.ObjectType } | select-object ClassificationReason, ClassificationSource
        $PrivilegedObject | Add-Member -MemberType NoteProperty -Name Classification -Value $Classifications -Force | Out-Null
        return $PrivilegedObject
    }
    #endregion
}