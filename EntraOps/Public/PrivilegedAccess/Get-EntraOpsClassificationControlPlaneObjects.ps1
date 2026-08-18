<#
.SYNOPSIS
    Returns a deduplicated list of Control Plane objects identified from one or more classification sources.

.DESCRIPTION
    Queries multiple data sources to identify Entra ID objects that hold Control Plane-level permissions and returns them as a unified, deduplicated list with classification metadata (source and reason).
    Supported sources are:
      - EntraOps       : objects already classified as ControlPlane in the EntraOps EAM JSON files (object-level tier or Control Plane role assignments).
      - PrivilegedRolesFromAzGraph : permanent Azure RBAC role assignments for high-privileged roles queried via Azure Resource Graph.
      - PrivilegedEdgesFromExposureManagement : objects with attack-path edges to critical assets in Microsoft Security Exposure Management.
      - PrivilegedObjectIds : a manually supplied list of Entra object IDs.
      - All (default)  : runs all four sources and merges the results.

    Each returned object includes ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectSignInName, management restriction flags, assigned administrative units, and a Classification property that lists every source and reason the object was identified.

.PARAMETER PrivilegedObjectClassificationSource
    One or more sources used to identify Control Plane objects.
    Valid values: "All", "EntraOps", "PrivilegedObjectIds", "PrivilegedRolesFromAzGraph", "PrivilegedEdgesFromExposureManagement".
    Defaults to "All".

.PARAMETER EntraIdClassificationParameterFile
    Path to the Entra ID classification parameter template file.
    Defaults to ./Classification/Templates/Classification_AadResources.Param.json.

.PARAMETER EntraIdCustomizedClassificationFile
    Path to the tenant-specific Entra ID classification file.
    Defaults to ./Classification/<TenantName>/Classification_AadResources.json, resolved from the active EntraOps tenant context.

.PARAMETER EntraOpsEamFolder
    Path to the root folder containing the EntraOps EAM JSON files (one subfolder per scope).
    Defaults to the EntraOps default classified EAM folder.

.PARAMETER EntraOpsScopes
    One or more EntraOps RBAC scopes to include when reading EAM data.
    Valid values: "Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender".
    Defaults to all available scopes.

.PARAMETER AzureHighPrivilegedRoles
    Azure RBAC role names that are considered high-privileged when using the PrivilegedRolesFromAzGraph source.
    Defaults to: "Owner", "Role Based Access Control Administrator", "User Access Administrator".

.PARAMETER AzureHighPrivilegedScopes
    Azure resource scopes (management group or subscription paths) to restrict the Azure Resource Graph query.
    Use "*" (default) to include all scopes, including management groups.

.PARAMETER ExposureCriticalityLevel
    KQL comparison expression applied to the criticalityLevel field in Exposure Management when using PrivilegedEdgesFromExposureManagement.
    Defaults to "<1" (Tier-0 / critical assets).

.PARAMETER PrivilegedObjectIds
    Array of Entra object IDs to classify as Control Plane when using the PrivilegedObjectIds source.

.EXAMPLE
    Return Control Plane objects identified by EntraOps EAM data across all available RBAC scopes.
    Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource "EntraOps"

.EXAMPLE
    Return Control Plane objects identified by EntraOps EAM data for a specific subset of RBAC scopes.
    Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource "EntraOps" -EntraOpsScopes ("Azure", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps")

.EXAMPLE
    Return objects with attack-path edges to critical assets (criticalityLevel < 1) in Microsoft Security Exposure Management.
    Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource "PrivilegedEdgesFromExposureManagement" -ExposureCriticalityLevel "<1"

.EXAMPLE
    Return objects holding high-privileged Azure RBAC roles on specific management group or subscription scopes queried via Azure Resource Graph.
    Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource "PrivilegedRolesFromAzGraph" -AzureHighPrivilegedRoles ("Owner", "Role Based Access Control Administrator", "User Access Administrator") -AzureHighPrivilegedScopes ("/", "/providers/microsoft.management/managementgroups/8693dc7e-63c1-47ab-a7ee-acfe488bf52a")

.EXAMPLE
    Return a merged and deduplicated list of Control Plane objects from all supported classification sources.
    Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource "All"

.EXAMPLE
    Return Control Plane objects for a manually compiled list of privileged users and groups.
    $PrivilegedUsers  = Get-AzAdUser  -Filter "startswith(DisplayName,'adm')"
    $PrivilegedGroups = Get-AzAdGroup -Filter "startswith(DisplayName,'prg')"
    $PrivilegedObjectIds = ($PrivilegedUsers + $PrivilegedGroups).Id
    Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource "PrivilegedObjectIds" -PrivilegedObjectIds $PrivilegedObjectIds

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
    if (!(Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)")) {
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
    if ($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "PrivilegedRolesFromAzGraph") {
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
        $Timespan = "P1D"
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
            "Timespan" = $Timespan;
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
        $PrivilegedObjects += $PrivilegedObjectIds | ForEach-Object {
            $PrivilegedObject = Get-EntraOpsPrivilegedEntraObject -AadObjectId $_
            $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationReason -Value @("Manual") -Force | Out-Null
            $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationSource -Value "Manual" -Force | Out-Null
            return $PrivilegedObject
        }
    }
    #endregion

    #region Display summary of identified Control Plane objects
    Write-Host "`n=== Control Plane Classification Summary ===" -ForegroundColor Cyan
    $UniqueTotalCount = ($PrivilegedObjects | Select-Object -Unique ObjectId).Count
    Write-Host "Total unique privileged objects identified: $UniqueTotalCount`n" -ForegroundColor White

    $PrivilegedObjects | Group-Object ClassificationSource | ForEach-Object {
        $SourceGroup = $_
        $UniqueSourceObjects = $SourceGroup.Group | Select-Object -Unique ObjectId, ObjectType, ObjectDisplayName
        Write-Host "  [Source: $($SourceGroup.Name)] - $($UniqueSourceObjects.Count) unique object(s)" -ForegroundColor Yellow

        switch ($SourceGroup.Name) {
            "EntraOps" {
                Write-Host "    Analyzed EntraOps scopes: $($EntraOpsScopes -join ', ')" -ForegroundColor Gray
                $ObjectLevelClassified = $SourceGroup.Group | Where-Object { $_.ClassificationReason -contains "ObjectAdminTierLevelName" } | Select-Object -Unique ObjectId
                $RoleLevelClassified = $SourceGroup.Group | Where-Object { $_.ClassificationReason -notcontains "ObjectAdminTierLevelName" } | Select-Object -Unique ObjectId
                if ($ObjectLevelClassified.Count -gt 0) {
                    Write-Host "    Classified by object-level Control Plane tier (ObjectAdminTierLevelName): $($ObjectLevelClassified.Count) object(s)" -ForegroundColor Gray
                }
                if ($RoleLevelClassified.Count -gt 0) {
                    $RoleSystems = $SourceGroup.Group | Where-Object { $_.ClassificationReason -notcontains "ObjectAdminTierLevelName" } `
                    | ForEach-Object { $_.ClassificationReason } | Where-Object { $null -ne $_.RoleSystem } `
                    | Select-Object -ExpandProperty RoleSystem -Unique | Sort-Object
                    Write-Host "    Classified by Control Plane role assignments: $($RoleLevelClassified.Count) object(s)" -ForegroundColor Gray
                    if ($RoleSystems) { Write-Host "    RBAC systems with Control Plane assignments: $($RoleSystems -join ', ')" -ForegroundColor Gray }
                }
            }
            "Azure Resource Graph" {
                Write-Host "    High privileged roles analyzed: $($AzureHighPrivilegedRoles -join ', ')" -ForegroundColor Gray
                if ($AzureHighPrivilegedScopes -eq "*") {
                    Write-Host "    Azure scopes: All scopes (including management groups)" -ForegroundColor Gray
                } else {
                    Write-Host "    Azure scopes: $($AzureHighPrivilegedScopes -join ', ')" -ForegroundColor Gray
                }
                $AssignedRoles = $SourceGroup.Group | ForEach-Object { $_.ClassificationReason } `
                | Where-Object { $null -ne $_.RoleName } | Select-Object -ExpandProperty RoleName -Unique | Sort-Object
                if ($AssignedRoles) { Write-Host "    Roles found assigned: $($AssignedRoles -join ', ')" -ForegroundColor Gray }
            }
            "XSPM" {
                Write-Host "    Exposure criticality level filter: $ExposureCriticalityLevel" -ForegroundColor Gray
                $EdgeLabels = $SourceGroup.Group | ForEach-Object { $_.ClassificationReason } `
                | Where-Object { $null -ne $_.EdgeLabel } | Select-Object -ExpandProperty EdgeLabel -Unique | Sort-Object
                if ($EdgeLabels) { Write-Host "    Exposure edge relations identified: $($EdgeLabels -join ', ')" -ForegroundColor Gray }
            }
            "Manual" {
                Write-Host "    Classification based on manually specified privileged object IDs" -ForegroundColor Gray
            }
        }

        $UniqueSourceObjects | Group-Object ObjectType | Sort-Object Name | ForEach-Object {
            Write-Host "    Object types: $($_.Count) $($_.Name)(s)" -ForegroundColor Gray
        }
        Write-Host ""
    }
    Write-Host "==========================================`n" -ForegroundColor Cyan
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