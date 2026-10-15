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
    Each configured value is matched exactly against the role assignment's scope; child scopes are not included.
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
        [System.String]$EntraIdClassificationParameterFile = "$DefaultFolderClassification/Templates/Classification_AadResources.Param.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$EntraIdCustomizedClassificationFile = "$DefaultFolderClassification/$($TenantNameContext)/Classification_AadResources.json"
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
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-EntraOpsAzContextValue -Property TenantId)
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$EnableParallelProcessing = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$ParallelThrottleLimit = 10
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
            | Select-Object -Unique ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectUserPrincipalName, ObjectTenantId, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices, AssociatedPawDevice `
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
                $PrivilegedObject = $_ | Select-Object ObjectId, ObjectType, ObjectSubType, ObjectDisplayName, ObjectUserPrincipalName, ObjectTenantId, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices, AssociatedPawDevice, RoleSystem
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
        # Fail rather than truncate: a partial result here drops privileged principals from the
        # Control Plane object list, which is indistinguishable from them not being privileged.
        $HighPrivilegedObjectIdsFromAzGraph = (Invoke-EntraOpsAzGraphQuery -KqlQuery $Query -ThrowOnFailure)
        $UniqueHighPrivilegedObjects = @($HighPrivilegedObjectIdsFromAzGraph | Select-Object -Unique PrincipalId, PrincipalType | Where-Object { -not [string]::IsNullOrEmpty($_.PrincipalId) } | ForEach-Object { [PSCustomObject]@{ ObjectId = $_.PrincipalId; ObjectType = $_.PrincipalType } })
        $AzGraphObjectDetailsCache = @{}
        if ($UniqueHighPrivilegedObjects.Count -gt 0) {
            $AzGraphObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution -UniqueObjects $UniqueHighPrivilegedObjects -TenantId $TenantId -EnableParallelProcessing $EnableParallelProcessing -ParallelThrottleLimit $ParallelThrottleLimit
        }
        $PrivilegedObjects += $UniqueHighPrivilegedObjects | ForEach-Object {
            $HighPrivilegedObjectId = $_
            $ResolvedObject = $AzGraphObjectDetailsCache[$HighPrivilegedObjectId.ObjectId]
            if ($null -ne $ResolvedObject -and $ResolvedObject.ObjectType -ne "unknown") {
                # Azure Resource Graph gives no row-order guarantee for joins, so RoleScope/RoleName pairs can
                # come back in a different order on every run - sort deterministically to avoid a spurious diff
                # in ScopeReasoning_ControlPlane.json each time the classification is regenerated with unchanged data.
                $HighPrivilegedRoles = $HighPrivilegedObjectIdsFromAzGraph | Where-Object { $_.PrincipalId -eq $HighPrivilegedObjectId.ObjectId -and $_.PrincipalType -eq $HighPrivilegedObjectId.ObjectType } | Sort-Object RoleScope, RoleName | Select-Object -Unique RoleScope, RoleName
                $PrivilegedObject = $ResolvedObject | Select-Object ObjectId, @{Name = 'ObjectType'; Expression = { $_.'ObjectType'.tolower() } }, ObjectSubType, ObjectDisplayName, ObjectSignInName, ObjectTenantId, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices, AssociatedPawDevice
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationReason -Value $HighPrivilegedRoles -Force | Out-Null
                $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationSource -Value "Azure Resource Graph" -Force | Out-Null
                $PrivilegedObject
            } else {
                Write-Warning "High privileged object with id $($HighPrivilegedObjectId.ObjectId) not found!"
            }
        }
    }
    #endregion

    #region Get list of all privileged objects by Microsoft Exposure Management
    if ($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "PrivilegedEdgesFromExposureManagement") {
        Write-Host "Get privileged objects from exposure graph edges and nodes in Exposure Management..."
        $Timespan = "P1D"
        # Performance: single-pass Tier0Assets scan (was 3 full ExposureGraphNodes scans unioned) and,
        # most importantly, the node join side is pre-filtered to just the filtered edges' source nodes
        # BEFORE the expensive mv-expand over EntityIds - previously the mv-expand ran over the ENTIRE
        # ExposureGraphNodes table (every resource/device/identity node), which dominated query runtime.
        $Query = '
        let Tier0Assets = ExposureGraphNodes
            | where isnotnull(NodeProperties.rawData.criticalityLevel) and (NodeProperties.rawData.criticalityLevel.criticalityLevel %CriticalLevel%)
            | where (NodeLabel != "device" and parse_json(Categories) !has "identities")
                or (NodeProperties.rawData.primaryProvider == "AzureActiveDirectory")
                or (NodeLabel == "device" and NodeProperties.rawData.isAzureADJoined == true)
            | project NodeId;
        let SensitiveRelation = dynamic(["has permissions to","can authenticate as","has role on","has credentials of","affecting", "can authenticate as", "Member of", "frequently logged in by"]);
        // Devices are not supported yet, no AadObject Id available in ExposureGraphNodes, DeviceInfo shows only AadDeviceId
        let FilteredNodes = dynamic(["user","group","serviceprincipal","managedidentity","device"]);
        let SensitiveEdges = ExposureGraphEdges
            | where EdgeLabel in (SensitiveRelation) and SourceNodeLabel in (FilteredNodes)
            | where TargetNodeId in (Tier0Assets) or SourceNodeId in (Tier0Assets);
        let SensitiveSourceNodeIds = SensitiveEdges | distinct SourceNodeId;
        SensitiveEdges
        | join kind=leftouter ( ExposureGraphNodes
            | where NodeId in (SensitiveSourceNodeIds)
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
            "Query"    = $Query;
            "Timespan" = $Timespan;
        } | ConvertTo-Json
        $PrivilegedObjectsGraphEdges = (Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/security/runHuntingQuery" -Body $Body).results
        if ($null -ne $PrivilegedObjectsGraphEdges) {
            $UniqueGraphEdgeObjects = @($PrivilegedObjectsGraphEdges | Select-Object -Unique ObjectDisplayName, ObjectId, ObjectType | Where-Object { -not [string]::IsNullOrEmpty($_.ObjectId) })
            $XspmObjectDetailsCache = @{}
            if ($UniqueGraphEdgeObjects.Count -gt 0) {
                $XspmResolutionObjects = @($UniqueGraphEdgeObjects | ForEach-Object { [PSCustomObject]@{ ObjectId = $_.ObjectId; ObjectType = $_.ObjectType } })
                $XspmObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution -UniqueObjects $XspmResolutionObjects -TenantId $TenantId -EnableParallelProcessing $EnableParallelProcessing -ParallelThrottleLimit $ParallelThrottleLimit
            }
            $PrivilegedObjects += $UniqueGraphEdgeObjects | ForEach-Object {
                $GraphEdge = $_
                # Normalize ObjectType casing (Get-EntraOpsPrivilegedEntraObject can return mixed-case values,
                # e.g. from the Graph @odata.type) so the same object isn't later treated as two distinct
                # entries by the ObjectId+ObjectType uniqueness check below.
                $ResolvedObject = $XspmObjectDetailsCache[$GraphEdge.ObjectId]
                if ($null -ne $ResolvedObject -and $ResolvedObject.ObjectType -ne "unknown") {
                    $PrivilegedObject = $ResolvedObject | Select-Object ObjectId, @{Name = 'ObjectType'; Expression = { $_.'ObjectType'.tolower() } }, ObjectSubType, ObjectDisplayName, ObjectSignInName, ObjectTenantId, AssignedAdministrativeUnits, RestrictedManagementByRAG, RestrictedManagementByAadRole, RestrictedManagementByRMAU, OwnedDevices, AssociatedPawDevice
                    $ClassificationReason = @()
                    $ClassificationReason += ($PrivilegedObjectsGraphEdges | Where-Object { $_.ObjectId -eq $GraphEdge.ObjectId -and $_.ObjectType -eq $GraphEdge.ObjectType }).ClassificationReason | ConvertFrom-Json
                    # Kusto's "summarize by" gives no ordering guarantee, so EdgeLabel/TargetNodeName pairs can come
                    # back in a different order on every run - sort deterministically to avoid a spurious diff in
                    # ScopeReasoning_ControlPlane.json each time the classification is regenerated with unchanged data.
                    $ClassificationReason = @($ClassificationReason | Sort-Object EdgeLabel, TargetNodeName)
                    $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationReason -Value $ClassificationReason -Force | Out-Null
                    $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationSource -Value "XSPM" -Force | Out-Null
                    $PrivilegedObject
                }
            }
        }
    }
    #endregion

    #region Get list of all privileged objects by manual list of ObjectIds
    if ($PrivilegedObjectClassificationSource -contains "PrivilegedObjectIds" -and $null -ne $PrivilegedObjectIds) {
        Write-Host "Get privileged objects from manual list of object ids..."
        $PrivilegedObjects += $PrivilegedObjectIds | ForEach-Object {
            $PrivilegedObject = Get-EntraOpsPrivilegedEntraObject -AadObjectId $_
            # Normalize ObjectType casing for the same reason as the XSPM source above.
            $PrivilegedObject.ObjectType = $PrivilegedObject.ObjectType.tolower()
            $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationReason -Value @("Manual") -Force | Out-Null
            $PrivilegedObject | Add-Member -MemberType NoteProperty -Name ClassificationSource -Value "Manual" -Force | Out-Null
            return $PrivilegedObject
        }
    }
    #endregion

    #region Display summary of identified Control Plane objects
    Write-Host "`n=== Control Plane Classification Summary ===" -ForegroundColor Cyan
    $UniqueTotalCount = @($PrivilegedObjects | Select-Object -Unique ObjectId).Count
    Write-Host "Total unique privileged objects identified: $UniqueTotalCount`n" -ForegroundColor White

    $PrivilegedObjects | Group-Object ClassificationSource | ForEach-Object {
        $SourceGroup = $_
        $UniqueSourceObjects = @($SourceGroup.Group | Select-Object -Unique ObjectId, ObjectType, ObjectDisplayName)
        Write-Host "  [Source: $($SourceGroup.Name)] - $($UniqueSourceObjects.Count) unique object(s)" -ForegroundColor Yellow

        switch ($SourceGroup.Name) {
            "EntraOps" {
                Write-Host "    Analyzed EntraOps scopes: $($EntraOpsScopes -join ', ')" -ForegroundColor Gray
                $ObjectLevelClassified = @($SourceGroup.Group | Where-Object { $_.ClassificationReason -contains "ObjectAdminTierLevelName" } | Select-Object -Unique ObjectId)
                $RoleLevelClassified = @($SourceGroup.Group | Where-Object { $_.ClassificationReason -notcontains "ObjectAdminTierLevelName" } | Select-Object -Unique ObjectId)
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
    # One entry per identity: Select-Object -Unique cannot be used here because it compares array/object
    # properties (AssignedAdministrativeUnits, OwnedDevices, ...) by reference and keeps identities whose
    # metadata differs between sources (previous EAM export vs live Graph resolution) - both produced duplicates.
    # Protection flags are merged fail-safe ($true only if every source reports protected), matching the
    # downstream "-ne $true = unprotected" evaluation; device and administrative unit references are unioned.
    $PrivilegedObjectGroups = @($PrivilegedObjects | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace("$($_.ObjectId)") } |
        Group-Object -Property { "$($_.ObjectId)".ToLowerInvariant() + '|' + "$($_.ObjectType)".ToLowerInvariant() })

    $MergedPrivilegedObjects = foreach ($PrivilegedObjectGroup in $PrivilegedObjectGroups) {
        $GroupEntries = @($PrivilegedObjectGroup.Group | Sort-Object { "$($_.ClassificationSource)" }, { $_ | Select-Object * -ExcludeProperty ClassificationReason, ClassificationSource | ConvertTo-Json -Compress -Depth 5 })

        $GetOptionalValue = {
            param($Entry, $PropertyName)
            # Missing optional metadata (including protection flags) is null, even under strict mode.
            $Property = $Entry.PSObject.Properties[$PropertyName]
            if ($null -ne $Property) { $Property.Value } else { $null }
        }
        $FirstValue = {
            param($PropertyName)
            $GroupEntries | ForEach-Object { & $GetOptionalValue $_ $PropertyName } | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | Select-Object -First 1
        }
        $MergeProtectionFlag = {
            param([object[]]$Values)
            if (@($Values | Where-Object { $_ -ne $true }).Count -eq 0) {
                $true
            } elseif (@($Values | Where-Object { $_ -eq $false }).Count -gt 0) {
                $false
            } else {
                $null
            }
        }
        $UnionValues = {
            param($PropertyName)
            $Values = @($GroupEntries | ForEach-Object { & $GetOptionalValue $_ $PropertyName } | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | Sort-Object -Unique)
            if ($Values.Count -gt 0) { , $Values } else { $null }
        }

        $AdministrativeUnits = @($GroupEntries | ForEach-Object { & $GetOptionalValue $_ 'AssignedAdministrativeUnits' } | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace("$($_.id)") } |
            Group-Object -Property { "$($_.id)".ToLowerInvariant() } | Sort-Object Name | ForEach-Object { $_.Group[0] })

        $RestrictedManagementFlags = @{}
        foreach ($FlagName in @('RestrictedManagementByAadRole', 'RestrictedManagementByRAG', 'RestrictedManagementByRMAU')) {
            $FlagValues = @($GroupEntries | ForEach-Object { & $GetOptionalValue $_ $FlagName })
            $RestrictedManagementFlags[$FlagName] = & $MergeProtectionFlag $FlagValues
            if (@($FlagValues | Where-Object { $_ -eq $true }).Count -gt 0 -and @($FlagValues | Where-Object { $_ -ne $true }).Count -gt 0) {
                Write-Warning "Conflicting $FlagName values for privileged object $($GroupEntries[0].ObjectId) across classification sources - treated as unprotected."
            }
        }

        $Classifications = @($GroupEntries | Select-Object ClassificationReason, ClassificationSource)
        # An object can carry multiple classification-reason entries (one per originating source: EntraOps
        # per-RBAC-scope hits, Azure Resource Graph, XSPM edges, ...), collected here via a plain filter with no
        # inherent order. Since ClassificationReason/ClassificationSource mix scalars and differently-shaped
        # objects (RoleSystem vs EdgeLabel/TargetNodeName), sort by their compact JSON representation - this is a
        # function of content only, so the order is stable across runs regardless of upstream arrival order
        # (notably the XSPM Kusto query, which gives no row-order guarantee).
        $Classifications = @($Classifications | Sort-Object { $_ | ConvertTo-Json -Compress -Depth 5 })

        [PSCustomObject][ordered]@{
            ObjectId                      = $GroupEntries[0].ObjectId
            ObjectType                    = "$($GroupEntries[0].ObjectType)".ToLowerInvariant()
            ObjectSubType                 = & $FirstValue 'ObjectSubType'
            ObjectDisplayName             = & $FirstValue 'ObjectDisplayName'
            ObjectSignInName              = & $FirstValue 'ObjectSignInName'
            ObjectTenantId                = & $FirstValue 'ObjectTenantId'
            RestrictedManagementByAadRole = $RestrictedManagementFlags['RestrictedManagementByAadRole']
            RestrictedManagementByRAG     = $RestrictedManagementFlags['RestrictedManagementByRAG']
            RestrictedManagementByRMAU    = $RestrictedManagementFlags['RestrictedManagementByRMAU']
            OwnedDevices                  = & $UnionValues 'OwnedDevices'
            AssociatedPawDevice           = & $UnionValues 'AssociatedPawDevice'
            AssignedAdministrativeUnits   = if ($AdministrativeUnits.Count -gt 0) { , $AdministrativeUnits } else { $null }
            Classification                = $Classifications
        }
    }

    # Sort deterministically (ObjectId as final tiebreaker) so the output order is stable across runs -
    # otherwise objects sharing the same ObjectType/ObjectDisplayName (e.g. same-named managed identities)
    # can swap positions between runs purely due to upstream API pagination/enumeration order, producing
    # spurious diff noise with no actual data change.
    $MergedPrivilegedObjects | Sort-Object ObjectType, ObjectDisplayName, ObjectId
    #endregion
}
