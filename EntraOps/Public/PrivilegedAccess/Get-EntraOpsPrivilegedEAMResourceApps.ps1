<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Resource Apps and assigned app roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Resource Apps and assigned app roles and classifications.
    Supports parallel processing (PowerShell 7+) using Microsoft Graph SDK's process-level authentication context.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".

.PARAMETER EnableParallelProcessing
    Enable parallel processing for object detail resolution. Default is $true. Requires PowerShell 7+ and MgGraph SDK.

.PARAMETER ParallelThrottleLimit
    Maximum number of parallel threads. Default is 10.

.PARAMETER IncludeJustification
    Include the Justification property (documenting a manual classification overwrite) on all Classification
    entries of the returned objects. Default is $false, so the property is not present in the output at all.

.PARAMETER IncludeObjectDetails
    Include descriptive object details in warning output. Defaults to ConsoleOutput.IncludeObjectDetails from
    EntraOpsConfig.json. Object IDs are always shown.
#>

function Get-EntraOpsPrivilegedEamResourceApps {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-EntraOpsAzContextValue -Property TenantId)
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification"
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$SampleMode = $False
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$GlobalExclusion = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$EnableParallelProcessing = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$ParallelThrottleLimit = 10
        ,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeJustification
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
    )

    # Ensure TenantId is always set before it propagates into parallel runspaces where
    # $Global:TenantIdContext is not available. (Get-AzContext).Tenant.Id can return null
    # when only MgGraph auth is active (no Az context), which would cause ObjectTenantId
    # to be empty in all output entries.
    if ([string]::IsNullOrEmpty($TenantId) -and -not [string]::IsNullOrEmpty($Global:TenantIdContext)) {
        $TenantId = $Global:TenantIdContext
    }

    # Configuration for batch processing
    $BatchSize = 100  # Number of objects to process before showing progress
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    #region Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ResourceAppsClassificationFilePath = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_ApiPermissions.json"
    #endregion

    Write-Host "Getting App Roles from Entra ID Service Principals..."

    #region Get all role assignments and global exclusions
    if ($SampleMode -ne $True) {
        $AppRoleAssignments = Get-EntraOpsPrivilegedAppRoles -TenantId $TenantId -WarningMessages $WarningMessages
    } else {
        $WarningMessages.Add([PSCustomObject]@{Type = "SampleMode"; Message = "SampleMode currently not supported!" })
    }
    $GlobalExclusionList = Import-EntraOpsGlobalExclusions -Enabled $GlobalExclusion
    #endregion

    #region Check if App Role Assignment and scope is defined in JSON classification
    Write-Host "Checking if App role and scope is defined in JSON classification..."
    # Classification_ApiPermissions.json (Classification/Templates or tenant-specific) uses the same nested
    # EAMTierLevelName/TierLevelDefinition[] schema as Azure/Defender/DeviceManagement/IdentityGovernance/
    # AadResources (entries additionally carry ResourceAppId/ResourceScope). Expand-EntraOpsPrivilegedEAMJsonFile
    # flattens it into one row per RoleDefinitionActions/RoleAssignmentScopeName pair, matching the shape the
    # matching logic below expects. Do not confuse this with the separate, FLAT per-permission catalog of the
    # same filename published at the root of the AzurePrivilegedIAM repository (Classification/Classification_
    # ApiPermissions.json, PermissionValue/PermissionType/TargetAppId/Category schema) - that file is an
    # independent artifact used for KQL/Sentinel lookups and the Classification Explorer's API Permissions
    # browsing view, not consumed here.
    $AppRoleByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $ResourceAppsClassificationFilePath

    # Role action overwrites are already baked into the classification file by Update-EntraOpsClassificationControlPlaneScope.
    #endregion

    #region Classify App Role Assignments for Service Principals
    $AppRoleClassifications = @(Resolve-EntraOpsAppRoleAssignmentClassification -AppRoleAssignments $AppRoleAssignments -ClassificationDefinitions $AppRoleByClassificationJSON)
    #endregion
    $AppRoleClassifications = $AppRoleClassifications | sort-object -property @{e = { $_.Classification.AdminTierLevel } }, RoleDefinitionName

    #region Get Agent Identities and store to $AppRoleClassifiedAgentIdObjectsByParentId
    Write-Host "Getting Agent Identities by parent blueprint principals..."
    
    $AllAgentIdBlueprintPrincipals = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?`$select=id, appId, displayName, createdByAppId, appOwnerOrganizationId"
    $AppRoleClassifiedAgentIdObjectsByParentId = foreach ( $AgentIdentityBlueprintPrincipal in $AllAgentIdBlueprintPrincipals ) {
        #region Process each Agent Identity Blueprint Principal
        Write-Verbose "Processing Agent Identity Blueprint Principal: $($AgentIdentityBlueprintPrincipal.displayName) ($($AgentIdentityBlueprintPrincipal.id))"

        # Add classified role assignments to Agent Identity Blueprint Principal
        $AgentIdentityBlueprintPrincipalAppRoles = $AppRoleClassifications | where-object { $_.ObjectId -eq $AgentIdentityBlueprintPrincipal.Id }

        if ( $AgentIdentityBlueprintPrincipal.appOwnerOrganizationId -ne $TenantId ) {
            $WarningMessages.Add([PSCustomObject]@{Type = "AgentIdentity-MultiTenant"; Message = "Skipping Agent Identity Blueprint Principal: $($AgentIdentityBlueprintPrincipal.displayName) ($($AgentIdentityBlueprintPrincipal.id)) as it belongs to multi-tenant app without visibility of inheritable permissions: $($AgentIdentityBlueprintPrincipal.appOwnerOrganizationId)"; Target = $AgentIdentityBlueprintPrincipal.id })
            $inheritablePermissionScopes = $null
            continue
        } else {
            $AgentIdentityPermissions = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/applications/microsoft.graph.agentIdentityBlueprint/$($AgentIdentityBlueprintPrincipal.appid)/inheritablePermissions"
            #region Extract inheritable permission scopes
            $inheritablePermissionScopes = foreach ($AgentIdentityResourceAppPermission in $AgentIdentityPermissions) {
                if ($AgentIdentityResourceAppPermission.inheritableScopes.kind -eq "allAllowed") {
                    $AllAllowedScopeId = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '$($AgentIdentityResourceAppPermission.resourceAppId)'" | select-object -ExpandProperty id
                    $InheritableResourceAppPermission = $AgentIdentityBlueprintPrincipalAppRoles | where-object { $_.RoleAssignmentScopeId -eq $AllAllowedScopeId -and $_.RoleType -eq "Delegated" }
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "RoleAssignmentType" -NotePropertyValue "Inheritable" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "RoleAssignmentSubType" -NotePropertyValue "AllAllowed" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByObjectDisplayName" -NotePropertyValue "$($AgentIdentityBlueprintPrincipal.displayName)" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByObjectId" -NotePropertyValue "$($AgentIdentityBlueprintPrincipal.id)" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByNestingObjectIds" -NotePropertyValue $null -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByNestingObjectDisplayNames" -NotePropertyValue $null -Force
                    $InheritableResourceAppPermission
                } elseif ($AgentIdentityResourceAppPermission.inheritableScopes.kind -eq "enumerated") {
                    $RoleAssignmentScopeId = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '$($AgentIdentityResourceAppPermission.resourceAppId)'" | select-object -ExpandProperty id
                    $RoleDefinitionNames = $AgentIdentityResourceAppPermission.inheritableScopes.scopes 
                    $InheritableResourceAppPermission = $AgentIdentityBlueprintPrincipalAppRoles | Where-Object { $_.RoleAssignmentScopeId -eq $RoleAssignmentScopeId -and $_.RoleDefinitionName -in $RoleDefinitionNames }
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "RoleAssignmentType" -NotePropertyValue "Inheritable" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "RoleAssignmentSubType" -NotePropertyValue "Enumerated" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByObjectDisplayName" -NotePropertyValue "$($AgentIdentityBlueprintPrincipal.displayName)" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByObjectId" -NotePropertyValue "$($AgentIdentityBlueprintPrincipal.id)" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByNestingObjectIds" -NotePropertyValue $null -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByNestingObjectDisplayNames" -NotePropertyValue $null -Force
                    $InheritableResourceAppPermission
                } elseif ($null -eq $AgentIdentityResourceAppPermission.inheritableScopes.kind) {
                    Write-Verbose "No inheritable scopes defined for Agent Identity $($AgentIdentityBlueprintPrincipal.displayName) Resource App Permission: $($AgentIdentityResourceAppPermission.id)"
                } else {
                    $WarningMessages.Add([PSCustomObject]@{Type = "AgentIdentity-UnknownScope"; Message = "Unknown inheritableScopes.kind: $($AgentIdentityResourceAppPermission.inheritableScopes.kind)" })
                }
            }
            #endregion

            if ( $inheritablePermissionScopes.Count -eq 0 -or $null -eq $inheritablePermissionScopes ) {
                Write-Host "No inheritable permission scopes found for Agent Identity Blueprint Principal: $($AgentIdentityBlueprintPrincipal.displayName) ($($AgentIdentityBlueprintPrincipal.id))"
                continue
            } else {
                $ChildAgentIdentities = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$filter=(isof('microsoft.graph.agentIdentity')%20OR%20(tags%2Fany(p%3Astartswith(p%2C%20'power-virtual-agents-'))%20OR%20tags%2Fany(p%3Ap%20eq%20'AgenticInstance')))%20AND%20createdByAppId%20eq%20'$($AgentIdentityBlueprintPrincipal.appId)'"
                foreach ( $ChildAgentIdentity in $ChildAgentIdentities ) {
                    $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ChildAgentIdentity.Id -TenantId $TenantId

                    # Classification
                    $Classification = @(Merge-EntraOpsEAMClassification -RoleAssignments @($inheritablePermissionScopes))
                    if ($Classification.Count -eq 0) {
                        $Classification += [PSCustomObject]@{
                            'AdminTierLevel'     = "Unclassified"
                            'AdminTierLevelName' = "Unclassified"
                            'Service'            = "Unclassified"
                        }
                    }

                    [PSCustomObject]@{
                        'ObjectId'                      = $ChildAgentIdentity.id
                        'ObjectTenantId'                = $AgentIdentityBlueprintPrincipal.appOwnerOrganizationId
                        'ObjectType'                    = $ObjectDetails.ObjectType.toLower()
                        'ObjectSubType'                 = $ObjectDetails.ObjectSubType
                        'ObjectDisplayName'             = $ObjectDetails.ObjectDisplayName
                        'ObjectUserPrincipalName'       = $ObjectDetails.ObjectSignInName
                        'ObjectAdminTierLevel'          = $ObjectDetails.AdminTierLevel
                        'ObjectAdminTierLevelName'      = $ObjectDetails.AdminTierLevelName
                        'OnPremSynchronized'            = $ObjectDetails.OnPremSynchronized
                        'AssignedAdministrativeUnits'   = $ObjectDetails.AssignedAdministrativeUnits
                        'RestrictedManagementByRAG'     = $ObjectDetails.RestrictedManagementByRAG
                        'RestrictedManagementByAadRole' = $ObjectDetails.RestrictedManagementByAadRole
                        'RestrictedManagementByRMAU'    = $ObjectDetails.RestrictedManagementByRMAU
                        'RoleSystem'                    = "ResourceApps"
                        'Classification'                = $Classification
                        'RoleAssignments'               = @($inheritablePermissionScopes | Sort-Object { ($_.Classification | Sort-Object AdminTierLevel -Top 1).AdminTierLevel }, RoleDefinitionName, RoleAssignmentScopeId, RoleAssignmentId)
                        'Sponsors'                      = $ObjectDetails.Sponsors
                        'Owners'                        = $ObjectDetails.Owners
                        'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                        'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                        'IdentityParent'                = $ObjectDetails.IdentityParent
                        'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                        'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
                    }
                }
            }
        }
        # endregion
    }
    #endregion

    #region Add classification and details of Service Principals to output
    Write-Host "Classifying of all assigned privileged app roles to service principals..."

    # Optimization: Collect all unique ObjectIds and batch resolve details
    # Case-insensitive dedup (mirrors Get-EntraOpsPrivilegedEAMAzure.ps1): Select-Object -Unique compares
    # ObjectId case-sensitively and would emit the same principal twice when ids differ only in casing.
    $UniqueObjects = @(
        $AppRoleAssignments |
            Where-Object { $null -ne $_.ObjectId } |
            Group-Object -Property { "$($_.ObjectId)".ToLowerInvariant() } |
            ForEach-Object { $_.Group[0] | Select-Object ObjectId, ObjectType }
    )
    
    # Use helper function for parallel/sequential object resolution
    $ObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution `
        -UniqueObjects $UniqueObjects `
        -TenantId $TenantId `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit

    # Group assignments by ObjectId for fast lookup
    $AppRoleByObject = $AppRoleClassifications | Group-Object ObjectId -AsHashTable -AsString
    $AgentIdObjectsByObject = if ($null -ne $AppRoleClassifiedAgentIdObjectsByParentId) {
        $AppRoleClassifiedAgentIdObjectsByParentId | Group-Object ObjectId -AsHashTable -AsString
    } else {
        @{}
    }

    # Classification is CPU-only and indexed; a runspace pool costs more than it saves for modest inventories.
    $HasSufficientObjects = $UniqueObjects.Count -ge 500
    $UseParallelForClassification = $EnableParallelProcessing -and $HasSufficientObjects
    
    if ($UseParallelForClassification) {
        # Convert hashtables to synchronized versions for thread-safe access
        $SyncObjectDetailsCache = [System.Collections.Hashtable]::Synchronized($ObjectDetailsCache)
        $SyncAppRoleByObject = [System.Collections.Hashtable]::Synchronized($AppRoleByObject)
        $SyncAgentIdObjects = [System.Collections.Hashtable]::Synchronized($AgentIdObjectsByObject)

        # Merge classifications up front (module helpers are not available in parallel runspaces).
        # Same assignment sources as below; duplicates do not affect the union.
        $MergedClassificationByObject = @{}
        foreach ($UniqueObject in $UniqueObjects) {
            $UniqueObjectId = $UniqueObject.ObjectId
            if ($null -eq $UniqueObjectId -or $MergedClassificationByObject.ContainsKey($UniqueObjectId)) { continue }
            $MergeAssignments = @($AppRoleByObject[$UniqueObjectId])
            if ($AgentIdObjectsByObject.ContainsKey($UniqueObjectId)) {
                $MergeAssignments += @($AgentIdObjectsByObject[$UniqueObjectId].RoleAssignments)
            }
            $MergedClassificationByObject[$UniqueObjectId] = @(Merge-EntraOpsEAMClassification -RoleAssignments $MergeAssignments)
        }
        $SyncMergedClassificationByObject = [System.Collections.Hashtable]::Synchronized($MergedClassificationByObject)
        
        $ClassificationThrottleLimit = [Math]::Min($ParallelThrottleLimit, 10)
        Write-Host "Using parallel classification processing with $ClassificationThrottleLimit threads for $($UniqueObjects.Count) objects..." -ForegroundColor Yellow
        
        $AppRoleClassifiedSpObjects = $UniqueObjects | ForEach-Object -ThrottleLimit $ClassificationThrottleLimit -Parallel {
            $obj = $_
            $ObjectId = $obj.ObjectId
            
            if ($null -ne $ObjectId) {
                $SharedDetailsCache = $using:SyncObjectDetailsCache
                $SharedAppRoleByObject = $using:SyncAppRoleByObject
                $SharedAgentIdObjects = $using:SyncAgentIdObjects
                
                $ObjectDetails = $SharedDetailsCache[$ObjectId]
                
                if ($null -eq $ObjectDetails) {
                    Write-Verbose "Skipping object $ObjectId - failed to retrieve details"
                    return
                }

                # Role Assignments
                $AppRoleAssignments = @()
                
                if ($SharedAgentIdObjects.ContainsKey($ObjectId)) {
                    $AppRoleAssignments += $SharedAppRoleByObject[$ObjectId] | Select-Object -Unique *
                    $AppRoleAssignments += $SharedAgentIdObjects[$ObjectId].RoleAssignments
                } else {
                    $AppRoleAssignments += $SharedAppRoleByObject[$ObjectId] | Select-Object -Unique *
                }

                # Merged classifications are precomputed in the calling runspace (module helpers are not
                # available here); see Merge-EntraOpsEAMClassification.
                $SharedMergedClassification = $using:SyncMergedClassificationByObject
                $Classification = @($SharedMergedClassification[$ObjectId])

                if ($Classification.Count -eq 0) {
                    $Classification = @([PSCustomObject]@{
                            'AdminTierLevel'     = "Unclassified"
                            'AdminTierLevelName' = "Unclassified"
                            'Service'            = "Unclassified"
                        })
                }

                [PSCustomObject]@{
                    'ObjectId'                      = $ObjectId
                    'ObjectTenantId'                = $ObjectDetails.ObjectTenantId
                    'ObjectType'                    = $ObjectDetails.ObjectType.toLower()
                    'ObjectSubType'                 = $ObjectDetails.ObjectSubType
                    'ObjectDisplayName'             = $ObjectDetails.ObjectDisplayName
                    'ObjectUserPrincipalName'       = $ObjectDetails.ObjectSignInName
                    'ObjectAdminTierLevel'          = $ObjectDetails.AdminTierLevel
                    'ObjectAdminTierLevelName'      = $ObjectDetails.AdminTierLevelName
                    'OnPremSynchronized'            = $ObjectDetails.OnPremSynchronized
                    'AssignedAdministrativeUnits'   = $ObjectDetails.AssignedAdministrativeUnits
                    'RestrictedManagementByRAG'     = $ObjectDetails.RestrictedManagementByRAG
                    'RestrictedManagementByAadRole' = $ObjectDetails.RestrictedManagementByAadRole
                    'RestrictedManagementByRMAU'    = $ObjectDetails.RestrictedManagementByRMAU
                    'RoleSystem'                    = "ResourceApps"
                    'Classification'                = $Classification
                    'RoleAssignments'               = @($AppRoleAssignments | Sort-Object { ($_.Classification | Sort-Object AdminTierLevel -Top 1).AdminTierLevel }, RoleDefinitionName, RoleAssignmentScopeId, RoleAssignmentId)
                    'Sponsors'                      = $ObjectDetails.Sponsors
                    'Owners'                        = $ObjectDetails.Owners
                    'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                    'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                    'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                    'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
                }
            }
        }

        if ($AppRoleClassifiedSpObjects.Count -ne $UniqueObjects.Count) {
            $WarningMessages.Add([PSCustomObject]@{Type = "Stage-Classification-Parallel"; Message = "Parallel classification returned fewer objects than expected. Expected: $($UniqueObjects.Count), Actual: $($AppRoleClassifiedSpObjects.Count)" })
            Write-Warning "Parallel classification returned fewer objects than expected. Expected: $($UniqueObjects.Count), Actual: $($AppRoleClassifiedSpObjects.Count)"
        }
    } else {
        if ($EnableParallelProcessing) {
            Write-Host "Using sequential classification processing (dataset too small: $($UniqueObjects.Count) objects)" -ForegroundColor Yellow
        } else {
            Write-Host "Using sequential classification processing (parallel disabled)..." -ForegroundColor Yellow
        }
        
        $AppRoleClassifiedSpObjects = $UniqueObjects | ForEach-Object {
            if ($null -ne $_.ObjectId) {
                $ObjectId = $_.ObjectId
                if ($VerbosePreference -ne 'SilentlyContinue') {
                    Write-Verbose -Message "Processing classifications for $($ObjectId)..."
                }
            
                # Object types
                $ObjectDetails = $ObjectDetailsCache[$ObjectId]
            
                # Skip if object details couldn't be retrieved
                if ($null -eq $ObjectDetails) {
                    $WarningMessages.Add([PSCustomObject]@{Type = "SkippedObject"; Message = "Skipping object $ObjectId - failed to retrieve details"; Target = $ObjectId })
                    return
                }

                # Role Assignments
                $AppRoleAssignments = @()

                if ($AgentIdObjectsByObject.ContainsKey($ObjectId)) {
                    # Merge classifications and role assignments if service principal has inheritable permissions by agent blueprint and assigned app roles
                    $AppRoleAssignments += $AppRoleByObject[$ObjectId] | Select-Object -Unique *
                    $AppRoleAssignments += $AgentIdObjectsByObject[$ObjectId].RoleAssignments
                } else {
                    $AppRoleAssignments += $AppRoleByObject[$ObjectId] | Select-Object -Unique *
                }

                # Classification - merge MatchedActions/ScopedObjects across all assignments per tier/service
                $Classification = @(Merge-EntraOpsEAMClassification -RoleAssignments @($AppRoleAssignments))

                if ($Classification.Count -eq 0) {
                    $Classification = @(
                        [PSCustomObject]@{
                            'AdminTierLevel'     = "Unclassified"
                            'AdminTierLevelName' = "Unclassified"
                            'Service'            = "Unclassified"
                        }
                    )
                }

                [PSCustomObject]@{
                    'ObjectId'                      = $ObjectId
                    'ObjectTenantId'                = $ObjectDetails.ObjectTenantId
                    'ObjectType'                    = $ObjectDetails.ObjectType.toLower()
                    'ObjectSubType'                 = $ObjectDetails.ObjectSubType
                    'ObjectDisplayName'             = $ObjectDetails.ObjectDisplayName
                    'ObjectUserPrincipalName'       = $ObjectDetails.ObjectSignInName
                    'ObjectAdminTierLevel'          = $ObjectDetails.AdminTierLevel
                    'ObjectAdminTierLevelName'      = $ObjectDetails.AdminTierLevelName
                    'OnPremSynchronized'            = $ObjectDetails.OnPremSynchronized
                    'AssignedAdministrativeUnits'   = $ObjectDetails.AssignedAdministrativeUnits
                    'RestrictedManagementByRAG'     = $ObjectDetails.RestrictedManagementByRAG
                    'RestrictedManagementByAadRole' = $ObjectDetails.RestrictedManagementByAadRole
                    'RestrictedManagementByRMAU'    = $ObjectDetails.RestrictedManagementByRMAU
                    'RoleSystem'                    = "ResourceApps"
                    'Classification'                = $Classification
                    'RoleAssignments'               = @($AppRoleAssignments | Sort-Object { ($_.Classification | Sort-Object AdminTierLevel -Top 1).AdminTierLevel }, RoleDefinitionName, RoleAssignmentScopeId, RoleAssignmentId)
                    'Sponsors'                      = $ObjectDetails.Sponsors
                    'Owners'                        = $ObjectDetails.Owners
                    'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                    'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                    'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                    'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
                }
            }
        }
    }
    #endregion

    #region Add agent identities to classified objects if not already present and correct role assignment ObjectIds
    $AppRoleClassifiedAgentIdObjects = $AppRoleClassifiedAgentIdObjectsByParentId | where-object { $_.ObjectId -notin $AppRoleClassifiedSpObjects.ObjectId }
    $AppRoleClassifiedObjects = @($AppRoleClassifiedSpObjects) + @($AppRoleClassifiedAgentIdObjects)

    # Overwrite ObjectId of RoleAssignments for Agent Identities to match Agent Identity ObjectId (and not include Blueprint Principal ObjectId)
    $AppRoleClassifiedObjects | Where-Object { $_.ObjectSubType -eq "AgentIdentity" } | ForEach-Object {
        $AgentObjectId = $_.ObjectId
        $_.RoleAssignments | ForEach-Object {
            $_.ObjectId = $AgentObjectId
        }
    }    
    #endregion       

    Write-Host "Applying global exclusions and finalizing results..."
    $AppRoleClassifiedObjects = $AppRoleClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }
    
    Write-Host "Completed processing $($AppRoleClassifiedObjects.Count) privileged objects."

    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages -IncludeObjectDetails $IncludeObjectDetails

    $AppRoleClassifiedObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Set-EntraOpsEAMClassificationJustification -IncludeJustification:$IncludeJustification | Sort-Object ObjectAdminTierLevel, ObjectDisplayName, ObjectId

}