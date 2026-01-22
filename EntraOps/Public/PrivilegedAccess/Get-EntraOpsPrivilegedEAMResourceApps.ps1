<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Resource Apps and assigned app roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Resource Apps and assigned app roles and classifications.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".
#>

function Get-EntraOpsPrivilegedEamResourceApps {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-AzContext).Tenant.Id
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification"
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$SampleMode = $False
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$GlobalExclusion = $true
    )

    # Configuration for batch processing
    $BatchSize = 100  # Number of objects to process before showing progress

    #region Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ClassificationFileName = "Classification_AppRoles.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $ResourceAppsClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    } elseif (Test-Path -Path "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)") {
        $ResourceAppsClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    } else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }
    #endregion

    Write-Host "Getting App Roles from Entra ID Service Principals..."

    #region Get all role assignments and global exclusions
    if ($SampleMode -ne $True) {
        $AppRoleAssignments = Get-EntraOpsPrivilegedAppRoles -TenantId $TenantId
    } else {
        Write-Warning "Currently not supported!"
    }
    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    } else {
        $GlobalExclusionList = $null
    }
    #endregion

    #region Check if App Role Assignment and scope is defined in JSON classification
    Write-Host "Checking if App role and scope is defined in JSON classification..."
    $AppRoleByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $ResourceAppsClassificationFilePath | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions
    $AppRoleClassificationsByJSON = @()
    $AppRoleClassificationsByJSON += foreach ($AppRoleAssignment in $AppRoleAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId, RoleDefinitionName) {
        # Check if role action and scope exists in JSON definition
        $AppRoleInJsonDefinition = @()
        $AppRoleInJsonDefinition = foreach ($RoleDefinitionName in $AppRoleAssignment.RoleDefinitionName) {
            $AppRoleByClassificationJSON | Where-Object { ($_.RoleDefinitionActions -eq $RoleDefinitionName -or $RoleDefinitionName -like $_.RoleDefinitionActions) -and $_.ExcludedRoleDefinitionActions -ne $RoleDefinitionName }
        }

        $Classification = @()
        if (($AppRoleInJsonDefinition.Count -gt 0)) {
            $ClassifiedAppRole = @()
            $ClassifiedAppRole += $AppRoleInJsonDefinition | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service | Sort-Object EAMTierLevelTagValue, EAMTierLevelName, Service
            $Classification += $ClassifiedAppRole | ForEach-Object {
                [PSCustomObject]@{
                    'AdminTierLevel'     = $_.EAMTierLevelTagValue
                    'AdminTierLevelName' = $_.EAMTierLevelName
                    'Service'            = $_.Service
                    'TaggedBy'           = "JSONwithAction"
                }
            }
        } else {
            $Classification += [PSCustomObject]@{
                'AdminTierLevel'     = "Unclassified"
                'AdminTierLevelName' = "Unclassified"
                'Service'            = "Unclassified"
                'TaggedBy'           = "JSONwithAction"
            }
        }

        [PSCustomObject]@{
            'RoleDefinitionId'      = $AppRoleAssignment.RoleDefinitionId
            'RoleAssignmentScopeId' = $AppRoleAssignment.RoleAssignmentScopeId
            'Classification'        = $Classification
        }
    }
    $AppRoleClassificationsByJSON = $AppRoleClassificationsByJSON | sort-object -property @{e = { $_.Classification.AdminTierLevel } }
    #endregion

    #region Classify App Role Assignments for Service Principals
    $AppRoleClassifications = foreach ($AppRoleAssignment in $AppRoleAssignments) {
        $AppRoleAssignment = $AppRoleAssignment | Select-Object -ExcludeProperty Classification
        $Classification = @()
        $ClassificationCollection = ($AppRoleClassificationsByJSON | Where-Object { $_.RoleAssignmentScopeId -eq $AppRoleAssignment.RoleAssignmentScopeId -and $_.RoleDefinitionId -eq $AppRoleAssignment.RoleDefinitionId })
        if ($ClassificationCollection.Classification.Count -gt 0) {
            $Classification += $ClassificationCollection.Classification | Sort-Object AdminTierLevel, AdminTierLevelName, Service | select-object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy
        }
        $AppRoleAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $AppRoleAssignment
    }
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
            Write-Warning "Skipping Agent Identity Blueprint Principal: $($AgentIdentityBlueprintPrincipal.displayName) ($($AgentIdentityBlueprintPrincipal.id)) as it belongs to multi-tenant app without visibility of inheritable permissions: $($AgentIdentityBlueprintPrincipal.appOwnerOrganizationId)"
            $inheritablePermissionScopes = $null
            continue
        } else {
            $AgentIdentityPermissions = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/applications/microsoft.graph.agentIdentityBlueprint/$($AgentIdentityBlueprintPrincipal.appid)/inheritablePermissions"
            #region Extract inheritable permission scopes
            $inheritablePermissionScopes = foreach ($AgentIdentityResourceAppPermission in $AgentIdentityPermissions) {
                if ($AgentIdentityResourceAppPermission.inheritableScopes.kind -eq "allAllowed") {
                    $InheritableResourceAppPermission = $AgentIdentityBlueprintPrincipalAppRoles | where-object { $_.RoleAssignmentScopeId -eq $RoleAssignmentScopeId -and $_.RoleType -eq "Delegated" }
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "RoleAssignmentType" -NotePropertyValue "Inheritable" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "RoleAssignmentSubType" -NotePropertyValue "AllAllowed" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByObjectDisplayName" -NotePropertyValue "$($AgentIdentityBlueprintPrincipal.displayName)" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByObjectId" -NotePropertyValue "$($AgentIdentityBlueprintPrincipal.id)" -Force                        
                    $InheritableResourceAppPermission
                } elseif ($AgentIdentityResourceAppPermission.inheritableScopes.kind -eq "enumerated") {
                    $RoleAssignmentScopeId = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '$($AgentIdentityResourceAppPermission.resourceAppId)'" | select-object -ExpandProperty id
                    $RoleDefinitionNames = $AgentIdentityResourceAppPermission.inheritableScopes.scopes 
                    $InheritableResourceAppPermission = $AgentIdentityBlueprintPrincipalAppRoles | Where-Object { $_.RoleAssignmentScopeId -eq $RoleAssignmentScopeId -and $_.RoleDefinitionName -in $RoleDefinitionNames }
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "RoleAssignmentType" -NotePropertyValue "Inheritable" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "RoleAssignmentSubType" -NotePropertyValue "Enumerated" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByObjectDisplayName" -NotePropertyValue "$($AgentIdentityBlueprintPrincipal.displayName)" -Force
                    $InheritableResourceAppPermission | Add-Member -NotePropertyName "TransitiveByObjectId" -NotePropertyValue "$($AgentIdentityBlueprintPrincipal.id)" -Force                    
                    $InheritableResourceAppPermission
                } elseif ($null -eq $AgentIdentityResourceAppPermission.inheritableScopes.kind) {
                    Write-Verbose "No inheritable scopes defined for Agent Identity $($AgentIdentityBlueprintPrincipal.displayName) Resource App Permission: $($AgentIdentityResourceAppPermission.id)"
                } else {
                    Write-Warning "Unknown inheritableScopes.kind: $($AgentIdentityResourceAppPermission.inheritableScopes.kind)"
                }
            }
            #endregion

            if ( $inheritablePermissionScopes.Count -eq 0 -or $null -eq $inheritablePermissionScopes ) {
                Write-Host "No inheritable permission scopes found for Agent Identity Blueprint Principal: $($AgentIdentityBlueprintPrincipal.displayName) ($($AgentIdentityBlueprintPrincipal.id))"
                continue
            } else {
                $ChildAgentIdentities = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$filter=(isof('microsoft.graph.agentIdentity')%20OR%20(tags%2Fany(p%3Astartswith(p%2C%20'power-virtual-agents-'))%20OR%20tags%2Fany(p%3Ap%20eq%20'AgenticInstance')))%20AND%20createdByAppId%20eq%20'$($AgentIdentityBlueprintPrincipal.appId)'"
                foreach ( $ChildAgentIdentity in $ChildAgentIdentities ) {
                    $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ChildAgentIdentity.Id

                    # Classification
                    $Classification = @()
                    $Classification += $inheritablePermissionScopes.Classification | Sort-Object AdminTierLevel, AdminTierLevelName, Service
                    if ($Classification.Count -eq 0) {
                        $Classification += [PSCustomObject]@{
                            'AdminTierLevel'     = "Unclassified"
                            'AdminTierLevelName' = "Unclassified"
                            'Service'            = "Unclassified"
                        }
                    }
                    $Classification = $Classification | Select-Object -Unique AdminTierLevel, AdminTierLevelName, Service

                    [PSCustomObject]@{
                        'ObjectId'                      = $ChildAgentIdentity.id
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
                        'RoleAssignments'               = $inheritablePermissionScopes
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
    $UniqueObjects = $AppRoleAssignments | Select-Object -Unique ObjectId, ObjectType | Where-Object { $null -ne $_.ObjectId }
    $UniqueObjectIds = @($UniqueObjects.ObjectId)
    
    Write-Host "Resolving details for $($UniqueObjectIds.Count) unique objects..."
    $ObjectDetailsCache = @{}
    
    # Batch resolution with progress reporting
    for ($i = 0; $i -lt $UniqueObjectIds.Count; $i++) {
        $ObjectId = $UniqueObjectIds[$i]
        
        # Update progress more frequently for better UX (every 10 items or 5%, whichever is less frequent)
        $ProgressInterval = [Math]::Max(10, [Math]::Floor($UniqueObjectIds.Count / 20))
        if (($i % $ProgressInterval) -eq 0 -or $i -eq ($UniqueObjectIds.Count - 1)) {
            $PercentComplete = [math]::Round(($i / $UniqueObjectIds.Count) * 100, 0)
            Write-Progress -Activity "Resolving Object Details" -Status "Processing object $($i + 1) of $($UniqueObjectIds.Count)" -PercentComplete $PercentComplete
            if ($VerbosePreference -ne 'SilentlyContinue') {
                Write-Verbose "Processing object $($i + 1) of $($UniqueObjectIds.Count)..."
            }
        }
        
        try {
            $ObjectDetailsCache[$ObjectId] = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $TenantId
        } catch {
            Write-Warning "Failed to get details for object $($ObjectId): $_"
            $ObjectDetailsCache[$ObjectId] = $null
        }
    }
    Write-Progress -Activity "Resolving Object Details" -Completed

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
                Write-Warning "Skipping object $ObjectId - failed to retrieve details"
                return
            }

            # Role Assignments
            $AppRoleAssignments = @()

            if ($ObjectId -in $AppRoleClassifiedAgentIdObjects.ObjectId) {
                # Merge classifications and role assignments if service principal has inheritable permissions by agent blueprint and assigned app roles
                $AppRoleAssignments += $AppRoleClassifications | Where-Object { $_.ObjectId -eq "$ObjectId" } | select-object -Unique *
                $AppRoleAssignments += $AppRoleClassifiedAgentIdObjects | Where-Object { $_.ObjectId -eq "$ObjectId" } | select-object -ExpandProperty RoleAssignments
            } else {
                $AppRoleAssignments += $AppRoleClassifications | Where-Object { $_.ObjectId -eq "$ObjectId" } | select-object -Unique *
            }

            # Classification - use hashtable for unique aggregation
            $UniqueClassificationsHash = @{}
            foreach ($Assignment in $AppRoleAssignments) {
                if ($null -ne $Assignment.Classification) {
                    foreach ($ClassItem in $Assignment.Classification) {
                        $key = "$($ClassItem.AdminTierLevel)|$($ClassItem.AdminTierLevelName)|$($ClassItem.Service)"
                        if (-not $UniqueClassificationsHash.ContainsKey($key)) {
                            $UniqueClassificationsHash[$key] = $ClassItem
                        }
                    }
                }
            }
            
            $Classification = @($UniqueClassificationsHash.Values | Select-Object -Unique -ExcludeProperty TaggedBy | Sort-Object AdminTierLevel, AdminTierLevelName, Service)

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
                'RoleAssignments'               = $AppRoleAssignments
                'Sponsors'                      = $ObjectDetails.Sponsors
                'Owners'                        = $ObjectDetails.Owners
                'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
            }
        }
    }
    #endregion

    #region Add agent identities to classified objects if not already present and correct role assignment ObjectIds
    $AppRoleClassifiedAgentIdObjects = $AppRoleClassifiedAgentIdObjectsByParentId | where-object { $_.ObjectId -notin $AppRoleClassifiedSpObjects.ObjectId }
    $AppRoleClassifiedObjects = $AppRoleClassifiedSpObjects + $AppRoleClassifiedAgentIdObjects

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
    $AppRoleClassifiedObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName

}

