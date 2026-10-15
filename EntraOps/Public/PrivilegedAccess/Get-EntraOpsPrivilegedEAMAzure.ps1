<#
.SYNOPSIS
    Get a list in EntraOps EAM schema of all privileged principals with Azure RBAC role assignments and their classifications.

.DESCRIPTION
    Collects Azure RBAC role assignments via Get-EntraOpsPrivilegedAzureRoles, fetches role definition
    actions from the Azure Resource Graph, then classifies each unique (RoleDefinitionId, RoleAssignmentScopeId)
    pair against Classification_Azure.json.

    Scope matching uses PowerShell -like wildcard patterns (e.g. "/*" matches any ARM path).
    Action matching uses bidirectional wildcard matching so that a role with actions ["*"] correctly
    matches specific classification actions, and classification patterns like
    "Microsoft.Authorization/*/write" correctly match a role action
    "Microsoft.Authorization/roleAssignments/write".  notActions exclusion is applied so that
    Contributor (actions=["*"], notActions=["Microsoft.Authorization/*/Write",...]) is not
    classified as having authorization write permissions.

    Run Update-EntraOpsClassificationControlPlaneScope with -ClassificationParameterScope including
    "Azure" before calling this function to get tenant-specific Tier0/Tier1 scope parameterization.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current Az context tenant.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is $DefaultFolderClassification.

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False.

.PARAMETER GlobalExclusion
    Apply the global exclusion list. Default is $true.

.PARAMETER EnableParallelProcessing
    Enable parallel processing for object resolution. Default is $true.

.PARAMETER ParallelThrottleLimit
    Maximum number of parallel threads. Default is 10.

.PARAMETER ControlPlaneScopeOnly
    Restrict the Azure RBAC role assignment scan to only the Control Plane ARM hierarchies defined as
    RoleAssignmentScopeName under the ControlPlane (EAMTierLevelTagValue "0") tier in Classification_Azure.json.
    The tenant-specific Classification/<TenantName>/Classification_Azure.json is used when it exists, otherwise
    the template is used. Wildcard entries ("/" and "/*") are ignored so only concrete management group,
    subscription, resource group or resource hierarchies limit the scan. Run
    Update-EntraOpsClassificationControlPlaneScope with -ClassificationParameterScope including "Azure" first
    to populate tenant-specific Tier0 scopes. Default is $false.

.PARAMETER IncludeJustification
    Include the Justification property (documenting a manual classification overwrite) on all Classification
    entries of the returned objects. Default is $false, so the property is not present in the output at all.

.PARAMETER UnresolvedRoleDefinitionFallbackTier
    Tier assigned to role assignments whose role definition could not be resolved from Azure Resource Graph
    (e.g. ARG replication lag for a new custom role, deleted role definition or a transient ARG failure).
    The fallback classification is marked with TaggedBy "FallbackUnresolvedRoleDefinition" and a warning is
    added to the summary for each affected (RoleDefinitionId, Scope) pair. Allowed values: "Unclassified"
    (default, consistent with the Unclassified fallback of the other RBAC systems), "ManagementPlane" or
    "ControlPlane" (stricter fail-closed tiers with Service "Unresolved Role Definition") or "None"
    (skip classification, previous behavior). Can be set via
    AzureRbacClassification.UnresolvedRoleDefinitionFallbackTier in EntraOpsConfig.json.

.PARAMETER DeletedPrincipalAssignmentHandling
    Controls Azure RBAC role assignments whose principal is confirmed deleted. "Filter" (default)
    removes those assignments from EAM output. "Keep" preserves the fail-closed unresolved object
    only after both the Microsoft Graph directory-object and user lookups return HTTP 404. Permission,
    throttling, network and other resolution failures remain visible. Can be set via
    AzureRbacClassification.DeletedPrincipalAssignmentHandling in EntraOpsConfig.json.

.PARAMETER IncludeObjectDetails
    Include descriptive object details in warning output. Defaults to ConsoleOutput.IncludeObjectDetails from
    EntraOpsConfig.json. Object IDs are always shown.

.EXAMPLE
    Get-EntraOpsPrivilegedEAMAzure -TenantId "00000000-0000-0000-0000-000000000000"

.EXAMPLE
    Scan only Control Plane hierarchies defined in Classification_Azure.json instead of the whole tenant.
    Get-EntraOpsPrivilegedEAMAzure -ControlPlaneScopeOnly $true
#>

function Get-EntraOpsPrivilegedEAMAzure {
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
        [System.Boolean]$ControlPlaneScopeOnly = $false
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$ClassifyConstrainedDelegationAlwaysAsControlPlane = $(if ($null -ne $EntraOpsConfig.AzureRbacClassification.ClassifyConstrainedDelegationAlwaysAsControlPlane) { [System.Convert]::ToBoolean($EntraOpsConfig.AzureRbacClassification.ClassifyConstrainedDelegationAlwaysAsControlPlane) } else { $false })
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Unclassified', 'ManagementPlane', 'ControlPlane', 'None')]
        [System.String]$UnresolvedRoleDefinitionFallbackTier = $(if (-not [string]::IsNullOrEmpty($EntraOpsConfig.AzureRbacClassification.UnresolvedRoleDefinitionFallbackTier)) { $EntraOpsConfig.AzureRbacClassification.UnresolvedRoleDefinitionFallbackTier } else { 'Unclassified' })
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Keep', 'Filter')]
        [System.String]$DeletedPrincipalAssignmentHandling = $(if (-not [string]::IsNullOrEmpty($EntraOpsConfig.AzureRbacClassification.DeletedPrincipalAssignmentHandling)) { $EntraOpsConfig.AzureRbacClassification.DeletedPrincipalAssignmentHandling } else { 'Filter' })
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
    )

    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"
    $Stage1Start = Get-Date

    #region Stage 1: Fetch Azure RBAC Role Assignments
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 1/4: Fetching Azure RBAC Role Assignments" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Retrieving Azure RBAC role assignments across tenant scope..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 1/4: Fetching Azure RBAC Roles" -Status "Loading role assignments and global exclusions..." -PercentComplete 10

    # Optionally restrict the Azure RBAC scan to Control Plane hierarchies defined in the classification file
    $ControlPlaneScopeFilterPatterns = @()
    if ($ControlPlaneScopeOnly -eq $true) {
        $AzureClassificationFilterPath = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_Azure.json" -FolderClassification $FolderClassification
        if ($null -eq $AzureClassificationFilterPath) {
            $WarningMessages.Add([PSCustomObject]@{ Type = "Stage1"; Message = "ControlPlaneScopeOnly enabled but Classification_Azure.json could not be resolved; scanning full tenant scope." })
        } else {
            try {
                $AzureClassificationForFilter = Get-Content -Path $AzureClassificationFilterPath -Raw | ConvertFrom-Json -Depth 10
                $ControlPlaneTier = $AzureClassificationForFilter | Where-Object { "$($_.EAMTierLevelTagValue)" -eq "0" }
                $ControlPlaneScopeFilterPatterns = @($ControlPlaneTier.TierLevelDefinition.RoleAssignmentScopeName |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne "/" -and $_ -ne "/*" } |
                    Select-Object -Unique)
                Write-Host "Control Plane scope filter: $($ControlPlaneScopeFilterPatterns.Count) hierarchy scope(s) from $([System.IO.Path]::GetFileName($AzureClassificationFilterPath))." -ForegroundColor Gray
                if ($ControlPlaneScopeFilterPatterns.Count -eq 0) {
                    $WarningMessages.Add([PSCustomObject]@{ Type = "Stage1"; Message = "ControlPlaneScopeOnly enabled but no specific Control Plane RoleAssignmentScopeName hierarchies found (only '/' or '/*'); scanning full tenant scope." })
                }
            } catch {
                $WarningMessages.Add([PSCustomObject]@{ Type = "Stage1"; Message = "Failed to load Control Plane scope filter from classification file: $($_.Exception.Message); scanning full tenant scope." })
            }
        }
    }

    if ($SampleMode -ne $True) {
        $AzureRbacAssignments = Get-EntraOpsPrivilegedAzureRoles -TenantId $TenantId -ControlPlaneScopeFilter $ControlPlaneScopeFilterPatterns -WarningMessages $WarningMessages
    } else {
        $WarningMessages.Add([PSCustomObject]@{ Type = "Stage1"; Message = "SampleMode is not supported for Azure RBAC." })
        $AzureRbacAssignments = @()
    }

    #region Resolve ForeignGroup principals (cross-tenant Azure RBAC) via remoteTenantGroups
    # Azure RBAC assignments to a group from another tenant are returned with principalType 'ForeignGroup'
    # (ObjectType 'foreigngroup'). These have no directory object in the home tenant, so resolve them via
    # remoteTenantGroups to obtain the real remote group id, display name and owning tenant. The matching
    # assignments are re-keyed to the remote group identity so the rest of the pipeline (object resolution,
    # classification grouping) treats them as ordinary groups. When the remote tenant matches the configured
    # managing tenant, full details are resolved later in Stage 4b via Invoke-EntraOpsCrossTenantObjectResolution.
    $ForeignGroupDetailsCache = @{}
    $ForeignGroupAssignments = @($AzureRbacAssignments | Where-Object { "$($_.ObjectType)" -ieq 'foreigngroup' })
    if ($ForeignGroupAssignments.Count -gt 0) {
        Write-Host "Resolving $($ForeignGroupAssignments.Count) ForeignGroup role assignment(s) via remoteTenantGroups..." -ForegroundColor Gray
        $ForeignGroupResolution = @{}
        foreach ($StubObjectId in @($ForeignGroupAssignments.ObjectId | Select-Object -Unique)) {
            $ResolvedForeignGroup = Get-EntraOpsPrivilegedEntraObject -AadObjectId $StubObjectId -TenantId $TenantId
            if ($null -ne $ResolvedForeignGroup -and "$($ResolvedForeignGroup.ObjectType)" -ieq 'group' -and -not [string]::IsNullOrEmpty($ResolvedForeignGroup.ObjectId)) {
                $ForeignGroupResolution[$StubObjectId] = $ResolvedForeignGroup
                $ForeignGroupDetailsCache[$ResolvedForeignGroup.ObjectId] = $ResolvedForeignGroup
            } else {
                $WarningMessages.Add([PSCustomObject]@{ Type = "Stage1-ForeignGroup"; Message = "ForeignGroup $StubObjectId could not be resolved via remoteTenantGroups." })
            }
        }
        foreach ($ForeignGroupAssignment in $ForeignGroupAssignments) {
            $ResolvedForeignGroup = $ForeignGroupResolution[$ForeignGroupAssignment.ObjectId]
            if ($null -ne $ResolvedForeignGroup) {
                $ForeignGroupAssignment.ObjectId = $ResolvedForeignGroup.ObjectId
                $ForeignGroupAssignment.ObjectTenantId = $ResolvedForeignGroup.ObjectTenantId
                $ForeignGroupAssignment.ObjectType = 'group'
            }
        }
    }
    #endregion

    $GlobalExclusionList = Import-EntraOpsGlobalExclusions -Enabled $GlobalExclusion

    $Stage1Duration = ((Get-Date) - $Stage1Start).TotalSeconds
    Write-Host "✓ Stage 1 completed in $([Math]::Round($Stage1Duration, 2)) seconds ($(@($AzureRbacAssignments).Count) role assignments retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 1/4: Fetching Azure RBAC Roles" -Completed
    #endregion

    if ($null -eq $AzureRbacAssignments -or @($AzureRbacAssignments).Count -eq 0) {
        Write-Warning "No Azure RBAC role assignments found. Returning empty result."
        return @()
    }

    #region Stage 2: Load Classification File and Classify by Role Definition and Scope
    $Stage2Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 2/4: Loading Classification Rules and Classifying Roles" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Loading Azure RBAC classification file and matching role definitions..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 2/4: Loading Classification Rules" -Status "Reading classification file..." -PercentComplete 25

    $AzureClassificationFilePath = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_Azure.json" -FolderClassification $FolderClassification
    if ($null -eq $AzureClassificationFilePath) {
        Write-Error "Could not resolve Classification_Azure.json. Run Update-EntraOpsClassificationFiles first."
        return @()
    }
    $AzureResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $AzureClassificationFilePath |
    Select-Object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, ActionType, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions

    # Fetch role definitions from Azure Resource Graph for all referenced role definition GUIDs.
    # Results are deduped by name (GUID) since the same built-in role can appear at multiple scopes.
    $RoleDefinitionCache = @{}
    $UniqueRoleDefIds = @($AzureRbacAssignments | ForEach-Object { $_.RoleDefinitionId } | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)

    if ($SampleMode -ne $True -and $UniqueRoleDefIds.Count -gt 0) {
        Write-Host "Fetching $($UniqueRoleDefIds.Count) unique role definition(s) from Azure Resource Graph..." -ForegroundColor Gray

        # Batch ARG queries in groups of 100 to stay within query length limits
        $ArgBatchSize = 100
        for ($BatchStart = 0; $BatchStart -lt $UniqueRoleDefIds.Count; $BatchStart += $ArgBatchSize) {
            $BatchEnd = [Math]::Min($BatchStart + $ArgBatchSize - 1, $UniqueRoleDefIds.Count - 1)
            $BatchIds = @($UniqueRoleDefIds[$BatchStart..$BatchEnd])
            $RoleDefIdFilter = ($BatchIds | ForEach-Object { "'$_'" }) -join ', '
            $RoleDefKql = "authorizationresources | where type =~ 'microsoft.authorization/roledefinitions' | where name in ($RoleDefIdFilter) | project name, properties"
            try {
                # -ThrowOnFailure makes the catch below reachable. Without it the helper reports failure
                # with a non-terminating error and returns whatever it collected, so a throttled batch
                # silently left role definitions unresolved and no warning was recorded.
                $BatchResults = @(Invoke-EntraOpsAzGraphQuery -KqlQuery $RoleDefKql -ThrowOnFailure)
                foreach ($RoleDef in $BatchResults) {
                    if (-not [string]::IsNullOrEmpty($RoleDef.name) -and -not $RoleDefinitionCache.ContainsKey($RoleDef.name)) {
                        $RoleDefinitionCache[$RoleDef.name] = $RoleDef
                    }
                }
            } catch {
                $WarningMessage = "Failed to fetch role definitions batch (start=$BatchStart): $($_.Exception.Message)"
                $WarningMessages.Add([PSCustomObject]@{ Type = "Stage2"; Message = $WarningMessage })
                Write-Warning $WarningMessage
            }
        }
        Write-Host "Resolved $($RoleDefinitionCache.Count) of $($UniqueRoleDefIds.Count) role definition(s) from Azure Resource Graph." -ForegroundColor Gray

        # Guardrail: a high unresolved ratio points to an ARG outage rather than individual stale role
        # definitions, so fallback classifications from this run should not be trusted blindly.
        $UnresolvedRoleDefIds = @($UniqueRoleDefIds | Where-Object { -not $RoleDefinitionCache.ContainsKey($_) })
        if ($UnresolvedRoleDefIds.Count -gt 0 -and ($UnresolvedRoleDefIds.Count / $UniqueRoleDefIds.Count) -gt 0.2) {
            $WarningMessages.Add([PSCustomObject]@{
                    Type    = "Stage2"
                    Message = "$($UnresolvedRoleDefIds.Count) of $($UniqueRoleDefIds.Count) role definitions could not be resolved from Azure Resource Graph. A transient ARG outage is suspected; fallback classifications of this run may be unreliable."
                })
        }
    }

    # Resolve tier tag and service of the configured unresolved-role-definition fallback.
    # "Unclassified" mirrors the assignment-level Unclassified fallback used by the other RBAC systems.
    $FallbackTierTagValue = $null
    $FallbackServiceName = $null
    if ($UnresolvedRoleDefinitionFallbackTier -eq 'Unclassified') {
        $FallbackTierTagValue = 'Unclassified'
        $FallbackServiceName = 'Unclassified'
    } elseif ($UnresolvedRoleDefinitionFallbackTier -ne 'None') {
        $FallbackTierTagValue = @($AzureResourcesByClassificationJSON | Where-Object { $_.EAMTierLevelName -eq $UnresolvedRoleDefinitionFallbackTier })[0].EAMTierLevelTagValue
        if ([string]::IsNullOrEmpty("$FallbackTierTagValue")) {
            $FallbackTierTagValue = if ($UnresolvedRoleDefinitionFallbackTier -eq 'ControlPlane') { '0' } else { '1' }
        }
        $FallbackServiceName = 'Unresolved Role Definition'
    }

    # Classify each unique (RoleDefinitionId, RoleAssignmentScopeId) combination.
    # For each matching scope+action pair the result is one classification entry with all matched actions.
    $AzureRbacClassificationsByJSON = @()
    # Select-Object -Unique compares case-SENSITIVELY, and ARM does not guarantee consistent casing of
    # role definition GUIDs or scope ids across endpoints, so the same logical pair could survive dedup
    # twice and be classified twice. Group on a lowercased key and keep the first member of each group.
    $UniqueAssignmentPairs = @(
        $AzureRbacAssignments |
            Group-Object -Property { "$($_.RoleDefinitionId)".ToLowerInvariant() + '|' + "$($_.RoleAssignmentScopeId)".ToLowerInvariant() } |
            ForEach-Object { $_.Group[0] | Select-Object RoleDefinitionId, RoleAssignmentScopeId }
    )
    $PairsProcessed = 0
    $PairsTotal = $UniqueAssignmentPairs.Count

    $AzureRbacClassificationsByJSON += foreach ($AzureRbacAssignment in $UniqueAssignmentPairs) {
        $PairsProcessed++
        if ($PairsProcessed % 20 -eq 0 -or $PairsProcessed -eq $PairsTotal) {
            Write-Progress -Activity "Stage 2/4: Loading Classification Rules" -Status "Classifying assignment $PairsProcessed of $PairsTotal" -PercentComplete (25 + ($PairsProcessed / [Math]::Max($PairsTotal, 1) * 25))
        }

        $RoleAssignmentScopeId = $AzureRbacAssignment.RoleAssignmentScopeId
        $RoleDefinitionId = $AzureRbacAssignment.RoleDefinitionId

        $RoleDef = $RoleDefinitionCache[$RoleDefinitionId]
        if ($null -eq $RoleDef) {
            if ($UnresolvedRoleDefinitionFallbackTier -eq 'None') {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "Stage2"
                        Message = "Role definition '$RoleDefinitionId' was not found in Azure Resource Graph; classification skipped for scope '$RoleAssignmentScopeId'."
                    })
                continue
            }
            # Emit a self-identifying fallback classification so the assignment stays visible instead of
            # silently losing classification when the role definition cannot be resolved.
            $WarningMessages.Add([PSCustomObject]@{
                    Type    = "Stage2-UnresolvedFallback"
                    Message = "Role definition '$RoleDefinitionId' was not found in Azure Resource Graph; assignment at scope '$RoleAssignmentScopeId' classified with $UnresolvedRoleDefinitionFallbackTier fallback."
                })
            [PSCustomObject]@{
                'RoleDefinitionId'      = $RoleDefinitionId
                'RoleAssignmentScopeId' = $RoleAssignmentScopeId
                'Classification'        = @([PSCustomObject]@{
                        'AdminTierLevel'             = "$FallbackTierTagValue"
                        'AdminTierLevelName'         = $UnresolvedRoleDefinitionFallbackTier
                        'Service'                    = $FallbackServiceName
                        'MatchedActions'             = $null
                        'ScopedObjects'              = $null
                        'TaggedBy'                   = "FallbackUnresolvedRoleDefinition"
                        'TaggedByObjectIds'          = $null
                        'TaggedByObjectDisplayNames' = $null
                        'TaggedByRoleSystem'         = "Azure"
                    })
            }
            continue
        }

        # --- Scope matching ---
        # Find classification entries whose RoleAssignmentScopeName pattern matches the assignment scope.
        $MatchedClassificationByScope = @()
        $MatchedClassificationByScope += foreach ($ClassEntry in $AzureResourcesByClassificationJSON) {
            if (-not ($RoleAssignmentScopeId -like $ClassEntry.RoleAssignmentScopeName)) { continue }

            # Check scope exclusions (one-directional: assignment scope -like exclusion pattern)
            $IsExcluded = $false
            foreach ($ExcludedScope in @($ClassEntry.ExcludedRoleAssignmentScopeName)) {
                if (-not [string]::IsNullOrEmpty($ExcludedScope) -and ($RoleAssignmentScopeId -like $ExcludedScope)) {
                    $IsExcluded = $true
                    break
                }
            }
            if (-not $IsExcluded) { $ClassEntry }
        }

        if ($MatchedClassificationByScope.Count -eq 0) { continue }

        # --- Action matching ---
        # Bidirectional wildcard: ($roleAction -like $classAction) handles specific role actions matching
        # a wildcard classification pattern (e.g. "Microsoft.Authorization/roleAssignments/write" -like
        # "Microsoft.Authorization/*/write"). ($classAction -like $roleAction) handles a broad role action
        # (e.g. "*") matching any specific classification action.
        # notActions exclusion: if the classification action is covered by a notAction, skip it
        # (e.g. Contributor's notActions prevent it from matching authorization write patterns).
        $ClassifiedWithMatchedActions = @()
        foreach ($ClassEntry in $MatchedClassificationByScope) {
            $IsDataActionRule = "$($ClassEntry.ActionType)" -ieq 'DataAction'
            foreach ($ClassAction in @($ClassEntry.RoleDefinitionActions)) {
                if ([string]::IsNullOrEmpty($ClassAction)) { continue }

                $ActionMatched = $false
                foreach ($Permission in @($RoleDef.properties.permissions)) {
                    if ($ActionMatched) { break }

                    if (-not $IsDataActionRule) {
                        # Management/control plane Actions must not match data-plane rules.
                        foreach ($RoleAction in @($Permission.actions)) {
                            if ([string]::IsNullOrEmpty($RoleAction)) { continue }
                            # Azure documents */read as control-plane metadata access. It must not
                            # satisfy an explicit telemetry or other sensitive-read classification.
                            if ($RoleAction -eq '*/read' -and $ClassAction -ne '*/read') { continue }
                            if ($RoleAction -like $ClassAction -or $ClassAction -like $RoleAction) {
                                $IsExcludedByClassification = @($ClassEntry.ExcludedRoleDefinitionActions | Where-Object {
                                        -not [string]::IsNullOrEmpty($_) -and $RoleAction -like $_
                                    }).Count -gt 0
                                if ($IsExcludedByClassification) { continue }
                                # Verify the classification action is not excluded by a notAction
                                $IsNotActioned = $false
                                foreach ($NotAction in @($Permission.notActions)) {
                                    if (-not [string]::IsNullOrEmpty($NotAction) -and ($ClassAction -like $NotAction)) {
                                        $IsNotActioned = $true
                                        break
                                    }
                                }
                                if (-not $IsNotActioned) {
                                    $ActionMatched = $true
                                    break
                                }
                            }
                        }
                    }

                    if ($ActionMatched) { break }

                    if ($IsDataActionRule) {
                        # DataActions grant access to resource data and must not match Actions rules.
                        foreach ($DataAction in @($Permission.dataActions)) {
                            if ([string]::IsNullOrEmpty($DataAction)) { continue }
                            if ($DataAction -like $ClassAction -or $ClassAction -like $DataAction) {
                                $IsExcludedByClassification = @($ClassEntry.ExcludedRoleDefinitionActions | Where-Object {
                                        -not [string]::IsNullOrEmpty($_) -and $DataAction -like $_
                                    }).Count -gt 0
                                if ($IsExcludedByClassification) { continue }
                                $IsNotDataActioned = $false
                                foreach ($NotDataAction in @($Permission.notDataActions)) {
                                    if (-not [string]::IsNullOrEmpty($NotDataAction) -and ($ClassAction -like $NotDataAction)) {
                                        $IsNotDataActioned = $true
                                        break
                                    }
                                }
                                if (-not $IsNotDataActioned) {
                                    $ActionMatched = $true
                                    break
                                }
                            }
                        }
                    }
                }

                if ($ActionMatched) {
                    $ClassifiedWithMatchedActions += [PSCustomObject]@{
                        EAMTierLevelName     = $ClassEntry.EAMTierLevelName
                        EAMTierLevelTagValue = $ClassEntry.EAMTierLevelTagValue
                        Service              = $ClassEntry.Service
                        MatchedAction        = $ClassAction
                    }
                }
            }
        }

        if ($ClassifiedWithMatchedActions.Count -gt 0) {
            $UniqueClassifications = $ClassifiedWithMatchedActions | Select-Object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service

            $Classification = foreach ($UniqueClass in $UniqueClassifications) {
                [array]$MatchedActions = @($ClassifiedWithMatchedActions | Where-Object {
                        $_.EAMTierLevelName -eq $UniqueClass.EAMTierLevelName -and
                        $_.EAMTierLevelTagValue -eq $UniqueClass.EAMTierLevelTagValue -and
                        $_.Service -eq $UniqueClass.Service
                    } | ForEach-Object { $_.MatchedAction } | Select-Object -Unique)

                [PSCustomObject]@{
                    'AdminTierLevel'             = $UniqueClass.EAMTierLevelTagValue
                    'AdminTierLevelName'         = $UniqueClass.EAMTierLevelName
                    'Service'                    = $UniqueClass.Service
                    'MatchedActions'             = if ($MatchedActions.Count -gt 0) { , @($MatchedActions) } else { $null }
                    'ScopedObjects'              = $null
                    'TaggedBy'                   = "JSONwithAction"
                    'TaggedByObjectIds'          = $null
                    'TaggedByObjectDisplayNames' = $null
                    'TaggedByRoleSystem'         = "Azure"
                }
            }

            [PSCustomObject]@{
                'RoleDefinitionId'      = $RoleDefinitionId
                'RoleAssignmentScopeId' = $RoleAssignmentScopeId
                'Classification'        = $Classification
            }
        }
    }

    $Stage2Duration = ((Get-Date) - $Stage2Start).TotalSeconds
    Write-Host "✓ Stage 2 completed in $([Math]::Round($Stage2Duration, 2)) seconds ($($AzureRbacClassificationsByJSON.Count) classified (RoleDefinitionId, Scope) pairs)" -ForegroundColor Green
    Write-Progress -Activity "Stage 2/4: Loading Classification Rules" -Completed
    #endregion

    #region Stage 2b: Resolve role definitions referenced by constrained-delegation conditions
    # Build a tier tag -> tier name lookup (ordered ascending; 0 = most privileged) used to downgrade
    # condition-based (ABAC) constrained-delegation Authorization classifications.
    $TierNameByTag = @{}
    foreach ($ClassEntry in $AzureResourcesByClassificationJSON) {
        if ($null -ne $ClassEntry.EAMTierLevelTagValue -and -not $TierNameByTag.ContainsKey("$($ClassEntry.EAMTierLevelTagValue)")) {
            $TierNameByTag["$($ClassEntry.EAMTierLevelTagValue)"] = $ClassEntry.EAMTierLevelName
        }
    }

    # Collect RoleDefinitionId GUIDs referenced inside RoleAssignmentCondition (constrained delegation) so we
    # can classify which roles the delegate may/may not grant. Fetch any that are not already cached.
    $ConditionRoleDefGuidPattern = "RoleDefinitionId\]\s*\w+:Guid(?:Not)?Equals\s*\{([^}]*)\}"
    $ReferencedRoleDefIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($AzureRbacAssignment in $AzureRbacAssignments) {
        if ([string]::IsNullOrEmpty($AzureRbacAssignment.RoleAssignmentCondition)) { continue }
        foreach ($Match in [regex]::Matches($AzureRbacAssignment.RoleAssignmentCondition, $ConditionRoleDefGuidPattern)) {
            foreach ($Guid in ($Match.Groups[1].Value -split ',')) {
                $TrimmedGuid = $Guid.Trim()
                if (-not [string]::IsNullOrEmpty($TrimmedGuid)) { [void]$ReferencedRoleDefIds.Add($TrimmedGuid) }
            }
        }
    }

    # Built-in constrained-delegation roles (e.g. Key Vault Data Access Administrator) carry their ABAC
    # condition on the role definition's permissions instead of the assignment. Track those role definitions
    # so Stage 3 also invokes the downgrade helper for them, and cache the roles their conditions reference.
    $RoleDefIdsWithPermissionCondition = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($CachedRoleDefId in @($RoleDefinitionCache.Keys)) {
        foreach ($Permission in @($RoleDefinitionCache[$CachedRoleDefId].properties.permissions)) {
            if ([string]::IsNullOrEmpty($Permission.condition)) { continue }
            [void]$RoleDefIdsWithPermissionCondition.Add($CachedRoleDefId)
            foreach ($Match in [regex]::Matches($Permission.condition, $ConditionRoleDefGuidPattern)) {
                foreach ($Guid in ($Match.Groups[1].Value -split ',')) {
                    $TrimmedGuid = $Guid.Trim()
                    if (-not [string]::IsNullOrEmpty($TrimmedGuid)) { [void]$ReferencedRoleDefIds.Add($TrimmedGuid) }
                }
            }
        }
    }
    $MissingConditionRoleDefIds = @($ReferencedRoleDefIds | Where-Object { -not $RoleDefinitionCache.ContainsKey($_) })
    if ($SampleMode -ne $True -and $MissingConditionRoleDefIds.Count -gt 0) {
        Write-Host "Fetching $($MissingConditionRoleDefIds.Count) role definition(s) referenced by delegation conditions..." -ForegroundColor Gray
        for ($BatchStart = 0; $BatchStart -lt $MissingConditionRoleDefIds.Count; $BatchStart += 100) {
            $BatchEnd = [Math]::Min($BatchStart + 99, $MissingConditionRoleDefIds.Count - 1)
            $BatchIds = @($MissingConditionRoleDefIds[$BatchStart..$BatchEnd])
            $RoleDefIdFilter = ($BatchIds | ForEach-Object { "'$_'" }) -join ', '
            $RoleDefKql = "authorizationresources | where type =~ 'microsoft.authorization/roledefinitions' | where name in ($RoleDefIdFilter) | project name, properties"
            try {
                foreach ($RoleDef in @(Invoke-EntraOpsAzGraphQuery -KqlQuery $RoleDefKql -ThrowOnFailure)) {
                    if (-not [string]::IsNullOrEmpty($RoleDef.name) -and -not $RoleDefinitionCache.ContainsKey($RoleDef.name)) {
                        $RoleDefinitionCache[$RoleDef.name] = $RoleDef
                    }
                }
            } catch {
                $WarningMessages.Add([PSCustomObject]@{ Type = "Stage2b"; Message = "Failed to fetch condition role definitions batch (start=$BatchStart): $($_.Exception.Message)" })
            }
        }
    }
    #endregion

    #region Stage 3: Apply Classifications to All Role Assignments
    $Stage3Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 3/4: Classifying Principals" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Matching principals against classified role assignments..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 3/4: Classifying Principals" -Status "Processing role assignments..." -PercentComplete 50

    $ClassificationsByRoleAndScope = @{}
    foreach ($ClassifiedPair in $AzureRbacClassificationsByJSON) {
        $ClassificationKey = "$($ClassifiedPair.RoleDefinitionId)|$($ClassifiedPair.RoleAssignmentScopeId)"
        if (-not $ClassificationsByRoleAndScope.ContainsKey($ClassificationKey)) {
            $ClassificationsByRoleAndScope[$ClassificationKey] = [System.Collections.Generic.List[object]]::new()
        }
        foreach ($ClassItem in @($ClassifiedPair.Classification)) {
            $ClassificationsByRoleAndScope[$ClassificationKey].Add($ClassItem)
        }
    }

    $AzureRbacClassifications = foreach ($AzureRbacAssignment in $AzureRbacAssignments) {
        $AzureRbacAssignment = $AzureRbacAssignment | Select-Object -ExcludeProperty Classification
        $ClassificationKey = "$($AzureRbacAssignment.RoleDefinitionId)|$($AzureRbacAssignment.RoleAssignmentScopeId)"
        $Classification = @($ClassificationsByRoleAndScope[$ClassificationKey])
        # @() keeps a single classification an array (consistent JSON shape across RBAC systems);
        # no classification stays $null as before.
        $Classification = @($Classification | Select-Object -Unique AdminTierLevel, AdminTierLevelName, MatchedActions, ScopedObjects, Service, TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames, TaggedByRoleSystem |
            Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy)
        if ($Classification.Count -eq 0) { $Classification = $null }
        $AzureRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force

        $AssignedRoleDefinitionForCondition = $RoleDefinitionCache["$($AzureRbacAssignment.RoleDefinitionId)"]
        $RoleDefinitionConditions = if ($null -eq $AssignedRoleDefinitionForCondition) {
            @()
        } else {
            @($AssignedRoleDefinitionForCondition.properties.permissions | Where-Object {
                    -not [string]::IsNullOrEmpty($_.condition)
                } | ForEach-Object {
                    [PSCustomObject]@{
                        Condition        = $_.condition
                        ConditionVersion = $_.conditionVersion
                    }
                })
        }
        $AzureRbacAssignment | Add-Member -NotePropertyName "RoleDefinitionConditions" -NotePropertyValue $RoleDefinitionConditions -Force

        $ConditionConstraints = @(
            @([PSCustomObject]@{
                    Source           = "Assignment"
                    Condition        = $AzureRbacAssignment.RoleAssignmentCondition
                    ConditionVersion = $AzureRbacAssignment.RoleAssignmentConditionVersion
                }) +
            @($RoleDefinitionConditions | ForEach-Object {
                    [PSCustomObject]@{
                        Source           = "RoleDefinition"
                        Condition        = $_.Condition
                        ConditionVersion = $_.ConditionVersion
                    }
                }) |
            Where-Object { -not [string]::IsNullOrEmpty($_.Condition) } |
            ForEach-Object {
                $ConditionSource = $_
                foreach ($Match in [regex]::Matches($_.Condition, "RoleDefinitionId\]\s*\w+:(Guid(?:Not)?Equals)\s*\{([^}]*)\}")) {
                    [PSCustomObject]@{
                        Source            = $ConditionSource.Source
                        Operator          = $Match.Groups[1].Value
                        RoleDefinitionIds = @($Match.Groups[2].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrEmpty($_) })
                    }
                }
            }
        )

        $HasCondition = -not [string]::IsNullOrEmpty($AzureRbacAssignment.RoleAssignmentCondition) -or $RoleDefinitionConditions.Count -gt 0
        $HasControlPlaneAuthorization = @($Classification | Where-Object {
                "$($_.AdminTierLevel)" -eq "0" -and (
                    $_.Service -eq "Authorization" -or
                    (@($_.MatchedActions) | Where-Object {
                        -not [string]::IsNullOrEmpty($_) -and ($_ -like "*roleAssignments/write" -or $_ -like "*roleAssignments/delete")
                    }).Count -gt 0
                )
            }).Count -gt 0
        $ConditionEvaluation = if (-not $HasCondition) {
            $null
        } elseif ($ClassifyConstrainedDelegationAlwaysAsControlPlane) {
            [PSCustomObject]@{
                Status      = "RetainedControlPlaneByConfiguration"
                Summary     = "Conditional delegation evaluation is disabled by configuration; the assignment remains Control Plane."
                Constraints = $ConditionConstraints
            }
        } else {
            [PSCustomObject]@{
                Status      = "Pending"
                Summary     = "The condition was evaluated against delegable role definitions at the assignment scope."
                Constraints = $ConditionConstraints
            }
        }

        # Condition-based (ABAC) constrained delegation: if the role can write role assignments but a
        # condition (on the assignment or on the role definition's permissions) limits which roles it can
        # grant, downgrade the Authorization Control Plane classification based on the roles referenced in
        # the condition (classified against the same scope).
        # When ClassifyConstrainedDelegationAlwaysAsControlPlane is enabled (config flag), this dynamic downgrade is
        # skipped so constrained-delegation authorization assignments always remain classified as Control Plane.
        if (-not $ClassifyConstrainedDelegationAlwaysAsControlPlane -and (
                -not [string]::IsNullOrEmpty($AzureRbacAssignment.RoleAssignmentCondition) -or
                $RoleDefIdsWithPermissionCondition.Contains("$($AzureRbacAssignment.RoleDefinitionId)")
            )) {
            $AzureRbacAssignment.Classification = @(Resolve-EntraOpsAzureConstrainedDelegationTier `
                    -Assignment $AzureRbacAssignment `
                    -ClassificationDefinitions $AzureResourcesByClassificationJSON `
                    -RoleDefinitionCache $RoleDefinitionCache `
                    -TierNameByTag $TierNameByTag)

            $DowngradedEntries = @($AzureRbacAssignment.Classification | Where-Object { $_.TaggedBy -eq "JSONwithConditionInScope" })
            if ($DowngradedEntries.Count -gt 0) {
                $ConditionEvaluation.Status = "DowngradedConstrainedActions"
                $ConditionEvaluation.Summary = "The condition limits role-assignment delegation; constrained actions were classified at $(@($DowngradedEntries.AdminTierLevelName | Select-Object -Unique) -join ', ')."
            } elseif (-not $HasControlPlaneAuthorization) {
                $ConditionEvaluation.Status = "AuthorizationNotClassifiedAtScope"
                $ConditionEvaluation.Summary = "No Control Plane Authorization classification matched this assignment scope, so there was nothing to downgrade. Verify that Classification_Azure.json covers the Authorization service at '$($AzureRbacAssignment.RoleAssignmentScopeId)' - otherwise the role-assignment delegation capability is not represented in this classification."
            } else {
                $ConditionEvaluation.Status = "RetainedControlPlane"
                $ConditionEvaluation.Summary = "The condition did not prove that every Control Plane capability is constrained, so the applicable classification remains Control Plane."
            }
        }
        $AzureRbacAssignment | Add-Member -NotePropertyName "ConditionEvaluation" -NotePropertyValue $ConditionEvaluation -Force
        $AzureRbacAssignment
    }

    # Apply role definition classification overwrites (down-/upgrade by RoleDefinitionId or RoleDefinitionName).
    # Applied after the constrained-delegation evaluation so an explicit operator pin always wins.
    $ClassificationOverwrites = Import-EntraOpsClassificationOverwrites -RbacSystem "Azure" -FolderClassification $FolderClassification
    if ($ClassificationOverwrites.RoleDefinitionOverwrites.Count -gt 0) {
        Write-Host "Applying $($ClassificationOverwrites.RoleDefinitionOverwrites.Count) role definition classification overwrite(s) from Classification_RoleDefinitionOverwrites.json..." -ForegroundColor Yellow
        $AzureRbacClassifications = @(Invoke-EntraOpsClassificationRoleOverwrite -RbacClassifications $AzureRbacClassifications -RoleDefinitionOverwrites $ClassificationOverwrites.RoleDefinitionOverwrites -RoleSystem "Azure")
    }

    $Stage3Duration = ((Get-Date) - $Stage3Start).TotalSeconds
    Write-Host "✓ Stage 3 completed in $([Math]::Round($Stage3Duration, 2)) seconds ($($AzureRbacClassifications.Count) role assignments classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 3/4: Classifying Principals" -Completed
    #endregion

    #region Stage 4: Resolve Object Details and Finalize Output
    $Stage4Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 4/4: Resolving Object Details and Finalizing" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Enriching principals with detailed attributes and applying exclusions..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 4/4: Resolving Objects" -Status "Resolving object details..." -PercentComplete 75

    $AzureRbacByObject = $AzureRbacClassifications | Group-Object ObjectId -AsHashTable -AsString
    # Case-insensitive dedup: a principal id returned with different casing by two ARM/Graph endpoints
    # (for example roleAssignmentScheduleInstances vs. the remoteTenantGroups re-keying in Stage 1)
    # would otherwise be resolved twice and emitted as two rows for the same object.
    $UniqueObjects = @(
        $AzureRbacAssignments |
            Where-Object { $null -ne $_.ObjectId } |
            Group-Object -Property { "$($_.ObjectId)".ToLowerInvariant() } |
            ForEach-Object { $_.Group[0] | Select-Object ObjectId, ObjectType }
    )

    $ObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution `
        -UniqueObjects $UniqueObjects `
        -TenantId $TenantId `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit

    #region Stage 4b: Cross-tenant resolution of objects living in the managing tenant
    # Objects that could not be resolved in the home tenant (e.g. ForeignGroups re-keyed to their remote group
    # identity in Stage 1) are resolved against the configured managing tenant, mirroring the Entra ID RBAC flow.
    # No-op when no managing tenant is configured or all objects were already resolved in the home tenant.
    $ObjectDetailsCache = Invoke-EntraOpsCrossTenantObjectResolution `
        -UniqueObjects $UniqueObjects `
        -ObjectDetailsCache $ObjectDetailsCache `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit

    # Fallback: any ForeignGroup still unresolved (managing tenant not configured, remote tenant differs, or
    # not reachable) uses the remoteTenantGroups details captured in Stage 1 so it still appears with its
    # remote display name and role-assignable group subtype instead of being dropped.
    if ($ForeignGroupDetailsCache.Count -gt 0) {
        foreach ($RemoteGroupId in $ForeignGroupDetailsCache.Keys) {
            $ExistingDetails = $ObjectDetailsCache[$RemoteGroupId]
            if ($null -eq $ExistingDetails -or "$($ExistingDetails.ObjectType)" -ieq 'unknown') {
                $ObjectDetailsCache[$RemoteGroupId] = $ForeignGroupDetailsCache[$RemoteGroupId]
            }
        }
    }
    #endregion

    if ($DeletedPrincipalAssignmentHandling -eq 'Filter') {
        $ObjectsBeforeDeletedPrincipalFilter = @($UniqueObjects)
        $UniqueObjects = @(Select-EntraOpsAzureRbacPrincipal `
            -UniqueObjects $UniqueObjects `
            -ObjectDetailsCache $ObjectDetailsCache `
            -DeletedPrincipalAssignmentHandling $DeletedPrincipalAssignmentHandling)

        # O(1) cache lookup per principal instead of scanning the retained-id array per id
        # (O(N x M) in large tenants just to build this informational message).
        $FilteredDeletedPrincipalIds = @($ObjectsBeforeDeletedPrincipalFilter |
                Where-Object { $ObjectDetailsCache[$_.ObjectId].ResolutionStatus -eq 'NotFound' } |
                ForEach-Object { $_.ObjectId })
        if ($FilteredDeletedPrincipalIds.Count -gt 0) {
            $FilteredAssignmentCount = @($AzureRbacClassifications | Where-Object { $_.ObjectId -in $FilteredDeletedPrincipalIds }).Count
            $FilteredPrincipalMessage = "Filtered $FilteredAssignmentCount Azure RBAC role assignment(s) for $($FilteredDeletedPrincipalIds.Count) principal(s) confirmed deleted by Microsoft Graph: $($FilteredDeletedPrincipalIds -join ', ')"
            Write-Host $FilteredPrincipalMessage -ForegroundColor Yellow
        }
    }

    # Explicit short-circuit: after the deleted-principal filter (or in an empty-scope tenant) no
    # principals may remain. Invoke-EntraOpsEAMClassificationAggregation deliberately keeps a strict
    # mandatory-collection contract, so an empty set is handled here with an empty result instead.
    if (@($UniqueObjects).Count -eq 0) {
        Write-Host "No Azure RBAC principals remain for classification aggregation - producing an empty export." -ForegroundColor Yellow
        $AzureRbacClassifiedObjects = @()
    } else {
        $AzureRbacClassifiedObjects = Invoke-EntraOpsEAMClassificationAggregation `
            -UniqueObjects $UniqueObjects `
            -ObjectDetailsCache $ObjectDetailsCache `
            -RbacClassificationsByObject $AzureRbacByObject `
            -RoleSystem "Azure" `
            -EnableParallelProcessing $EnableParallelProcessing `
            -ParallelThrottleLimit $ParallelThrottleLimit `
            -WarningMessages $WarningMessages
    }

    Write-Progress -Activity "Stage 4/4: Resolving Objects" -Status "Applying global exclusions and sorting..." -PercentComplete 90
    $FilteredAzureObjects = $AzureRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }

    $Stage4Duration = ((Get-Date) - $Stage4Start).TotalSeconds
    $TotalDuration = ((Get-Date) - $Stage1Start).TotalSeconds

    Write-Progress -Activity "Stage 4/4: Resolving Objects" -Completed
    Write-Host "✓ Stage 4 completed in $([Math]::Round($Stage4Duration, 2)) seconds ($($FilteredAzureObjects.Count) privileged objects after exclusions)" -ForegroundColor Green

    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages -IncludeObjectDetails $IncludeObjectDetails

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✓ All Stages Completed Successfully" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "Total execution time: $([Math]::Round($TotalDuration, 2)) seconds" -ForegroundColor Gray
    Write-Host "Final result: $($FilteredAzureObjects.Count) privileged objects ready for export" -ForegroundColor Gray
    #endregion

    $FilteredAzureObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Set-EntraOpsEAMClassificationJustification -IncludeJustification:$IncludeJustification | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}
