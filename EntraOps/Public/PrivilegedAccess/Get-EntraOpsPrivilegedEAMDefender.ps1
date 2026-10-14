<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Microsoft Defender XDR Unified RBAC and assigned roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Microsoft Defender XDR Unified RBAC and assigned roles and classifications.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".

.PARAMETER IncludeJustification
    Include the Justification property (documenting a manual classification overwrite) on all Classification
    entries of the returned objects. Default is $false, so the property is not present in the output at all.

.PARAMETER IncludeObjectDetails
    Include descriptive object details in warning output. Defaults to ConsoleOutput.IncludeObjectDetails from
    EntraOpsConfig.json. Object IDs are always shown.
#>

function Get-EntraOpsPrivilegedEamDefender {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-EntraOpsAzContextValue -Property TenantId)
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassifiedObjects = "$DefaultFolderClassifiedEam"
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

    # Configuration for batch processing
    $BatchSize = 100  # Number of objects to process before showing progress
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    $DefenderClassificationFilePath = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_Defender.json"

    #region Get all role assignments and global exclusions
    #region Stage 1: Fetch Defender Role Assignments
    $Stage1Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 1/4: Fetching Defender Role Assignments" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Retrieving Microsoft Defender Unified RBAC role assignments and definitions..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 1/4: Fetching Defender Roles" -Status "Loading role assignments and global exclusions..." -PercentComplete 10

    if ($SampleMode -ne $True) {
        $DefenderRbacAssignments = EntraOps\Get-EntraOpsPrivilegedDefenderRoles -TenantId $TenantId -WarningMessages $WarningMessages
    } else {
        $WarningMessages.Add([PSCustomObject]@{Type = "Stage1"; Message = "SampleMode currently not supported!" })
    }

    $GlobalExclusionList = Import-EntraOpsGlobalExclusions -Enabled $GlobalExclusion
    
    $Stage1Duration = ((Get-Date) - $Stage1Start).TotalSeconds
    Write-Host "✓ Stage 1 completed in $([Math]::Round($Stage1Duration, 2)) seconds ($($DefenderRbacAssignments.Count) role assignments retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 1/4: Fetching Defender Roles" -Completed
    #endregion

    # Return early if no role assignments found to prevent null index errors
    if ($null -eq $DefenderRbacAssignments -or @($DefenderRbacAssignments).Count -eq 0) {
        Write-Warning "No Defender role assignments found. Returning empty result."
        return @()
    }
    
    #region Check if RBAC role action and scope is defined in JSON classification
    #region Stage 2: Load and Classify Role Actions
    $Stage2Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 2/4: Loading Classification Rules" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Loading Defender role action classifications and matching against JSON definitions..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 2/4: Loading Classification Rules" -Status "Reading classification file..." -PercentComplete 25
    
    # Optimization: Pre-fetch all Defender role definitions to avoid N+1 queries
    $DefenderRoleDefinitionsCache = @{}
    try {
        if ($SampleMode -ne $True) {
            Write-Verbose "Pre-fetching all Defender role definitions..."
            $AllDefenderRoles = Invoke-EntraOpsMsGraphQuery -Method GET -Uri https://graph.microsoft.com/beta/roleManagement/defender/roleDefinitions -OutputType PSObject
            foreach ($Role in $AllDefenderRoles) {
                $DefenderRoleDefinitionsCache[$Role.Id] = $Role
            }
        }
    } catch {
        Write-Warning "Failed to pre-fetch Defender role definitions. Falling back to per-item lookup."
    }

    $DefenderResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $DefenderClassificationFilePath | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions

    # Load classification overwrites (down-/upgrade of entire role definitions) from tenant-specific folder or Templates fallback.
    # Role action overwrites are already baked into the classification file by Update-EntraOpsClassificationControlPlaneScope.
    $ClassificationOverwrites = Import-EntraOpsClassificationOverwrites -RbacSystem "Defender" -FolderClassification $FolderClassification
    $DefenderRbacClassificationsByJSON = @()
    $DefenderRbacClassificationsByCloudSetScope = @()

    # A Defender CloudSet is an explicit Defender for Cloud boundary over Azure subscriptions. Its
    # classification follows the most privileged member subscription, even if the custom Defender
    # role has no action represented in Classification_Defender.json.
    $AzureScopeReasoning = $null
    $AzureScopeReasoningFile = Join-Path -Path $FolderClassification -ChildPath "$TenantNameContext/ScopeReasoning_Azure.json"
    if (Test-Path -LiteralPath $AzureScopeReasoningFile) {
        try {
            $AzureScopeReasoning = Get-Content -LiteralPath $AzureScopeReasoningFile -Raw | ConvertFrom-Json -Depth 10
            $EffectiveAzureTier0Scopes = @($AzureScopeReasoning.Tier0Scope | Where-Object { $_ -and $_ -ne '/' })
            $EffectiveAzureTier1Scopes = @($AzureScopeReasoning.Tier1Scope | Where-Object { $_ -and $_ -ne '/' })
            if ($EffectiveAzureTier0Scopes.Count -eq 0 -and $EffectiveAzureTier1Scopes.Count -eq 0 -and @($AzureScopeReasoning.ScopeDetails).Count -eq 0) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = 'CloudSetAzureScopeReasoningDegenerate'
                        Message = "Azure scope reasoning file '$AzureScopeReasoningFile' contains no effective ARM Tier0/Tier1 scopes or scope details. Defender CloudSet subscriptions will resolve as UserAccess and will not produce privileged classifications."
                    })
            }
        } catch {
            $WarningMessages.Add([PSCustomObject]@{
                    Type    = 'CloudSetAzureScopeReasoningReadError'
                    Message = "Failed to load Azure scope reasoning file '$AzureScopeReasoningFile': $($_.Exception.Message)"
                })
        }
    }

    function Test-DefenderRoleActionMatch {
        param(
            [string]$RoleAction,
            [object[]]$ClassificationActions
        )

        foreach ($ClassificationAction in @($ClassificationActions)) {
            if ([string]::IsNullOrWhiteSpace("$ClassificationAction")) { continue }
            if ($RoleAction -like "$ClassificationAction" -or "$ClassificationAction" -like $RoleAction) {
                return $true
            }
        }
        return $false
    }

    
    $ProcessedRoleDefs = 0
    $UniqueRoleDefs = $DefenderRbacAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId, CloudSetSubscriptionScopes
    $TotalRoleDefs = $UniqueRoleDefs.Count
    $WarnedUserAccessCloudSets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $DefenderRbacClassificationsByJSON += foreach ($DefenderRbacAssignment in $UniqueRoleDefs) {
        $ProcessedRoleDefs++
        if ($ProcessedRoleDefs % 10 -eq 0) {
            Write-Progress -Activity "Stage 2/4: Loading Classification Rules" -Status "Classifying role definition $ProcessedRoleDefs of $TotalRoleDefs" -PercentComplete (25 + ($ProcessedRoleDefs / $TotalRoleDefs * 25))
        }

        if ($DefenderRbacAssignment.RoleAssignmentScopeId -ne "/") {
            $DefenderRbacAssignment.RoleAssignmentScopeId = "$($DefenderRbacAssignment.RoleAssignmentScopeId)"
        }
        # Role actions are defined for scope and role definition contains an action of the role, otherwise all role actions within role assignment scope will be applied
        if ($SampleMode -eq $True) {
            # Removed redundant warning
        } else {
            # Optimization: Use cache lookup
            if ($DefenderRoleDefinitionsCache.ContainsKey("$($DefenderRbacAssignment.RoleDefinitionId)")) {
                $DefenderRoleActions = $DefenderRoleDefinitionsCache["$($DefenderRbacAssignment.RoleDefinitionId)"]
            } else {
                $DefenderRoleActions = (Invoke-EntraOpsMsGraphQuery -Method GET -Uri https://graph.microsoft.com/beta/roleManagement/defender/roleDefinitions -OutputType PSObject) | Where-Object { $_.Id -eq "$($DefenderRbacAssignment.RoleDefinitionId)" }
            }
        }

        $EffectiveScopeIds = [System.Collections.Generic.List[string]]::new()
        $EffectiveScopeIds.Add("$($DefenderRbacAssignment.RoleAssignmentScopeId)") | Out-Null
        if ($DefenderRbacAssignment.PSObject.Properties.Name -contains 'CloudSetSubscriptionScopes') {
            foreach ($CloudSetSubscriptionScope in @($DefenderRbacAssignment.CloudSetSubscriptionScopes)) {
                if (-not [string]::IsNullOrWhiteSpace("$CloudSetSubscriptionScope")) {
                    $EffectiveScopeIds.Add("$CloudSetSubscriptionScope") | Out-Null
                }
            }
        }

        $EffectiveScopeIds = @($EffectiveScopeIds | Select-Object -Unique)
        $MatchedClassificationByScope = foreach ($EffectiveScopeId in $EffectiveScopeIds) {
            # Check if the direct scope or a CloudSet member subscription is listed in JSON by wildcard.
            $DefenderResourcesByClassificationJSON | Where-Object {
                $EffectiveScopeId -like $_.RoleAssignmentScopeName -and
                $_.ExcludedRoleAssignmentScopeName -notcontains $EffectiveScopeId
            }
        }

        $CloudSetSubscriptionScopes = @($DefenderRbacAssignment.CloudSetSubscriptionScopes | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") })
        if ($CloudSetSubscriptionScopes.Count -gt 0) {
            if ($null -eq $AzureScopeReasoning) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = 'CloudSetAzureScopeReasoningMissing'
                        Message = "CloudSet '$($DefenderRbacAssignment.RoleAssignmentScopeId)' has resolved subscription scope(s), but Azure scope reasoning is unavailable. Run Update-EntraOpsClassificationControlPlaneScope for Azure before exporting Defender EAM data."
                    })
            } else {
                $ResolvedCloudSetScopeTiers = @($CloudSetSubscriptionScopes | ForEach-Object {
                        Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId $_ -AzureScopeReasoning $AzureScopeReasoning
                    } | Where-Object { $null -ne $_ })
                $CloudSetScopeTiers = @($ResolvedCloudSetScopeTiers | Where-Object { $_.AdminTierLevelName -in @('ControlPlane', 'ManagementPlane') })
                $CloudSetScopeTier = $CloudSetScopeTiers | Sort-Object { [int]$_.AdminTierLevel } | Select-Object -First 1
                if ($null -ne $CloudSetScopeTier) {
                    $DefenderRbacClassificationsByCloudSetScope += [PSCustomObject]@{
                        RoleDefinitionId      = $DefenderRbacAssignment.RoleDefinitionId
                        RoleAssignmentScopeId = $DefenderRbacAssignment.RoleAssignmentScopeId
                        Classification        = [PSCustomObject]@{
                            AdminTierLevel             = $CloudSetScopeTier.AdminTierLevel
                            AdminTierLevelName         = $CloudSetScopeTier.AdminTierLevelName
                            MatchedActions             = $null
                            ScopedObjects              = $null
                            Service                    = 'Azure subscription scope (Defender CloudSet)'
                            TaggedBy                   = 'CloudSetAzureScopeReasoning'
                            TaggedByObjectIds          = @($CloudSetSubscriptionScopes)
                            TaggedByObjectDisplayNames = @($CloudSetSubscriptionScopes)
                            TaggedByRoleSystem         = 'Azure'
                        }
                    }
                } elseif ($WarnedUserAccessCloudSets.Add("$($DefenderRbacAssignment.RoleAssignmentScopeId)")) {
                    $WarningMessages.Add([PSCustomObject]@{
                            Type     = 'CloudSetResolvedAsUserAccess'
                            ObjectId = "$($DefenderRbacAssignment.RoleAssignmentScopeId)"
                            Message  = "CloudSet '$($DefenderRbacAssignment.RoleAssignmentScopeId)' contains $($CloudSetSubscriptionScopes.Count) resolved subscription scope(s), but none map to Azure ControlPlane or ManagementPlane reasoning. No privileged CloudSet classification was generated."
                        })
                }
            }
        }

        # Check if role action and scope exists in JSON definition
        $DefenderRoleActionsInJsonDefinition = @()
        $DefenderRoleActionsInJsonDefinition = foreach ($Action in $DefenderRoleActions.rolePermissions.allowedResourceActions) {
            $MatchedClassificationByScope | Where-Object {
                (Test-DefenderRoleActionMatch -RoleAction $Action -ClassificationActions $_.RoleDefinitionActions) -and
                -not (Test-DefenderRoleActionMatch -RoleAction $Action -ClassificationActions $_.ExcludedRoleDefinitionActions)
            }
        }

        if (($DefenderRoleActionsInJsonDefinition.Count -gt 0)) {
            $ClassifiedWithMatchedActions = @()
            foreach ($DefenderRoleAction in $DefenderRoleActions.rolePermissions.allowedResourceActions) {
                foreach ($EffectiveScopeId in $EffectiveScopeIds) {
                    $ClassifiedWithMatchedActions += $DefenderResourcesByClassificationJSON | Where-Object {
                        (Test-DefenderRoleActionMatch -RoleAction $DefenderRoleAction -ClassificationActions $_.RoleDefinitionActions) -and
                        $EffectiveScopeId -like $_.RoleAssignmentScopeName -and
                        -not (Test-DefenderRoleActionMatch -RoleAction $DefenderRoleAction -ClassificationActions $_.ExcludedRoleDefinitionActions)
                    } | ForEach-Object {
                        [PSCustomObject]@{
                            EAMTierLevelName     = $_.EAMTierLevelName
                            EAMTierLevelTagValue = $_.EAMTierLevelTagValue
                            Service              = $_.Service
                            MatchedAction        = $DefenderRoleAction
                        }
                    }
                }
            }
            $UniqueClassifications = $ClassifiedWithMatchedActions | Select-Object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification = foreach ($UniqueClass in $UniqueClassifications) {
                $MatchedEntries = @($ClassifiedWithMatchedActions | Where-Object {
                        $_.EAMTierLevelName -eq $UniqueClass.EAMTierLevelName -and
                        $_.EAMTierLevelTagValue -eq $UniqueClass.EAMTierLevelTagValue -and
                        $_.Service -eq $UniqueClass.Service
                    })
                [array]$MatchedActions = @($MatchedEntries | Select-Object -ExpandProperty MatchedAction | Select-Object -Unique)
                [PSCustomObject]@{
                    'AdminTierLevel'             = $UniqueClass.EAMTierLevelTagValue
                    'AdminTierLevelName'         = $UniqueClass.EAMTierLevelName
                    'Service'                    = $UniqueClass.Service
                    'MatchedActions'             = if ($MatchedActions.Count -gt 0) { , @($MatchedActions) } else { $null }
                    'ScopedObjects'              = $null
                    'TaggedBy'                   = "JSONwithAction"
                    'TaggedByObjectIds'          = $null
                    'TaggedByObjectDisplayNames' = $null
                    'TaggedByRoleSystem'         = "Defender"
                }
            }

            [PSCustomObject]@{
                'RoleDefinitionId'      = $DefenderRbacAssignment.RoleDefinitionId
                'RoleAssignmentScopeId' = $DefenderRbacAssignment.RoleAssignmentScopeId
                'Classification'        = $Classification
            }
        } else {
            $ClassifiedDefenderMgmtRbacRoleWithActions = @()
        }
    }
    
    $Stage2Duration = ((Get-Date) - $Stage2Start).TotalSeconds
    Write-Host "✓ Stage 2 completed in $([Math]::Round($Stage2Duration, 2)) seconds ($($DefenderRbacClassificationsByJSON.Count) role definitions classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 2/4: Loading Classification Rules" -Completed
    #endregion

    #region Classify all assigned privileged users and groups in Device Management
    #region Stage 3: Classify Principals
    $Stage3Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 3/4: Classifying Principals" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Matching principals against classified role assignments and building classification..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 3/4: Classifying Principals" -Status "Processing role assignments..." -PercentComplete 50
    
    # Initialize assigned objects classification (not yet implemented for Defender, placeholder for future use)
    if (-not $DefenderRbacClassificationsByAssignedObjects) {
        $DefenderRbacClassificationsByAssignedObjects = @()
    }

    $DefenderRbacClassifications = foreach ($DefenderRbacAssignment in $DefenderRbacAssignments) {
        $DefenderRbacAssignment = $DefenderRbacAssignment | Select-Object -ExcludeProperty Classification
        $Classification = @()
        $Classification += ($DefenderRbacClassificationsByAssignedObjects | Where-Object { $_.RoleAssignmentScopeId -contains $DefenderRbacAssignment.RoleAssignmentScopeId }).Classification
        $Classification += ($DefenderRbacClassificationsByJSON | Where-Object { $_.RoleAssignmentScopeId -contains $DefenderRbacAssignment.RoleAssignmentScopeId -and $_.RoleDefinitionId -eq $DefenderRbacAssignment.RoleDefinitionId }).Classification
        $Classification += ($DefenderRbacClassificationsByCloudSetScope | Where-Object { $_.RoleAssignmentScopeId -contains $DefenderRbacAssignment.RoleAssignmentScopeId -and $_.RoleDefinitionId -eq $DefenderRbacAssignment.RoleDefinitionId }).Classification
        $Classification = $Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, MatchedActions, ScopedObjects, Service, TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames, TaggedByRoleSystem, Justification | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy
        $DefenderRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $DefenderRbacAssignment
    }
    
    # Apply role definition classification overwrites (down-/upgrade by RoleDefinitionId or RoleDefinitionName)
    if ($ClassificationOverwrites.RoleDefinitionOverwrites.Count -gt 0) {
        Write-Host "Applying $($ClassificationOverwrites.RoleDefinitionOverwrites.Count) role definition classification overwrite(s) from Classification_RoleDefinitionOverwrites.json..." -ForegroundColor Yellow
        $DefenderRbacClassifications = Invoke-EntraOpsClassificationRoleOverwrite -RbacClassifications $DefenderRbacClassifications -RoleDefinitionOverwrites $ClassificationOverwrites.RoleDefinitionOverwrites -RoleSystem "Defender"
    }
    
    $Stage3Duration = ((Get-Date) - $Stage3Start).TotalSeconds
    Write-Host "✓ Stage 3 completed in $([Math]::Round($Stage3Duration, 2)) seconds ($($DefenderRbacClassifications.Count) role assignments classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 3/4: Classifying Principals" -Completed
    #endregion

    #region Apply classification to all assigned privileged users and groups in Device Management
    #region Stage 4: Resolve and Finalize Objects
    $Stage4Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 4/4: Resolving Object Details and Finalizing" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Enriching principals with detailed attributes and applying exclusions..." -ForegroundColor Gray

    # Group assignments by ObjectId for efficient lookup
    $DefenderRbacByObject = $DefenderRbacClassifications | Group-Object ObjectId -AsHashTable -AsString

    # Collect unique objects and resolve details
    $UniqueObjects = $DefenderRbacAssignments | Select-Object -Unique ObjectId, ObjectType | Where-Object { $null -ne $_.ObjectId }
    $ObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution `
        -UniqueObjects $UniqueObjects `
        -TenantId $TenantId `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit

    # Aggregate classifications and build output objects
    $DefenderRbacClassifiedObjects = Invoke-EntraOpsEAMClassificationAggregation `
        -UniqueObjects $UniqueObjects `
        -ObjectDetailsCache $ObjectDetailsCache `
        -RbacClassificationsByObject $DefenderRbacByObject `
        -RoleSystem "Defender" `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit `
        -WarningMessages $WarningMessages
    #endregion
    
    Write-Progress -Activity "Stage 4/4: Finalizing Results" -Status "Applying global exclusions and sorting..." -PercentComplete 90
    $FilteredDefenderObjects = $DefenderRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }

    $Stage4Duration = ((Get-Date) - $Stage4Start).TotalSeconds
    $TotalDuration = ((Get-Date) - $Stage1Start).TotalSeconds
    
    Write-Progress -Activity "Stage 4/4: Finalizing Results" -Completed
    Write-Host "✓ Stage 4 completed in $([Math]::Round($Stage4Duration, 2)) seconds ($($FilteredDefenderObjects.Count) privileged objects after exclusions)" -ForegroundColor Green

    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages -IncludeObjectDetails $IncludeObjectDetails

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✓ All Stages Completed Successfully" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "Total execution time: $([Math]::Round($TotalDuration, 2)) seconds" -ForegroundColor Gray
    Write-Host "Final result: $($FilteredDefenderObjects.Count) privileged objects ready for export" -ForegroundColor Gray
    #endregion
    
    $FilteredDefenderObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Set-EntraOpsEAMClassificationJustification -IncludeJustification:$IncludeJustification | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}
