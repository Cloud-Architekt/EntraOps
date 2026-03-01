<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Microsoft Intune and assigned roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Microsoft Intune and assigned roles and classifications.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".
#>

function Get-EntraOpsPrivilegedEamDefender {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-AzContext).Tenant.Id
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassifiedObjects = "$DefaultFolderClassifiedEam"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$ApplyClassificationByAssignedObjects = $false
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
    $DefenderRbacClassificationsByJSON = @()
    
    $ProcessedRoleDefs = 0
    $UniqueRoleDefs = $DefenderRbacAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId
    $TotalRoleDefs = $UniqueRoleDefs.Count

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

        $MatchedClassificationByScope = @()
        # Check if RBAC scope is listed in JSON by wildcard in RoleAssignmentScope (e.g. /azops-rg/*)
        $MatchedClassificationByScope += $DefenderResourcesByClassificationJSON | foreach-object {
            $Classification = $_
            $Classification | where-object { $DefenderRbacAssignment.RoleAssignmentScopeId -like $Classification.RoleAssignmentScopeName -and $DefenderRbacAssignment.RoleAssignmentScopeId -notcontains $Classification.ExcludedRoleAssignmentScopeName }
        }

        # Check if role action and scope exists in JSON definition
        $DefenderRoleActionsInJsonDefinition = @()
        $DefenderRoleActionsInJsonDefinition = foreach ($Action in $DefenderRoleActions.rolePermissions.allowedResourceActions) {
            $MatchedClassificationByScope | Where-Object { $_.RoleDefinitionActions -Contains $Action -and $_.ExcludedRoleDefinitionActions -notcontains $Action }
        }

        if (($DefenderRoleActionsInJsonDefinition.Count -gt 0)) {
            $ClassifiedDefenderMgmtRbacRoleWithActions = @()
            foreach ($DefenderRoleAction in $DefenderRoleActions.rolePermissions.allowedResourceActions) {
                $ClassifiedDefenderMgmtRbacRoleWithActions += $DefenderResourcesByClassificationJSON | Where-Object { $DefenderRoleAction -in $_.RoleDefinitionActions -and $_.RoleAssignmentScopeName -contains $DefenderRbacAssignment.RoleAssignmentScopeId -and $_.ExcludedRoleAssignmentScopeName -notcontains $DefenderRbacAssignment.RoleAssignmentScopeId }
            }
            $ClassifiedDefenderMgmtRbacRoleWithActions = $ClassifiedDefenderMgmtRbacRoleWithActions | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification = $ClassifiedDefenderMgmtRbacRoleWithActions | ForEach-Object {
                [PSCustomObject]@{
                    'AdminTierLevel'             = $_.EAMTierLevelTagValue
                    'AdminTierLevelName'         = $_.EAMTierLevelName
                    'Service'                    = $_.Service
                    'TaggedBy'                   = "JSONwithAction"
                    'TaggedByObjectIds'          = $null
                    'TaggedByObjectDisplayNames' = $null
                    'TaggedByRoleSystem'         = $null
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
        $Classification = $Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames, TaggedByRoleSystem | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy
        $DefenderRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $DefenderRbacAssignment
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

    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✓ All Stages Completed Successfully" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "Total execution time: $([Math]::Round($TotalDuration, 2)) seconds" -ForegroundColor Gray
    Write-Host "Final result: $($FilteredDefenderObjects.Count) privileged objects ready for export" -ForegroundColor Gray
    #endregion
    
    $FilteredDefenderObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}