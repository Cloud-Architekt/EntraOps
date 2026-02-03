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

    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ClassificationFileName = "Classification_Defender.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $DefenderClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    } elseif (Test-Path -Path "$DefaultFolderClassification/Templates/$($ClassificationFileName)") {
        $DefenderClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    } else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }

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

    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    } else {
        $GlobalExclusionList = $null
    }
    
    $Stage1Duration = ((Get-Date) - $Stage1Start).TotalSeconds
    Write-Host "✓ Stage 1 completed in $([Math]::Round($Stage1Duration, 2)) seconds ($($DefenderRbacAssignments.Count) role assignments retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 1/4: Fetching Defender Roles" -Completed
    #endregion

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
            $MatchedClassificationByScope | Where-Object { $_.RoleDefinitionActions -Contains $Action -and $Classification.ExcludedRoleDefinitionActions -notcontains $_.RoleDefinitionActions }
        }

        if (($DefenderRoleActionsInJsonDefinition.Count -gt 0)) {
            $ClassifiedDefenderMgmtRbacRoleWithActions = @()
            foreach ($DefenderRoleAction in $DefenderRoleActions.rolePermissions.allowedResourceActions) {
                $ClassifiedDefenderMgmtRbacRoleWithActions += $DefenderResourcesByClassificationJSON | Where-Object { $DefenderRoleAction -in $_.RoleDefinitionActions -and $_.RoleAssignmentScopeName -contains $DefenderRbacAssignment.RoleAssignmentScopeId -and $_.ExcludedRoleAssignmentScopeName -notcontains $DefenderRbacAssignment.RoleAssignmentScopeId }
            }
            $ClassifiedDefenderMgmtRbacRoleWithActions = $ClassifiedDefenderMgmtRbacRoleWithActions | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification = $ClassifiedDefenderMgmtRbacRoleWithActions | ForEach-Object {
                [PSCustomObject]@{
                    'AdminTierLevel'     = $_.EAMTierLevelTagValue
                    'AdminTierLevelName' = $_.EAMTierLevelName
                    'Service'            = $_.Service
                    'TaggedBy'           = "JSONwithAction"
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
    
    $DefenderRbacClassifications = foreach ($DefenderRbacAssignment in $DefenderRbacAssignments) {
        $DefenderRbacAssignment = $DefenderRbacAssignment | Select-Object -ExcludeProperty Classification
        $Classification = @()
        $Classification += ($DefenderRbacClassificationsByAssignedObjects | Where-Object { $_.RoleAssignmentScopeId -contains $DefenderRbacAssignment.RoleAssignmentScopeId }).Classification
        $Classification += ($DefenderRbacClassificationsByJSON | Where-Object { $_.RoleAssignmentScopeId -contains $DefenderRbacAssignment.RoleAssignmentScopeId -and $_.RoleDefinitionId -eq $DefenderRbacAssignment.RoleDefinitionId }).Classification
        $Classification = $Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy
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

    # Warning Collection
    $WarningMessages = New-Object System.Collections.Generic.List[psobject]

    # Optimization: Group assignments by ObjectId to avoid O(N^2) filtering
    $DefenderRbacByObject = $DefenderRbacClassifications | Group-Object ObjectId -AsHashTable -AsString

    # Optimization: Collect all unique ObjectIds and batch resolve details
    $UniqueObjects = $DefenderRbacAssignments | Select-Object -Unique ObjectId, ObjectType | Where-Object { $null -ne $_.ObjectId }
    
    # Use helper function for parallel/sequential object resolution
    $ObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution `
        -UniqueObjects $UniqueObjects `
        -TenantId $TenantId `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit

    # Determine if parallel processing is viable for classification aggregation
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    $HasSufficientObjects = $UniqueObjects.Count -ge 50
    $UseParallelForClassification = $EnableParallelProcessing -and $IsPowerShell7 -and $HasSufficientObjects
    
    if ($UseParallelForClassification) {
        $SyncObjectDetailsCache = [System.Collections.Hashtable]::Synchronized($ObjectDetailsCache)
        $SyncDefenderRbacByObject = [System.Collections.Hashtable]::Synchronized($DefenderRbacByObject)
        
        $ClassificationThrottleLimit = [Math]::Min($ParallelThrottleLimit * 2, 100)
        Write-Host "Using parallel classification processing with $ClassificationThrottleLimit threads for $($UniqueObjects.Count) objects..." -ForegroundColor Yellow
        
        $DefenderRbacClassifiedObjects = $UniqueObjects | ForEach-Object -ThrottleLimit $ClassificationThrottleLimit -Parallel {
            $obj = $_
            $ObjectId = $obj.ObjectId
            
            if ($null -ne $ObjectId) {
                $SharedDetailsCache = $using:SyncObjectDetailsCache
                $SharedRbacByObject = $using:SyncDefenderRbacByObject
                
                $ObjectDetails = $SharedDetailsCache[$ObjectId]
                
                if ($null -eq $ObjectDetails) {
                    Write-Verbose "Skipping object $ObjectId - failed to retrieve details"
                    return
                }

                $DefenderRbacClassifiedAssignments = $SharedRbacByObject[$ObjectId]

                $UniqueClassificationsHash = @{}
                foreach ($Assignment in $DefenderRbacClassifiedAssignments) {
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
                    $Classification += [PSCustomObject]@{
                        'AdminTierLevel'     = "Unclassified"
                        'AdminTierLevelName' = "Unclassified"
                        'Service'            = "Unclassified"
                    }
                }

                [PSCustomObject]@{
                    'ObjectId'                      = $ObjectId
                    'ObjectType'                    = $ObjectDetails.ObjectType.ToLower()
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
                    'RoleSystem'                    = "Defender"
                    'Classification'                = $Classification
                    'RoleAssignments'               = @($DefenderRbacClassifiedAssignments | Sort-Object RoleAssignmentId)
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
    } else {
        if ($EnableParallelProcessing -and $IsPowerShell7) {
            Write-Host "Using sequential classification processing (dataset too small: $($UniqueObjects.Count) objects)" -ForegroundColor Yellow
        } else {
            Write-Host "Using sequential classification processing..." -ForegroundColor Yellow
        }
        
        $DefenderRbacClassifiedObjects = $UniqueObjects | ForEach-Object {
        if ($null -ne $_.ObjectId) {
            $ObjectId = $_.ObjectId
            if ($VerbosePreference -ne 'SilentlyContinue') {
                Write-Verbose -Message "Processing classifications for $($ObjectId)..."
            }
            
            # Object types
            $ObjectDetails = $ObjectDetailsCache[$ObjectId]
            
            # Skip if object details couldn't be retrieved
            if ($null -eq $ObjectDetails) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "Skipping Object"
                        Message = "Skipping object $ObjectId - failed to retrieve details"
                        Target  = $ObjectId
                    })
                return
            }

            # RBAC Assignments
            $DefenderRbacClassifiedAssignments = $DefenderRbacByObject[$ObjectId]

            # Classification - use hashtable for unique aggregation
            $UniqueClassificationsHash = @{}
            foreach ($Assignment in $DefenderRbacClassifiedAssignments) {
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
                $Classification += [PSCustomObject]@{
                    'AdminTierLevel'     = "Unclassified"
                    'AdminTierLevelName' = "Unclassified"
                    'Service'            = "Unclassified"
                }
            }

            [PSCustomObject]@{
                'ObjectId'                      = $ObjectId
                'ObjectType'                    = $ObjectDetails.ObjectType.ToLower()
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
                'RoleSystem'                    = "Defender"
                'Classification'                = $Classification
                'RoleAssignments'               = @($DefenderRbacClassifiedAssignments | Sort-Object RoleAssignmentId)
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
    #endregion
    
    Write-Progress -Activity "Stage 4/4: Finalizing Results" -Status "Applying global exclusions and sorting..." -PercentComplete 90
    $FilteredDefenderObjects = $DefenderRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }

    $Stage4Duration = ((Get-Date) - $Stage4Start).TotalSeconds
    $TotalDuration = ((Get-Date) - $Stage1Start).TotalSeconds
    
    Write-Progress -Activity "Stage 4/4: Finalizing Results" -Completed
    Write-Host "✓ Stage 4 completed in $([Math]::Round($Stage4Duration, 2)) seconds ($($FilteredDefenderObjects.Count) privileged objects after exclusions)" -ForegroundColor Green

    # Display Warning Summary
    if ($WarningMessages.Count -gt 0) {
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "  ⚠ Warnings Summary" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        
        # Group by Type first, then by distinct message within each type
        $GroupedByType = $WarningMessages | Group-Object Type
        foreach ($TypeGroup in $GroupedByType) {
            Write-Host "  $($TypeGroup.Name):" -ForegroundColor Yellow
            
            # Group messages by distinct message pattern to avoid duplicates
            $GroupedByMessage = $TypeGroup.Group | Group-Object Message
            foreach ($MessageGroup in $GroupedByMessage) {
                if ($MessageGroup.Count -eq 1) {
                    Write-Host "    - $($MessageGroup.Name)" -ForegroundColor DarkYellow
                } else {
                    Write-Host "    - $($MessageGroup.Name) [$($MessageGroup.Count) occurrences]" -ForegroundColor DarkYellow
                }
            }
        }
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✓ All Stages Completed Successfully" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "Total execution time: $([Math]::Round($TotalDuration, 2)) seconds" -ForegroundColor Gray
    Write-Host "Final result: $($FilteredDefenderObjects.Count) privileged objects ready for export" -ForegroundColor Gray
    #endregion
    
    $FilteredDefenderObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}