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

.PARAMETER IncludeJustification
    Include the Justification property (documenting a manual classification overwrite) on all Classification
    entries of the returned objects. Default is $false, so the property is not present in the output at all.

.PARAMETER IncludeObjectDetails
    Include descriptive object details in warning output. Defaults to ConsoleOutput.IncludeObjectDetails from
    EntraOpsConfig.json. Object IDs are always shown.
#>

function Get-EntraOpsPrivilegedEAMIntune {
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

    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $IntuneClassificationFilePath = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_DeviceManagement.json" -FolderClassification $FolderClassification

    # Load group → device member mapping for BloodHound edge enrichment (created by Update-EntraOpsClassificationControlPlaneScope)
    $DeviceMembersFile = Join-Path (Split-Path $IntuneClassificationFilePath -Parent) "DeviceManagement_ScopeGroupDeviceMembers.json"
    $DeviceMembersData = if (Test-Path $DeviceMembersFile) {
        Get-Content $DeviceMembersFile -Raw | ConvertFrom-Json
    } else { $null }

    #region Get all role assignments and global exclusions
    #region Stage 1: Fetch Device Management Roles
    $Stage1Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 1/4: Fetching Device Management Roles" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Retrieving Intune device management role assignments and definitions..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 1/4: Fetching Device Management Roles" -Status "Loading role assignments and global exclusions..." -PercentComplete 10

    if ($SampleMode -ne $True) {
        $DeviceMgmtRbacAssignments = Get-EntraOpsPrivilegedDeviceRoles -TenantId $TenantId -WarningMessages $WarningMessages
    } else {
        $WarningMessages.Add([PSCustomObject]@{Type = "Stage1"; Message = "SampleMode currently not supported!" })
    }

    $GlobalExclusionList = Import-EntraOpsGlobalExclusions -Enabled $GlobalExclusion

    $Stage1Duration = ((Get-Date) - $Stage1Start).TotalSeconds
    Write-Host "✓ Stage 1 completed in $([Math]::Round($Stage1Duration, 2)) seconds ($($DeviceMgmtRbacAssignments.Count) role assignments retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 1/4: Fetching Device Management Roles" -Completed
    #endregion

    # Return early if no role assignments found to prevent null index errors
    if ($null -eq $DeviceMgmtRbacAssignments -or @($DeviceMgmtRbacAssignments).Count -eq 0) {
        Write-Warning "No Device Management role assignments found. Returning empty result."
        return @()
    }

    #region Get scope tages and assignments
    #region Stage 2: Fetch Scope Tags
    $Stage2Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 2/4: Fetching Scope Tags" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Retrieving role scope tags and their assignments for Intune device management..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 2/4: Fetching Scope Tags" -Status "Loading scope tags and assignments..." -PercentComplete 25

    $ScopeTags = (Invoke-EntraOpsMsGraphQuery -Method GET -Uri https://graph.microsoft.com/beta/deviceManagement/roleScopeTags -OutputType PSObject)
    # Build scope tag name lookup for display name resolution
    $ScopeTagNameLookup = @{}
    foreach ($ScopeTag in $ScopeTags) {
        $ScopeTagNameLookup["$($ScopeTag.Id)"] = $ScopeTag.DisplayName
    }

    # Resolve display names for directoryScopeIds from role assignments
    # Scope tags are only for visibility, not scope enforcement — directoryScopeIds per assignment is authoritative
    Write-Host "Resolving display names for role assignment directoryScopeIds..." -ForegroundColor Gray
    $ScopeGroupNameCache = @{}
    $AllDirectoryScopeIds = @($DeviceMgmtRbacAssignments | Where-Object { $null -ne $_.DirectoryScopeIds } | ForEach-Object { $_.DirectoryScopeIds } | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)
    $AllGroupIdsToResolve = @($AllDirectoryScopeIds | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)
    if ($AllGroupIdsToResolve.Count -gt 0) {
        try {
            $Body = @{ ids = @($AllGroupIdsToResolve) } | ConvertTo-Json -Depth 3
            $GroupObjects = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "https://graph.microsoft.com/beta/directoryObjects/getByIds" -Body $Body -OutputType PSObject
            foreach ($GroupObj in $GroupObjects) {
                $ScopeGroupNameCache[$GroupObj.id] = $GroupObj.displayName
            }
        } catch {
            Write-Warning "Failed to batch-resolve directory object display names: $($_.Exception.Message)"
        }
        # Fallback for any IDs not resolved
        foreach ($GroupId in $AllGroupIdsToResolve) {
            if (-not $ScopeGroupNameCache.ContainsKey($GroupId)) {
                $ScopeGroupNameCache[$GroupId] = $GroupId
            }
        }
    }
    Write-Host "Resolved display names for $($ScopeGroupNameCache.Count) directory object(s)." -ForegroundColor Gray

    $Stage2Duration = ((Get-Date) - $Stage2Start).TotalSeconds
    Write-Host "✓ Stage 2 completed in $([Math]::Round($Stage2Duration, 2)) seconds ($($ScopeTags.Count) scope tags retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 2/4: Fetching Scope Tags" -Completed
    #endregion

    #region Check if RBAC role action and scope is defined in JSON classification
    #region Stage 3: Classify Role Actions
    $Stage3Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 3/4: Classifying Role Actions" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Checking if RBAC role action and scope is defined in JSON classification..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 3/4: Classifying Role Actions" -Status "Mapping JSON classifications..." -PercentComplete 50

    # Optimization: Pre-fetch all role definitions to avoid N+1 API calls
    $IntuneRoleDefinitionsCache = @{}
    if ($SampleMode -ne $True) {
        Write-Host "Pre-fetching all Intune role definitions..." -ForegroundColor Gray
        $AllIntuneRoles = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/deviceManagement/roleDefinitions" -OutputType PSObject
        foreach ($Role in $AllIntuneRoles) {
            if ($null -ne $Role.id) {
                # Ensure ID is string for consistent lookup
                $IntuneRoleDefinitionsCache["$($Role.id)"] = $Role
            }
        }
        Write-Host "Cached $($IntuneRoleDefinitionsCache.Count) role definitions." -ForegroundColor Gray
    }

    # Build lookup: (RoleDefinitionId, RoleAssignmentScopeId) -> directoryScopeIds for scope matching and TaggedBy enrichment
    # Scoped per role assignment to avoid cross-contamination between different role assignments sharing the same scope tag
    $DirectoryScopesByRoleAndScope = @{}
    foreach ($assignment in $DeviceMgmtRbacAssignments | Where-Object { $_.RoleAssignmentScopeId -ne "/" -and $null -ne $_.DirectoryScopeIds }) {
        $key = "$($assignment.RoleDefinitionId)|$($assignment.RoleAssignmentScopeId)"
        if (-not $DirectoryScopesByRoleAndScope.ContainsKey($key)) {
            $DirectoryScopesByRoleAndScope[$key] = [System.Collections.Generic.List[string]]::new()
        }
        foreach ($dsId in $assignment.DirectoryScopeIds) {
            if (-not [string]::IsNullOrEmpty($dsId) -and -not $DirectoryScopesByRoleAndScope[$key].Contains($dsId)) {
                $DirectoryScopesByRoleAndScope[$key].Add($dsId)
            }
        }
    }

    $IntuneResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $IntuneClassificationFilePath | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions

    # Load classification overwrites (down-/upgrade of entire role definitions) from tenant-specific folder or Templates fallback.
    # Role action overwrites are already baked into the classification file by Update-EntraOpsClassificationControlPlaneScope.
    $ClassificationOverwrites = Import-EntraOpsClassificationOverwrites -RbacSystem "DeviceManagement" -FolderClassification $FolderClassification
    $DeviceMgmtRbacClassificationsByJSON = @()
    $DeviceMgmtRbacClassificationsByJSON += foreach ($DeviceMgmtRbacAssignment in $DeviceMgmtRbacAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId) {
        if ($DeviceMgmtRbacAssignment.RoleAssignmentScopeId -ne "/") {
            $DeviceMgmtRbacAssignment.RoleAssignmentScopeId = "$($DeviceMgmtRbacAssignment.RoleAssignmentScopeId)"
        }
        # Role actions are defined for scope and role definition contains an action of the role, otherwise all role actions within role assignment scope will be applied
        if ($SampleMode -eq $True) {
            $WarningMessages.Add([PSCustomObject]@{Type = "Stage3"; Message = "SampleMode currently not supported!" })
        } else {
            $IntuneRoleActions = $IntuneRoleDefinitionsCache["$($DeviceMgmtRbacAssignment.RoleDefinitionId)"]
        }

        # Scope tags are for visibility only — use directoryScopeIds of this specific assignment for scope matching
        $AppScopeId = "$($DeviceMgmtRbacAssignment.RoleAssignmentScopeId)"

        # Get directoryScopeIds specific to this role definition + scope combination
        $IsScoped = ($AppScopeId -ne "/")
        $RoleAndScopeKey = "$($DeviceMgmtRbacAssignment.RoleDefinitionId)|$AppScopeId"
        $AssignmentDirectoryScopes = @()
        if ($IsScoped -and $DirectoryScopesByRoleAndScope.ContainsKey($RoleAndScopeKey)) {
            $AssignmentDirectoryScopes = @($DirectoryScopesByRoleAndScope[$RoleAndScopeKey])
        }

        $MatchedClassificationByScope = @()
        # Check if RBAC scope is listed in JSON classification.
        # For scoped assignments, the assignment's own directoryScopeIds are matched against
        # RoleAssignmentScopeName (which contains group GUIDs from classification parameters).
        # "/*" matches any scoped (non-root) assignment.
        # "/" matches tenant-wide assignments.
        # Specific GUIDs match against the assignment's directoryScopeIds.
        $MatchedClassificationByScope += foreach ($ClassEntry in $IntuneResourcesByClassificationJSON) {
            $ScopeName = $ClassEntry.RoleAssignmentScopeName

            # Determine scope match
            # Note: Intune uses numeric scope tag IDs (e.g. "2") not path-like scopes,
            # so -like with "/*" pattern does not work here (unlike Defender/EntraID).
            $ScopeMatch = $false
            if ($AppScopeId -eq "/" -and $ScopeName -eq "/") {
                $ScopeMatch = $true
            } elseif ($AppScopeId -ne "/" -and $ScopeName -eq "/*") {
                $ScopeMatch = $true
            } elseif ($AppScopeId -ne "/" -and $ScopeName -ne "/" -and $ScopeName -ne "/*" -and $AssignmentDirectoryScopes.Count -gt 0) {
                # Group GUID match: check if classification scope name is among this assignment's directoryScopeIds
                if ($ScopeName -in $AssignmentDirectoryScopes) {
                    $ScopeMatch = $true
                }
            }

            if ($ScopeMatch) {
                # Exclusion check against this assignment's directoryScopeIds (not all scope tag groups)
                $IsExcluded = $false
                if ($AppScopeId -eq "/") {
                    $IsExcluded = ($ClassEntry.ExcludedRoleAssignmentScopeName -contains "/")
                } elseif ($ScopeName -eq "/*" -and $IsScoped -and $AssignmentDirectoryScopes.Count -gt 0) {
                    # Wildcard match: only exclude if ALL of this assignment's directoryScopeIds are excluded
                    $NonExcludedGroups = @($AssignmentDirectoryScopes | Where-Object { $_ -notin $ClassEntry.ExcludedRoleAssignmentScopeName })
                    $IsExcluded = ($NonExcludedGroups.Count -eq 0)
                } elseif ($ScopeName -ne "/*" -and $ScopeName -ne "/") {
                    # GUID match: check if the specific matched group is excluded
                    $IsExcluded = ($ScopeName -in $ClassEntry.ExcludedRoleAssignmentScopeName)
                }

                if (-not $IsExcluded) {
                    $ClassEntry
                }
            }
        }

        # Guard: does any allowed role action match an in-scope classification? Matchers are
        # precomputed once (loop-invariant) and the probe short-circuits on the first hit instead
        # of materializing the full match set only to test .Count -gt 0.
        $GuardMatchers = @(foreach ($ClassEntry in $MatchedClassificationByScope) {
                Build-EntraOpsClassificationActionMatcher -RoleDefinitionActions $ClassEntry.RoleDefinitionActions -ExcludedRoleDefinitionActions $ClassEntry.ExcludedRoleDefinitionActions
            })
        $HasClassifiedRoleAction = $false
        foreach ($Action in $IntuneRoleActions.rolePermissions.allowedResourceActions) {
            if ([string]::IsNullOrEmpty($Action)) { continue }
            foreach ($Matcher in $GuardMatchers) {
                $AllowedMatch = $Matcher.AllowedExact.Contains($Action)
                if (-not $AllowedMatch) {
                    foreach ($Pattern in $Matcher.AllowedWildcards) { if ($Action -like $Pattern) { $AllowedMatch = $true; break } }
                }
                if (-not $AllowedMatch) { continue }
                $ExcludedMatch = $Matcher.ExcludedExact.Contains($Action)
                if (-not $ExcludedMatch) {
                    foreach ($Pattern in $Matcher.ExcludedWildcards) { if ($Action -like $Pattern) { $ExcludedMatch = $true; break } }
                }
                if (-not $ExcludedMatch) { $HasClassifiedRoleAction = $true; break }
            }
            if ($HasClassifiedRoleAction) { break }
        }

        if ($HasClassifiedRoleAction) {
            # Track which scope name (group GUID or wildcard) triggered each classification match,
            # and which specific groups from this assignment are relevant (non-excluded)
            # Matchers precomputed once per classification entry (loop-invariant across the action
            # loop). This site deliberately checks allowed actions only, like the helper call it
            # replaces - exclusions here are scope-based, handled below per match type.
            $IntuneClassificationMatchers = @(foreach ($ClassEntry in $IntuneResourcesByClassificationJSON) {
                    [pscustomobject]@{
                        Entry   = $ClassEntry
                        Matcher = Build-EntraOpsClassificationActionMatcher -RoleDefinitionActions $ClassEntry.RoleDefinitionActions
                    }
                })
            $ClassifiedWithMatchedScope = @()
            foreach ($IntuneRoleAction in $IntuneRoleActions.rolePermissions.allowedResourceActions) {
                if ([string]::IsNullOrEmpty($IntuneRoleAction)) { continue }
                $ClassifiedWithMatchedScope += foreach ($MatcherEntry in $IntuneClassificationMatchers) {
                    $ClassEntry = $MatcherEntry.Entry
                    $ScopeName = $ClassEntry.RoleAssignmentScopeName

                    # Same scope matching logic as above
                    $ScopeMatch = $false
                    $MatchType = $null
                    if ($AppScopeId -eq "/" -and $ScopeName -eq "/") {
                        $ScopeMatch = $true
                        $MatchType = "root"
                    } elseif ($AppScopeId -ne "/" -and $ScopeName -eq "/*") {
                        $ScopeMatch = $true
                        $MatchType = "wildcard"
                    } elseif ($AppScopeId -ne "/" -and $ScopeName -ne "/" -and $ScopeName -ne "/*" -and $AssignmentDirectoryScopes.Count -gt 0 -and $ScopeName -in $AssignmentDirectoryScopes) {
                        $ScopeMatch = $true
                        $MatchType = "guid"
                    }

                    $ActionMatch = $false
                    if ($ScopeMatch) {
                        $ActionMatch = $MatcherEntry.Matcher.AllowedExact.Contains($IntuneRoleAction)
                        if (-not $ActionMatch) {
                            foreach ($Pattern in $MatcherEntry.Matcher.AllowedWildcards) { if ($IntuneRoleAction -like $Pattern) { $ActionMatch = $true; break } }
                        }
                    }
                    if ($ScopeMatch -and $ActionMatch) {
                        $IsExcluded = $false
                        $EntryMatchedGroups = @()

                        if ($AppScopeId -eq "/") {
                            $IsExcluded = ($ClassEntry.ExcludedRoleAssignmentScopeName -contains "/")
                        } elseif ($MatchType -eq "wildcard" -and $IsScoped -and $AssignmentDirectoryScopes.Count -gt 0) {
                            # Wildcard: filter to only the non-excluded directoryScopeIds from this assignment
                            $EntryMatchedGroups = @($AssignmentDirectoryScopes | Where-Object { $_ -notin $ClassEntry.ExcludedRoleAssignmentScopeName })
                            $IsExcluded = ($EntryMatchedGroups.Count -eq 0)
                        } elseif ($MatchType -eq "guid") {
                            # GUID match: check if the specific matched group is excluded
                            $IsExcluded = ($ScopeName -in $ClassEntry.ExcludedRoleAssignmentScopeName)
                            if (-not $IsExcluded -and $ScopeName -in $AssignmentDirectoryScopes) {
                                $EntryMatchedGroups = @($ScopeName)
                            }
                        }

                        if (-not $IsExcluded) {
                            [PSCustomObject]@{
                                EAMTierLevelName     = $ClassEntry.EAMTierLevelName
                                EAMTierLevelTagValue = $ClassEntry.EAMTierLevelTagValue
                                Service              = $ClassEntry.Service
                                MatchedScopeName     = $ScopeName
                                MatchType            = $MatchType
                                MatchedGroupIds      = $EntryMatchedGroups
                                MatchedAction        = $IntuneRoleAction
                            }
                        }
                    }
                }
            }

            # Group by unique classification and compute per-classification TaggedBy
            $UniqueClassifications = $ClassifiedWithMatchedScope | Select-Object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification = foreach ($UniqueClass in $UniqueClassifications) {
                # Aggregate matched entries for this classification
                $MatchedEntries = @($ClassifiedWithMatchedScope | Where-Object {
                    $_.EAMTierLevelName -eq $UniqueClass.EAMTierLevelName -and
                    $_.EAMTierLevelTagValue -eq $UniqueClass.EAMTierLevelTagValue -and
                    $_.Service -eq $UniqueClass.Service
                })

                # Aggregate matched actions across all entries
                [array]$MatchedActions = @($MatchedEntries.MatchedAction | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)

                if ($IsScoped) {
                    [array]$TaggedByIds = @($MatchedEntries | ForEach-Object { $_.MatchedGroupIds } | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)

                    if ($TaggedByIds.Count -gt 0) {
                        [array]$TaggedByNames = @($TaggedByIds | ForEach-Object { $ScopeGroupNameCache[$_] })
                        $TaggedBySystem = "ScopeTagAssignedGroup"
                    } else {
                        $TaggedByIds = $null
                        $TaggedByNames = $null
                        $TaggedBySystem = $null
                    }
                } else {
                    $TaggedByIds = $null
                    $TaggedByNames = $null
                    $TaggedBySystem = $null
                }

                # Resolve scoped devices from group → device member mapping
                $ScopedObjects = @()
                if ($null -ne $DeviceMembersData) {
                    if ($TaggedByIds.Count -gt 0) {
                        # Scoped assignment: devices from matched groups
                        $ScopedObjects = @($TaggedByIds | ForEach-Object {
                            $grpData = $DeviceMembersData.groupDeviceMembers.$_
                            if ($grpData) { $grpData.deviceMembers }
                        } | Where-Object { $null -ne $_ })
                    } elseif (-not $IsScoped) {
                        # Tenant-wide assignment: all classified devices
                        $ScopedObjects = @($DeviceMembersData.allClassifiedDevices | Where-Object { $null -ne $_ })
                    }
                }

                [PSCustomObject]@{
                    'AdminTierLevel'             = $UniqueClass.EAMTierLevelTagValue
                    'AdminTierLevelName'         = $UniqueClass.EAMTierLevelName
                    'MatchedActions'             = if ($MatchedActions.Count -gt 0) { , @($MatchedActions) } else { $null }
                    'ScopedObjects'              = if ($ScopedObjects.Count -gt 0) { , @($ScopedObjects) } else { $null }
                    'Service'                    = $UniqueClass.Service
                    'TaggedBy'                   = "JSONwithAction"
                    'TaggedByObjectIds'          = $TaggedByIds
                    'TaggedByObjectDisplayNames' = $TaggedByNames
                    'TaggedByRoleSystem'         = $TaggedBySystem
                }
            }

            [PSCustomObject]@{
                'RoleDefinitionId'      = $DeviceMgmtRbacAssignment.RoleDefinitionId
                'RoleAssignmentScopeId' = $DeviceMgmtRbacAssignment.RoleAssignmentScopeId
                'Classification'        = $Classification
            }
        } else {
            $ClassifiedWithMatchedScope = @()
        }
    }
    #endregion

    #region Classify all assigned privileged users and groups in Device Management
    $DeviceMgmtRbacClassifications = foreach ($DeviceMgmtRbacAssignment in $DeviceMgmtRbacAssignments) {
        $DeviceMgmtRbacAssignment = $DeviceMgmtRbacAssignment | Select-Object -ExcludeProperty Classification, DirectoryScopeIds
        $Classification = @()
        $Classification += ($DeviceMgmtRbacClassificationsByJSON | Where-Object { $_.RoleAssignmentScopeId -eq $DeviceMgmtRbacAssignment.RoleAssignmentScopeId -and $_.RoleDefinitionId -eq $DeviceMgmtRbacAssignment.RoleDefinitionId }).Classification
        $Classification = @($Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames, TaggedByRoleSystem, MatchedActions, ScopedObjects, Justification | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy)
        if ($Classification.Count -eq 0) { $Classification = $null }
        $DeviceMgmtRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $DeviceMgmtRbacAssignment
    }

    # Apply role definition classification overwrites (down-/upgrade by RoleDefinitionId or RoleDefinitionName)
    if ($ClassificationOverwrites.RoleDefinitionOverwrites.Count -gt 0) {
        Write-Host "Applying $($ClassificationOverwrites.RoleDefinitionOverwrites.Count) role definition classification overwrite(s) from Classification_RoleDefinitionOverwrites.json..." -ForegroundColor Yellow
        $DeviceMgmtRbacClassifications = Invoke-EntraOpsClassificationRoleOverwrite -RbacClassifications $DeviceMgmtRbacClassifications -RoleDefinitionOverwrites $ClassificationOverwrites.RoleDefinitionOverwrites -RoleSystem "DeviceManagement"
    }

    $Stage3Duration = ((Get-Date) - $Stage3Start).TotalSeconds
    Write-Host "✓ Stage 3 completed in $([Math]::Round($Stage3Duration, 2)) seconds ($($DeviceMgmtRbacClassifications.Count) role assignments classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 3/4: Classifying Role Actions" -Completed
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
    $DeviceMgmtRbacByObject = $DeviceMgmtRbacClassifications | Group-Object ObjectId -AsHashTable -AsString

    # Collect unique objects and resolve details
    # Case-insensitive dedup (mirrors Get-EntraOpsPrivilegedEAMAzure.ps1): Select-Object -Unique compares
    # ObjectId case-sensitively and would emit the same principal twice when ids differ only in casing.
    $UniqueObjects = @(
        $DeviceMgmtRbacAssignments |
            Where-Object { $null -ne $_.ObjectId } |
            Group-Object -Property { "$($_.ObjectId)".ToLowerInvariant() } |
            ForEach-Object { $_.Group[0] | Select-Object ObjectId, ObjectType }
    )
    $ObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution `
        -UniqueObjects $UniqueObjects `
        -TenantId $TenantId `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit

    # Aggregate classifications and build output objects
    $DeviceMgmtRbacClassifiedObjects = Invoke-EntraOpsEAMClassificationAggregation `
        -UniqueObjects $UniqueObjects `
        -ObjectDetailsCache $ObjectDetailsCache `
        -RbacClassificationsByObject $DeviceMgmtRbacByObject `
        -RoleSystem "DeviceManagement" `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit `
        -WarningMessages $WarningMessages
    #endregion

    Write-Host "Applying global exclusions and finalizing results..."
    $FilteredIntuneObjects = $DeviceMgmtRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }

    Write-Host "Completed processing $($FilteredIntuneObjects.Count) privileged objects."

    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages -IncludeObjectDetails $IncludeObjectDetails

    $FilteredIntuneObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Set-EntraOpsEAMClassificationJustification -IncludeJustification:$IncludeJustification | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}
