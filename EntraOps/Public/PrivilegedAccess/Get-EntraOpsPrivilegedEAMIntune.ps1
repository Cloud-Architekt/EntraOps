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

function Get-EntraOpsPrivilegedEAMIntune {
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
        [ValidateSet("Azure", "EntraID", "DeviceManagement")]
        [Array]$FilterClassifiedRbacs = ("Azure", "EntraID", "DeviceManagement")
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
    $ClassificationFileName = "Classification_DeviceManagement.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $IntuneClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    } elseif (Test-Path -Path "$DefaultFolderClassification/Templates/$($ClassificationFileName)") {
        $IntuneClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    } else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }

    #region Get all role assignments and global exclusions
    #region Stage 1: Fetch Device Management Roles
    $Stage1Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 1/5: Fetching Device Management Roles" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Retrieving Intune device management role assignments and definitions..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 1/5: Fetching Device Management Roles" -Status "Loading role assignments and global exclusions..." -PercentComplete 10

    if ($SampleMode -ne $True) {
        $DeviceMgmtRbacAssignments = Get-EntraOpsPrivilegedDeviceRoles -TenantId $TenantId -WarningMessages $WarningMessages
    } else {
        $WarningMessages.Add([PSCustomObject]@{Type = "Stage1"; Message = "SampleMode currently not supported!"})
    }

    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    } else {
        $GlobalExclusionList = $null
    }
    
    $Stage1Duration = ((Get-Date) - $Stage1Start).TotalSeconds
    Write-Host "✓ Stage 1 completed in $([Math]::Round($Stage1Duration, 2)) seconds ($($DeviceMgmtRbacAssignments.Count) role assignments retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 1/5: Fetching Device Management Roles" -Completed
    #endregion

    #region Get scope tages and assignments
    #region Stage 2: Fetch Scope Tags
    $Stage2Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 2/5: Fetching Scope Tags" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Retrieving role scope tags and their assignments for Intune device management..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 2/5: Fetching Scope Tags" -Status "Loading scope tags and assignments..." -PercentComplete 20
    
    $ScopeTags = (Invoke-EntraOpsMsGraphQuery -Method GET -Uri https://graph.microsoft.com/beta/deviceManagement/roleScopeTags -OutputType PSObject)
    # In research, replacement of the workaround solution (see blow) by using Get-MgBetaDeviceManagementDeviceCategory?

    $ScopeTagsAssignments = foreach ($ScopeTag in $ScopeTags) {
        $AssignmentIds = (Invoke-EntraOpsMsGraphQuery -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$($ScopeTag.Id)/assignments" -OutputType PSObject).id
        foreach ($AssignmentId in $AssignmentIds) {
            if ($null -ne $AssignmentId) {
                [PSCustomObject]@{
                    'ScopeTagName' = $ScopeTag.DisplayName
                    'ScopeTagId'   = $ScopeTag.Id
                    'AssignmentId' = $AssignmentId.Replace("_0", "")
                }
            } else {
                $WarningMessages.Add([PSCustomObject]@{Type = "Stage2"; Message = "No assignments for $($ScopeTag.DisplayName) - $($ScopeTag.Id)"})
            }
        }
    }
    
    $Stage2Duration = ((Get-Date) - $Stage2Start).TotalSeconds
    Write-Host "✓ Stage 2 completed in $([Math]::Round($Stage2Duration, 2)) seconds ($($ScopeTags.Count) scope tags retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 2/5: Fetching Scope Tags" -Completed
    #endregion

    #region Classify all Device Management assignments by classification of assigned objects and their privileged in other RBAC systems
    if ($ApplyClassificationByAssignedObjects -eq $true) {
        #region Stage 3: Classify PAW Devices (Optional)
        $Stage3Start = Get-Date
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Stage 3/5: Classifying PAW Devices (Optional)" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "Analyzing privileged user PAW devices and applying inherited classifications from other RBAC systems..." -ForegroundColor Gray
        Write-Progress -Activity "Stage 3/5: Classifying PAW Devices" -Status "Loading privileged user devices..." -PercentComplete 35

        # Get scope for classification of privileged users and PAW devices
        Write-Host "Getting Intune Device ID and details of classified privileged users to build classification for PAW devices..."
        $RbacPawDevices = @()
        $MatchedClassificationPawDevices += foreach ($RbacSystem in $FilterClassifiedRbacs) {
            # Get Classification of Privileged Users by individual RBAC System including associated PAW devices
            $ClassificationSource = $FolderClassifiedObjects + "/" + $RbacSystem + "/" + $RbacSystem + ".json"
            $ClassifiedPrivilegedPawUsers = Get-Content -Path $ClassificationSource -ErrorAction SilentlyContinue | ConvertFrom-Json -Depth 10 | Where-Object { $_.ObjectType -eq "user" -and $_.ObjectSubType -ne "Guest" }
            # Checking if associated PAW device ID exists in Intune or User is Owner of Devices
            $RbacPawDevices += foreach ($ClassifiedPrivilegedPawUser in $ClassifiedPrivilegedPawUsers) {
                $Devices = @()

                Write-Host "Checking Device ID in Associated PAW Device custom attribute in Intune..."
                try {
                    if ($ClassifiedPrivilegedPawUser.AssociatedPawDevice.Count -gt 0) {
                        $DeviceIds = (Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId+eq+'$($ClassifiedPrivilegedPawUser.AssociatedPawDevice)'&`$select=id,userId,userPrincipalName,azureADDeviceId,roleScopeTagIds" -OutputType PSObject).id
                        if ($Null -ne $DeviceIds) {
                            # Parallelize device lookups for better performance
                            if ($DeviceIds.Count -gt 3) {
                                $Devices += $DeviceIds | ForEach-Object -Parallel {
                                    $ModulePath = $using:PSScriptRoot
                                    Import-Module "$ModulePath/../../EntraOps.psm1" -Force -WarningAction SilentlyContinue
                                    (Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/deviceManagement/managedDevices/$($_)?`$select=id,userId,userPrincipalName,azureADDeviceId,roleScopeTagIds" -OutputType PSObject)
                                } -ThrottleLimit 10
                            } else {
                                # For small counts, sequential is fine
                                $Devices += Foreach ($DeviceId in $DeviceIds) {
                                    (Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/deviceManagement/managedDevices/$($DeviceId)?`$select=id,userId,userPrincipalName,azureADDeviceId,roleScopeTagIds" -OutputType PSObject)
                                }
                            }                           
                        } else {
                            Write-Output "No device for Entra ID DeviceId $($ClassifiedPrivilegedPawUser.AssociatedPawDevice) of $($ClassifiedPrivilegedPawUser.ObjectDisplayName) found in Intune!"
                        }
                    }
                } catch {
                    Write-Output "No device with Entra ID DeviceId $($ClassifiedPrivilegedPawUser.AssociatedPawDevice) of $($ClassifiedPrivilegedPawUser.ObjectDisplayName) - $($ClassifiedPrivilegedPawUser.ObjectId) found in Intune!"
                }

                Write-Host "Checking Owner attribute in Intune..."
                try {
                    if ($Null -ne $ClassifiedPrivilegedPawUser.ObjectUserPrincipalName) {
                    
                        $DeviceIds = (Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/deviceManagement/managedDevices?`$filter=userPrincipalName+eq+'$($ClassifiedPrivilegedPawUser.ObjectUserPrincipalName)'" -OutputType PSObject).id
                        if ($Null -ne $DeviceIds) {
                            $Devices += Foreach ($DeviceId in $DeviceIds) {
                                (Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/deviceManagement/managedDevices/$($DeviceId)" -OutputType PSObject) | Select-Object id, userId, userPrincipalName, azureADDeviceId, roleScopeTagIds
                            } 
                        } else {
                             $WarningMessages.Add([PSCustomObject]@{Type = "Stage3"; Message = "No device for $($ClassifiedPrivilegedPawUser.ObjectUserPrincipalName) found in Intune! $($_)"})
                        }
                    }
                } catch {
                    $WarningMessages.Add([PSCustomObject]@{Type = "Stage3"; Message = "No device Entra ID Device found for $($ClassifiedPrivilegedPawUser.ObjectDisplayName) - $($ClassifiedPrivilegedPawUser.ObjectId) in Intune"})
                }
                # Summarize all devices of classified privileged user
                $Devices = $Devices | Where-Object { $_.id -ne $null } | Select-Object -Unique *
                $Devices | Add-Member -NotePropertyName Classification -NotePropertyValue $ClassifiedPrivilegedPawUser.Classification -Force
                $Devices
            }
            $RbacPawDevices | Select-Object -Unique *
        }

        Write-Host "Correlate ScopeTagName and AssignmentId..."
        $ClassifiedScopeTagsAssignments = @()
        $ClassifiedScopeTagsAssignments = foreach ($ScopeTagsAssignment in $ScopeTagsAssignments) {
            $DeviceClassifications = ($MatchedClassificationPawDevices | Where-Object { $_.roleScopeTagIds -contains $ScopeTagsAssignment.ScopeTagId } | Select-Object -Unique *).Classification | Select-Object -Unique *
            $ScopeTagsAssignment | Add-Member -NotePropertyName Classification -NotePropertyValue $DeviceClassifications -Force
            $ScopeTagsAssignment
        }        


        Write-Host "Classifiying of all Device Management assignments by classification of assigned and classified catalog objects"        
        $DeviceMgmtRbacClassificationsByAssignedObjects = @()
        $DeviceMgmtRbacClassificationsByAssignedObjects += foreach ($DeviceMgmtRbacAssignment in $DeviceMgmtRbacAssignments) {
            $Classification = @()
            if ($DeviceMgmtRbacAssignment.RoleAssignmentScopeId -eq "/") {
                $Classification += ($MatchedClassificationPawDevices).Classification | Sort-Object AdminTierLevel | Select-Object -Unique *
                $DeviceMgmtRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
                $DeviceMgmtRbacAssignment.Classification | ForEach-Object { $_ | Add-Member -NotePropertyName "TaggedBy" -NotePropertyValue "AssignedDeviceObjects" -Force }
            } else {
                $Classification += ($ClassifiedScopeTagsAssignments | Where-Object { $_.AssignmentId -eq $($DeviceMgmtRbacAssignment.RoleAssignmentScopeId) }).Classification | Sort-Object AdminTierLevel | Select-Object -Unique *
                $DeviceMgmtRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
                $DeviceMgmtRbacAssignment.Classification | ForEach-Object { $_ | Add-Member -NotePropertyName "TaggedBy" -NotePropertyValue "AssignedDeviceObjects" -Force }
            }
            if ($Classification.count -eq "0") {
                $WarningMessages.Add([PSCustomObject]@{Type = "Stage3"; Message = "No classification found for $($DeviceMgmtRbacAssignment.RoleDefinitionId) with scope $($DeviceMgmtRbacAssignment.RoleAssignmentScopeId)!"})
                $DeviceMgmtRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
            }
            $DeviceMgmtRbacAssignment
        }
    } else {
        $DeviceMgmtRbacClassificationsByAssignedObjects = $null
    }
    #endregion

    #region Check if RBAC role action and scope is defined in JSON classification
    #region Stage 4: Classify Role Actions
    $Stage4Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 4/5: Classifying Role Actions" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Checking if RBAC role action and scope is defined in JSON classification..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 4/5: Classifying Role Actions" -Status "Mapping JSON classifications..." -PercentComplete 60

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

    $IntuneResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $IntuneClassificationFilePath | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions
    $DeviceMgmtRbacClassificationsByJSON = @()
    $DeviceMgmtRbacClassificationsByJSON += foreach ($DeviceMgmtRbacAssignment in $DeviceMgmtRbacAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId) {
        if ($DeviceMgmtRbacAssignment.RoleAssignmentScopeId -ne "/") {
            $DeviceMgmtRbacAssignment.RoleAssignmentScopeId = "$($DeviceMgmtRbacAssignment.RoleAssignmentScopeId)"
        }
        # Role actions are defined for scope and role definition contains an action of the role, otherwise all role actions within role assignment scope will be applied
        if ($SampleMode -eq $True) {
            $WarningMessages.Add([PSCustomObject]@{Type = "Stage4"; Message = "SampleMode currently not supported!"})
        } else {
             $IntuneRoleActions = $IntuneRoleDefinitionsCache["$($DeviceMgmtRbacAssignment.RoleDefinitionId)"]
        }

        $MatchedClassificationByScope = @()
        # Check if RBAC scope is listed in JSON by wildcard in RoleAssignmentScope (e.g. /azops-rg/*)
        $MatchedClassificationByScope += $IntuneResourcesByClassificationJSON | foreach-object {
            $Classification = $_
            $Classification | where-object { $DeviceMgmtRbacAssignment.RoleAssignmentScopeId -like $Classification.RoleAssignmentScopeName -and $DeviceMgmtRbacAssignment.RoleAssignmentScopeId -notcontains $Classification.ExcludedRoleAssignmentScopeName }
        }

        # Check if role action and scope exists in JSON definition
        $IntuneRoleActionsInJsonDefinition = @()
        $IntuneRoleActionsInJsonDefinition = foreach ($Action in $IntuneRoleActions.rolePermissions.allowedResourceActions) {
            $MatchedClassificationByScope | Where-Object { $_.RoleDefinitionActions -Contains $Action -and $Classification.ExcludedRoleDefinitionActions -notcontains $_.RoleDefinitionActions }
        }


        if (($IntuneRoleActionsInJsonDefinition.Count -gt 0)) {
            $ClassifiedDeviceMgmtRbacRoleWithActions = @()
            foreach ($IntuneRoleAction in $IntuneRoleActions.rolePermissions.allowedResourceActions) {
                $ClassifiedDeviceMgmtRbacRoleWithActions += $IntuneResourcesByClassificationJSON | Where-Object { $IntuneRoleAction -in $_.RoleDefinitionActions -and $_.RoleAssignmentScopeName -contains $DeviceMgmtRbacAssignment.RoleAssignmentScopeId -and $_.ExcludedRoleAssignmentScopeName -notcontains $DeviceMgmtRbacAssignment.RoleAssignmentScopeId }
            }
            $ClassifiedDeviceMgmtRbacRoleWithActions = $ClassifiedDeviceMgmtRbacRoleWithActions | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification = $ClassifiedDeviceMgmtRbacRoleWithActions | ForEach-Object {
                [PSCustomObject]@{
                    'AdminTierLevel'     = $_.EAMTierLevelTagValue
                    'AdminTierLevelName' = $_.EAMTierLevelName
                    'Service'            = $_.Service
                    'TaggedBy'           = "JSONwithAction"
                }
            }

            [PSCustomObject]@{
                'RoleDefinitionId'      = $DeviceMgmtRbacAssignment.RoleDefinitionId
                'RoleAssignmentScopeId' = $DeviceMgmtRbacAssignment.RoleAssignmentScopeId
                'Classification'        = $Classification
            }
        } else {
            $ClassifiedDeviceMgmtRbacRoleWithActions = @()
        }
    }
    #endregion

    #region Classify all assigned privileged users and groups in Device Management
    $DeviceMgmtRbacClassifications = foreach ($DeviceMgmtRbacAssignment in $DeviceMgmtRbacAssignments) {
        $DeviceMgmtRbacAssignment = $DeviceMgmtRbacAssignment | Select-Object -ExcludeProperty Classification
        $Classification = @()
        $Classification += ($DeviceMgmtRbacClassificationsByAssignedObjects | Where-Object { $_.RoleAssignmentScopeId -contains $DeviceMgmtRbacAssignment.RoleAssignmentScopeId }).Classification
        $Classification += ($DeviceMgmtRbacClassificationsByJSON | Where-Object { $_.RoleAssignmentScopeId -contains $DeviceMgmtRbacAssignment.RoleAssignmentScopeId -and $_.RoleDefinitionId -eq $DeviceMgmtRbacAssignment.RoleDefinitionId }).Classification
        $Classification = $Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy
        $DeviceMgmtRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $DeviceMgmtRbacAssignment
    }
    
    $Stage4Duration = ((Get-Date) - $Stage4Start).TotalSeconds
    Write-Host "✓ Stage 4 completed in $([Math]::Round($Stage4Duration, 2)) seconds ($($DeviceMgmtRbacClassifications.Count) role assignments classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 4/5: Classifying Role Actions" -Completed
    #endregion

    #region Apply classification to all assigned privileged users and groups in Device Management
    #region Stage 5: Resolve and Finalize Objects
    $Stage5Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 5/5: Resolving Object Details and Finalizing" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Enriching principals with detailed attributes and applying exclusions..." -ForegroundColor Gray

    # Optimization: Group assignments by ObjectId to avoid O(N^2) filtering
    $DeviceMgmtRbacByObject = $DeviceMgmtRbacClassifications | Group-Object ObjectId -AsHashTable -AsString

    # Optimization: Collect all unique ObjectIds and batch resolve details
    $UniqueObjects = $DeviceMgmtRbacAssignments | Select-Object -Unique ObjectId, ObjectType | Where-Object { $null -ne $_.ObjectId }
    
    # Use helper function for parallel/sequential object resolution
    $ObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution `
        -UniqueObjects $UniqueObjects `
        -TenantId $TenantId `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit

    $DeviceMgmtRbacClassifiedObjects = $UniqueObjects | ForEach-Object {
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

            # RBAC Assignments
            $DeviceMgmtRbacClassifiedAssignments = $DeviceMgmtRbacByObject[$ObjectId]

            # Classification - use hashtable for unique aggregation
            $UniqueClassificationsHash = @{}
            foreach ($Assignment in $DeviceMgmtRbacClassifiedAssignments) {
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
                'RoleSystem'                    = "DeviceManagement"
                'Classification'                = $Classification
                'RoleAssignments'               = @($DeviceMgmtRbacClassifiedAssignments | Sort-Object RoleAssignmentId)
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
    #endregion
    
    Write-Host "Applying global exclusions and finalizing results..."
    $FilteredIntuneObjects = $DeviceMgmtRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }
    
    Write-Host "Completed processing $($FilteredIntuneObjects.Count) privileged objects."

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

    $FilteredIntuneObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}