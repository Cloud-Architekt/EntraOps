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

function Get-EntraOpsPrivilegedEamIntune {
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
    )

    # Configuration for batch processing
    $BatchSize = 100  # Number of objects to process before showing progress

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
    Write-Host "Getting Device Management Roles (for Microsoft Intune)..."

    if ($SampleMode -ne $True) {
        $DeviceMgmtRbacAssignments = Get-EntraOpsPrivilegedDeviceRoles -TenantId $TenantId
    } else {
        Write-Warning "Currently not supported!"
    }

    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    } else {
        $GlobalExclusionList = $null
    }
    #endregion

    #region Get scope tages and assignments
    Write-Host "Getting scope and tags in relation to ..."
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
                Write-Warning "No assignments for $($ScopeTag.DisplayName) - $($ScopeTag.Id)"
            }
        }
    }
    #endregion

    #region Classify all Device Management assignments by classification of assigned objects and their privileged in other RBAC systems
    if ($ApplyClassificationByAssignedObjects -eq $true) {

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
                            Write-Warning "No device for $($ClassifiedPrivilegedPawUser.ObjectUserPrincipalName) found in Intune! $($_)"
                        }
                    }
                } catch {
                    Write-Warning "No device Entra ID Device found for $($ClassifiedPrivilegedPawUser.ObjectDisplayName) - $($ClassifiedPrivilegedPawUser.ObjectId) in Intune"
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
                Write-Warning "No classification found for $($DeviceMgmtRbacAssignment.RoleDefinitionId) with scope $($DeviceMgmtRbacAssignment.RoleAssignmentScopeId)!"
                $DeviceMgmtRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
            }
            $DeviceMgmtRbacAssignment
        }
    } else {
        $DeviceMgmtRbacClassificationsByAssignedObjects = $null
    }
    #endregion

    #region Check if RBAC role action and scope is defined in JSON classification
    Write-Host "Checking if RBAC role action and scope is defined in JSON classification..."
    $IntuneResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $IntuneClassificationFilePath | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions
    $DeviceMgmtRbacClassificationsByJSON = @()
    $DeviceMgmtRbacClassificationsByJSON += foreach ($DeviceMgmtRbacAssignment in $DeviceMgmtRbacAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId) {
        if ($DeviceMgmtRbacAssignment.RoleAssignmentScopeId -ne "/") {
            $DeviceMgmtRbacAssignment.RoleAssignmentScopeId = "$($DeviceMgmtRbacAssignment.RoleAssignmentScopeId)"
        }
        # Role actions are defined for scope and role definition contains an action of the role, otherwise all role actions within role assignment scope will be applied
        if ($SampleMode -eq $True) {
            Write-Warning "Currently not supported!"
        } else {
            $IntuneRoleActions = (Invoke-EntraOpsMsGraphQuery -Method GET -Uri https://graph.microsoft.com/beta/roleManagement/deviceManagement/roleDefinitions -OutputType PSObject) | Where-Object { $_.Id -eq "$($DeviceMgmtRbacAssignment.RoleDefinitionId)" }
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
    #endregion

    #region Apply classification to all assigned privileged users and groups in Device Management
    Write-Host "Classifying of all assigned privileged users and groups in Device Management..."

    # Optimization: Group assignments by ObjectId to avoid O(N^2) filtering
    $DeviceMgmtRbacByObject = $DeviceMgmtRbacClassifications | Group-Object ObjectId -AsHashTable -AsString

    # Optimization: Collect all unique ObjectIds and batch resolve details
    $UniqueObjects = $DeviceMgmtRbacAssignments | Select-Object -Unique ObjectId, ObjectType | Where-Object { $null -ne $_.ObjectId }
    $UniqueObjectIds = $UniqueObjects.ObjectId
    
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
            
            $Classification = @($UniqueClassificationsHash.Values | Sort-Object AdminTierLevel, AdminTierLevelName, Service)
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
                'RoleAssignments'               = $DeviceMgmtRbacClassifiedAssignments
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
    $FilteredIntuneObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}