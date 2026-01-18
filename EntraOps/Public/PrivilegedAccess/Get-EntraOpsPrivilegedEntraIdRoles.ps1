<#
.SYNOPSIS
    Get a list of directory role member assignments in Entra ID.

.DESCRIPTION
    Get a list of directory role member assignments in Entra ID.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER PrincipalTypeFilter
    Filter for principal type. Default is User, Group, ServicePrincipal. Possible values are User, Group, ServicePrincipal.

.PARAMETER ExpandGroupMembers
    Expand group members for transitive role assignments. Default is $true.

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False.

.EXAMPLE
    Get a list of assignment of Entra ID directory roles.
    Get-EntraOpsPrivilegedEntraIdRoles
#>

function Get-EntraOpsPrivilegedEntraIdRoles {
    param (
        [Parameter(Mandatory = $False)]
        [System.String]$TenantId
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("User", "Group", "ServicePrincipal")]
        [Array]$PrincipalTypeFilter = ("User", "Group", "ServicePrincipal")
        ,
        [Parameter(Mandatory = $False)]
        [System.Boolean]$ExpandGroupMembers = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$SampleMode = $False
    )

    # Set Error Action
    $ErrorActionPreference = "Stop"

    #region Get Role Definitions and Role Assignments
    Write-Host "Get Entra ID Role Management Assignments and Role Definition..."
    if ($SampleMode -eq $True) {
        $AadRoleDefinitions = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementRoleDefinitions.json" | ConvertFrom-Json -Depth 10
        $AadRoleAssignments = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementAssignments.json" | ConvertFrom-Json -Depth 10
        $AadEligibleRoleAssignments = @()
        if (Test-Path "$EntraOpsBaseFolder/Samples/AadRoleManagementEligibleAssignments.json") {
            $AadEligibleRoleAssignments = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementEligibleAssignments.json" | ConvertFrom-Json -Depth 10
        }
    } else {
        $AadRoleDefinitions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions?`$select=id,displayName,description,rolePermissions,isBuiltIn"
        $AadRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleAssignments?`$select=id,principalId,roleDefinitionId,directoryScopeId"
        $AadEligibleRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleEligibilitySchedules?`$select=id,principalId,roleDefinitionId,directoryScopeId,memberType,status"
    }

    # Optimization: Build Lookup Tables
    Write-Verbose "Building Role Definition Dictionary..."
    $RoleDefLookup = @{}
    foreach ($Role in $AadRoleDefinitions) { $RoleDefLookup[$Role.id] = $Role }

    # Optimization: Collect all Unique IDs for Batch Resolution
    $IdsToResolve = [System.Collections.Generic.HashSet[string]]::new()
    $GuidPattern = "([0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12})"

    foreach ($Ass in $AadRoleAssignments) {
        if ($Ass.principalId) { $IdsToResolve.Add($Ass.principalId) | Out-Null }
        if ($Ass.directoryScopeId -and $Ass.directoryScopeId -ne "/" -and $Ass.directoryScopeId -match $GuidPattern) {
            $IdsToResolve.Add($Matches[1]) | Out-Null
        }
    }
    $EligibleToProcess = $AadEligibleRoleAssignments | Where-Object { $_.memberType -eq "Direct" -and $_.status -eq "Provisioned" }
    foreach ($Ass in $EligibleToProcess) {
        if ($Ass.principalId) { $IdsToResolve.Add($Ass.principalId) | Out-Null }
        if ($Ass.directoryScopeId -and $Ass.directoryScopeId -ne "/" -and $Ass.directoryScopeId -match $GuidPattern) {
            $IdsToResolve.Add($Matches[1]) | Out-Null
        }
    }

    Write-Host "Resolving $($IdsToResolve.Count) directory objects in batches..."
    $DirObjLookup = @{}
    $IdArray = $IdsToResolve | Select-Object -Unique
    if ($IdArray.Count -gt 0) {
        $TotalBatches = [Math]::Ceiling($IdArray.Count / 1000)
        Write-Verbose "Resolving $($IdArray.Count) directory objects in $TotalBatches batches..."
        for ($i = 0; $i -lt $IdArray.Count; $i += 1000) {
            $CurrentBatch = [Math]::Floor($i / 1000) + 1
            $PercentComplete = [math]::Round(($CurrentBatch / $TotalBatches) * 100, 0)
            Write-Progress -Activity "Resolving Directory Objects" -Status "Processing batch $CurrentBatch of $TotalBatches" -PercentComplete $PercentComplete
            
            $Batch = $IdArray[$i..([Math]::Min($i + 999, $IdArray.Count - 1))]
            # directoryObjects/getByIds allows up to 1000 items
            $Body = @{ ids = $Batch; types = @("directoryObject") } | ConvertTo-Json -Compress
            try {
                $Response = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/directoryObjects/getByIds" -Body $Body -OutputType PSObject
                foreach ($Obj in $Response) { $DirObjLookup[$Obj.id] = $Obj }
            } catch {
                Write-Warning "Failed to resolve directory objects batch: $_"
            }
        }
        Write-Progress -Activity "Resolving Directory Objects" -Completed
    }
    #endregion

    #region Collect permanent direct role assignments
    Write-Host "Get details of Entra ID Role Assignments foreach individual principal..."
    # Iterate over Assignments directly, filtered by local logic instead of Re-Querying API
    $AadRbacActiveAndPermanentAssignments = foreach ($AadPrincipalRoleAssignment in $AadRoleAssignments) {
        $Principal = $AadPrincipalRoleAssignment.principalId
        
        # Resolve Principal
        $ObjectType = "unknown"
        $PrincipalProfile = $null

        if ($DirObjLookup.ContainsKey($Principal)) {
            $PrincipalProfile = $DirObjLookup[$Principal]
        }

        # Fallback: If not found in batch lookup, try individual redundant fetch
        if ($null -eq $PrincipalProfile) {
            try {
                $PrincipalProfile = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($Principal)" -OutputType PSObject
            } catch {
                Write-Warning "Issue to resolve directory object $Principal. Error: $_"
            }
        }

        if ($PrincipalProfile) {
            if ($PrincipalProfile.'@odata.type') {
                $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
            } else {
                # Fallback if odata.type is missing (should not happen on Graph objects)
                Write-Verbose "Object type missing for $Principal"
            }
        }
        
        # Resolve Role
        $RoleDefId = $AadPrincipalRoleAssignment.roleDefinitionId
        $RoleDefinitionName = "Unknown"
        $RoleType = "CustomRole"
        $RoleIsPrivileged = $false

        if ($RoleDefLookup.ContainsKey($RoleDefId)) {
            $Role = $RoleDefLookup[$RoleDefId]
        } else {
            # Fallback for deprecated/hidden roles
            try {
                $Role = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions/$RoleDefId"
                $RoleDefLookup[$RoleDefId] = $Role
            } catch { $Role = $null }
        }

        if ($Role) {
            $RoleDefinitionName = $Role.displayName
            $RoleIsPrivileged = $Role.isPrivileged
            if ($Role.isBuiltIn -eq $True -or $Role.isBuiltIn -eq "true") { 
                $RoleType = "BuiltInRole" 
            }
            if ($Role.templateId) {
                $RoleDefId = $Role.templateId
            }
        }

        # Resolve Scope
        $RoleAssignmentScopeName = "Directory"
        if ($AadPrincipalRoleAssignment.directoryScopeId -ne "/") {
            $ScopeId = $null
            if ($AadPrincipalRoleAssignment.directoryScopeId -match $GuidPattern) {
                $ScopeId = $Matches[1]
            }
            if ($ScopeId -and $DirObjLookup.ContainsKey($ScopeId)) {
                $RoleAssignmentScopeName = $DirObjLookup[$ScopeId].displayName
            } elseif ($ScopeId) {
                try {
                    $ScopeObj = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($ScopeId)" -OutputType PSObject
                    if ($ScopeObj) {
                        $DirObjLookup[$ScopeId] = $ScopeObj 
                        $RoleAssignmentScopeName = $ScopeObj.displayName
                    } else {
                        $RoleAssignmentScopeName = $AadPrincipalRoleAssignment.directoryScopeId
                    }
                } catch {
                    $RoleAssignmentScopeName = $AadPrincipalRoleAssignment.directoryScopeId
                }
            } else {
                $RoleAssignmentScopeName = $AadPrincipalRoleAssignment.directoryScopeId
            }
        }

        [pscustomobject]@{
            RoleAssignmentId                = $AadPrincipalRoleAssignment.Id
            RoleName                        = $RoleDefinitionName
            RoleId                          = $RoleDefId
            RoleType                        = $RoleType
            IsPrivileged                    = $RoleIsPrivileged
            RoleAssignmentPIMRelated        = $False
            RoleAssignmentPIMAssignmentType = "Permanent"
            RoleAssignmentScopeId           = $AadPrincipalRoleAssignment.directoryScopeId
            RoleAssignmentScopeName         = $RoleAssignmentScopeName
            RoleAssignmentType              = "Direct"
            RoleAssignmentSubType           = ""
            ObjectDisplayName               = if ($PrincipalProfile) { $PrincipalProfile.displayName } else { $Principal }
            ObjectId                        = $Principal
            ObjectType                      = $ObjectType.ToLower()
            TransitiveByObjectId            = $null
            TransitiveByObjectDisplayName   = $null
        }
    }
    #endregion

    #region Collect eligible direct role assignments
    Write-Host "Get details of Entra ID Eligible Role Assignments..."
    # Already filtered in EligibleToProcess (from top block)
    $AadEligibleUserRoleAssignments = foreach ($EligiblePrincipalRoleAssignment in $EligibleToProcess) {
        $Principal = $EligiblePrincipalRoleAssignment.principalId
        
        # Resolve Principal
        $ObjectType = "unknown"
        $PrincipalProfile = $null

        if ($DirObjLookup.ContainsKey($Principal)) {
            $PrincipalProfile = $DirObjLookup[$Principal]
        }

        # Fallback
        if ($null -eq $PrincipalProfile) {
            try {
                $PrincipalProfile = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($Principal)" -OutputType PSObject
            } catch {
                Write-Warning "Issue to resolve directory object $Principal. Error: $_"
            }
        }

        if ($PrincipalProfile) {
            if ($PrincipalProfile.'@odata.type') {
                $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
            }
        }

        # Resolve Role
        $RoleDefId = $EligiblePrincipalRoleAssignment.roleDefinitionId
        $RoleDefinitionName = "Unknown"
        $RoleType = "CustomRole"
        $RoleIsPrivileged = $false

        if ($RoleDefLookup.ContainsKey($RoleDefId)) {
            $Role = $RoleDefLookup[$RoleDefId]
        } else {
            # Fallback
            try {
                $Role = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions/$RoleDefId"
                $RoleDefLookup[$RoleDefId] = $Role
            } catch { $Role = $null }
        }

        if ($Role) {
            $RoleDefinitionName = $Role.displayName
            $RoleIsPrivileged = $Role.isPrivileged
            if ($Role.isBuiltIn -eq $True -or $Role.isBuiltIn -eq "true") { 
                $RoleType = "BuiltInRole" 
            }
            if ($Role.templateId) {
                $RoleDefId = $Role.templateId
            }
        }

        # Resolve Scope
        $RoleAssignmentScopeName = "Directory"
        if ($EligiblePrincipalRoleAssignment.directoryScopeId -ne "/") {
            $ScopeId = $null
            if ($EligiblePrincipalRoleAssignment.directoryScopeId -match $GuidPattern) {
                $ScopeId = $Matches[1]
            }
            if ($ScopeId -and $DirObjLookup.ContainsKey($ScopeId)) {
                $RoleAssignmentScopeName = $DirObjLookup[$ScopeId].displayName
            } elseif ($ScopeId) {
                try {
                    $ScopeObj = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($ScopeId)" -OutputType PSObject
                    if ($ScopeObj) {
                        $DirObjLookup[$ScopeId] = $ScopeObj 
                        $RoleAssignmentScopeName = $ScopeObj.displayName
                    } else {
                        $RoleAssignmentScopeName = $EligiblePrincipalRoleAssignment.directoryScopeId
                    }
                } catch {
                    $RoleAssignmentScopeName = $EligiblePrincipalRoleAssignment.directoryScopeId
                }
            } else {
                $RoleAssignmentScopeName = $EligiblePrincipalRoleAssignment.directoryScopeId
            }
        }

        [pscustomobject]@{
            RoleAssignmentId                = $EligiblePrincipalRoleAssignment.Id
            RoleName                        = $RoleDefinitionName
            RoleId                          = $RoleDefId
            RoleType                        = $RoleType
            IsPrivileged                    = $RoleIsPrivileged
            RoleAssignmentPIMRelated        = $True
            RoleAssignmentPIMAssignmentType = "Eligible"
            RoleAssignmentScopeId           = $EligiblePrincipalRoleAssignment.directoryScopeId
            RoleAssignmentScopeName         = $RoleAssignmentScopeName
            RoleAssignmentType              = "Direct"
            RoleAssignmentSubType           = ""
            ObjectDisplayName               = if ($PrincipalProfile) { $PrincipalProfile.displayName } else { $Principal }
            ObjectId                        = $Principal
            ObjectType                      = $ObjectType.ToLower()
            TransitiveByObjectId            = $null
            TransitiveByObjectDisplayName   = $null
        }
    }
    #endregion

    #region Remove activated (eligible) assignments and mark time-bounded assignments in permanent assignments
    # Get active assignments to remove it from collection of role assignments
    $AadRoleAssignmentsByPim = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/roleManagement/directory/roleAssignmentScheduleInstances" -OutputType PSObject
    $AadActiveRoleAssignments = $AadRoleAssignmentsByPim | Where-Object { $_.assignmentType -eq 'Activated' }
    $AadTimeBoundedRoleAssignments = $AadRoleAssignmentsByPim | Where-Object { $_.assignmentType -eq 'Assigned' -and $null -ne $_.endDateTime }

    $AadPermanentRoleAssignmentsWithEnrichment = foreach ($AadRbacActiveAndPermanentAssignment in $AadRbacActiveAndPermanentAssignments) {
        if (($AadRbacActiveAndPermanentAssignment.RoleAssignmentId -in $AadActiveRoleAssignments.id) -and ($AadRbacActiveAndPermanentAssignment.RoleAssignmentId -in $AadActiveRoleAssignments.RoleAssignmentOriginId)) {
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMRelated = $True
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMAssignmentType = "Activated"
        } elseif ((($AadRbacActiveAndPermanentAssignment.RoleAssignmentId -in $AadTimeBoundedRoleAssignments.id) -and ($AadRbacActiveAndPermanentAssignment.RoleAssignmentId -in $AadTimeBoundedRoleAssignments.RoleAssignmentOriginId))) {
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMRelated = $True
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMAssignmentType = "TimeBounded"
        } else {
            Write-Verbose "Permanent assignment $($AadRbacActiveAndPermanentAssignment) No active or eligible assignment detected"
        }
        $AadRbacActiveAndPermanentAssignment
    }

    $AadPermanentRoleAssignments = $AadPermanentRoleAssignmentsWithEnrichment | Where-Object { $_.RoleAssignmentPIMAssignmentType -ne "Activated" }
    #endregion

    # Summarize results with direct permanent (excl.s activated roles) and eligible role assignments
    $AllAadRbacAssignments = @()
    $AllAadRbacAssignments += $AadPermanentRoleAssignments
    $AllAadRbacAssignments += $AadEligibleUserRoleAssignments

    #region Collect transitive assignments by group members of Role-Assignable Groups
    if ($ExpandGroupMembers -eq $True) {    
        Write-Verbose "Expanding groups for direct or transitive Entra ID role assignments"
        $GroupsWithRbacAssignment = $AllAadRbacAssignments | where-object { $_.ObjectType -eq "group" } | Select-Object -Unique ObjectId, ObjectDisplayName
        $AllTransitiveMembers = @()

        foreach ($GroupWithRbacAssignment in $GroupsWithRbacAssignment) {
            $TransitiveMembers = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $($GroupWithRbacAssignment.ObjectId)
            foreach ($TransitiveMember in $TransitiveMembers) {
                $Member = [pscustomobject]@{
                    displayName            = $TransitiveMember.displayName
                    id                     = $TransitiveMember.id
                    '@odata.type'          = $TransitiveMember.'@odata.type'
                    RoleAssignmentSubType  = $TransitiveMember.RoleAssignmentSubType
                    GroupObjectDisplayName = $GroupWithRbacAssignment.ObjectDisplayName
                    GroupObjectId          = $GroupWithRbacAssignment.ObjectId
                }
                $AllTransitiveMembers += $Member
            }
        }

        $AadRbacTransitiveAssignments = [System.Collections.Generic.List[object]]::new()
        foreach ($RbacAssignmentByGroup in ($AllAadRbacAssignments | where-object { $_.ObjectType -eq "group" }) ) {

            $RbacAssignmentByNestedGroupMembers = $AllTransitiveMembers | Where-Object { $_.GroupObjectId -eq $RbacAssignmentByGroup.ObjectId }

            if ($RbacAssignmentByNestedGroupMembers.Count -gt 0) {
                $RbacAssignmentByNestedGroupMembers | foreach-object {
                    [pscustomobject]@{
                        RoleAssignmentId                = $RbacAssignmentByGroup.RoleAssignmentId
                        RoleName                        = $RbacAssignmentByGroup.RoleName
                        RoleId                          = $RbacAssignmentByGroup.RoleId
                        RoleType                        = $RbacAssignmentByGroup.RoleType
                        IsPrivileged                    = $RbacAssignmentByGroup.isPrivileged
                        RoleAssignmentPIMRelated        = $RbacAssignmentByGroup.RoleAssignmentPIMRelated
                        RoleAssignmentPIMAssignmentType = $RbacAssignmentByGroup.RoleAssignmentPIMAssignmentType
                        RoleAssignmentScopeId           = $RbacAssignmentByGroup.RoleAssignmentScopeId
                        RoleAssignmentScopeName         = $RbacAssignmentByGroup.RoleAssignmentScopeName
                        RoleAssignmentType              = "Transitive"
                        RoleAssignmentSubType           = $_.RoleAssignmentSubType
                        ObjectDisplayName               = $_.displayName
                        ObjectId                        = $_.id
                        ObjectType                      = $_.'@odata.type'.Replace("#microsoft.graph.", "").ToLower()
                        TransitiveByObjectId            = $RbacAssignmentByGroup.ObjectId
                        TransitiveByObjectDisplayName   = $_.GroupObjectDisplayName
                    }
                }
            } else {
                Write-Warning "Empty group $($RbacAssignmentByGroup.ObjectId)"
            }

            $AadRbacTransitiveAssignments.Add($TransitiveMember) | Out-Null
        }
    }
    #endregion

    #region Filtering export if needed
    $AllAadRbacAssignments += $AadRbacTransitiveAssignments
    $AllAadRbacAssignments = $AllAadRbacAssignments | where-object { $_.ObjectType -in $PrincipalTypeFilter }
    $AllAadRbacAssignments = $AllAadRbacAssignments | select-object -Unique *
    $AllAadRbacAssignments | Sort-Object RoleAssignmentId, RoleAssignmentType, ObjectId
    #endregion
}