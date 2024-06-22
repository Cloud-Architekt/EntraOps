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
    }
    else {
        $AadRoleDefinitions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions"
        $AadRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleAssignments"
    }
    #endregion

    # Get all principals for role assignments for further iteration
    $AadRoleAssignmentPrincipals = ($AadRoleAssignments | select-object principalId -Unique).principalId

    #region Collect permanent direct role assignments
    Write-Host "Get details of Entra ID Role Assignments foreach individual principal..."
    $AadRbacActiveAndPermanentAssignments = foreach ($Principal in $AadRoleAssignmentPrincipals) {
        Write-Verbose -Message "Collect basic information for permanent member $($Principal)!"
        try {
            $PrincipalProfile = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($Principal)" -OutputType PSObject
            $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
        }
        catch {
            Write-Warning "Issue to resolve directory object $Principal. Error: $_"
        }

        $AllPrinicpalAadRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleAssignments?$count=true&`$filter=principalId eq '$Principal'" -ConsistencyLevel "eventual"
        foreach ($AadPrincipalRoleAssignment in $AllPrinicpalAadRoleAssignments) {
            $Role = ($AadRoleDefinitions | where-object { $_.id -eq $AadPrincipalRoleAssignment.roleDefinitionId })
            if ($Role.isBuiltIn -eq $True) {
                $RoleType = "BuiltinRole"
                $RoleIsPrivileged = $Role.isPrivileged
                $RoleDefinitionName = $Role.displayName
            }
            else {
                # RoleDefinitionId in Assignment has different Guid than in RoleDefinition, explicit request will resolve original RoleDefinitionName
                # Set RoleDisplayName and RoleDefinitionId from RoleDefinition Endpoint
                # Side Note: Deprecated role definition are just visible by direct RoleDefinition requests
                $OriginalRoleDefinition = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions/$($AadPrincipalRoleAssignment.roleDefinitionId)" -OutputType PSObject
                $AadPrincipalRoleAssignment.roleDefinitionId = $OriginalRoleDefinition.id
                $RoleDefinitionName = $OriginalRoleDefinition.displayName
                $RoleIsPrivileged = $OriginalRoleDefinition.isPrivileged
                if ($OriginalRoleDefinition.isBuiltIn -eq "true") {
                    $RoleType = "BuiltinRole"
                }
                else {
                    $RoleType = "CustomRole"
                }
            }

            <# Workaround to get only ObjectId from RoleAssignmentScopeId #>
            if ($AadPrincipalRoleAssignment.directoryScopeId -ne "/") {
                $GuidPattern = "(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}"
                $RoleAssignmentScopeObjectId = [Regex]::Matches($($AadPrincipalRoleAssignment.directoryScopeId), $GuidPattern).Value

                if ($null -ne $RoleAssignmentScopeObjectId) {
                    try {
                        $RoleAssignmentScopeObject = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($RoleAssignmentScopeObjectId)" -OutputType PSObject)
                        $RoleAssignmentScopeName = "$($RoleAssignmentScopeObject.displayName)"
                    }
                    catch {
                        Write-Warning "Can't found scope name of $($AadPrincipalRoleAssignment.directoryScopeId) for $($Principal)"
                        $RoleAssignmentScopeName = "Unknown name"
                    }
                }
                else {
                    $RoleAssignmentScopeName = $AadPrincipalRoleAssignment.directoryScopeId
                }

            }
            else {
                $RoleAssignmentScopeName = "Directory"
            }

            [pscustomobject]@{
                RoleAssignmentId                = $AadPrincipalRoleAssignment.Id
                RoleName                        = $RoleDefinitionName
                RoleId                          = $AadPrincipalRoleAssignment.roleDefinitionId
                RoleType                        = $RoleType
                IsPrivileged                    = $RoleIsPrivileged
                RoleAssignmentPIMRelated        = $False
                RoleAssignmentPIMAssignmentType = "Permanent"
                RoleAssignmentScopeId           = $AadPrincipalRoleAssignment.directoryScopeId
                RoleAssignmentScopeName         = $RoleAssignmentScopeName
                RoleAssignmentType              = "Direct"
                RoleAssignmentSubType           = ""
                ObjectDisplayName               = $PrincipalProfile.AdditionalProperties.displayName
                ObjectId                        = $Principal
                ObjectType                      = $ObjectType.ToLower()
                TransitiveByObjectId            = $null
                TransitiveByObjectDisplayName   = $null
            }
        }
    }
    #endregion

    #region Collect eligible direct role assignments
    Write-Host "Get details of Entra ID Eligible Role Assignments..."
    $AadEligibleRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleEligibilitySchedules"

    # Filter for role assignments with direct assignments
    $AadEligibleRolePrincipals = ($AadEligibleRoleAssignments | where-object { $_.memberType -eq "Direct" -and $_.status -eq "Provisioned" } | select-object principalId -Unique).principalId
    $AadEligibleUserRoleAssignments = foreach ($Principal in $AadEligibleRolePrincipals) {
        Write-Verbose -Message "Collect basic information for eligible member $($Principal)!"
        try {
            $PrincipalProfile = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($Principal)" -OutputType PSObject
            $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
        }
        catch {
            Write-Warning "Issue to resolve directory object $Principal. Error: $_"
        }
        $AllEligiblePrincipalRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$Principal'" | where-object { $_.memberType -eq "Direct" -and $_.status -eq "Provisioned" }

        foreach ($EligiblePrincipalRoleAssignment in $AllEligiblePrincipalRoleAssignments) {

            $Role = ($AadRoleDefinitions | where-object { $_.id -eq $EligiblePrincipalRoleAssignment.roleDefinitionId })
            if ($Role.isBuiltIn -eq $True) {
                $RoleType = "BuiltinRole"
                $RoleDefinitionName = $Role.displayName
                $RoleIsPrivileged = $Role.IsPrivileged
                # Deprecated role definition are just visible by direct RoleDefinition requests
                if ($null -eq $RoleDefinitionName) {
                    Write-Warning "Dep - $($AadPrincipalRoleAssignment.roleDefinitionId)"
                    $RoleDefinitionName = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/roleManagement/directory/roleDefinitions/$($EligiblePrincipalRoleAssignment.roleDefinitionId)" -OutputType PSObject).displayName
                }
            }
            else {
                # RoleDefinitionId in Assignment has different Guid than in RoleDefinition, explicit request will resolve original RoleDefinitionName
                # Set RoleDisplayName and RoleDefinitionId from RoleDefinition Endpoint
                # Side Note: Deprecated role definition are just visible by direct RoleDefinition requests
                $OriginalRoleDefinition = Invoke-EntraOpsMsGraphQuery -uri "/beta/roleManagement/directory/roleDefinitions/$($EligiblePrincipalRoleAssignment.roleDefinitionId)"
                $EligiblePrincipalRoleAssignment.roleDefinitionId = $OriginalRoleDefinition.id
                $RoleDefinitionName = $OriginalRoleDefinition.displayName
                $RoleIsPrivileged = $OriginalRoleDefinition.isPrivileged
                if ($OriginalRoleDefinition.isBuiltIn -eq "true") {
                    $RoleType = "BuiltinRole"
                }
                else {
                    $RoleType = "CustomRole"
                }
            }

            <# Workaround to get only ObjectId from RoleAssignmentScopeId #>
            if ($EligiblePrincipalRoleAssignment.directoryScopeId -ne "/") {
                $GuidPattern = "(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}"
                $RoleAssignmentScopeObjectId = [Regex]::Matches($EligiblePrincipalRoleAssignment.directoryScopeId, $GuidPattern).Value
                try {
                    $RoleAssignmentScopeObject = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($RoleAssignmentScopeObjectId)" -OutputType PSObject)
                    $RoleAssignmentScopeName = "$($RoleAssignmentScopeObject.displayName)"
                }
                catch {
                    Write-Warning "Can't found $($EligiblePrincipalRoleAssignment.directoryScopeId) for $($Principal)"
                    $RoleAssignmentScopeName = "Unknown name"
                }
            }
            else {
                $RoleAssignmentScopeName = "Directory"
            }

            [pscustomobject]@{
                RoleAssignmentId                = $EligiblePrincipalRoleAssignment.Id
                RoleName                        = $RoleDefinitionName
                RoleId                          = $EligiblePrincipalRoleAssignment.roleDefinitionId
                RoleType                        = $RoleType
                IsPrivileged                    = $RoleIsPrivileged
                RoleAssignmentPIMRelated        = $True
                RoleAssignmentPIMAssignmentType = "Eligible"
                RoleAssignmentScopeId           = $EligiblePrincipalRoleAssignment.directoryScopeId
                RoleAssignmentScopeName         = $RoleAssignmentScopeName
                RoleAssignmentType              = "Direct"
                RoleAssignmentSubType           = ""
                ObjectDisplayName               = $PrincipalProfile.AdditionalProperties.displayName
                ObjectId                        = $Principal
                ObjectType                      = $ObjectType.ToLower()
                TransitiveByObjectId            = $null
                TransitiveByObjectDisplayName   = $null
            }
        }
    }

    #region Remove activated (eligible) assignments and mark time-bounded assignments in permanent assignments
    # Get active assignments to remove it from collection of role assignments
    $AadRoleAssignmentsByPim = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/roleManagement/directory/roleAssignmentScheduleInstances" -OutputType PSObject
    $AadActiveRoleAssignments = $AadRoleAssignmentsByPim | Where-Object { $_.assignmentType -eq 'Activated' }
    $AadTimeBoundedRoleAssignments = $AadRoleAssignmentsByPim | Where-Object { $_.assignmentType -eq 'Assigned' -and $null -ne $_.endDateTime }

    $AadPermanentRoleAssignmentsWithEnrichment = foreach ($AadRbacActiveAndPermanentAssignment in $AadRbacActiveAndPermanentAssignments) {
        if (($AadRbacActiveAndPermanentAssignment.RoleAssignmentId -in $AadActiveRoleAssignments.id) -and ($AadRbacActiveAndPermanentAssignment.RoleAssignmentId -in $AadActiveRoleAssignments.RoleAssignmentOriginId)) {
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMRelated = $True
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMAssignmentType = "Activated"
        }
        elseif ((($AadRbacActiveAndPermanentAssignment.RoleAssignmentId -in $AadTimeBoundedRoleAssignments.id) -and ($AadRbacActiveAndPermanentAssignment.RoleAssignmentId -in $AadTimeBoundedRoleAssignments.RoleAssignmentOriginId))) {
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMRelated = $True
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMAssignmentType = "TimeBounded"
        }
        else {
            Write-Verbose "Permanent assignment $($AadRbacActiveAndPermanentAssignment) No active or eligible assignment detected"
        }
        $AadRbacActiveAndPermanentAssignment
    }

    $AadPermanentRoleAssignments = $AadPermanentRoleAssignmentsWithEnrichment | Where-Object { $_.RoleAssignmentPIMAssignmentType -ne "Activated" }
    #endregion

    # Summarize results with direct permanent (excl. activated roles) and eligible role assignments
    $AllAadRbacAssignments = @()
    $AllAadRbacAssignments += $AadPermanentRoleAssignments
    $AllAadRbacAssignments += $AadEligibleUserRoleAssignments

    #region Collect transitive assignments by group members of Role-Assignable Groups
    if ($ExpandGroupMembers -eq $True) {
        Write-Verbose "Expanding groups for direct or transitive Entra ID role assignments"
        $GroupsWithRbacAssignment = $AllAadRbacAssignments | where-object { $_.ObjectType -eq "group" } | Select-Object -Unique ObjectId, displayName
        $AllTransitiveMembers = $GroupsWithRbacAssignment | foreach-object {
            $GroupObjectDisplayName = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/groups/$($_.ObjectId)" -OutputType PSObject).displayName
            $TransitiveMembers = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $_.ObjectId
            $TransitiveMembers | Add-Member -MemberType NoteProperty -Name "GroupObjectDisplayName" -Value $GroupObjectDisplayName -Force
            $TransitiveMembers | Add-Member -MemberType NoteProperty -Name "GroupObjectId" -Value $_.ObjectId -Force
            return $TransitiveMembers
        }

        $AadRbacTransitiveAssignments = foreach ($RbacAssignmentByGroup in ($AllAadRbacAssignments | where-object { $_.ObjectType -eq "group" }) ) {

            $RbacAssignmentByNestedGroupMembers = $AllTransitiveMembers | Where-Object { $_.GroupObjectId -eq $RbacAssignmentByGroup.ObjectId }

            if ($RbacAssignmentByNestedGroupMembers.Count -gt "0") {
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
            }
            else {
                Write-Warning "Empty group $($RbacAssignmentByGroup.ObjectId)"
            }

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