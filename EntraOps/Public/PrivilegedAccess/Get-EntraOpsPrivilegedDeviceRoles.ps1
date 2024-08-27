<#
.SYNOPSIS
    Get a list of directory role member assignments in Microsoft Intune.

.DESCRIPTION
    Get a list of RBAC member assignments in Microsoft Intune.

.PARAMETER TenantId
    Tenant ID of the Microsoft Microsoft Intune tenant. Default is the current tenant ID.

.PARAMETER PrincipalTypeFilter
    Filter for principal type. Default is User, Group, ServicePrincipal. Possible values are User, Group, ServicePrincipal.

.PARAMETER ExpandGroupMembers
    Expand group members for transitive role assignments. Default is $true.

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False.

.EXAMPLE
    Get a list of assignment of Microsoft Intune roles.
    Get-EntraOpsPrivilegedDeviceRoles
#>

function Get-EntraOpsPrivilegedDeviceRoles {
    param (
        [Parameter(Mandatory = $False)]
        [System.String]$TenantId = (Get-AzContext).Tenant.id
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
    Write-Host "Get Device Management Role Management Assignments and Role Definition..."
    if ($SampleMode -eq $True) {
        Write-Warning "Not supported yet!"
    }
    else {
        $DeviceMgmtRoleDefinitions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/deviceManagement/roleDefinitions" -OutputType PSObject
        $DeviceMgmtRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/deviceManagement/roleAssignments" -OutputType PSObject
    }
    #endregion

    #region Get Scope and tags
    Write-Verbose -Message "Getting scope and tags for scope name ..."
    $ScopeTags = (Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/deviceManagement/roleScopeTags" -OutputType PSObject)
    # In research, replacement of the workaround solution (see blow) by using Get-MgBetaDeviceManagementDeviceCategory?
    #endregion

    #region Get role assignments for all permanent role member
    Write-Host "Get details of Device Management Role Assignments foreach individual principal..."    
    $DeviceMgmtRoleAssignmentPrincipals = ($DeviceMgmtRoleAssignments | select-object -ExpandProperty principalIds -Unique)
    $DeviceMgmtPermanentRbacAssignments = foreach ($Principal in $DeviceMgmtRoleAssignmentPrincipals) {
        Write-Verbose "Get identity information from permanent member $Principal"
        try {
            $PrincipalProfile = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/directoryObjects/$($Principal)" -OutputType PSObject
            $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
        }
        catch {
            Write-Host $_
            Write-Error "Issue to resolve directory object $Principal"
        }

        #Troubleshooting
        #$AllPrinicpalDeviceMgmtRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/deviceManagement/roleAssignments?$filter=principalId eq '$Principal'"

        $AllPrinicpalDeviceMgmtRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/deviceManagement/RoleAssignments?$count=true&`$filter=principalIds/any(a:a+eq+'$Principal')" -ConsistencyLevel "eventual"

        foreach ($DeviceMgmtPrincipalRoleAssignment in $AllPrinicpalDeviceMgmtRoleAssignments) {

            $Role = ($DeviceMgmtRoleDefinitions | where-object { $_.id -eq $DeviceMgmtPrincipalRoleAssignment.roleDefinitionId })

            if ($null -eq $Role) { Write-Warning "Role is empty $(DeviceMgmtPrincipalRoleAssignment.id)" }
            # Directory Scope is multi-value
            foreach ($directoryScopeId in $DeviceMgmtPrincipalRoleAssignment.directoryScopeIds) {

                # Get scope name from tags
                if ($directoryScopeId -ne "/") {
                    $RoleAssignmentScopeName = foreach ($appScopeId in $DeviceMgmtPrincipalRoleAssignment.appScopeIds) {
                        $ScopeTags | Where-Object { $_.Id -eq $appScopeId } | Select-Object -ExpandProperty displayName
                    }
                }
                else {
                    $RoleAssignmentScopeName = "Tenant-wide"
                }

                [pscustomobject]@{
                    RoleAssignmentId              = $DeviceMgmtPrincipalRoleAssignment.Id
                    RoleAssignmentScopeId         = $directoryScopeId
                    RoleAssignmentScopeName       = $RoleAssignmentScopeName
                    RoleAssignmentType            = "Direct"
                    RoleAssignmentSubType         = ""
                    PIMManagedRole                = $False
                    PIMAssignmentType             = "Permanent"
                    RoleDefinitionName            = $Role.displayName
                    RoleDefinitionId              = $Role.id
                    RoleType                      = if ($Role.isBuiltIn -eq $True) { "Built-In" } else { "Custom" }
                    RoleIsPrivileged              = $Role.isPrivileged
                    ObjectId                      = $Principal
                    ObjectType                    = $ObjectType
                    TransitiveByObjectId          = ""
                    TransitiveByObjectDisplayName = ""
                }
            }
        }
    }
    #endregion

    # Summarize results with direct permanent (excl. activated roles) and eligible role assignments
    $AllDeviceMgmtRbacAssignments = @()
    $AllDeviceMgmtRbacAssignments += $DeviceMgmtPermanentRbacAssignments
    
    #region Collect transitive assignments by group members of Role-Assignable Groups or Security Groups
    if ($ExpandGroupMembers -eq $True) {
        Write-Verbose -Message "Expanding groups for direct or transitive Intune role assignments"
        # DeviceMgmtRbacAssignments
        $GroupsWithRbacAssignment = $AllDeviceMgmtRbacAssignments | where-object { $_.ObjectType -eq "Group" } | Select-Object -Unique ObjectId, displayName
        $AllTransitiveMembers = $GroupsWithRbacAssignment | foreach-object {
            $GroupObjectDisplayName = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/groups/$($_.ObjectId)" -OutputType PSObject).displayName
            $TransitiveMembers = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $_.ObjectId
            $TransitiveMembers | Add-Member -MemberType NoteProperty -Name "GroupObjectDisplayName" -Value $GroupObjectDisplayName -Force
            $TransitiveMembers | Add-Member -MemberType NoteProperty -Name "GroupObjectId" -Value $_.ObjectId -Force
            return $TransitiveMembers
        }

        $DeviceMgmtTransitiveRbacAssignments = foreach ($RbacAssignmentByGroup in ($AllDeviceMgmtRbacAssignments | where-object { $_.ObjectType -eq "group" }) ) {

            $RbacAssignmentByNestedGroupMembers = $AllTransitiveMembers | Where-Object { $_.GroupObjectId -eq $RbacAssignmentByGroup.ObjectId }

            if ($RbacAssignmentByNestedGroupMembers.Count -gt "0") {
                $RbacAssignmentByNestedGroupMembers | foreach-object {
                    [pscustomobject]@{
                        RoleAssignmentId              = $RbacAssignmentByGroup.RoleAssignmentId
                        RoleAssignmentScopeId         = $RbacAssignmentByGroup.RoleAssignmentScopeId
                        RoleAssignmentScopeName       = $RbacAssignmentByGroup.RoleAssignmentScopeName
                        RoleAssignmentType            = "Transitive"
                        RoleAssignmentSubType         = $_.RoleAssignmentSubType
                        PIMManagedRole                = $RbacAssignmentByGroup.PIMManagedRole
                        PIMAssignmentType             = $RbacAssignmentByGroup.PIMAssignmentType
                        RoleDefinitionName            = $RbacAssignmentByGroup.RoleDefinitionName
                        RoleDefinitionId              = $RbacAssignmentByGroup.RoleDefinitionId
                        RoleType                      = $RbacAssignmentByGroup.RoleType
                        RoleIsPrivileged              = $Role.isPrivileged
                        ObjectId                      = $_.Id
                        ObjectType                    = $_.'@odata.type'.Replace("#microsoft.graph.", "").ToLower()
                        TransitiveByObjectId          = $RbacAssignmentByGroup.ObjectId
                        TransitiveByObjectDisplayName = $_.GroupObjectDisplayName
                    }
                }
            }
            else {
                Write-Warning "Empty group $($RbacAssignmentByGroup.ObjectId) - $($GroupObjectDisplayName)"
            }
        }
    }
    #endregion

    #region Filtering export if needed
    $AllDeviceMgmtRbacAssignments += $DeviceMgmtTransitiveRbacAssignments
    $AllDeviceMgmtRbacAssignments = $AllDeviceMgmtRbacAssignments | where-object { $_.ObjectType -in $PrincipalTypeFilter }
    $AllDeviceMgmtRbacAssignments = $AllDeviceMgmtRbacAssignments | select-object -Unique *
    $AllDeviceMgmtRbacAssignments | Sort-Object RoleAssignmentId, RoleAssignmentType, ObjectId
    #endregion
}