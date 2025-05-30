<#
.SYNOPSIS
    Get a list of directory role member assignments in Microsoft Defender.

.DESCRIPTION
    Get a list of RBAC member assignments in Microsoft Defender.

.PARAMETER TenantId
    Tenant ID of the Microsoft Microsoft Defender tenant. Default is the current tenant ID.

.PARAMETER PrincipalTypeFilter
    Filter for principal type. Default is User, Group, ServicePrincipal. Possible values are User, Group, ServicePrincipal.

.PARAMETER ExpandGroupMembers
    Expand group members for transitive role assignments. Default is $true.

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False.

.EXAMPLE
    Get a list of assignment of Microsoft Defender roles.
    Get-EntraOpsPrivilegedDefenderRoles
#>

function Get-EntraOpsPrivilegedDefenderRoles {
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
    Write-Host "Get Defender Role Management Assignments and Role Definition..."
    if ($SampleMode -eq $True) {
        Write-Warning "Not supported yet!"
    } else {
        $DefenderRoleDefinitions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/defender/roleDefinitions" -OutputType PSObject
        $DefenderRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/defender/roleAssignments" -OutputType PSObject
    }
    #endregion


    #region Get role assignments for all permanent role member
    Write-Host "Get details of Defender Role Assignments foreach individual principal..."
    if (![string]::IsNullOrWhiteSpace($DefenderRoleAssignments.id)) {
        $DefenderRoleAssignmentPrincipals = ($DefenderRoleAssignments | select-object -ExpandProperty principalIds -Unique)
        $DefenderPermanentRbacAssignments = foreach ($Principal in $DefenderRoleAssignmentPrincipals) {
            Write-Verbose "Get identity information from permanent member $Principal"
            try {
                $PrincipalProfile = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/directoryObjects/$($Principal)" -OutputType PSObject
                $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
            } catch {
                Write-Host $_
                Write-Error "Issue to resolve directory object $Principal"
            }

            $AllPrinicpalDefenderRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/defender/RoleAssignments?$count=true&`$filter=principalIds/any(a:a+eq+'$Principal')" -ConsistencyLevel "eventual" -OutputType PSObject

            foreach ($DefenderPrincipalRoleAssignment in $AllPrinicpalDefenderRoleAssignments) {

                $Role = ($DefenderRoleDefinitions | where-object { $_.id -eq $DefenderPrincipalRoleAssignment.roleDefinitionId })

                if ($null -eq $Role) { Write-Warning "Role definition is empty or does not exist for Role Assignment $($DefenderPrincipalRoleAssignment.id)" }

                if ( [string]::IsNullOrEmpty($DefenderPrincipalRoleAssignment.directoryScopeIds) ) {
                    # Directory Scope Id is null if the role is assigned to all devices or all users, only scoping on both object types includes "/" as directoryScopeId
                    # No indicator to identify the scope type, so empty value is used for considering RBAC role without specific directoryScopeId
                    $DefenderPrincipalRoleAssignment.directoryScopeIds = "/"
                }

                foreach ($directoryScopeId in $DefenderPrincipalRoleAssignment.directoryScopeIds) {
                    # Get scope name from tags
                    if ($directoryScopeId -ne "/") {
                        $RoleAssignmentScopeName = foreach ($appScopeId in $DefenderPrincipalRoleAssignment.appScopeIds) {
                            $ScopeTags | Where-Object { $_.Id -eq $appScopeId } | Select-Object -ExpandProperty displayName
                        }
                    } elseif ($directoryScopeId -eq "/") {
                        $RoleAssignmentScopeName = "Tenant-wide"
                    } else {
                        Write-Warning "No scope name found for directoryScopeId $directoryScopeId"
                    }

                    # Check for restriction of Device Groups
                    

                    $RoleAssignmentScopeName | foreach-object {
                        [pscustomobject]@{
                            RoleAssignmentId              = $DefenderPrincipalRoleAssignment.Id
                            RoleAssignmentScopeId         = $directoryScopeId
                            RoleAssignmentScopeName       = $_
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
        }
    } else {
        Write-Warning "No Defender Role Assignments found!"
        $DefenderPermanentRbacAssignments = $null
    }

    #endregion

    # Summarize results with direct permanent (excl. activated roles) and eligible role assignments
    $AllDefenderRbacAssignments = @()
    $AllDefenderRbacAssignments += $DefenderPermanentRbacAssignments

    #region Collect transitive assignments by group members of Role-Assignable Groups or Security Groups
    if ($ExpandGroupMembers -eq $True) {
        Write-Verbose -Message "Expanding groups for direct or transitive Microsoft Defender XDR role assignments"
        # DefenderRbacAssignments
        $GroupsWithRbacAssignment = $AllDefenderRbacAssignments | where-object { $_.ObjectType -eq "Group" } | Select-Object -Unique ObjectId, displayName
        $AllTransitiveMembers = $GroupsWithRbacAssignment | foreach-object {
            $GroupObjectDisplayName = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/groups/$($_.ObjectId)" -OutputType PSObject).displayName
            $TransitiveMembers = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $_.ObjectId
            $TransitiveMembers | Add-Member -MemberType NoteProperty -Name "GroupObjectDisplayName" -Value $GroupObjectDisplayName -Force
            $TransitiveMembers | Add-Member -MemberType NoteProperty -Name "GroupObjectId" -Value $_.ObjectId -Force
            return $TransitiveMembers
        }

        $DefenderTransitiveRbacAssignments = foreach ($RbacAssignmentByGroup in ($AllDefenderRbacAssignments | where-object { $_.ObjectType -eq "group" }) ) {

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
            } else {
                Write-Warning "Empty group $($RbacAssignmentByGroup.ObjectId) - $($GroupObjectDisplayName)"
            }
        }
    }
    #endregion

    #region Filtering export if needed
    $AllDefenderRbacAssignments += $DefenderTransitiveRbacAssignments
    $AllDefenderRbacAssignments = $AllDefenderRbacAssignments | where-object { $_.ObjectType -in $PrincipalTypeFilter }
    $AllDefenderRbacAssignments = $AllDefenderRbacAssignments | select-object -Unique *
    $AllDefenderRbacAssignments | Sort-Object RoleAssignmentId, RoleAssignmentScopeName, RoleAssignmentScopeId, RoleAssignmentType, ObjectId
    #endregion
}