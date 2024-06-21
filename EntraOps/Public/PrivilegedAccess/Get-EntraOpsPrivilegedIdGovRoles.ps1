<#
.SYNOPSIS
    Get a list of delegated administrator roles in Microsoft Entra Identity Governance.

.DESCRIPTION
    Get a list of delegated administrator roles in Microsoft Entra Identity Governance.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER PrincipalTypeFilter
    Filter for principal type. Default is User, Group, ServicePrincipal. Possible values are User, Group, ServicePrincipal.

.PARAMETER ExpandGroupMembers
    Expand group members for transitive role assignments. Default is $true.

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False.  

.EXAMPLE
    Get a list of delegated administrator assignment in Identity Governance access packages and catalogs.
    Get-EntraOpsPrivilegedIdGovRoles
#>

function Get-EntraOpsPrivilegedIdGovRoles {
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

    $ElmRbacAssignments = @()

    if ($SampleMode -eq $True) {
        Write-Warning "Not supported yet!"
    }
    else {
        $ElmRoleDefinitions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/entitlementManagement/roleDefinitions"
        $ElmRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/entitlementManagement/roleAssignments"
    }

    $ElmRoleAssignmentPrincipals = ($ElmRoleAssignments | select-object principalId -Unique).principalId
    $ElmRbacAssignments = foreach ($Principal in $ElmRoleAssignmentPrincipals) {
        Write-Verbose "Get identity information from permanent member $Principal"
        try {
            $PrincipalProfile = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/directoryObjects/$($Principal)" -OutputType PSObject
            $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
        }
        catch {
            Write-Error "Issue to resolve directory object $Principal. Error: $($_.Exception.Message)"
        }

        $AllPrinicpalElmRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/entitlementManagement/RoleAssignments?$count=true&`$filter=principalId eq '$Principal'" -ConsistencyLevel "eventual"
        foreach ($ElmPrincipalRoleAssignment in $AllPrinicpalElmRoleAssignments) {
            $Role = ($ElmRoleDefinitions | where-object { $_.id -eq $ElmPrincipalRoleAssignment.roleDefinitionId })

            try {
                $CatalogId = $($ElmPrincipalRoleAssignment.appScopeId).Replace("/AccessPackageCatalog/", "")
                $AccessPackageDisplayName = (Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs/$($CatalogId)" -OutputType PSObject).displayName
            }
            catch {
                $AccessPackageDisplayName = "Unknown name"
            }

            [pscustomobject]@{
                RoleAssignmentId              = $ElmPrincipalRoleAssignment.Id
                RoleAssignmentScopeId         = $ElmPrincipalRoleAssignment.appScopeId
                RoleAssignmentScopeName       = $AccessPackageDisplayName
                RoleAssignmentType            = "Direct"
                RoleAssignmentSubType         = ""
                PIMManagedRole                = $False
                PIMAssignmentType             = "Permanent"
                RoleDefinitionName            = $Role.displayName
                RoleDefinitionId              = $ElmPrincipalRoleAssignment.roleDefinitionId
                RoleType                      = "Built-in"
                RoleIsPrivileged              = $Role.isPrivileged
                ObjectId                      = $Principal
                ObjectType                    = $ObjectType.toLower()
                TransitiveByObjectId          = ""
                TransitiveByObjectDisplayName = ""
            }
        }
    }

    # List all eligible roleAssignment

    if ($ExpandGroupMembers -eq $True) {
        Write-Verbose -Message "Expanding groups for direct or transitive Entra ID role assignments"
        $GroupsWithRbacAssignment = $ElmRbacAssignments | where-object { $_.ObjectType -eq "group" }
        $AllTransitiveMembers = $GroupsWithRbacAssignment | foreach-object {
            $GroupObjectDisplayName = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/groups/$($_.ObjectId)" -OutputType PSObject).displayName
            $TransitiveMembers = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $_.ObjectId
            $TransitiveMembers | Add-Member -MemberType NoteProperty -Name "GroupObjectDisplayName" -Value $GroupObjectDisplayName -Force
            $TransitiveMembers | Add-Member -MemberType NoteProperty -Name "GroupObjectId" -Value $_.ObjectId -Force
            return $TransitiveMembers
        }

        $ElmRbacTransitiveAssignments = foreach ($RbacAssignmentByGroup in $GroupsWithRbacAssignment ) {

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
                        ObjectType                    = $_.'@odata.type'.Replace('#microsoft.graph.', '').toLower()
                        TransitiveByObjectId          = $RbacAssignmentByGroup.ObjectId
                        TransitiveByObjectDisplayName = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/groups/$($RbacAssignmentByGroup.ObjectId)" -OutputType PSObject).displayName
                    }
                }
            }
            else {
                Write-Warning "Empty group $($RbacAssignmentByGroup.ObjectId) - $($GroupObjectDisplayName)"
            } 
        }
    }
    $AllElmRbacAssignments = @()
    $AllElmRbacAssignments += $ElmRbacAssignments
    $AllElmRbacAssignments += $ElmRbacTransitiveAssignments
    $AllElmRbacAssignments = $AllElmRbacAssignments | where-object { $_.ObjectType -in $PrincipalTypeFilter }
    $AllElmRbacAssignments = $AllElmRbacAssignments | select-object -Unique *
    $AllElmRbacAssignments | Sort-Object RoleAssignmentId, RoleAssignmentType, ObjectId
}