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
        ,
        [Parameter(Mandatory = $False)]
        [System.Collections.Generic.List[psobject]]$WarningMessages
    )

    # Set Error Action
    $ErrorActionPreference = "Stop"

    $ElmRbacAssignments = @()

    if ($SampleMode -eq $True) {
        Write-Warning "Not supported yet!"
    } else {
        $ElmRoleDefinitions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/entitlementManagement/roleDefinitions?`$select=id,displayName,description"
        $ElmRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/entitlementManagement/roleAssignments?`$select=id,principalId,roleDefinitionId,appScopeId"
    }

    $ElmRoleAssignmentPrincipals = ($ElmRoleAssignments | select-object principalId -Unique).principalId
    Write-Host "Processing $($ElmRoleAssignmentPrincipals.Count) Identity Governance role principals..."
    $PrincipalCounter = 0
    $ElmRbacAssignments = foreach ($Principal in $ElmRoleAssignmentPrincipals) {
        $PrincipalCounter++
        if (($PrincipalCounter % 10) -eq 0 -or $PrincipalCounter -eq $ElmRoleAssignmentPrincipals.Count) {
            $PercentComplete = [math]::Round(($PrincipalCounter / $ElmRoleAssignmentPrincipals.Count) * 100, 0)
            Write-Progress -Activity "Processing IdGov Role Principals" -Status "Processing principal $PrincipalCounter of $($ElmRoleAssignmentPrincipals.Count)" -PercentComplete $PercentComplete
        }
        Write-Verbose "Get identity information from permanent member $Principal"
        try {
            $PrincipalProfile = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/directoryObjects/$($Principal)" -OutputType PSObject
            $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
        } catch {
            $WarningMessage = "Issue to resolve directory object $Principal! $($_.Exception.Message)"
            if ($null -ne $WarningMessages) {
                $WarningMessages.Add([pscustomobject]@{
                        Timestamp = (Get-Date)
                        Type      = "ObjectResolutionError"
                        ObjectId  = $Principal
                        Message   = $WarningMessage
                    })
            }
            Write-Warning $WarningMessage
        }

        $AllPrinicpalElmRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/entitlementManagement/RoleAssignments?$count=true&`$filter=principalId eq '$Principal'" -ConsistencyLevel "eventual"
        foreach ($ElmPrincipalRoleAssignment in $AllPrinicpalElmRoleAssignments) {
            $Role = ($ElmRoleDefinitions | where-object { $_.id -eq $ElmPrincipalRoleAssignment.roleDefinitionId })

            try {
                if ($ElmPrincipalRoleAssignment.appScopeId -eq "/") {
                    $AccessPackageDisplayName = "Directory"
                } else {
                    $CatalogId = $($ElmPrincipalRoleAssignment.appScopeId).Replace("/AccessPackageCatalog/", "")
                    $CatalogObj = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($CatalogId)" -OutputType PSObject -WarningAction SilentlyContinue
                    if ($null -ne $CatalogObj) {
                        $AccessPackageDisplayName = $CatalogObj.displayName
                    } else {
                        $AccessPackageDisplayName = "Invalid or deleted object"
                        if ($null -ne $WarningMessages) {
                            $WarningMessages.Add([pscustomobject]@{
                                    Timestamp = (Get-Date)
                                    Type      = "CatalogResolution"
                                    ObjectId  = $CatalogId
                                    Message   = "Access Package Catalog $CatalogId not found (likely deleted)."
                                })
                        }
                    }
                }
            } catch {
                $AccessPackageDisplayName = "Invalid or deleted object"
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
                RoleType                      = "BuiltInRole"
                RoleIsPrivileged              = $Role.isPrivileged
                ObjectId                      = $Principal
                ObjectType                    = $ObjectType.toLower()
                TransitiveByObjectId          = ""
                TransitiveByObjectDisplayName = ""
            }
        }
    }
    # List all eligible roleAssignment

    #region Collect transitive assignments by group members of Role-Assignable Groups
    if ($ExpandGroupMembers -eq $True) {    
        Write-Verbose "Expanding groups for direct or transitive ELM role assignments"
        $GroupsWithRbacAssignment = $ElmRbacAssignments | where-object { $_.ObjectType -eq "group" }
        $AllTransitiveMembers = @()

        foreach ($GroupWithRbacAssignment in $GroupsWithRbacAssignment) {
            $GroupObjectDisplayName = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/groups/$($GroupWithRbacAssignment.ObjectId)" -OutputType PSObject).displayName
            $TransitiveMembers = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $($GroupWithRbacAssignment.ObjectId)
            foreach ($TransitiveMember in $TransitiveMembers) {
                $Member = [pscustomobject]@{
                    displayName            = $TransitiveMember.displayName
                    id                     = $TransitiveMember.id
                    '@odata.type'          = $TransitiveMember.'@odata.type'
                    RoleAssignmentSubType  = $TransitiveMember.RoleAssignmentSubType
                    GroupObjectDisplayName = $GroupObjectDisplayName
                    GroupObjectId          = $GroupWithRbacAssignment.ObjectId
                }
                $AllTransitiveMembers += $Member
            }
        }

        $ElmRbacTransitiveAssignments = [System.Collections.Generic.List[object]]::new()
        foreach ($RbacAssignmentByGroup in ($GroupsWithRbacAssignment | where-object { $_.ObjectType -eq "group" }) ) {

            $RbacAssignmentByNestedGroupMembers = $AllTransitiveMembers | Where-Object { $_.GroupObjectId -eq $RbacAssignmentByGroup.ObjectId }

            if ($RbacAssignmentByNestedGroupMembers.Count -gt 0) {
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
            } else {
                if ($null -ne $WarningMessages) {
                    $WarningMessages.Add([pscustomobject]@{
                            Timestamp = (Get-Date)
                            Type      = "EmptyGroup"
                            ObjectId  = $RbacAssignmentByGroup.ObjectId
                            Message   = "Group has no members or members could not be resolved."
                        })
                }
            }

            $ElmRbacTransitiveAssignments.Add($TransitiveMember) | Out-Null
        }
    }
    #endregion

    $AllElmRbacAssignments = @()
    $AllElmRbacAssignments += $ElmRbacAssignments
    $AllElmRbacAssignments += $ElmRbacTransitiveAssignments
    $AllElmRbacAssignments = $AllElmRbacAssignments | where-object { $_.ObjectType -in $PrincipalTypeFilter }
    $AllElmRbacAssignments = $AllElmRbacAssignments | select-object -Unique *
    $AllElmRbacAssignments | Sort-Object RoleAssignmentId, RoleAssignmentType, ObjectId
}