<#
.SYNOPSIS
    Assigns Entitlement Management catalog roles to service groups.

.DESCRIPTION
    Assigns the following Entitlement Management catalog-scoped roles to the
    matching service groups (matched by DisplayName wildcard pattern):

    - Catalog Owner    → *-ControlPlane-Admins  (skipped when SkipControlPlaneDelegation is set)
    - Catalog Reader   → *-CatalogPlane-Members
    - Catalog Reader   → *-WorkloadPlane-Admins
    - Catalog Reader   → *-ManagementPlane-Admins
    - AP Assignment Manager → *-ManagementPlane-Admins

    Idempotent: existing role assignments are detected and skipped.
    Delegated groups are included — this function must receive the full
    $ServiceGroups collection (including synthetic delegated entries) so
    the delegated ControlPlane/ManagementPlane groups are matched correctly.

.PARAMETER ServiceCatalogId
    Object ID of the Entitlement Management catalog.

.PARAMETER ServiceGroups
    All service group objects, including synthetic delegated entries.
    Matched against catalog role filter patterns by DisplayName.

.PARAMETER SkipControlPlaneDelegation
    When set, the Catalog Owner assignment for *-ControlPlane-Admins is skipped.
    Used when ControlPlane is not delegated at all (neither owned nor delegated group).
    Do NOT set when a ControlPlaneDelegationGroupId is provided — in that case
    Bootstrap injects the delegated group so the Owner assignment must still run.

.PARAMETER SkipCatalogOwnerAssignment
    Skips the permanent Catalog Owner assignment for *-ControlPlane-Admins (owned or delegated group).

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServiceEMCatalogResourceRole `
        -ServiceGroups $groups `
        -ServiceCatalogId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

    Assigns Owner to *-ControlPlane-Admins, Reader to *-CatalogPlane-Members,
    *-WorkloadPlane-Admins and *-ManagementPlane-Admins, and AP Assignment
    Manager to *-ManagementPlane-Admins.

.EXAMPLE
    New-EntraOpsServiceEMCatalogResourceRole `
        -ServiceGroups $groups `
        -ServiceCatalogId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -SkipControlPlaneDelegation

    Same as above but omits the Catalog Owner assignment.

#>
function New-EntraOpsServiceEMCatalogResourceRole {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [switch]$SkipControlPlaneDelegation,        

        [switch]$SkipCatalogOwnerAssignment,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $catalogAssignments = @()
        $catalogRolesUri = "/v1.0/roleManagement/entitlementManagement/roleAssignments?`$filter=appScopeId eq '/AccessPackageCatalog/$($ServiceCatalogId)'"

        try{
            Write-Verbose "$logPrefix Looking up catalog role assignments"
            $catalogAssignments += Invoke-EntraOpsMsGraphQuery -Method GET -Uri $catalogRolesUri -OutputType PSObject -DisableCache
        }catch{
            Write-Verbose "$logPrefix Failed to find catalog role assignments"
            Write-Error $_
        }

        $catalogRoles = @"
displayName,id,filter
Owner,ae79f266-94d4-4dab-b730-feca7e132178,*ControlPlane-Admins
Reader,44272f93-9762-48e8-af59-1b5351b1d6b3,*CatalogPlane-Members
Reader,44272f93-9762-48e8-af59-1b5351b1d6b3,*WorkloadPlane-Admins
Reader,44272f93-9762-48e8-af59-1b5351b1d6b3,*ManagementPlane-Admins
ApAssignmentManager,e2182095-804a-4656-ae11-64734e9b7ae5,*ManagementPlane-Admins
"@|ConvertFrom-Csv
    }

    process {
        Write-Verbose "$logPrefix Beginning EM Catalog Resource Role"

        if($SkipControlPlaneDelegation -or $SkipCatalogOwnerAssignment){
            Write-Verbose "$logPrefix Skipping Catalog Owner assignment for ControlPlane-Admins"
            $catalogRoles = $catalogRoles | Where-Object { $_.displayName -ne "Owner" }
        }

        Write-Verbose "$logPrefix Processing $(($catalogRoles|Measure-Object).Count) catalog resource role assignments"
        foreach($catalogRole in $catalogRoles){
            $catalogRoleParams = @{
                principalId = ($ServiceGroups|Where-Object{$_.DisplayName -like "$($catalogRole.filter)"}).Id
                roleDefinitionId = $catalogRole.id
                appScopeId = "/AccessPackageCatalog/$($ServiceCatalogId)"
            }

            try{
                if(($ServiceGroups|Where-Object{$_.id -eq $catalogRoleParams.principalId}).DisplayName -like $catalogRole.filter){
                    $nr = $catalogRoleParams.principalId+"_"+$catalogRoleParams.roleDefinitionId
                    $er = $catalogAssignments|ForEach-Object{$_.PrincipalId+"_"+$_.RoleDefinitionId}
                    if($nr -notin $er){
                        $catalogAssignments += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/roleManagement/entitlementManagement/roleAssignments" -Body ($catalogRoleParams | ConvertTo-Json -Depth 10) -OutputType PSObject
                    }
                }
            }catch{
                Write-Verbose "$logPrefix Failed to assign catalog roles"
                Write-Error $_
            }
        }

        $assignmentManagerGroup = $ServiceGroups | Where-Object { $_.DisplayName -like "*ManagementPlane-Admins" } | Select-Object -First 1
        if ($assignmentManagerGroup.IsDelegated) {
            Write-Verbose "$logPrefix Delegated ManagementPlane-Admins ($($assignmentManagerGroup.Id)) hold 'Access package assignment manager'; their own membership isn't part of this catalog"
        } elseif ($assignmentManagerGroup) {
            Write-Warning "$logPrefix ManagementPlane-Admins ($($assignmentManagerGroup.Id)) hold the permanent catalog role 'Access package assignment manager' on the catalog that also contains their own access package: members can directly assign every access package of the catalog without approval and add further ManagementPlane admins without the approval of ControlPlane-Admins (escalation within the ManagementPlane tier). Use -EnablePimForGroups to make this permission just-in-time, or the Centralized governance model (-GovernanceModel Centralized), where ManagementPlane-Admins is a tenant-wide group that is governed outside the service catalogs."
        }
    }

    end {
        $expectedIds = @($catalogAssignments | Where-Object { $_.id } | Select-Object -ExpandProperty id)
        $check = @{}
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "Catalog role assignments" -logPrefix $logPrefix -Condition {
            $check.Assignments = Invoke-EntraOpsMsGraphQuery -Method GET -Uri $catalogRolesUri -OutputType PSObject -DisableCache
            $actualIds = @($check.Assignments | Where-Object { $_.id } | Select-Object -ExpandProperty id)
            ($expectedIds.Count -eq 0 -and $actualIds.Count -eq 0) -or (Compare-Object $expectedIds $actualIds | Measure-Object).Count -eq 0
        }
        if(-not $confirmed){
            throw "Catalog Resource Role Assignment consistency with Entra not achieved"
        }
        return [psobject[]]$check.Assignments
    }
}