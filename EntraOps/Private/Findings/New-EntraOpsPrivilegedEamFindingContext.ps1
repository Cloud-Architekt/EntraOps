function New-EntraOpsPrivilegedEamFindingContext {
    <#
    .SYNOPSIS
        Builds the privileged objects and role assignments that the Privileged EAM finding rules evaluate.
    .DESCRIPTION
        Reads the Privileged EAM export (PrivilegedEAM/<RbacSystem>/<RbacSystem>.json) and returns:
          * Inventory: the merged privileged objects of New-EntraOpsPrivilegedAssetsFindingContext, with
            AccessTier (the most privileged tier of their role assignments without delegated permissions: a
            delegated permission acts within the rights of the signed-in user, so its tier is the tier of the
            role assignment, not of the object's access) and RequiredTier (the more privileged of AccessTier and
            the object tier).
          * Assignments: every role assignment of every RBAC system with all exported fields (Assignment),
            its object and Tier, the most privileged tier of its classification (or $null when it has none),
            and whether the object is the service principal of a Microsoft first-party application.
        Tiers are ControlPlane, ManagementPlane, WorkloadPlane and UserAccess, from the most privileged.

        Used by Invoke-EntraOpsFindingEvaluation.
    .PARAMETER ImportPath
        Folder with the Privileged EAM export.
    .PARAMETER Export
        The export from Read-EntraOpsPrivilegedEamExport, to reuse instead of reading -ImportPath.
    .PARAMETER Inventory
        Context of New-EntraOpsPrivilegedAssetsFindingContext for the same export, to reuse instead of
        building it again.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ImportPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Export,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Inventory
    )

    if ($null -eq $Export) { $Export = Read-EntraOpsPrivilegedEamExport -ImportPath $ImportPath }
    if ($null -eq $Inventory) { $Inventory = New-EntraOpsPrivilegedAssetsFindingContext -Export $Export }
    foreach ($Object in $Inventory.Objects) {
        $AccessTier = Get-EntraOpsMostPrivilegedTier -TierName "$($Object.assignmentSummary.highestAccessTierName)"
        $Object['accessTier'] = $AccessTier
        $Object['requiredTier'] = Get-EntraOpsMostPrivilegedTier -TierName $AccessTier, "$($Object.tierName)"
    }

    $Assignments = [System.Collections.Generic.List[object]]::new()
    foreach ($System in $Export.Systems) {
        $RoleSystem = $System.RoleSystem
        foreach ($Source in $System.Objects) {
            $ObjectId = "$($Source.ObjectId)".ToLowerInvariant()
            foreach ($RoleAssignment in @($Source.RoleAssignments)) {
                if ($null -eq $RoleAssignment) { continue }
                $Assignments.Add([pscustomobject]@{
                        System         = $RoleSystem
                        ObjectId       = $ObjectId
                        ObjectType     = "$($Source.ObjectType)".ToLowerInvariant()
                        ObjectSubType  = "$($Source.ObjectSubType)"
                        DisplayName    = $(if ("$($Source.ObjectDisplayName)") { "$($Source.ObjectDisplayName)" } else { $ObjectId })
                        ObjectTierName = $(if ("$($Source.ObjectAdminTierLevelName)") { "$($Source.ObjectAdminTierLevelName)" } else { 'Unclassified' })
                        ObjectTenantId = "$($Source.ObjectTenantId)"
                        # Service principal of a Microsoft first-party application (see Test-EntraOpsMicrosoftFirstParty).
                        IsMicrosoftFirstParty = [bool]$(if ($Inventory.ObjectsById.Contains($ObjectId)) { $Inventory.ObjectsById[$ObjectId].isMicrosoftFirstParty })
                        IsMicrosoftConsentClient = [bool]$(if ($Inventory.ObjectsById.Contains($ObjectId)) { $Inventory.ObjectsById[$ObjectId].isMicrosoftConsentClient })
                        Assignment     = $RoleAssignment
                        Tier           = Get-EntraOpsMostPrivilegedTier -TierName @(@($RoleAssignment.Classification) | ForEach-Object { if ($null -ne $_) { $_.AdminTierLevelName } })
                        InstanceKey    = "$RoleSystem|$ObjectId|$(if ($RoleAssignment.RoleAssignmentInstanceId) { $RoleAssignment.RoleAssignmentInstanceId } else { Get-EntraOpsRoleAssignmentInstanceId -RoleSystem $RoleSystem -RoleAssignment $RoleAssignment })"
                    })
            }
        }
    }

    [pscustomobject]@{
        Area         = 'PrivilegedEAM'
        Inventory    = $Inventory
        Assignments  = $Assignments
        HomeTenantId = $Inventory.HomeTenantId
    }
}
