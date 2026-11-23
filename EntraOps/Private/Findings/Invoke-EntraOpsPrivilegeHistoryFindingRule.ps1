function Invoke-EntraOpsPrivilegeHistoryFindingRule {
    <#
    .SYNOPSIS
        Evaluates a Privilege History finding rule by comparing the newest and the previous snapshot.
    .DESCRIPTION
        Pure evaluation of the context from New-EntraOpsPrivilegeHistoryFindingContext:
          * newControlPlaneAccess (EO.8001): every Control Plane role assignment of the newest snapshot (without PIM
            activations, which are temporary instances of eligible assignments, and without delegated permissions,
            reported by EO.8003) is an evaluated instance; it fails when the previous snapshot does not have it
            (same object and role assignment instance ID, or role assignment ID for snapshots without instance ID).
            A reclassified role (its assignment gets a new instance ID) counts as new access.
          * tierBreachIncrease (EO.8002): every tier breach of the newest snapshot is an evaluated instance, and
            every breach the previous snapshot does not have fails. A tier breach follows EO.1001 and EO.1003: a role
            assignment of a user or service principal classified at a more privileged admin tier level than the
            object (Management and Workload Plane are both Tier 1), without delegated permissions, without
            Microsoft first-party service principals and without PIM activations (the eligible assignment is the breach). New breaches of unclassified objects (counted as User
            Access) are counted apart (UnclassifiedCount), like EO.1003. The Privilege History chart still counts
            every breach (totals.tierBreaches), so its number can be higher.
          * newDelegatedPrivilegedPermission (EO.8003): every delegated permission classified Control or Management
            Plane of the newest snapshot is an evaluated instance; it fails when the previous snapshot does not have
            it (a new scope of an existing grant has its own instance ID). Microsoft first-party applications are left
            out, except the Microsoft clients whose delegated permissions the tenant grants by consent (Graph CLI).
        All three rules need the role type of the assignments (Privilege History data of this EntraOps version) to
        tell delegated permissions apart: without it in both snapshots, they are skipped.
        Returns the evaluated instances (see Invoke-EntraOpsFindingRuleSet).
    .PARAMETER Context
        Context from New-EntraOpsPrivilegeHistoryFindingContext.
    .PARAMETER Rule
        The Privilege History finding rule (from Get-EntraOpsFindingRule).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    # The day of a snapshot (yyyy-MM-dd), or the commit date as written when it is not a date.
    function Get-Day($Snapshot) {
        $Date = ConvertTo-EntraOpsPrivilegeHistoryDate $Snapshot['commitDate']
        if ($Date -ne [datetimeoffset]::MinValue) { return $Date.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) }
        if ("$($Snapshot['commitDate'])") { return "$($Snapshot['commitDate'])" }
        return "commit $("$($Snapshot['commitSha'])")"
    }
    $Period = "between $(Get-Day $Context.Previous) and $(Get-Day $Context.Latest)"
    # Role assignments of a snapshot. Like New-EntraOpsPrivilegedEamPrivilegeHistoryData, an assignment is
    # identified by its instance ID, else by its assignment ID. The assignment ID matches only when one of the
    # two snapshots has no instance ID for the assignment (an export of an older version): it is not unique, for
    # example every scope of a delegated permission grant has the ID of the grant.
    function Get-SnapshotAssignment($Snapshot) {
        foreach ($Object in @($Snapshot['objects'])) {
            if ($Object -isnot [System.Collections.IDictionary]) { continue }
            foreach ($Assignment in @($Object['roleAssignments'])) {
                if ($Assignment -isnot [System.Collections.IDictionary]) { continue }
                $ObjectKey = "$($Object['objectId'])".ToLowerInvariant()
                $InstanceKey = if ($Assignment['roleAssignmentInstanceId']) { "$ObjectKey|$("$($Assignment['roleAssignmentInstanceId'])".ToLowerInvariant())" } else { $null }
                $AssignmentKey = if ($Assignment['roleAssignmentId']) { "$ObjectKey|$("$($Assignment['roleAssignmentId'])".ToLowerInvariant())" } else { $null }
                $Tiers = @(@($Assignment['classification']) | Where-Object { $_ -is [System.Collections.IDictionary] } | ForEach-Object { "$($_['adminTierLevelName'])" } | Where-Object { $_ } | Select-Object -Unique)
                [pscustomobject]@{
                    Key           = $(if ($InstanceKey) { $InstanceKey } elseif ($AssignmentKey) { $AssignmentKey } else { "$ObjectKey|$($Assignment['roleDefinitionName'])|$($Assignment['roleSystem'])" })
                    InstanceKey   = $InstanceKey
                    AssignmentKey = $AssignmentKey
                    Object        = $Object
                    Assignment    = $Assignment
                    # The most privileged tier of the classification of the assignment, or $null.
                    Tier          = Get-EntraOpsMostPrivilegedTier -TierName $Tiers
                    Delegated     = "$($Assignment['roleType'])" -eq 'Delegated'
                }
            }
        }
    }
    # Whether a snapshot has the role type of its assignments (Privilege History data of EntraOps with EO.8003).
    # Without it, a delegated permission looks like a role assignment, so no rule can leave it out or select it.
    function Test-RoleType($Snapshot) {
        foreach ($Object in @($Snapshot['objects'])) {
            if ($Object -isnot [System.Collections.IDictionary]) { continue }
            foreach ($Assignment in @($Object['roleAssignments'])) {
                if ($Assignment -is [System.Collections.IDictionary]) { return @($Assignment.Keys) -contains 'roleType' }
            }
        }
        # A snapshot without role assignments has nothing to tell apart.
        return $true
    }
    $RoleTypeReason = 'The Privilege History data has no role type of the role assignments, so delegated permissions cannot be told apart. Generate the report data again with this EntraOps version (New-EntraOpsReportingData).'
    # Control Plane role assignments, without PIM activations (an activation is a temporary instance of an eligible
    # assignment; the export lists both) and without delegated permissions (EO.8003).
    function Get-ControlPlaneAssignment($Snapshot) {
        Get-SnapshotAssignment $Snapshot | Where-Object {
            "$($_.Assignment['pimAssignmentType'])" -ne 'Activated' -and -not $_.Delegated -and
            @(@($_.Assignment['classification']) | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['adminTierLevelName'] -ceq 'ControlPlane' }).Count
        }
    }
    # Tier breaches of a snapshot like EO.1001 and EO.1003: a role assignment of a user or service principal
    # whose classification is of a more privileged admin tier level than the object, without delegated
    # permissions and Microsoft first-party service principals. One per assignment, with its most privileged tier.
    # A PIM activation is left out like in EO.8001: the export lists it next to its eligible assignment, which is
    # the breach, so activating a role would show as a new tier breach.
    function Get-TierBreach($Snapshot) {
        foreach ($Item in Get-SnapshotAssignment $Snapshot) {
            $Object = $Item.Object
            if ("$($Item.Assignment['pimAssignmentType'])" -eq 'Activated') { continue }
            if ("$($Object['objectType'])" -notin 'user', 'serviceprincipal' -or $Item.Delegated -or $Object['isMicrosoftFirstParty'] -eq $true -or -not $Item.Tier) { continue }
            $ObjectTier = if ($script:EntraOpsTierRank.ContainsKey("$($Object['objectAdminTierLevelName'])")) { "$($Object['objectAdminTierLevelName'])" } else { 'Unclassified' }
            # An unclassified object is compared as User Access, like EO.1001 to EO.1003.
            if ((Get-EntraOpsAdminTierLevel $Item.Tier) -ge (Get-EntraOpsAdminTierLevel $ObjectTier)) { continue }
            $Classification = @(@($Item.Assignment['classification']) | Where-Object { $_ -is [System.Collections.IDictionary] })
            [pscustomobject]@{
                Key           = $Item.Key
                InstanceKey   = $Item.InstanceKey
                AssignmentKey = $Item.AssignmentKey
                ObjectTier    = $ObjectTier
                Tier          = $Item.Tier
                Services      = @($Classification | Where-Object { "$($_['adminTierLevelName'])" -ceq $Item.Tier -and "$($_['service'])" } | ForEach-Object { "$($_['service'])" } | Select-Object -Unique)
                Object        = $Object
                Assignment    = $Item.Assignment
            }
        }
    }
    # Delegated permissions classified Control or Management Plane: Microsoft first-party applications only when the
    # tenant grants their permissions by consent (Graph CLI, Graph Explorer).
    function Get-DelegatedPermission($Snapshot) {
        Get-SnapshotAssignment $Snapshot | Where-Object {
            $_.Delegated -and (Test-EntraOpsPrivilegedTier $_.Tier) -and -not ($_.Object['isMicrosoftFirstParty'] -eq $true -and $_.Object['isMicrosoftConsentClient'] -ne $true)
        }
    }
    # Index of the assignments of the previous snapshot, and whether an assignment of the latest one is in it.
    function New-AssignmentIndex($Items) {
        $Index = [pscustomobject]@{
            Instance                  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            Assignment                = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            AssignmentWithoutInstance = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            Key                       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        }
        foreach ($Item in $Items) {
            $null = $Index.Key.Add($Item.Key)
            if ($Item.InstanceKey) { $null = $Index.Instance.Add($Item.InstanceKey) }
            if ($Item.AssignmentKey) {
                $null = $Index.Assignment.Add($Item.AssignmentKey)
                if (-not $Item.InstanceKey) { $null = $Index.AssignmentWithoutInstance.Add($Item.AssignmentKey) }
            }
        }
        $Index
    }
    function Test-KnownAssignment($Item, $Index) {
        if ($Item.InstanceKey) { return $Index.Instance.Contains($Item.InstanceKey) -or ($Item.AssignmentKey -and $Index.AssignmentWithoutInstance.Contains($Item.AssignmentKey)) }
        if ($Item.AssignmentKey) { return $Index.Assignment.Contains($Item.AssignmentKey) }
        return $Index.Key.Contains($Item.Key)
    }
    function Get-Tier($TierName) { Get-EntraOpsTierDisplayName $TierName }
    function Get-ObjectTierName($Object) { if ($script:EntraOpsTierRank.ContainsKey("$($Object['objectAdminTierLevelName'])")) { "$($Object['objectAdminTierLevelName'])" } else { 'Unclassified' } }

    switch ($Rule.Key) {
        'newControlPlaneAccess' {
            if (-not (Test-RoleType $Context.Latest) -or -not (Test-RoleType $Context.Previous)) { return [pscustomobject]@{ SkipReason = $RoleTypeReason } }
            $PreviousIndex = New-AssignmentIndex @(Get-ControlPlaneAssignment $Context.Previous)
            foreach ($Item in Get-ControlPlaneAssignment $Context.Latest) {
                $Known = Test-KnownAssignment $Item $PreviousIndex
                [pscustomobject]@{
                    Failed             = -not $Known
                    InstanceKey        = $Item.Key
                    ObjectId           = "$($Item.Object['objectId'])"
                    ObjectType         = "$($Item.Object['objectType'])"
                    DisplayName        = "$($Item.Object['objectDisplayName'])"
                    AdminTierLevel     = Get-EntraOpsAdminTierLevel "$($Item.Object['objectAdminTierLevelName'])"
                    AdminTierLevelName = Get-ObjectTierName $Item.Object
                    Message            = "$(Get-Tier (Get-ObjectTierName $Item.Object)) object '$($Item.Object['objectDisplayName'])' got the Control Plane role '$($Item.Assignment['roleDefinitionName'])' ($($Item.Assignment['roleSystem'])) $Period."
                    Evidence           = [ordered]@{ RoleSystem = "$($Item.Assignment['roleSystem'])"; RoleDefinitionName = "$($Item.Assignment['roleDefinitionName'])"; PIMAssignmentType = "$($Item.Assignment['pimAssignmentType'])"; CommitSha = "$($Context.Latest['commitSha'])" }
                }
            }
        }
        'tierBreachIncrease' {
            if (-not (Test-RoleType $Context.Latest) -or -not (Test-RoleType $Context.Previous)) { return [pscustomobject]@{ SkipReason = $RoleTypeReason } }
            $PreviousBreaches = @(Get-TierBreach $Context.Previous)
            $PreviousIndex = New-AssignmentIndex $PreviousBreaches
            $Breaches = @(Get-TierBreach $Context.Latest)
            $Previous = $PreviousBreaches.Count
            $Latest = $Breaches.Count
            foreach ($Item in $Breaches) {
                $New = -not (Test-KnownAssignment $Item $PreviousIndex)
                $Services = if ($Item.Services.Count) { " (services: $($Item.Services -join ', '))" } else { '' }
                $IsUnclassified = $Item.ObjectTier -eq 'Unclassified'
                $ObjectLabel = if ($IsUnclassified) { 'Unclassified object (counted as User Access)' } else { "$(Get-Tier $Item.ObjectTier) object" }
                [pscustomobject]@{
                    Failed             = $New
                    # New breaches of unclassified objects are counted apart, like EO.1003: their tier is unknown.
                    Unclassified       = $IsUnclassified
                    InstanceKey        = $Item.Key
                    ObjectId           = "$($Item.Object['objectId'])"
                    ObjectType         = "$($Item.Object['objectType'])"
                    DisplayName        = "$($Item.Object['objectDisplayName'])"
                    AdminTierLevel     = Get-EntraOpsAdminTierLevel $Item.ObjectTier
                    AdminTierLevelName = $Item.ObjectTier
                    Message            = "$ObjectLabel '$($Item.Object['objectDisplayName'])' holds the $(Get-Tier $Item.Tier) role '$($Item.Assignment['roleDefinitionName'])' ($($Item.Assignment['roleSystem']))$Services, a new tier breach $Period ($Previous tier breaches before, $Latest now)."
                    Evidence           = [ordered]@{
                        RoleSystem          = "$($Item.Assignment['roleSystem'])"
                        RoleDefinitionName  = "$($Item.Assignment['roleDefinitionName'])"
                        RoleTierLevelName   = $Item.Tier
                        ObjectTierLevelName = $Item.ObjectTier
                        Services            = $Item.Services
                        PIMAssignmentType   = "$($Item.Assignment['pimAssignmentType'])"
                        Previous            = $Previous
                        Latest              = $Latest
                        PreviousCommitSha   = "$($Context.Previous['commitSha'])"
                        LatestCommitSha     = "$($Context.Latest['commitSha'])"
                    }
                }
            }
            $NewUnclassified = @($Breaches | Where-Object { $_.ObjectTier -eq 'Unclassified' -and -not (Test-KnownAssignment $_ $PreviousIndex) }).Count
            if ($NewUnclassified -gt 0) { [pscustomobject]@{ NoteOnly = $true; Note = "$NewUnclassified new tier breach(es) of unclassified objects are counted apart: classify these objects (EO.2001) to evaluate them." } }
            # Without any tier breach, the tenant is the evaluated instance (the check passes).
            if ($Breaches.Count -eq 0) {
                [pscustomobject]@{ Failed = $false; InstanceKey = 'tenant'; ObjectType = 'tenant'; DisplayName = 'Tenant' }
            }
        }
        'newDelegatedPrivilegedPermission' {
            if (-not (Test-RoleType $Context.Latest) -or -not (Test-RoleType $Context.Previous)) { return [pscustomobject]@{ SkipReason = $RoleTypeReason } }
            $PreviousIndex = New-AssignmentIndex @(Get-DelegatedPermission $Context.Previous)
            foreach ($Item in Get-DelegatedPermission $Context.Latest) {
                $Resource = "$($Item.Assignment['resourceName'])"
                [pscustomobject]@{
                    Failed             = -not (Test-KnownAssignment $Item $PreviousIndex)
                    InstanceKey        = $Item.Key
                    ObjectId           = "$($Item.Object['objectId'])"
                    ObjectType         = "$($Item.Object['objectType'])"
                    DisplayName        = "$($Item.Object['objectDisplayName'])"
                    AdminTierLevel     = Get-EntraOpsAdminTierLevel (Get-ObjectTierName $Item.Object)
                    AdminTierLevelName = Get-ObjectTierName $Item.Object
                    Message            = "'$($Item.Object['objectDisplayName'])' got the delegated $(Get-Tier $Item.Tier) permission '$($Item.Assignment['roleDefinitionName'])'$(if ($Resource) { " of '$Resource'" }) $Period."
                    Evidence           = [ordered]@{
                        RoleSystem         = "$($Item.Assignment['roleSystem'])"
                        RoleDefinitionName = "$($Item.Assignment['roleDefinitionName'])"
                        Tier               = $Item.Tier
                        Resource           = $Resource
                        PreviousCommitSha  = "$($Context.Previous['commitSha'])"
                        LatestCommitSha    = "$($Context.Latest['commitSha'])"
                    }
                }
            }
        }
        default { throw "No Privilege History evaluator for finding rule '$($Rule.Id)' ($($Rule.Key))." }
    }
}
