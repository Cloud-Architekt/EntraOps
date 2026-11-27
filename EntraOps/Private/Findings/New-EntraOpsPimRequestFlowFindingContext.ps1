function New-EntraOpsPimRequestFlowFindingContext {
    <#
    .SYNOPSIS
        Builds the PIM role setting flows that the PIM Request Flow finding rules evaluate.
    .DESCRIPTION
        Builds the flow model of the PIM Request Flow report for one Tenant Governance snapshot: every
        microsoft.entra.rolesetting resource expands into three flows (activation, eligible
        assignment, active assignment) with the id "<roleId>|<path>". The report shows the role tiers and
        approvers of this model (New-EntraOpsReportFindingData) and does not resolve them itself.

        The role tier starts with the Classification Explorer role catalog (tier map), overridden by the
        role definitions of the EAM Dashboard dataset (both the classification catalog of the role). A PIM
        role setting applies to every current and future assignment of the role at any scope, so the
        classified role assignments can raise this tier but not lower it: the role has the most privileged
        tier of the catalog and its assignments. Only a role definition overwrite of the tenant
        (Classification_RoleDefinitionOverwrites.json, assignments tagged by RoleDefinitionOverwrites)
        replaces the catalog tier, so then the assignments decide alone. Roles without a tier fall back to
        the most privileged tier of their role actions.

        Activation approvers are resolved by user principal name, then display name (only when one object
        has the name), against the EAM Dashboard objects; unresolved approvers count as User Access. A group
        approver without member data or without members stays unresolved: the tier of its access does not
        stand in for the protection of its members. An approver or member whose display name another known
        object has is named with the start of its object ID (Get-EntraOpsUniqueDisplayName).

        Every flow is checked once against the PIM Request Flow rules (checks, see
        Get-EntraOpsPimRequestFlowFlag): the report shows the failed checks as risk flags and the rule
        evaluator returns the checks of a rule as its instances.

        Used by Invoke-EntraOpsFindingEvaluation and New-EntraOpsReportFindingData.
    .PARAMETER ReportData
        Datasets from Import-EntraOpsReportFindingData.
    .PARAMETER SnapshotIndex
        Index of the snapshot in ReportData.Snapshots. Defaults to the newest snapshot with embedded content.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$ReportData,

        [Parameter(Mandatory = $false)]
        [Nullable[int]]$SnapshotIndex
    )

    function Get-Upper($Value) { "$Value".ToUpperInvariant() }

    # Role tier indexes are the same for every snapshot: build them once per dataset.
    if ($null -eq $ReportData.PSObject.Properties['PimRoleTierIndex']) {
        $Ordinal = [System.StringComparer]::Ordinal
        $RoleDefinitionTierIndex = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
        $RoleActionTierIndex = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
        $TierMap = $ReportData.TierMap

        foreach ($Role in $(if ($null -ne $TierMap -and $TierMap['roles'] -is [array]) { $TierMap['roles'] } else { @() })) {
            if ("$($Role['sys'])".ToLowerInvariant() -ne 'entraid' -or -not (Test-EntraOpsJsTruthy $Role['roleId']) -or -not (Test-EntraOpsJsTruthy $Role['roleClass']) -or $Role['roleClass'] -ceq 'Unclassified') { continue }
            $RoleDefinitionTierIndex[(Get-Upper $Role['roleId'])] = [pscustomobject]@{
                tierName = $Role['roleClass']
                service  = $(if (Test-EntraOpsJsTruthy $Role['service']) { $Role['service'] } else { 'Entra ID directory role catalog' })
            }
        }
        foreach ($Path in $(if ($null -ne $TierMap -and $TierMap['paths'] -is [array]) { $TierMap['paths'] } else { @() })) {
            if ("$($Path['sys'])".ToLowerInvariant() -ne 'entraid') { continue }
            if ((Test-EntraOpsJsTruthy $Path['action']) -and (Test-EntraOpsJsTruthy $Path['tier']) -and $Path['tier'] -cne 'Unclassified') {
                $ActionKey = "$($Path['action'])".ToLowerInvariant()
                $ActionCurrent = $null
                if (-not $RoleActionTierIndex.TryGetValue($ActionKey, [ref]$ActionCurrent) -or (Get-EntraOpsReportTierRank $Path['tier']) -lt (Get-EntraOpsReportTierRank $ActionCurrent.tierName)) {
                    $RoleActionTierIndex[$ActionKey] = [pscustomobject]@{
                        tierName = $Path['tier']
                        service  = $(if (Test-EntraOpsJsTruthy $Path['service']) { $Path['service'] } else { 'Entra ID directory role action' })
                    }
                }
            }
            if (-not (Test-EntraOpsJsTruthy $Path['roleId'])) { continue }
            $TierName = if (Test-EntraOpsJsTruthy $Path['roleClass']) { $Path['roleClass'] } else { $Path['tier'] }
            if (-not (Test-EntraOpsJsTruthy $TierName) -or $TierName -ceq 'Unclassified') { continue }
            $Key = Get-Upper $Path['roleId']
            $Current = $null
            if (-not $RoleDefinitionTierIndex.TryGetValue($Key, [ref]$Current) -or (Get-EntraOpsReportTierRank $TierName) -lt (Get-EntraOpsReportTierRank $Current.tierName)) {
                $RoleDefinitionTierIndex[$Key] = [pscustomobject]@{
                    tierName = $TierName
                    service  = $(if (Test-EntraOpsJsTruthy $Path['service']) { $Path['service'] } else { 'Entra ID directory role catalog' })
                }
            }
        }

        $EamData = $ReportData.EamData
        if ($null -ne $EamData) {
            foreach ($Role in $(if ($EamData['roleDefinitions'] -is [array]) { $EamData['roleDefinitions'] } else { @() })) {
                if (-not (Test-EntraOpsJsTruthy $Role['roleDefinitionId']) -or -not (Test-EntraOpsJsTruthy $Role['tierName'])) { continue }
                $RoleDefinitionTierIndex[(Get-Upper $Role['roleDefinitionId'])] = [pscustomobject]@{
                    tierName = $Role['tierName']
                    service  = $(if (Test-EntraOpsJsTruthy $Role['service']) { $Role['service'] } else { 'Entra ID directory role' })
                }
            }
            if ($EamData['objects'] -is [array]) {
                # Per assignment, the most privileged classification counts as one vote for the role. The
                # role setting applies to every assignment at any scope: a vote can raise the catalog tier,
                # but a lower one (for example of an assignment scoped to an administrative unit) does not
                # lower it. A role definition overwrite (RoleDefinitionOverwrites) is the classification
                # of the role chosen by the tenant: then the votes replace the catalog tier.
                $Votes = [ordered]@{}
                $Overwritten = [System.Collections.Generic.HashSet[string]]::new($Ordinal)
                foreach ($Object in $EamData['objects']) {
                    foreach ($Assignment in $(if ($Object['roleAssignments'] -is [array]) { $Object['roleAssignments'] } else { @() })) {
                        if (-not (Test-EntraOpsJsTruthy $Assignment['roleDefinitionId'])) { continue }
                        $Classifications = @(if ($Assignment['classification'] -is [array]) { $Assignment['classification'] })
                        if ($Classifications.Count -eq 0) { continue }
                        $Best = @{ rank = 5; tierName = $null; service = $null }
                        foreach ($Classification in $Classifications) {
                            $Rank = Get-EntraOpsReportTierRank $Classification['adminTierLevelName']
                            if ($Rank -lt $Best.rank) { $Best = @{ rank = $Rank; tierName = $Classification['adminTierLevelName']; service = $Classification['service'] } }
                        }
                        if (-not (Test-EntraOpsJsTruthy $Best.tierName)) { continue }
                        $Key = Get-Upper $Assignment['roleDefinitionId']
                        if (@($Classifications | Where-Object { "$($_['taggedBy'])" -ceq 'RoleDefinitionOverwrites' }).Count -gt 0) { $null = $Overwritten.Add($Key) }
                        if (-not $Votes.Contains($Key)) { $Votes[$Key] = [ordered]@{} }
                        $VoteKey = "$($Best.tierName)|$(if (Test-EntraOpsJsTruthy $Best.service) { $Best.service } else { '' })"
                        $Votes[$Key][$VoteKey] = [int]$Votes[$Key][$VoteKey] + 1
                    }
                }
                foreach ($Key in $Votes.Keys) {
                    $BestVote = $null
                    foreach ($VoteKey in $Votes[$Key].Keys) {
                        $Separator = $VoteKey.IndexOf('|')
                        $TierName = $VoteKey.Substring(0, $Separator)
                        $Rank = Get-EntraOpsReportTierRank $TierName
                        if ($null -eq $BestVote -or $Rank -lt $BestVote.rank) { $BestVote = @{ tierName = $TierName; rank = $Rank; service = $VoteKey.Substring($Separator + 1) } }
                    }
                    if ($null -eq $BestVote) { continue }
                    # The catalog tier stays when it is more privileged (an equal vote names the classified service).
                    $Catalog = $null
                    if (-not $Overwritten.Contains($Key) -and $RoleDefinitionTierIndex.TryGetValue($Key, [ref]$Catalog) -and (Get-EntraOpsReportTierRank $Catalog.tierName) -lt $BestVote.rank) { continue }
                    $RoleDefinitionTierIndex[$Key] = [pscustomobject]@{ tierName = $BestVote.tierName; service = $BestVote.service }
                }
            }
        }

        $ReportData | Add-Member -NotePropertyName PimRoleTierIndex -NotePropertyValue ([pscustomobject]@{ RoleDefinition = $RoleDefinitionTierIndex; RoleAction = $RoleActionTierIndex }) -Force
    }
    $RoleDefinitionTierIndex = $ReportData.PimRoleTierIndex.RoleDefinition
    $RoleActionTierIndex = $ReportData.PimRoleTierIndex.RoleAction

    function Get-RoleDefinitionActionTier($RoleDefinition) {
        if ($null -eq $RoleDefinition -or $RoleDefinition.rolePermissions -isnot [array]) { return $null }
        $Best = $null
        foreach ($Permission in $RoleDefinition.rolePermissions) {
            $Actions = if ($Permission -is [string]) { @($Permission) } elseif ($Permission -is [System.Collections.IDictionary] -and $Permission['AllowedResourceActions'] -is [array]) { $Permission['AllowedResourceActions'] } else { @() }
            foreach ($Action in $Actions) {
                $Candidate = $null
                if ($RoleActionTierIndex.TryGetValue("$Action".ToLowerInvariant(), [ref]$Candidate) -and ($null -eq $Best -or (Get-EntraOpsReportTierRank $Candidate.tierName) -lt (Get-EntraOpsReportTierRank $Best.tierName))) { $Best = $Candidate }
            }
        }
        return $Best
    }

    function Get-Approver($Upn) {
        $Upper = Get-Upper $Upn
        $Hit = $null
        # A display name resolves only when one object has it: with several, the approver stays unresolved
        # instead of taking the tier of the wrong object.
        $Ambiguous = $false
        if (-not $ReportData.ObjectUpnIndex.TryGetValue($Upper, [ref]$Hit)) {
            $Ambiguous = $null -ne $ReportData.PSObject.Properties['AmbiguousDisplayNames'] -and $null -ne $ReportData.AmbiguousDisplayNames -and $ReportData.AmbiguousDisplayNames.Contains($Upper)
            if (-not $Ambiguous) { $null = $ReportData.ObjectDisplayNameIndex.TryGetValue($Upper, [ref]$Hit) }
        }
        $Protection = if ($Hit) { Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id "$($Hit.objectId)" -Hit $Hit -Detail } else { $null }
        # A group without member data: who can approve is unknown, and the tier of its access says nothing about
        # how its members are protected, so it is not compared (like an unresolved approver).
        $GroupWithoutMembers = Test-EntraOpsGroupApproverWithoutMemberData -ReportData $ReportData -Id "$($Hit.objectId)" -Hit $Hit
        # A group whose member list has no user or service principal (NoMembers, or no protection tier despite member
        # data): nobody can approve through it, and the tier of its access must not stand in for it either.
        $EmptyGroup = [bool]$Hit -and (($null -ne $Protection -and $null -ne $Protection.PSObject.Properties['NoMembers'] -and $Protection.NoMembers -eq $true) -or ("$($Hit.objectType)" -eq 'group' -and $null -eq $Protection -and -not $GroupWithoutMembers))
        if ($EmptyGroup) { $GroupWithoutMembers = $false }
        # An approver named by a user principal name that is not in the Privileged EAM data is a user without
        # privileged access (also a guest): User Access, compared like a classified approver. A display name (of a
        # group, or of several objects) stays unresolved: who can approve is unknown.
        $UnprivilegedUser = -not $Hit -and -not $Ambiguous -and "$Upn" -match '^[^@\s]+@[^@\s]+$'
        # Named with the start of its object ID when another known object has its display name (a label with the
        # user principal name is unique already).
        $Name = if ($Hit -and "$($Hit.displayName)") { Get-EntraOpsUniqueDisplayName -ReportData $ReportData -Name "$($Hit.displayName)" -Id "$($Hit.objectId)" } else { "$Upn" }
        [pscustomobject]@{
            # Approvers found by display name (groups) are named once.
            label    = $(if ($GroupWithoutMembers) { "$Name (group without member data)" } elseif ($EmptyGroup) { "$Name (group without members)" } elseif ($Hit -and "$($Hit.displayName)" -ne "$Upn") { "$($Hit.displayName) ($Upn)" } elseif ($Ambiguous) { "$Upn (display name of several objects)" } else { $Name })
            # The name of the approver, for the notes of the rules.
            name     = $Name
            tier     = $(if ($Hit) { $Hit.tierName } else { 'UserAccess' })
            # The tier the approver is protected for (see Get-EntraOpsApproverProtectionTier), compared by EO.1008,
            # and for a group its least protected member (named uniquely by Get-EntraOpsApproverProtectionTier).
            protectionTier   = $(if ($UnprivilegedUser) { 'UserAccess' } else { $Protection.Tier })
            protectionMember = $Protection.Member
            resolved = ([bool]$Hit -and -not $GroupWithoutMembers -and -not $EmptyGroup) -or $UnprivilegedUser
            source   = $(if ($GroupWithoutMembers) { 'groupWithoutMembers' } elseif ($EmptyGroup) { 'emptyGroup' } elseif ($Hit) { 'direct' } else { 'default' })
        }
    }

    $Snapshots = $ReportData.Snapshots
    if ($null -eq $SnapshotIndex) {
        $SnapshotIndex = -1
        for ($Index = 0; $Index -lt $Snapshots.Count; $Index++) { if ($Snapshots[$Index].hasDetail) { $SnapshotIndex = $Index } }
    }
    $Flows = [System.Collections.Generic.List[object]]::new()
    $Snapshot = if ($SnapshotIndex -ge 0 -and $SnapshotIndex -lt $Snapshots.Count) { $Snapshots[$SnapshotIndex] } else { $null }
    $Blobs = $ReportData.ConfigurationAnalyzer['blobs']

    if ($null -ne $Snapshot) {
        $RoleDefinitions = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        $RoleSettings = [System.Collections.Generic.List[object]]::new()
        foreach ($Resource in $Snapshot.resources) {
            $Type = "$($Resource.type)".ToLowerInvariant()
            if ($Type -ne 'microsoft.entra.rolesetting' -and $Type -ne 'microsoft.entra.roledefinition') { continue }
            if (-not (Test-EntraOpsJsTruthy $Resource.h) -or $Blobs -isnot [System.Collections.IDictionary] -or -not $Blobs.Contains("$($Resource.h)")) { continue }
            $Blob = $Blobs["$($Resource.h)"]
            if ($null -eq $Blob) { continue }
            $Properties = if ($Blob -is [System.Collections.IDictionary] -and (Test-EntraOpsJsTruthy $Blob['properties'])) { $Blob['properties'] } else { @{} }
            if ($Type -eq 'microsoft.entra.roledefinition') {
                $Id = if (Test-EntraOpsJsTruthy $Properties['Id']) { $Properties['Id'] } else { $Properties['TemplateId'] }
                if (Test-EntraOpsJsTruthy $Id) {
                    $RoleDefinitions["$Id"] = [pscustomobject]@{
                        id              = $Id
                        displayName     = $(if (Test-EntraOpsJsTruthy $Properties['DisplayName']) { $Properties['DisplayName'] } else { $Resource.name })
                        rolePermissions = $(if ($Properties['RolePermissions'] -is [array]) { , $Properties['RolePermissions'] } else { , @() })
                    }
                }
            } else {
                $RoleSettings.Add([pscustomobject]@{ p = $Properties; resource = $Resource })
            }
        }

        foreach ($Item in $RoleSettings) {
            $Properties = $Item.p
            $RoleId = $Properties['Id']
            $RoleDefinition = $null
            if (Test-EntraOpsJsTruthy $RoleId) { $null = $RoleDefinitions.TryGetValue("$RoleId", [ref]$RoleDefinition) }
            $RoleName = if (Test-EntraOpsJsTruthy $Properties['DisplayName']) { $Properties['DisplayName'] } elseif ($RoleDefinition) { $RoleDefinition.displayName } else { $Item.resource.name }
            $TierHit = $null
            if (Test-EntraOpsJsTruthy $RoleId) { $null = $RoleDefinitionTierIndex.TryGetValue((Get-Upper $RoleId), [ref]$TierHit) }
            if (-not $TierHit) { $TierHit = Get-RoleDefinitionActionTier $RoleDefinition }
            $FlowRoot = if (Test-EntraOpsJsTruthy $RoleId) { "$RoleId" } else { "$($Item.resource.p)" }
            $Approvers = @(if ($Properties['ActivateApprover'] -is [array]) { foreach ($Upn in $Properties['ActivateApprover']) { Get-Approver $Upn } })

            $PathOrder = 0
            foreach ($PathKey in 'activation', 'eligibleAssignment', 'activeAssignment') {
                $Flow = [pscustomobject]@{
                    id              = "$FlowRoot|$PathKey"
                    path            = $PathKey
                    pathOrder       = $PathOrder
                    roleId          = $RoleId
                    roleName        = $RoleName
                    roleTier        = $(if ($TierHit) { $TierHit.tierName } else { $null })
                    roleTierService = $(if ($TierHit) { $TierHit.service } else { $null })
                    resourcePath    = $Item.resource.p
                    approvers       = $(if ($PathKey -eq 'activation') { , $Approvers } else { , @() })
                    p               = $Properties
                    checks          = $null
                }
                $Flow.checks = Get-EntraOpsPimRequestFlowFlag -Flow $Flow
                $Flows.Add($Flow)
                $PathOrder++
            }
        }
    }

    # The role tiers come from the Classification Explorer and EAM Dashboard datasets, which are optional: when
    # one is missing and no role has a tier, the rules for privileged roles are skipped instead of having no scope.
    $RoleTierSkipReason = $null
    if ($Flows.Count -gt 0 -and @($Flows | Where-Object { $_.roleTier }).Count -eq 0) {
        $MissingData = @(
            if ($null -eq $ReportData.TierMap) { 'Classification Explorer data (New-EntraOpsClassificationExplorerData)' }
            if ($null -eq $ReportData.EamData) { 'EAM Dashboard data (New-EntraOpsPrivilegedEamDashboardData)' }
        )
        if ($MissingData.Count -gt 0) { $RoleTierSkipReason = "None of the PIM role settings has a tier, because the report data has no $($MissingData -join ' and no '). Generate the report data with New-EntraOpsReportingData." }
    }

    [pscustomobject]@{
        Area               = 'PimRequestFlow'
        SnapshotKey        = $(if ($Snapshot) { $Snapshot.key } else { $null })
        Flows              = $Flows
        # Set when no role has a tier because the datasets with the role tiers are missing.
        RoleTierSkipReason = $RoleTierSkipReason
    }
}
