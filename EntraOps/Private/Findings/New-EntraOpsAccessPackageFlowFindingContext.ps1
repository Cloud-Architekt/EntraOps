function New-EntraOpsAccessPackageFlowFindingContext {
    <#
    .SYNOPSIS
        Builds the access package assignment policy flows that the Access Package Flow finding rules evaluate.
    .DESCRIPTION
        Builds the flow model of the Access Package Flow report for one Tenant Governance snapshot: one flow
        per access package assignment policy (id = policy id) with its requestor scope, requestors, approval
        setting, approvers, the target resources and the current assignments of the policy, each with its
        tier. The report shows these tiers (New-EntraOpsReportFindingData) and does not resolve them itself.

        Target tiers are the more privileged of the classified resource role scope tier and the tier of the
        resource itself (its own EntraOps classification). A target group is not resolved via its transitive
        membership: the package grants the access of the group, not the other access of its current members.
        A target group without role assignments takes its declared tier: the Group filters of the Alternate Tier
        Level Attributes, else the Object Classification File (source objectClassification, declaredBy names the
        source, the justification is the reason), and is unclassified without one (source unclassified, no tier).
        Requestors and approvers are subjects and are also resolved via the group membership; a known but
        unclassified user or group counts as User Access, and so do the broad requestor scopes of directory
        members and subjects. ApprovalTier of a flow is the tier its approval is protected for
        (Get-EntraOpsAccessPackageFlowApprovalTier).
        Snapshots that omit access packages or their resource role scopes are completed with the live
        access package data (New-EntraOpsAccessPackageFlowData); its requestor and approver subjects are
        matched by position, like the report does.

        The access drift of that data (Access Guardian access drift report) is the current state, so only the
        targets of the newest snapshot get their drift (target.drift, matched by resource and the catalog of
        the access package, see Get-EntraOpsAccessDrift). AccessDrift tells whether the drift data was collected.

        Every flow is checked once against the Access Package Flow rules (checks, see
        Get-EntraOpsAccessPackageFlowFlag): the report shows the failed checks as risk flags and the rule
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

    $Ordinal = [System.StringComparer]::Ordinal
    # Requestor scopes the report names (SCOPE_TYPE_LABELS of Reports/AccessPackageFlow/js/app.js); the broad
    # scopes of directory members and subjects count as User Access.
    $NamedScopeTypes = @('NoSubjects', 'AllConfiguredConnectedOrganizationSubjects', 'AllExistingConnectedOrganizationSubjects', 'AllExistingDirectoryMemberUsers', 'AllExistingDirectorySubjects', 'AllExternalSubjects')
    $UserAccessScopeTypes = @('AllExistingDirectoryMemberUsers', 'AllExistingDirectorySubjects')
    $Truthy = { param($Value) Test-EntraOpsJsTruthy $Value }
    function Get-Prop($Object, [string]$Name) { Get-EntraOpsReportProperty -Object $Object -Name $Name }
    function Get-Array($Value) { if ($Value -is [array]) { , $Value } else { , @() } }

    $AssignmentData = $ReportData.AccessPackageData
    $AssignmentsByPackage = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
    if ($null -ne $AssignmentData -and $AssignmentData['assignments'] -is [array]) {
        foreach ($Assignment in $AssignmentData['assignments']) {
            if (-not (& $Truthy $Assignment['accessPackageId'])) { continue }
            # Expired assignments no longer grant access; datasets without a state keep every assignment.
            if ("$($Assignment['state'])".ToLowerInvariant() -eq 'expired') { continue }
            $Key = "$($Assignment['accessPackageId'])"
            if (-not $AssignmentsByPackage.ContainsKey($Key)) { $AssignmentsByPackage[$Key] = [System.Collections.Generic.List[object]]::new() }
            $AssignmentsByPackage[$Key].Add($Assignment)
        }
    }
    $PolicyRequestorApprovers = if ($null -ne $AssignmentData -and $AssignmentData['policyRequestorApprovers'] -is [System.Collections.IDictionary]) { $AssignmentData['policyRequestorApprovers'] } else { @{} }
    $LivePackages = if ($null -ne $AssignmentData -and $AssignmentData['packages'] -is [System.Collections.IDictionary]) { $AssignmentData['packages'] } else { @{} }
    # Declared tiers of target groups (Alternate Tier Level Attributes or Object Classification File) by group ID, upper case.
    $ObjectClassifications = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
    if ($null -ne $AssignmentData -and $AssignmentData['objectClassifications'] -is [System.Collections.IDictionary]) {
        foreach ($GroupId in @($AssignmentData['objectClassifications'].Keys)) {
            $Declared = $AssignmentData['objectClassifications'][$GroupId]
            if ($Declared -is [System.Collections.IDictionary] -and (& $Truthy $Declared['tierName'])) { $ObjectClassifications["$GroupId".ToUpperInvariant()] = $Declared }
        }
    }
    # Without the EAM Dashboard data, no object is known as classified: groups are not judged to be without roles.
    $HasEamData = $ReportData.ObjectTierIndex.Count -gt 0
    $GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    function Find-ById($Items, $Id) {
        if ($Items -isnot [System.Collections.IDictionary] -or -not (& $Truthy $Id)) { return $null }
        if ($Items.Contains("$Id") -and (& $Truthy $Items["$Id"])) { return $Items["$Id"] }
        $Wanted = "$Id".ToUpperInvariant()
        foreach ($Candidate in $Items.Keys) { if ("$Candidate".ToUpperInvariant() -ceq $Wanted) { return $Items[$Candidate] } }
        return $null
    }

    # Tenant Governance snapshots serialize AccessPackageId as the package display name, whereas the live
    # data uses the package's GUID as the key.
    function Find-Package($Packages, $IdOrName) {
        $ById = Find-ById $Packages $IdOrName
        if ($null -ne $ById) { return $ById }
        $Wanted = "$IdOrName".ToUpperInvariant()
        foreach ($Candidate in $Packages.Keys) { if ("$($Packages[$Candidate].displayName)".ToUpperInvariant() -ceq $Wanted) { return $Packages[$Candidate] } }
        return $null
    }

    function Resolve-IdentityHit($Id, [bool]$PreferGroupMembership) {
        if (-not (& $Truthy $Id)) { return $null }
        $Upper = "$Id".ToUpperInvariant()
        $Candidates = [System.Collections.Generic.List[object]]::new()
        foreach ($Index in $ReportData.ObjectTierIndex, $ReportData.ResolvedGroupTierIndex, $ReportData.AssignmentResolvedGroupTierIndex) {
            $Hit = $null
            if ($Index.TryGetValue($Upper, [ref]$Hit) -and $null -ne $Hit) { $Candidates.Add($Hit) }
        }
        if ($Candidates.Count -eq 0) { return $null }
        # Stable sort like Array.prototype.sort: by tier rank, then (for group subjects) group roll-ups first.
        $Best = $Candidates[0]
        foreach ($Candidate in @($Candidates | Select-Object -Skip 1)) {
            $RankDiff = (Get-EntraOpsReportTierRank $Candidate.tierName) - (Get-EntraOpsReportTierRank $Best.tierName)
            if ($RankDiff -lt 0 -or ($RankDiff -eq 0 -and $PreferGroupMembership -and $Candidate.members -is [array] -and $Best.members -isnot [array])) { $Best = $Candidate }
        }
        return $Best
    }

    function Get-UserSet($UserSet, $LiveUserSet, [switch]$Approver) {
        $TypeName = "$(Get-Prop $UserSet 'odataType')".Replace('#microsoft.graph.', '')
        $Id = Get-Prop $UserSet 'Id'
        if (-not (& $Truthy $Id)) { $Id = $null }
        $IdSource = if ($Id) { 'snapshot' } else { $null }
        $LiveId = if ($null -ne $LiveUserSet) { Get-Prop $LiveUserSet 'Id' } else { $null }
        $LiveDescription = if ($null -ne $LiveUserSet) { $(if (& $Truthy (Get-Prop $LiveUserSet 'DisplayName')) { Get-Prop $LiveUserSet 'DisplayName' } else { Get-Prop $LiveUserSet 'Description' }) } else { $null }
        $SnapshotDescription = if (& $Truthy (Get-Prop $UserSet 'DisplayName')) { Get-Prop $UserSet 'DisplayName' } else { Get-Prop $UserSet 'Description' }
        if (-not $Id -and (& $Truthy $LiveId)) { $Id = $LiveId; $IdSource = 'live' }
        # A snapshot names a single user by user principal name, the indexes use object IDs: the object ID of the live
        # data, else the object of that user principal name.
        if ($Id -and "$Id" -notmatch $GuidPattern) {
            $ByUpn = $null
            if ((& $Truthy $LiveId) -and "$LiveId" -match $GuidPattern) { $Id = "$LiveId"; $IdSource = 'live' }
            elseif ($ReportData.ObjectUpnIndex.TryGetValue("$Id".ToUpperInvariant(), [ref]$ByUpn) -and (& $Truthy $ByUpn.objectId)) { $Id = "$($ByUpn.objectId)" }
        }
        $Hit = Resolve-IdentityHit $Id ($TypeName -ceq 'groupMembers')
        $Protection = if ($Hit) { Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id $Id -Hit $Hit -Detail } else { $null }
        $Tier = if ($Hit) { $Hit.tierName } else { $null }
        # A group roll-up always has members; a directly classified object never has.
        $Source = if ($Hit) { $(if ($Hit.members -is [array]) { 'groupMembership' } else { 'direct' }) } else { $null }
        # A group without member data: who can approve is unknown, and the tier of its access says nothing about
        # how its members are protected, so it is not compared (like an unresolved approver). A group without
        # members (emptyGroup) is not compared either: nobody can approve through it.
        $GroupWithoutMembers = $Approver -and (Test-EntraOpsGroupApproverWithoutMemberData -ReportData $ReportData -Id $Id -Hit $Hit)
        $NoMembers = $GroupWithoutMembers -and $null -ne $Protection -and $Protection.NoMembers -eq $true
        if ($GroupWithoutMembers) { $Source = $(if ($NoMembers) { 'emptyGroup' } else { 'groupWithoutMembers' }) }
        if (-not $Hit -and $Id -and ($TypeName -ceq 'singleUser' -or $TypeName -ceq 'groupMembers')) { $Tier = 'UserAccess'; $Source = 'default' }
        # A single user approver that is not in the Privileged EAM data is a user without privileged access: User Access,
        # compared like a classified approver (as such a user is as a member of an approver group). A group outside the
        # data stays unresolved: who can approve is unknown.
        $UnprivilegedUser = $Approver -and -not $Hit -and $Id -and $TypeName -ceq 'singleUser'
        $Description = if (& $Truthy $LiveDescription) { $LiveDescription } else { $SnapshotDescription }
        # Known objects that share the display name of another one are named with the start of their object ID.
        $HitName = if ($Hit) { Get-EntraOpsUniqueDisplayName -ReportData $ReportData -Name "$($Hit.displayName)" -Id "$Id" } else { $null }
        $Label = switch -CaseSensitive ($TypeName) {
            'singleUser' { if ($Hit) { "User: $HitName" } elseif (& $Truthy $Description) { "User: $Description" } elseif ($Id) { "User ($Id)" } else { 'User (id not captured by snapshot)' } }
            'groupMembers' { if ($Hit) { "Members of: $HitName" } elseif (& $Truthy $Description) { "Members of: $Description" } elseif ($Id) { "Members of group ($Id)" } else { 'Group members (id not captured by snapshot)' } }
            'connectedOrganizationMembers' { 'Connected org members' + $(if ($Id) { " ($Id)" } else { '' }) }
            'requestorManager' {
                $Level = Get-Prop $UserSet 'ManagerLevel'
                "Requestor's manager" + $(if ((& $Truthy $Level) -and $Level -gt 1) { " (level $Level)" } else { '' })
            }
            'internalSponsors' { 'Internal sponsors' }
            'externalSponsors' { 'External sponsors' }
            default { if ($TypeName) { $TypeName } else { 'Unknown subject' } }
        }
        $Entry = [pscustomobject]@{
            label    = $Label
            tier     = $Tier
            # The tier the subject is protected for (its own classification, for a group its least protected member),
            # compared by the approver checks (see Get-EntraOpsApproverProtectionTier).
            protectionTier = $(if ($UnprivilegedUser) { 'UserAccess' } else { $Protection.Tier })
            # The least protected member of a group subject (the reason of its protection tier).
            protectionMember = $Protection.Member
            resolved = ([bool]$Hit -and -not $GroupWithoutMembers) -or $UnprivilegedUser
            source   = $Source
            idSource = $IdSource
            id       = $Id
            groupId  = $(if ($TypeName -ceq 'groupMembers' -and $Id) { $Id } else { $null })
        }
        if ($Approver) {
            # The user set type (singleUser, groupMembers, requestorManager, ...): a user or group without an ID was not
            # captured by the snapshot and is only resolvable with the live access package data.
            $Entry | Add-Member -NotePropertyName subjectType -NotePropertyValue $TypeName
            # An approver group without members: nobody can approve through it (source emptyGroup).
            $Entry | Add-Member -NotePropertyName noMembers -NotePropertyValue ([bool]$NoMembers)
            # A fallback approver (Graph isBackup): approves when the primary approver (for example the manager) is
            # not found. Fallback approvers can approve, so they are compared; the messages mark them.
            $SnapshotIsBackup = Get-Prop $UserSet 'IsBackup'
            $IsBackup = if ($null -ne $SnapshotIsBackup) { & $Truthy $SnapshotIsBackup } elseif ($null -ne $LiveUserSet) { & $Truthy (Get-Prop $LiveUserSet 'IsBackup') } else { $false }
            $Entry | Add-Member -NotePropertyName isBackup -NotePropertyValue ([bool]$IsBackup)
        }
        $Entry
    }

    # Requestor and approver subjects, de-duplicated per approval stage by the subject (object ID, else label): two
    # different groups of the same name stay apart, and the same approver in two stages stays in both, so the stage
    # checks see every approver of a stage. LiveUserSets are matched by position.
    # Stages: the approval stage (0-based) of each user set, for the approvers; every approver of a stage can approve.
    function Get-UserSetList($UserSets, $LiveUserSets, [int[]]$Stages = @(), [switch]$Approvers) {
        $List = [System.Collections.Generic.List[object]]::new()
        $Keys = [System.Collections.Generic.HashSet[string]]::new($Ordinal)
        for ($Index = 0; $Index -lt $UserSets.Count; $Index++) {
            $Entry = Get-UserSet $UserSets[$Index] $(if ($Index -lt $LiveUserSets.Count) { $LiveUserSets[$Index] } else { $null }) -Approver:$Approvers
            $Stage = if ($Index -lt $Stages.Count) { $Stages[$Index] } else { $null }
            if ($null -ne $Stage) { $Entry | Add-Member -NotePropertyName stage -NotePropertyValue $Stage -Force }
            $Subject = if (& $Truthy $Entry.id) { "id:$("$($Entry.id)".ToUpperInvariant())" } else { "label:$($Entry.label)" }
            if ($Keys.Add("$Stage|$Subject")) { $List.Add($Entry) }
        }
        , $List
    }

    $Snapshots = $ReportData.Snapshots
    $NewestIndex = -1
    for ($Index = 0; $Index -lt $Snapshots.Count; $Index++) { if ($Snapshots[$Index].hasDetail) { $NewestIndex = $Index } }
    if ($null -eq $SnapshotIndex) { $SnapshotIndex = $NewestIndex }

    # Access drift (current state) by upper-case resource ID; only for the newest snapshot.
    $AccessDriftData = if ($null -ne $AssignmentData -and $AssignmentData['accessDrift'] -is [System.Collections.IDictionary]) { $AssignmentData['accessDrift'] } else { $null }
    $AccessDrift = [pscustomobject]@{
        Status = $(if ($null -eq $AccessDriftData) { 'missing' } else { "$($AccessDriftData['status'])" })
        Reason = $(if ($null -ne $AccessDriftData) { "$($AccessDriftData['reason'])" } else { '' })
    }
    $DriftByResource = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
    if ($AccessDrift.Status -eq 'collected' -and $SnapshotIndex -eq $NewestIndex) {
        foreach ($Drift in (Get-Array $AccessDriftData['resources'])) {
            $Key = "$($Drift['resourceId'])".ToUpperInvariant()
            if (-not $Key) { continue }
            if (-not $DriftByResource.ContainsKey($Key)) { $DriftByResource[$Key] = [System.Collections.Generic.List[object]]::new() }
            $DriftByResource[$Key].Add($Drift)
        }
    }
    $Snapshot = if ($SnapshotIndex -ge 0 -and $SnapshotIndex -lt $Snapshots.Count) { $Snapshots[$SnapshotIndex] } else { $null }
    $Blobs = $ReportData.ConfigurationAnalyzer['blobs']
    $Flows = [System.Collections.Generic.List[object]]::new()

    if ($null -ne $Snapshot) {
        # Keys are case-sensitive like the JavaScript objects of the report.
        $Catalogs = [System.Collections.Specialized.OrderedDictionary]::new($Ordinal)
        $CatalogResourcesByOriginId = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
        $Packages = [System.Collections.Specialized.OrderedDictionary]::new($Ordinal)
        $Policies = [System.Collections.Generic.List[object]]::new()
        # The origin system of the resources (AadGroup, AadApplication, SharePointOnline), by upper-case origin ID.
        $OriginSystemByOriginId = [System.Collections.Generic.Dictionary[string, string]]::new($Ordinal)
        foreach ($LivePackage in @($LivePackages.Values)) {
            if (-not (& $Truthy $LivePackage) -or $LivePackage['targets'] -isnot [array]) { continue }
            foreach ($Target in $LivePackage['targets']) {
                if ((& $Truthy $Target['originId']) -and (& $Truthy $Target['originSystem'])) { $OriginSystemByOriginId["$($Target['originId'])".ToUpperInvariant()] = "$($Target['originSystem'])" }
            }
        }
        $ResourceTypes = @('microsoft.entra.entitlementmanagementaccesspackagecatalog', 'microsoft.entra.entitlementmanagementaccesspackage', 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy', 'microsoft.entra.entitlementmanagementaccesspackagecatalogresource')
        foreach ($Resource in $Snapshot.resources) {
            $Type = "$($Resource.type)".ToLowerInvariant()
            if ($Type -notin $ResourceTypes) { continue }
            if (-not (& $Truthy $Resource.h) -or $Blobs -isnot [System.Collections.IDictionary] -or -not $Blobs.Contains("$($Resource.h)")) { continue }
            $Blob = $Blobs["$($Resource.h)"]
            if ($null -eq $Blob) { continue }
            $Properties = if ($Blob -is [System.Collections.IDictionary] -and (& $Truthy $Blob['properties'])) { $Blob['properties'] } else { @{} }
            switch ($Type) {
                'microsoft.entra.entitlementmanagementaccesspackagecatalog' {
                    $Key = if (& $Truthy (Get-Prop $Properties 'Id')) { Get-Prop $Properties 'Id' } else { $Resource.name }
                    $Catalogs["$Key"] = [pscustomobject]@{ id = Get-Prop $Properties 'Id' }
                }
                'microsoft.entra.entitlementmanagementaccesspackagecatalogresource' {
                    $OriginId = Get-Prop $Properties 'OriginId'
                    if (& $Truthy $OriginId) {
                        $CatalogResourcesByOriginId["$OriginId"] = [pscustomobject]@{
                            displayName = $(if (& $Truthy (Get-Prop $Properties 'DisplayName')) { Get-Prop $Properties 'DisplayName' } else { $Resource.name })
                            catalogId   = Get-Prop $Properties 'CatalogId'
                        }
                        if (& $Truthy (Get-Prop $Properties 'OriginSystem')) { $OriginSystemByOriginId["$OriginId".ToUpperInvariant()] = "$(Get-Prop $Properties 'OriginSystem')" }
                    }
                }
                'microsoft.entra.entitlementmanagementaccesspackage' {
                    $Key = if (& $Truthy (Get-Prop $Properties 'Id')) { Get-Prop $Properties 'Id' } else { $Resource.name }
                    $Scopes = [System.Collections.Generic.List[object]]::new()
                    foreach ($Scope in (Get-Array (Get-Prop $Properties 'AccessPackageResourceRoleScopes'))) { $Scopes.Add($Scope) }
                    $Packages["$Key"] = [pscustomobject]@{
                        id                 = Get-Prop $Properties 'Id'
                        displayName        = $(if (& $Truthy (Get-Prop $Properties 'DisplayName')) { Get-Prop $Properties 'DisplayName' } else { $Resource.name })
                        catalogId          = Get-Prop $Properties 'CatalogId'
                        resourceRoleScopes = $Scopes
                        targets            = $null
                    }
                }
                'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' {
                    $Policies.Add([pscustomobject]@{ p = $Properties; resource = $Resource })
                }
            }
        }

        # Snapshots can omit access packages and their resource role scopes: the live data restores them.
        foreach ($PackageId in @($LivePackages.Keys)) {
            $LivePackage = $LivePackages[$PackageId]
            if (-not (& $Truthy $LivePackage)) { continue }
            if (-not $Packages.Contains("$PackageId")) {
                $Packages["$PackageId"] = [pscustomobject]@{
                    id                 = $PackageId
                    displayName        = $(if (& $Truthy $LivePackage['displayName']) { $LivePackage['displayName'] } else { $PackageId })
                    catalogId          = $LivePackage['catalogId']
                    resourceRoleScopes = [System.Collections.Generic.List[object]]::new()
                    targets            = $null
                }
            }
            $Package = $Packages["$PackageId"]
            if (& $Truthy $LivePackage['displayName']) { $Package.displayName = $LivePackage['displayName'] }
            if (-not (& $Truthy $Package.catalogId) -and (& $Truthy $LivePackage['catalogId'])) { $Package.catalogId = $LivePackage['catalogId'] }
            if ($Package.resourceRoleScopes.Count -gt 0 -or $LivePackage['targets'] -isnot [array]) { continue }
            foreach ($Target in $LivePackage['targets']) {
                if ((& $Truthy $Target['originId']) -and (& $Truthy $Target['displayName'])) {
                    $CatalogResourcesByOriginId["$($Target['originId'])"] = [pscustomobject]@{ displayName = $Target['displayName']; catalogId = $null }
                }
                $Package.resourceRoleScopes.Add(@{
                        AccessPackageResourceOriginId = $Target['originId']
                        AccessPackageResourceTierName = $Target['tierName']
                    })
            }
        }

        # Target tiers: the more privileged of the classified scope tier and the tier of the resource itself.
        # The tier of a resource is its own classification (a group by its own role assignments), never the roll-up
        # of its members: the other access of the current members is not granted by the access package. A group
        # without role assignments (not in the EAM data, and its scope classification is not privileged) takes its
        # declared tier (Group filters of the Alternate Tier Level Attributes, else the Object Classification File), and is
        # unclassified without one: its scope classification
        # (User Access, "not classified in any RBAC system") only says that EntraOps knows no access it grants.
        foreach ($Package in $Packages.Values) {
            $Targets = [System.Collections.Generic.List[object]]::new()
            foreach ($Scope in $Package.resourceRoleScopes) {
                $OriginId = Get-Prop $Scope 'AccessPackageResourceOriginId'
                # Any hit (also a group roll-up) names the resource; only the object's own classification sets its tier.
                $Hit = Resolve-IdentityHit $OriginId $false
                $ObjectHit = $null
                if (& $Truthy $OriginId) { $null = $ReportData.ObjectTierIndex.TryGetValue("$OriginId".ToUpperInvariant(), [ref]$ObjectHit) }
                $ClassifiedTier = Get-Prop $Scope 'AccessPackageResourceTierName'
                if (-not (& $Truthy $ClassifiedTier)) { $ClassifiedTier = $null }
                # The access the resource grants: without its delegated permissions, which act within the rights of the
                # signed-in user (an application with delegated Control Plane permissions grants no Control Plane access).
                $ObjectHitTier = if ($null -ne $ObjectHit -and $null -ne $ObjectHit.PSObject.Properties['accessTierName']) { $ObjectHit.accessTierName } elseif ($null -ne $ObjectHit) { $ObjectHit.tierName } else { $null }
                $HitTier = if (& $Truthy $ObjectHitTier) { $ObjectHitTier } else { $null }
                $Tier = if ($ClassifiedTier -and $HitTier) {
                    if ((Get-EntraOpsReportTierRank $ClassifiedTier) -le (Get-EntraOpsReportTierRank $HitTier)) { $ClassifiedTier } else { $HitTier }
                } elseif ($ClassifiedTier) { $ClassifiedTier } else { $HitTier }
                $CatalogResource = $null
                if (& $Truthy $OriginId) { $null = $CatalogResourcesByOriginId.TryGetValue("$OriginId", [ref]$CatalogResource) }
                $CapturedName = if ($CatalogResource) { $CatalogResource.displayName } else { $null }
                $ResourceName = if ($Hit -and (& $Truthy $Hit.displayName) -and (-not (& $Truthy $CapturedName) -or $CapturedName -ceq 'Root')) { $Hit.displayName }
                elseif (& $Truthy $CapturedName) { $CapturedName } elseif (& $Truthy $OriginId) { $OriginId } else { '(unresolved resource)' }
                $Source = if ($HitTier -and $Tier -ceq $HitTier) { 'direct' } elseif ($ClassifiedTier) { 'scopeClassification' } else { $null }
                $Reason = $null
                $DeclaredBy = $null
                $UpperOriginId = if (& $Truthy $OriginId) { "$OriginId".ToUpperInvariant() } else { $null }
                $OriginSystem = $null
                if ($UpperOriginId) { $null = $OriginSystemByOriginId.TryGetValue($UpperOriginId, [ref]$OriginSystem) }
                $IsGroup = $OriginSystem -ceq 'AadGroup' -or (-not $OriginSystem -and $Hit -and $Hit.members -is [array])
                if ($IsGroup -and $HasEamData -and -not $ObjectHit -and -not (Test-EntraOpsPrivilegedTier $ClassifiedTier)) {
                    $Declared = $null
                    $null = $ObjectClassifications.TryGetValue($UpperOriginId, [ref]$Declared)
                    if ($Declared) {
                        $Tier = "$($Declared['tierName'])"
                        $Source = 'objectClassification'
                        $Reason = "$($Declared['justification'])"
                        $DeclaredBy = if (& $Truthy $Declared['declaredBy']) { "$($Declared['declaredBy'])" } else { 'Object Classification File' }
                    } else {
                        $Tier = $null
                        $Source = 'unclassified'
                    }
                }
                $Targets.Add([pscustomobject]@{ originId = $OriginId; resourceName = $ResourceName; tier = $Tier; source = $Source; reason = $Reason; declaredBy = $DeclaredBy; catalogId = $Package.catalogId; drift = (Get-EntraOpsAccessDrift -DriftByResource $DriftByResource -OriginId $OriginId -CatalogId @($Package.catalogId)) })
            }
            # Packages without a target resource keep the placeholder of the report (no model entry).
            $Package | Add-Member -NotePropertyName hasTargets -NotePropertyValue ($Targets.Count -gt 0) -Force
            if ($Targets.Count -eq 0) { $Targets.Add([pscustomobject]@{ originId = $null; resourceName = $null; tier = $null; source = $null; catalogId = $null; drift = $null }) }
            $Package.targets = $Targets
        }

        # An assignment without assignment policy id is only attributed when its package has exactly one policy.
        $PolicyCountByPackage = [System.Collections.Generic.Dictionary[string, int]]::new($Ordinal)
        foreach ($Item in $Policies) {
            $LivePolicy = Find-ById $PolicyRequestorApprovers (Get-Prop $Item.p 'Id')
            $PackageReference = if ($LivePolicy -and (& $Truthy (Get-Prop $LivePolicy 'AccessPackageId'))) { Get-Prop $LivePolicy 'AccessPackageId' } else { Get-Prop $Item.p 'AccessPackageId' }
            $PackageHit = Find-Package $Packages $PackageReference
            $ResolvedReference = if ($PackageHit -and (& $Truthy $PackageHit.id)) { $PackageHit.id } else { $PackageReference }
            if (& $Truthy $ResolvedReference) {
                $Count = 0
                $null = $PolicyCountByPackage.TryGetValue("$ResolvedReference", [ref]$Count)
                $PolicyCountByPackage["$ResolvedReference"] = $Count + 1
            }
        }

        foreach ($Item in $Policies) {
            $Properties = $Item.p
            $PolicyId = Get-Prop $Properties 'Id'
            $LiveForPolicy = Find-ById $PolicyRequestorApprovers $PolicyId
            $PackageId = if ($LiveForPolicy -and (& $Truthy (Get-Prop $LiveForPolicy 'AccessPackageId'))) { Get-Prop $LiveForPolicy 'AccessPackageId' } else { Get-Prop $Properties 'AccessPackageId' }
            $Package = Find-Package $Packages $PackageId
            $ResolvedPackageId = if ($Package -and (& $Truthy $Package.id)) { $Package.id } else { $PackageId }
            # @() keeps a single live requestor or approver an array (assigning the if statement unrolls it).
            $LiveRequestors = @(if ($LiveForPolicy -and $LiveForPolicy['requestors'] -is [array]) { $LiveForPolicy['requestors'] })
            $LiveApprovers = @(if ($LiveForPolicy -and $LiveForPolicy['approvers'] -is [array]) { $LiveForPolicy['approvers'] })

            $RequestorSettings = Get-Prop $Properties 'RequestorSettings'
            if (-not (& $Truthy $RequestorSettings)) { $RequestorSettings = @{} }
            $SnapshotScopeType = Get-Prop $RequestorSettings 'ScopeType'
            if (-not (& $Truthy $SnapshotScopeType)) { $SnapshotScopeType = 'NoSubjects' }
            $LiveScopeType = if ($LiveForPolicy) { Get-Prop $LiveForPolicy 'ScopeType' } else { $null }
            $ScopeType = if ($SnapshotScopeType -ceq 'Unknown' -and (& $Truthy $LiveScopeType)) { $LiveScopeType } else { $SnapshotScopeType }
            $AllowedRequestors = Get-Array (Get-Prop $RequestorSettings 'AllowedRequestors')
            # Policies that do not accept requests (NoSubjects or AcceptRequests disabled) are assigned by administrators only.
            $AcceptsRequests = $ScopeType -cne 'NoSubjects' -and (Get-Prop $RequestorSettings 'AcceptRequests') -ne $false
            # A named scope without specific requestors (or an "All..." scope) is the scope itself; the report
            # names it by scopeType.
            $Requestors = if ($ScopeType -cin $NamedScopeTypes -and ($AllowedRequestors.Count -eq 0 -or $ScopeType.StartsWith('All', [System.StringComparison]::Ordinal))) {
                $IsUserAccessScope = $ScopeType -cin $UserAccessScopeTypes
                , @([pscustomobject]@{ scopeType = $ScopeType; tier = $(if ($IsUserAccessScope) { 'UserAccess' } else { $null }); resolved = $false; source = $(if ($IsUserAccessScope) { 'broadScope' } else { $null }) })
            } elseif ($AllowedRequestors.Count -gt 0) {
                Get-UserSetList $AllowedRequestors $LiveRequestors
            } else {
                , @([pscustomobject]@{ scopeType = $ScopeType; tier = $null; resolved = $false; source = $null })
            }

            $ApprovalSettings = Get-Prop $Properties 'RequestApprovalSettings'
            if (-not (& $Truthy $ApprovalSettings)) { $ApprovalSettings = @{} }
            $IsApprovalRequired = & $Truthy (Get-Prop $ApprovalSettings 'IsApprovalRequired')
            # The primary approvers of every stage, with their stage (escalation approvers only act after a timeout).
            # Primary approvers include the fallback approvers (IsBackup), who approve when the primary approver
            # (for example the manager) is not found: they can approve, so they are compared as well.
            $ApproverSets = [System.Collections.Generic.List[object]]::new()
            $ApproverStages = [System.Collections.Generic.List[int]]::new()
            $StageIndex = 0
            foreach ($Stage in (Get-Array (Get-Prop $ApprovalSettings 'ApprovalStages'))) {
                foreach ($UserSet in (Get-Array (Get-Prop $Stage 'PrimaryApprovers'))) { $ApproverSets.Add($UserSet); $ApproverStages.Add($StageIndex) }
                $StageIndex++
            }
            $Approvers = [System.Collections.Generic.List[object]]::new()
            if ($IsApprovalRequired) {
                if ($ApproverSets.Count -gt 0) {
                    $Approvers = Get-UserSetList $ApproverSets $LiveApprovers $ApproverStages.ToArray() -Approvers
                } else {
                    $Approvers.Add([pscustomobject]@{ label = '(no approver captured)'; tier = $null; resolved = $false; source = $null })
                }
            }

            $Targets = if ($Package) { $Package.targets } else { @([pscustomobject]@{ originId = $null; tier = $null }) }

            $Assignments = if ((& $Truthy $ResolvedPackageId) -and $AssignmentsByPackage.ContainsKey("$ResolvedPackageId")) { $AssignmentsByPackage["$ResolvedPackageId"] } else { @() }
            $PackagePolicyCount = 0
            if (& $Truthy $ResolvedPackageId) { $null = $PolicyCountByPackage.TryGetValue("$ResolvedPackageId", [ref]$PackagePolicyCount) }
            $AssignedPrincipals = foreach ($Assignment in $Assignments) {
                if (-not (& $Truthy $Assignment['assignmentPolicyId'])) { if ($PackagePolicyCount -ne 1) { continue } }
                # Policy IDs are GUIDs: compared case-insensitively (the assignments come from Microsoft Graph, the policy from the snapshot).
                elseif ("$($Assignment['assignmentPolicyId'])" -ine "$PolicyId") { continue }
                $Target = if (& $Truthy $Assignment['target']) { $Assignment['target'] } else { @{} }
                $Hit = $null
                if (& $Truthy $Target['objectId']) { $null = $ReportData.ObjectTierIndex.TryGetValue("$($Target['objectId'])".ToUpperInvariant(), [ref]$Hit) }
                [pscustomobject]@{
                    tierName = $(if ($Hit) { $Hit.tierName } elseif (& $Truthy $Target['objectId']) { 'UserAccess' } else { 'Unclassified' })
                    resolved = [bool]$Hit
                    source   = $(if ($Hit) { 'direct' } elseif (& $Truthy $Target['objectId']) { 'default' } else { $null })
                    label    = $(foreach ($Name in $(if ($Hit) { $Hit.displayName }), $Target['displayName'], $Target['principalName'], $Target['objectId'], '(unresolved principal)') { if (& $Truthy $Name) { $Name; break } })
                    # Named with the start of the object ID when another known object has the display name.
                    name     = $(if ($Hit) { foreach ($Name in $Hit.displayName, $Target['principalName'], $Target['objectId']) { if (& $Truthy $Name) { Get-EntraOpsUniqueDisplayName -ReportData $ReportData -Name "$Name" -Id "$($Target['objectId'])"; break } } } else { $null })
                }
            }

            $Flow = [pscustomobject]@{
                id                 = $(if (& $Truthy $PolicyId) { "$PolicyId" } else { "$($Item.resource.p)" })
                name               = $(if (& $Truthy (Get-Prop $Properties 'DisplayName')) { Get-Prop $Properties 'DisplayName' } else { $Item.resource.name })
                accessPackageId    = $ResolvedPackageId
                accessPackageName  = $(if ($Package) { $Package.displayName } elseif (& $Truthy $PackageId) { $PackageId } else { '(unresolved access package)' })
                scopeType          = $ScopeType
                acceptsRequests    = $AcceptsRequests
                requestors         = @($Requestors)
                isApprovalRequired = $IsApprovalRequired
                approvers          = $Approvers
                targets            = @($Targets)
                assignedPrincipals = @($AssignedPrincipals)
                # The live access package data has the policy (with the IDs of its requestors and approvers).
                livePolicy         = [bool]$LiveForPolicy
                resourcePath       = $Item.resource.p
                properties         = $Properties
                checks             = $null
                approvalTier       = $null
            }
            $Flow.checks = Get-EntraOpsAccessPackageFlowFlag -Flow $Flow
            $Flow.approvalTier = Get-EntraOpsAccessPackageFlowApprovalTier -Flow $Flow
            $Flows.Add($Flow)
        }
    }

    [pscustomobject]@{
        Area            = 'AccessPackageFlow'
        SnapshotKey     = $(if ($Snapshot) { $Snapshot.key } else { $null })
        Flows           = $Flows
        # The Access Package Flow data (assignments) was generated: without it, no policy has assigned principals.
        HasAssignments  = ($null -ne $AssignmentData -and $AssignmentData['assignments'] -is [array])
        AccessDrift     = $AccessDrift
        # Drift entries by upper-case resource ID (newest snapshot only) for the access drift rules.
        DriftByResource = $DriftByResource
        # Target resources per access package (key as in the report) for the report model.
        Packages        = $(if ($null -ne $Snapshot) { $Packages } else { [ordered]@{} })
        # The EAM Dashboard data was loaded: only then are target groups without role assignments recognized.
        HasEamData      = $HasEamData
    }
}
