function Test-EntraOpsJsTruthy {
    <#
    .SYNOPSIS
        Evaluates a value like a JavaScript condition (the report rules were written in JavaScript).
    .DESCRIPTION
        $null, $false, 0 and '' are false; every other value - also an empty array or object - is true.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [string]) { return $Value.Length -gt 0 }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return $Value -ne 0 -and -not [double]::IsNaN([double]$Value) }
    return $true
}

function Get-EntraOpsReportProperty {
    <#
    .SYNOPSIS
        Case-insensitive property lookup like prop() of Reports/AccessPackageFlow/js/app.js.
    .DESCRIPTION
        Returns the value of the exact key, else of the first key that matches case-insensitively, else $null.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Object -isnot [System.Collections.IDictionary]) { return $null }
    if ($Object.Contains($Name)) { return , $Object[$Name] }
    foreach ($Key in $Object.Keys) {
        if ([string]::Equals([string]$Key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return , $Object[$Key] }
    }
    return $null
}

function Import-EntraOpsReportFindingData {
    <#
    .SYNOPSIS
        Loads the report datasets that the PIM Request Flow and Access Package Flow finding rules evaluate.
    .DESCRIPTION
        The PIM Request Flow and Access Package Flow reports combine several generated datasets, so their
        finding rules evaluate the same datasets:
          * ConfigurationAnalyzer/data/configuration-analyzer-data.js: Tenant Governance snapshots (required).
          * ClassificationExplorer/data/tier-map.js: role catalog tiers (PIM Request Flow, optional).
          * EamDashboard/data/eam-dashboard-data.js: classified privileged objects (optional).
          * AccessPackageFlow/data/access-package-assignments-data.js: live access package data (optional).
        Returns $null when the Configuration Analyzer dataset is missing. The datasets are parsed with
        case-sensitive keys like JavaScript objects. Builds the object tier indexes of
        Reports/ConfigurationAnalyzer/js/core.js and the snapshot list (newest last).
    .PARAMETER ReportPath
        The Reports folder with the generated data files.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )

    $Files = [ordered]@{
        configurationAnalyzer = Read-EntraOpsReportDataFile -Path (Join-Path $ReportPath 'ConfigurationAnalyzer/data/configuration-analyzer-data.js')
        eam                   = Read-EntraOpsReportDataFile -Path (Join-Path $ReportPath 'EamDashboard/data/eam-dashboard-data.js')
        tierMap               = Read-EntraOpsReportDataFile -Path (Join-Path $ReportPath 'ClassificationExplorer/data/tier-map.js')
        accessPackage         = Read-EntraOpsReportDataFile -Path (Join-Path $ReportPath 'AccessPackageFlow/data/access-package-assignments-data.js')
    }
    if ($null -eq $Files.configurationAnalyzer) { return $null }
    $ConfigurationAnalyzer = $Files.configurationAnalyzer.Data
    $EamData = if ($Files.eam) { $Files.eam.Data }
    $TierMap = if ($Files.tierMap) { $Files.tierMap.Data }
    $AccessPackageData = if ($Files.accessPackage) { $Files.accessPackage.Data }

    # The snapshot key of the reports ("<commitSha>|<commitDate>") uses the values exactly as written, and so
    # does the generation time of each dataset: the reports tell by it whether findings generated from these
    # datasets still match the datasets they show.
    $Raw = Get-EntraOpsReportDataRawValue -DataFile $Files.configurationAnalyzer -Name 'generatedAt' -ArrayName 'snapshots' -ElementProperty 'commitSha', 'commitDate'
    $SnapshotKeys = $Raw.ElementKeys
    $SourceStamps = [ordered]@{
        configurationAnalyzer = $Raw.Values['generatedAt']
        eam                   = $(if ($Files.eam) { (Get-EntraOpsReportDataRawValue -DataFile $Files.eam -Name 'generatedAt').Values['generatedAt'] })
        tierMap               = $(if ($Files.tierMap) { (Get-EntraOpsReportDataRawValue -DataFile $Files.tierMap -Name 'generatedUtc').Values['generatedUtc'] })
        accessPackage         = $(if ($Files.accessPackage) { (Get-EntraOpsReportDataRawValue -DataFile $Files.accessPackage -Name 'generatedAt').Values['generatedAt'] })
    }

    # Snapshot model of core.js: resource type and name from the resource path.
    $Snapshots = [System.Collections.Generic.List[object]]::new()
    $SnapshotNumber = -1
    foreach ($Snapshot in @($ConfigurationAnalyzer['snapshots'])) {
        $SnapshotNumber++
        if ($null -eq $Snapshot) { continue }
        $Resources = foreach ($Resource in @($Snapshot['resources'])) {
            if ($null -eq $Resource) { continue }
            $Segments = "$($Resource['p'])".Split('/')
            [ordered]@{
                p        = $Resource['p']
                h        = $Resource['h']
                type     = $(if ($Segments[0]) { $Segments[0] } else { 'unknown' })
                name     = $Segments[-1] -replace '(?i)\.json$', ''
            }
        }
        $Snapshots.Add([ordered]@{
                commitSha  = $Snapshot['commitSha']
                commitDate = $Snapshot['commitDate']
                key        = $SnapshotKeys[$SnapshotNumber]
                hasDetail  = Test-EntraOpsJsTruthy $Snapshot['hasDetail']
                resources  = @($Resources)
            })
    }

    # Object tier indexes of core.js: one entry per object with its most privileged tier.
    $Ordinal = [System.StringComparer]::Ordinal
    $ObjectTierIndex = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
    $ObjectUpnIndex = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
    $ObjectDisplayNameIndex = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
    $AmbiguousDisplayNames = [System.Collections.Generic.HashSet[string]]::new($Ordinal)
    if ($null -ne $EamData -and $EamData['objects'] -is [array]) {
        foreach ($Object in $EamData['objects']) {
            if (-not (Test-EntraOpsJsTruthy $Object['objectId'])) { continue }
            $Services = [System.Collections.Generic.List[string]]::new()
            foreach ($Classification in @($Object['classification'])) { if ($null -ne $Classification -and (Test-EntraOpsJsTruthy $Classification['service']) -and -not $Services.Contains($Classification['service'])) { $Services.Add($Classification['service']) } }
            $TierNames = [System.Collections.Generic.List[object]]::new()
            $TierNames.Add($Object['objectAdminTierLevelName'])
            foreach ($Classification in @($Object['classification'])) { if ($null -ne $Classification) { $TierNames.Add($Classification['adminTierLevelName']) } }
            # The access of the object itself, without delegated permissions: an application acts within the rights of
            # the signed-in user with a delegated permission (as highestAccessTierName of Privileged Assets).
            $AccessTierNames = [System.Collections.Generic.List[object]]::new()
            $HasDelegated = $false
            $AccessTierNames.Add($Object['objectAdminTierLevelName'])
            foreach ($Assignment in @($Object['roleAssignments'])) {
                if ($null -eq $Assignment) { continue }
                foreach ($Classification in @($Assignment['classification'])) {
                    if ($null -eq $Classification) { continue }
                    $TierNames.Add($Classification['adminTierLevelName'])
                    if ("$($Assignment['roleType'])" -ne 'Delegated') { $AccessTierNames.Add($Classification['adminTierLevelName']) } else { $HasDelegated = $true }
                    if ((Test-EntraOpsJsTruthy $Classification['service']) -and -not $Services.Contains($Classification['service'])) { $Services.Add($Classification['service']) }
                }
            }
            $EffectiveTier = $null
            # Only tier names count: an unknown name (rank 5) never becomes the tier of the object.
            $EffectiveRank = 5
            foreach ($TierName in $TierNames) {
                if (-not (Test-EntraOpsJsTruthy $TierName)) { continue }
                $Rank = Get-EntraOpsReportTierRank $TierName
                if ($Rank -lt $EffectiveRank) { $EffectiveRank = $Rank; $EffectiveTier = $TierName }
            }
            if (-not $EffectiveTier) { $EffectiveTier = 'Unclassified' }
            $AccessTier = 'Unclassified'
            foreach ($TierName in $AccessTierNames) {
                if ((Test-EntraOpsJsTruthy $TierName) -and (Get-EntraOpsReportTierRank $TierName) -lt (Get-EntraOpsReportTierRank $AccessTier)) { $AccessTier = "$TierName" }
            }
            # Delegated permissions only: access through the object stays within the rights of the user, User Access.
            if ($HasDelegated -and $AccessTier -ceq 'Unclassified') { $AccessTier = 'UserAccess' }
            # The classification of the object itself: the tier it is protected for (tierName is the most privileged
            # of this and its access). The approver checks compare the protection of the approver, so existing
            # excessive access does not make an approver appear adequately protected.
            $OwnTier = if (Test-EntraOpsJsTruthy $Object['objectAdminTierLevelName']) { "$($Object['objectAdminTierLevelName'])" } else { 'Unclassified' }

            $Key = "$($Object['objectId'])".ToUpperInvariant()
            $Entry = $null
            if ($ObjectTierIndex.TryGetValue($Key, [ref]$Entry)) {
                foreach ($Service in $Services) { if (-not $Entry.services.Contains($Service)) { $Entry.services.Add($Service) } }
                if ((Get-EntraOpsReportTierRank $EffectiveTier) -lt (Get-EntraOpsReportTierRank $Entry.tierName)) { $Entry.tierName = $EffectiveTier }
                if ((Get-EntraOpsReportTierRank $AccessTier) -lt (Get-EntraOpsReportTierRank $Entry.accessTierName)) { $Entry.accessTierName = $AccessTier }
                if (-not $Entry.userPrincipalName -and (Test-EntraOpsJsTruthy $Object['objectUserPrincipalName'])) { $Entry.userPrincipalName = $Object['objectUserPrincipalName'] }
                if (-not $Entry.displayName -and (Test-EntraOpsJsTruthy $Object['objectDisplayName'])) { $Entry.displayName = $Object['objectDisplayName'] }
                if ($Entry.objectTierName -eq 'Unclassified' -and $OwnTier -ne 'Unclassified') { $Entry.objectTierName = $OwnTier }
            } else {
                $Entry = [pscustomobject]@{
                    objectId          = $Object['objectId']
                    objectType        = $(if (Test-EntraOpsJsTruthy $Object['objectType']) { $Object['objectType'] } else { '' })
                    userPrincipalName = $(if (Test-EntraOpsJsTruthy $Object['objectUserPrincipalName']) { $Object['objectUserPrincipalName'] } else { '' })
                    tierName          = $EffectiveTier
                    # The tier without delegated permissions (the access the object itself grants), for access package targets.
                    accessTierName    = $AccessTier
                    objectTierName    = $OwnTier
                    services          = $Services
                    displayName       = $(if (Test-EntraOpsJsTruthy $Object['objectDisplayName']) { $Object['objectDisplayName'] } else { '' })
                    members           = $null
                }
                $ObjectTierIndex[$Key] = $Entry
            }
            if (Test-EntraOpsJsTruthy $Object['objectUserPrincipalName']) { $ObjectUpnIndex["$($Object['objectUserPrincipalName'])".ToUpperInvariant()] = $Entry }
            if (Test-EntraOpsJsTruthy $Object['objectDisplayName']) {
                $NameKey = "$($Object['objectDisplayName'])".ToUpperInvariant()
                # A display name of several objects does not identify one of them (the index keeps the last one).
                $Named = $null
                if ($ObjectDisplayNameIndex.TryGetValue($NameKey, [ref]$Named) -and "$($Named.objectId)" -ne "$($Entry.objectId)") { $null = $AmbiguousDisplayNames.Add($NameKey) }
                $ObjectDisplayNameIndex[$NameKey] = $Entry
            }
        }
    }

    # Groups resolved via their transitive membership (Configuration Analyzer and Access Package Flow data).
    function New-GroupTierIndex($Groups) {
        $Index = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
        if ($Groups -isnot [System.Collections.IDictionary]) { return , $Index }
        foreach ($Id in $Groups.Keys) {
            $Group = $Groups[$Id]
            if ($Group -is [System.Collections.IDictionary] -and (Test-EntraOpsJsTruthy $Group['tierName'])) {
                $Index["$Id".ToUpperInvariant()] = [pscustomobject]@{
                    tierName              = $Group['tierName']
                    displayName           = $Group['displayName']
                    members               = $(if ($Group['members'] -is [array]) { , $Group['members'] } else { $null })
                    totalMembers          = $Group['totalMembers']
                    principalCount        = $Group['principalCount']
                    privilegedMemberCount = $Group['privilegedMemberCount']
                }
            }
        }
        return , $Index
    }
    $ResolvedGroupTierIndex = New-GroupTierIndex $ConfigurationAnalyzer['resolvedGroupTiers']
    $AssignmentResolvedGroupTierIndex = New-GroupTierIndex $(if ($AccessPackageData) { $AccessPackageData['resolvedGroupTiers'] })

    # The object IDs of every display name the datasets know (classified objects, resolved groups and their members),
    # so the messages tell objects of the same name apart (Get-EntraOpsUniqueDisplayName). Members count as well: a
    # regular user can share the name of a classified account, and only its group membership is in the data.
    $DisplayNameObjectIds = [System.Collections.Generic.Dictionary[string, object]]::new($Ordinal)
    $AddName = {
        param($Name, $Id)
        if (-not (Test-EntraOpsJsTruthy $Name) -or -not (Test-EntraOpsJsTruthy $Id)) { return }
        $NameKey = "$Name".ToUpperInvariant()
        $Ids = $null
        if (-not $DisplayNameObjectIds.TryGetValue($NameKey, [ref]$Ids)) { $Ids = [System.Collections.Generic.HashSet[string]]::new($Ordinal); $DisplayNameObjectIds[$NameKey] = $Ids }
        $null = $Ids.Add("$Id".ToUpperInvariant())
    }
    foreach ($Entry in $ObjectTierIndex.Values) { & $AddName $Entry.displayName $Entry.objectId }
    foreach ($Index in $ResolvedGroupTierIndex, $AssignmentResolvedGroupTierIndex) {
        foreach ($GroupId in $Index.Keys) {
            & $AddName $Index[$GroupId].displayName $GroupId
            foreach ($Member in @($Index[$GroupId].members)) {
                if ($Member -is [System.Collections.IDictionary]) { & $AddName $Member['displayName'] $Member['id'] } elseif ($null -ne $Member) { & $AddName $Member.displayName $Member.id }
            }
        }
    }

    [pscustomobject]@{
        ConfigurationAnalyzer            = $ConfigurationAnalyzer
        EamData                          = $EamData
        TierMap                          = $TierMap
        AccessPackageData                = $AccessPackageData
        SourceStamps                     = $SourceStamps
        Snapshots                        = $Snapshots
        ObjectTierIndex                  = $ObjectTierIndex
        ObjectUpnIndex                   = $ObjectUpnIndex
        ObjectDisplayNameIndex           = $ObjectDisplayNameIndex
        # Display names (upper case) of more than one object.
        AmbiguousDisplayNames            = $AmbiguousDisplayNames
        ResolvedGroupTierIndex           = $ResolvedGroupTierIndex
        AssignmentResolvedGroupTierIndex = $AssignmentResolvedGroupTierIndex
        # Object IDs (upper case) by display name (upper case), of every object the datasets name.
        DisplayNameObjectIds             = $DisplayNameObjectIds
    }
}

function Get-EntraOpsUniqueDisplayName {
    <#
    .SYNOPSIS
        Returns the display name of an object, with the first eight characters of its object ID when the datasets
        know another object of the same name ("Name (1a2b3c4d)").
    .DESCRIPTION
        Display names are not unique (a guest and a member account of the same person, for example): a message that
        names "Adele Vance" must tell which of them. The known objects are those of DisplayNameObjectIds of
        Import-EntraOpsReportFindingData; without it, or without an ID, the name is returned unchanged.
    .PARAMETER ReportData
        Report data from Import-EntraOpsReportFindingData.
    .PARAMETER Name
        The display name.
    .PARAMETER Id
        The object ID of the named object.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$ReportData,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Id
    )

    if (-not $Name -or -not $Id -or $null -eq $ReportData -or $null -eq $ReportData.PSObject.Properties['DisplayNameObjectIds'] -or $null -eq $ReportData.DisplayNameObjectIds) { return $Name }
    $Ids = $null
    if (-not $ReportData.DisplayNameObjectIds.TryGetValue($Name.ToUpperInvariant(), [ref]$Ids) -or $Ids.Count -le 1) { return $Name }
    # The same pattern as Get-UniqueName of the Privileged Assets rules.
    "$Name ($($Id.Substring(0, [Math]::Min(8, $Id.Length))))"
}

function Get-EntraOpsApproverComparedTier {
    <#
    .SYNOPSIS
        The tier an approver is compared with by the approver checks (EO.1008, EO.1009, EO.1010), or $null.
    .DESCRIPTION
        The protection tier of the approver (Get-EntraOpsApproverProtectionTier); an approver without one (data of
        older contexts and tests) counts with its tier. A group approver without members or without member data
        never falls back to its tier: the tier of the access of the group says nothing about who approves, and a
        group without members has nobody who can approve. Such approvers have source emptyGroup or
        groupWithoutMembers (or noMembers set) and return $null.
    .PARAMETER Approver
        An approver of a flow context.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Approver
    )

    if ($null -eq $Approver) { return $null }
    if ($null -ne $Approver.PSObject.Properties['protectionTier'] -and (Test-EntraOpsJsTruthy $Approver.protectionTier)) { return $Approver.protectionTier }
    if ($null -ne $Approver.PSObject.Properties['noMembers'] -and $Approver.noMembers -eq $true) { return $null }
    if ($null -ne $Approver.PSObject.Properties['source'] -and "$($Approver.source)" -cin 'emptyGroup', 'groupWithoutMembers') { return $null }
    $Approver.tier
}

function Test-EntraOpsGroupApproverWithoutMemberData {
    <#
    .SYNOPSIS
        Tests whether an approver is a group without a known member who can approve: its members are unknown (no
        member list in the report data), or its member list has no user or service principal (an empty group).
    .DESCRIPTION
        Such a group has no protection tier, and the tier of its access says nothing about how its members are
        protected: the flow contexts treat it as an unresolved approver (source groupWithoutMembers) and must never
        compare the tier of its access instead. An empty group is included, as nobody can approve through it; the
        NoMembers property of Get-EntraOpsApproverProtectionTier -Detail tells it apart (the Access Package Flow
        context gives it the source emptyGroup).
    .PARAMETER ReportData
        Report data from Import-EntraOpsReportFindingData.
    .PARAMETER Id
        Object ID of the approver.
    .PARAMETER Hit
        The resolved entry of the approver.
    #>
    param($ReportData, [string]$Id, $Hit)

    if ($null -eq $Hit) { return $false }
    # A member list without a principal: nobody can approve, so the group must not count with the tier of its access.
    if ((Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id $Id -Hit $Hit -Detail).NoMembers) { return $true }
    if ($Hit.members -is [array]) { return $false }
    if ("$($Hit.objectType)" -ne 'group') { return $false }
    $Upper = "$Id".ToUpperInvariant()
    foreach ($Index in $ReportData.ResolvedGroupTierIndex, $ReportData.AssignmentResolvedGroupTierIndex) {
        $Candidate = $null
        if ($Upper -and $null -ne $Index -and $Index.TryGetValue($Upper, [ref]$Candidate) -and $Candidate.members -is [array]) { return $false }
    }
    return $true
}

function Get-EntraOpsApproverProtectionTier {
    <#
    .SYNOPSIS
        Returns the tier an approver is protected for: the classification of the approver itself, or for a group,
        of its least protected member.
    .DESCRIPTION
        Every member of an approver group can approve, so the group is only as protected as its weakest member.
        A group without member data has no protection tier ($null): the flow contexts then treat the group as an
        unresolved approver (source groupWithoutMembers), as the tier of its access says nothing about its members.
        Members of a resolved group that are not in the Privileged EAM data (totalMembers above
        privilegedMemberCount) are regular users: User Access. The members of both group tier indexes count
        (Configuration Analyzer and Access Package Flow data), so such a member is named when one of them lists it;
        otherwise it is "a member without privileged access". Members in the data use their own classification
        (objectTierName of the object tier index), not the tier of their access. Returns $null when the approver
        is not resolved.
    .PARAMETER ReportData
        Report data from Import-EntraOpsReportFindingData.
    .PARAMETER Id
        Object ID of the approver (user or group).
    .PARAMETER Hit
        The resolved entry of the approver (object tier index or a group tier index), if already looked up.
    .PARAMETER Detail
        Returns an object with the tier (Tier), for a group the least protected member (Member, with the start of its
        object ID when another known object has its name, see Get-EntraOpsUniqueDisplayName) and NoMembers instead of
        the tier. NoMembers is $true for a group whose member list has no user or service principal: nobody can
        approve through it, and its Tier is $null (never the tier of the access of the group).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$ReportData,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Id,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Hit,

        [Parameter(Mandatory = $false)]
        [switch]$Detail
    )
    $Return = { param($Tier, $Member, $NoMembers = $false) if ($Detail) { [pscustomobject]@{ Tier = $Tier; Member = $Member; NoMembers = $NoMembers } } else { $Tier } }

    $Upper = "$Id".ToUpperInvariant()
    $Group = $null
    # The members of the group in both group tier indexes: the Configuration Analyzer lists only the privileged
    # members, the Access Package Flow data all members of its groups. The other index adds the members that the
    # first one leaves out, so the least protected member is named where one of them lists it.
    $Members = [System.Collections.Generic.List[object]]::new()
    $MemberIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $AddMembers = {
        param($Source)
        foreach ($Member in @($Source.members)) {
            if ($null -eq $Member) { continue }
            $MemberId = "$(if ($Member -is [System.Collections.IDictionary]) { $Member['id'] } else { $Member.id })"
            if (-not $MemberId -or $MemberIds.Add($MemberId)) { $Members.Add($Member) }
        }
    }
    if ($Upper) {
        foreach ($Index in $ReportData.ResolvedGroupTierIndex, $ReportData.AssignmentResolvedGroupTierIndex) {
            $Candidate = $null
            if ($null -ne $Index -and $Index.TryGetValue($Upper, [ref]$Candidate) -and $Candidate.members -is [array]) {
                if ($null -eq $Group) { $Group = $Candidate }
                & $AddMembers $Candidate
            }
        }
    }
    if ($null -eq $Group -and $null -ne $Hit -and $Hit.members -is [array]) { $Group = $Hit; & $AddMembers $Hit }
    if ($null -ne $Group) {
        # Nested groups are not approvers themselves: their members are listed as well (transitive membership).
        $Principals = @(foreach ($Member in $Members) {
                $Get = { param($Name) if ($Member -is [System.Collections.IDictionary]) { $Member[$Name] } else { $Member.$Name } }
                $MemberId = "$(& $Get 'id')".ToUpperInvariant()
                $Entry = $null
                # Report data without the object tier index (tests of the group indexes only): no member is classified.
                $null = $MemberId -and $null -ne $ReportData.PSObject.Properties['ObjectTierIndex'] -and $null -ne $ReportData.ObjectTierIndex -and $ReportData.ObjectTierIndex.TryGetValue($MemberId, [ref]$Entry)
                if ("$(& $Get 'objectType')" -eq 'group' -or ($null -ne $Entry -and "$($Entry.objectType)" -eq 'group')) { continue }
                [pscustomobject]@{
                    Tier = $(if ($null -ne $Entry -and $Entry.objectTierName) { $Entry.objectTierName } else { 'UserAccess' })
                    Name = $(if ("$(& $Get 'displayName')") { Get-EntraOpsUniqueDisplayName -ReportData $ReportData -Name "$(& $Get 'displayName')" -Id "$(& $Get 'id')" } elseif ($null -ne $Entry -and $Entry.displayName) { Get-EntraOpsUniqueDisplayName -ReportData $ReportData -Name "$($Entry.displayName)" -Id "$(& $Get 'id')" } else { "$(& $Get 'id')" })
                }
            })
        # Members that are not listed (a group of the Configuration Analyzer lists only privileged members) are regular users.
        $Total = if ($null -ne $Group.PSObject.Properties['principalCount'] -and $null -ne $Group.principalCount) { [int]$Group.principalCount } else { [int]$Group.totalMembers }
        if ($Total -gt $Principals.Count) { $Principals += [pscustomobject]@{ Tier = 'UserAccess'; Name = 'a member without privileged access' } }
        # No member who can approve (an empty group, or only nested groups without members): no protection tier.
        if ($Principals.Count -eq 0) { return (& $Return $null $null $true) }
        $Weakest = @($Principals | Sort-Object { Get-EntraOpsReportTierRank $_.Tier } -Descending)[0]
        return (& $Return $Weakest.Tier $Weakest.Name)
    }

    $Entry = $Hit
    if ($null -eq $Entry -and $Upper) { $null = $ReportData.ObjectTierIndex.TryGetValue($Upper, [ref]$Entry) }
    if ($null -eq $Entry) { return $null }
    # A group without member data: its own classification says nothing about the members who approve (groups
    # usually have no tier tag), so there is no protection tier and the approver is not compared.
    if ("$($Entry.objectType)" -eq 'group') { return $null }
    if ($null -ne $Entry.PSObject.Properties['objectTierName'] -and $Entry.objectTierName) { return (& $Return $Entry.objectTierName $null) }
    return (& $Return $Entry.tierName $null)
}
