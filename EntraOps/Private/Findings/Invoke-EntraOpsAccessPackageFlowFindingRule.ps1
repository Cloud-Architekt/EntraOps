function Get-EntraOpsAccessPackageFlowApprovalTier {
    <#
    .SYNOPSIS
        The tier the approval of an access package assignment policy flow is protected for, or $null.
    .DESCRIPTION
        Evaluated like the approver checks of Get-EntraOpsAccessPackageFlowFlag (EO.1009): each resolved approver
        counts with the tier it is protected for (its protection tier, for a group its least protected member);
        any approver of a stage can approve, so a stage is as weak as its least protected approver, and every
        stage has to approve, so the approval is as strong as its strongest stage. Approvers without a stage share
        one stage. Tiers are compared by admin tier level; $null when no approver is resolved. The Access Package
        Flow report shows it as the approval tier of the policy.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Flow
    )

    $StageWorst = @{}
    foreach ($Approver in @($Flow.approvers)) {
        if ($null -eq $Approver) { continue }
        # Never the tier of the access of a group without members or member data (Get-EntraOpsApproverComparedTier).
        $Tier = "$(Get-EntraOpsApproverComparedTier -Approver $Approver)"
        if (-not ($Approver.resolved -and (Test-EntraOpsJsTruthy $Tier)) -or (Get-EntraOpsReportTierRank $Tier) -ge 5) { continue }
        $Level = Get-EntraOpsAdminTierLevel $Tier
        $Stage = if ($null -ne $Approver.PSObject.Properties['stage'] -and $null -ne $Approver.stage) { [int]$Approver.stage } else { 0 }
        if (-not $StageWorst.ContainsKey($Stage) -or $Level -gt $StageWorst[$Stage].Level) { $StageWorst[$Stage] = @{ Level = $Level; Tier = $Tier } }
    }
    $Best = $null
    foreach ($Stage in @($StageWorst.Keys | Sort-Object)) {
        if ($null -eq $Best -or $StageWorst[$Stage].Level -lt $Best.Level) { $Best = $StageWorst[$Stage] }
    }
    if ($Best) { $Best.Tier } else { $null }
}

function Get-EntraOpsAccessPackageFlowFlag {
    <#
    .SYNOPSIS
        Evaluates the Access Package Flow rules for one flow: { Applies; Failed; Text } per rule key, in report order.
    .DESCRIPTION
        Applies tells whether the assignment policy is in the scope of the rule (policies granting a Control
        Plane or Management Plane resource for the access drift flags, such policies that accept requests for
        noApproval and broadRequestor, policies with approval for the approver checks), Failed whether it fails the rule, and Text the risk flag the
        Access Package Flow report shows (New-EntraOpsReportFindingData keeps only the failed keys). A target
        is privileged when its tier is ControlPlane or ManagementPlane. New-EntraOpsAccessPackageFlowFindingContext
        evaluates every flow once (checks of the flow).
        Both approver checks only compare resolved approvers: an approver that could not be resolved
        against the EAM data counts as User Access for display only, and a policy without a resolved approver is
        not in their scope (the rules name the number of such policies in their reason). A policy with resolved and
        unresolved approvers is compared by its resolved approvers; the rules name the unresolved ones in their reason. Tiers are compared by
        admin tier level: Management and Workload Plane are both Tier 1 (like EO.1001 and EO.1002). The access drift flags (unauthorizedAccess,
        missingAccess) use the drift of the privileged targets (target.drift, newest snapshot only); their
        rules evaluate the privileged resources instead (Get-EntraOpsAccessPackageFlowDriftEvaluation).
        unclassifiedTarget applies to policies with target groups without role assignments (their tier comes from the
        Alternate Tier Level Attributes or the Object Classification File, see New-EntraOpsAccessPackageFlowFindingContext) and fails when one of them has
        no declared tier; its rule evaluates the groups instead (Get-EntraOpsAccessPackageFlowUnclassifiedEvaluation).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Flow
    )

    # The effective tier of the approval: any approver of a stage can approve, so a stage is as weak as its least
    # privileged resolved approver; every stage has to approve, so the approval is as strong as its strongest stage.
    # Approvers without a stage (older data) share one stage.
    # Levels are admin tier levels (0 Control Plane, 1 Management and Workload Plane, 2 User Access and Unclassified);
    # 9 is "none". The tier name of a level is the first tier name seen with it, for the messages.
    $None = 9
    $TierOfLevel = @{}
    function Get-Level($TierName) {
        if (-not (Test-EntraOpsJsTruthy $TierName) -or (Get-EntraOpsReportTierRank $TierName) -ge 5) { return $None }
        $Level = Get-EntraOpsAdminTierLevel $TierName
        if (-not $TierOfLevel.ContainsKey($Level)) { $TierOfLevel[$Level] = "$TierName" }
        $Level
    }
    $StageWorstLevel = @{}
    foreach ($Approver in $Flow.approvers) {
        # The tier the approver is protected for (own classification, for a group its least protected member), not
        # the tier of its access: excessive access must not make an inadequately protected approver appear safe.
        # A group approver without members or without member data has none and is not compared (never with the
        # tier of its access): see Get-EntraOpsApproverComparedTier.
        $ApproverTier = Get-EntraOpsApproverComparedTier -Approver $Approver
        if (-not ($Approver.resolved -and (Test-EntraOpsJsTruthy $ApproverTier))) { continue }
        $Level = Get-Level $ApproverTier
        if ($Level -eq $None) { continue }
        $Stage = if ($null -ne $Approver.PSObject.Properties['stage'] -and $null -ne $Approver.stage) { [int]$Approver.stage } else { 0 }
        if (-not $StageWorstLevel.ContainsKey($Stage) -or $Level -gt $StageWorstLevel[$Stage]) { $StageWorstLevel[$Stage] = $Level }
    }
    $ResolvedApproverLevel = $None
    foreach ($Level in $StageWorstLevel.Values) { $ResolvedApproverLevel = [Math]::Min($ResolvedApproverLevel, $Level) }
    $TargetLevel = $None
    $TargetTierName = $null
    foreach ($Target in $Flow.targets) {
        $Level = Get-Level $Target.tier
        if ($Level -lt $TargetLevel) { $TargetLevel = $Level; $TargetTierName = "$($Target.tier)" }
    }
    # Approval policies without a resolved approver are not in the scope of the approver checks.
    $HasResolvedApprover = $ResolvedApproverLevel -ne $None
    $TargetIsPrivileged = @($Flow.targets | Where-Object { Test-EntraOpsPrivilegedTier $_.tier }).Count -gt 0
    # Approval and requestor scope apply only to policies that accept requests (flows without the flag accept them).
    $AcceptsRequests = -not ($null -ne $Flow.PSObject.Properties['acceptsRequests'] -and $Flow.acceptsRequests -eq $false)
    # Every member, every user including guests, every external user, or the users of all (configured or existing) connected organizations.
    $BroadScopeTypes = @('AllExistingDirectoryMemberUsers', 'AllExistingDirectorySubjects', 'AllExternalSubjects', 'AllConfiguredConnectedOrganizationSubjects', 'AllExistingConnectedOrganizationSubjects')
    $Checks = [ordered]@{}
    function Add-Check([string]$Key, [bool]$Applies, [bool]$Failed, [scriptblock]$Text) {
        $IsFailed = $Applies -and $Failed
        $Checks[$Key] = [pscustomobject]@{ Applies = $Applies; Failed = $IsFailed; Text = $(if ($IsFailed) { & $Text } else { $null }) }
    }

    $TargetText = if ($TargetTierName) { "a $(Get-EntraOpsTierDisplayName $TargetTierName) resource" } else { 'a Control Plane / Management Plane resource' }
    Add-Check 'noApproval' ($TargetIsPrivileged -and $AcceptsRequests) (-not $Flow.isApprovalRequired) { "Requests for $TargetText are fulfilled without approval." }
    $ScopeText = switch -Wildcard ("$($Flow.scopeType)") {
        '*External*' { 'external user'; break }
        '*ConnectedOrganization*' { 'external user'; break }
        'AllExistingDirectorySubjects' { 'user of the directory, including guests,'; break }
        default { 'directory member' }
    }
    Add-Check 'broadRequestor' ($TargetIsPrivileged -and $AcceptsRequests) ($BroadScopeTypes -ccontains "$($Flow.scopeType)") { "Any $ScopeText can request $TargetText ($($Flow.scopeType))." }
    # The approvers that set the compared tier, with the least protected member of a group, to explain the result.
    # Fallback approvers (isBackup) are compared as they can approve, and marked as such.
    $LowerApprovers = @(@(foreach ($Approver in $Flow.approvers) {
            $ApproverTier = Get-EntraOpsApproverComparedTier -Approver $Approver
            if ($Approver.resolved -and (Get-Level $ApproverTier) -eq $ResolvedApproverLevel) {
                "$($Approver.label)$(if ($null -ne $Approver.PSObject.Properties['isBackup'] -and $Approver.isBackup -eq $true) { ' (fallback)' })$(if ($null -ne $Approver.PSObject.Properties['protectionMember'] -and $Approver.protectionMember) { " (least protected member: $($Approver.protectionMember))" })"
            }
        }) | Select-Object -Unique)
    # Only policies whose target tier is known: an unclassified target group (EO.2005) cannot be compared.
    Add-Check 'approverLowerTier' ($Flow.isApprovalRequired -and $HasResolvedApprover -and $TargetLevel -ne $None) ($ResolvedApproverLevel -gt $TargetLevel) { "Approver(s) are classified at a lower privilege tier ($(Get-EntraOpsTierDisplayName $TierOfLevel[$ResolvedApproverLevel])) than the resource being granted ($(Get-EntraOpsTierDisplayName $TargetTierName))$(if ($LowerApprovers.Count) { ": $($LowerApprovers -join ', ')" })." }
    $MorePrivileged = @(if ($Flow.isApprovalRequired -and $HasResolvedApprover) {
            foreach ($Principal in $Flow.assignedPrincipals) {
                if ($Principal.resolved -and (Get-Level $Principal.tierName) -lt $ResolvedApproverLevel) { $Principal.name }
            }
        })
    Add-Check 'assignedMorePrivileged' ($Flow.isApprovalRequired -and $HasResolvedApprover) ($MorePrivileged.Count -gt 0) {
        $Names = (@($MorePrivileged | Select-Object -First 5) -join ', ') + $(if ($MorePrivileged.Count -gt 5) { ', ' + [char]0x2026 } else { '' })
        "Currently assigned principal(s) have a higher privilege tier (the more privileged of their classification and their access) than this policy's approver(s) are protected for ($(Get-EntraOpsTierDisplayName $TierOfLevel[$ResolvedApproverLevel])$(if ($LowerApprovers.Count) { ": $($LowerApprovers -join ', ')" })): $Names."
    }
    # Access drift of the privileged targets (newest snapshot only): unauthorized and missing access separately.
    $PrivilegedDrift = @($Flow.targets | Where-Object { (Test-EntraOpsPrivilegedTier $_.tier) -and $null -ne $_.drift })
    $AsOf = $null
    foreach ($Value in @($PrivilegedDrift | ForEach-Object { $_.drift.createdDateTime })) {
        # ISO text, or a date when an older PowerShell converted it.
        $Date = [datetimeoffset]::MinValue
        if ($Value -is [datetime]) { $Date = [datetimeoffset]$Value } elseif (-not [datetimeoffset]::TryParse("$Value", [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Date)) { continue }
        if ($null -eq $AsOf -or $Date -gt $AsOf) { $AsOf = $Date }
    }
    $AsOfText = if ($null -ne $AsOf) { " as of $($AsOf.UtcDateTime.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture))" } else { '' }
    $Unauthorized = @($PrivilegedDrift | Where-Object { $_.drift.unauthorized -gt 0 })
    Add-Check 'unauthorizedAccess' $TargetIsPrivileged ($Unauthorized.Count -gt 0) {
        $Resources = @($Unauthorized | ForEach-Object { "$($_.resourceName) ($(Get-EntraOpsTierDisplayName $_.tier)): $($_.drift.unauthorized)" }) -join '; '
        "Members or app role assignments without an access package assignment on a Control Plane / Management Plane resource of this access package$AsOfText - $Resources (Access Guardian > Access Drift)."
    }
    $Missing = @($PrivilegedDrift | Where-Object { $_.drift.missing -gt 0 })
    Add-Check 'missingAccess' $TargetIsPrivileged ($Missing.Count -gt 0) {
        $Resources = @($Missing | ForEach-Object { "$($_.resourceName) ($(Get-EntraOpsTierDisplayName $_.tier)): $($_.drift.missing)" }) -join '; '
        "Access package assignments without the membership or app role assignment on a Control Plane / Management Plane resource of this access package$AsOfText - $Resources (Access Guardian > Access Drift)."
    }
    # Target groups without role assignments and without a declared tier (Alternate Tier Level Attributes or Object
    # Classification File): the access
    # their membership grants is unknown, so the tier checks above cannot judge the policy.
    $RoleLessTargets = @($Flow.targets | Where-Object { $null -ne $_.PSObject.Properties['source'] -and $_.source -cin 'unclassified', 'objectClassification' })
    $Unclassified = @($RoleLessTargets | Where-Object { $_.source -ceq 'unclassified' })
    Add-Check 'unclassifiedTarget' ($RoleLessTargets.Count -gt 0) ($Unclassified.Count -gt 0) {
        "EntraOps cannot classify $(if ($Unclassified.Count -eq 1) { 'the target group' } else { "$($Unclassified.Count) target groups" }) of this access package: $(@($Unclassified | ForEach-Object { $_.resourceName }) -join ', '). $(if ($Unclassified.Count -eq 1) { 'It has' } else { 'They have' }) no role assignment and no tier from the Alternate Tier Level Attributes or the Object Classification File, so the tier of the access the membership grants is unknown."
    }
    $Checks
}

function Invoke-EntraOpsAccessPackageFlowFindingRule {
    <#
    .SYNOPSIS
        Evaluates an Access Package Flow finding rule against the flows of the Access Package Flow context.
    .DESCRIPTION
        Pure evaluation of the assignment policy flows from New-EntraOpsAccessPackageFlowFindingContext. Returns
        the evaluated instances (see Invoke-EntraOpsFindingRuleSet): every policy in the scope of the rule,
        failed with the text of the report, from the checks the context evaluated once per flow
        (Get-EntraOpsAccessPackageFlowFlag).

        unauthorizedAccess and missingAccess evaluate the Control Plane and Management Plane resources of the
        access packages instead (one instance per resource): a resource with unauthorized or missing access in
        the access drift report fails. Without collected drift data, the rules return a SkipReason.
    .PARAMETER Context
        Context from New-EntraOpsAccessPackageFlowFindingContext.
    .PARAMETER Rule
        The Access Package Flow finding rule (from Get-EntraOpsFindingRule).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    if ($Rule.Key -cin 'unauthorizedAccess', 'missingAccess') { return (Get-EntraOpsAccessPackageFlowDriftEvaluation -Context $Context -Rule $Rule) }
    if ($Rule.Key -ceq 'unclassifiedTarget') { return (Get-EntraOpsAccessPackageFlowUnclassifiedEvaluation -Context $Context) }
    # The assigned principals come from the Access Package Flow data: without it, the rule has nothing to compare.
    if ($Rule.Key -ceq 'assignedMorePrivileged' -and $null -ne $Context.PSObject.Properties['HasAssignments'] -and -not $Context.HasAssignments) {
        return [pscustomobject]@{ SkipReason = 'No Access Package Flow data with the access package assignments found. Generate it with New-EntraOpsAccessPackageFlowData (New-EntraOpsReportingData), which reads the assignments from Microsoft Graph.' }
    }

    # The approver checks leave out approval policies without a resolved approver, and approverLowerTier the policies
    # whose target tier is unknown (unclassified target groups, EO.2005): the rule names how many, for each reason.
    # A policy without a resolved approver is named by its cause: an approver group without members, an access
    # package without live data (the snapshot has no approver IDs), or approvers that could not be resolved.
    if ($Rule.Key -cin 'approverLowerTier', 'assignedMorePrivileged') {
        $IsEmptyGroup = { param($Approver) $null -ne $Approver -and $null -ne $Approver.PSObject.Properties['source'] -and $Approver.source -ceq 'emptyGroup' }
        $NotEvaluated = @($Context.Flows | Where-Object { $_.isApprovalRequired -and $null -ne $_.checks[$Rule.Key] -and -not $_.checks[$Rule.Key].Applies })
        $NoApprover = @($NotEvaluated | Where-Object { $null -eq (Get-EntraOpsAccessPackageFlowApprovalTier -Flow $_) })
        # Approver groups without members, of every policy with approval (evaluated or not): nobody can approve
        # through them, and they are never compared with the tier of their access.
        $EmptyGroupFlowIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $EmptyGroups = @(foreach ($Flow in @($Context.Flows | Where-Object { $_.isApprovalRequired -and $null -ne $_.checks[$Rule.Key] })) {
                $Groups = @($Flow.approvers | Where-Object { & $IsEmptyGroup $_ } | ForEach-Object { "'$("$($_.label)" -replace '^Members of: ', '')'" } | Select-Object -Unique)
                if ($Groups.Count -eq 0) { continue }
                $null = $EmptyGroupFlowIds.Add("$($Flow.id)")
                "Approver group $($Groups -join ', ') of the policy '$($Flow.accessPackageName) / $($Flow.name)' $(if ($Groups.Count -eq 1) { 'has' } else { 'have' }) no members, so nobody can approve through $(if ($Groups.Count -eq 1) { 'it' } else { 'them' })$(if ($null -eq (Get-EntraOpsAccessPackageFlowApprovalTier -Flow $Flow)) { '; the policy has no other resolved approver and was not evaluated.' } elseif ($Flow.checks[$Rule.Key].Applies) { '; the policy is compared by its other approvers.' } else { '.' })"
            })
        if ($EmptyGroups.Count -gt 0) { [pscustomobject]@{ NoteOnly = $true; Note = "$(@($EmptyGroups | Select-Object -First 5) -join ' ')$(if ($EmptyGroups.Count -gt 5) { " $($EmptyGroups.Count - 5) more policies have approver groups without members." })" } }
        $NoApprover = @($NoApprover | Where-Object { -not $EmptyGroupFlowIds.Contains("$($_.id)") })
        # Policies the live access package data does not have, with user or group approvers the snapshot names
        # without an ID: their approvers cannot be resolved until the live data has the policy.
        $NoLiveData = @($NoApprover | Where-Object {
                $null -ne $_.PSObject.Properties['livePolicy'] -and -not $_.livePolicy -and
                @($_.approvers | Where-Object { $null -ne $_.PSObject.Properties['subjectType'] -and $_.subjectType -cin 'singleUser', 'groupMembers' -and -not (Test-EntraOpsJsTruthy $_.id) }).Count -gt 0
            })
        $NoLiveDataCount = @($NoLiveData | ForEach-Object { $_.id } | Select-Object -Unique).Count
        if ($NoLiveDataCount -gt 0) {
            $PackageNames = @($NoLiveData | ForEach-Object { "$($_.accessPackageName)" } | Select-Object -Unique)
            $PackageText = (@($PackageNames | Select-Object -First 5) -join ', ') + $(if ($PackageNames.Count -gt 5) { " and $($PackageNames.Count - 5) more" } else { '' })
            [pscustomobject]@{ NoteOnly = $true; Note = "$NoLiveDataCount assignment $(if ($NoLiveDataCount -eq 1) { 'policy' } else { 'policies' }) with approval $(if ($NoLiveDataCount -eq 1) { 'is' } else { 'are' }) not in the live access package data and the Tenant Governance snapshot has no approver IDs, so $(if ($NoLiveDataCount -eq 1) { 'its approvers' } else { 'their approvers' }) could not be resolved and $(if ($NoLiveDataCount -eq 1) { 'it was' } else { 'they were' }) not evaluated (generate the Access Package Flow data again with New-EntraOpsAccessPackageFlowData). Access $(if ($PackageNames.Count -eq 1) { 'package' } else { 'packages' }): $PackageText." }
        }
        $NoLiveDataIds = @($NoLiveData | ForEach-Object { "$($_.id)" })
        $Unresolved = @($NoApprover | Where-Object { $NoLiveDataIds -notcontains "$($_.id)" })
        $UnresolvedCount = @($Unresolved | ForEach-Object { $_.id } | Select-Object -Unique).Count
        # Group approvers without member data are not resolved either: named, as their policies are not evaluated.
        $GroupsWithoutMembers = @($Unresolved | ForEach-Object { $_.approvers } | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['source'] -and $_.source -ceq 'groupWithoutMembers' } | ForEach-Object { "$($_.label)" } | Select-Object -Unique)
        if ($UnresolvedCount -gt 0) { [pscustomobject]@{ NoteOnly = $true; Note = "$UnresolvedCount assignment $(if ($UnresolvedCount -eq 1) { 'policy' } else { 'policies' }) with approval $(if ($UnresolvedCount -eq 1) { 'has' } else { 'have' }) no approver resolved against the Privileged EAM data and $(if ($UnresolvedCount -eq 1) { 'was' } else { 'were' }) not evaluated.$(if ($GroupsWithoutMembers.Count) { " Group approvers without member data (generate the report data while connected to Microsoft Graph with ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets turned on): $(Join-EntraOpsFindingName $GroupsWithoutMembers)." })" } }
        $UnknownTarget = @($NotEvaluated | Where-Object { $null -ne (Get-EntraOpsAccessPackageFlowApprovalTier -Flow $_) } | ForEach-Object { $_.id } | Select-Object -Unique).Count
        if ($UnknownTarget -gt 0) { [pscustomobject]@{ NoteOnly = $true; Note = "$UnknownTarget assignment $(if ($UnknownTarget -eq 1) { 'policy' } else { 'policies' }) with approval $(if ($UnknownTarget -eq 1) { 'grants' } else { 'grant' }) no resource of a known tier (for example only unclassified target groups, EO.2005) and $(if ($UnknownTarget -eq 1) { 'was' } else { 'were' }) not evaluated." } }
    }
    # Evaluated policies that also have approvers that could not be resolved: these approvers are not compared, so
    # the rule names them and a pass is visibly incomplete. Approver groups without members are named above.
    if ($Rule.Key -cin 'approverLowerTier', 'assignedMorePrivileged') {
        $Incomplete = @(foreach ($Flow in $Context.Flows) {
                if ($null -eq $Flow.checks[$Rule.Key] -or -not $Flow.checks[$Rule.Key].Applies) { continue }
                $NotResolved = @($Flow.approvers | Where-Object { -not $_.resolved -and -not (& $IsEmptyGroup $_) } | ForEach-Object { "$($_.label)" })
                if ($NotResolved.Count -gt 0) { "$($NotResolved.Count) approver(s) of the policy '$($Flow.accessPackageName) / $($Flow.name)' could not be resolved against the Privileged EAM data and are not evaluated: $(Join-EntraOpsFindingName $NotResolved)." }
            })
        if ($Incomplete.Count -gt 0) {
            [pscustomobject]@{ NoteOnly = $true; Note = "$(@($Incomplete | Select-Object -First 5) -join ' ')$(if ($Incomplete.Count -gt 5) { " $($Incomplete.Count - 5) more policies have approvers that could not be resolved." })" }
        }
    }
    foreach ($Flow in $Context.Flows) {
        $Check = $Flow.checks[$Rule.Key]
        if ($null -eq $Check) { throw "No Access Package Flow evaluator for finding rule '$($Rule.Id)' ($($Rule.Key))." }
        if (-not $Check.Applies) { continue }
        if (-not $Check.Failed) { [pscustomobject]@{ Failed = $false; InstanceKey = $Flow.id }; continue }

        [pscustomobject]@{
            Failed      = $true
            InstanceKey = $Flow.id
            ObjectId    = "$($Flow.id)"
            ObjectType  = 'accessPackageAssignmentPolicy'
            DisplayName = "$($Flow.accessPackageName) / $($Flow.name)"
            Message     = $Check.Text
            Evidence    = [ordered]@{
                FlowId            = $Flow.id
                AccessPackageId   = $Flow.accessPackageId
                AccessPackageName = $Flow.accessPackageName
                ScopeType         = $Flow.scopeType
                SnapshotKey       = $Context.SnapshotKey
                TargetTiers       = @($Flow.targets | ForEach-Object { $_.tier })
                # Tier: the tier of the approver's access; ProtectionTier: the classification the approver checks compare.
                Approvers         = @($Flow.approvers | ForEach-Object { [ordered]@{ Label = $_.label; Tier = $_.tier; ProtectionTier = $(if ($null -ne $_.PSObject.Properties['protectionTier']) { $_.protectionTier }); LeastProtectedMember = $(if ($null -ne $_.PSObject.Properties['protectionMember']) { $_.protectionMember }); Resolved = $_.resolved; IsBackup = ($null -ne $_.PSObject.Properties['isBackup'] -and $_.isBackup -eq $true); NoMembers = ($null -ne $_.PSObject.Properties['noMembers'] -and $_.noMembers -eq $true) } })
            }
        }
    }
}

function Get-EntraOpsAccessPackageFlowDriftEvaluation {
    <#
    .SYNOPSIS
        Evaluates the access drift rules: the Control Plane and Management Plane resources of the access packages
        with unauthorized access (unauthorizedAccess) or missing access (missingAccess) in the access drift report
        of Access Guardian.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $SkipReason = switch ("$($Context.AccessDrift.Status)") {
        'collected' { $null }
        'unavailable' { "Access drift could not be read from Microsoft Graph when the Access Package Flow data was generated: $($Context.AccessDrift.Reason) The access drift report needs Microsoft Entra ID Governance or Microsoft Entra Suite and EntitlementManagement.Read.All." }
        default { 'The Access Package Flow data has no access drift. Generate it again with New-EntraOpsAccessPackageFlowData (EntraOps 1.2.0 or later).' }
    }
    if ($SkipReason) { return [pscustomobject]@{ SkipReason = $SkipReason } }
    # unauthorized: access granted outside of governance; missing: access package assignment not applied.
    $DriftType = if ($Rule.Key -ceq 'unauthorizedAccess') { 'unauthorized' } else { 'missing' }

    # One instance per privileged resource, with the access packages that grant it. Its drift is the drift in
    # the catalogs of these packages (every catalog when the catalog of a package is unknown), so a resource
    # shared by packages of several catalogs keeps the drift of each catalog.
    $Resources = [ordered]@{}
    foreach ($Flow in $Context.Flows) {
        foreach ($Target in $Flow.targets) {
            if (-not (Test-EntraOpsPrivilegedTier $Target.tier) -or -not (Test-EntraOpsJsTruthy $Target.originId)) { continue }
            $Key = "$($Target.originId)".ToUpperInvariant()
            if (-not $Resources.Contains($Key)) { $Resources[$Key] = [pscustomobject]@{ Target = $Target; AccessPackages = [System.Collections.Generic.List[string]]::new(); CatalogIds = [System.Collections.Generic.List[object]]::new() } }
            if ($Resources[$Key].AccessPackages -notcontains "$($Flow.accessPackageName)") { $Resources[$Key].AccessPackages.Add("$($Flow.accessPackageName)") }
            if ($Resources[$Key].CatalogIds -notcontains $Target.catalogId) { $Resources[$Key].CatalogIds.Add($Target.catalogId) }
        }
    }

    foreach ($Entry in $Resources.Values) {
        $Target = $Entry.Target
        $Drift = Get-EntraOpsAccessDrift -DriftByResource $Context.DriftByResource -OriginId $Target.originId -CatalogId @($Entry.CatalogIds)
        $Count = if ($null -ne $Drift) { [int]$Drift.$DriftType } else { 0 }
        $Examples = @(if ($Count -gt 0) {
                $Drift.details | Where-Object { "$($_['driftType'])" -ieq $DriftType } | ForEach-Object {
                    [ordered]@{
                        Identity      = (@($_['identities'] | Where-Object { $null -ne $_ }) | ForEach-Object { if ($_['principalName']) { "$($_['principalName'])" } else { "$($_['displayName'])" } }) -join ', '
                        AccessPackage = "$($_['accessPackageName'])"
                        AssignedRole  = "$($_['assignedRole'])"
                        ExpectedRole  = "$($_['expectedRole'])"
                    }
                }
            })
        # The drift report is generated by Microsoft Graph on its own schedule and can be days older than the
        # evaluation: the message tells its date ("as of 2026-11-08"), not only the evidence.
        $ReportDateTime = if ($null -ne $Drift) { ConvertTo-EntraOpsIsoDateTime $Drift.createdDateTime } else { $null }
        $AsOfText = if ("$ReportDateTime" -match '^\d{4}-\d{2}-\d{2}') { " as of $($Matches[0])" } else { '' }
        $Message = if ($Count -le 0) { $null }
        elseif ($DriftType -eq 'unauthorized') { "'$($Target.resourceName)' ($(Get-EntraOpsTierDisplayName $Target.tier)) has $Count member(s) or app role assignment(s) without an access package assignment$AsOfText. Access package(s): $($Entry.AccessPackages -join ', ')." }
        else { "'$($Target.resourceName)' ($(Get-EntraOpsTierDisplayName $Target.tier)) misses the membership or app role assignment of $Count access package assignment(s)$AsOfText. Access package(s): $($Entry.AccessPackages -join ', ')." }
        [pscustomobject]@{
            Failed         = $Count -gt 0
            InstanceKey    = "$($Target.originId)"
            ObjectId       = "$($Target.originId)"
            ObjectType     = $(if ($null -ne $Drift -and $Drift.resourceType) { $Drift.resourceType } else { 'accessPackageResource' })
            DisplayName    = "$($Target.resourceName)"
            AdminTierLevel = ConvertTo-EntraOpsAdminTierLevel -Value $Target.tier
            AdminTierLevelName = $(if (Test-EntraOpsJsTruthy $Target.tier) { "$($Target.tier)" } else { $null })
            Message        = $Message
            Evidence       = [ordered]@{
                Tier           = $Target.tier
                AccessPackages = @($Entry.AccessPackages)
                Count          = $Count
                TotalDrift     = $(if ($null -ne $Drift) { $Drift.total } else { 0 })
                # @(if ...) keeps a single catalog an array.
                Catalogs       = @(if ($null -ne $Drift) { $Drift.catalogNames })
                # ISO 8601 (UTC), also when the JSON reader converted it to a date.
                ReportDateTime = $ReportDateTime
                # The drift report returns up to five examples per resource (of both drift types).
                Examples       = $Examples
                MoreExamples   = $Count -gt $Examples.Count
                SnapshotKey    = $Context.SnapshotKey
            }
        }
    }
}

function Get-EntraOpsAccessPackageFlowUnclassifiedEvaluation {
    <#
    .SYNOPSIS
        Evaluates the unclassifiedTarget rule: the target groups of the access packages without role assignments.
    .DESCRIPTION
        One instance per target group without role assignments (see New-EntraOpsAccessPackageFlowFindingContext): it
        passes with a declared tier (Group filters of the Alternate Tier Level Attributes or the Object Classification
        File) and fails without one. Without the EAM
        Dashboard data, no group is known to be without role assignments and the rule returns a SkipReason.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    if ($null -ne $Context.PSObject.Properties['HasEamData'] -and -not $Context.HasEamData) {
        return [pscustomobject]@{ SkipReason = 'No EAM Dashboard data found: EntraOps cannot tell which access package target groups have no role assignment. Generate it with New-EntraOpsReportingData.' }
    }
    $Groups = [ordered]@{}
    foreach ($Flow in $Context.Flows) {
        foreach ($Target in $Flow.targets) {
            if ($null -eq $Target.PSObject.Properties['source'] -or $Target.source -cnotin 'unclassified', 'objectClassification' -or -not (Test-EntraOpsJsTruthy $Target.originId)) { continue }
            $Key = "$($Target.originId)".ToUpperInvariant()
            if (-not $Groups.Contains($Key)) { $Groups[$Key] = [pscustomobject]@{ Target = $Target; AccessPackages = [System.Collections.Generic.List[string]]::new() } }
            if ($Groups[$Key].AccessPackages -notcontains "$($Flow.accessPackageName)") { $Groups[$Key].AccessPackages.Add("$($Flow.accessPackageName)") }
        }
    }
    foreach ($Entry in $Groups.Values) {
        $Target = $Entry.Target
        $Failed = $Target.source -ceq 'unclassified'
        [pscustomobject]@{
            Failed             = $Failed
            InstanceKey        = "$($Target.originId)"
            ObjectId           = "$($Target.originId)"
            ObjectType         = 'group'
            DisplayName        = "$($Target.resourceName)"
            AdminTierLevel     = $(if ($Failed) { $null } else { ConvertTo-EntraOpsAdminTierLevel -Value $Target.tier })
            AdminTierLevelName = $(if ($Failed) { $null } else { "$($Target.tier)" })
            Message            = $(if ($Failed) { "'$($Target.resourceName)' has no role assignment and no tier from the Alternate Tier Level Attributes or the Object Classification File: the tier of the access its membership grants is unknown. Access package(s): $($Entry.AccessPackages -join ', ')." } else { $null })
            Evidence           = [ordered]@{
                Tier           = $Target.tier
                Source         = $Target.source
                Justification  = $Target.reason
                DeclaredBy     = $(if ($null -ne $Target.PSObject.Properties['declaredBy']) { $Target.declaredBy } else { $null })
                AccessPackages = @($Entry.AccessPackages)
                SnapshotKey    = $Context.SnapshotKey
            }
        }
    }
}

function Get-EntraOpsAccessDrift {
    <#
    .SYNOPSIS
        Sums the access drift of a resource in the given catalogs (Access Guardian access drift report).
    .DESCRIPTION
        Returns the totals, the drift details (up to five per resource and catalog), the catalog names and the
        report time of the drift entries of the resource whose catalog is one of -CatalogId; an empty or
        unknown catalog matches every catalog. Returns $null without matching drift.
    .PARAMETER DriftByResource
        Drift entries by upper-case resource ID (DriftByResource of New-EntraOpsAccessPackageFlowFindingContext).
    .PARAMETER OriginId
        The resource ID.
    .PARAMETER CatalogId
        The catalogs of the access packages that grant the resource.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DriftByResource,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$OriginId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$CatalogId = @()
    )

    $Entries = $null
    if ($null -eq $DriftByResource -or -not (Test-EntraOpsJsTruthy $OriginId) -or -not $DriftByResource.TryGetValue("$OriginId".ToUpperInvariant(), [ref]$Entries)) { return $null }
    $AnyCatalog = @($CatalogId).Count -eq 0 -or @(@($CatalogId) | Where-Object { -not (Test-EntraOpsJsTruthy $_) }).Count -gt 0
    $Matching = @($Entries | Where-Object { $AnyCatalog -or @($CatalogId) -contains "$($_['catalogId'])" })
    if ($Matching.Count -eq 0) { return $null }
    $Total = 0; $Unauthorized = 0; $Missing = 0
    foreach ($Entry in $Matching) { $Total += [int]$Entry['total']; $Unauthorized += [int]$Entry['unauthorized']; $Missing += [int]$Entry['missing'] }
    $Details = @(foreach ($Entry in $Matching) { foreach ($Detail in @(if ($Entry['details'] -is [array]) { $Entry['details'] })) { $Detail } })
    [pscustomobject]@{
        total           = $Total
        unauthorized    = $Unauthorized
        missing         = $Missing
        resourceType    = "$($Matching[0]['resourceType'])"
        catalogNames    = @($Matching | ForEach-Object { "$($_['catalogName'])" } | Where-Object { $_ } | Select-Object -Unique)
        createdDateTime = @($Matching | ForEach-Object { $_['createdDateTime'] } | Where-Object { $_ })[0]
        # The drift report returns up to five details per resource.
        details         = $Details
    }
}

function ConvertTo-EntraOpsIsoDateTime {
    <#
    .SYNOPSIS
        Formats a date (ISO text, [datetime] or [datetimeoffset]) as ISO 8601 in UTC (yyyy-MM-ddTHH:mm:ssZ).
    .DESCRIPTION
        Text that is no date is returned unchanged; $null or empty text returns $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    $Date = [datetimeoffset]::MinValue
    if ($Value -is [datetimeoffset]) { $Date = $Value }
    elseif ($Value -is [datetime]) { $Date = if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { [datetimeoffset]::new([datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)) } else { [datetimeoffset]$Value } }
    elseif (-not [datetimeoffset]::TryParse("$Value", [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Date)) { return "$Value" }
    $Date.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [cultureinfo]::InvariantCulture)
}
