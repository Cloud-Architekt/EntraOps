function ConvertFrom-EntraOpsIsoDuration {
    <#
    .SYNOPSIS
        Converts an ISO 8601 duration (for example P365D, PT8H or P1Y) to hours.
    .DESCRIPTION
        Years count as 365 days and months as 30 days. Returns $null for empty or invalid values.
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Duration
    )

    if ("$Duration" -notmatch '^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$' -or "$Duration" -eq 'P' -or "$Duration" -eq 'PT') { return $null }
    $Value = { param($Index) if ($Matches[$Index]) { [double]$Matches[$Index] } else { 0 } }
    return ((& $Value 1) * 365 + (& $Value 2) * 30 + (& $Value 3) * 7 + (& $Value 4)) * 24 + (& $Value 5) + (& $Value 6) / 60 + (& $Value 7) / 3600
}

function Format-EntraOpsIsoDuration {
    <#
    .SYNOPSIS
        Formats an ISO 8601 duration for messages: PT8H as "8 hours", P365D as "365 days", P1Y as "1 year".
    .DESCRIPTION
        Every part of the duration is named (P1DT12H as "1 day 12 hours"). A value that is no ISO 8601 duration is
        returned unchanged.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Duration
    )

    if ("$Duration" -notmatch '^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$' -or "$Duration" -eq 'P' -or "$Duration" -eq 'PT') { return "$Duration" }
    $Units = @('year', 'month', 'week', 'day', 'hour', 'minute', 'second')
    $Parts = @(for ($Index = 1; $Index -le 7; $Index++) {
            if ($Matches[$Index]) { $Number = [int]$Matches[$Index]; "$Number $($Units[$Index - 1])$(if ($Number -ne 1) { 's' })" }
        })
    if ($Parts.Count -eq 0) { return "$Duration" }
    $Parts -join ' '
}

function Invoke-EntraOpsTenantGovernanceFindingRule {
    <#
    .SYNOPSIS
        Evaluates a Tenant Governance finding rule against the settings of the newest snapshot.
    .DESCRIPTION
        Pure evaluation of the context from New-EntraOpsTenantGovernanceFindingContext: PIM role settings of
        Control and Management Plane roles, access package assignment policies of Control and Management Plane
        resources, enabled Conditional Access policies and administrative units. Returns the evaluated
        instances (see Invoke-EntraOpsFindingRuleSet).

        conditionalAccessControlPlaneExclusion does not report emergency access accounts: the accounts and
        groups of EmergencyAccessAccounts. Without the setting, every excluded Control Plane user is reported; the
        users excluded from every enabled policy (with at least two enabled policies) are typically the emergency
        access accounts, so the reason of the rule names them to add to the setting. Excluded directory roles count when their tier is Control Plane (by the
        PIM role settings of the snapshot). It does not report the exclusions of a block policy that other enabled
        policies target (allow-list of the block policy, for example privileged accounts excluded from a policy
        that blocks everyone else from admin portals); they are listed in the evidence (ScopedExclusions). An excluded
        group with member data is part of the allow-list as well when each of its Control Plane users, without the
        emergency access accounts, is targeted by another enabled policy that does not exclude them: by user, as
        (transitive) member of an included group with member data, or by an included directory role they hold actively
        on the directory. Otherwise the result names the Control Plane members that remain uncovered
        (UncoveredControlPlaneMembers). Three or more policies whose only reported exclusion is the same user or group
        are one result for that user or group, with the policies in its evidence (Policies).

        controlPlaneActivationAuthContext also fails when the required authentication context is not targeted by an
        enabled Conditional Access policy of the snapshot (authContextPolicy of the PIM flow).

        Without the EAM Dashboard objects (an optional dataset), conditionalAccessControlPlaneExclusion (when a
        policy excludes users) and dynamicPrivilegedAdministrativeUnit return a SkipReason, and so do the rules
        of the PIM role settings when no role has a tier because a dataset with the role tiers is missing.
    .PARAMETER Context
        Context from New-EntraOpsTenantGovernanceFindingContext.
    .PARAMETER Rule
        The Tenant Governance finding rule (from Get-EntraOpsFindingRule).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $ReportData = $Context.ReportData
    function New-RoleInstance($Flow, [bool]$Failed, [string]$Message, [System.Collections.IDictionary]$Evidence = [ordered]@{}) {
        $Evidence['RoleTier'] = $Flow.roleTier
        # The flow of the PIM Request Flow report (#flow=).
        $Evidence['FlowId'] = $Flow.id
        $Evidence['SnapshotKey'] = $Context.SnapshotKey
        [pscustomobject]@{
            Failed         = $Failed
            InstanceKey    = $Flow.id
            ObjectId       = "$($Flow.roleId)"
            ObjectType     = 'roleSetting'
            DisplayName    = "$($Flow.roleName)"
            AdminTierLevel = Get-EntraOpsAdminTierLevel $Flow.roleTier
            AdminTierLevelName = $(if ($Flow.roleTier) { "$($Flow.roleTier)" } else { $null })
            Message        = $Message
            Evidence       = $Evidence
        }
    }
    function New-PolicyInstance($Flow, [bool]$Failed, [string]$Message) {
        [pscustomobject]@{
            Failed      = $Failed
            InstanceKey = $Flow.id
            ObjectId    = $Flow.id
            ObjectType  = 'accessPackageAssignmentPolicy'
            DisplayName = "$($Flow.accessPackageName) / $($Flow.name)"
            Message     = $Message
            Evidence    = [ordered]@{ AccessPackageId = $Flow.accessPackageId; AccessPackageName = $Flow.accessPackageName; TargetTiers = @($Flow.targets | ForEach-Object { $_.tier } | Where-Object { $_ } | Select-Object -Unique); SnapshotKey = $Context.SnapshotKey }
        }
    }
    $PrivilegedPolicies = @($Context.AccessPackage.Flows | Where-Object { @($_.targets | Where-Object { Test-EntraOpsPrivilegedTier $_.tier }).Count -gt 0 })
    function Get-Setting($Flow, [string]$Name) { $Flow.p[$Name] }
    # The EAM Dashboard dataset is optional. Without its objects no user resolves to a tier, so the rules that need
    # the objects are skipped instead of passing or having no scope.
    $HasObjectData = $null -ne $ReportData.PSObject.Properties['ObjectTierIndex'] -and $null -ne $ReportData.ObjectTierIndex -and $ReportData.ObjectTierIndex.Count -gt 0
    $ObjectDataReason = 'The report data has no EAM Dashboard data with the classified privileged objects. Generate it with New-EntraOpsReportingData (New-EntraOpsPrivilegedEamDashboardData) from the Privileged EAM export.'
    # The same for the role tiers: without them no role is privileged (see New-EntraOpsPimRequestFlowFindingContext).
    if ($Rule.Key -cin 'eligibleAssignmentDuration', 'controlPlaneActivationDuration', 'controlPlaneActivationAuthContext', 'privilegedRoleAlert' -and $null -ne $Context.Pim.PSObject.Properties['RoleTierSkipReason'] -and $Context.Pim.RoleTierSkipReason) {
        return [pscustomobject]@{ SkipReason = $Context.Pim.RoleTierSkipReason }
    }

    switch ($Rule.Key) {
        'eligibleAssignmentDuration' {
            $PermanentAllowed = 0
            $Unreadable = 0
            $Evaluated = 0
            foreach ($Flow in $Context.Pim.Flows) {
                if ($Flow.path -ne 'eligibleAssignment' -or -not (Test-EntraOpsPimRoleSettingInScope -Flow $Flow)) { continue }
                # A role that allows permanent eligible assignments is reported by permanentEligible (the same test as EO.3004).
                $ExpirationRequired = Get-Setting $Flow 'PermanentEligibleAssignmentisExpirationRequired'
                if ($ExpirationRequired -is [bool] -and -not $ExpirationRequired) { $PermanentAllowed++; continue }
                $Hours = ConvertFrom-EntraOpsIsoDuration (Get-Setting $Flow 'ExpireEligibleAssignment')
                if ($null -eq $Hours) { $Unreadable++; continue }
                $Evaluated++
                $MaxDays = [double]$Rule.ParameterValues['MaxDays']
                New-RoleInstance $Flow ($Hours -gt $MaxDays * 24) "Eligible assignments of the $(Get-EntraOpsTierDisplayName $Flow.roleTier) role '$($Flow.roleName)' expire after $(Format-EntraOpsIsoDuration (Get-Setting $Flow 'ExpireEligibleAssignment')), more than the configured maximum of $MaxDays days." ([ordered]@{ ExpireEligibleAssignment = "$(Get-Setting $Flow 'ExpireEligibleAssignment')"; MaxDays = $MaxDays })
            }
            if ($Evaluated -eq 0 -and $PermanentAllowed -gt 0) {
                $UnreadableText = if ($Unreadable -gt 0) { " $Unreadable more role(s) have no readable expiration." } else { '' }
                $Subject = if ($Unreadable -gt 0) { "$PermanentAllowed of $($PermanentAllowed + $Unreadable) evaluated Control and Management Plane roles allow" } else { "All $PermanentAllowed evaluated Control and Management Plane roles allow" }
                [pscustomobject]@{ SkipReason = "$Subject permanent eligible assignments, so no expiration applies (reported by EO.3004).$UnreadableText"; SkipCode = 'NotApplicable' }
            } elseif ($Evaluated -eq 0 -and $Unreadable -gt 0) {
                [pscustomobject]@{ SkipReason = "None of the $Unreadable Control and Management Plane roles has a readable expiration of eligible assignments (ExpireEligibleAssignment) in the Tenant Governance snapshot." }
            }
        }
        'controlPlaneActivationDuration' {
            $Evaluated = 0
            $Unreadable = 0
            foreach ($Flow in $Context.Pim.Flows) {
                if ($Flow.path -ne 'activation' -or -not (Test-EntraOpsPimRoleSettingInScope -Flow $Flow -ControlPlaneOnly)) { continue }
                $Hours = ConvertFrom-EntraOpsIsoDuration (Get-Setting $Flow 'ActivationMaxDuration')
                if ($null -eq $Hours) { $Unreadable++; continue }
                $Evaluated++
                $MaxHours = [double]$Rule.ParameterValues['MaxHours']
                New-RoleInstance $Flow ($Hours -gt $MaxHours) "The Control Plane role '$($Flow.roleName)' can be activated for $(Format-EntraOpsIsoDuration (Get-Setting $Flow 'ActivationMaxDuration')), longer than the configured maximum of $MaxHours hours." ([ordered]@{ ActivationMaxDuration = "$(Get-Setting $Flow 'ActivationMaxDuration')"; MaxHours = $MaxHours })
            }
            if ($Evaluated -eq 0 -and $Unreadable -gt 0) {
                [pscustomobject]@{ SkipReason = "None of the $Unreadable Control Plane roles has a readable maximum activation duration (ActivationMaxDuration) in the Tenant Governance snapshot." }
            }
        }
        'controlPlaneActivationAuthContext' {
            $Unknown = 0
            foreach ($Flow in $Context.Pim.Flows) {
                if ($Flow.path -ne 'activation' -or -not (Test-EntraOpsPimRoleSettingInScope -Flow $Flow -ControlPlaneOnly)) { continue }
                $Required = Test-EntraOpsJsTruthy (Get-Setting $Flow 'AuthenticationContextRequired')
                $Policy = if ($Required -and $null -ne $Flow.PSObject.Properties['authContextPolicy']) { $Flow.authContextPolicy } else { $null }
                if ($null -ne $Policy -and $Policy.State -ceq 'Unknown') { $Unknown++ }
                $NotEnforced = $null -ne $Policy -and $Policy.State -cin 'None', 'ReportOnly'
                $Message = if ($NotEnforced) { "The activation of the Control Plane role '$($Flow.roleName)' requires the authentication context '$($Policy.Context)', but $(Get-EntraOpsAuthContextPolicyText $Policy)." } else { "The activation of the Control Plane role '$($Flow.roleName)' does not require an authentication context." }
                $Evidence = [ordered]@{}
                if ($null -ne $Policy) { $Evidence['AuthenticationContextPolicy'] = [ordered]@{ Context = $Policy.Context; State = $Policy.State; Policies = @($Policy.Policies) } }
                New-RoleInstance $Flow (-not $Required -or $NotEnforced) $Message $Evidence
            }
            if ($Unknown -gt 0) { [pscustomobject]@{ NoteOnly = $true; Note = Get-EntraOpsAuthContextUnknownNote -Count $Unknown } }
        }
        'privilegedRoleAlert' {
            # Admin alerts of the PIM role setting. In the M365DSC naming of the snapshot, EligibleAssignment* are
            # the notifications when eligible members activate the role, Eligible* when members are assigned as eligible.
            $Alerts = [ordered]@{ EligibleAssignment = 'activation'; Eligible = 'eligible assignment'; Active = 'active assignment' }
            $Evaluated = 0
            $NotExported = 0
            foreach ($Flow in $Context.Pim.Flows) {
                if ($Flow.path -ne 'activation' -or -not (Test-EntraOpsPimRoleSettingInScope -Flow $Flow)) { continue }
                # A snapshot without the notification settings of the role (older schema) cannot be evaluated: not reported.
                $Exported = @($Alerts.Keys | Where-Object { $null -ne (Get-Setting $Flow "$($_)AlertNotificationDefaultRecipient") })
                if ($Exported.Count -eq 0) { $NotExported++; continue }
                $Evaluated++
                $Missing = @(foreach ($Prefix in $Exported) {
                        $Additional = @(Get-Setting $Flow "${Prefix}AlertNotificationAdditionalRecipient") | Where-Object { $_ }
                        if (-not (Test-EntraOpsJsTruthy (Get-Setting $Flow "${Prefix}AlertNotificationDefaultRecipient")) -and @($Additional).Count -eq 0) { $Alerts[$Prefix] }
                    })
                New-RoleInstance $Flow ($Missing.Count -gt 0) "The $(Get-EntraOpsTierDisplayName $Flow.roleTier) role '$($Flow.roleName)' does not alert administrators on $($Missing -join ', ')." ([ordered]@{ MissingAlerts = $Missing })
            }
            if ($Evaluated -eq 0 -and $NotExported -gt 0) {
                [pscustomobject]@{ SkipReason = "The Tenant Governance snapshot has no notification settings of the $NotExported Control and Management Plane roles (a snapshot of an older schema). Take a new snapshot (Invoke-EntraOpsTenantGovernanceSnapshot)." }
            }
        }
        'accessPackageExpiration' {
            $FallbackFailed = 0
            foreach ($Flow in $PrivilegedPolicies) {
                $LiveExp = if ($null -ne $Flow.PSObject.Properties['expiration']) { $Flow.expiration } else { $null }
                $ExpType = if ($null -ne $LiveExp) { "$(Get-EntraOpsReportProperty -Object $LiveExp -Name 'type')" } else { '' }
                if ($ExpType) {
                    $NoExpiration = $ExpType -in 'noExpiration', 'notSpecified'
                } else {
                    $Days = Get-EntraOpsReportProperty -Object $Flow.properties -Name 'DurationInDays'
                    $Expiration = Get-EntraOpsReportProperty -Object $Flow.properties -Name 'ExpirationDateTime'
                    $NoExpiration = [int]"$(if ("$Days" -match '^\d+$') { $Days } else { 0 })" -le 0 -and -not (Test-EntraOpsJsTruthy $Expiration)
                    if ($NoExpiration) { $FallbackFailed++ }
                }
                New-PolicyInstance $Flow $NoExpiration "Assignments of the policy '$($Flow.name)' of the access package '$($Flow.accessPackageName)' do not expire."
            }
            if ($FallbackFailed -gt 0) {
                [pscustomobject]@{ NoteOnly = $true; Note = "$FallbackFailed failed $(if ($FallbackFailed -eq 1) { 'policy has' } else { 'policies have' }) no live expiration pattern in the Access Package Flow data and $(if ($FallbackFailed -eq 1) { 'was' } else { 'were' }) evaluated from DurationInDays of the Tenant Governance snapshot, which cannot tell fixed-date or hour-based expirations from non-expiring policies. Generate the Access Package Flow data again with New-EntraOpsAccessPackageFlowData to verify the expiration type." }
            }
        }
        'accessPackageAccessReview' {
            foreach ($Flow in $PrivilegedPolicies) {
                $Review = Get-EntraOpsReportProperty -Object $Flow.properties -Name 'AccessReviewSettings'
                New-PolicyInstance $Flow (-not (Test-EntraOpsJsTruthy (Get-EntraOpsReportProperty -Object $Review -Name 'IsEnabled'))) "The policy '$($Flow.name)' of the access package '$($Flow.accessPackageName)' has no access review."
            }
        }
        'conditionalAccessControlPlaneExclusion' {
            if (-not $HasObjectData -and @($Context.ConditionalAccessPolicies | Where-Object { @($_['ExcludeUsers'] | Where-Object { $_ }).Count -gt 0 }).Count -gt 0) {
                return [pscustomobject]@{ SkipReason = "The users excluded from the Conditional Access policies cannot be resolved to their tier. $ObjectDataReason" }
            }
            # Resolves a user (user principal name or object ID) or group (display name or object ID) reference.
            $IsAmbiguousName = {
                param([string]$Upper)
                ($null -ne $Context.PSObject.Properties['AmbiguousGroupNames'] -and $null -ne $Context.AmbiguousGroupNames -and $Context.AmbiguousGroupNames.Contains($Upper)) -or
                ($null -ne $ReportData.PSObject.Properties['AmbiguousDisplayNames'] -and $null -ne $ReportData.AmbiguousDisplayNames -and $ReportData.AmbiguousDisplayNames.Contains($Upper))
            }
            $Resolve = {
                param([string]$Reference, [bool]$IsGroup)
                $Upper = $Reference.ToUpperInvariant()
                $Hit = $null
                if ($ReportData.ObjectTierIndex.TryGetValue($Upper, [ref]$Hit)) { return $Hit }
                if ($IsGroup) {
                    if ($ReportData.ResolvedGroupTierIndex.TryGetValue($Upper, [ref]$Hit)) { return $Hit }
                    # A display name of several groups or objects stays unresolved instead of taking the tier of the wrong one.
                    if (& $IsAmbiguousName $Upper) { return $null }
                    if ($Context.ResolvedGroupTierByName.TryGetValue($Upper, [ref]$Hit)) { return $Hit }
                    if ($ReportData.ObjectDisplayNameIndex.TryGetValue($Upper, [ref]$Hit)) { return $Hit }
                } elseif ($ReportData.ObjectUpnIndex.TryGetValue($Upper, [ref]$Hit)) { return $Hit }
                return $null
            }
            if (-not $HasObjectData) {
                $ExcludedGroups = @($Context.ConditionalAccessPolicies | ForEach-Object { @($_['ExcludeGroups']) } | Where-Object { $_ } | Select-Object -Unique)
                if ($ExcludedGroups.Count -gt 0 -and @($ExcludedGroups | Where-Object { & $Resolve "$_" $true }).Count -eq 0) {
                    return [pscustomobject]@{ SkipReason = "The groups excluded from the Conditional Access policies cannot be resolved to their tier. $ObjectDataReason" }
                }
            }
            # Emergency access accounts: only the configured accounts and groups. Nothing is taken for an emergency
            # access account without the setting: a user excluded from every enabled policy (with at least two
            # enabled policies) is reported and named in the reason as a candidate for the setting.
            $EmergencyAccess = @(@($Rule.ParameterValues['EmergencyAccessAccounts']) | Where-Object { $_ } | ForEach-Object { "$_" })
            $PolicyCount = $Context.ConditionalAccessPolicies.Count
            $UserExclusionCount = @{}
            foreach ($Policy in $Context.ConditionalAccessPolicies) {
                foreach ($Reference in @(@($Policy['ExcludeUsers']) | Where-Object { $_ } | Select-Object -Unique)) {
                    $UserExclusionCount["$Reference"] = [int]$UserExclusionCount["$Reference"] + 1
                }
            }
            $IsConfiguredEmergencyAccess = {
                param([string]$Reference)
                $Hit = & $Resolve $Reference $false
                if (-not $Hit) { $Hit = & $Resolve $Reference $true }
                return ($EmergencyAccess -contains $Reference) -or ($Hit -and ($EmergencyAccess -contains "$($Hit.objectId)" -or ($Hit.displayName -and $EmergencyAccess -contains "$($Hit.displayName)") -or ($Hit.userPrincipalName -and $EmergencyAccess -contains "$($Hit.userPrincipalName)")))
            }
            # Users and groups that enabled policies target (IncludeUsers, IncludeGroups) and exclude (ExcludeUsers,
            # ExcludeGroups), by reference and object ID. A block policy that excludes such an identity is an allow-list
            # (for example "block access to admin portals for everyone except privileged accounts"), not a gap: the
            # identity has its own enabled policy that targets it without excluding it.
            $IncludedBy = @{}
            $ExcludedBy = @{}
            foreach ($Policy in $Context.ConditionalAccessPolicies) {
                foreach ($Entry in @(@(@($Policy['IncludeUsers']) | ForEach-Object { @{ Reference = $_; IsGroup = $false } }) + @(@($Policy['IncludeGroups']) | ForEach-Object { @{ Reference = $_; IsGroup = $true } }))) {
                    if (-not "$($Entry.Reference)" -or "$($Entry.Reference)" -in 'All', 'None', 'GuestsOrExternalUsers') { continue }
                    $Hit = & $Resolve "$($Entry.Reference)" $Entry.IsGroup
                    foreach ($Key in @("$($Entry.Reference)".ToUpperInvariant(), $(if ($Hit) { "$($Hit.objectId)".ToUpperInvariant() }))) {
                        if (-not $Key) { continue }
                        if (-not $IncludedBy.ContainsKey($Key)) { $IncludedBy[$Key] = [System.Collections.Generic.HashSet[string]]::new() }
                        $null = $IncludedBy[$Key].Add("$($Policy['Id'])")
                    }
                }
                foreach ($Entry in @(@(@($Policy['ExcludeUsers']) | ForEach-Object { @{ Reference = $_; IsGroup = $false } }) + @(@($Policy['ExcludeGroups']) | ForEach-Object { @{ Reference = $_; IsGroup = $true } }))) {
                    if (-not "$($Entry.Reference)" -or "$($Entry.Reference)" -in 'All', 'None', 'GuestsOrExternalUsers') { continue }
                    $Hit = & $Resolve "$($Entry.Reference)" $Entry.IsGroup
                    foreach ($Key in @("$($Entry.Reference)".ToUpperInvariant(), $(if ($Hit) { "$($Hit.objectId)".ToUpperInvariant() }))) {
                        if (-not $Key) { continue }
                        if (-not $ExcludedBy.ContainsKey($Key)) { $ExcludedBy[$Key] = [System.Collections.Generic.HashSet[string]]::new() }
                        $null = $ExcludedBy[$Key].Add("$($Policy['Id'])")
                    }
                }
                # Directory roles are referenced by display name; their keys have a prefix to keep them apart from groups.
                foreach ($Role in @($Policy['IncludeRoles'] | Where-Object { $_ })) {
                    $Key = "ROLE:$("$Role".ToUpperInvariant())"
                    if (-not $IncludedBy.ContainsKey($Key)) { $IncludedBy[$Key] = [System.Collections.Generic.HashSet[string]]::new() }
                    $null = $IncludedBy[$Key].Add("$($Policy['Id'])")
                }
                foreach ($Role in @($Policy['ExcludeRoles'] | Where-Object { $_ })) {
                    $Key = "ROLE:$("$Role".ToUpperInvariant())"
                    if (-not $ExcludedBy.ContainsKey($Key)) { $ExcludedBy[$Key] = [System.Collections.Generic.HashSet[string]]::new() }
                    $null = $ExcludedBy[$Key].Add("$($Policy['Id'])")
                }
            }
            # The tier of the directory roles by display name (PIM role settings of the snapshot).
            $RoleTierByName = @{}
            foreach ($Flow in @($Context.Pim.Flows)) {
                if ($Flow.roleName -and $Flow.roleTier -and -not $RoleTierByName.ContainsKey("$($Flow.roleName)".ToUpperInvariant())) { $RoleTierByName["$($Flow.roleName)".ToUpperInvariant()] = $Flow.roleTier }
            }
            $IsTargetedElsewhere = {
                param($Policy, [string]$Reference, $Hit)
                $Keys = @($Reference.ToUpperInvariant(), $(if ($Hit) { "$($Hit.objectId)".ToUpperInvariant() })) | Where-Object { $_ } | Select-Object -Unique
                foreach ($Key in $Keys) {
                    if (-not $IncludedBy.ContainsKey($Key)) { continue }
                    foreach ($OtherId in $IncludedBy[$Key]) {
                        if ($OtherId -eq "$($Policy['Id'])") { continue }
                        $AlsoExcluded = @($Keys | Where-Object { $ExcludedBy.ContainsKey($_) -and $ExcludedBy[$_].Contains($OtherId) }).Count -gt 0
                        if (-not $AlsoExcluded) { return $true }
                    }
                }
                return $false
            }
            # The member data of a group (transitive privileged members of the Configuration Analyzer data), $null without it.
            $GetGroupMembers = {
                param([string]$Reference)
                $Upper = $Reference.ToUpperInvariant()
                $Group = $null
                if (-not $ReportData.ResolvedGroupTierIndex.TryGetValue($Upper, [ref]$Group) -and -not (& $IsAmbiguousName $Upper)) { $null = $Context.ResolvedGroupTierByName.TryGetValue($Upper, [ref]$Group) }
                if ($null -eq $Group) {
                    $Hit = & $Resolve $Reference $true
                    if ($Hit -and "$($Hit.objectId)") { $null = $ReportData.ResolvedGroupTierIndex.TryGetValue("$($Hit.objectId)".ToUpperInvariant(), [ref]$Group) }
                }
                if ($null -ne $Group -and $Group.members -is [array]) { return , $Group.members }
                return $null
            }
            $MemberValue = { param($Member, [string]$Name) if ($Member -is [System.Collections.IDictionary]) { $Member[$Name] } else { $Member.$Name } }
            # Active directory roles of the users on the directory (EAM Dashboard data), by object ID: Conditional Access
            # targets the active members of a role, not the eligible ones.
            $RolesByObject = @{}
            foreach ($Object in @(if ($ReportData.EamData) { $ReportData.EamData['objects'] })) {
                if ($null -eq $Object -or "$($Object['roleSystem'])" -ne 'EntraID') { continue }
                foreach ($Assignment in @($Object['roleAssignments'])) {
                    if ($Assignment -isnot [System.Collections.IDictionary] -or "$($Assignment['pimAssignmentType'])" -eq 'Eligible' -or "$($Assignment['roleAssignmentScopeId'])" -ne '/' -or -not "$($Assignment['roleDefinitionName'])") { continue }
                    $Key = "$($Object['objectId'])".ToUpperInvariant()
                    if (-not $RolesByObject.ContainsKey($Key)) { $RolesByObject[$Key] = [System.Collections.Generic.HashSet[string]]::new() }
                    $null = $RolesByObject[$Key].Add("$($Assignment['roleDefinitionName'])".ToUpperInvariant())
                }
            }
            # The users each enabled policy targets and excludes (object IDs and references, upper case): directly, as
            # (transitive) member of a group with member data, and by role. 'All' does not count: the allow-list
            # needs a policy of its own for the user.
            $PolicyMemberScope = @{}
            foreach ($Policy in $Context.ConditionalAccessPolicies) {
                $Scope = @{}
                foreach ($Direction in 'Include', 'Exclude') {
                    $Ids = [System.Collections.Generic.HashSet[string]]::new()
                    foreach ($Reference in @($Policy["$($Direction)Users"] | Where-Object { $_ })) {
                        if ("$Reference" -in 'All', 'None', 'GuestsOrExternalUsers') { continue }
                        $null = $Ids.Add("$Reference".ToUpperInvariant())
                        $Hit = & $Resolve "$Reference" $false
                        if ($Hit) { $null = $Ids.Add("$($Hit.objectId)".ToUpperInvariant()) }
                    }
                    foreach ($Reference in @($Policy["$($Direction)Groups"] | Where-Object { $_ })) {
                        $Members = & $GetGroupMembers "$Reference"
                        foreach ($Member in @($Members)) { if ($null -ne $Member) { $null = $Ids.Add("$(& $MemberValue $Member 'id')".ToUpperInvariant()) } }
                    }
                    $Scope[$Direction] = $Ids
                    $Scope["$($Direction)Roles"] = @($Policy["$($Direction)Roles"] | Where-Object { $_ } | ForEach-Object { "$_".ToUpperInvariant() })
                }
                $PolicyMemberScope["$($Policy['Id'])"] = $Scope
            }
            $IsMemberTargetedElsewhere = {
                param($Policy, [string]$MemberId)
                $Keys = @($MemberId.ToUpperInvariant())
                $Entry = $null
                if ($ReportData.ObjectTierIndex.TryGetValue($Keys[0], [ref]$Entry) -and "$($Entry.userPrincipalName)") { $Keys += "$($Entry.userPrincipalName)".ToUpperInvariant() }
                $Roles = $RolesByObject[$Keys[0]]
                foreach ($Other in $Context.ConditionalAccessPolicies) {
                    if ("$($Other['Id'])" -eq "$($Policy['Id'])") { continue }
                    $Scope = $PolicyMemberScope["$($Other['Id'])"]
                    $Included = @($Keys | Where-Object { $Scope.Include.Contains($_) }).Count -gt 0 -or ($Roles -and @($Scope.IncludeRoles | Where-Object { $Roles.Contains($_) }).Count -gt 0)
                    $IsExcluded = @($Keys | Where-Object { $Scope.Exclude.Contains($_) }).Count -gt 0 -or ($Roles -and @($Scope.ExcludeRoles | Where-Object { $Roles.Contains($_) }).Count -gt 0)
                    if ($Included -and -not $IsExcluded) { return $true }
                }
                return $false
            }
            # Members of the configured emergency access groups (the configured accounts are found by IsConfiguredEmergencyAccess).
            $EmergencyAccessMemberIds = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($Reference in $EmergencyAccess) {
                $Members = & $GetGroupMembers "$Reference"
                foreach ($Member in @($Members)) { if ($null -ne $Member) { $null = $EmergencyAccessMemberIds.Add("$(& $MemberValue $Member 'id')".ToUpperInvariant()) } }
            }
            # The Control Plane users of an excluded group (member data) that no other enabled policy targets, without
            # the emergency access accounts; $null for a group without member data. Nested groups are left out: their
            # members are listed themselves (transitive membership), and so are service principals, which policies for
            # users do not apply to.
            $GetUncoveredMembers = {
                param($Policy, [string]$Reference)
                $Members = & $GetGroupMembers $Reference
                if ($null -eq $Members) { return $null }
                $Uncovered = [System.Collections.Generic.List[string]]::new()
                foreach ($Member in $Members) {
                    if ($null -eq $Member) { continue }
                    $MemberId = "$(& $MemberValue $Member 'id')"
                    $Entry = $null
                    $null = $MemberId -and $ReportData.ObjectTierIndex.TryGetValue($MemberId.ToUpperInvariant(), [ref]$Entry)
                    $Tier = if ("$(& $MemberValue $Member 'tierName')") { "$(& $MemberValue $Member 'tierName')" } elseif ($Entry) { "$($Entry.tierName)" }
                    $Type = if ("$(& $MemberValue $Member 'objectType')") { "$(& $MemberValue $Member 'objectType')" } elseif ($Entry) { "$($Entry.objectType)" }
                    if (-not $MemberId -or $Tier -cne 'ControlPlane' -or $Type -in 'group', 'servicePrincipal') { continue }
                    if ($EmergencyAccessMemberIds.Contains($MemberId.ToUpperInvariant()) -or ($EmergencyAccess.Count -gt 0 -and (& $IsConfiguredEmergencyAccess $MemberId))) { continue }
                    if (& $IsMemberTargetedElsewhere $Policy $MemberId) { continue }
                    $Uncovered.Add($(if ("$(& $MemberValue $Member 'displayName')") { "$(& $MemberValue $Member 'displayName')" } elseif ($Entry -and "$($Entry.displayName)") { "$($Entry.displayName)" } else { $MemberId }))
                }
                return , $Uncovered
            }
            # Excluded groups without member data (not resolved when the report data was generated): their Control
            # Plane members cannot be evaluated, so the rule names them instead of passing them silently.
            $UnresolvedGroups = @(@(foreach ($Policy in $Context.ConditionalAccessPolicies) {
                    foreach ($Reference in @($Policy['ExcludeGroups'] | Where-Object { $_ })) {
                        if (& $Resolve "$Reference" $true) { continue }
                        if ($EmergencyAccess.Count -gt 0 -and (& $IsConfiguredEmergencyAccess "$Reference")) { continue }
                        "$Reference"
                    }
                }) | Sort-Object -Unique)
            $UnresolvedNote = if ($UnresolvedGroups.Count -gt 0) {
                "$($UnresolvedGroups.Count) excluded group(s) could not be resolved to their members, so their Control Plane members are not evaluated: $(@($UnresolvedGroups | Select-Object -First 5) -join ', ')$(if ($UnresolvedGroups.Count -gt 5) { " and $($UnresolvedGroups.Count - 5) more" }). Generate the Configuration Analyzer data with EntraOps 1.2.0 or later while connected to Microsoft Graph, with ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets turned on (default)."
            }
            $AmbiguousGroups = @($UnresolvedGroups | Where-Object { & $IsAmbiguousName "$_".ToUpperInvariant() })
            if ($AmbiguousGroups.Count -gt 0) {
                $UnresolvedNote += " $($AmbiguousGroups.Count) of them have a display name that several groups or objects share, so the policy doesn't tell which one is excluded: $(@($AmbiguousGroups | Select-Object -First 5) -join ', ')$(if ($AmbiguousGroups.Count -gt 5) { " and $($AmbiguousGroups.Count - 5) more" }). Rename the groups to tell them apart."
            }
            # Failed policies by the identities they exclude, for the hint below.
            $FailedExclusions = [System.Collections.Generic.List[object]]::new()
            # Reported users excluded from every enabled policy (candidates for EmergencyAccessAccounts), for the note below.
            $Candidates = [System.Collections.Generic.List[string]]::new()
            $PolicyInstances = foreach ($Policy in $Context.ConditionalAccessPolicies) {
                $Excluded = [System.Collections.Generic.List[string]]::new()
                $Scoped = [System.Collections.Generic.List[string]]::new()
                $ExcludedRoles = [System.Collections.Generic.List[string]]::new()
                # Excluded groups of a block policy with member data: their Control Plane members no other enabled policy targets.
                $UncoveredMembers = [ordered]@{}
                $IsBlockPolicy = @($Policy['BuiltInControls']) -contains 'block'
                $Controls = @(@($Policy['BuiltInControls'] | Where-Object { $_ }) + @(if ("$($Policy['AuthenticationStrength'])") { "authentication strength '$($Policy['AuthenticationStrength'])'" }))
                $GrantLabel = if ($IsBlockPolicy) { 'block access' } elseif ($Controls.Count) { "require $($Controls -join ', ')" } else { 'session controls' }
                foreach ($Reference in @($Policy['ExcludeUsers'] | Where-Object { $_ })) {
                    $Hit = & $Resolve "$Reference" $false
                    if (-not ($Hit -and $Hit.tierName -ceq 'ControlPlane')) { continue }
                    if ($EmergencyAccess.Count -gt 0 -and (& $IsConfiguredEmergencyAccess "$Reference")) { continue }
                    if ($IsBlockPolicy -and (& $IsTargetedElsewhere $Policy "$Reference" $Hit)) { $Scoped.Add("$Reference"); continue }
                    $Excluded.Add("$Reference")
                    # Reported, and excluded from every enabled policy: a candidate for EmergencyAccessAccounts.
                    if ($PolicyCount -ge 2 -and $UserExclusionCount["$Reference"] -ge $PolicyCount -and -not $Candidates.Contains("$Reference")) { $Candidates.Add("$Reference") }
                }
                foreach ($Reference in @($Policy['ExcludeGroups'] | Where-Object { $_ })) {
                    $Hit = & $Resolve "$Reference" $true
                    if (-not ($Hit -and $Hit.tierName -ceq 'ControlPlane')) { continue }
                    if ($EmergencyAccess.Count -gt 0 -and (& $IsConfiguredEmergencyAccess "$Reference")) { continue }
                    if ($IsBlockPolicy) {
                        if (& $IsTargetedElsewhere $Policy "$Reference" $Hit) { $Scoped.Add("$Reference"); continue }
                        # A group with member data is part of the allow-list when other enabled policies target each of
                        # its Control Plane members (directly, by group or by role), without the emergency access accounts.
                        $Uncovered = & $GetUncoveredMembers $Policy "$Reference"
                        if ($null -ne $Uncovered) {
                            if ($Uncovered.Count -eq 0) { $Scoped.Add("$Reference"); continue }
                            $UncoveredMembers["$Reference"] = @($Uncovered)
                        }
                    }
                    $Excluded.Add("$Reference")
                }
                # Excluded Control Plane directory roles: the policy does not apply to their active members.
                foreach ($Role in @($Policy['ExcludeRoles'] | Where-Object { $_ })) {
                    if ($RoleTierByName["$Role".ToUpperInvariant()] -cne 'ControlPlane') { continue }
                    if ($IsBlockPolicy -and (& $IsTargetedElsewhere $Policy "ROLE:$Role" $null)) { $Scoped.Add("role '$Role'") } else { $ExcludedRoles.Add("$Role") }
                }
                $ExcludedLabels = @(@($Excluded | ForEach-Object { if ($UncoveredMembers.Contains("$_")) { "$_ (Control Plane members no other enabled policy targets: $(Join-EntraOpsFindingName $UncoveredMembers["$_"]))" } else { "$_" } }) + @($ExcludedRoles | ForEach-Object { "role '$_'" }))
                if ($ExcludedLabels.Count -gt 0) { $FailedExclusions.Add([pscustomobject]@{ Labels = $ExcludedLabels; Users = @($Excluded) }) }
                [pscustomobject]@{
                    Failed      = $ExcludedLabels.Count -gt 0
                    InstanceKey = "$($Policy['Id'])"
                    Note        = $UnresolvedNote
                    ObjectId    = "$($Policy['Id'])"
                    ObjectType  = 'conditionalAccessPolicy'
                    DisplayName = "$($Policy['DisplayName'])"
                    Message     = "The Conditional Access policy '$($Policy['DisplayName'])' ($GrantLabel) does not apply to the excluded Control Plane users, groups or roles$(if ($IsBlockPolicy) { ', and no other enabled policy targets them' }): $($ExcludedLabels -join ', ')."
                    Evidence    = [ordered]@{
                        ExcludedControlPlane         = @($Excluded)
                        ExcludedControlPlaneRoles    = @($ExcludedRoles)
                        # Control Plane users, groups and roles excluded from this block policy that other enabled policies target
                        # (allow-list of the block policy, not reported).
                        ScopedExclusions             = @($Scoped)
                        # Excluded groups of this block policy with member data and their Control Plane members that no
                        # other enabled policy targets.
                        UncoveredControlPlaneMembers = @(foreach ($Group in $UncoveredMembers.Keys) { [ordered]@{ Group = $Group; Members = @($UncoveredMembers[$Group]) } })
                        # Excluded groups of this policy without member data (see the note of the rule result).
                        UnresolvedExcludedGroups     = @(@($Policy['ExcludeGroups'] | Where-Object { $_ }) | Where-Object { $UnresolvedGroups -contains "$_" })
                        GrantControls                = $Controls
                        SnapshotKey                  = $Context.SnapshotKey
                    }
                }
            }
            # Three or more policies whose only reported exclusion is the same user or group (typically the emergency
            # access accounts) are one result for that identity, with the policies in its evidence.
            $PolicyInstances = @($PolicyInstances)
            $Collapsed = @{}
            foreach ($Group in @($PolicyInstances | Where-Object { $_.Failed -and $_.Evidence.ExcludedControlPlane.Count -eq 1 -and $_.Evidence.ExcludedControlPlaneRoles.Count -eq 0 } | Group-Object { "$($_.Evidence.ExcludedControlPlane[0])".ToUpperInvariant() } | Where-Object { $_.Count -ge 3 })) {
                $Reference = "$($Group.Group[0].Evidence.ExcludedControlPlane[0])"
                # A group resolved by its member data has no object ID of its own: its key in the index is the ID.
                $IsGroup = @($Context.ConditionalAccessPolicies | Where-Object { @($_['ExcludeGroups']) -contains $Reference }).Count -gt 0
                $Hit = & $Resolve $Reference $IsGroup
                $HitId = if ($Hit -is [System.Collections.IDictionary]) { "$($Hit['objectId'])" } elseif ($Hit) { "$($Hit.objectId)" } else { '' }
                if (-not $HitId -and $IsGroup -and $Hit) {
                    foreach ($Pair in $ReportData.ResolvedGroupTierIndex.GetEnumerator()) { if ([object]::ReferenceEquals($Pair.Value, $Hit)) { $HitId = "$($Pair.Key)".ToLowerInvariant(); break } }
                }
                $PolicyNames = @($Group.Group | ForEach-Object { $_.DisplayName })
                $Uncovered = @($Group.Group | ForEach-Object { $_.Evidence.UncoveredControlPlaneMembers } | ForEach-Object { $_.Members } | Where-Object { $_ } | Select-Object -Unique)
                foreach ($Instance in $Group.Group) { $Collapsed[$Instance.InstanceKey] = $true }
                [pscustomobject]@{
                    Failed             = $true
                    InstanceKey        = "exclusion|$($Reference.ToUpperInvariant())"
                    Note               = $UnresolvedNote
                    ObjectId           = $(if ($HitId) { $HitId } else { $Reference })
                    ObjectType         = $(if ($IsGroup) { 'group' } else { 'user' })
                    DisplayName        = $(if ($Hit -and "$($Hit.displayName)") { "$($Hit.displayName)" } else { $Reference })
                    AdminTierLevel     = Get-EntraOpsAdminTierLevel 'ControlPlane'
                    AdminTierLevelName = 'ControlPlane'
                    Message            = "$($Group.Count) enabled Conditional Access policies do not apply to the excluded Control Plane $(if ($IsGroup) { 'group' } else { 'user' }) '$Reference'$(if ($Uncovered.Count -gt 0) { " (Control Plane members no other enabled policy targets: $(Join-EntraOpsFindingName $Uncovered))" }), their only reported exclusion: $(Join-EntraOpsFindingName $PolicyNames)."
                    Evidence           = [ordered]@{
                        ExcludedControlPlane         = @($Reference)
                        ExcludedControlPlaneRoles    = @()
                        Policies                     = @($Group.Group | ForEach-Object { [ordered]@{ Id = $_.ObjectId; DisplayName = $_.DisplayName; GrantControls = @($_.Evidence.GrantControls) } })
                        UncoveredControlPlaneMembers = @($(if ($Uncovered.Count -gt 0) { [ordered]@{ Group = $Reference; Members = $Uncovered } }))
                        SnapshotKey                  = $Context.SnapshotKey
                    }
                }
            }
            $PolicyInstances | Where-Object { -not $Collapsed.ContainsKey($_.InstanceKey) }
            # Users excluded from every enabled policy are typically the emergency access accounts: they are reported,
            # and the reason names them so they can be added to EmergencyAccessAccounts if they are.
            if ($Candidates.Count -gt 0) {
                $Names = @(foreach ($Reference in $Candidates) {
                        $Hit = & $Resolve $Reference $false
                        "'$(if ("$($Hit.displayName)") { $Hit.displayName } else { $Reference })' ($($Hit.objectId))"
                    })
                [pscustomobject]@{ NoteOnly = $true; Note = "$($Candidates.Count) Control Plane user(s) are excluded from every enabled Conditional Access policy: $(Join-EntraOpsFindingName $Names). If they are emergency access accounts, add them (or their group) to Findings.EmergencyAccessAccounts." }
            }
            # Hint: results that only exclude one user or group, typically the emergency access accounts (not repeated
            # for a user the note above names already). Configuring them in EmergencyAccessAccounts removes these
            # results; other exclusions stay reported.
            if ($FailedExclusions.Count -gt 0) {
                $Single = @($FailedExclusions | Where-Object { $_.Labels.Count -eq 1 -and $_.Users.Count -eq 1 } | Group-Object { $_.Users[0] } | Sort-Object Count -Descending | Select-Object -First 1)
                if ($Single.Count -eq 1 -and -not $Candidates.Contains("$($Single[0].Name)")) {
                    $Name = $Single[0].Name
                    $Hit = & $Resolve $Name $true
                    if (-not $Hit) { $Hit = & $Resolve $Name $false }
                    $Label = if ($Hit -and "$($Hit.displayName)" -and "$($Hit.displayName)" -ne $Name) { "'$($Hit.displayName)' ($Name)" } else { "'$Name'" }
                    $Hint = if ($EmergencyAccess.Count -gt 0) { "If it is an emergency access account or group, add it to Findings.EmergencyAccessAccounts." } else { "If it is your emergency access account or group, set Findings.EmergencyAccessAccounts." }
                    [pscustomobject]@{ NoteOnly = $true; Note = "$($Single[0].Count) of $($FailedExclusions.Count) policies with a reported exclusion only exclude $Label. $Hint" }
                }
            }
        }
        'dynamicPrivilegedAdministrativeUnit' {
            if (-not $HasObjectData -and $Context.AdministrativeUnits.Count -gt 0) {
                return [pscustomobject]@{ SkipReason = "The privileged members of the administrative units are unknown. $ObjectDataReason" }
            }
            # Administrative units with Control or Management Plane members (EAM Dashboard data).
            $PrivilegedMembers = @{}
            foreach ($Object in @(if ($ReportData.EamData) { $ReportData.EamData['objects'] })) {
                if ($null -eq $Object) { continue }
                $Entry = $null
                if (-not $ReportData.ObjectTierIndex.TryGetValue("$($Object['objectId'])".ToUpperInvariant(), [ref]$Entry) -or -not (Test-EntraOpsPrivilegedTier $Entry.tierName)) { continue }
                foreach ($Unit in @($Object['assignedAdministrativeUnits'])) {
                    if ($Unit -isnot [System.Collections.IDictionary]) { continue }
                    $UnitId = "$($Unit['id'])".ToLowerInvariant()
                    if (-not $PrivilegedMembers.ContainsKey($UnitId)) { $PrivilegedMembers[$UnitId] = [System.Collections.Generic.HashSet[string]]::new() }
                    $null = $PrivilegedMembers[$UnitId].Add("$($Object['objectId'])".ToLowerInvariant())
                }
            }
            foreach ($Unit in $Context.AdministrativeUnits) {
                $UnitId = "$($Unit['Id'])".ToLowerInvariant()
                if (-not $PrivilegedMembers.ContainsKey($UnitId)) { continue }
                [pscustomobject]@{
                    Failed      = "$($Unit['MembershipType'])" -eq 'Dynamic'
                    InstanceKey = $UnitId
                    ObjectId    = $UnitId
                    ObjectType  = 'administrativeUnit'
                    DisplayName = "$($Unit['DisplayName'])"
                    Message     = "The administrative unit '$($Unit['DisplayName'])' has dynamic membership ($($Unit['MembershipRule'])) and $($PrivilegedMembers[$UnitId].Count) privileged member(s)."
                    Evidence    = [ordered]@{ MembershipRule = "$($Unit['MembershipRule'])"; PrivilegedMemberIds = @($PrivilegedMembers[$UnitId]); SnapshotKey = $Context.SnapshotKey }
                }
            }
        }
        default { throw "No Tenant Governance evaluator for finding rule '$($Rule.Id)' ($($Rule.Key))." }
    }
}
