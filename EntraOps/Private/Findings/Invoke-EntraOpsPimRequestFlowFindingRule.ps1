function Get-EntraOpsPimRequestFlowFlag {
    <#
    .SYNOPSIS
        Evaluates the PIM Request Flow rules for one flow: { Applies; Failed; Text } per rule key, in report order.
    .DESCRIPTION
        Applies tells whether the flow is in the scope of the rule (for example the activation flows of
        privileged roles for noMfaActivation), Failed whether it fails the rule, and Text the risk flag the
        PIM Request Flow report shows (New-EntraOpsReportFindingData keeps only the failed keys). A role is
        privileged when its tier is ControlPlane or ManagementPlane. New-EntraOpsPimRequestFlowFindingContext
        evaluates every flow once (checks of the flow).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Flow
    )

    $Properties = $Flow.p
    $RoleTier = $Flow.roleTier
    $Privileged = Test-EntraOpsPrivilegedTier $RoleTier
    # Approvers are compared by admin tier level: Management and Workload Plane are both Tier 1 (like EO.1001 and EO.1002).
    $RoleLevel = Get-EntraOpsAdminTierLevel $RoleTier
    # "the Control Plane role 'Global Administrator'", for the messages.
    $Role = "the $(if ($RoleTier) { "$(Get-EntraOpsTierDisplayName $RoleTier) " })role '$($Flow.roleName)'"
    $RoleText = $Role.Substring(0, 1).ToUpperInvariant() + $Role.Substring(1)
    $Truthy = { param($Name) Test-EntraOpsJsTruthy $Properties[$Name] }
    $Activation = $Flow.path -eq 'activation'
    $ApprovalRequired = & $Truthy 'ApprovaltoActivate'
    $Checks = [ordered]@{}
    function Add-Check([string]$Key, [bool]$Applies, [scriptblock]$Failed, [scriptblock]$Text) {
        $IsFailed = $Applies -and [bool](& $Failed)
        $Checks[$Key] = [pscustomobject]@{ Applies = $Applies; Failed = $IsFailed; Text = $(if ($IsFailed) { & $Text } else { $null }) }
    }

    # PIM offers either Azure MFA or an authentication context on activation; a configured context is the stronger choice.
    $AuthContextEnforced = (& $Truthy 'AuthenticationContextRequired') -and ((& $Truthy 'AuthenticationContextName') -or (& $Truthy 'AuthenticationContextId'))
    Add-Check 'noMfaActivation' ($Activation -and $Privileged) { -not (& $Truthy 'ActivationReqMFA') -and -not $AuthContextEnforced } { "$RoleText can be activated without MFA or an authentication context." }
    Add-Check 'noApprovalActivation' ($Activation -and $Privileged) { -not $ApprovalRequired } { "$RoleText can be activated without approval." }
    Add-Check 'approverNotEnforced' $Activation { -not $ApprovalRequired -and $Properties['ActivateApprover'] -is [array] -and $Properties['ActivateApprover'].Count -gt 0 } { "$RoleText has $($Properties['ActivateApprover'].Count) approver(s) configured, but 'Require approval to activate' is disabled - the approver list has no effect." }
    # The approver checks apply to privileged (Control and Management Plane) roles with approval.
    # The tier the approver is protected for (own classification, for a group its least protected member), not the
    # tier of its access: excessive access must not make an inadequately protected approver appear safe. A group
    # without members or member data is never compared with the tier of its access (Get-EntraOpsApproverComparedTier).
    $ApproverTier = { param($Approver) Get-EntraOpsApproverComparedTier -Approver $Approver }
    # Approvers in the Privileged EAM data (direct) and users outside it (default, resolved): users without privileged access.
    $LowerTier = @(if ($Activation -and $ApprovalRequired -and $Privileged) { $Flow.approvers | Where-Object { ($_.source -ceq 'direct' -or ($_.source -ceq 'default' -and $_.resolved)) -and (Test-EntraOpsJsTruthy (& $ApproverTier $_)) -and (Get-EntraOpsAdminTierLevel (& $ApproverTier $_)) -gt $RoleLevel } })
    Add-Check 'approverLowerTier' ($Activation -and $ApprovalRequired -and $Privileged) { $LowerTier.Count -gt 0 } { "$RoleText is approved by approver(s) classified at a lower tier: $(@($LowerTier | ForEach-Object {
                # A group is not classified at the tier it is protected for: that is the classification of its least protected member.
                if ($null -ne $_.PSObject.Properties['protectionMember'] -and $_.protectionMember) { "$($_.label) (least protected member: $($_.protectionMember), classified as $(Get-EntraOpsTierDisplayName (& $ApproverTier $_)))" }
                elseif ($_.source -ceq 'default') { "$($_.label), without privileged access (User Access)" }
                else { "$($_.label), classified as $(Get-EntraOpsTierDisplayName (& $ApproverTier $_))" }
            }) -join ', ')." }
    $Unresolved = @(if ($Activation -and $ApprovalRequired -and $Privileged) { $Flow.approvers | Where-Object { -not $_.resolved } })
    Add-Check 'approverUnclassified' ($Activation -and $ApprovalRequired -and $Privileged) { $Unresolved.Count -gt 0 } { "$($Unresolved.Count) approver(s) of $Role could not be resolved against the Privileged EAM data, so their tier is not compared: $(@($Unresolved | ForEach-Object { "'$($_.label)'" }) -join ', ')." }
    # A context is configured when the snapshot has its name or its ID (the same test as noMfaActivation).
    Add-Check 'authContextMissing' $Activation { (& $Truthy 'AuthenticationContextRequired') -and -not ((& $Truthy 'AuthenticationContextName') -or (& $Truthy 'AuthenticationContextId')) } { "$RoleText requires an authentication context on activation, but no context is configured." }
    Add-Check 'permanentEligible' ($Flow.path -eq 'eligibleAssignment' -and $Privileged) { $Properties['PermanentEligibleAssignmentisExpirationRequired'] -is [bool] -and -not $Properties['PermanentEligibleAssignmentisExpirationRequired'] } { "$RoleText allows permanent (non-expiring) eligible assignments." }
    Add-Check 'permanentActive' ($Flow.path -eq 'activeAssignment' -and $Privileged) { $Properties['PermanentActiveAssignmentisExpirationRequired'] -is [bool] -and -not $Properties['PermanentActiveAssignmentisExpirationRequired'] } { "$RoleText allows permanent (non-expiring) active assignments." }
    Add-Check 'noMfaActiveAssign' ($Flow.path -eq 'activeAssignment' -and $Privileged) { -not (& $Truthy 'AssignmentReqMFA') } { "$RoleText can be assigned as active without MFA at assignment time." }
    $Checks
}

function Invoke-EntraOpsPimRequestFlowFindingRule {
    <#
    .SYNOPSIS
        Evaluates a PIM Request Flow finding rule against the flows of the PIM Request Flow context.
    .DESCRIPTION
        Pure evaluation of the flows from New-EntraOpsPimRequestFlowFindingContext. Returns the evaluated
        instances (see Invoke-EntraOpsFindingRuleSet): every flow in the scope of the rule, failed with the
        text of the report, from the checks the context evaluated once per flow (Get-EntraOpsPimRequestFlowFlag).
    .PARAMETER Context
        Context from New-EntraOpsPimRequestFlowFindingContext.
    .PARAMETER Rule
        The PIM Request Flow finding rule (from Get-EntraOpsFindingRule).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    # The role tiers come from optional datasets: without them no role is privileged and nothing would be in scope.
    if ($Rule.Key -cnotin 'approverNotEnforced', 'authContextMissing' -and $null -ne $Context.PSObject.Properties['RoleTierSkipReason'] -and $Context.RoleTierSkipReason) {
        return [pscustomobject]@{ SkipReason = $Context.RoleTierSkipReason }
    }
    # Approvers that could not be resolved and approver groups without members are not compared (EO.2003 reports
    # them): the rule names them, so a pass is visibly incomplete.
    if ($Rule.Key -ceq 'approverLowerTier') {
        $Incomplete = @(foreach ($Flow in $Context.Flows) {
                if ($null -eq $Flow.checks[$Rule.Key] -or -not $Flow.checks[$Rule.Key].Applies) { continue }
                # A group without members is resolved, but nobody can approve through it: named on its own.
                $EmptyGroups = @($Flow.approvers | Where-Object { -not $_.resolved -and $_.source -ceq 'emptyGroup' } | ForEach-Object { "$(if ($null -ne $_.PSObject.Properties['name'] -and $_.name) { $_.name } else { $_.label })" })
                $NotResolved = @($Flow.approvers | Where-Object { -not $_.resolved -and $_.source -cne 'emptyGroup' } | ForEach-Object { "$($_.label)" })
                $Texts = @(
                    if ($NotResolved.Count -gt 0) { "$($NotResolved.Count) approver(s) of the role '$($Flow.roleName)' could not be resolved against the Privileged EAM data and are not evaluated: $(Join-EntraOpsFindingName $NotResolved)." }
                    foreach ($Group in $EmptyGroups) { "The approver group '$Group' of the role '$($Flow.roleName)' has no members, so nobody can approve through it." }
                )
                if ($Texts.Count -gt 0) { $Texts -join ' ' }
            })
        if ($Incomplete.Count -gt 0) {
            [pscustomobject]@{ NoteOnly = $true; Note = "$(@($Incomplete | Select-Object -First 5) -join ' ')$(if ($Incomplete.Count -gt 5) { " $($Incomplete.Count - 5) more roles have approvers that could not be resolved or groups without members." })" }
        }
    }
    foreach ($Flow in $Context.Flows) {
        $Check = $Flow.checks[$Rule.Key]
        if ($null -eq $Check) { throw "No PIM Request Flow evaluator for finding rule '$($Rule.Id)' ($($Rule.Key))." }
        if (-not $Check.Applies) { continue }
        if (-not $Check.Failed) { [pscustomobject]@{ Failed = $false; InstanceKey = $Flow.id }; continue }

        [pscustomobject]@{
            Failed         = $true
            InstanceKey    = $Flow.id
            ObjectId       = "$($Flow.roleId)"
            ObjectType     = 'roleSetting'
            DisplayName    = "$($Flow.roleName)"
            AdminTierLevel = $(if ($Flow.roleTier) { Get-EntraOpsAdminTierLevel $Flow.roleTier } else { $null })
            AdminTierLevelName = $(if ($Flow.roleTier) { "$($Flow.roleTier)" } else { $null })
            Message        = $Check.Text
            Evidence       = [ordered]@{
                FlowId      = $Flow.id
                Path        = $Flow.path
                RoleTier    = $Flow.roleTier
                SnapshotKey = $Context.SnapshotKey
                # Tier: the tier of the approver's access; ProtectionTier: the classification the approver checks compare.
                Approvers   = @($Flow.approvers | ForEach-Object { [ordered]@{ Label = $_.label; Tier = $_.tier; ProtectionTier = $(if ($null -ne $_.PSObject.Properties['protectionTier']) { $_.protectionTier }); LeastProtectedMember = $(if ($null -ne $_.PSObject.Properties['protectionMember']) { $_.protectionMember }); Resolved = $_.resolved } })
            }
        }
    }
}
