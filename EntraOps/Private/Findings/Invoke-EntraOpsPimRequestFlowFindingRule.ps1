# Built-in directory roles that cannot be assigned (template IDs): User, Guest User, Restricted Guest User, Device Users,
# Workplace Device Join, Device Join and the deprecated Device Managers. PIM has role settings for them, but no assignment
# can use these settings, so the role setting rules do not evaluate them.
$script:EntraOpsNonAssignableDirectoryRoleIds = [System.Collections.Generic.HashSet[string]]::new([string[]]@(
        'a0b1b346-4d3e-4e8b-98f8-753987be4970', '10dae51f-b6af-4016-8d66-8c2a99b929b3', '2af84b1e-32c8-42b7-82bc-daa82404023b',
        'd405c6df-0af8-4e3b-95e4-4d06e542189e', 'c34f683f-4d5a-4403-affd-6615e00e3a7f', '9c094953-4995-41c8-84c8-3ebb9b32c93f',
        '2b499bcd-da44-4968-8aec-78e1674fa64d'), [System.StringComparer]::OrdinalIgnoreCase)

function Test-EntraOpsPimRoleSettingInScope {
    <#
    .SYNOPSIS
        Tells whether the role setting rules evaluate the role of a PIM flow.
    .DESCRIPTION
        A Control Plane role is always evaluated: its setting applies to every future assignment. A Management
        Plane role is evaluated when it has a current eligible or active assignment (roleAssigned; unknown without
        Privileged EAM data counts as assigned). Roles that cannot be assigned are never evaluated. With
        -ControlPlaneOnly, only Control Plane roles are in scope.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Flow,

        [Parameter(Mandatory = $false)]
        [switch]$ControlPlaneOnly
    )

    if ($null -ne $Flow.PSObject.Properties['roleAssignable'] -and $Flow.roleAssignable -eq $false) { return $false }
    if ($Flow.roleTier -ceq 'ControlPlane') { return $true }
    if ($ControlPlaneOnly -or -not (Test-EntraOpsPrivilegedTier $Flow.roleTier)) { return $false }
    return -not ($null -ne $Flow.PSObject.Properties['roleAssigned'] -and $Flow.roleAssigned -eq $false)
}

function Get-EntraOpsAuthContextPolicyText {
    <#
    .SYNOPSIS
        Says why the authentication context of a role setting enforces nothing (authContextPolicy of a PIM flow).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    if ($Policy.State -ceq 'ReportOnly') { return "only report-only Conditional Access policies target it ($(Join-EntraOpsFindingName @($Policy.Policies))), so it enforces nothing" }
    'no enabled Conditional Access policy targets it, so it enforces nothing'
}

function Get-EntraOpsAuthContextUnknownNote {
    <#
    .SYNOPSIS
        The note of a rule for roles whose authentication context could not be compared with Conditional Access.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [int]$Count
    )

    "$Count role(s) require an authentication context on activation, but the Tenant Governance snapshot has no Conditional Access policies, so it is not evaluated whether an enabled policy enforces the context. Add microsoft.entra.conditionalaccesspolicy to the snapshot."
}

function Get-EntraOpsPimRequestFlowFlag {
    <#
    .SYNOPSIS
        Evaluates the PIM Request Flow rules for one flow: { Applies; Failed; Text } per rule key, in report order.
    .DESCRIPTION
        Applies tells whether the flow is in the scope of the rule (for example the activation flows of
        privileged roles for noMfaActivation), Failed whether it fails the rule, and Text the risk flag the
        PIM Request Flow report shows (New-EntraOpsReportFindingData keeps only the failed keys). A role is
        in scope when it is Control Plane, or Management Plane with a current assignment, and can be assigned
        (Test-EntraOpsPimRoleSettingInScope). New-EntraOpsPimRequestFlowFindingContext
        evaluates every flow once (checks of the flow).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Flow
    )

    $Properties = $Flow.p
    $RoleTier = $Flow.roleTier
    $Privileged = Test-EntraOpsPimRoleSettingInScope -Flow $Flow
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
    # The context enforces nothing unless an enabled Conditional Access policy targets it (authContextPolicy of the
    # flow); without Conditional Access policies in the snapshot (Unknown) the configured context counts.
    $ContextPolicy = if ($null -ne $Flow.PSObject.Properties['authContextPolicy']) { $Flow.authContextPolicy } else { $null }
    $ContextNotEnforced = $null -ne $ContextPolicy -and $ContextPolicy.State -cin 'None', 'ReportOnly'
    $AuthContextEnforced = (& $Truthy 'AuthenticationContextRequired') -and ((& $Truthy 'AuthenticationContextName') -or (& $Truthy 'AuthenticationContextId')) -and -not $ContextNotEnforced
    Add-Check 'noMfaActivation' ($Activation -and $Privileged) { -not (& $Truthy 'ActivationReqMFA') -and -not $AuthContextEnforced } {
        if ($ContextNotEnforced) { "$RoleText can be activated without MFA: it requires the authentication context '$($ContextPolicy.Context)', but $(Get-EntraOpsAuthContextPolicyText $ContextPolicy)." }
        else { "$RoleText can be activated without MFA or an authentication context." }
    }
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
    if ($Rule.Key -ceq 'noMfaActivation') {
        $Unknown = @($Context.Flows | Where-Object { $null -ne $_.checks[$Rule.Key] -and $_.checks[$Rule.Key].Applies -and $null -ne $_.PSObject.Properties['authContextPolicy'] -and $null -ne $_.authContextPolicy -and $_.authContextPolicy.State -ceq 'Unknown' })
        if ($Unknown.Count -gt 0) { [pscustomobject]@{ NoteOnly = $true; Note = Get-EntraOpsAuthContextUnknownNote -Count $Unknown.Count } }
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
                AuthenticationContextPolicy = $(if ($null -ne $Flow.PSObject.Properties['authContextPolicy'] -and $null -ne $Flow.authContextPolicy) { [ordered]@{ Context = $Flow.authContextPolicy.Context; State = $Flow.authContextPolicy.State; Policies = @($Flow.authContextPolicy.Policies) } })
                # Tier: the tier of the approver's access; ProtectionTier: the classification the approver checks compare.
                Approvers   = @($Flow.approvers | ForEach-Object { [ordered]@{ Label = $_.label; Tier = $_.tier; ProtectionTier = $(if ($null -ne $_.PSObject.Properties['protectionTier']) { $_.protectionTier }); LeastProtectedMember = $(if ($null -ne $_.PSObject.Properties['protectionMember']) { $_.protectionMember }); Resolved = $_.resolved } })
            }
        }
    }
}
