#Requires -Modules Pester

Describe 'PIM Request Flow role tiers and approvers' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        function Get-TestId([int]$Number) { '{0:d8}-0000-0000-0000-{1:d12}' -f $Number, $Number }
        $script:Roles = @{
            Lowered = (Get-TestId 101); ScopedLower = (Get-TestId 102); Raised = (Get-TestId 103)
            Overwritten = (Get-TestId 104); AssignedOnly = (Get-TestId 105); Approved = (Get-TestId 106)
        }
        $script:Ids = @{ EmptyGroup = (Get-TestId 201); TwinGroup = (Get-TestId 202); TwinMember = (Get-TestId 11); TwinAdmin = (Get-TestId 12); Assignee = (Get-TestId 13) }

        function Write-TestDataFile([string]$Path, [string]$Variable, $Data) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
            "window.$Variable = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path
        }

        # Report data with one role setting per case: the tier map is the classification catalog, the EAM Dashboard
        # data has the classified role assignments and the approvers.
        function New-TestReportData([string]$Root) {
            $Blobs = [ordered]@{}
            $Resources = @(foreach ($Role in @(
                        @{ Id = $script:Roles.Lowered; Name = 'Application Developer' }
                        @{ Id = $script:Roles.ScopedLower; Name = 'Password Administrator' }
                        @{ Id = $script:Roles.Raised; Name = 'Raised Role' }
                        @{ Id = $script:Roles.Overwritten; Name = 'Overwritten Role' }
                        @{ Id = $script:Roles.AssignedOnly; Name = 'Assigned Only Role' }
                        @{ Id = $script:Roles.Approved; Name = 'Approved Role'; Approval = $true }
                    )) {
                    $Hash = "h$($Blobs.Count + 1)"
                    $Blobs[$Hash] = [ordered]@{ properties = [ordered]@{
                            Id = $Role.Id; DisplayName = $Role.Name; ActivationReqMFA = $true; ApprovaltoActivate = [bool]$Role.Approval
                            ActivateApprover = $(if ($Role.Approval) { @('Empty Approvers', 'Twin Approvers') } else { @() })
                            PermanentEligibleAssignmentisExpirationRequired = $false; PermanentActiveAssignmentisExpirationRequired = $true; AssignmentReqMFA = $true
                        } }
                    [ordered]@{ type = 'microsoft.entra.rolesetting'; name = $Role.Name; p = "microsoft.entra.rolesetting/test/$($Role.Name).json"; h = $Hash }
                })
            Write-TestDataFile "$Root/ConfigurationAnalyzer/data/configuration-analyzer-data.js" 'ENTRAOPS_CONFIGANALYZER_DATA' ([ordered]@{
                    snapshots          = @([ordered]@{ commitSha = 'cccccccc'; commitDate = '2026-10-20T10:00:00.0000000+00:00'; hasDetail = $true; resources = $Resources })
                    blobs              = $Blobs
                    resolvedGroupTiers = @{
                        # A group with member data but without members: nobody can approve through it.
                        $script:Ids.EmptyGroup = @{ tierName = 'ControlPlane'; displayName = 'Empty Approvers'; members = @(); totalMembers = 0; principalCount = 0 }
                        # Its member has the name of a classified Control Plane account.
                        $script:Ids.TwinGroup  = @{ tierName = 'ControlPlane'; displayName = 'Twin Approvers'; members = @(@{ id = $script:Ids.TwinMember; displayName = 'Twin Name'; objectType = 'user' }); totalMembers = 1; principalCount = 1 }
                    }
                })
            Write-TestDataFile "$Root/ClassificationExplorer/data/tier-map.js" 'EOCE_TIER_MAP' ([ordered]@{
                    roles = @(
                        @{ sys = 'EntraID'; roleId = $script:Roles.Lowered; roleClass = 'ManagementPlane' }
                        @{ sys = 'EntraID'; roleId = $script:Roles.ScopedLower; roleClass = 'ControlPlane' }
                        @{ sys = 'EntraID'; roleId = $script:Roles.Raised; roleClass = 'ManagementPlane' }
                        @{ sys = 'EntraID'; roleId = $script:Roles.Overwritten; roleClass = 'ControlPlane' }
                        @{ sys = 'EntraID'; roleId = $script:Roles.Approved; roleClass = 'ControlPlane' }
                    )
                    paths = @()
                })
            $Assignment = { param($RoleId, $Tier, $Service, $TaggedBy = 'JSONwithAction') @{ roleDefinitionId = $RoleId; classification = @(@{ adminTierLevelName = $Tier; service = $Service; taggedBy = $TaggedBy }) } }
            Write-TestDataFile "$Root/EamDashboard/data/eam-dashboard-data.js" 'ENTRAOPS_EAM_DATA' ([ordered]@{
                    objects         = @(
                        [ordered]@{ objectId = $script:Ids.Assignee; objectType = 'user'; objectUserPrincipalName = 'assignee@contoso.com'; objectDisplayName = 'Assignee'; objectAdminTierLevelName = 'ControlPlane'; classification = @(); roleAssignments = @(
                                & $Assignment $script:Roles.Lowered 'UserAccess' 'Extended member'
                                & $Assignment $script:Roles.ScopedLower 'ManagementPlane' 'User Management'
                                & $Assignment $script:Roles.Raised 'ControlPlane' 'Privileged User Management'
                                & $Assignment $script:Roles.Overwritten 'ManagementPlane' 'Custom Classification' 'RoleDefinitionOverwrites'
                                & $Assignment $script:Roles.AssignedOnly 'ManagementPlane' 'Groups'
                            ) }
                        [ordered]@{ objectId = $script:Ids.TwinAdmin; objectType = 'user'; objectUserPrincipalName = 'twin.admin@contoso.com'; objectDisplayName = 'Twin Name'; objectAdminTierLevelName = 'ControlPlane'; classification = @(); roleAssignments = @() }
                        # The empty group has User Access: before, its access tier stood in for its members.
                        [ordered]@{ objectId = $script:Ids.EmptyGroup; objectType = 'group'; objectDisplayName = 'Empty Approvers'; objectAdminTierLevelName = 'UserAccess'; classification = @(); roleAssignments = @() }
                        [ordered]@{ objectId = $script:Ids.TwinGroup; objectType = 'group'; objectDisplayName = 'Twin Approvers'; objectAdminTierLevelName = 'ControlPlane'; classification = @(); roleAssignments = @() }
                    )
                    roleDefinitions = @()
                })
            $Root
        }

        $script:Root = New-TestReportData -Root (Join-Path $TestDrive 'pim-tier')
        $script:Context = & (Get-Module EntraOps) { param($Root) New-EntraOpsPimRequestFlowFindingContext -ReportData (Import-EntraOpsReportFindingData -ReportPath $Root) } $script:Root
        $script:Tier = @{}
        foreach ($Flow in @($script:Context.Flows | Where-Object path -eq 'activation')) { $script:Tier[$Flow.roleId] = $Flow }
        $script:ByKey = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow -ReportPath $script:Root -ConfigFilePath (Join-Path $TestDrive 'none.json')) { $script:ByKey[$Result.Key] = $Result }
    }

    It 'does not lower the catalog tier of a role by a less privileged assignment' {
        # Application Developer: Management Plane in the catalog, its assignment is classified User Access.
        $script:Tier[$script:Roles.Lowered].roleTier | Should -Be 'ManagementPlane'
        # Password Administrator: Control Plane in the catalog, Management Plane by a scoped assignment.
        $script:Tier[$script:Roles.ScopedLower].roleTier | Should -Be 'ControlPlane'
    }

    It 'raises the catalog tier of a role by a more privileged assignment' {
        $script:Tier[$script:Roles.Raised].roleTier | Should -Be 'ControlPlane'
        $script:Tier[$script:Roles.Raised].roleTierService | Should -Be 'Privileged User Management'
    }

    It 'takes the tier of a role definition overwrite of the tenant, also when it is lower than the catalog' {
        $script:Tier[$script:Roles.Overwritten].roleTier | Should -Be 'ManagementPlane'
        $script:Tier[$script:Roles.Overwritten].roleTierService | Should -Be 'Custom Classification'
    }

    It 'takes the tier of the assignments for a role without catalog tier' {
        $script:Tier[$script:Roles.AssignedOnly].roleTier | Should -Be 'ManagementPlane'
    }

    It 'evaluates the PIM settings of the roles with their catalog tier' {
        # Every role setting allows permanent eligible assignments: all six are privileged (none was lowered to User Access).
        $script:ByKey.permanentEligible.EvaluatedCount | Should -Be 6
        ($script:ByKey.permanentEligible.Results | Where-Object { $_.Instance.ObjectId -eq $script:Roles.ScopedLower }).Message | Should -Be "The Control Plane role 'Password Administrator' allows permanent (non-expiring) eligible assignments."
    }

    It 'does not compare an approver group without members with the tier of its access' {
        $Approver = @($script:Tier[$script:Roles.Approved].approvers | Where-Object name -eq 'Empty Approvers')[0]
        $Approver.resolved | Should -BeFalse
        $Approver.source | Should -Be 'emptyGroup'
        $Approver.label | Should -Be 'Empty Approvers (group without members)'
        $Approver.protectionTier | Should -BeNullOrEmpty

        $Check = $script:Tier[$script:Roles.Approved].checks.approverLowerTier
        $Check.Text | Should -Not -BeLike '*Empty Approvers*'
        # The rule names the group in its reason: nobody can approve through it.
        $script:ByKey.approverLowerTier.Reason | Should -BeLike "*The approver group 'Empty Approvers' of the role 'Approved Role' has no members, so nobody can approve through it.*"
        $script:ByKey.approverLowerTier.Reason | Should -Not -BeLike '*could not be resolved*'
    }

    It 'names the least protected member with the start of its object ID when another object has its name' {
        $Approver = @($script:Tier[$script:Roles.Approved].approvers | Where-Object name -eq 'Twin Approvers')[0]
        $Approver.resolved | Should -BeTrue
        $Approver.protectionTier | Should -Be 'UserAccess'
        $Approver.protectionMember | Should -Be "Twin Name ($($script:Ids.TwinMember.Substring(0, 8)))"
        $script:ByKey.approverLowerTier.Results.Message | Should -Be "The Control Plane role 'Approved Role' is approved by approver(s) classified at a lower tier: Twin Approvers (least protected member: Twin Name (00000011), classified as User Access)."
    }

    It 'never compares a group approver without members or member data with the tier of its access' {
        $Flags = & (Get-Module EntraOps) {
            Get-EntraOpsPimRequestFlowFlag -Flow ([pscustomobject]@{
                    path = 'activation'; roleTier = 'ControlPlane'; roleName = 'CP Role'; p = @{ ActivationReqMFA = $true; ApprovaltoActivate = $true; ActivateApprover = @('a', 'b') }
                    approvers = @(
                        [pscustomobject]@{ label = 'Empty (group without members)'; name = 'Empty'; tier = 'UserAccess'; protectionTier = $null; resolved = $false; source = 'emptyGroup' }
                        [pscustomobject]@{ label = 'Unknown (group without member data)'; name = 'Unknown'; tier = 'UserAccess'; protectionTier = $null; resolved = $false; source = 'groupWithoutMembers' }
                    )
                })
        }
        $Flags.approverLowerTier.Failed | Should -BeFalse
        $Flags.approverUnclassified.Failed | Should -BeTrue
    }
}
