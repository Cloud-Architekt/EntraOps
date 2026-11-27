#Requires -Modules Pester

# EO.4003: the excluded groups of a block policy (allow-list) are evaluated with their Control Plane members.
Describe 'Conditional Access allow-list of block policies by the members of the excluded groups (EO.4003)' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        function Write-TestDataFile([string]$Path, [string]$Variable, $Data) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
            "window.$Variable = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path
        }
        $script:Ids = @{
            Alice = '00000001-0000-0000-0000-000000000001'; Bob = '00000002-0000-0000-0000-000000000002'; Carol = '00000003-0000-0000-0000-000000000003'
            Breakglass = '00000004-0000-0000-0000-000000000004'; Service = '00000005-0000-0000-0000-000000000005'; Nested = '00000006-0000-0000-0000-000000000006'
            AllowGroup = '00000101-0000-0000-0000-000000000101'; AdminGroup = '00000102-0000-0000-0000-000000000102'; EmergencyGroup = '00000103-0000-0000-0000-000000000103'
            NoMemberData = '00000104-0000-0000-0000-000000000104'
        }
        $Member = { param($Id, $Name, $Type = 'user', $Tier = 'ControlPlane') [ordered]@{ id = $Id; displayName = $Name; tierName = $Tier; objectType = $Type } }
        $script:Groups = [ordered]@{
            # The excluded group of the block policy: Control Plane users, a nested group and a service principal.
            $script:Ids.AllowGroup     = [ordered]@{ tierName = 'ControlPlane'; displayName = 'Allow list'; totalMembers = 5; principalCount = 4; privilegedMemberCount = 5; members = @(
                    (& $Member $script:Ids.Alice 'Alice'), (& $Member $script:Ids.Bob 'Bob'), (& $Member $script:Ids.Carol 'Carol'),
                    (& $Member $script:Ids.Nested 'Nested group' 'group'), (& $Member $script:Ids.Service 'Automation' 'servicePrincipal')) }
            # Included by other policies: Bob is a transitive member.
            $script:Ids.AdminGroup     = [ordered]@{ tierName = 'ControlPlane'; displayName = 'Admins'; totalMembers = 1; principalCount = 1; privilegedMemberCount = 1; members = @((& $Member $script:Ids.Bob 'Bob')) }
            $script:Ids.EmergencyGroup = [ordered]@{ tierName = 'ControlPlane'; displayName = 'Emergency access'; totalMembers = 1; principalCount = 1; privilegedMemberCount = 1; members = @((& $Member $script:Ids.Breakglass 'Break glass')) }
        }
        $EamObject = {
            param($Id, $Type, $Upn, $Name, $Tier, $Roles = @())
            [ordered]@{ objectId = $Id; objectType = $Type; objectUserPrincipalName = $Upn; objectDisplayName = $Name; objectAdminTierLevelName = $Tier; roleSystem = 'EntraID'; assignedAdministrativeUnits = @(); roleAssignments = @($Roles) }
        }
        $Role = { param($Name, $Type = 'Permanent', $Scope = '/') [ordered]@{ roleDefinitionName = $Name; pimAssignmentType = $Type; roleAssignmentScopeId = $Scope; classification = @(@{ adminTierLevelName = 'ControlPlane' }) } }
        $script:EamObjects = @(
            & $EamObject $script:Ids.Alice 'user' 'alice@contoso.com' 'Alice' 'ControlPlane'
            & $EamObject $script:Ids.Bob 'user' 'bob@contoso.com' 'Bob' 'ControlPlane'
            # Carol holds the role actively on the directory, eligibly, or on an administrative unit (by the test).
            & $EamObject $script:Ids.Carol 'user' 'carol@contoso.com' 'Carol' 'ControlPlane' @((& $Role 'Global Administrator'))
            & $EamObject $script:Ids.Breakglass 'user' 'breakglass@contoso.com' 'Break glass' 'ControlPlane'
            & $EamObject $script:Ids.Service 'servicePrincipal' '' 'Automation' 'ControlPlane'
            & $EamObject $script:Ids.NoMemberData 'group' '' 'No member data' 'ControlPlane'
        )

        # A Reports folder with the given enabled Conditional Access policies, the groups with member data and the objects.
        function New-TestAllowListData([string]$Name, [object[]]$Policies, [object[]]$Objects = $script:EamObjects) {
            $Folder = Join-Path $TestDrive $Name
            $Blobs = [ordered]@{}
            $Resources = @(foreach ($Policy in $Policies) {
                    $Hash = "h$($Blobs.Count + 1)"
                    $Policy['State'] = 'enabled'
                    $Blobs[$Hash] = [ordered]@{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; displayName = $Policy.DisplayName; properties = $Policy }
                    [ordered]@{ p = "microsoft.entra.conditionalaccesspolicy/test/$Hash.json"; h = $Hash }
                })
            Write-TestDataFile "$Folder/ConfigurationAnalyzer/data/configuration-analyzer-data.js" 'ENTRAOPS_CONFIGANALYZER_DATA' ([ordered]@{
                    snapshots          = @([ordered]@{ commitSha = 'cccccccc'; commitDate = '2026-10-20T10:00:00.0000000+00:00'; hasDetail = $true; resources = $Resources })
                    blobs              = $Blobs
                    resolvedGroupTiers = $script:Groups
                })
            Write-TestDataFile "$Folder/EamDashboard/data/eam-dashboard-data.js" 'ENTRAOPS_EAM_DATA' ([ordered]@{ objects = @($Objects) })
            $Folder
        }
        function Get-TestAllowListResult([string]$ReportPath, [string[]]$EmergencyAccessAccounts = @()) {
            $Config = Join-Path $TestDrive "config-$([guid]::NewGuid()).json"
            @{ Findings = @{ EmergencyAccessAccounts = @($EmergencyAccessAccounts) } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Config
            Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -ReportPath $ReportPath -ConfigFilePath $Config | Where-Object Key -eq 'conditionalAccessControlPlaneExclusion'
        }
        # Blocks admin portals for everyone except the allow-list group.
        function New-TestBlockPolicy([string[]]$ExcludeGroups = @('Allow list')) {
            [ordered]@{ Id = 'block'; DisplayName = 'Block admin portals'; BuiltInControls = @('block'); IncludeUsers = @('All'); ExcludeGroups = $ExcludeGroups }
        }
        # Policies that target Alice by user principal name, Bob through the included group and Carol by role.
        function Get-TestCoveringPolicy {
            [ordered]@{ Id = 'alice'; DisplayName = 'Alice'; BuiltInControls = @('mfa'); IncludeUsers = @('alice@contoso.com') }
            [ordered]@{ Id = 'admins'; DisplayName = 'Admins'; BuiltInControls = @('mfa'); IncludeGroups = @('Admins') }
            [ordered]@{ Id = 'roles'; DisplayName = 'Roles'; BuiltInControls = @('mfa'); IncludeRoles = @('Global Administrator') }
        }
    }

    It 'does not report an excluded group of a block policy when other enabled policies target each Control Plane member' {
        $Folder = New-TestAllowListData 'covered' (@(New-TestBlockPolicy) + @(Get-TestCoveringPolicy))
        $Result = Get-TestAllowListResult $Folder
        $Result.Status | Should -Be 'Passed'
        $Result.EvaluatedCount | Should -Be 4
    }

    It 'names the Control Plane members that no other enabled policy targets' {
        # Without the policy of the role, Carol is not targeted (the nested group and the service principal do not count).
        $Folder = New-TestAllowListData 'uncovered' (@(New-TestBlockPolicy) + @(Get-TestCoveringPolicy | Where-Object Id -ne 'roles'))
        $Result = Get-TestAllowListResult $Folder
        $Result.FailedCount | Should -Be 1
        $Block = $Result.Results | Where-Object { $_.Instance.DisplayName -eq 'Block admin portals' }
        $Block.Message | Should -BeLike "*no other enabled policy targets them: Allow list (Control Plane members no other enabled policy targets: Carol)."
        $Block.Evidence.ExcludedControlPlane | Should -Be @('Allow list')
        $Block.Evidence.UncoveredControlPlaneMembers.Count | Should -Be 1
        $Block.Evidence.UncoveredControlPlaneMembers[0].Group | Should -Be 'Allow list'
        $Block.Evidence.UncoveredControlPlaneMembers[0].Members | Should -Be @('Carol')
    }

    It 'counts only active directory roles on the directory, not an <Case> role' -ForEach @(
        @{ Case = 'eligible'; Type = 'Eligible'; Scope = '/' }
        @{ Case = 'administrative unit'; Type = 'Permanent'; Scope = '/administrativeUnits/00000201-0000-0000-0000-000000000201' }
    ) {
        $Objects = @($script:EamObjects | ForEach-Object {
                if ($_.objectId -ne $script:Ids.Carol) { return $_ }
                $Carol = [ordered]@{}; foreach ($Key in $_.Keys) { $Carol[$Key] = $_[$Key] }
                $Carol.roleAssignments = @([ordered]@{ roleDefinitionName = 'Global Administrator'; pimAssignmentType = $Type; roleAssignmentScopeId = $Scope })
                $Carol
            })
        $Folder = New-TestAllowListData "role-$Type-$($Scope.Length)" (@(New-TestBlockPolicy) + @(Get-TestCoveringPolicy)) $Objects
        $Result = Get-TestAllowListResult $Folder
        ($Result.Results | Where-Object { $_.Instance.DisplayName -eq 'Block admin portals' }).Evidence.UncoveredControlPlaneMembers[0].Members | Should -Be @('Carol')
    }

    It 'does not count a policy that excludes the member as well' {
        $Policies = @(New-TestBlockPolicy) + @(Get-TestCoveringPolicy | ForEach-Object {
                # The policy of Alice excludes her again through the allow-list group.
                if ($_.Id -eq 'alice') { $_['ExcludeGroups'] = @('Allow list') }
                $_
            })
        $Result = Get-TestAllowListResult (New-TestAllowListData 'excluded-elsewhere' $Policies)
        ($Result.Results | Where-Object { $_.Instance.DisplayName -eq 'Block admin portals' }).Evidence.UncoveredControlPlaneMembers[0].Members | Should -Be @('Alice')
    }

    It 'leaves out the emergency access accounts and the members of the emergency access groups (setting <Setting>)' -ForEach @(
        @{ Setting = 'breakglass@contoso.com' }
        @{ Setting = 'Emergency access' }
    ) {
        $Groups = $script:Groups
        $script:Groups = [ordered]@{}; foreach ($Key in $Groups.Keys) { $script:Groups[$Key] = $Groups[$Key] }
        $script:Groups[$script:Ids.AllowGroup] = [ordered]@{ tierName = 'ControlPlane'; displayName = 'Allow list'; totalMembers = 2; principalCount = 2; privilegedMemberCount = 2; members = @(
                [ordered]@{ id = $script:Ids.Alice; displayName = 'Alice'; tierName = 'ControlPlane'; objectType = 'user' }
                [ordered]@{ id = $script:Ids.Breakglass; displayName = 'Break glass'; tierName = 'ControlPlane'; objectType = 'user' }) }
        try {
            $Folder = New-TestAllowListData "emergency-$($Setting.Length)" (@(New-TestBlockPolicy) + @(Get-TestCoveringPolicy))
        } finally { $script:Groups = $Groups }
        $Result = Get-TestAllowListResult $Folder
        ($Result.Results | Where-Object { $_.Instance.DisplayName -eq 'Block admin portals' }).Evidence.UncoveredControlPlaneMembers[0].Members | Should -Be @('Break glass')
        (Get-TestAllowListResult $Folder @($Setting)).Status | Should -Be 'Passed'
    }

    It 'keeps reporting an excluded group without member data that no other enabled policy targets' {
        $Folder = New-TestAllowListData 'no-member-data' (@(New-TestBlockPolicy @('No member data')) + @(Get-TestCoveringPolicy))
        $Result = Get-TestAllowListResult $Folder
        $Block = $Result.Results | Where-Object { $_.Instance.DisplayName -eq 'Block admin portals' }
        $Block.Message | Should -BeLike '*no other enabled policy targets them: No member data.'
        @($Block.Evidence.UncoveredControlPlaneMembers).Count | Should -Be 0
    }

    It 'keeps reporting an excluded group of a policy that does not block access' {
        $Policies = @([ordered]@{ Id = 'mfa'; DisplayName = 'Require MFA for all'; BuiltInControls = @('mfa'); IncludeUsers = @('All'); ExcludeGroups = @('Allow list') }) + @(Get-TestCoveringPolicy)
        $Result = Get-TestAllowListResult (New-TestAllowListData 'grant' $Policies)
        @($Result.Results.Instance.DisplayName) | Should -Be @('Require MFA for all')
        $Result.Results[0].Message | Should -BeLike '*(require mfa) does not apply to the excluded Control Plane users, groups or roles: Allow list.'
    }
}
