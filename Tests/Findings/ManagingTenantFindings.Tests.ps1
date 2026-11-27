#Requires -Modules Pester

# Principals managed by another tenant: the Control Plane check (EO.4011) with the managing tenant of Tenant Governance
# (ManagingTenantId and ManagingTenantName of EntraOpsConfig.json) accepted, and the marking of the managing tenant in
# the role assignments of principals of other tenants (EO.4010).
Describe 'Principals managed by another tenant' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        $script:HomeTenant = '11111111-1111-1111-1111-111111111111'
        $script:SyncTenant = '22222222-2222-2222-2222-222222222222'
        $script:GuestTenant = '33333333-3333-3333-3333-333333333333'
        $script:ManagingTenant = '44444444-4444-4444-4444-444444444444'
        $script:VendorTenant = '55555555-5555-5555-5555-555555555555'

        function Get-TestId([int]$Number) { '{0:d8}-0000-0000-0000-{1:d12}' -f $Number, $Number }
        function New-TestAssignment([string]$Name, [string]$Tier, [hashtable]$Property = @{}) {
            $Assignment = [ordered]@{
                RoleAssignmentId = "ra-$Name"; RoleAssignmentInstanceId = "i-$Name"; RoleDefinitionName = $Name; RoleDefinitionId = "rd-$Name"; RoleType = 'BuiltInRole'
                RoleAssignmentType = 'Direct'; PIMAssignmentType = 'Eligible'; RoleAssignmentScopeId = '/'
                Classification = @(@{ AdminTierLevelName = $Tier; Service = "S-$Tier" })
            }
            foreach ($Key in $Property.Keys) { $Assignment[$Key] = $Property[$Key] }
            $Assignment
        }
        function New-TestObject([int]$Number, [string]$Type, [string]$SubType, [string]$Tier, [object[]]$Assignments, [hashtable]$Property = @{}) {
            $Object = [ordered]@{
                ObjectId = (Get-TestId $Number); ObjectType = $Type; ObjectSubType = $SubType; ObjectDisplayName = "Object $Number"; ObjectTenantId = $script:HomeTenant
                ObjectAdminTierLevelName = $Tier; RoleAssignments = $Assignments; OriginType = 'Cloud'; OriginTenantId = $script:HomeTenant; OriginId = (Get-TestId $Number)
            }
            foreach ($Key in $Property.Keys) { $Object[$Key] = $Property[$Key] }
            $Object
        }
        # Privileged EAM data with one principal of each kind of another tenant, and local principals.
        function New-TestExport([string]$Root) {
            foreach ($System in 'EntraID', 'ResourceApps') { New-Item -ItemType Directory -Path "$Root/$System" -Force | Out-Null }
            $ControlPlane = { New-TestAssignment 'Global Administrator' 'ControlPlane' }
            ConvertTo-Json -Depth 10 -InputObject @(
                # Reported: synchronized from another tenant, an external member, a group of a governing tenant that is not configured.
                New-TestObject 1 'user' 'Member' 'ControlPlane' @(& $ControlPlane) @{ ObjectUserPrincipalName = 'adele@contoso.com'; OriginType = 'CrossTenantSync'; OriginTenantId = $script:SyncTenant }
                New-TestObject 2 'user' 'Member' 'ControlPlane' @(& $ControlPlane) @{ ObjectUserPrincipalName = 'alex_fabrikam.com#EXT#@contoso.onmicrosoft.com'; OutsideOfHomeTenant = $true; OriginType = 'B2BInvitation'; OriginTenantId = $script:GuestTenant }
                # The group of the governing tenant (a remote group with access through Tenant Governance).
                New-TestObject 3 'group' 'Security' 'ControlPlane' @(& $ControlPlane) @{ ObjectTenantId = $script:ManagingTenant; OutsideOfHomeTenant = $true; OriginType = 'TenantGovernance'; OriginTenantId = $script:ManagingTenant }
                # Not in scope: a guest (EO.4002), Management Plane access only. Evaluated but passing: local Control Plane users.
                New-TestObject 4 'user' 'Guest' 'ControlPlane' @(& $ControlPlane) @{ OutsideOfHomeTenant = $true; OriginType = 'B2BInvitation'; OriginTenantId = $script:GuestTenant }
                New-TestObject 5 'user' 'Member' 'ManagementPlane' @(New-TestAssignment 'User Administrator' 'ManagementPlane') @{ OriginType = 'CrossTenantSync'; OriginTenantId = $script:SyncTenant }
                New-TestObject 6 'user' 'Member' 'ControlPlane' @(& $ControlPlane)
                New-TestObject 7 'user' 'Member' 'ControlPlane' @(& $ControlPlane)
                # A guest of the managing tenant: informational only when the managing tenant is configured.
                New-TestObject 9 'user' 'Guest' 'ControlPlane' @(& $ControlPlane) @{ OutsideOfHomeTenant = $true; OriginType = 'B2BInvitation'; OriginTenantId = $script:ManagingTenant }
            ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
            # Not in scope: the service principal of an application of another organization (EO.5001).
            ConvertTo-Json -Depth 10 -InputObject @(
                New-TestObject 8 'serviceprincipal' 'Application' 'ControlPlane' @(New-TestAssignment 'Directory.ReadWrite.All' 'ControlPlane' @{ RoleType = 'Application'; PIMAssignmentType = 'Permanent' }) @{ OriginType = 'ExternalApplication'; OriginTenantId = $script:VendorTenant }
                # The application of the managing tenant.
                New-TestObject 10 'serviceprincipal' 'Application' 'ControlPlane' @(New-TestAssignment 'RoleManagement.ReadWrite.Directory' 'ControlPlane' @{ RoleType = 'Application'; PIMAssignmentType = 'Permanent' }) @{ OriginType = 'ExternalApplication'; OriginTenantId = $script:ManagingTenant }
            ) | Set-Content -LiteralPath "$Root/ResourceApps/ResourceApps.json"
        }
        function Invoke-TestEvaluation([string]$Root, [hashtable]$Config) {
            $ConfigPath = Join-Path $Root 'EntraOpsConfig.json'
            ConvertTo-Json -Depth 5 -InputObject $Config | Set-Content -LiteralPath $ConfigPath
            $Results = @{}
            foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM, PrivilegedAssets -ImportPath $Root -ReportPath (Join-Path $TestDrive 'noreports') -ConfigFilePath $ConfigPath -WarningAction SilentlyContinue) { $Results[$Result.RuleId] = $Result }
            $Results
        }
    }

    It 'reports Control Plane principals managed by another tenant, apart from guests and applications (EO.4011)' {
        $Root = Join-Path $TestDrive 'unconfigured'
        New-TestExport $Root
        $Results = Invoke-TestEvaluation $Root @{ TenantName = 'contoso.onmicrosoft.com' }
        $Rule = $Results['EO.4011']
        $Rule.Status | Should -Be 'Failed'
        $Rule.Severity | Should -Be 'High'
        @($Rule.Results.Instance.ObjectId | Sort-Object) | Should -Be @((Get-TestId 1), (Get-TestId 2), (Get-TestId 3))
        $ById = @{}; foreach ($Result in $Rule.Results) { $ById[$Result.Instance.ObjectId] = $Result }
        $ById[(Get-TestId 1)].Message | Should -Be "User 'Object 1' is synchronized from tenant $script:SyncTenant (cross-tenant synchronization) and has Control Plane access."
        $ById[(Get-TestId 1)].Detail | Should -Be "Is synchronized from tenant $script:SyncTenant (cross-tenant synchronization) and has Control Plane access."
        $ById[(Get-TestId 2)].Message | Should -Be "User 'Object 2' is an external member invited from tenant $script:GuestTenant and has Control Plane access."
        $ById[(Get-TestId 3)].Message | Should -Be "Group 'Object 3' is an object of tenant $script:ManagingTenant with access through Tenant Governance and has Control Plane access."
        $ById[(Get-TestId 3)].Evidence.OriginType | Should -Be 'TenantGovernance'
        # Without ManagingTenantId, the note names the setting for the governing tenant.
        $Rule.ReasonCode | Should -Be 'Note'
        $Rule.Reason | Should -BeLike '1 of the reported principals have access through Tenant Governance.*set ManagingTenantId*'
        # Evaluated: all users and groups with Control Plane access apart from guests (objects 1, 2, 3 and the local users 6, 7).
        $Rule.EvaluatedCount | Should -Be 5
        $Rule.FailedCount | Should -Be 3
        # Without the setting, the guest and the application of that tenant are reported like any other.
        @($Results['EO.4002'].Results.Instance.ObjectId | Sort-Object) | Should -Be @((Get-TestId 4), (Get-TestId 9))
        @($Results['EO.5001'].Results.Instance.ObjectId | Sort-Object) | Should -Be @((Get-TestId 8), (Get-TestId 10))
    }

    It 'accepts the principals of the managing tenant with a note, and names the managing tenant (EO.4011, EO.4010)' {
        $Root = Join-Path $TestDrive 'configured'
        New-TestExport $Root
        $Results = Invoke-TestEvaluation $Root @{ TenantName = 'contoso.onmicrosoft.com'; ManagingTenantId = $script:ManagingTenant.ToUpperInvariant(); ManagingTenantName = 'fabrikam.onmicrosoft.com' }

        $Rule = $Results['EO.4011']
        @($Rule.Results.Instance.ObjectId | Sort-Object) | Should -Be @((Get-TestId 1), (Get-TestId 2))
        $Rule.EvaluatedCount | Should -Be 5
        $Rule.Reason | Should -Be "1 principal(s) of the managing tenant $($script:ManagingTenant.ToUpperInvariant()) (fabrikam.onmicrosoft.com) (ManagingTenantId of EntraOpsConfig.json) are not reported: Object 3. EO.4010 lists their role assignments."
        $Rule.Parameters.ManagingTenantId | Should -Be $script:ManagingTenant.ToUpperInvariant()
        $Rule.Parameters.ManagingTenantName | Should -Be 'fabrikam.onmicrosoft.com'

        # Guests (EO.4002) and applications (EO.5001) of the managing tenant are informational only as well.
        $Guests = $Results['EO.4002']
        @($Guests.Results.Instance.ObjectId) | Should -Be @((Get-TestId 4))
        $Guests.Reason | Should -BeLike '1 principal(s) of the managing tenant * are not reported: Object 9. EO.4010 lists their role assignments.'
        $Guests.Parameters.ManagingTenantName | Should -Be 'fabrikam.onmicrosoft.com'
        $Applications = $Results['EO.5001']
        @($Applications.Results.Instance.ObjectId) | Should -Be @((Get-TestId 8))
        $Applications.Reason | Should -BeLike '1 principal(s) of the managing tenant * are not reported: Object 10. EO.4010 lists their role assignments.'

        # The inventory keeps the managing tenant, named and marked.
        $Inventory = $Results['EO.4010']
        $Managed = @($Inventory.Results | Where-Object { $_.Instance.ObjectId -eq (Get-TestId 3) })
        $Managed.Count | Should -Be 1
        $Managed[0].Message | Should -BeLike "*is an object of tenant $script:ManagingTenant (the managing tenant fabrikam.onmicrosoft.com) with access through Tenant Governance, outside the home tenant, with the Control Plane role*"
        $Managed[0].Evidence.ManagingTenant | Should -BeTrue
        foreach ($Number in 9, 10) { @($Inventory.Results | Where-Object { $_.Instance.ObjectId -eq (Get-TestId $Number) })[0].Evidence.ManagingTenant | Should -BeTrue }
        @($Inventory.Results | Where-Object { $_.Instance.ObjectId -eq (Get-TestId 1) })[0].Evidence.Contains('ManagingTenant') | Should -BeFalse
    }

    It 'passes instead of being skipped when all Control Plane principals belong to this tenant (EO.4011)' {
        $Root = Join-Path $TestDrive 'local'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 6 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Global Administrator' 'ControlPlane')
            New-TestObject 11 'group' 'Role-assignable' 'ControlPlane' @(New-TestAssignment 'Privileged Role Administrator' 'ControlPlane')
            # An external member with Management Plane access only is not in the scope of this rule.
            New-TestObject 5 'user' 'Member' 'ManagementPlane' @(New-TestAssignment 'User Administrator' 'ManagementPlane') @{ OutsideOfHomeTenant = $true; OriginType = 'B2BInvitation' }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        $Rule = (Invoke-TestEvaluation $Root @{ TenantName = 'contoso.onmicrosoft.com' })['EO.4011']
        $Rule.Status | Should -Be 'Passed'
        $Rule.EvaluatedCount | Should -Be 2
        $Rule.FailedCount | Should -Be 0
        @($Rule.Results).Count | Should -Be 0
    }

    It 'does not report groups of another tenant without restricted management, but names them (EO.4004)' {
        $Root = Join-Path $TestDrive 'remote-group'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 3 'group' 'Security' 'ControlPlane' @(New-TestAssignment 'Global Administrator' 'ControlPlane') @{ ObjectTenantId = $script:ManagingTenant; OutsideOfHomeTenant = $true; OriginType = 'TenantGovernance'; OriginTenantId = $script:ManagingTenant }
            New-TestObject 12 'group' 'Security' 'ControlPlane' @(New-TestAssignment 'Privileged Role Administrator' 'ControlPlane')
            New-TestObject 6 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Global Administrator' 'ControlPlane')
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        $Rule = (Invoke-TestEvaluation $Root @{ TenantName = 'contoso.onmicrosoft.com' })['EO.4004']
        $Rule.Status | Should -Be 'Failed'
        $Rule.EvaluatedCount | Should -Be 2
        @($Rule.Results.Instance.ObjectId) | Should -Be @((Get-TestId 12))
        $Rule.ReasonCode | Should -Be 'Note'
        $Rule.Reason | Should -Be '1 group(s) of other tenants are not reported: Object 3. Their membership and protection are managed in their tenant; EO.4011 and EO.4010 report their access.'
        @((Invoke-TestEvaluation $Root @{ TenantName = 'contoso.onmicrosoft.com' })['EO.4011'].Results.Instance.ObjectId) | Should -Be @((Get-TestId 3))
    }

    It 'returns an error for the rules of the managing tenant when ManagingTenantId is not a tenant ID' {
        $Root = Join-Path $TestDrive 'invalid'
        New-TestExport $Root
        $Results = Invoke-TestEvaluation $Root @{ TenantName = 'contoso.onmicrosoft.com'; ManagingTenantId = 'fabrikam.onmicrosoft.com' }
        foreach ($Id in 'EO.4002', 'EO.4010', 'EO.4011', 'EO.5001') {
            $Results[$Id].Status | Should -Be 'Error'
            $Results[$Id].Reason | Should -Be "ManagingTenantId of EntraOpsConfig.json must be a tenant ID (GUID), but is 'fabrikam.onmicrosoft.com'"
        }
        # The other rules are evaluated.
        $Results['EO.3001'].Status | Should -Not -Be 'Error'
    }

    It 'reads ManagingTenantId from the root of EntraOpsConfig.json, not from the Findings section' {
        $ConfigPath = Join-Path $TestDrive 'findings-section.json'
        ConvertTo-Json -Depth 5 -InputObject @{ Findings = @{ ManagingTenantId = $script:ManagingTenant } } | Set-Content -LiteralPath $ConfigPath
        $Setting = & (Get-Module EntraOps) { param($Path) Get-EntraOpsFindingSetting -ConfigFilePath $Path -WarningVariable Warnings -WarningAction SilentlyContinue; $script:TestWarnings = $Warnings } $ConfigPath
        $Setting.Values.ContainsKey('ManagingTenantId') | Should -BeFalse
        (& (Get-Module EntraOps) { $script:TestWarnings }) -join ' ' | Should -BeLike '*Unknown Findings setting(s)*ManagingTenantId*'
        (& (Get-Module EntraOps) { (Get-EntraOpsFindingCatalog).SettingNames }) | Should -Not -Contain 'ManagingTenantId'
    }
}
