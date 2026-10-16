#Requires -Modules Pester

BeforeAll {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepositoryRoot 'EntraOps') -Force

    function New-EamTestObject {
        param ([string]$Id, [string]$Tier = 'ControlPlane')
        [ordered]@{
            objectId                 = $Id
            objectDisplayName        = "Object $Id"
            objectType               = 'user'
            objectAdminTierLevelName = $Tier
            associatedWorkAccount    = @()
            roleAssignments          = @([ordered]@{
                    roleAssignmentId        = "assignment-$Id"
                    roleDefinitionName      = 'Global Administrator'
                    roleAssignmentScopeName = '/'
                })
        }
    }

    function Set-EamTestDataset {
        param ([string]$Path, [object[]]$Objects, [string]$TenantName = 'contoso.onmicrosoft.com')
        New-Item -Path (Split-Path -Parent $Path) -ItemType Directory -Force | Out-Null
        $Json = [ordered]@{ tenantName = $TenantName; objects = @($Objects) } | ConvertTo-Json -Depth 10 -Compress
        Set-Content -LiteralPath $Path -Value "window.ENTRAOPS_EAM_DATA = $Json;" -Encoding UTF8
    }

    # Writes the object ids of the Privileged EAM export (read by the mocked dashboard object transform).
    function Set-EamTestExport {
        param ([string[]]$Ids)
        Set-Content -LiteralPath (Join-Path $ImportPath 'EntraID/EntraID.json') -Value (ConvertTo-Json -InputObject @($Ids)) -Encoding UTF8
    }

    function Invoke-TestGit {
        & git -C $Root -c user.name=EntraOps -c user.email=entraops@example.com -c commit.gpgsign=false -c tag.gpgsign=false @args 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "git $args failed with exit code $LASTEXITCODE." }
    }

    function Save-EamTestCommit {
        param ([string[]]$Ids)
        Set-EamTestExport -Ids $Ids
        Invoke-TestGit add -A
        Invoke-TestGit commit -m "Privileged EAM $($Ids -join ',')"
    }
}

Describe 'New-EntraOpsPrivilegedEamDashboardData change notification baseline' {
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $script:AppRoot = Join-Path $Root 'Reports/EamDashboard'
        $script:ImportPath = Join-Path $Root 'PrivilegedEAM'
        $script:OutFile = Join-Path $AppRoot 'data/eam-dashboard-data.js'
        New-Item -Path (Join-Path $AppRoot 'data'), (Join-Path $ImportPath 'EntraID') -ItemType Directory -Force | Out-Null
        Set-EamTestExport -Ids 'a', 'b'

        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedEamDashboardObjects {
            @(Get-Content -LiteralPath (Join-Path $ImportPath 'EntraID/EntraID.json') -Raw | ConvertFrom-Json) | ForEach-Object { New-EamTestObject -Id $_ }
        }
        Mock -ModuleName EntraOps Import-EntraOpsDashboardScopeReasoning { @{} }
        Mock -ModuleName EntraOps Import-EntraOpsControlPlaneReasoning { @{} }
        Mock -ModuleName EntraOps Get-EntraOpsClassificationSourceCache { $null }
        Mock -ModuleName EntraOps Get-EntraOpsReportingTenantName { 'contoso.onmicrosoft.com' }

        $script:GeneratorParams = @{
            RepoRoot                       = $Root
            AppRoot                        = $AppRoot
            ImportPath                     = $ImportPath
            ResolveLinkedIdentityObjectIds = $false
            PassThru                       = $true
            WarningAction                  = 'SilentlyContinue'
            InformationAction              = 'SilentlyContinue'
        }
    }

    It 'compares with the existing output file' {
        Set-EamTestDataset -Path $OutFile -Objects @((New-EamTestObject -Id 'a' -Tier 'ManagementPlane'), (New-EamTestObject -Id 'b'))

        $Payload = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams 6>$null

        @($Payload.notifications.id) | Should -Be @('asset-tier:a')
    }

    It 'warns without notifications and without failing when the existing output file cannot be parsed' {
        Set-Content -LiteralPath $OutFile -Value 'window.ENTRAOPS_EAM_DATA = {not json;' -Encoding UTF8

        $Payload = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams -WarningVariable Warnings 6>$null

        @($Warnings.Message) -join "`n" | Should -Match 'could not be used as a notification baseline'
        @($Payload.notifications) | Should -BeNullOrEmpty
        (Get-Content -LiteralPath $OutFile -Raw) | Should -Match 'window\.ENTRAOPS_EAM_DATA = '
    }

    It 'does not compare with an existing output file of another tenant' {
        Set-EamTestDataset -Path $OutFile -Objects @(New-EamTestObject -Id 'a') -TenantName 'fabrikam.onmicrosoft.com'

        $Payload = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams -WarningVariable Warnings 6>$null

        @($Warnings.Message) -join "`n" | Should -Match "belongs to tenant 'fabrikam\.onmicrosoft\.com'"
        @($Payload.notifications) | Should -BeNullOrEmpty
    }

    It 'generates no notifications and no baseline warning without output file outside a git working copy' {
        $Payload = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams -WarningVariable Warnings 6>$null

        @($Warnings.Message) -join "`n" | Should -Not -Match 'baseline'
        @($Payload.notifications) | Should -BeNullOrEmpty
    }

    Context 'without output file in a git working copy' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        BeforeEach {
            Invoke-TestGit init --quiet
        }

        It 'generates no notifications for the first export' {
            Save-EamTestCommit -Ids 'a', 'b'

            $Payload = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams -WarningVariable Warnings 6>$null

            @($Warnings.Message) -join "`n" | Should -Not -Match 'baseline'
            @($Payload.notifications) | Should -BeNullOrEmpty
        }

        It 'compares with the export before its latest commit' {
            Save-EamTestCommit -Ids 'a', 'c'
            Save-EamTestCommit -Ids 'a'
            Save-EamTestCommit -Ids 'a', 'b'

            $Payload = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams 6>$null

            @($Payload.notifications.id) | Should -Be @('asset-added:b', 'assignment-added:assignment-b')
        }

        It 'compares uncommitted export changes with the last commit' {
            Save-EamTestCommit -Ids 'a'
            Set-EamTestExport -Ids 'a', 'b'

            $Payload = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams 6>$null

            @($Payload.notifications.id) | Should -Be @('asset-added:b', 'assignment-added:assignment-b')
        }

        It 'compares with the export of the latest reporting release tag' {
            Save-EamTestCommit -Ids 'a', 'c'
            Invoke-TestGit tag reporting-20261001-060000
            Save-EamTestCommit -Ids 'a', 'd'
            Invoke-TestGit tag not-a-reporting-tag
            Save-EamTestCommit -Ids 'a'
            Save-EamTestCommit -Ids 'a', 'b'

            $Payload = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams 6>$null

            @($Payload.notifications.id) | Should -Contain 'asset-added:b'
            @($Payload.notifications.id) | Should -Contain 'asset-removed:c'
            @($Payload.notifications.id) | Should -Not -Contain 'asset-removed:d'
        }

        It 'keeps the change set id of a repeated run without new Privileged EAM changes' {
            Save-EamTestCommit -Ids 'a'
            Save-EamTestCommit -Ids 'a', 'b'

            $First = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams 6>$null
            # The pipelines start every run without a previous dataset.
            Remove-Item -LiteralPath $OutFile -Force
            Start-Sleep -Milliseconds 20
            $Repeated = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams 6>$null
            Remove-Item -LiteralPath $OutFile -Force
            Save-EamTestCommit -Ids 'a', 'b', 'c'
            $Changed = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams 6>$null

            @($First.notifications) | Should -Not -BeNullOrEmpty
            $Repeated.generatedAt | Should -Not -Be $First.generatedAt
            $Repeated.changeSetId | Should -Be $First.changeSetId
            $Changed.changeSetId | Should -Not -Be $First.changeSetId
        }

        It 'prefers the existing output file over git history' {
            Save-EamTestCommit -Ids 'a'
            Save-EamTestCommit -Ids 'a', 'b'
            Set-EamTestDataset -Path $OutFile -Objects @((New-EamTestObject -Id 'a'), (New-EamTestObject -Id 'b'))

            $Payload = New-EntraOpsPrivilegedEamDashboardData @GeneratorParams 6>$null

            @($Payload.notifications) | Should -BeNullOrEmpty
        }
    }
}
